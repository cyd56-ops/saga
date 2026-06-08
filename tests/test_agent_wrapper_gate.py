"""Tests for tool-level execution gating inside the local agent wrapper."""

from __future__ import annotations

import unittest
from unittest import mock

from smolagents import tool
from smolagents.memory import TaskStep

from agent_backend.base import AgentWrapper, CodeAgentWrapper
from saga.execution_gate import ExecutionAuthorizationError, reason_for_unauthorized_scope


def _make_echo_tool():
    @tool
    def echo(text: str) -> str:
        """Return the provided text unchanged.

        Args:
            text: The text to echo back.
        """
        return text

    return echo


class _StubExecutionContext:
    """Minimal execution context stub used by the tool-gating tests."""

    def __init__(self, allowed_scopes: set[str]) -> None:
        self.allowed_scopes = allowed_scopes
        self.seen_scopes: list[str] = []

    def authorize_action(self, action_scope: str) -> bool:
        """Record the request and decide whether it is allowed."""
        self.seen_scopes.append(action_scope)
        return action_scope in self.allowed_scopes

    def require_action(self, action_scope: str) -> None:
        """Raise when the requested action scope is not allowed."""
        self.seen_scopes.append(action_scope)
        if action_scope not in self.allowed_scopes:
            raise ExecutionAuthorizationError(
                reason_for_unauthorized_scope(action_scope),
                action_scope,
            )


class _TestAgentWrapper(AgentWrapper):
    """Concrete subclass used only to access helper methods in tests."""

    def _create_local_agent_object(self, **kwargs):
        raise NotImplementedError


class _RunCapableTestAgentWrapper(AgentWrapper):
    """Concrete subclass with a minimal runnable local agent stub."""

    def _create_local_agent_object(self, **kwargs):
        return type(
            "LocalAgentStub",
            (),
            {
                "memory": type("MemoryStub", (), {"steps": []})(),
                "run": lambda self, query, reset=False, **_kwargs: query,
            },
        )()


class AgentWrapperExecutionGateTests(unittest.TestCase):
    """Verify that tool execution is mediated by the local execution context."""

    def test_tool_call_is_allowed_when_scope_matches(self) -> None:
        """A matching tool scope should allow the wrapped tool to run."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:echo"})
        gated_tool = wrapper._wrap_tool_with_execution_gate(_make_echo_tool())

        result = gated_tool(text="hello")

        self.assertEqual(result, "hello")
        self.assertEqual(wrapper._execution_context.seen_scopes, ["tool_call:echo"])

    def test_tool_call_is_rejected_when_scope_mismatches(self) -> None:
        """A mismatched tool scope must fail closed before execution."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:send_email"})
        gated_tool = wrapper._wrap_tool_with_execution_gate(_make_echo_tool())

        with self.assertRaisesRegex(ExecutionAuthorizationError, "tool_not_authorized"):
            gated_tool(text="hello")

        self.assertEqual(wrapper._execution_context.seen_scopes, ["tool_call:echo"])

    def test_tool_call_rejection_exposes_stable_reason(self) -> None:
        """Tool permission failures should be distinguishable from PQ-CAN gate rejects."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:send_email"})
        gated_tool = wrapper._wrap_tool_with_execution_gate(_make_echo_tool())

        with self.assertRaises(ExecutionAuthorizationError) as raised:
            gated_tool(text="hello")

        self.assertEqual(raised.exception.reason, "tool_not_authorized")
        self.assertEqual(raised.exception.action_scope, "tool_call:echo")

    def test_memory_read_helper_requires_matching_scope(self) -> None:
        """Reading agent memory should require the explicit memory_read scope."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"memory_read"})
        agent_instance = type(
            "AgentStub",
            (),
            {"memory": type("MemoryStub", (), {"steps": [TaskStep(task="hello")]})()},
        )()

        steps = wrapper._read_agent_memory_steps(agent_instance)

        self.assertEqual(len(steps), 1)
        self.assertEqual(wrapper._execution_context.seen_scopes, ["memory_read"])

    def test_memory_write_helper_rejects_without_scope(self) -> None:
        """Appending to agent memory must fail closed without memory_write."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"memory_read"})
        agent_instance = type(
            "AgentStub",
            (),
            {"memory": type("MemoryStub", (), {"steps": []})()},
        )()

        with self.assertRaisesRegex(PermissionError, "memory_write"):
            wrapper._append_agent_memory_step(agent_instance, TaskStep(task="blocked"))

        self.assertEqual(agent_instance.memory.steps, [])
        self.assertEqual(wrapper._execution_context.seen_scopes, ["memory_write"])

    def test_delegation_helper_rejects_without_scope(self) -> None:
        """Delegation helper should be available even before a concrete delegation pipeline exists."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:echo"})

        with self.assertRaisesRegex(PermissionError, "delegation"):
            wrapper._require_delegation_permission()

        self.assertEqual(wrapper._execution_context.seen_scopes, ["delegation"])

    def test_delegation_interface_calls_handler_when_scope_matches(self) -> None:
        """The first-class delegation interface should invoke the configured runtime handler."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"delegation"})
        captured: list[tuple[str, str, dict]] = []

        wrapper.set_delegation_handler(
            lambda target_aid, message, **kwargs: captured.append((target_aid, message, kwargs)) or "delegated"
        )

        result = wrapper.delegate_to_agent(
            "alice@example.com:calendar_agent",
            "schedule this for me",
            turn_id="turn-1",
        )

        self.assertEqual(result, "delegated")
        self.assertEqual(
            captured,
            [("alice@example.com:calendar_agent", "schedule this for me", {"turn_id": "turn-1"})],
        )
        self.assertEqual(wrapper._execution_context.seen_scopes, ["delegation"])

    def test_delegation_interface_requires_configured_handler(self) -> None:
        """Delegation should fail explicitly when no runtime handler is installed."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"delegation"})
        wrapper._delegation_handler = None

        with self.assertRaisesRegex(NotImplementedError, "delegation handler is not configured"):
            wrapper.delegate_to_agent("alice@example.com:calendar_agent", "hello")

    def test_run_blocks_initiating_memory_bootstrap_without_memory_write_scope(self) -> None:
        """The real initialization-time memory append should now pass through the gate."""
        wrapper = _RunCapableTestAgentWrapper.__new__(_RunCapableTestAgentWrapper)
        wrapper._execution_context = None
        wrapper.custom_prompt = {
            "initiating_agent": "bootstrap",
            "receiving_agent": "recv",
            "system_prompt": "[[[preamble]]]\n[[[task_finished_token]]]\n[[[today_date]]]\n[[[specific_agent_instruction]]]\n[[[task]]]",
        }
        wrapper.task_finished_token = "<TASK_FINISHED>"
        wrapper.config = type("Cfg", (), {"specific_agent_instruction": ""})()

        with self.assertRaisesRegex(PermissionError, "memory_write"):
            wrapper.run(
                "hello",
                initiating_agent=True,
                execution_context=_StubExecutionContext({"memory_read"}),
            )

    def test_code_agent_disables_automatic_base_tools(self) -> None:
        """CodeAgent must not inject unwrapped base tools outside the execution gate."""
        wrapper = CodeAgentWrapper.__new__(CodeAgentWrapper)
        wrapper.tool_collections = [_make_echo_tool()]
        wrapper.model = object()
        wrapper.config = type("Cfg", (), {"additional_authorized_imports": ["datetime"]})()

        with mock.patch("agent_backend.base.CodeAgent", return_value=object()) as code_agent:
            wrapper._create_local_agent_object(template_text="system prompt")

        kwargs = code_agent.call_args.kwargs
        self.assertFalse(kwargs["add_base_tools"])
        self.assertEqual(kwargs["tools"], wrapper.tool_collections)


if __name__ == "__main__":
    unittest.main()
