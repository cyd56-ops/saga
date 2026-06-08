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


def _make_failing_tool():
    @tool
    def fail_tool() -> str:
        """Raise a backend error after authorization succeeds."""
        raise RuntimeError("backend failed")

    return fail_tool


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


class _DirectBackendStub:
    """Tracks whether a protected backend method was reached."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def send_email(self, *args, **kwargs) -> bool:
        """Record a direct backend email send attempt."""
        self.calls.append(("send_email", args, kwargs))
        return True

    def get_emails(self, *args, **kwargs) -> list[dict]:
        """Record a direct backend email read attempt."""
        self.calls.append(("get_emails", args, kwargs))
        return [{"subject": "ok"}]


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

    def test_tool_backend_error_is_not_rewritten_as_authorization_failure(self) -> None:
        """Tool-internal failures should remain distinguishable from local authorization denials."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:fail_tool"})
        gated_tool = wrapper._wrap_tool_with_execution_gate(_make_failing_tool())

        with self.assertRaisesRegex(RuntimeError, "backend failed"):
            gated_tool()

        self.assertEqual(wrapper._execution_context.seen_scopes, ["tool_call:fail_tool"])

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

    def test_memory_read_helper_rejects_without_scope(self) -> None:
        """缺少 memory_read scope 时，读取 helper 不能返回 memory 快照。"""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"memory_write"})
        agent_instance = type(
            "AgentStub",
            (),
            {"memory": type("MemoryStub", (), {"steps": [TaskStep(task="private")]})()},
        )()

        with self.assertRaisesRegex(PermissionError, "unauthorized_memory_read"):
            wrapper._read_agent_memory_steps(agent_instance)

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

    def test_direct_tool_backend_proxy_rejects_without_scope(self) -> None:
        """Direct backend calls through the gated resource must not bypass tool scopes."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:check_inbox"})
        backend = _DirectBackendStub()
        gated_backend = wrapper._gated_tool_resource(
            backend,
            {"send_email": "tool_call:send_email"},
        )

        with self.assertRaises(ExecutionAuthorizationError) as raised:
            gated_backend.send_email(to=["hr@example.com"], subject="x", body="blocked")

        self.assertEqual(raised.exception.reason, "unauthorized_tool_scope")
        self.assertEqual(backend.calls, [])
        self.assertEqual(wrapper._execution_context.seen_scopes, ["tool_call:send_email"])

    def test_direct_tool_backend_proxy_allows_matching_scope(self) -> None:
        """A gated backend method should run only after matching tool capability."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:send_email"})
        backend = _DirectBackendStub()
        gated_backend = wrapper._gated_tool_resource(
            backend,
            {"send_email": "tool_call:send_email"},
        )

        result = gated_backend.send_email(to=["hr@example.com"], subject="x", body="allowed")

        self.assertTrue(result)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(wrapper._execution_context.seen_scopes, ["tool_call:send_email"])

    def test_direct_email_backend_read_scope_depends_on_where_argument(self) -> None:
        """Email backend reads should bind inbox/outbox scopes to the where argument."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:check_inbox"})
        backend = _DirectBackendStub()
        gated_backend = wrapper._gated_tool_resource(
            backend,
            wrapper._email_backend_method_scopes(),
        )

        self.assertEqual(gated_backend.get_emails(where="inbox"), [{"subject": "ok"}])
        with self.assertRaisesRegex(PermissionError, "unauthorized_tool_scope"):
            gated_backend.get_emails(where="sent")

        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(
            wrapper._execution_context.seen_scopes,
            ["tool_call:check_inbox", "tool_call:check_outbox"],
        )

    def test_direct_tool_backend_proxy_rejects_missing_context_in_strict_mode(self) -> None:
        """Strict capability mode should reject backend access when context is missing."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = None
        wrapper.set_strict_execution_capabilities(True)
        backend = _DirectBackendStub()
        gated_backend = wrapper._gated_tool_resource(
            backend,
            {"send_email": "tool_call:send_email"},
        )

        with self.assertRaises(ExecutionAuthorizationError) as raised:
            gated_backend.send_email(to=["hr@example.com"], subject="x", body="blocked")

        self.assertEqual(raised.exception.reason, "missing_local_execution_context")
        self.assertEqual(raised.exception.action_scope, "tool_call:send_email")
        self.assertEqual(backend.calls, [])

    def test_direct_memory_facade_write_rejects_without_scope(self) -> None:
        """Direct use of the memory capability facade must not mutate memory without scope."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"memory_read"})
        memory = type("MemoryStub", (), {"steps": []})()

        with self.assertRaisesRegex(PermissionError, "unauthorized_memory_write"):
            wrapper._execution_capability_facade().append_memory_step(
                memory,
                TaskStep(task="blocked"),
            )

        self.assertEqual(memory.steps, [])
        self.assertEqual(wrapper._execution_context.seen_scopes, ["memory_write"])

    def test_direct_delegation_facade_rejects_without_scope(self) -> None:
        """Direct delegation through the capability facade should reject before side effects."""
        wrapper = _TestAgentWrapper.__new__(_TestAgentWrapper)
        wrapper._execution_context = _StubExecutionContext({"tool_call:echo"})
        delegated: list[tuple[str, str]] = []

        with self.assertRaisesRegex(PermissionError, "unauthorized_delegation"):
            wrapper._execution_capability_facade().delegate(
                lambda target_aid, message: delegated.append((target_aid, message)),
                "alice@example.com:calendar_agent",
                "hello",
            )

        self.assertEqual(delegated, [])
        self.assertEqual(wrapper._execution_context.seen_scopes, ["delegation"])

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
