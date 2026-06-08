"""Tests for policy-aware intent compilation."""

from __future__ import annotations

import unittest

from saga.intent import AgentIntent, IntentCompiler


class IntentCompilerTests(unittest.TestCase):
    """Verify requested scopes are proposals, not authorization decisions."""

    def test_compiler_keeps_only_policy_allowed_scopes(self) -> None:
        """LLM requested scopes must be intersected with local policy scopes."""
        compiler = IntentCompiler(
            {
                "llm_prompt",
                "tool_call:get_free_time_slots",
                "tool_call:add_calendar_event",
            }
        )
        intent = AgentIntent(
            action_scope="llm_prompt",
            requested_scopes=(
                "tool_call:get_free_time_slots",
                "memory_write",
                "delegation",
            ),
        )

        decision = compiler.compile(intent)

        self.assertEqual(
            decision.allowed_scopes,
            ("llm_prompt", "tool_call:get_free_time_slots"),
        )
        self.assertEqual(decision.reason, "scope_escalation")
        self.assertEqual(decision.rejected_scopes, ("delegation", "memory_write"))

    def test_broad_policy_scope_can_allow_qualified_tool_request(self) -> None:
        """A local broad tool policy may authorize a qualified requested tool."""
        decision = IntentCompiler({"llm_prompt", "tool_call"}).compile(
            AgentIntent(
                action_scope="llm_prompt",
                requested_scopes=("tool_call:send_email",),
            )
        )

        self.assertEqual(
            decision.allowed_scopes,
            ("llm_prompt", "tool_call:send_email"),
        )
        self.assertEqual(decision.rejected_scopes, ())

    def test_invalid_requested_scope_is_rejected_during_intent_build(self) -> None:
        """Invalid requested scopes should fail before envelope construction."""
        with self.assertRaisesRegex(ValueError, "unsupported action_scope"):
            AgentIntent(
                action_scope="llm_prompt",
                requested_scopes=("calendar_write",),
            )

    def test_missing_entry_scope_is_policy_reject(self) -> None:
        """When the entry action itself is disallowed, the compiler should report policy_reject."""
        decision = IntentCompiler({"tool_call:send_email"}).compile(
            AgentIntent(
                action_scope="llm_prompt",
                requested_scopes=("tool_call:send_email",),
            )
        )

        self.assertEqual(decision.reason, "policy_reject")
        self.assertEqual(decision.allowed_scopes, ("tool_call:send_email",))
        self.assertEqual(decision.rejected_scopes, ("llm_prompt",))


if __name__ == "__main__":
    unittest.main()
