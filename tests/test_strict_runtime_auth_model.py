"""Tests for the strict runtime-auth lightweight formal model."""

from __future__ import annotations

import json
import unittest

from proofs.strict_runtime_auth_model import (
    RuntimeAuthState,
    check_execute_surface_claim,
    enumerate_states,
    mutated_transition_without_scope_check,
    protected_model_surfaces,
    transition,
)
from saga.security_kernel import EXECUTE_SURFACE_CLAIM, protected_sink_surfaces


class StrictRuntimeAuthModelTests(unittest.TestCase):
    """验证 P5 轻量模型能穷举 strict runtime-auth kernel 的执行必要条件。"""

    def test_model_surfaces_match_protected_sink_inventory(self) -> None:
        """模型覆盖的 surfaces 必须和 protected sink audit 保持一致。"""
        self.assertEqual(
            set(protected_model_surfaces()),
            set(protected_sink_surfaces()),
        )

    def test_execute_surface_claim_holds_for_all_enumerated_states(self) -> None:
        """穷举所有布尔授权状态时，只有五个必要条件全真才能 Execute。"""
        report = check_execute_surface_claim()
        surface_count = len(protected_model_surfaces())

        self.assertTrue(report.passed)
        self.assertEqual(report.claim, EXECUTE_SURFACE_CLAIM)
        self.assertEqual(report.explored_state_count, surface_count * 32)
        self.assertEqual(report.execute_transition_count, surface_count)
        self.assertEqual(report.reject_transition_count, surface_count * 31)
        self.assertEqual(report.violations, ())
        self.assertIn("N_verify=1", report.claim)

    def test_transition_rejects_each_missing_required_term(self) -> None:
        """任一必要条件为假时，抽象转移都必须拒绝而不是执行。"""
        base_state = {
            "surface": "llm_prompt",
            "n_verify": True,
            "scope_ok": True,
            "replay_ok": True,
            "delegation_ok": True,
            "policy_ok": True,
        }
        cases = {
            "n_verify": "n_verify_reject",
            "scope_ok": "scope_reject",
            "replay_ok": "replay_reject",
            "delegation_ok": "delegation_reject",
            "policy_ok": "policy_reject",
        }

        for term, reason in cases.items():
            with self.subTest(term=term):
                state_args = dict(base_state)
                state_args[term] = False
                result = transition(RuntimeAuthState(**state_args))

                self.assertEqual(result.decision, "reject")
                self.assertEqual(result.reason, reason)
                self.assertFalse(result.violates_execute_claim())

    def test_all_true_state_is_the_only_execute_state_per_surface(self) -> None:
        """每个 surface 在 32 种组合中只有全真状态进入 execute。"""
        for surface in protected_model_surfaces():
            with self.subTest(surface=surface):
                transitions = [transition(state) for state in enumerate_states((surface,))]
                execute_states = [
                    candidate.state
                    for candidate in transitions
                    if candidate.decision == "execute"
                ]

                self.assertEqual(len(execute_states), 1)
                self.assertTrue(all(execute_states[0].required_terms().values()))

    def test_scope_check_mutation_produces_counterexample(self) -> None:
        """删除 scope_ok 检查的 mutation 必须产生违反 Execute claim 的反例。"""
        state = RuntimeAuthState(
            surface="tool_call:<tool_name>",
            n_verify=True,
            scope_ok=False,
            replay_ok=True,
            delegation_ok=True,
            policy_ok=True,
        )

        result = mutated_transition_without_scope_check(state)

        self.assertEqual(result.decision, "execute")
        self.assertTrue(result.violates_execute_claim())

    def test_model_report_is_json_serializable(self) -> None:
        """模型检查报告必须能序列化，便于后续论文附录和 refinement 表复用。"""
        encoded = json.dumps(check_execute_surface_claim().as_dict(), sort_keys=True)

        self.assertIn("Execute(surface)", encoded)
        self.assertIn("llm_prompt", encoded)
        self.assertIn("passed", encoded)


if __name__ == "__main__":
    unittest.main()
