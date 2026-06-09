"""Tests for the delegation/replay refinement model."""

from __future__ import annotations

import json
import unittest

from proofs.strict_runtime_auth_delegation_replay_model import (
    DELEGATION_REPLAY_CLAIM,
    DelegationReplayState,
    check_delegation_replay_claim,
    enumerate_states,
    mutated_transition_without_parent_fact_source,
    mutated_transition_without_replay_reserve,
    transition,
)
from saga.security_kernel import EXECUTE_SURFACE_CLAIM, layer_refinement_mappings


class DelegationReplayRefinementModelTests(unittest.TestCase):
    """验证 delegation/replay 子模型能细化主 Execute(surface) 命题。"""

    def test_delegation_replay_claim_holds_for_all_enumerated_states(self) -> None:
        """穷举所有细化状态时，只有所有必要条件满足才触发委托副作用。"""
        report = check_delegation_replay_claim()

        self.assertTrue(report.passed)
        self.assertEqual(report.claim, DELEGATION_REPLAY_CLAIM)
        self.assertEqual(report.parent_claim, EXECUTE_SURFACE_CLAIM)
        self.assertEqual(report.explored_state_count, (2**11) * 3)
        self.assertEqual(report.execute_transition_count, 1)
        self.assertEqual(report.reject_transition_count, report.explored_state_count - 1)
        self.assertEqual(report.violations, ())
        self.assertEqual(
            set(report.linked_sink_ids),
            {"delegation_handler", "replay_reserve_consume"},
        )

    def test_enumerated_states_include_replay_status_variants(self) -> None:
        """模型状态空间必须显式包含 reserved/replayed/failed 三类 replay 结果。"""
        statuses = {state.replay_reserve_status for state in enumerate_states()}

        self.assertEqual(statuses, {"reserved", "replayed", "failed"})

    def test_transition_rejects_each_missing_parent_condition(self) -> None:
        """父摘要、父 scope 事实源、scope 衰减和深度条件缺失时必须拒绝。"""
        cases = {
            "parent_digest_present": "missing_parent_envelope_digest",
            "parent_digest_known": "unknown_parent_envelope_digest",
            "parent_authorized_scopes_present": "missing_parent_authorized_scopes",
            "parent_authorized_scopes_match": "parent_authorized_scopes_mismatch",
            "delegation_depth_positive": "invalid_delegation_depth",
            "delegation_depth_within_limit": "delegation_depth_exceeded",
            "child_scopes_attenuated": "delegation_scope_escalation",
        }

        for field_name, reason in cases.items():
            with self.subTest(field=field_name):
                state = _valid_state(**{field_name: False})
                result = transition(state)

                self.assertEqual(result.decision, "reject")
                self.assertEqual(result.reason, reason)
                self.assertFalse(result.side_effect_triggered)
                self.assertFalse(result.violates_delegation_replay_claim())

    def test_transition_rejects_replay_failures_before_side_effect(self) -> None:
        """已消费、后端失败或 reserve 冲突都必须在委托副作用前拒绝。"""
        cases = (
            (_valid_state(replay_already_seen=True), "replayed_request_envelope"),
            (_valid_state(replay_reserve_status="failed"), "replay_state_persistence_failed"),
            (_valid_state(replay_reserve_status="replayed"), "replayed_request_envelope"),
        )

        for state, reason in cases:
            with self.subTest(reason=reason):
                result = transition(state)

                self.assertEqual(result.decision, "reject")
                self.assertEqual(result.reason, reason)
                self.assertFalse(result.side_effect_triggered)
                self.assertFalse(result.violates_execute_surface_claim())

    def test_all_valid_state_executes_once(self) -> None:
        """所有细化条件均满足时，子模型允许一次委托执行。"""
        result = transition(_valid_state())

        self.assertEqual(result.decision, "execute")
        self.assertEqual(result.reason, "authorized")
        self.assertTrue(result.side_effect_triggered)
        self.assertFalse(result.violates_delegation_replay_claim())

    def test_parent_fact_source_mutation_produces_counterexample(self) -> None:
        """跳过父 capability 事实源检查时，未知父摘要会形成反例。"""
        state = _valid_state(
            parent_digest_known=False,
            parent_authorized_scopes_match=False,
        )

        result = mutated_transition_without_parent_fact_source(state)

        self.assertEqual(result.decision, "execute")
        self.assertTrue(result.side_effect_triggered)
        self.assertTrue(result.violates_delegation_replay_claim())
        self.assertTrue(result.violates_execute_surface_claim())

    def test_replay_reserve_mutation_produces_counterexample(self) -> None:
        """跳过 replay reserve 检查时，已消费信封会形成反例。"""
        state = _valid_state(
            replay_already_seen=True,
            replay_reserve_status="replayed",
        )

        result = mutated_transition_without_replay_reserve(state)

        self.assertEqual(result.decision, "execute")
        self.assertTrue(result.side_effect_triggered)
        self.assertTrue(result.violates_delegation_replay_claim())
        self.assertTrue(result.violates_execute_surface_claim())

    def test_layer_refinement_links_delegation_and_replay_sinks(self) -> None:
        """layer refinement 中 delegation/replay 两层必须覆盖该子模型的 sink。"""
        mappings_by_layer = {
            mapping.layer_id: mapping for mapping in layer_refinement_mappings()
        }

        self.assertIn(
            "delegation_handler",
            mappings_by_layer["delegation_layer"].linked_sink_ids,
        )
        self.assertIn(
            "replay_reserve_consume",
            mappings_by_layer["replay_layer"].linked_sink_ids,
        )

    def test_model_report_is_json_serializable(self) -> None:
        """子模型报告必须能序列化，便于 proof artifact 归档。"""
        encoded = json.dumps(check_delegation_replay_claim().as_dict(), sort_keys=True)

        self.assertIn("DelegateExecute", encoded)
        self.assertIn("delegation_handler", encoded)
        self.assertIn("replay_reserve_consume", encoded)


def _valid_state(**overrides: object) -> DelegationReplayState:
    """构造默认全真且 replay 首次 reserve 成功的模型状态。"""
    state_args: dict[str, object] = {
        "n_verify": True,
        "scope_ok": True,
        "policy_ok": True,
        "parent_digest_present": True,
        "parent_digest_known": True,
        "parent_authorized_scopes_present": True,
        "parent_authorized_scopes_match": True,
        "child_scopes_attenuated": True,
        "delegation_depth_positive": True,
        "delegation_depth_within_limit": True,
        "replay_already_seen": False,
        "replay_reserve_status": "reserved",
    }
    state_args.update(overrides)
    return DelegationReplayState(**state_args)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
