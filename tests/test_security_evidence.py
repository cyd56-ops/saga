"""Tests for U9/U10 security-property evidence mapping."""

from __future__ import annotations

import json
import unittest

from experiments.ablation_overhead_runner import (
    ABLATION_MODES,
    run_ablation_overhead,
    summarize_ablation,
)
from experiments.negative_injection_runner import DEFAULT_SCENARIOS
from experiments.real_negative_runner import DEFAULT_SCENARIOS as REAL_NEGATIVE_SCENARIOS
from experiments.real_negative_runner import EXPECTED_REASONS
from experiments.security_evidence import (
    SECURITY_PROPERTY_ORDER,
    ablation_expected_negative_rejections,
    as_serializable_report,
    mappings_by_property,
    source_reason_map,
    summarize_property_evidence,
    validate_evidence_properties,
)


class SecurityEvidenceMappingTests(unittest.TestCase):
    """Validate the paper-facing U9/U10 property map.

    测试性质陈述、负向 runner、真实 runner 和消融证据之间的映射不漂移。
    """

    def test_all_evidence_references_declared_properties(self) -> None:
        """Every mapping should point to a declared U9 property.

        证据映射不能引用未声明的安全性质。
        """
        self.assertEqual(validate_evidence_properties(), ())

    def test_each_security_property_has_evidence(self) -> None:
        """Every U9 property should have at least one U10 evidence row.

        每个论文级性质都必须至少有一个测试或实验样本支撑。
        """
        by_property = mappings_by_property()

        self.assertEqual(set(by_property), set(SECURITY_PROPERTY_ORDER))
        for property_id, mappings in by_property.items():
            self.assertGreater(len(mappings), 0, property_id)

    def test_offline_negative_mapping_covers_default_scenarios(self) -> None:
        """Offline negative runner scenarios should all be mapped.

        默认离线负向场景必须全部映射到安全性质。
        """
        expected_reasons = source_reason_map("offline_negative_injection")

        self.assertEqual(set(DEFAULT_SCENARIOS), set(expected_reasons))
        self.assertEqual(expected_reasons["tampered_message"], "message_digest_mismatch")
        self.assertEqual(
            expected_reasons["tampered_authorized_scope"],
            "signature_verification_failed",
        )
        self.assertEqual(
            expected_reasons["agent_runtime_context_ignoring_local_agent"],
            "local_agent_execution_context_unsupported",
        )

    def test_real_negative_mapping_matches_runner_contract(self) -> None:
        """Real-service runner scenarios and reasons should be mapped.

        真实服务负向 runner 的场景和预期 reason 不能与证据表漂移。
        """
        expected_reasons = source_reason_map("real_negative_runner")

        self.assertEqual(set(REAL_NEGATIVE_SCENARIOS), set(expected_reasons))
        for scenario in REAL_NEGATIVE_SCENARIOS:
            self.assertEqual(expected_reasons[scenario], EXPECTED_REASONS[scenario])

    def test_ablation_mapping_matches_current_summary(self) -> None:
        """Ablation evidence should match current per-mode rejection counts.

        消融证据表中的负向拒绝数量必须等于 runner 当前统计。
        """
        ablation_results, _ = run_ablation_overhead(iterations=1)
        summary = summarize_ablation(ablation_results)
        expected_rejections = ablation_expected_negative_rejections()

        self.assertEqual(set(expected_rejections), set(ABLATION_MODES))
        for mode in ABLATION_MODES:
            self.assertEqual(
                expected_rejections[mode],
                summary["modes"][mode]["negative_rejected_count"],
            )

    def test_summary_and_report_are_json_serializable(self) -> None:
        """The U9/U10 report should be stable JSON-compatible data.

        性质与证据报告必须能直接序列化，便于论文表格和审计复用。
        """
        summary = summarize_property_evidence()
        report = as_serializable_report()

        self.assertEqual(summary["property_order"], list(SECURITY_PROPERTY_ORDER))
        self.assertGreater(summary["evidence_count"], 0)
        encoded = json.dumps(report, sort_keys=True)
        self.assertIn("side_effect_free_rejection", encoded)
        self.assertIn("shamir_secured_pq_can", encoded)


if __name__ == "__main__":
    unittest.main()
