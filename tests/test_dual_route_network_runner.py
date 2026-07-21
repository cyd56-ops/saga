"""Tests for the versioned R18 dual-route network report."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from experiments.dual_route_network_runner import (
    DUAL_ROUTE_NETWORK_REPORT_SCHEMA_V1,
    NetworkExchangeObservationV1,
    _build_report,
    summarize_network_latency,
)


class DualRouteNetworkRunnerTests(unittest.TestCase):
    """验证纯报告汇总、分位口径和 authority/no-side-effect 硬门槛。"""

    def test_report_accepts_committed_positives_and_zero_effect_negatives(self) -> None:
        """完整正负观测应生成通过的版本化网络 manifest。"""
        observations = (
            self._observation("positive-0", True, 1, None, 0.030, 0.020, 0.001),
            self._observation("positive-1", True, 1, None, 0.050, 0.040, 0.002),
            self._observation(
                "replay",
                False,
                0,
                "replayed_request_envelope",
                0.010,
                0.008,
                None,
            ),
            self._observation(
                "tampered-signature",
                False,
                0,
                "route_b_rejected",
                0.011,
                0.009,
                None,
            ),
        )
        contexts = (
            SimpleNamespace(
                coordinator_committed=True,
                durable_authorization_required=True,
            ),
            SimpleNamespace(
                coordinator_committed=True,
                durable_authorization_required=True,
            ),
        )
        shadow = (
            SimpleNamespace(authority_granted=False),
            SimpleNamespace(authority_granted=False),
        )

        report = _build_report(
            generated_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
            mode="route_b_with_a_shadow",
            sample_count=2,
            observations=observations,
            contexts=contexts,
            shadow_evidence=shadow,
        )

        self.assertTrue(report.all_passed)
        self.assertEqual(report.schema_version, DUAL_ROUTE_NETWORK_REPORT_SCHEMA_V1)
        self.assertEqual(
            report.latency["transport_round_trip"].p50_seconds,
            0.03,
        )
        self.assertEqual(report.latency["transport_round_trip"].p95_seconds, 0.05)
        self.assertEqual(report.authority["route_evidence_authority_count"], 0)
        self.assertEqual(report.negative_evidence["replay_sink_effect_delta"], 0)

    def test_latency_summary_rejects_non_finite_or_negative_samples(self) -> None:
        """延迟统计不能让 NaN、Inf 或负值进入论文 manifest。"""
        for values in ((-0.1,), (float("nan"),), (float("inf"),)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                summarize_network_latency(values)

    @staticmethod
    def _observation(
        case_id: str,
        expected_accept: bool,
        sink_effect_delta: int,
        audit_reason: str | None,
        transport_seconds: float,
        receive_seconds: float,
        prompt_sink_seconds: float | None,
    ) -> NetworkExchangeObservationV1:
        """构造无 server error 的确定性 runner 观测。"""
        return NetworkExchangeObservationV1(
            case_id=case_id,
            expected_accept=expected_accept,
            receiver_ended=True,
            response_bytes=128 if expected_accept else 0,
            sink_effect_delta=sink_effect_delta,
            transport_seconds=transport_seconds,
            receive_seconds=receive_seconds,
            prompt_sink_seconds=prompt_sink_seconds,
            audit_reason=audit_reason,
            server_error_type=None,
        )


if __name__ == "__main__":
    unittest.main()
