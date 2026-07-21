"""Tests for the R18 dual-route fair experiment runner."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from experiments import dual_route_fair_runner


class DualRouteFairRunnerTests(unittest.TestCase):
    """验证公平语料、四象限、延迟、恢复和无敏感输出 contract。"""

    @classmethod
    def setUpClass(cls) -> None:
        """只运行一次真实 ML-DSA/fixed Route A/B 报告以控制测试耗时。"""
        cls.report = dual_route_fair_runner.build_dual_route_fair_report(
            shadow_load_cases=4,
            shadow_queue_capacity=1,
            shadow_delay_seconds=0.01,
        )
        cls.payload = cls.report.as_dict()

    def test_four_modes_share_inputs_and_cover_all_quadrants(self) -> None:
        """16 个核心 run 必须复用四个输入，并在 offline mode 覆盖四象限。"""
        self.assertTrue(self.report.all_passed)
        self.assertEqual(
            self.payload["schema_version"],
            dual_route_fair_runner.DUAL_ROUTE_FAIR_REPORT_SCHEMA_V1,
        )
        self.assertEqual(self.payload["workload"]["logical_case_count"], 4)
        self.assertEqual(self.payload["workload"]["core_run_count"], 16)
        self.assertEqual(
            self.payload["quadrants"],
            {"a0_b0": 1, "a0_b1": 1, "a1_b0": 1, "a1_b1": 1},
        )
        self.assertTrue(
            self.payload["gate_checks"]["same_logical_inputs_across_modes"]
        )

    def test_reference_latency_authority_and_replay_are_separate(self) -> None:
        """reference 零 mismatch，且 commit/sink/replay 与 mode 公式一致。"""
        reference = self.payload["reference_equivalence"]
        authority = self.payload["authority"]
        replay = self.payload["replay"]
        latency = self.payload["latency"]

        self.assertEqual(reference["route_a_mismatch_count"], 0)
        self.assertEqual(reference["route_b_mismatch_count"], 0)
        self.assertEqual(reference["route_a_false_reject_count"], 0)
        self.assertEqual(reference["route_b_false_reject_count"], 0)
        self.assertEqual(
            authority["core_commit_count_by_mode"],
            {
                "route_b_only": 2,
                "route_b_with_a_shadow": 2,
                "dual_required_research": 1,
                "offline_compare": 0,
            },
        )
        self.assertEqual(authority["core_commit_count"], 5)
        self.assertEqual(authority["core_protected_sink_effect_count"], 5)
        self.assertEqual(authority["unexpected_core_sink_effect_count"], 0)
        self.assertEqual(replay["probe_count"], 5)
        self.assertEqual(replay["rejected_count"], 5)
        self.assertGreater(latency["route_a_fixed"]["sample_count"], 0)
        self.assertGreater(latency["route_b_standard_plus_fixed"]["p95_seconds"], 0)

    def test_shadow_load_and_crash_recovery_keep_authority_boundaries(self) -> None:
        """shadow drop/backlog/error 有独立字段，PENDING 恢复不直接发布 Context。"""
        shadow = self.payload["shadow_load"]
        recovery = self.payload["crash_recovery"]

        self.assertEqual(shadow["case_count"], 4)
        self.assertEqual(shadow["committed_authority_count"], 4)
        self.assertEqual(shadow["protected_sink_effect_count"], 4)
        self.assertTrue(shadow["authority_isolated"])
        self.assertTrue(shadow["all_submissions_accounted"])
        self.assertIn("pending_count", shadow["queue_stats"])
        self.assertIn("dropped_submission_count", shadow)
        self.assertIn("error_or_timeout_count", shadow)
        self.assertTrue(recovery["passed"])
        self.assertEqual(recovery["state_before_restart"], "PENDING")
        self.assertEqual(recovery["state_after_restart"], "COMMITTED")
        self.assertEqual(recovery["post_recovery_replay_status"], "replayed")
        self.assertFalse(recovery["context_issued_by_probe"])

    def test_report_excludes_request_and_key_material(self) -> None:
        """报告不得复制 token、消息、签名、密钥或 SQLite 路径。"""
        encoded = json.dumps(self.payload, sort_keys=True)
        for forbidden in (
            "dual-route-fair-token",
            "authorize the fixed experiment task",
            "route_a_secret_key",
            "route_b_secret_key",
            "private_key",
            ".sqlite3",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_cli_writes_the_same_report_emitted_on_stdout(self) -> None:
        """CLI 应写出同一版本化 JSON，并按 all_passed 返回成功。"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "dual-route-fair.json"
            stdout = io.StringIO()
            with mock.patch.object(
                dual_route_fair_runner,
                "build_dual_route_fair_report",
                return_value=self.report,
            ), redirect_stdout(stdout):
                return_code = dual_route_fair_runner.main(
                    ("--output", str(output),)
                )
            self.assertEqual(return_code, 0)
            self.assertEqual(
                json.loads(stdout.getvalue()),
                json.loads(output.read_text(encoding="utf-8")),
            )


if __name__ == "__main__":
    unittest.main()
