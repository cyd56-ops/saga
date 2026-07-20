"""Tests for the Route A A1 final AG1-AG8 gate runner."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from experiments import route_a_a1_gate_runner


class RouteAA1GateRunnerTests(unittest.TestCase):
    """验证 A1 最终 gate 状态、等价计数、source closure 与 CLI。"""

    @classmethod
    def setUpClass(cls) -> None:
        """只运行一次完整 tiny exhaustive/normal differential report。"""
        cls.report = route_a_a1_gate_runner.build_a1_gate_report()

    def test_all_ag_gates_pass_with_research_only_boundary(self) -> None:
        """A1 应关闭 AG1-AG8，但仍不能标记为 production-ready。"""
        self.assertTrue(self.report["all_ag1_ag8_passed"])
        self.assertTrue(self.report["a2_stage_gate_open"])
        self.assertFalse(self.report["production_ready"])
        self.assertFalse(self.report["parse_hash_inside_claimed_circuit"])
        self.assertEqual(
            set(self.report["gate_status"].values()),
            {"pass"},
        )

    def test_ag2_has_complete_tiny_domain_and_seeded_normal_corpus(self) -> None:
        """AG2 evidence 必须包含 20736 个 tiny case 和正常参数固定种子差分。"""
        tiny = self.report["a1_tiny_exhaustive_evidence"]
        normal = self.report["a1_normal_differential_evidence"]
        self.assertEqual(tiny["case_count"], 20736)
        self.assertEqual(tiny["mismatch_count"], 0)
        self.assertEqual(normal["seed"], 20260718)
        self.assertEqual(normal["case_count"], 32)
        self.assertEqual(normal["mismatch_count"], 0)

    def test_ag3_and_ag8_manifests_are_complete(self) -> None:
        """AG3 必须无 forbidden source finding，AG8 必须含边界/复杂度/实测。"""
        closure = self.report["a1_source_closure"]
        normal = self.report["a1_normal_differential_evidence"]
        self.assertTrue(closure["passed"])
        self.assertEqual(closure["python_modulo_findings"], [])
        self.assertEqual(closure["python_equality_findings"], [])
        self.assertEqual(closure["data_branch_findings"], [])
        self.assertEqual(closure["verifier_call_findings"], [])
        self.assertIn("boundary", normal)
        self.assertIn("complexity", normal)
        self.assertGreaterEqual(normal["batch_latency_seconds"], 0.0)
        self.assertGreater(normal["peak_memory_bytes"], 0)

    def test_main_writes_supplied_gate_report(self) -> None:
        """CLI 应写出 JSON，并按 all-gates 状态返回成功。"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "a1-gates.json"
            with mock.patch.object(
                route_a_a1_gate_runner,
                "build_a1_gate_report",
                return_value=self.report,
            ):
                return_code = route_a_a1_gate_runner.main(
                    ("--output", str(output_path))
                )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(return_code, 0)
            self.assertTrue(payload["all_ag1_ag8_passed"])


if __name__ == "__main__":
    unittest.main()
