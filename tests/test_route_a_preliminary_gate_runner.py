"""Tests for the Route A A0.5 preliminary gate evidence runner."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from experiments import route_a_preliminary_gate_runner


class RouteAPreliminaryGateRunnerTests(unittest.TestCase):
    """验证 preliminary 报告的通过项、开放项和机器可读 manifest。"""

    def test_report_passes_preliminary_gates_but_keeps_ag2_ag3_open(self) -> None:
        """A0.5 只能阶段性通过 AG1/AG4-AG8，不能宣称全部 AG gate 完成。"""
        report = route_a_preliminary_gate_runner.build_preliminary_gate_report()

        self.assertTrue(report["preliminary_gates_passed"])
        self.assertFalse(report["all_ag1_ag8_passed"])
        self.assertFalse(report["production_ready"])
        statuses = report["gate_status"]
        for gate in ("AG1", "AG4", "AG5", "AG6", "AG7", "AG8"):
            self.assertEqual(statuses[gate], "preliminary_pass")
        self.assertTrue(statuses["AG2"].startswith("open_"))
        self.assertTrue(statuses["AG3"].startswith("open_"))
        self.assertIn("python_integer_modulo_a0_5", report["open_gate_reasons"]["AG3"])

    def test_report_contains_two_equivalent_shared_core_manifests(self) -> None:
        """Dense/ring manifest 应共享 core、无 mismatch，并包含延迟与内存字段。"""
        report = route_a_preliminary_gate_runner.build_preliminary_gate_report()
        projector_evidence = report["projector_evidence"]

        self.assertTrue(projector_evidence["same_core_id"])
        self.assertTrue(projector_evidence["all_reference_equivalent"])
        self.assertTrue(projector_evidence["numeric_bounds_valid"])
        manifests = projector_evidence["manifests"]
        self.assertEqual(len(manifests), 2)
        self.assertEqual(
            {manifest["backend"] for manifest in manifests},
            {"dense-fixed-matrix-v1", "tiny-negacyclic-fixed-matrix-v1"},
        )
        for manifest in manifests:
            self.assertEqual(manifest["reference_mismatches"], 0)
            self.assertGreater(manifest["reference_equivalence_cases"], 0)
            self.assertGreaterEqual(manifest["latency_seconds"], 0.0)
            self.assertGreater(manifest["peak_memory_bytes"], 0)

    def test_main_writes_json_report(self) -> None:
        """CLI 应写出可重读 JSON，并以成功状态结束 preliminary gate run。"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "route-a-report.json"

            return_code = route_a_preliminary_gate_runner.main(
                ("--output", str(output_path))
            )

            self.assertEqual(return_code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["preliminary_gates_passed"])
            self.assertFalse(payload["all_ag1_ag8_passed"])


if __name__ == "__main__":
    unittest.main()
