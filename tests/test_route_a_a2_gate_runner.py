"""Tests for the Route A A2 module-lattice gate runner."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from experiments import route_a_a2_gate_runner


class RouteAA2GateRunnerTests(unittest.TestCase):
    """验证 A2 gate、等价样本、mutation、manifest 与 CLI。"""

    @classmethod
    def setUpClass(cls) -> None:
        """只运行一次完整 tiny exhaustive/rank-2 differential report。"""

        cls.report = route_a_a2_gate_runner.build_a2_gate_report()

    def test_all_a2_gates_pass_with_research_only_boundary(self) -> None:
        """R16 第一阶段可关闭，但绝不能标记为 production-ready。"""

        self.assertTrue(self.report["all_a2_gates_passed"])
        self.assertTrue(self.report["r16_first_stage_complete"])
        self.assertTrue(self.report["research_only"])
        self.assertFalse(self.report["production_ready"])
        self.assertFalse(self.report["ntt_implemented"])
        self.assertFalse(self.report["ml_dsa_neuralized"])
        self.assertEqual(set(self.report["gate_status"].values()), {"pass"})

    def test_equivalence_corpora_cover_tiny_ring_and_rank_two(self) -> None:
        """tiny 全域与 rank-2 固定种子 corpus 必须均为零 mismatch。"""

        tiny = self.report["tiny_ring_exhaustive_evidence"]
        normal = self.report["rank_two_differential_manifest"]
        self.assertEqual(tiny["case_count"], 2025)
        self.assertEqual(tiny["mismatch_count"], 0)
        self.assertEqual(normal["parameters"]["module_rank"], 2)
        self.assertEqual(normal["case_count"], 64)
        self.assertEqual(normal["mismatch_count"], 0)

    def test_source_mutation_and_manifest_evidence_are_complete(self) -> None:
        """source closure、6/6 mutation 与环复杂度 manifest 必须完整。"""

        source = self.report["a2_source_closure"]
        mutations = self.report["mutation_evidence"]
        manifest = self.report["rank_two_differential_manifest"]
        self.assertTrue(source["passed"])
        self.assertEqual(source["python_modulo_findings"], [])
        self.assertEqual(source["python_equality_findings"], [])
        self.assertTrue(mutations["all_detected"])
        self.assertEqual(mutations["detected_count"], 6)
        self.assertEqual(
            manifest["complexity"]["projector_backend"],
            "tiny-negacyclic-fixed-matrix-v1",
        )
        self.assertGreater(manifest["peak_memory_bytes"], 0)

    def test_main_writes_supplied_gate_report(self) -> None:
        """CLI 应写出 JSON，并按 all-gates 状态返回成功。"""

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "a2-gates.json"
            with mock.patch.object(
                route_a_a2_gate_runner,
                "build_a2_gate_report",
                return_value=self.report,
            ):
                return_code = route_a_a2_gate_runner.main(
                    ("--output", str(output_path))
                )
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(return_code, 0)
            self.assertTrue(payload["all_a2_gates_passed"])


if __name__ == "__main__":
    unittest.main()
