"""Tests for the deterministic Route B preliminary gate evidence runner."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from experiments.fixed_policy_gate_runner import (
    PRELIMINARY_GATE_REPORT_VERSION,
    build_preliminary_gate_report,
    main,
)


class FixedPolicyGateRunnerTests(unittest.TestCase):
    """验证 BG1-BG6 preliminary report 的门槛、边界和 JSON contract。"""

    def test_report_passes_all_six_preliminary_gates(self) -> None:
        """合成穷举、差分、signature 和 mutation evidence 应形成六项通过报告。"""
        report = build_preliminary_gate_report(seed=109, differential_cases=64)
        gates = {gate.gate_id: gate for gate in report.gates}

        self.assertEqual(report.report_version, PRELIMINARY_GATE_REPORT_VERSION)
        self.assertEqual(report.stage, "B1_shadow_preliminary")
        self.assertTrue(report.all_passed)
        self.assertEqual(
            set(gates),
            {f"BG{index}_preliminary" for index in range(1, 7)},
        )
        self.assertTrue(all(gate.passed for gate in gates.values()))
        self.assertEqual(gates["BG3_preliminary"].evidence["exhaustive_cases"], 64)
        self.assertEqual(
            gates["BG3_preliminary"].evidence["fixed_seed_differential_cases"],
            64,
        )
        self.assertTrue(gates["BG2_preliminary"].evidence["missing_fact_rejected"])
        self.assertTrue(gates["BG2_preliminary"].evidence["duplicate_fact_rejected"])
        self.assertTrue(
            gates["BG2_preliminary"].evidence["canonical_ir_deletion_rejected"]
        )
        self.assertEqual(gates["BG5_preliminary"].evidence["mutation_count"], 6)
        self.assertEqual(gates["BG5_preliminary"].evidence["detected_count"], 6)
        self.assertEqual(
            gates["BG5_preliminary"].evidence["protected_sink_side_effect_count"],
            0,
        )
        self.assertEqual(gates["BG6_preliminary"].evidence["trainable_finding_count"], 0)

    def test_report_is_machine_readable_and_preserves_non_enforcement_limitations(self) -> None:
        """JSON 报告必须显式说明 synthetic/shadow 证据不批准进入 B1.5。"""
        report = build_preliminary_gate_report(seed=203, differential_cases=16)
        payload = report.as_dict()
        encoded = json.dumps(payload, sort_keys=True)

        self.assertTrue(payload["all_passed"])
        self.assertIn("B1_shadow_preliminary", encoded)
        self.assertIn("not approval to enter B1.5 enforcement", encoded)
        self.assertIn("no Agent/runtime shadow traffic", encoded)
        self.assertNotIn("private key", encoded.lower())

    def test_cli_writes_the_same_report_returned_on_stdout(self) -> None:
        """CLI 可将 deterministic report 写入指定临时路径且返回成功。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "fixed-policy-gates.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--seed",
                        "307",
                        "--differential-cases",
                        "8",
                        "--output",
                        str(output_path),
                    ]
                )

            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout_payload, file_payload)
            self.assertTrue(file_payload["all_passed"])

    def test_report_rejects_non_deterministic_or_empty_case_parameters(self) -> None:
        """seed 和差分样本数必须使用明确的内建整数 contract。"""
        with self.assertRaises(TypeError):
            build_preliminary_gate_report(seed=True, differential_cases=1)
        for value in (True, 0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    build_preliminary_gate_report(
                        seed=1,
                        differential_cases=value,
                    )


if __name__ == "__main__":
    unittest.main()
