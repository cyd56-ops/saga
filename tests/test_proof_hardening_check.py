"""Tests for the optional proof-hardening check entrypoint."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from experiments import end_to_end_validation, proof_hardening_check


class ProofHardeningCheckTests(unittest.TestCase):
    """验证 proof-hardening 验收入口的编排和失败语义。"""

    def test_default_proof_tests_include_tlc_decomposition_runner(self) -> None:
        """默认 proof tests 必须覆盖 TLC 分解验收入口的编排测试。"""
        self.assertIn(
            "tests/test_tlc_strict_runtime_auth_check.py",
            proof_hardening_check.DEFAULT_PROOF_TESTS,
        )
        self.assertIn(
            "tests/test_strict_runtime_auth_evidence_summary.py",
            proof_hardening_check.DEFAULT_PROOF_TESTS,
        )

    def test_run_check_accepts_proof_tests_and_detected_mutation_artifacts(self) -> None:
        """proof tests 成功且 mutation artifact 验收通过时应返回 passed。"""
        mutation_report = end_to_end_validation.ArtifactValidationReport(
            passed=True,
            findings=(),
            metadata={"mutation_evidence": {"source": "mutation_evidence_runner"}},
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.proof_hardening_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=0,
                stdout="proof tests passed\n",
                stderr="",
            ),
        ) as subprocess_run, mock.patch(
            "experiments.proof_hardening_check.mutation_evidence_runner.run_mutation_evidence",
        ) as mutation_run, mock.patch(
            "experiments.proof_hardening_check.end_to_end_validation.validate_mutation_evidence_run_dir",
            return_value=mutation_report,
        ) as mutation_validate:
            report = proof_hardening_check.run_proof_hardening_check(
                output_dir=tmpdir,
                proof_tests=("tests/test_security_kernel.py",),
                mutation_names=("skip_replay_reserve",),
                required_mutations=("skip_replay_reserve",),
                python_executable="python",
            )

            summary_path = Path(tmpdir) / "proof_hardening_check_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertTrue(report.passed)
        self.assertTrue(summary["passed"])
        subprocess_run.assert_called_once()
        mutation_run.assert_called_once()
        mutation_validate.assert_called_once()
        self.assertEqual(mutation_run.call_args.kwargs["python_executable"], "python")
        self.assertEqual(
            mutation_validate.call_args.kwargs["required_mutations"],
            ("skip_replay_reserve",),
        )

    def test_run_check_reports_pytest_failure(self) -> None:
        """proof pytest 返回非零时，验收必须失败并记录稳定原因。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.proof_hardening_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=1,
                stdout="failed\n",
                stderr="",
            ),
        ), mock.patch(
            "experiments.proof_hardening_check.mutation_evidence_runner.run_mutation_evidence"
        ) as mutation_run:
            report = proof_hardening_check.run_proof_hardening_check(
                output_dir=tmpdir,
                proof_tests=("tests/test_security_kernel.py",),
                skip_mutations=True,
                python_executable="python",
            )

        mutation_run.assert_not_called()
        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("proof pytest command returned 1", reasons)

    def test_run_check_rejects_invalid_mutation_artifact(self) -> None:
        """mutation artifact validation 失败不能被入口误判为成功。"""
        mutation_report = end_to_end_validation.ArtifactValidationReport(
            passed=False,
            findings=(
                end_to_end_validation.ArtifactValidationFinding(
                    "mutation_evidence.jsonl:skip_replay_reserve",
                    "pytest returncode is not the expected test-failure code 1",
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.proof_hardening_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=0,
                stdout="ok\n",
                stderr="",
            ),
        ), mock.patch(
            "experiments.proof_hardening_check.mutation_evidence_runner.run_mutation_evidence"
        ), mock.patch(
            "experiments.proof_hardening_check.end_to_end_validation.validate_mutation_evidence_run_dir",
            return_value=mutation_report,
        ):
            report = proof_hardening_check.run_proof_hardening_check(
                output_dir=tmpdir,
                proof_tests=("tests/test_security_kernel.py",),
                mutation_names=("skip_replay_reserve",),
                python_executable="python",
            )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn(
            "pytest returncode is not the expected test-failure code 1",
            reasons,
        )

    def test_cli_returns_success_for_skipped_mutation_fast_check(self) -> None:
        """CLI 可作为快速 proof-test-only 检查运行。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.proof_hardening_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=0,
                stdout="ok\n",
                stderr="",
            ),
        ), mock.patch.object(proof_hardening_check, "print") as print_mock:
            exit_code = proof_hardening_check.main(
                [
                    "--output-dir",
                    tmpdir,
                    "--proof-test",
                    "tests/test_security_kernel.py",
                    "--skip-mutations",
                    "--python-executable",
                    "python",
                ]
            )

        self.assertEqual(exit_code, 0)
        report = json.loads(print_mock.call_args.args[0])
        self.assertTrue(report["passed"])


if __name__ == "__main__":
    unittest.main()
