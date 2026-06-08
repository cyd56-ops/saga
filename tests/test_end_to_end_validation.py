"""Tests for offline end-to-end artifact validation."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments import end_to_end_validation


def _positive_summary(*, runtime_auth_enabled: bool = True) -> dict[str, object]:
    """构造最小正向 batch summary fixture。"""
    return {
        "task_count": 2,
        "succeeded_count": 2,
        "failed_count": 0,
        "audit_record_count": 0,
        "tasks": [
            {
                "task_name": "schedule_meeting",
                "success": True,
                "runtime_auth_enabled": runtime_auth_enabled,
                "audit_reject_count": 0,
                "peer_audit_reject_count": 0,
            },
            {
                "task_name": "expense_report",
                "success": True,
                "runtime_auth_enabled": runtime_auth_enabled,
                "audit_reject_count": 0,
                "peer_audit_reject_count": 0,
            },
        ],
    }


def _real_negative_results() -> list[dict[str, object]]:
    """构造真实服务负向 runner 的最小结果 fixture。"""
    return [
        {
            "scenario": "missing_request_envelope",
            "passed": True,
            "expected_reason": "missing_request_envelope",
            "observed_reason": "missing_request_envelope",
            "side_effect_triggered": False,
            "local_agent_run_count": 0,
        },
        {
            "scenario": "tampered_message",
            "passed": True,
            "expected_reason": "message_digest_mismatch",
            "observed_reason": "message_digest_mismatch",
            "side_effect_triggered": False,
            "local_agent_run_count": 0,
        },
    ]


def _real_negative_summary() -> dict[str, object]:
    """构造真实服务负向 runner 的最小 summary fixture。"""
    return {
        "scenario_count": 2,
        "passed_count": 2,
        "failed_count": 0,
        "all_passed": True,
        "failed_scenarios": [],
        "scenarios": ["missing_request_envelope", "tampered_message"],
    }


class EndToEndValidationTests(unittest.TestCase):
    """Verify artifact-level end-to-end acceptance checks."""

    def test_positive_batch_summary_accepts_all_success_no_rejects(self) -> None:
        """正向 summary 必须全任务成功且无 gate reject。"""
        report = end_to_end_validation.validate_positive_batch_summary(
            _positive_summary(),
            expected_task_count=2,
            expected_runtime_auth_enabled=True,
        )

        self.assertTrue(report.passed)
        self.assertEqual(report.findings, ())

    def test_positive_batch_summary_rejects_gate_rejects_and_failed_tasks(self) -> None:
        """正向 summary 中失败任务或 gate reject 必须让验收失败。"""
        summary = _positive_summary()
        tasks = summary["tasks"]
        assert isinstance(tasks, list)
        tasks[0]["success"] = False
        tasks[1]["peer_audit_reject_count"] = 1
        summary["succeeded_count"] = 1
        summary["failed_count"] = 1
        summary["audit_record_count"] = 1

        report = end_to_end_validation.validate_positive_batch_summary(summary)

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("positive task did not succeed", reasons)
        self.assertIn("peer_audit_reject_count is not zero", reasons)
        self.assertIn("audit_record_count is not zero", reasons)

    def test_real_negative_artifacts_accept_fail_closed_no_side_effects(self) -> None:
        """真实负向产物必须全部拒绝且没有触发本地执行副作用。"""
        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=_real_negative_summary(),
            results=_real_negative_results(),
            required_scenarios=("missing_request_envelope", "tampered_message"),
        )

        self.assertTrue(report.passed)

    def test_real_negative_artifacts_reject_missing_scenario_and_side_effect(self) -> None:
        """缺少必需场景或出现 local_agent.run 副作用时验收失败。"""
        results = _real_negative_results()
        results[0]["side_effect_triggered"] = True
        results[0]["local_agent_run_count"] = 1

        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=_real_negative_summary(),
            results=results,
            required_scenarios=("wrong_trusted_sender_key",),
        )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("missing required scenario wrong_trusted_sender_key", reasons)
        self.assertIn("side effect was triggered", reasons)
        self.assertIn("local_agent_run_count is not zero", reasons)

    def test_file_loaders_and_cli_validate_artifacts(self) -> None:
        """CLI 应能离线读取 summary / JSONL 并返回稳定状态码。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline_path = root / "baseline_summary.json"
            baseline_path.write_text(
                json.dumps(
                    _positive_summary(runtime_auth_enabled=False),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            pq_can_path = root / "pq_can_summary.json"
            pq_can_path.write_text(
                json.dumps(
                    _positive_summary(runtime_auth_enabled=True),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            real_dir = root / "real_negative"
            real_dir.mkdir()
            (real_dir / "real_negative_summary.json").write_text(
                json.dumps(_real_negative_summary(), sort_keys=True),
                encoding="utf-8",
            )
            (real_dir / "real_negative_results.jsonl").write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n"
                    for row in _real_negative_results()
                ),
                encoding="utf-8",
            )

            with mock.patch.object(end_to_end_validation, "print") as print_mock:
                exit_code = end_to_end_validation.main(
                    [
                        "--baseline-summary",
                        str(baseline_path),
                        "--pq-can-summary",
                        str(pq_can_path),
                        "--positive-task-count",
                        "2",
                        "--real-negative-run-dir",
                        str(real_dir),
                        "--required-real-negative-scenario",
                        "missing_request_envelope",
                    ]
                )

        self.assertEqual(exit_code, 0)
        report = json.loads(print_mock.call_args.args[0])
        self.assertTrue(report["passed"])

    def test_cli_returns_nonzero_for_invalid_artifact(self) -> None:
        """任一产物不满足验收条件时 CLI 必须返回非零。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            positive_path = Path(tmpdir) / "end_to_end_stats_summary.json"
            summary = _positive_summary()
            summary["task_count"] = 3
            positive_path.write_text(
                json.dumps(summary, sort_keys=True),
                encoding="utf-8",
            )

            with mock.patch.object(end_to_end_validation, "print") as print_mock:
                exit_code = end_to_end_validation.main(
                    ["--positive-summary", str(positive_path)]
                )

        self.assertEqual(exit_code, 1)
        report = json.loads(print_mock.call_args.args[0])
        self.assertFalse(report["passed"])

    def test_cli_returns_nonzero_without_artifacts(self) -> None:
        """未提供任何验收产物时 CLI 不能返回成功。"""
        with mock.patch.object(end_to_end_validation, "print") as print_mock:
            exit_code = end_to_end_validation.main([])

        self.assertEqual(exit_code, 1)
        report = json.loads(print_mock.call_args.args[0])
        self.assertFalse(report["passed"])
        self.assertEqual(report["findings"][0]["reason"], "no artifacts were provided")


if __name__ == "__main__":
    unittest.main()
