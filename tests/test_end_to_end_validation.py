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
        {
            "scenario": "unauthorized_tool_scope",
            "passed": True,
            "expected_reason": "unauthorized_tool_scope",
            "observed_reason": "unauthorized_tool_scope",
            "side_effect_triggered": False,
            "local_agent_run_count": 1,
        },
    ]


def _real_negative_summary() -> dict[str, object]:
    """构造真实服务负向 runner 的最小 summary fixture。"""
    return {
        "scenario_count": 3,
        "passed_count": 3,
        "failed_count": 0,
        "all_passed": True,
        "failed_scenarios": [],
        "scenarios": [
            "missing_request_envelope",
            "tampered_message",
            "unauthorized_tool_scope",
        ],
    }


def _mutation_evidence_results() -> list[dict[str, object]]:
    """构造 mutation evidence runner 的最小结果 fixture。"""
    return [
        {
            "mutation_id": "skip_replay_reserve",
            "mutation_detected": True,
            "returncode": 1,
            "command": ["python", "-m", "pytest", "tests/test_execution_gate.py"],
            "workspace": "/tmp/saga-mut/repo",
            "applied": True,
            "stdout_tail": "failed as expected",
            "stderr_tail": "",
            "error": "",
            "dry_run": False,
        }
    ]


def _mutation_evidence_summary() -> dict[str, object]:
    """构造 mutation evidence runner 的最小 summary fixture。"""
    return {
        "mutation_count": 1,
        "detected_count": 1,
        "undetected_count": 0,
        "all_detected": True,
        "dry_run": False,
        "detected_mutations": ["skip_replay_reserve"],
        "undetected_mutations": [],
        "mutations": ["skip_replay_reserve"],
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

    def test_positive_batch_summary_rejects_empty_evidence(self) -> None:
        """正向 artifact 不能用空任务列表伪装成通过证据。"""
        summary = {
            "task_count": 0,
            "succeeded_count": 0,
            "failed_count": 0,
            "audit_record_count": 0,
            "tasks": [],
        }

        report = end_to_end_validation.validate_positive_batch_summary(summary)

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("task_count must be positive", reasons)
        self.assertIn("positive task list is empty", reasons)

    def test_real_negative_artifacts_accept_fail_closed_no_side_effects(self) -> None:
        """真实负向产物必须全部拒绝且没有触发本地执行副作用。"""
        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=_real_negative_summary(),
            results=_real_negative_results(),
            required_scenarios=("missing_request_envelope", "tampered_message"),
        )

        self.assertTrue(report.passed)
        payload = report.as_dict()
        metadata = payload["metadata"]
        assert isinstance(metadata, dict)
        security_evidence = metadata["security_evidence"]
        assert isinstance(security_evidence, dict)
        self.assertEqual(security_evidence["source"], "real_negative_runner")
        self.assertEqual(
            security_evidence["required_scenarios"],
            ["missing_request_envelope", "tampered_message"],
        )
        coverage = security_evidence["coverage"]
        assert isinstance(coverage, dict)
        properties = coverage["properties"]
        assert isinstance(properties, dict)
        self.assertGreater(
            properties["side_effect_free_rejection"]["evidence_count"],
            0,
        )

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
        self.assertIn("local_agent_run_count is not 0", reasons)

    def test_real_negative_artifacts_reject_reason_not_in_evidence_map(self) -> None:
        """真实负向 expected reason 必须匹配 U10 证据映射。"""
        results = _real_negative_results()
        results[1]["expected_reason"] = "wrong_reason"

        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=_real_negative_summary(),
            results=results,
        )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("expected_reason does not match security evidence map", reasons)
        self.assertIn("observed_reason does not match expected_reason", reasons)

    def test_real_negative_artifacts_reject_unmapped_scenario(self) -> None:
        """真实负向 artifact 中出现未映射场景时验收失败。"""
        results = _real_negative_results()
        results.append(
            {
                "scenario": "unmapped_probe",
                "passed": True,
                "expected_reason": "reject",
                "observed_reason": "reject",
                "side_effect_triggered": False,
                "local_agent_run_count": 0,
            }
        )
        summary = _real_negative_summary()
        summary["scenario_count"] = 4
        summary["passed_count"] = 4
        summary["scenarios"] = [
            "missing_request_envelope",
            "tampered_message",
            "unauthorized_tool_scope",
            "unmapped_probe",
        ]

        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=summary,
            results=results,
        )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("scenario is missing from security evidence map", reasons)

    def test_real_negative_artifacts_reject_empty_evidence(self) -> None:
        """真实负向 artifact 不能用空场景列表伪装成 fail-closed 证据。"""
        summary = {
            "scenario_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "all_passed": True,
            "failed_scenarios": [],
            "scenarios": [],
        }

        report = end_to_end_validation.validate_real_negative_artifacts(
            summary=summary,
            results=[],
        )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("scenario_count must be positive", reasons)
        self.assertIn("real negative result list is empty", reasons)

    def test_mutation_evidence_artifacts_accept_detected_mutation(self) -> None:
        """mutation evidence artifact 必须证明指定 mutation 被测试检出。"""
        report = end_to_end_validation.validate_mutation_evidence_artifacts(
            summary=_mutation_evidence_summary(),
            results=_mutation_evidence_results(),
            required_mutations=("skip_replay_reserve",),
        )

        self.assertTrue(report.passed)
        payload = report.as_dict()
        metadata = payload["metadata"]
        assert isinstance(metadata, dict)
        mutation_metadata = metadata["mutation_evidence"]
        assert isinstance(mutation_metadata, dict)
        self.assertEqual(mutation_metadata["source"], "mutation_evidence_runner")
        self.assertEqual(
            mutation_metadata["validated_mutations"],
            ["skip_replay_reserve"],
        )

    def test_mutation_evidence_artifacts_reject_dry_run_and_collection_error(self) -> None:
        """dry-run 或 pytest collection error 不能算作有效 mutation 证据。"""
        summary = _mutation_evidence_summary()
        summary["all_detected"] = False
        summary["dry_run"] = True
        summary["undetected_count"] = 1
        summary["undetected_mutations"] = ["skip_replay_reserve"]
        results = _mutation_evidence_results()
        results[0]["mutation_detected"] = False
        results[0]["returncode"] = 4
        results[0]["applied"] = False
        results[0]["dry_run"] = True
        results[0]["error"] = "pytest collection failed"

        report = end_to_end_validation.validate_mutation_evidence_artifacts(
            summary=summary,
            results=results,
            required_mutations=("skip_replay_reserve",),
        )

        self.assertFalse(report.passed)
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("all_detected is not true", reasons)
        self.assertIn("dry_run artifact is not evidence", reasons)
        self.assertIn("mutation was not detected", reasons)
        self.assertIn("mutation patch was not applied", reasons)
        self.assertIn("dry-run row is not evidence", reasons)
        self.assertIn(
            "pytest returncode is not the expected test-failure code 1",
            reasons,
        )
        self.assertIn("mutation runner recorded an error", reasons)

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
            mutation_dir = root / "mutation_evidence"
            mutation_dir.mkdir()
            (mutation_dir / "mutation_evidence_summary.json").write_text(
                json.dumps(_mutation_evidence_summary(), sort_keys=True),
                encoding="utf-8",
            )
            (mutation_dir / "mutation_evidence.jsonl").write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n"
                    for row in _mutation_evidence_results()
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
                        "--mutation-evidence-run-dir",
                        str(mutation_dir),
                        "--required-mutation",
                        "skip_replay_reserve",
                    ]
                )

        self.assertEqual(exit_code, 0)
        report = json.loads(print_mock.call_args.args[0])
        self.assertTrue(report["passed"])
        metadata = report["metadata"]
        self.assertEqual(len(metadata["reports"]), 2)
        security_evidence = metadata["reports"][0]["security_evidence"]
        self.assertEqual(security_evidence["source"], "real_negative_runner")
        self.assertIn(
            "missing_request_envelope",
            security_evidence["validated_scenarios"],
        )
        self.assertIn("coverage", security_evidence)
        mutation_evidence = metadata["reports"][1]["mutation_evidence"]
        self.assertEqual(mutation_evidence["source"], "mutation_evidence_runner")
        self.assertEqual(
            mutation_evidence["required_mutations"],
            ["skip_replay_reserve"],
        )

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
