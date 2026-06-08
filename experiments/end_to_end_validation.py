"""Validate end-to-end experiment artifacts without starting live services."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArtifactValidationFinding:
    """记录端到端产物验收中发现的单个问题。"""

    artifact: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        """返回可写入 JSON 报告的稳定字典。"""
        return {
            "artifact": self.artifact,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ArtifactValidationReport:
    """汇总端到端产物验收结果。"""

    passed: bool
    findings: tuple[ArtifactValidationFinding, ...]

    def as_dict(self) -> dict[str, object]:
        """返回可机器读取的验收报告。"""
        return {
            "passed": self.passed,
            "finding_count": len(self.findings),
            "findings": [finding.as_dict() for finding in self.findings],
        }


def validate_positive_batch_summary(
    summary: Mapping[str, Any],
    *,
    artifact_name: str = "end_to_end_stats_summary.json",
    expected_task_count: int | None = None,
    expected_runtime_auth_enabled: bool | None = None,
    require_no_gate_rejects: bool = True,
) -> ArtifactValidationReport:
    """校验正向 batch summary 是否满足端到端成功和审计口径。"""
    findings: list[ArtifactValidationFinding] = []
    tasks = _tasks(summary, artifact_name, findings)
    task_count = _int_field(summary, "task_count", artifact_name, findings)
    succeeded_count = _int_field(summary, "succeeded_count", artifact_name, findings)
    failed_count = _int_field(summary, "failed_count", artifact_name, findings)

    if expected_task_count is not None and task_count != expected_task_count:
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                f"expected task_count={expected_task_count}, observed {task_count}",
            )
        )
    if task_count != len(tasks):
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                f"task_count={task_count} does not match tasks length={len(tasks)}",
            )
        )

    observed_successes = sum(1 for task in tasks if task.get("success") is True)
    if succeeded_count != observed_successes:
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                f"succeeded_count={succeeded_count} does not match task successes={observed_successes}",
            )
        )
    if failed_count != task_count - succeeded_count:
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                f"failed_count={failed_count} does not match task_count-succeeded_count={task_count - succeeded_count}",
            )
        )

    for index, task in enumerate(tasks):
        task_name = str(task.get("task_name", f"task[{index}]"))
        task_artifact = f"{artifact_name}:{task_name}"
        if task.get("success") is not True:
            findings.append(
                ArtifactValidationFinding(task_artifact, "positive task did not succeed")
            )
        if (
            expected_runtime_auth_enabled is not None
            and task.get("runtime_auth_enabled") is not expected_runtime_auth_enabled
        ):
            findings.append(
                ArtifactValidationFinding(
                    task_artifact,
                    "runtime_auth_enabled does not match expected mode",
                )
            )
        if require_no_gate_rejects:
            _require_zero_int(task, "audit_reject_count", task_artifact, findings)
            _require_zero_int(task, "peer_audit_reject_count", task_artifact, findings)

    if require_no_gate_rejects:
        _require_zero_int(summary, "audit_record_count", artifact_name, findings)

    return _report(findings)


def validate_real_negative_artifacts(
    *,
    summary: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    artifact_name: str = "real_negative_summary.json",
    required_scenarios: Iterable[str] | None = None,
) -> ArtifactValidationReport:
    """校验真实服务负向产物是否全部 fail-closed 且没有本地副作用。"""
    findings: list[ArtifactValidationFinding] = []
    scenario_count = _int_field(summary, "scenario_count", artifact_name, findings)
    passed_count = _int_field(summary, "passed_count", artifact_name, findings)
    failed_count = _int_field(summary, "failed_count", artifact_name, findings)

    if scenario_count != len(results):
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                f"scenario_count={scenario_count} does not match results length={len(results)}",
            )
        )
    if passed_count != sum(1 for result in results if result.get("passed") is True):
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                "passed_count does not match result rows",
            )
        )
    if failed_count != scenario_count - passed_count:
        findings.append(
            ArtifactValidationFinding(
                artifact_name,
                "failed_count does not match scenario_count-passed_count",
            )
        )
    if summary.get("all_passed") is not True:
        findings.append(ArtifactValidationFinding(artifact_name, "all_passed is not true"))

    scenarios = {str(result.get("scenario", "")) for result in results}
    for scenario in required_scenarios or ():
        if scenario not in scenarios:
            findings.append(
                ArtifactValidationFinding(
                    artifact_name,
                    f"missing required scenario {scenario}",
                )
            )

    for index, result in enumerate(results):
        scenario = str(result.get("scenario", f"result[{index}]"))
        result_artifact = f"real_negative_results.jsonl:{scenario}"
        if result.get("passed") is not True:
            findings.append(
                ArtifactValidationFinding(result_artifact, "negative scenario did not pass")
            )
        if result.get("observed_reason") != result.get("expected_reason"):
            findings.append(
                ArtifactValidationFinding(
                    result_artifact,
                    "observed_reason does not match expected_reason",
                )
            )
        if result.get("side_effect_triggered") is not False:
            findings.append(
                ArtifactValidationFinding(result_artifact, "side effect was triggered")
            )
        if _int_value(result.get("local_agent_run_count")) != 0:
            findings.append(
                ArtifactValidationFinding(
                    result_artifact,
                    "local_agent_run_count is not zero",
                )
            )

    return _report(findings)


def load_json_object(path: str | Path) -> dict[str, Any]:
    """读取 JSON 文件并要求顶层为对象。"""
    payload_path = Path(path)
    with payload_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{payload_path} must contain a JSON object")
    return payload


def load_jsonl_objects(path: str | Path) -> list[dict[str, Any]]:
    """读取 JSONL 文件并要求每一行都是对象。"""
    payload_path = Path(path)
    rows: list[dict[str, Any]] = []
    with payload_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            if not isinstance(payload, dict):
                raise ValueError(f"{payload_path}:{line_number} must contain a JSON object")
            rows.append(payload)
    return rows


def validate_positive_summary_file(
    path: str | Path,
    *,
    expected_task_count: int | None = None,
    expected_runtime_auth_enabled: bool | None = None,
    require_no_gate_rejects: bool = True,
) -> ArtifactValidationReport:
    """从文件读取并校验正向 batch summary。"""
    summary_path = Path(path)
    return validate_positive_batch_summary(
        load_json_object(summary_path),
        artifact_name=str(summary_path),
        expected_task_count=expected_task_count,
        expected_runtime_auth_enabled=expected_runtime_auth_enabled,
        require_no_gate_rejects=require_no_gate_rejects,
    )


def validate_real_negative_run_dir(
    run_dir: str | Path,
    *,
    required_scenarios: Iterable[str] | None = None,
) -> ArtifactValidationReport:
    """从真实服务负向 run 目录读取 summary 和 JSONL 并校验。"""
    run_path = Path(run_dir)
    return validate_real_negative_artifacts(
        summary=load_json_object(run_path / "real_negative_summary.json"),
        results=load_jsonl_objects(run_path / "real_negative_results.jsonl"),
        artifact_name=str(run_path / "real_negative_summary.json"),
        required_scenarios=required_scenarios,
    )


def combine_reports(reports: Iterable[ArtifactValidationReport]) -> ArtifactValidationReport:
    """合并多个验收报告，用于一次 CLI 同时校验多类产物。"""
    findings = tuple(
        finding
        for report in reports
        for finding in report.findings
    )
    return ArtifactValidationReport(passed=not findings, findings=findings)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析端到端产物验收 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description="Validate SAGA-PQ-CAN end-to-end result artifacts."
    )
    parser.add_argument(
        "--baseline-summary",
        action="append",
        default=[],
        help="Positive baseline end_to_end_stats_summary.json; expects runtime auth disabled.",
    )
    parser.add_argument(
        "--pq-can-summary",
        action="append",
        default=[],
        help="Positive PQ-CAN end_to_end_stats_summary.json; expects runtime auth enabled.",
    )
    parser.add_argument("--positive-summary", action="append", default=[])
    parser.add_argument("--positive-task-count", type=int)
    parser.add_argument(
        "--positive-runtime-auth",
        choices=("true", "false"),
        help="Expected runtime_auth_enabled value for every positive task.",
    )
    parser.add_argument(
        "--allow-positive-gate-rejects",
        action="store_true",
        help="Do not require positive task audit reject counts to be zero.",
    )
    parser.add_argument("--real-negative-run-dir", action="append", default=[])
    parser.add_argument("--required-real-negative-scenario", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """运行离线端到端产物验收；任一产物失败则返回非零。"""
    args = parse_args(argv)
    runtime_auth_expected = _parse_optional_bool(args.positive_runtime_auth)
    if not args.baseline_summary and not args.pq_can_summary and not args.positive_summary and not args.real_negative_run_dir:
        report = ArtifactValidationReport(
            passed=False,
            findings=(
                ArtifactValidationFinding(
                    "cli",
                    "no artifacts were provided",
                ),
            ),
        )
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
        return 1

    reports = [
        validate_positive_summary_file(
            path,
            expected_task_count=args.positive_task_count,
            expected_runtime_auth_enabled=False,
            require_no_gate_rejects=not args.allow_positive_gate_rejects,
        )
        for path in args.baseline_summary
    ]
    reports.extend(
        validate_positive_summary_file(
            path,
            expected_task_count=args.positive_task_count,
            expected_runtime_auth_enabled=True,
            require_no_gate_rejects=not args.allow_positive_gate_rejects,
        )
        for path in args.pq_can_summary
    )
    reports.extend(
        validate_positive_summary_file(
            path,
            expected_task_count=args.positive_task_count,
            expected_runtime_auth_enabled=runtime_auth_expected,
            require_no_gate_rejects=not args.allow_positive_gate_rejects,
        )
        for path in args.positive_summary
    )
    reports.extend(
        validate_real_negative_run_dir(
            run_dir,
            required_scenarios=args.required_real_negative_scenario,
        )
        for run_dir in args.real_negative_run_dir
    )
    report = combine_reports(reports)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.passed else 1


def _tasks(
    summary: Mapping[str, Any],
    artifact_name: str,
    findings: list[ArtifactValidationFinding],
) -> list[Mapping[str, Any]]:
    tasks = summary.get("tasks", [])
    if not isinstance(tasks, list):
        findings.append(ArtifactValidationFinding(artifact_name, "tasks is not a list"))
        return []
    if not all(isinstance(task, Mapping) for task in tasks):
        findings.append(
            ArtifactValidationFinding(artifact_name, "tasks contains non-object rows")
        )
        return []
    return tasks


def _int_field(
    payload: Mapping[str, Any],
    field_name: str,
    artifact_name: str,
    findings: list[ArtifactValidationFinding],
) -> int:
    value = payload.get(field_name)
    parsed = _int_value(value)
    if parsed is None:
        findings.append(
            ArtifactValidationFinding(artifact_name, f"{field_name} is not an integer")
        )
        return 0
    return parsed


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _require_zero_int(
    payload: Mapping[str, Any],
    field_name: str,
    artifact_name: str,
    findings: list[ArtifactValidationFinding],
) -> None:
    value = _int_field(payload, field_name, artifact_name, findings)
    if value != 0:
        findings.append(
            ArtifactValidationFinding(artifact_name, f"{field_name} is not zero")
        )


def _report(findings: Sequence[ArtifactValidationFinding]) -> ArtifactValidationReport:
    return ArtifactValidationReport(passed=not findings, findings=tuple(findings))


def _parse_optional_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value == "true"


if __name__ == "__main__":
    raise SystemExit(main())
