"""Opt-in real end-to-end ablation runner for SAGA-PQ-CAN."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Literal

from experiments import preflight as experiment_preflight
from experiments.paper_tables import (
    DEFAULT_BASELINE_SUMMARY_PATH,
    DEFAULT_PQ_CAN_SUMMARY_PATH,
    load_end_to_end_summary,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_BATCH_SCRIPT = REPO_ROOT / "experiments" / "batch_run.py"
DEFAULT_TASKS = ("all",)

REAL_ABLATION_MODE_ORDER = (
    "saga_only",
    "ordinary_pq_middleware",
    "naive_neural_verifier",
    "shamir_secured_pq_can",
)


@dataclass(frozen=True)
class RealAblationMode:
    """描述一个真实端到端消融 mode 的当前接入状态。"""

    mode_id: str
    title: str
    live_supported: bool
    expected_runtime_auth_enabled: bool | None
    initiator_config: Path | None
    receiver_config: Path | None
    default_summary_path: Path | None
    notes: str

    def as_dict(self) -> dict[str, object]:
        """返回可 JSON 序列化的 mode 描述，供计划和报告复用。"""
        return {
            "mode": self.mode_id,
            "title": self.title,
            "live_supported": self.live_supported,
            "expected_runtime_auth_enabled": self.expected_runtime_auth_enabled,
            "initiator_config": (
                str(self.initiator_config) if self.initiator_config is not None else None
            ),
            "receiver_config": (
                str(self.receiver_config) if self.receiver_config is not None else None
            ),
            "default_summary_path": (
                str(self.default_summary_path)
                if self.default_summary_path is not None
                else None
            ),
            "notes": self.notes,
        }


REAL_ABLATION_MODES: tuple[RealAblationMode, ...] = (
    RealAblationMode(
        mode_id="saga_only",
        title="SAGA Only",
        live_supported=True,
        expected_runtime_auth_enabled=False,
        initiator_config=REPO_ROOT / "user_configs" / "emma.yaml",
        receiver_config=REPO_ROOT / "user_configs" / "raj.yaml",
        default_summary_path=DEFAULT_BASELINE_SUMMARY_PATH,
        notes="Real baseline batch with protocol admission and runtime auth disabled.",
    ),
    RealAblationMode(
        mode_id="ordinary_pq_middleware",
        title="Ordinary PQ Middleware",
        live_supported=False,
        expected_runtime_auth_enabled=None,
        initiator_config=None,
        receiver_config=None,
        default_summary_path=None,
        notes=(
            "Offline-only in the current prototype; no real Agent runtime wiring "
            "exists for byte-level PQ verification without execution-surface policy."
        ),
    ),
    RealAblationMode(
        mode_id="naive_neural_verifier",
        title="Naive Neural Verifier",
        live_supported=False,
        expected_runtime_auth_enabled=None,
        initiator_config=None,
        receiver_config=None,
        default_summary_path=None,
        notes=(
            "Offline-only in the current prototype; no real Agent runtime wiring "
            "exists for compiled verification without Shamir MASK and scope policy."
        ),
    ),
    RealAblationMode(
        mode_id="shamir_secured_pq_can",
        title="Shamir-Secured PQ-CAN",
        live_supported=True,
        expected_runtime_auth_enabled=True,
        initiator_config=REPO_ROOT / "user_configs" / "emma_pqcan.yaml",
        receiver_config=REPO_ROOT / "user_configs" / "raj_pqcan.yaml",
        default_summary_path=DEFAULT_PQ_CAN_SUMMARY_PATH,
        notes="Real PQ-CAN batch with signed intent runtime auth enabled.",
    ),
)

REAL_ABLATION_MODES_BY_ID = {
    mode.mode_id: mode
    for mode in REAL_ABLATION_MODES
}


def selected_real_ablation_modes(
    mode_ids: Sequence[str] | None = None,
) -> tuple[RealAblationMode, ...]:
    """按稳定顺序返回选中的真实端到端消融 mode。"""
    if not mode_ids:
        return REAL_ABLATION_MODES
    selected: list[RealAblationMode] = []
    seen: set[str] = set()
    for mode_id in mode_ids:
        if mode_id in seen:
            continue
        seen.add(mode_id)
        try:
            selected.append(REAL_ABLATION_MODES_BY_ID[mode_id])
        except KeyError as exc:
            raise ValueError(f"unknown real ablation mode: {mode_id}") from exc
    return tuple(selected)


def build_batch_command(
    mode: RealAblationMode,
    *,
    run_dir: str | Path,
    task_names: Sequence[str] = DEFAULT_TASKS,
    python_executable: str = sys.executable,
    batch_script: str | Path = DEFAULT_BATCH_SCRIPT,
    probe_required_successes: int | None = None,
    probe_max_attempts: int | None = None,
    probe_interval_seconds: float | None = None,
    model_probe_timeout_seconds: float | None = None,
    skip_model_probe: bool = False,
    skip_db_preflight: bool = False,
    skip_seed: bool = False,
    allow_task_failure: bool = False,
) -> list[str]:
    """为一个已接入真实 runtime 的 mode 构造 batch_run 命令。"""
    if not mode.live_supported:
        raise ValueError(f"{mode.mode_id} is not wired for real end-to-end runs")
    if mode.initiator_config is None or mode.receiver_config is None:
        raise ValueError(f"{mode.mode_id} is missing real run configs")

    command = [
        python_executable,
        str(batch_script),
    ]
    for task_name in task_names:
        command.extend(["--task", task_name])
    command.extend(
        [
            "--initiator-config",
            str(mode.initiator_config),
            "--receiver-config",
            str(mode.receiver_config),
            "--run-dir",
            str(run_dir),
            "--python",
            python_executable,
        ]
    )
    if probe_required_successes is not None:
        command.extend(["--probe-required-successes", str(probe_required_successes)])
    if probe_max_attempts is not None:
        command.extend(["--probe-max-attempts", str(probe_max_attempts)])
    if probe_interval_seconds is not None:
        command.extend(["--probe-interval", str(probe_interval_seconds)])
    if model_probe_timeout_seconds is not None:
        command.extend(["--model-probe-timeout", str(model_probe_timeout_seconds)])
    if skip_model_probe:
        command.append("--skip-model-probe")
    if skip_db_preflight:
        command.append("--skip-db-preflight")
    if skip_seed:
        command.append("--skip-seed")
    if allow_task_failure:
        command.append("--allow-task-failure")
    return command


def build_real_ablation_plan(
    *,
    mode_ids: Sequence[str] | None = None,
) -> dict[str, object]:
    """生成真实端到端消融计划，明确哪些 mode 尚未接入真实 runtime。"""
    modes = selected_real_ablation_modes(mode_ids)
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "mode_order": [mode.mode_id for mode in modes],
        "live_supported_modes": [
            mode.mode_id for mode in modes if mode.live_supported
        ],
        "offline_only_modes": [
            mode.mode_id for mode in modes if not mode.live_supported
        ],
        "modes": [mode.as_dict() for mode in modes],
        "notes": {
            "ordinary_pq_middleware": (
                "Current real Agent runtime does not expose a byte-level PQ-only "
                "execution path; use offline ablation evidence for this mode."
            ),
            "naive_neural_verifier": (
                "Current real Agent runtime does not expose a no-MASK neural "
                "verifier path; use offline ablation evidence for this mode."
            ),
            "live_runs": (
                "The run subcommand starts local services and model-backed tasks; "
                "use it only as an explicit opt-in experiment."
            ),
        },
    }


def build_real_ablation_summary(
    *,
    summary_paths: Mapping[str, str | Path] | None = None,
    mode_ids: Sequence[str] | None = None,
) -> dict[str, object]:
    """从真实 batch summary 构造端到端消融汇总。"""
    path_overrides = {
        mode_id: Path(path)
        for mode_id, path in (summary_paths or {}).items()
    }
    modes = selected_real_ablation_modes(mode_ids)
    rows = [
        _build_mode_summary_row(
            mode,
            summary_path=path_overrides.get(mode.mode_id, mode.default_summary_path),
        )
        for mode in modes
    ]
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "mode_order": [mode.mode_id for mode in modes],
        "rows": rows,
        "live_supported_modes": [
            mode.mode_id for mode in modes if mode.live_supported
        ],
        "offline_only_modes": [
            mode.mode_id for mode in modes if not mode.live_supported
        ],
        "notes": {
            "scope": (
                "This summary reports real end-to-end task batches only for modes "
                "wired into the current Agent runtime."
            ),
            "offline_only": (
                "ordinary_pq_middleware and naive_neural_verifier remain offline "
                "ablation modes until dedicated real-runtime adapters are added."
            ),
            "api_cost": (
                "API cost and token usage are copied only from explicit model "
                "diagnostics in end_to_end_stats_summary.json."
            ),
        },
    }


def live_real_ablation_config_paths(
    mode_ids: Sequence[str] | None = None,
) -> tuple[Path, ...]:
    """返回选中真实消融 live mode 需要预检的用户配置路径。"""
    config_paths: list[Path] = []
    seen: set[Path] = set()
    for mode in selected_real_ablation_modes(mode_ids):
        if not mode.live_supported:
            continue
        for config_path in (mode.initiator_config, mode.receiver_config):
            if config_path is None or config_path in seen:
                continue
            seen.add(config_path)
            config_paths.append(config_path)
    return tuple(config_paths)


def build_real_ablation_preflight_report(
    *,
    mode_ids: Sequence[str] | None = None,
    check_db_sync: bool = False,
    check_model_backends: bool = False,
    model_probe_timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """运行不启动服务的真实消融预检，并返回机器可读报告。"""
    modes = selected_real_ablation_modes(mode_ids)
    live_modes = [mode for mode in modes if mode.live_supported]
    config_paths = live_real_ablation_config_paths(mode_ids)
    if not live_modes:
        return {
            "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
            "ok": False,
            "status": "no_live_supported_modes_selected",
            "mode_order": [mode.mode_id for mode in modes],
            "live_supported_modes": [],
            "offline_only_modes": [
                mode.mode_id for mode in modes if not mode.live_supported
            ],
            "config_paths": [],
            "check_db_sync": check_db_sync,
            "check_model_backends": check_model_backends,
            "model_probe_timeout_seconds": model_probe_timeout_seconds,
            "results": [],
            "failed_checks": [],
            "notes": {
                "scope": (
                    "Only live-supported modes have user configs that can be "
                    "preflighted before a real end-to-end batch."
                ),
            },
        }

    results = experiment_preflight.run_preflight_checks(
        config_paths=config_paths,
        check_db_sync=check_db_sync,
        check_model_backends=check_model_backends,
        model_probe_timeout_seconds=model_probe_timeout_seconds,
    )
    failed_checks = [result.name for result in results if not result.ok]
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "ok": not failed_checks,
        "status": "passed" if not failed_checks else "failed",
        "mode_order": [mode.mode_id for mode in modes],
        "live_supported_modes": [mode.mode_id for mode in live_modes],
        "offline_only_modes": [
            mode.mode_id for mode in modes if not mode.live_supported
        ],
        "config_paths": [str(path) for path in config_paths],
        "check_db_sync": check_db_sync,
        "check_model_backends": check_model_backends,
        "model_probe_timeout_seconds": model_probe_timeout_seconds,
        "results": [_check_result_as_dict(result) for result in results],
        "failed_checks": failed_checks,
        "notes": {
            "scope": (
                "This preflight does not start MongoDB, CA, Provider, listeners, "
                "or model-backed tasks. Model probes run only when explicitly "
                "requested."
            ),
        },
    }


def write_real_ablation_preflight_report(
    report: Mapping[str, object],
    output_dir: str | Path,
) -> Path:
    """将真实消融预检报告写入稳定 JSON 文件。"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    report_path = output_path / "real_ablation_preflight.json"
    report_path.write_text(
        json.dumps(dict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def run_live_real_ablation(
    *,
    output_dir: str | Path,
    mode_ids: Sequence[str] | None = None,
    task_names: Sequence[str] = DEFAULT_TASKS,
    python_executable: str = sys.executable,
    probe_required_successes: int | None = None,
    probe_max_attempts: int | None = None,
    probe_interval_seconds: float | None = None,
    model_probe_timeout_seconds: float | None = None,
    skip_model_probe: bool = False,
    skip_db_preflight: bool = False,
    skip_seed: bool = False,
    allow_task_failure: bool = False,
) -> dict[str, object]:
    """显式运行已接入真实 runtime 的端到端消融 mode，并返回汇总。"""
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    summary_paths: dict[str, Path] = {}
    commands: dict[str, list[str]] = {}
    for mode in selected_real_ablation_modes(mode_ids):
        if not mode.live_supported:
            continue
        run_dir = base_dir / mode.mode_id
        command = build_batch_command(
            mode,
            run_dir=run_dir,
            task_names=task_names,
            python_executable=python_executable,
            probe_required_successes=probe_required_successes,
            probe_max_attempts=probe_max_attempts,
            probe_interval_seconds=probe_interval_seconds,
            model_probe_timeout_seconds=model_probe_timeout_seconds,
            skip_model_probe=skip_model_probe,
            skip_db_preflight=skip_db_preflight,
            skip_seed=skip_seed,
            allow_task_failure=allow_task_failure,
        )
        commands[mode.mode_id] = command
        subprocess.run(command, check=True)
        summary_paths[mode.mode_id] = run_dir / "end_to_end_stats_summary.json"

    summary = build_real_ablation_summary(
        summary_paths=summary_paths,
        mode_ids=mode_ids,
    )
    summary["commands"] = commands
    summary_path = write_real_ablation_summary(summary, base_dir)
    summary["summary_path"] = str(summary_path)
    return summary


def write_real_ablation_summary(
    summary: Mapping[str, object],
    output_dir: str | Path,
) -> Path:
    """将真实端到端消融汇总写入稳定 JSON 文件。"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary_path = output_path / "real_ablation_summary.json"
    summary_path.write_text(
        json.dumps(dict(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary_path


def parse_summary_overrides(entries: Sequence[str]) -> dict[str, Path]:
    """解析 ``mode=path`` 形式的 summary 覆盖参数。"""
    overrides: dict[str, Path] = {}
    for entry in entries:
        if "=" not in entry:
            raise ValueError("--summary entries must use mode=path")
        mode_id, raw_path = entry.split("=", 1)
        if mode_id not in REAL_ABLATION_MODES_BY_ID:
            raise ValueError(f"unknown real ablation mode: {mode_id}")
        overrides[mode_id] = Path(raw_path)
    return overrides


def _build_mode_summary_row(
    mode: RealAblationMode,
    *,
    summary_path: Path | None,
) -> dict[str, object]:
    """构造单个 mode 的真实端到端消融汇总行。"""
    base_row: dict[str, object] = {
        "mode": mode.mode_id,
        "title": mode.title,
        "live_supported": mode.live_supported,
        "expected_runtime_auth_enabled": mode.expected_runtime_auth_enabled,
        "summary_path": str(summary_path) if summary_path is not None else None,
        "notes": mode.notes,
    }
    if not mode.live_supported:
        return {
            **base_row,
            "status": "offline_only_not_live_wired",
            "runtime_auth_enabled": None,
            "runtime_auth_matches_expected": None,
            "task_count": None,
            "succeeded_count": None,
            "failed_count": None,
            "task_latency_seconds_total": None,
            "task_latency_seconds_mean": None,
            "model_call_count": None,
            "audit_record_count": None,
            "api_cost_available": None,
            "token_usage_available": None,
        }
    if summary_path is None or not summary_path.exists():
        return {
            **base_row,
            "status": "summary_missing",
            "runtime_auth_enabled": None,
            "runtime_auth_matches_expected": False,
            "task_count": None,
            "succeeded_count": None,
            "failed_count": None,
            "task_latency_seconds_total": None,
            "task_latency_seconds_mean": None,
            "model_call_count": None,
            "audit_record_count": None,
            "api_cost_available": None,
            "token_usage_available": None,
        }

    summary = load_end_to_end_summary(summary_path)
    tasks = _tasks(summary)
    runtime_auth_enabled = _uniform_task_value(tasks, "runtime_auth_enabled")
    expected = mode.expected_runtime_auth_enabled
    return {
        **base_row,
        "status": "summary_available",
        "runtime_auth_enabled": runtime_auth_enabled,
        "runtime_auth_matches_expected": (
            runtime_auth_enabled == expected if expected is not None else None
        ),
        "task_count": int(summary.get("task_count", len(tasks)) or 0),
        "succeeded_count": int(summary.get("succeeded_count", 0) or 0),
        "failed_count": int(summary.get("failed_count", 0) or 0),
        "task_latency_seconds_total": _number_or_none(
            summary.get("task_latency_seconds_total")
        ),
        "task_latency_seconds_mean": _number_or_none(
            summary.get("task_latency_seconds_mean")
        ),
        "model_call_count": int(summary.get("model_call_count", 0) or 0),
        "audit_record_count": int(summary.get("audit_record_count", 0) or 0),
        "api_cost_available": bool(summary.get("api_cost_available", False)),
        "token_usage_available": bool(summary.get("token_usage_available", False)),
    }


def _tasks(summary: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """读取 batch summary 中的任务记录，格式异常时返回空列表。"""
    tasks = summary.get("tasks", [])
    if not isinstance(tasks, list):
        return []
    return [task for task in tasks if isinstance(task, Mapping)]


def _uniform_task_value(
    tasks: Sequence[Mapping[str, Any]],
    field_name: str,
) -> object:
    """若所有任务字段一致则返回该值，否则返回 mixed。"""
    values = {task.get(field_name) for task in tasks}
    if len(values) == 1:
        return next(iter(values))
    if not values:
        return None
    return "mixed"


def _number_or_none(value: object) -> float | None:
    """把数值字段规范化为 float；缺失或非数值时返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _check_result_as_dict(
    result: experiment_preflight.CheckResult,
) -> dict[str, object]:
    """把预检结果转换为稳定 JSON 行。"""
    return {
        "name": result.name,
        "ok": result.ok,
        "summary": result.summary,
        "details": list(result.details),
    }


def _default_output_dir() -> Path:
    """返回 ignored runs 目录下的默认真实消融输出目录。"""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_RUNS_DIR / f"{timestamp}-real-e2e-ablation"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析真实端到端消融 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description="Plan, summarize, or run real end-to-end ablation batches."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--mode", action="append", choices=REAL_ABLATION_MODE_ORDER)

    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--mode", action="append", choices=REAL_ABLATION_MODE_ORDER)
    preflight_parser.add_argument("--output-dir")
    preflight_parser.add_argument(
        "--check-db-sync",
        action="store_true",
        help="Also check Provider DB registration state. Requires MongoDB to be running.",
    )
    preflight_parser.add_argument(
        "--model-probe",
        action="store_true",
        help="Also probe configured model endpoints. This may use network and API quota.",
    )
    preflight_parser.add_argument(
        "--model-probe-timeout",
        type=float,
        default=20.0,
        help="Per-endpoint timeout for each optional model probe request.",
    )

    summarize_parser = subparsers.add_parser("summarize")
    summarize_parser.add_argument("--mode", action="append", choices=REAL_ABLATION_MODE_ORDER)
    summarize_parser.add_argument(
        "--summary",
        action="append",
        default=[],
        help="Override a summary path with mode=path.",
    )
    summarize_parser.add_argument("--output-dir")

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--mode", action="append", choices=REAL_ABLATION_MODE_ORDER)
    run_parser.add_argument(
        "--task",
        action="append",
        default=None,
        help="Task passed through to batch_run.py; repeat or use all.",
    )
    run_parser.add_argument("--output-dir")
    run_parser.add_argument(
        "--python",
        dest="python_executable",
        default=sys.executable,
        help="Python executable used for batch_run.py and subprocess entrypoints.",
    )
    run_parser.add_argument("--probe-required-successes", type=int)
    run_parser.add_argument("--probe-max-attempts", type=int)
    run_parser.add_argument("--probe-interval", type=float)
    run_parser.add_argument("--model-probe-timeout", type=float)
    run_parser.add_argument("--skip-model-probe", action="store_true")
    run_parser.add_argument("--skip-db-preflight", action="store_true")
    run_parser.add_argument("--skip-seed", action="store_true")
    run_parser.add_argument("--allow-task-failure", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 入口；默认只输出计划或读取已有 artifact，run 子命令才启动真实任务。"""
    args = parse_args(argv)
    if args.command == "plan":
        print(json.dumps(build_real_ablation_plan(mode_ids=args.mode), indent=2, sort_keys=True))
        return 0
    if args.command == "preflight":
        report = build_real_ablation_preflight_report(
            mode_ids=args.mode,
            check_db_sync=args.check_db_sync,
            check_model_backends=args.model_probe,
            model_probe_timeout_seconds=args.model_probe_timeout,
        )
        if args.output_dir:
            report_path = write_real_ablation_preflight_report(report, args.output_dir)
            report["report_path"] = str(report_path)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1
    if args.command == "summarize":
        summary = build_real_ablation_summary(
            summary_paths=parse_summary_overrides(args.summary),
            mode_ids=args.mode,
        )
        if args.output_dir:
            summary_path = write_real_ablation_summary(summary, args.output_dir)
            summary["summary_path"] = str(summary_path)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.command == "run":
        output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
        summary = run_live_real_ablation(
            output_dir=output_dir,
            mode_ids=args.mode,
            task_names=tuple(args.task or DEFAULT_TASKS),
            python_executable=args.python_executable,
            probe_required_successes=args.probe_required_successes,
            probe_max_attempts=args.probe_max_attempts,
            probe_interval_seconds=args.probe_interval,
            model_probe_timeout_seconds=args.model_probe_timeout,
            skip_model_probe=args.skip_model_probe,
            skip_db_preflight=args.skip_db_preflight,
            skip_seed=args.skip_seed,
            allow_task_failure=args.allow_task_failure,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    raise ValueError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
