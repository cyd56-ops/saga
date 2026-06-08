"""Build stable paper-table rows from end-to-end batch summaries."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE_SUMMARY_PATH = (
    REPO_ROOT
    / "experiments"
    / "runs"
    / "20260527T114103Z-schedule_meeting-expense_report-create_blogpost"
    / "end_to_end_stats_summary.json"
)
DEFAULT_PQ_CAN_SUMMARY_PATH = (
    REPO_ROOT
    / "experiments"
    / "runs"
    / "20260527T114953Z-schedule_meeting-expense_report-create_blogpost"
    / "end_to_end_stats_summary.json"
)

RUN_LEVEL_COLUMNS = (
    "mode",
    "runtime_auth_enabled",
    "task_count",
    "succeeded_count",
    "failed_count",
    "task_latency_seconds_total",
    "task_latency_seconds_mean",
    "model_call_count",
    "llm_elapsed_seconds_total",
    "audit_record_count",
    "audit_reject_count",
    "audit_logging_overhead_record_count",
    "logging_stats_collection_latency_seconds_total",
    "api_cost_available",
    "api_cost_usd_total",
    "token_usage_available",
    "total_tokens",
)
TASK_LEVEL_COLUMNS = (
    "mode",
    "task_name",
    "success",
    "runtime_auth_enabled",
    "task_latency_seconds",
    "model_call_count",
    "local_model_call_count",
    "peer_model_call_count",
    "llm_elapsed_seconds_total",
    "audit_record_count",
    "audit_reject_count",
    "peer_audit_reject_count",
    "audit_logging_overhead_record_count",
    "api_cost_available",
    "api_cost_usd",
    "token_usage_available",
    "total_tokens",
    "oracle_reason",
)


def load_end_to_end_summary(path: str | Path) -> dict[str, Any]:
    """读取 batch run 端到端 summary JSON，返回可用于表格生成的字典。"""
    summary_path = Path(path)
    with summary_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{summary_path} must contain a JSON object")
    return payload


def build_paper_tables(
    summaries_by_mode: Mapping[str, Mapping[str, Any]],
) -> dict[str, object]:
    """从多个 mode 的 summary 构造稳定论文表格数据。"""
    run_level_rows = [
        build_run_level_row(mode, summary)
        for mode, summary in summaries_by_mode.items()
    ]
    task_level_rows = [
        build_task_level_row(mode, task)
        for mode, summary in summaries_by_mode.items()
        for task in _tasks(summary)
    ]
    return {
        "run_level_columns": list(RUN_LEVEL_COLUMNS),
        "task_level_columns": list(TASK_LEVEL_COLUMNS),
        "run_level_rows": run_level_rows,
        "task_level_rows": task_level_rows,
        "notes": {
            "api_cost": (
                "API cost is reported only when model diagnostics expose explicit cost fields."
            ),
            "token_usage": (
                "Token usage is reported only when model diagnostics expose explicit token fields."
            ),
            "audit_counts": (
                "Audit counts refer to execution-gate audit records, not model/tool permission text."
            ),
        },
    }


def build_run_level_row(mode: str, summary: Mapping[str, Any]) -> dict[str, object]:
    """构造 run 级表格行，汇总成功率、延迟、模型调用和审计计数。"""
    tasks = _tasks(summary)
    row = {
        "mode": mode,
        "runtime_auth_enabled": _uniform_task_value(tasks, "runtime_auth_enabled"),
        "task_count": int(summary.get("task_count", len(tasks)) or 0),
        "succeeded_count": int(summary.get("succeeded_count", 0) or 0),
        "failed_count": int(summary.get("failed_count", 0) or 0),
        "task_latency_seconds_total": _round_float(
            summary.get("task_latency_seconds_total", 0.0)
        ),
        "task_latency_seconds_mean": _round_float(
            summary.get("task_latency_seconds_mean", 0.0)
        ),
        "model_call_count": int(summary.get("model_call_count", 0) or 0),
        "llm_elapsed_seconds_total": _round_float(
            sum(_number(task.get("llm_elapsed_seconds_total")) for task in tasks)
        ),
        "audit_record_count": int(summary.get("audit_record_count", 0) or 0),
        "audit_reject_count": int(
            sum(_number(task.get("audit_reject_count")) for task in tasks)
        ),
        "audit_logging_overhead_record_count": int(
            summary.get("audit_logging_overhead_record_count", 0) or 0
        ),
        "logging_stats_collection_latency_seconds_total": _round_float(
            summary.get("logging_stats_collection_latency_seconds_total", 0.0),
            digits=9,
        ),
        "api_cost_available": bool(summary.get("api_cost_available", False)),
        "api_cost_usd_total": summary.get("api_cost_usd_total"),
        "token_usage_available": bool(summary.get("token_usage_available", False)),
        "total_tokens": summary.get("total_tokens"),
    }
    return _ordered_row(RUN_LEVEL_COLUMNS, row)


def build_task_level_row(mode: str, task_record: Mapping[str, Any]) -> dict[str, object]:
    """构造任务级表格行，保留每个真实任务的关键统计字段。"""
    row = {
        "mode": mode,
        "task_name": str(task_record.get("task_name", "")),
        "success": task_record.get("success"),
        "runtime_auth_enabled": task_record.get("runtime_auth_enabled"),
        "task_latency_seconds": _round_float(task_record.get("task_latency_seconds", 0.0)),
        "model_call_count": int(task_record.get("model_call_count", 0) or 0),
        "local_model_call_count": int(task_record.get("local_model_call_count", 0) or 0),
        "peer_model_call_count": int(task_record.get("peer_model_call_count", 0) or 0),
        "llm_elapsed_seconds_total": _round_float(
            task_record.get("llm_elapsed_seconds_total", 0.0)
        ),
        "audit_record_count": int(task_record.get("audit_record_count", 0) or 0),
        "audit_reject_count": int(task_record.get("audit_reject_count", 0) or 0),
        "peer_audit_reject_count": int(
            task_record.get("peer_audit_reject_count", 0) or 0
        ),
        "audit_logging_overhead_record_count": int(
            task_record.get("audit_logging_overhead_record_count", 0) or 0
        ),
        "api_cost_available": bool(task_record.get("api_cost_available", False)),
        "api_cost_usd": task_record.get("api_cost_usd"),
        "token_usage_available": bool(task_record.get("token_usage_available", False)),
        "total_tokens": task_record.get("total_tokens"),
        "oracle_reason": task_record.get("oracle_reason"),
    }
    return _ordered_row(TASK_LEVEL_COLUMNS, row)


def format_markdown_table(
    rows: Sequence[Mapping[str, object]],
    columns: Sequence[str],
) -> str:
    """将表格行格式化为稳定 Markdown，便于直接放入论文草稿或记录。"""
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"
    body = [
        "| "
        + " | ".join(_format_markdown_cell(row.get(column)) for column in columns)
        + " |"
        for row in rows
    ]
    return "\n".join([header, separator, *body])


def build_default_paper_tables() -> dict[str, object]:
    """读取默认 2026-05-27 baseline/PQ-CAN summary 并生成表格数据。"""
    return build_paper_tables(
        {
            "baseline": load_end_to_end_summary(DEFAULT_BASELINE_SUMMARY_PATH),
            "pq_can": load_end_to_end_summary(DEFAULT_PQ_CAN_SUMMARY_PATH),
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口：读取 summary 路径并输出 JSON 或 Markdown 表格。"""
    parser = argparse.ArgumentParser(
        description="Build paper-table rows from SAGA-PQ-CAN batch summaries."
    )
    parser.add_argument(
        "--baseline-summary",
        type=Path,
        default=DEFAULT_BASELINE_SUMMARY_PATH,
        help="Path to the baseline end_to_end_stats_summary.json.",
    )
    parser.add_argument(
        "--pq-can-summary",
        type=Path,
        default=DEFAULT_PQ_CAN_SUMMARY_PATH,
        help="Path to the PQ-CAN end_to_end_stats_summary.json.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format.",
    )
    args = parser.parse_args(argv)

    tables = build_paper_tables(
        {
            "baseline": load_end_to_end_summary(args.baseline_summary),
            "pq_can": load_end_to_end_summary(args.pq_can_summary),
        }
    )
    if args.format == "markdown":
        print("## Run-Level Summary")
        print(
            format_markdown_table(
                tables["run_level_rows"],
                tables["run_level_columns"],
            )
        )
        print()
        print("## Task-Level Summary")
        print(
            format_markdown_table(
                tables["task_level_rows"],
                tables["task_level_columns"],
            )
        )
    else:
        print(json.dumps(tables, indent=2, sort_keys=True))
    return 0


def _tasks(summary: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """读取 summary 中的任务列表，并校验其基本结构。"""
    tasks = summary.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("summary.tasks must be a list")
    return [task for task in tasks if isinstance(task, Mapping)]


def _uniform_task_value(
    tasks: Sequence[Mapping[str, Any]],
    field_name: str,
) -> object:
    """当所有任务字段一致时返回该值，否则返回 mixed。"""
    values = {task.get(field_name) for task in tasks}
    if len(values) == 1:
        return next(iter(values))
    return "mixed"


def _number(value: object) -> float:
    """把数值字段规范化为 float，缺失或非数值按 0 处理。"""
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _round_float(value: object, *, digits: int = 6) -> float:
    """统一表格中浮点数的小数位，避免无意义的 JSON 浮点噪音。"""
    return round(_number(value), digits)


def _ordered_row(
    columns: Sequence[str],
    row: Mapping[str, object],
) -> dict[str, object]:
    """按列顺序构造 dict，保持 JSON 和 Markdown 输出稳定。"""
    return {column: row.get(column) for column in columns}


def _format_markdown_cell(value: object) -> str:
    """格式化 Markdown 单元格，避免 None 和竖线破坏表格。"""
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value).replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
