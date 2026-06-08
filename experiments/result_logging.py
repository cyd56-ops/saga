"""Helpers for structured experiment result and audit summaries."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any

from saga.runtime_diagnostics import (
    filter_diagnostics_since,
    load_local_run_diagnostic_records,
    summarize_local_run_diagnostics,
)


DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"


def load_execution_gate_audit_records(agent_workdir: str | Path | None) -> list[dict[str, object]]:
    """Load execution-gate audit records from an agent workdir if they exist."""
    if agent_workdir is None:
        return []

    audit_path = Path(agent_workdir) / "audit" / "execution_gate.jsonl"
    if not audit_path.exists():
        return []

    records: list[dict[str, object]] = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def filter_records_since(
    records: Sequence[Mapping[str, Any]],
    *,
    started_at: datetime,
    timestamp_field: str = "recorded_at",
) -> list[dict[str, Any]]:
    """按记录时间筛出本次真实任务窗口内的诊断或审计记录。"""
    if started_at.tzinfo is None:
        raise ValueError("started_at must be timezone-aware")

    filtered: list[dict[str, Any]] = []
    for record in records:
        timestamp = record.get(timestamp_field)
        if not isinstance(timestamp, str):
            continue
        try:
            timestamp_dt = datetime.fromisoformat(timestamp)
        except ValueError:
            continue
        if timestamp_dt.tzinfo is None:
            timestamp_dt = timestamp_dt.replace(tzinfo=timezone.utc)
        if timestamp_dt >= started_at:
            filtered.append(dict(record))
    return filtered


def summarize_execution_gate_audits(
    audit_records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Summarize execution-gate audit records into stable result fields."""
    reasons = [
        str(record["reason"])
        for record in audit_records
        if "reason" in record and record.get("allowed") is False
    ]
    reason_counts = dict(sorted(Counter(reasons).items()))
    return {
        "audit_reject_count": len(reasons),
        "audit_reject_reasons": reason_counts,
    }


def _sum_numeric_field(
    records: Sequence[Mapping[str, object]],
    field_name: str,
) -> float:
    """累加诊断记录中的数值字段，忽略缺失或非数值字段。"""
    total = 0.0
    for record in records:
        value = record.get(field_name)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            total += float(value)
    return total


def _count_completed_model_runs(
    records: Sequence[Mapping[str, object]],
) -> int:
    """累加诊断中的模型调用步数，缺失时回退到已结束 run 次数。"""
    total = 0
    fallback_runs = 0
    saw_explicit_count = False
    for record in records:
        value = record.get("model_call_count")
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            total += value
            saw_explicit_count = True
        elif record.get("run_status") in {"completed", "failed"}:
            fallback_runs += 1
    return total if saw_explicit_count else fallback_runs


def summarize_end_to_end_task_stats(
    *,
    started_at: datetime,
    finished_at: datetime,
    local_run_records: Sequence[Mapping[str, object]],
    peer_run_records: Sequence[Mapping[str, object]],
    local_audit_records: Sequence[Mapping[str, object]],
    peer_audit_records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """汇总真实任务端到端 latency、模型调用轮次、审计和可用 cost 字段。

    API cost 只从诊断记录中已有的显式 cost/usage 字段汇总；当前后端未暴露这些字段时，
    结果会标记为 unavailable，避免用 token 价格做猜测。
    """
    if started_at.tzinfo is None or finished_at.tzinfo is None:
        raise ValueError("started_at and finished_at must be timezone-aware")
    if finished_at < started_at:
        raise ValueError("finished_at must be greater than or equal to started_at")

    all_run_records = [*local_run_records, *peer_run_records]
    all_audit_records = [*local_audit_records, *peer_audit_records]
    api_cost_usd = _sum_numeric_field(all_run_records, "api_cost_usd")
    prompt_tokens = int(_sum_numeric_field(all_run_records, "prompt_tokens"))
    completion_tokens = int(_sum_numeric_field(all_run_records, "completion_tokens"))
    total_tokens = int(_sum_numeric_field(all_run_records, "total_tokens"))
    explicit_cost_available = any("api_cost_usd" in record for record in all_run_records)
    explicit_token_usage_available = any(
        any(field_name in record for field_name in ("prompt_tokens", "completion_tokens", "total_tokens"))
        for record in all_run_records
    )

    # 真实任务的 wall-clock 延迟以 query 进程视角计；LLM 时间来自两端诊断记录。
    return {
        "task_started_at": started_at.isoformat(),
        "task_finished_at": finished_at.isoformat(),
        "task_latency_seconds": (finished_at - started_at).total_seconds(),
        "model_call_count": _count_completed_model_runs(all_run_records),
        "local_model_call_count": _count_completed_model_runs(local_run_records),
        "peer_model_call_count": _count_completed_model_runs(peer_run_records),
        "llm_elapsed_seconds_total": _sum_numeric_field(all_run_records, "llm_elapsed_seconds"),
        "local_llm_elapsed_seconds": _sum_numeric_field(
            local_run_records,
            "llm_elapsed_seconds",
        ),
        "peer_llm_elapsed_seconds": _sum_numeric_field(
            peer_run_records,
            "llm_elapsed_seconds",
        ),
        "api_cost_available": explicit_cost_available,
        "api_cost_usd": api_cost_usd if explicit_cost_available else None,
        "token_usage_available": explicit_token_usage_available,
        "prompt_tokens": prompt_tokens if explicit_token_usage_available else None,
        "completion_tokens": completion_tokens if explicit_token_usage_available else None,
        "total_tokens": total_tokens if explicit_token_usage_available else None,
        "audit_record_count": len(all_audit_records),
        "local_audit_record_count": len(local_audit_records),
        "peer_audit_record_count": len(peer_audit_records),
        "audit_logging_overhead_record_count": len(all_audit_records),
    }


def collect_query_execution_stats(
    *,
    local_workdir: str | Path,
    peer_workdir: str | Path,
    started_at: datetime,
    finished_at: datetime,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """收集一次真实 query 任务窗口内的本地/对端诊断、审计和端到端统计。"""
    collection_started_at = time.perf_counter()
    local_run_records = filter_diagnostics_since(
        load_local_run_diagnostic_records(local_workdir),
        started_at=started_at,
    )
    peer_run_records = filter_diagnostics_since(
        load_local_run_diagnostic_records(peer_workdir),
        started_at=started_at,
    )
    local_audit_records = filter_records_since(
        load_execution_gate_audit_records(local_workdir),
        started_at=started_at,
    )
    peer_audit_records = filter_records_since(
        load_execution_gate_audit_records(peer_workdir),
        started_at=started_at,
    )
    local_run_summary = summarize_local_run_diagnostics(local_run_records)
    peer_run_summary = summarize_local_run_diagnostics(
        peer_run_records,
        prefix="peer_run",
    )
    peer_audit_summary = {
        f"peer_{key}": value
        for key, value in summarize_execution_gate_audits(peer_audit_records).items()
    }
    end_to_end_stats = summarize_end_to_end_task_stats(
        started_at=started_at,
        finished_at=finished_at,
        local_run_records=local_run_records,
        peer_run_records=peer_run_records,
        local_audit_records=local_audit_records,
        peer_audit_records=peer_audit_records,
    )
    end_to_end_stats["logging_stats_collection_latency_seconds"] = (
        time.perf_counter() - collection_started_at
    )
    return local_audit_records, {
        **local_run_summary,
        **peer_run_summary,
        **peer_audit_summary,
        **end_to_end_stats,
    }


def build_experiment_result_record(
    *,
    task_name: str,
    mode: str,
    config_path: str,
    other_config_path: str | None,
    agent_aid: str,
    peer_aid: str | None,
    runtime_auth_enabled: bool,
    success: bool | None,
    audit_records: Sequence[Mapping[str, object]],
    extra_fields: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a structured experiment result record."""
    record = {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "task_name": task_name,
        "mode": mode,
        "config_path": config_path,
        "other_config_path": other_config_path,
        "agent_aid": agent_aid,
        "peer_aid": peer_aid,
        "runtime_auth_enabled": runtime_auth_enabled,
        "success": success,
    }
    record.update(summarize_execution_gate_audits(audit_records))
    if extra_fields is not None:
        record.update(dict(extra_fields))
    return record


def append_experiment_result_record(
    task_name: str,
    record: Mapping[str, object],
    *,
    results_dir: str | Path | None = None,
) -> Path:
    """Append a structured experiment result row to a task-specific JSONL file.

    将真实任务结果追加到任务级 JSONL 文件，供 batch runner 汇总端到端统计。
    """
    base_dir = Path(results_dir) if results_dir is not None else DEFAULT_RESULTS_DIR
    base_dir.mkdir(parents=True, exist_ok=True)
    result_path = base_dir / f"{task_name}.jsonl"
    payload = dict(record)
    with result_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return result_path
