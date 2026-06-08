"""Structured local runtime diagnostics for experiment triage."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def _truncate_text(value: object, *, limit: int = 160) -> str | None:
    """Return a short preview string for diagnostic logging."""
    if value is None:
        return None

    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _extract_step_tool_names(step: object) -> list[str]:
    """Extract tool-call names from one memory step when present."""
    tool_calls = getattr(step, "tool_calls", None) or []
    names: list[str] = []
    for tool_call in tool_calls:
        tool_name = getattr(tool_call, "name", None)
        if tool_name is not None:
            names.append(str(tool_name))
    return names


def summarize_agent_memory_steps(
    agent_instance: object | None,
    *,
    step_start_index: int = 0,
) -> dict[str, object]:
    """Summarize newly added memory steps after one local-agent run.

    诊断中的模型调用次数按新增非 TaskStep 记忆步骤估算，避免只统计外层 run 次数。
    """
    memory = getattr(agent_instance, "memory", None)
    steps = list(getattr(memory, "steps", []) or [])
    new_steps = steps[step_start_index:]

    tool_call_names: list[str] = []
    error_count = 0
    final_answer_count = 0
    step_type_counts: Counter[str] = Counter()
    for step in new_steps:
        step_type_counts[type(step).__name__] += 1
        tool_call_names.extend(_extract_step_tool_names(step))
        if getattr(step, "error", None) is not None:
            error_count += 1
        if bool(getattr(step, "is_final_answer", False)):
            final_answer_count += 1

    return {
        "memory_step_count": len(steps),
        "new_memory_step_count": len(new_steps),
        "step_type_counts": dict(sorted(step_type_counts.items())),
        "model_call_count": sum(
            count
            for step_type, count in step_type_counts.items()
            if step_type not in {"TaskStep", "SystemPromptStep"}
        ),
        "tool_call_count": len(tool_call_names),
        "tool_call_names": tool_call_names,
        "error_step_count": error_count,
        "final_answer_step_count": final_answer_count,
        "last_step_type": type(steps[-1]).__name__ if steps else None,
    }


def build_local_run_diagnostic_record(
    *,
    agent_aid: str,
    peer_aid: str | None,
    conversation_side: str,
    turn_index: int,
    query: str,
    response: object,
    llm_elapsed_seconds: float | None,
    agent_instance: object | None,
    step_start_index: int = 0,
) -> dict[str, object]:
    """Build one structured local runtime diagnostic record."""
    record: dict[str, object] = {
        "agent_aid": agent_aid,
        "peer_aid": peer_aid,
        "conversation_side": conversation_side,
        "turn_index": turn_index,
        "query_length": len(str(query)),
        "query_preview": _truncate_text(query),
        "response_length": len(str(response)),
        "response_preview": _truncate_text(response),
        "response_is_task_finished": str(response) == "<TASK_FINISHED>",
        "llm_elapsed_seconds": llm_elapsed_seconds,
    }
    record.update(
        summarize_agent_memory_steps(
            agent_instance,
            step_start_index=step_start_index,
        )
    )
    return record


def append_local_run_diagnostic_record(
    workdir: str | Path | None,
    record: Mapping[str, object],
) -> Path | None:
    """Append one local runtime diagnostic row to a JSONL file."""
    if workdir is None:
        return None

    diagnostics_dir = Path(workdir) / "diagnostics"
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_path = diagnostics_dir / "local_agent_runs.jsonl"
    payload = dict(record)
    payload["recorded_at"] = datetime.now(tz=timezone.utc).isoformat()
    with diagnostics_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return diagnostics_path


def load_local_run_diagnostic_records(
    agent_workdir: str | Path | None,
) -> list[dict[str, Any]]:
    """Load local runtime diagnostics from an agent workdir if present."""
    if agent_workdir is None:
        return []

    diagnostics_path = Path(agent_workdir) / "diagnostics" / "local_agent_runs.jsonl"
    if not diagnostics_path.exists():
        return []

    records: list[dict[str, Any]] = []
    with diagnostics_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def filter_diagnostics_since(
    diagnostic_records: Sequence[Mapping[str, Any]],
    *,
    started_at: datetime,
) -> list[dict[str, Any]]:
    """Return diagnostic rows recorded at or after ``started_at``."""
    if started_at.tzinfo is None:
        raise ValueError("started_at must be timezone-aware")

    rows: list[dict[str, Any]] = []
    for record in diagnostic_records:
        recorded_at = record.get("recorded_at")
        if not isinstance(recorded_at, str):
            continue
        try:
            recorded_dt = datetime.fromisoformat(recorded_at)
        except ValueError:
            continue
        if recorded_dt.tzinfo is None:
            recorded_dt = recorded_dt.replace(tzinfo=timezone.utc)
        if recorded_dt >= started_at:
            rows.append(dict(record))
    return rows


def summarize_local_run_diagnostics(
    diagnostic_records: Sequence[Mapping[str, object]],
    *,
    prefix: str = "local_run",
) -> dict[str, object]:
    """Summarize local runtime diagnostics into stable result fields."""
    tool_names: list[str] = []
    model_call_count = 0
    error_step_count = 0
    final_answer_count = 0
    by_side: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    failed_count = 0
    errors: list[str] = []
    for record in diagnostic_records:
        tool_names.extend(str(name) for name in record.get("tool_call_names", []) or [])
        model_call_count += int(record.get("model_call_count", 0))
        error_step_count += int(record.get("error_step_count", 0))
        final_answer_count += int(record.get("final_answer_step_count", 0))
        side = record.get("conversation_side")
        if side is not None:
            by_side[str(side)] += 1
        status = record.get("run_status")
        if status is not None:
            status_text = str(status)
            by_status[status_text] += 1
            if status_text == "failed":
                failed_count += 1
        error = record.get("error")
        if isinstance(error, str) and error:
            errors.append(error)

    return {
        f"{prefix}_count": len(diagnostic_records),
        f"{prefix}_model_call_count": model_call_count,
        f"{prefix}_tool_call_count": len(tool_names),
        f"{prefix}_tool_names": sorted(set(tool_names)),
        f"{prefix}_error_step_count": error_step_count,
        f"{prefix}_final_answer_step_count": final_answer_count,
        f"{prefix}_by_side": dict(sorted(by_side.items())),
        f"{prefix}_by_status": dict(sorted(by_status.items())),
        f"{prefix}_failed_count": failed_count,
        f"{prefix}_errors": errors,
    }
