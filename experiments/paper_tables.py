"""Build stable paper-table rows from end-to-end batch summaries."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import re
from typing import Any

from experiments.security_evidence import evidence_mappings, property_claims
from saga.security_kernel import (
    EXECUTE_SURFACE_CLAIM,
    layer_refinement_mappings,
    model_refinement_mappings,
    mutation_evidence as kernel_mutation_evidence,
    protected_sink_audits,
)


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
SECURITY_PROPERTY_COLUMNS = (
    "property_id",
    "title",
    "enforcement_terms",
    "assumptions",
    "limitations",
)
SECURITY_EVIDENCE_COLUMNS = (
    "source",
    "name",
    "properties",
    "expected_reason",
    "evidence_kind",
    "side_effect_expectation",
)
PROOF_CLAIM_COLUMNS = (
    "claim_id",
    "claim",
    "source",
    "boundary",
)
PROTECTED_SINK_COLUMNS = (
    "sink_id",
    "surface",
    "side_effect",
    "required_predicate",
    "evidence_tests",
    "residual_risk",
)
PROOF_MUTATION_COLUMNS = (
    "mutation_id",
    "protected_property",
    "sink_ids",
    "expected_test_failures",
    "notes",
)
MODEL_REFINEMENT_COLUMNS = (
    "mapping_id",
    "model_term",
    "python_symbols",
    "evidence_tests",
    "linked_sink_ids",
    "residual_risk",
)
LAYER_REFINEMENT_COLUMNS = (
    "layer_id",
    "tla_surfaces",
    "protected_sinks",
    "guard_terms",
    "evidence_tests",
    "residual_risk",
)
PROOF_ARTIFACT_COLUMNS = (
    "artifact_name",
    "artifact_sha256",
    "passed",
    "finding_count",
    "proof_tests_summary",
    "mutation_validation_passed",
    "mutation_count",
    "detected_count",
    "all_detected",
    "undetected_count",
    "recorded_at",
)


def load_json_object(path: str | Path) -> dict[str, Any]:
    """读取 JSON object 文件，供实验 summary 和 proof artifact summary 共用。"""
    summary_path = Path(path)
    with summary_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{summary_path} must contain a JSON object")
    return payload


def load_end_to_end_summary(path: str | Path) -> dict[str, Any]:
    """读取 batch run 端到端 summary JSON，返回可用于表格生成的字典。"""
    return load_json_object(path)


def build_paper_tables(
    summaries_by_mode: Mapping[str, Mapping[str, Any]],
    *,
    proof_artifact_summary: Mapping[str, Any] | None = None,
    mutation_evidence_summary: Mapping[str, Any] | None = None,
    proof_artifact_name: str = "",
    proof_artifact_sha256: str = "",
) -> dict[str, object]:
    """从多个 mode 的 summary 构造稳定论文表格和 proof appendix 数据。"""
    run_level_rows = [
        build_run_level_row(mode, summary)
        for mode, summary in summaries_by_mode.items()
    ]
    task_level_rows = [
        build_task_level_row(mode, task)
        for mode, summary in summaries_by_mode.items()
        for task in _tasks(summary)
    ]
    security_property_rows = build_security_property_rows()
    security_evidence_rows = build_security_evidence_rows()
    proof_artifact_rows = []
    if proof_artifact_summary is not None and mutation_evidence_summary is not None:
        proof_artifact_rows.append(
            build_proof_artifact_row(
                proof_artifact_summary,
                mutation_evidence_summary,
                artifact_name=proof_artifact_name,
                artifact_sha256=proof_artifact_sha256,
            )
        )
    return {
        "run_level_columns": list(RUN_LEVEL_COLUMNS),
        "task_level_columns": list(TASK_LEVEL_COLUMNS),
        "security_property_columns": list(SECURITY_PROPERTY_COLUMNS),
        "security_evidence_columns": list(SECURITY_EVIDENCE_COLUMNS),
        "proof_claim_columns": list(PROOF_CLAIM_COLUMNS),
        "protected_sink_columns": list(PROTECTED_SINK_COLUMNS),
        "proof_mutation_columns": list(PROOF_MUTATION_COLUMNS),
        "model_refinement_columns": list(MODEL_REFINEMENT_COLUMNS),
        "layer_refinement_columns": list(LAYER_REFINEMENT_COLUMNS),
        "proof_artifact_columns": list(PROOF_ARTIFACT_COLUMNS),
        "run_level_rows": run_level_rows,
        "task_level_rows": task_level_rows,
        "security_property_rows": security_property_rows,
        "security_evidence_rows": security_evidence_rows,
        "proof_claim_rows": build_proof_claim_rows(),
        "protected_sink_rows": build_protected_sink_rows(),
        "proof_mutation_rows": build_proof_mutation_rows(),
        "model_refinement_rows": build_model_refinement_rows(),
        "layer_refinement_rows": build_layer_refinement_rows(),
        "proof_artifact_rows": proof_artifact_rows,
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
            "security_evidence": (
                "Security-property rows and evidence rows are generated from experiments/security_evidence.py."
            ),
            "proof_appendix": (
                "Proof appendix rows are generated from saga/security_kernel.py and optional proof-hardening artifact summaries."
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


def build_security_property_rows() -> list[dict[str, object]]:
    """构造 U9 安全性质表格行。"""
    rows = []
    for claim in property_claims():
        rows.append(
            _ordered_row(
                SECURITY_PROPERTY_COLUMNS,
                {
                    "property_id": claim.property_id,
                    "title": claim.title,
                    "enforcement_terms": ", ".join(claim.enforcement_terms),
                    "assumptions": "; ".join(claim.assumptions),
                    "limitations": "; ".join(claim.limitations),
                },
            )
        )
    return rows


def build_security_evidence_rows() -> list[dict[str, object]]:
    """构造 U10 证据映射表格行。"""
    rows = []
    for mapping in evidence_mappings():
        rows.append(
            _ordered_row(
                SECURITY_EVIDENCE_COLUMNS,
                {
                    "source": mapping.source,
                    "name": mapping.name,
                    "properties": ", ".join(mapping.properties),
                    "expected_reason": mapping.expected_reason,
                    "evidence_kind": mapping.evidence_kind,
                    "side_effect_expectation": mapping.side_effect_expectation,
                },
            )
        )
    return rows


def build_proof_claim_rows() -> list[dict[str, object]]:
    """构造 strict runtime-auth proof appendix 的核心 claim 行。"""
    return [
        _ordered_row(
            PROOF_CLAIM_COLUMNS,
            {
                "claim_id": "strict_runtime_auth_execute_guard",
                "claim": EXECUTE_SURFACE_CLAIM,
                "source": "saga/security_kernel.py",
                "boundary": (
                    "Strict runtime-auth protected sinks only; legacy, experiment, "
                    "attack model, and raw backend paths are excluded."
                ),
            },
        )
    ]


def build_protected_sink_rows() -> list[dict[str, object]]:
    """构造 protected sink coverage 表格行。"""
    rows = []
    for sink in protected_sink_audits():
        rows.append(
            _ordered_row(
                PROTECTED_SINK_COLUMNS,
                {
                    "sink_id": sink.sink_id,
                    "surface": sink.surface,
                    "side_effect": sink.side_effect,
                    "required_predicate": sink.required_predicate,
                    "evidence_tests": ", ".join(sink.evidence_tests),
                    "residual_risk": sink.residual_risk,
                },
            )
        )
    return rows


def build_proof_mutation_rows() -> list[dict[str, object]]:
    """构造 proof-hardening mutation evidence 表格行。"""
    rows = []
    for evidence in kernel_mutation_evidence():
        rows.append(
            _ordered_row(
                PROOF_MUTATION_COLUMNS,
                {
                    "mutation_id": evidence.mutation_id,
                    "protected_property": evidence.protected_property,
                    "sink_ids": ", ".join(evidence.sink_ids),
                    "expected_test_failures": ", ".join(evidence.expected_test_failures),
                    "notes": evidence.notes,
                },
            )
        )
    return rows


def build_model_refinement_rows() -> list[dict[str, object]]:
    """构造 P6 model-to-Python refinement mapping 表格行。"""
    rows = []
    for mapping in model_refinement_mappings():
        rows.append(
            _ordered_row(
                MODEL_REFINEMENT_COLUMNS,
                {
                    "mapping_id": mapping.mapping_id,
                    "model_term": mapping.model_term,
                    "python_symbols": ", ".join(mapping.python_symbols),
                    "evidence_tests": ", ".join(mapping.evidence_tests),
                    "linked_sink_ids": ", ".join(mapping.linked_sink_ids),
                    "residual_risk": mapping.residual_risk,
                },
            )
        )
    return rows


def build_layer_refinement_rows() -> list[dict[str, object]]:
    """构造 layered TLA+ 到 Python protected sinks 的 appendix 表格行。"""
    rows = []
    for mapping in layer_refinement_mappings():
        rows.append(
            _ordered_row(
                LAYER_REFINEMENT_COLUMNS,
                {
                    "layer_id": mapping.layer_id,
                    "tla_surfaces": ", ".join(mapping.tla_surface_values),
                    "protected_sinks": ", ".join(mapping.linked_sink_ids),
                    "guard_terms": ", ".join(mapping.guard_terms),
                    "evidence_tests": ", ".join(mapping.evidence_tests),
                    "residual_risk": mapping.residual_risk,
                },
            )
        )
    return rows


def build_proof_artifact_row(
    proof_summary: Mapping[str, Any],
    mutation_summary: Mapping[str, Any],
    *,
    artifact_name: str = "",
    artifact_sha256: str = "",
) -> dict[str, object]:
    """把 GitHub proof-hardening artifact summary 规范化为论文附录表格行。"""
    mutation_validation = proof_summary.get("mutation_validation", {})
    if not isinstance(mutation_validation, Mapping):
        mutation_validation = {}
    proof_tests = proof_summary.get("proof_tests", {})
    if not isinstance(proof_tests, Mapping):
        proof_tests = {}
    row = {
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha256,
        "passed": bool(proof_summary.get("passed", False)),
        "finding_count": int(proof_summary.get("finding_count", 0) or 0),
        "proof_tests_summary": _extract_pytest_summary(
            str(proof_tests.get("stdout_tail", ""))
        ),
        "mutation_validation_passed": bool(mutation_validation.get("passed", False)),
        "mutation_count": int(mutation_summary.get("mutation_count", 0) or 0),
        "detected_count": int(mutation_summary.get("detected_count", 0) or 0),
        "all_detected": bool(mutation_summary.get("all_detected", False)),
        "undetected_count": int(mutation_summary.get("undetected_count", 0) or 0),
        "recorded_at": str(mutation_summary.get("recorded_at", "")),
    }
    return _ordered_row(PROOF_ARTIFACT_COLUMNS, row)


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


def format_paper_tables_markdown(tables: Mapping[str, object]) -> str:
    """将完整论文表格集合格式化为带章节标题的 Markdown 文档。"""
    sections = [
        (
            "Run-Level Summary",
            "run_level_rows",
            "run_level_columns",
        ),
        (
            "Task-Level Summary",
            "task_level_rows",
            "task_level_columns",
        ),
        (
            "Security Properties",
            "security_property_rows",
            "security_property_columns",
        ),
        (
            "Security Evidence",
            "security_evidence_rows",
            "security_evidence_columns",
        ),
        (
            "Proof Claim",
            "proof_claim_rows",
            "proof_claim_columns",
        ),
        (
            "Protected Sinks",
            "protected_sink_rows",
            "protected_sink_columns",
        ),
        (
            "Proof Mutation Evidence",
            "proof_mutation_rows",
            "proof_mutation_columns",
        ),
        (
            "Model Refinement Mapping",
            "model_refinement_rows",
            "model_refinement_columns",
        ),
        (
            "Layer Refinement Mapping",
            "layer_refinement_rows",
            "layer_refinement_columns",
        ),
        (
            "Proof Artifact Summary",
            "proof_artifact_rows",
            "proof_artifact_columns",
        ),
    ]
    rendered_sections = []
    for title, rows_key, columns_key in sections:
        rows = _mapping_sequence(tables.get(rows_key), rows_key)
        columns = _string_sequence(tables.get(columns_key), columns_key)
        rendered_sections.append(
            "\n".join(
                [
                    f"## {title}",
                    format_markdown_table(rows, columns),
                ]
            )
        )
    return "\n\n".join(rendered_sections) + "\n"


def write_paper_table_archive(
    tables: Mapping[str, object],
    output_dir: str | Path,
) -> dict[str, Path]:
    """把论文表格同时归档为 JSON 与 Markdown 文件。"""
    archive_dir = Path(output_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    json_path = archive_dir / "paper_tables.json"
    markdown_path = archive_dir / "paper_tables.md"
    json_path.write_text(
        json.dumps(tables, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        format_paper_tables_markdown(tables),
        encoding="utf-8",
    )
    return {
        "json": json_path,
        "markdown": markdown_path,
    }


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
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Optional directory where paper_tables.json and paper_tables.md are archived.",
    )
    parser.add_argument(
        "--proof-hardening-summary",
        type=Path,
        help="Optional proof_hardening_check_summary.json from a proof-hardening artifact.",
    )
    parser.add_argument(
        "--mutation-evidence-summary",
        type=Path,
        help="Optional mutation_evidence_summary.json from the same proof-hardening artifact.",
    )
    parser.add_argument(
        "--proof-artifact-name",
        default="",
        help="Optional human-readable proof-hardening artifact filename.",
    )
    parser.add_argument(
        "--proof-artifact-sha256",
        default="",
        help="Optional SHA-256 digest for the proof-hardening artifact archive.",
    )
    args = parser.parse_args(argv)

    if (args.proof_hardening_summary is None) != (
        args.mutation_evidence_summary is None
    ):
        parser.error(
            "--proof-hardening-summary and --mutation-evidence-summary must be provided together"
        )
    proof_summary = (
        load_json_object(args.proof_hardening_summary)
        if args.proof_hardening_summary is not None
        else None
    )
    mutation_summary = (
        load_json_object(args.mutation_evidence_summary)
        if args.mutation_evidence_summary is not None
        else None
    )
    tables = build_paper_tables(
        {
            "baseline": load_end_to_end_summary(args.baseline_summary),
            "pq_can": load_end_to_end_summary(args.pq_can_summary),
        },
        proof_artifact_summary=proof_summary,
        mutation_evidence_summary=mutation_summary,
        proof_artifact_name=args.proof_artifact_name,
        proof_artifact_sha256=args.proof_artifact_sha256,
    )
    if args.output_dir is not None:
        write_paper_table_archive(tables, args.output_dir)

    if args.format == "markdown":
        print(format_paper_tables_markdown(tables), end="")
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


def _extract_pytest_summary(stdout_tail: str) -> str:
    """从 pytest 输出尾部提取稳定的 passed/subtests 摘要。"""
    match = re.search(r"(\d+ passed(?:, \d+ subtests passed)?)", stdout_tail)
    if match is None:
        return ""
    return match.group(1)


def _ordered_row(
    columns: Sequence[str],
    row: Mapping[str, object],
) -> dict[str, object]:
    """按列顺序构造 dict，保持 JSON 和 Markdown 输出稳定。"""
    return {column: row.get(column) for column in columns}


def _mapping_sequence(value: object, field_name: str) -> list[Mapping[str, object]]:
    """校验并返回 Markdown 渲染需要的行对象序列。"""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field_name} must be a sequence")
    rows = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"{field_name} must contain mapping rows")
        rows.append(item)
    return rows


def _string_sequence(value: object, field_name: str) -> list[str]:
    """校验并返回 Markdown 渲染需要的列名序列。"""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field_name} must be a sequence")
    columns = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must contain string columns")
        columns.append(item)
    return columns


def _format_markdown_cell(value: object) -> str:
    """格式化 Markdown 单元格，避免 None 和竖线破坏表格。"""
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value).replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
