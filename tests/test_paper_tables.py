"""Tests for paper-table extraction from end-to-end summaries."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from experiments.paper_tables import (
    DEFAULT_BASELINE_SUMMARY_PATH,
    DEFAULT_PQ_CAN_SUMMARY_PATH,
    TASK_LEVEL_COLUMNS,
    RUN_LEVEL_COLUMNS,
    build_paper_tables,
    format_markdown_table,
    load_end_to_end_summary,
)


def _summary(
    *,
    runtime_auth_enabled: bool,
    task_latency: float,
    model_call_count: int,
    llm_elapsed: float,
    peer_audit_reject_count: int = 0,
) -> dict[str, object]:
    """构造最小端到端 summary fixture，避免测试依赖 ignored 运行产物。"""
    return {
        "task_count": 1,
        "succeeded_count": 1,
        "failed_count": 0,
        "task_latency_seconds_total": task_latency,
        "task_latency_seconds_mean": task_latency,
        "model_call_count": model_call_count,
        "audit_record_count": peer_audit_reject_count,
        "audit_logging_overhead_record_count": peer_audit_reject_count,
        "logging_stats_collection_latency_seconds_total": 0.001234567,
        "api_cost_available": False,
        "api_cost_usd_total": None,
        "token_usage_available": False,
        "total_tokens": None,
        "tasks": [
            {
                "task_name": "schedule_meeting",
                "success": True,
                "runtime_auth_enabled": runtime_auth_enabled,
                "task_latency_seconds": task_latency,
                "model_call_count": model_call_count,
                "local_model_call_count": 1,
                "peer_model_call_count": model_call_count - 1,
                "llm_elapsed_seconds_total": llm_elapsed,
                "audit_record_count": peer_audit_reject_count,
                "audit_reject_count": 0,
                "peer_audit_reject_count": peer_audit_reject_count,
                "audit_logging_overhead_record_count": peer_audit_reject_count,
                "api_cost_available": False,
                "api_cost_usd": None,
                "token_usage_available": False,
                "total_tokens": None,
                "oracle_reason": "meeting_scheduled",
            }
        ],
    }


class PaperTablesTests(unittest.TestCase):
    """Verify paper-table rows use stable experiment fields and conservative cost semantics."""

    def test_build_paper_tables_emits_run_and_task_rows(self) -> None:
        """Run-level and task-level rows should expose stable columns."""
        tables = build_paper_tables(
            {
                "baseline": _summary(
                    runtime_auth_enabled=False,
                    task_latency=10.1234567,
                    model_call_count=2,
                    llm_elapsed=8.5,
                ),
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                ),
            }
        )

        self.assertEqual(tables["run_level_columns"], list(RUN_LEVEL_COLUMNS))
        self.assertEqual(tables["task_level_columns"], list(TASK_LEVEL_COLUMNS))
        self.assertEqual(len(tables["run_level_rows"]), 2)
        self.assertEqual(len(tables["task_level_rows"]), 2)

        baseline_row = tables["run_level_rows"][0]
        pq_can_task = tables["task_level_rows"][1]
        self.assertEqual(baseline_row["mode"], "baseline")
        self.assertFalse(baseline_row["runtime_auth_enabled"])
        self.assertEqual(baseline_row["task_latency_seconds_total"], 10.123457)
        self.assertEqual(baseline_row["llm_elapsed_seconds_total"], 8.5)
        self.assertFalse(baseline_row["api_cost_available"])
        self.assertIsNone(baseline_row["api_cost_usd_total"])
        self.assertEqual(pq_can_task["mode"], "pq_can")
        self.assertTrue(pq_can_task["runtime_auth_enabled"])
        self.assertEqual(pq_can_task["oracle_reason"], "meeting_scheduled")

    def test_audit_counts_track_execution_gate_records_only(self) -> None:
        """Audit fields should preserve execution-gate counts without inventing tool failures."""
        tables = build_paper_tables(
            {
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                    peer_audit_reject_count=2,
                )
            }
        )

        row = tables["run_level_rows"][0]
        task_row = tables["task_level_rows"][0]
        self.assertEqual(row["audit_record_count"], 2)
        self.assertEqual(row["audit_reject_count"], 0)
        self.assertEqual(task_row["peer_audit_reject_count"], 2)

    def test_load_end_to_end_summary_reads_json_object(self) -> None:
        """Summary loader should reject non-object JSON and return objects unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_path = Path(tmpdir) / "summary.json"
            summary_path.write_text(json.dumps({"task_count": 0}), encoding="utf-8")

            self.assertEqual(load_end_to_end_summary(summary_path), {"task_count": 0})

            summary_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                load_end_to_end_summary(summary_path)

    def test_format_markdown_table_outputs_stable_cells(self) -> None:
        """Markdown output should keep column order and render None as an empty cell."""
        markdown = format_markdown_table(
            [{"mode": "baseline", "api_cost_usd_total": None, "value": 1.230000}],
            ("mode", "api_cost_usd_total", "value"),
        )

        self.assertEqual(
            markdown.splitlines(),
            [
                "| mode | api_cost_usd_total | value |",
                "| --- | --- | --- |",
                "| baseline |  | 1.23 |",
            ],
        )

    def test_default_summary_paths_can_build_current_20260527_tables(self) -> None:
        """Checked local run summaries should remain readable when present in the workspace."""
        if not DEFAULT_BASELINE_SUMMARY_PATH.exists() or not DEFAULT_PQ_CAN_SUMMARY_PATH.exists():
            self.skipTest("local ignored end-to-end summaries are not present")

        tables = build_paper_tables(
            {
                "baseline": load_end_to_end_summary(DEFAULT_BASELINE_SUMMARY_PATH),
                "pq_can": load_end_to_end_summary(DEFAULT_PQ_CAN_SUMMARY_PATH),
            }
        )

        rows_by_mode = {
            str(row["mode"]): row
            for row in tables["run_level_rows"]
        }
        self.assertEqual(rows_by_mode["baseline"]["succeeded_count"], 3)
        self.assertEqual(rows_by_mode["pq_can"]["succeeded_count"], 3)
        self.assertEqual(rows_by_mode["baseline"]["audit_record_count"], 0)
        self.assertEqual(rows_by_mode["pq_can"]["audit_record_count"], 0)


if __name__ == "__main__":
    unittest.main()
