"""Tests for structured experiment result logging helpers."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from experiments.result_logging import (
    append_experiment_result_record,
    build_experiment_result_record,
    collect_query_execution_stats,
    filter_records_since,
    load_execution_gate_audit_records,
    summarize_end_to_end_task_stats,
    summarize_execution_gate_audits,
)


class ExperimentResultLoggingTests(unittest.TestCase):
    """Verify JSONL result logging and audit summaries for experiments."""

    def test_summarize_execution_gate_audits_counts_reject_reasons(self) -> None:
        """Reject counts should aggregate only denied audit records."""
        summary = summarize_execution_gate_audits(
            [
                {"allowed": False, "reason": "missing_pq_signature"},
                {"allowed": False, "reason": "missing_pq_signature"},
                {"allowed": False, "reason": "signature_verification_failed"},
                {"allowed": True, "reason": "authorized"},
            ]
        )

        self.assertEqual(summary["audit_reject_count"], 3)
        self.assertEqual(
            summary["audit_reject_reasons"],
            {
                "missing_pq_signature": 2,
                "signature_verification_failed": 1,
            },
        )

    def test_build_experiment_result_record_includes_audit_summary(self) -> None:
        """Result records should carry stable experiment and audit summary fields."""
        record = build_experiment_result_record(
            task_name="schedule_meeting",
            mode="query",
            config_path="user_configs/emma_pqcan.yaml",
            other_config_path="user_configs/raj_pqcan.yaml",
            agent_aid="emma_johnson@gmail.com:calendar_agent",
            peer_aid="raj.sharma@gmail.com:calendar_agent",
            runtime_auth_enabled=True,
            success=True,
            audit_records=[
                {"allowed": False, "reason": "signature_verification_failed"},
                {"allowed": False, "reason": "signature_verification_failed"},
            ],
            extra_fields={"oracle_reason": "meeting_scheduled"},
        )

        self.assertEqual(record["task_name"], "schedule_meeting")
        self.assertEqual(record["mode"], "query")
        self.assertTrue(record["runtime_auth_enabled"])
        self.assertTrue(record["success"])
        self.assertEqual(record["audit_reject_count"], 2)
        self.assertEqual(
            record["audit_reject_reasons"],
            {"signature_verification_failed": 2},
        )
        self.assertEqual(record["oracle_reason"], "meeting_scheduled")
        self.assertIn("recorded_at", record)

    def test_append_experiment_result_record_writes_task_jsonl(self) -> None:
        """Result records should append to task-specific JSONL files."""
        record = {
            "task_name": "create_blogpost",
            "mode": "listen",
            "agent_aid": "emma_johnson@gmail.com:writing_agent",
            "success": None,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            result_path = append_experiment_result_record(
                "create_blogpost",
                record,
                results_dir=tmpdir,
            )

            self.assertEqual(result_path, Path(tmpdir) / "create_blogpost.jsonl")
            rows = result_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(rows), 1)
            payload = json.loads(rows[0])
            self.assertEqual(payload["task_name"], "create_blogpost")
            self.assertEqual(payload["mode"], "listen")
            self.assertIsNone(payload["success"])

    def test_load_execution_gate_audit_records_reads_jsonl_rows(self) -> None:
        """Audit record loading should deserialize JSONL rows from agent workdirs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = Path(tmpdir) / "audit"
            audit_dir.mkdir(parents=True, exist_ok=True)
            audit_path = audit_dir / "execution_gate.jsonl"
            audit_path.write_text(
                "\n".join(
                    [
                        json.dumps({"allowed": False, "reason": "missing_pq_signature"}),
                        json.dumps({"allowed": False, "reason": "action_scope_mismatch"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            records = load_execution_gate_audit_records(tmpdir)

            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["reason"], "missing_pq_signature")
            self.assertEqual(records[1]["reason"], "action_scope_mismatch")

    def test_filter_records_since_uses_recorded_at_window(self) -> None:
        """Task summaries should ignore stale audit rows from previous runs."""
        started_at = datetime(2026, 5, 27, 8, 0, tzinfo=timezone.utc)

        rows = filter_records_since(
            [
                {"recorded_at": "2026-05-27T07:59:59+00:00", "reason": "old"},
                {"recorded_at": "2026-05-27T08:00:00+00:00", "reason": "current"},
                {"recorded_at": "bad timestamp", "reason": "ignored"},
            ],
            started_at=started_at,
        )

        self.assertEqual([row["reason"] for row in rows], ["current"])

    def test_summarize_end_to_end_task_stats_counts_latency_calls_and_audits(self) -> None:
        """End-to-end stats should expose latency, model calls, audit counts, and cost status."""
        started_at = datetime(2026, 5, 27, 8, 0, tzinfo=timezone.utc)
        finished_at = started_at + timedelta(seconds=12)

        summary = summarize_end_to_end_task_stats(
            started_at=started_at,
            finished_at=finished_at,
            local_run_records=[
                {"run_status": "started", "llm_elapsed_seconds": None},
                {
                    "run_status": "completed",
                    "model_call_count": 2,
                    "llm_elapsed_seconds": 1.5,
                    "api_cost_usd": 0.02,
                    "total_tokens": 100,
                },
            ],
            peer_run_records=[
                {
                    "run_status": "completed",
                    "model_call_count": 3,
                    "llm_elapsed_seconds": 2.5,
                    "api_cost_usd": 0.03,
                    "total_tokens": 200,
                }
            ],
            local_audit_records=[],
            peer_audit_records=[{"allowed": False, "reason": "missing_pq_signature"}],
        )

        self.assertEqual(summary["task_latency_seconds"], 12.0)
        self.assertEqual(summary["model_call_count"], 5)
        self.assertEqual(summary["local_model_call_count"], 2)
        self.assertEqual(summary["peer_model_call_count"], 3)
        self.assertEqual(summary["llm_elapsed_seconds_total"], 4.0)
        self.assertTrue(summary["api_cost_available"])
        self.assertEqual(summary["api_cost_usd"], 0.05)
        self.assertTrue(summary["token_usage_available"])
        self.assertEqual(summary["total_tokens"], 300)
        self.assertEqual(summary["audit_record_count"], 1)

    def test_collect_query_execution_stats_reads_current_window(self) -> None:
        """Query stats should combine diagnostics and execution-gate audit summaries."""
        started_at = datetime(2026, 5, 27, 8, 0, tzinfo=timezone.utc)
        finished_at = started_at + timedelta(seconds=3)

        with tempfile.TemporaryDirectory() as local_tmp, tempfile.TemporaryDirectory() as peer_tmp:
            local_diag_dir = Path(local_tmp) / "diagnostics"
            peer_diag_dir = Path(peer_tmp) / "diagnostics"
            local_diag_dir.mkdir(parents=True)
            peer_diag_dir.mkdir(parents=True)
            (local_diag_dir / "local_agent_runs.jsonl").write_text(
                json.dumps(
                    {
                        "recorded_at": started_at.isoformat(),
                        "conversation_side": "initiating",
                        "run_status": "completed",
                        "tool_call_names": ["send_email"],
                        "tool_call_count": 1,
                        "model_call_count": 1,
                        "error_step_count": 0,
                        "final_answer_step_count": 1,
                        "llm_elapsed_seconds": 1.0,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (peer_diag_dir / "local_agent_runs.jsonl").write_text(
                json.dumps(
                    {
                        "recorded_at": finished_at.isoformat(),
                        "conversation_side": "receiving",
                        "run_status": "completed",
                        "tool_call_names": ["check_inbox"],
                        "tool_call_count": 1,
                        "model_call_count": 2,
                        "error_step_count": 0,
                        "final_answer_step_count": 0,
                        "llm_elapsed_seconds": 2.0,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            peer_audit_dir = Path(peer_tmp) / "audit"
            peer_audit_dir.mkdir(parents=True)
            (peer_audit_dir / "execution_gate.jsonl").write_text(
                json.dumps(
                    {
                        "recorded_at": finished_at.isoformat(),
                        "allowed": False,
                        "reason": "signature_verification_failed",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            audit_records, stats = collect_query_execution_stats(
                local_workdir=local_tmp,
                peer_workdir=peer_tmp,
                started_at=started_at,
                finished_at=finished_at,
            )

        self.assertEqual(audit_records, [])
        self.assertEqual(stats["model_call_count"], 3)
        self.assertEqual(stats["local_run_tool_names"], ["send_email"])
        self.assertEqual(stats["peer_run_tool_names"], ["check_inbox"])
        self.assertEqual(stats["peer_audit_reject_count"], 1)
        self.assertEqual(stats["audit_record_count"], 1)
        self.assertFalse(stats["api_cost_available"])
        self.assertIsNone(stats["api_cost_usd"])


if __name__ == "__main__":
    unittest.main()
