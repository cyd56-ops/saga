"""Tests for structured local runtime diagnostics."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone

from smolagents.memory import ActionStep, TaskStep, ToolCall
from smolagents.monitoring import Timing

from saga.runtime_diagnostics import (
    append_local_run_diagnostic_record,
    build_local_run_diagnostic_record,
    filter_diagnostics_since,
    load_local_run_diagnostic_records,
    summarize_local_run_diagnostics,
)


class RuntimeDiagnosticsTests(unittest.TestCase):
    """Verify runtime diagnostic records and summaries remain stable."""

    def _build_agent_instance(self):
        """Create a minimal agent-like object with memory steps."""
        action_step = ActionStep(
            step_number=1,
            timing=Timing(start_time=0.0, end_time=1.0),
            tool_calls=[ToolCall(name="add_calendar_event", arguments={}, id="call-1")],
            is_final_answer=True,
        )
        memory = type("MemoryStub", (), {"steps": [TaskStep(task="bootstrap"), action_step]})()
        return type("AgentInstanceStub", (), {"memory": memory})()

    def test_build_local_run_diagnostic_record_summarizes_new_steps(self) -> None:
        """One local run should report tool calls, final answer, and step deltas."""
        record = build_local_run_diagnostic_record(
            agent_aid="emma@example.com:calendar_agent",
            peer_aid="raj@example.com:calendar_agent",
            conversation_side="receiving",
            turn_index=0,
            query="Please book the meeting.",
            response="<TASK_FINISHED>",
            llm_elapsed_seconds=1.25,
            agent_instance=self._build_agent_instance(),
            step_start_index=1,
        )

        self.assertEqual(record["agent_aid"], "emma@example.com:calendar_agent")
        self.assertEqual(record["conversation_side"], "receiving")
        self.assertEqual(record["memory_step_count"], 2)
        self.assertEqual(record["new_memory_step_count"], 1)
        self.assertEqual(record["model_call_count"], 1)
        self.assertEqual(record["tool_call_count"], 1)
        self.assertEqual(record["tool_call_names"], ["add_calendar_event"])
        self.assertEqual(record["final_answer_step_count"], 1)
        self.assertTrue(record["response_is_task_finished"])

    def test_append_and_load_local_run_diagnostic_records_round_trip(self) -> None:
        """Diagnostic rows should persist to per-agent JSONL files."""
        record = {
            "agent_aid": "emma@example.com:calendar_agent",
            "conversation_side": "initiating",
            "turn_index": 2,
            "tool_call_names": ["check_calendar"],
            "tool_call_count": 1,
            "error_step_count": 0,
            "final_answer_step_count": 0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            diagnostics_path = append_local_run_diagnostic_record(tmpdir, record)
            self.assertIsNotNone(diagnostics_path)

            rows = load_local_run_diagnostic_records(tmpdir)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tool_call_names"], ["check_calendar"])
        self.assertIn("recorded_at", rows[0])

    def test_summarize_local_run_diagnostics_aggregates_tools_and_sides(self) -> None:
        """Aggregated summaries should expose stable counts for result logging."""
        summary = summarize_local_run_diagnostics(
            [
                {
                    "conversation_side": "initiating",
                    "tool_call_names": ["check_calendar"],
                    "model_call_count": 1,
                    "error_step_count": 0,
                    "final_answer_step_count": 0,
                    "run_status": "started",
                },
                {
                    "conversation_side": "receiving",
                    "tool_call_names": ["add_calendar_event"],
                    "model_call_count": 2,
                    "error_step_count": 1,
                    "final_answer_step_count": 1,
                    "run_status": "failed",
                    "error": "model timeout",
                },
            ]
        )

        self.assertEqual(summary["local_run_count"], 2)
        self.assertEqual(summary["local_run_model_call_count"], 3)
        self.assertEqual(summary["local_run_tool_call_count"], 2)
        self.assertEqual(
            summary["local_run_tool_names"],
            ["add_calendar_event", "check_calendar"],
        )
        self.assertEqual(summary["local_run_error_step_count"], 1)
        self.assertEqual(summary["local_run_final_answer_step_count"], 1)
        self.assertEqual(
            summary["local_run_by_side"],
            {"initiating": 1, "receiving": 1},
        )
        self.assertEqual(
            summary["local_run_by_status"],
            {"failed": 1, "started": 1},
        )
        self.assertEqual(summary["local_run_failed_count"], 1)
        self.assertEqual(summary["local_run_errors"], ["model timeout"])

    def test_filter_diagnostics_since_returns_current_run_window(self) -> None:
        """Experiment summaries should be able to exclude stale diagnostic rows."""
        started_at = datetime(2026, 5, 18, 8, 0, tzinfo=timezone.utc)

        rows = filter_diagnostics_since(
            [
                {"recorded_at": "2026-05-18T07:59:59+00:00", "run_status": "completed"},
                {"recorded_at": "2026-05-18T08:00:00+00:00", "run_status": "started"},
                {"recorded_at": "2026-05-18T08:00:01+00:00", "run_status": "failed"},
                {"recorded_at": "not-a-date", "run_status": "ignored"},
                {"run_status": "missing_timestamp"},
            ],
            started_at=started_at,
        )

        self.assertEqual([row["run_status"] for row in rows], ["started", "failed"])


if __name__ == "__main__":
    unittest.main()
