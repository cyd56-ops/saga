"""Tests for the schedule-meeting experiment oracle."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
from unittest import mock

from experiments.schedule_meeting import (
    MeetingScheduleTest,
    _next_workday_anchor,
    build_schedule_meeting_task,
)


class MeetingScheduleTestOracleTests(unittest.TestCase):
    """Verify the experiment oracle reports stable success/failure reasons."""

    def test_task_prompt_binds_initiator_email(self) -> None:
        """The live prompt should bind the real invite address to avoid placeholders."""
        task = build_schedule_meeting_task(
            initiator_name="Emma Johnson",
            initiator_email="emma_johnson@gmail.com",
            receiver_name="Raj Sharma",
            receiver_email="raj.sharma@gmail.com",
            earliest_start=datetime(2026, 5, 20, 9, 0, 0),
        )

        self.assertIn("Emma Johnson", task)
        self.assertIn("emma_johnson@gmail.com", task)
        self.assertIn("Raj Sharma", task)
        self.assertIn("raj.sharma@gmail.com", task)
        self.assertIn("Wednesday, May 20, 2026", task)
        self.assertIn("09:00 and 17:00", task)
        self.assertIn("Do not use placeholder or example email addresses", task)
        self.assertNotIn("alex.chen@acme.com", task)
        self.assertNotIn("Tuesday for a 30-minute meeting", task)

    def test_next_workday_anchor_skips_past_and_weekends(self) -> None:
        """任务日期锚点必须始终落在未来工作日上午。"""
        self.assertEqual(
            _next_workday_anchor(datetime(2026, 5, 19, 17, 31, 0)),
            datetime(2026, 5, 20, 9, 0, 0),
        )
        self.assertEqual(
            _next_workday_anchor(datetime(2026, 5, 22, 17, 31, 0)),
            datetime(2026, 5, 25, 9, 0, 0),
        )

    def test_success_records_structured_oracle_details(self) -> None:
        """A matching future half-hour meeting should be marked successful."""
        now = datetime.now()
        event = {
            "time_from": now + timedelta(days=1),
            "time_to": now + timedelta(days=1, minutes=30),
            "event": "NDSS sync",
            "details": "Discuss paper status",
        }
        user_config = SimpleNamespace(name="Emma", email="emma@example.com")

        calendars = [
            mock.Mock(get_upcoming_events=mock.Mock(return_value=[event])),
            mock.Mock(get_upcoming_events=mock.Mock(return_value=[event])),
        ]
        with mock.patch("experiments.schedule_meeting.LocalCalendarTool", side_effect=calendars):
            oracle = MeetingScheduleTest(user_config)

            success = oracle.success("Raj", "raj@example.com")

        self.assertTrue(success)
        assert oracle.last_evaluation is not None
        self.assertTrue(oracle.last_evaluation["oracle_success"])
        self.assertEqual(oracle.last_evaluation["oracle_reason"], "meeting_scheduled")
        self.assertEqual(oracle.last_evaluation["meeting_duration_hours"], 0.5)

    def test_mismatched_duration_returns_stable_failure_reason(self) -> None:
        """Unexpected meeting duration should be reported explicitly."""
        now = datetime.now()
        event = {
            "time_from": now + timedelta(days=1),
            "time_to": now + timedelta(days=1, hours=1),
            "event": "NDSS sync",
            "details": "Discuss paper status",
        }
        user_config = SimpleNamespace(name="Emma", email="emma@example.com")

        calendars = [
            mock.Mock(get_upcoming_events=mock.Mock(return_value=[event])),
            mock.Mock(get_upcoming_events=mock.Mock(return_value=[event])),
        ]
        with mock.patch("experiments.schedule_meeting.LocalCalendarTool", side_effect=calendars):
            oracle = MeetingScheduleTest(user_config)

            success = oracle.success("Raj", "raj@example.com")

        self.assertFalse(success)
        assert oracle.last_evaluation is not None
        self.assertEqual(oracle.last_evaluation["oracle_reason"], "unexpected_meeting_duration")
        self.assertEqual(oracle.last_evaluation["meeting_duration_hours"], 1.0)


if __name__ == "__main__":
    unittest.main()
