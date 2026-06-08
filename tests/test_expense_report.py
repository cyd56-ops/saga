"""Tests for the expense-report experiment prompt."""

from __future__ import annotations

import unittest

from experiments.expense_report import build_expense_report_task


class ExpenseReportTaskTests(unittest.TestCase):
    """Verify the live expense-report task binds the oracle-critical fields."""

    def test_task_prompt_binds_year_total_and_hr_email(self) -> None:
        """The prompt should prevent date drift and require the HR report email."""
        task = build_expense_report_task(
            initiator_name="Emma Johnson",
            initiator_email="emma_johnson@gmail.com",
            receiver_name="Raj Sharma",
            receiver_email="raj.sharma@gmail.com",
        )

        self.assertIn("Emma Johnson", task)
        self.assertIn("emma_johnson@gmail.com", task)
        self.assertIn("raj.sharma@gmail.com", task)
        self.assertIn("hr@university.com", task)
        self.assertIn("2025", task)
        self.assertIn("2140", task)
        self.assertIn("Do not ask whether the trip year is 2026", task)
        self.assertIn("Do not finish the task until the HR email has been sent", task)


if __name__ == "__main__":
    unittest.main()
