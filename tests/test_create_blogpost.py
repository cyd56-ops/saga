"""Tests for the create-blogpost experiment prompt."""

from __future__ import annotations

import unittest

from experiments.create_blogpost import build_blogpost_task


class BlogPostTaskTests(unittest.TestCase):
    """Verify the blogpost task binds the final artifact and participants."""

    def test_task_prompt_requires_saving_expected_markdown_file(self) -> None:
        """The prompt should make document creation the explicit completion condition."""
        task = build_blogpost_task(
            initiator_name="Emma Johnson",
            initiator_email="emma_johnson@gmail.com",
            receiver_name="Raj Sharma",
            receiver_email="raj.sharma@gmail.com",
        )

        self.assertIn("Emma Johnson", task)
        self.assertIn("emma_johnson@gmail.com", task)
        self.assertIn("Raj Sharma", task)
        self.assertIn("raj.sharma@gmail.com", task)
        self.assertIn("Privacy in the Age of AI: Legal and Ethical Implications.md", task)
        self.assertIn("save the final markdown file in documents", task.lower())
        self.assertIn("Do not search existing blogposts", task)
        self.assertIn("Do not finish the task until the blogpost has been saved", task)
        self.assertIn("reply only with the task-finished token", task)


if __name__ == "__main__":
    unittest.main()
