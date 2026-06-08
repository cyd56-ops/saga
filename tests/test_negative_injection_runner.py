"""Tests for the offline negative-injection runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock

from experiments.negative_injection_runner import (
    DEFAULT_SCENARIOS,
    NegativeInjectionResult,
    available_scenarios,
    build_summary,
    main,
    run_negative_injections,
    write_negative_injection_results,
)


class NegativeInjectionRunnerTests(unittest.TestCase):
    """Verify deterministic fail-closed negative-injection scenarios.

    测试离线负向注入 runner 的覆盖范围、输出和失败状态码。
    """

    def test_default_scenarios_cover_required_negative_cases(self) -> None:
        """Runner scenario names should include the current required coverage list.

        默认场景清单必须覆盖当前要求的负向测试范围。
        """
        self.assertEqual(available_scenarios(), DEFAULT_SCENARIOS)
        self.assertIn("tampered_message", DEFAULT_SCENARIOS)
        self.assertIn("tampered_action_scope", DEFAULT_SCENARIOS)
        self.assertIn("tampered_authorized_scope", DEFAULT_SCENARIOS)
        self.assertIn("expired_envelope", DEFAULT_SCENARIOS)
        self.assertIn("replayed_envelope", DEFAULT_SCENARIOS)
        self.assertIn("unauthorized_tool_scope", DEFAULT_SCENARIOS)
        self.assertIn("unauthorized_memory_write", DEFAULT_SCENARIOS)
        self.assertIn("unauthorized_delegation", DEFAULT_SCENARIOS)
        self.assertIn("real_valued_signature_input", DEFAULT_SCENARIOS)
        self.assertIn("untrusted_sender_aid", DEFAULT_SCENARIOS)
        self.assertIn("wrong_trusted_sender_key", DEFAULT_SCENARIOS)
        self.assertIn("agent_runtime_prompt_surface_tool_only", DEFAULT_SCENARIOS)
        self.assertIn("agent_runtime_replayed_envelope", DEFAULT_SCENARIOS)
        self.assertIn("agent_runtime_scope_escalation_tool", DEFAULT_SCENARIOS)

    def test_runner_passes_all_default_negative_injections(self) -> None:
        """All default injections should be rejected with their expected reasons.

        每个默认注入都应按预期 fail-closed。
        """
        results = run_negative_injections()
        summary = build_summary(results)

        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["scenario_count"], len(DEFAULT_SCENARIOS))
        self.assertEqual(summary["passed_count"], len(DEFAULT_SCENARIOS))
        observed = {result.scenario: result.observed_reason for result in results}
        self.assertEqual(observed["tampered_message"], "message_digest_mismatch")
        self.assertEqual(observed["tampered_action_scope"], "action_scope_mismatch")
        self.assertEqual(
            observed["tampered_authorized_scope"],
            "signature_verification_failed",
        )
        self.assertEqual(observed["expired_envelope"], "envelope_expired")
        self.assertEqual(observed["replayed_envelope"], "replayed_request_envelope")
        self.assertEqual(observed["untrusted_sender_aid"], "untrusted_sender_aid")
        self.assertEqual(
            observed["wrong_trusted_sender_key"],
            "signature_verification_failed",
        )
        self.assertEqual(
            observed["agent_runtime_prompt_surface_tool_only"],
            "prompt_scope_not_authorized",
        )
        self.assertEqual(
            observed["agent_runtime_replayed_envelope"],
            "replayed_request_envelope",
        )
        self.assertEqual(
            observed["agent_runtime_scope_escalation_tool"],
            "unauthorized_tool_scope",
        )

    def test_runner_records_execution_surface_rejections_without_side_effects(self) -> None:
        """Tool, memory, and delegation injections should not trigger side effects.

        工具、内存和委托越权不应触发实际副作用。
        """
        results = run_negative_injections(
            (
                "unauthorized_tool_scope",
                "unauthorized_memory_write",
                "unauthorized_delegation",
            )
        )

        self.assertTrue(all(result.passed for result in results))
        self.assertTrue(all(not result.side_effect_triggered for result in results))
        self.assertEqual(
            {result.observed_reason for result in results},
            {
                "unauthorized_tool_scope",
                "unauthorized_memory_write",
                "unauthorized_delegation",
            },
        )

    def test_runner_covers_real_agent_runtime_negative_paths(self) -> None:
        """Agent runtime injections should reject before unauthorized side effects.

        真实 Agent 执行路径中的 prompt/replay/scope escalation 必须 fail-closed。
        """
        results = run_negative_injections(
            (
                "agent_runtime_prompt_surface_tool_only",
                "agent_runtime_replayed_envelope",
                "agent_runtime_scope_escalation_tool",
            )
        )

        self.assertTrue(all(result.passed for result in results))
        self.assertTrue(all(not result.side_effect_triggered for result in results))
        self.assertEqual(
            {result.observed_reason for result in results},
            {
                "prompt_scope_not_authorized",
                "replayed_request_envelope",
                "unauthorized_tool_scope",
            },
        )

    def test_result_writer_emits_jsonl_and_summary(self) -> None:
        """Runner artifacts should be stable JSON files.

        runner 产物应是可机器读取的稳定 JSON/JSONL 文件。
        """
        results = run_negative_injections(("tampered_message", "expired_envelope"))

        with tempfile.TemporaryDirectory() as tmpdir:
            results_path, summary_path = write_negative_injection_results(results, tmpdir)

            rows = [
                json.loads(line)
                for line in results_path.read_text(encoding="utf-8").splitlines()
            ]
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["scenario"], "tampered_message")
        self.assertTrue(rows[0]["passed"])
        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["passed_count"], 2)
        self.assertEqual(summary["scenario_count"], 2)

    def test_cli_returns_nonzero_when_a_result_fails(self) -> None:
        """CLI status should fail when any scenario does not reject as expected.

        任一场景未按预期拒绝时 CLI 必须返回非零。
        """
        bad_result = NegativeInjectionResult(
            scenario="bad",
            category="test",
            passed=False,
            allowed=True,
            expected_reason="reject",
            observed_reason="authorized",
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.negative_injection_runner.run_negative_injections",
            return_value=[bad_result],
        ):
            exit_code = main(["--scenario", "tampered_message", "--output-dir", tmpdir])

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
