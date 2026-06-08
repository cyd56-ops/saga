"""Tests for the offline ablation and overhead runner."""

from __future__ import annotations

import json
import tempfile
import unittest

from experiments.ablation_overhead_runner import (
    ABLATION_MODES,
    OVERHEAD_METRICS,
    run_ablation_overhead,
    summarize_ablation,
    write_ablation_overhead_results,
)


class AblationOverheadRunnerTests(unittest.TestCase):
    """Verify offline SAGA-PQ-CAN ablation and overhead experiments.

    测试消融对比、开销指标和实验结果落盘格式。
    """

    def test_ablation_modes_capture_expected_security_differences(self) -> None:
        """Ablation results should show the added coverage of PQ-CAN layers.

        不同模式应体现 envelope、scope policy 和 Shamir MASK 的增量作用。
        """
        ablation_results, _ = run_ablation_overhead(iterations=1)
        by_mode_case = {
            (result.mode, result.case): result for result in ablation_results
        }

        self.assertEqual(set(ABLATION_MODES), {result.mode for result in ablation_results})
        for mode in ABLATION_MODES:
            self.assertTrue(by_mode_case[(mode, "valid_prompt")].allowed)

        self.assertTrue(by_mode_case[("saga_only", "tampered_message")].allowed)
        self.assertFalse(
            by_mode_case[("ordinary_pq_middleware", "tampered_message")].allowed
        )
        self.assertTrue(
            by_mode_case[("ordinary_pq_middleware", "prompt_surface_tool_only")].allowed
        )
        self.assertTrue(
            by_mode_case[("naive_neural_verifier", "real_valued_signature_input")].allowed
        )
        self.assertFalse(
            by_mode_case[("shamir_secured_pq_can", "prompt_surface_tool_only")].allowed
        )
        self.assertFalse(
            by_mode_case[("shamir_secured_pq_can", "unauthorized_tool_scope")].allowed
        )
        self.assertFalse(
            by_mode_case[("shamir_secured_pq_can", "real_valued_signature_input")].allowed
        )

    def test_ablation_summary_counts_negative_rejections_by_mode(self) -> None:
        """Summary should expose per-mode rejection coverage.

        summary 用于比较不同消融模式拒绝负向样本的数量。
        """
        ablation_results, _ = run_ablation_overhead(iterations=1)
        summary = summarize_ablation(ablation_results)

        saga_only = summary["modes"]["saga_only"]
        pq_can = summary["modes"]["shamir_secured_pq_can"]

        self.assertEqual(saga_only["negative_rejected_count"], 0)
        self.assertEqual(pq_can["negative_rejected_count"], 5)
        self.assertEqual(pq_can["passed_count"], 6)

    def test_overhead_results_include_all_metrics(self) -> None:
        """The runner should emit stable timing metric names.

        开销统计必须覆盖签名、普通验签、compiled verifier、CAN 和 gate。
        """
        _, overhead_results = run_ablation_overhead(iterations=3)

        self.assertEqual(
            {result.metric for result in overhead_results},
            set(OVERHEAD_METRICS),
        )
        for result in overhead_results:
            self.assertEqual(result.iterations, 3)
            self.assertGreaterEqual(result.min_ns, 0)
            self.assertGreaterEqual(result.max_ns, result.min_ns)
            self.assertGreaterEqual(result.mean_ns, 0.0)
            self.assertGreaterEqual(result.median_ns, 0.0)

    def test_writer_emits_ablation_overhead_artifacts(self) -> None:
        """Ablation and overhead artifacts should be JSON-readable.

        实验结果应以稳定 JSON/JSONL 形式写入 ignored run 目录。
        """
        ablation_results, overhead_results = run_ablation_overhead(iterations=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            ablation_path, overhead_path, summary_path = write_ablation_overhead_results(
                ablation_results=ablation_results,
                overhead_results=overhead_results,
                output_dir=tmpdir,
            )

            ablation_rows = [
                json.loads(line)
                for line in ablation_path.read_text(encoding="utf-8").splitlines()
            ]
            overhead_rows = json.loads(overhead_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(len(ablation_rows), len(ABLATION_MODES) * 6)
        self.assertEqual(len(overhead_rows), len(OVERHEAD_METRICS))
        self.assertIn("shamir_secured_pq_can", summary["modes"])
        self.assertEqual(set(summary["overhead_metrics"]), set(OVERHEAD_METRICS))


if __name__ == "__main__":
    unittest.main()
