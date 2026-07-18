"""Tests for the real ML-DSA Route B fixed-policy shadow runner."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from experiments.route_b_shadow_runner import (
    main,
    run_real_route_b_shadow_corpus,
)


class RealRouteBShadowRunnerTests(unittest.TestCase):
    """验证真实 backend corpus、事实覆盖和无敏感材料报告 contract。"""

    def test_real_runner_covers_all_facts_and_never_grants_authority(self) -> None:
        """八个真实签名 case 应全等价、覆盖六项 false fact 且 authority 为零。"""
        report = run_real_route_b_shadow_corpus()
        payload = report.as_dict()

        self.assertTrue(report.all_passed)
        self.assertEqual(report.manifest.total_cases, 8)
        self.assertEqual(report.manifest.signature_accepted_count, 7)
        self.assertEqual(report.manifest.fixed_accepted_count, 2)
        self.assertEqual(report.manifest.equivalent_count, 8)
        self.assertEqual(report.manifest.mismatch_count, 0)
        self.assertEqual(report.manifest.authority_granted_count, 0)
        self.assertTrue(
            all(count > 0 for _name, count in report.manifest.fact_false_counts)
        )
        self.assertEqual(report.expected_reason_mismatches, ())
        self.assertEqual(payload["backend"]["algorithm_id"], 44)
        self.assertEqual(payload["backend"]["profile_id"], 2)

        encoded = json.dumps(payload, sort_keys=True)
        self.assertNotIn("secret_key", encoded)
        self.assertNotIn("private_key", encoded)
        self.assertNotIn("public_key", encoded)
        self.assertNotIn("signature_bytes", encoded)
        self.assertIn("cannot authorize execution", encoded)

    def test_cli_writes_the_same_real_report_emitted_on_stdout(self) -> None:
        """CLI 应将不含密钥的报告写入临时路径，并以零状态表示通过。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "route-b-shadow.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["--output", str(output_path)])

            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout_payload, file_payload)
            self.assertTrue(file_payload["all_passed"])


if __name__ == "__main__":
    unittest.main()
