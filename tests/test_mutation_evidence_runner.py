"""Tests for the executable mutation-evidence runner."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from experiments import mutation_evidence_runner as runner
from saga.security_kernel import mutation_evidence


class MutationEvidenceRunnerTests(unittest.TestCase):
    """验证 mutation evidence runner 的清单、产物和命令执行语义。"""

    def test_mutation_specs_match_security_kernel_evidence(self) -> None:
        """可执行 mutation 定义必须和 security kernel 中的 P4 清单保持一致。"""
        evidence_by_id = {evidence.mutation_id: evidence for evidence in mutation_evidence()}
        specs_by_id = {spec.mutation_id: spec for spec in runner.mutation_specs()}

        self.assertEqual(set(specs_by_id), set(evidence_by_id))
        for mutation_id, spec in specs_by_id.items():
            self.assertEqual(
                spec.expected_test_failures,
                evidence_by_id[mutation_id].expected_test_failures,
            )
            self.assertTrue(spec.description)
            self.assertTrue(spec.patches)

    def test_select_mutations_deduplicates_and_expands_all(self) -> None:
        """CLI mutation 选择应支持 all 和重复项去重。"""
        all_specs = runner.select_mutations(("all",))
        selected = runner.select_mutations(
            (
                "skip_replay_reserve",
                "skip_replay_reserve",
                "relax_action_scope_matching",
            )
        )

        self.assertEqual(runner.available_mutations(), tuple(spec.mutation_id for spec in all_specs))
        self.assertEqual(
            tuple(spec.mutation_id for spec in selected),
            ("skip_replay_reserve", "relax_action_scope_matching"),
        )

    def test_apply_mutation_patches_rewrites_exact_needle(self) -> None:
        """源码替换必须按精确 needle 发生，避免误改未预期片段。"""
        spec = runner.MutationSpec(
            mutation_id="example",
            description="test mutation",
            patches=(
                runner.MutationPatch(
                    relative_path="pkg/mod.py",
                    needle="return secure()\n",
                    replacement="return insecure()\n",
                ),
            ),
            expected_test_failures=("tests/test_example.py::test_rejects_mutation",),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            target = workspace / "pkg" / "mod.py"
            target.parent.mkdir()
            target.write_text("def f():\n    return secure()\n", encoding="utf-8")

            runner.apply_mutation_patches(workspace, spec)

            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "def f():\n    return insecure()\n",
            )

    def test_dry_run_writes_json_artifacts_without_running_pytest(self) -> None:
        """dry-run 只写计划产物，不复制 workspace 或执行 pytest。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.mutation_evidence_runner.subprocess.run"
        ) as subprocess_run:
            results = runner.run_mutation_evidence(
                ("skip_replay_reserve",),
                output_dir=tmpdir,
                dry_run=True,
            )
            summary = json.loads(
                (Path(tmpdir) / "mutation_evidence_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            rows = [
                json.loads(line)
                for line in (Path(tmpdir) / "mutation_evidence.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]

        subprocess_run.assert_not_called()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].dry_run)
        self.assertTrue(summary["dry_run"])
        self.assertEqual(rows[0]["mutation_id"], "skip_replay_reserve")
        self.assertFalse(rows[0]["applied"])

    def test_run_mutation_evidence_uses_requested_python_executable(self) -> None:
        """调用方指定的 Python 解释器必须传递到 mutation pytest 命令。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = runner.run_mutation_evidence(
                ("skip_replay_reserve",),
                output_dir=tmpdir,
                dry_run=True,
                python_executable="/custom/python",
            )

        self.assertEqual(results[0].command[0], "/custom/python")

    def test_run_mutation_treats_nonzero_pytest_as_detected(self) -> None:
        """对应测试返回非零时，runner 应标记 mutation 已被检测到。"""
        spec = runner.MutationSpec(
            mutation_id="example_detected",
            description="test mutation",
            patches=(
                runner.MutationPatch(
                    relative_path="pkg/mod.py",
                    needle="return secure()\n",
                    replacement="return insecure()\n",
                ),
            ),
            expected_test_failures=("tests/test_example.py::test_rejects_mutation",),
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.mutation_evidence_runner._tracked_or_unignored_files",
            return_value=(Path("pkg/mod.py"),),
        ), mock.patch(
            "experiments.mutation_evidence_runner.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=1,
                stdout="failed as expected\n",
                stderr="",
            ),
        ):
            source_root = Path(tmpdir) / "src"
            source_file = source_root / "pkg" / "mod.py"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("def f():\n    return secure()\n", encoding="utf-8")

            result = runner.run_mutation(
                spec,
                source_root=source_root,
                output_dir=Path(tmpdir) / "out",
                keep_workspace=True,
            )

        self.assertTrue(result.applied)
        self.assertTrue(result.mutation_detected)
        self.assertEqual(result.returncode, 1)
        self.assertIn("failed as expected", result.stdout_tail)

    def test_run_mutation_does_not_treat_collection_error_as_detected(self) -> None:
        """pytest 收集错误不能算作 mutation 被测试有效检测。"""
        spec = runner.MutationSpec(
            mutation_id="example_collection_error",
            description="test mutation",
            patches=(
                runner.MutationPatch(
                    relative_path="pkg/mod.py",
                    needle="return secure()\n",
                    replacement="return insecure()\n",
                ),
            ),
            expected_test_failures=("tests/test_example.py::missing_test",),
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.mutation_evidence_runner._tracked_or_unignored_files",
            return_value=(Path("pkg/mod.py"),),
        ), mock.patch(
            "experiments.mutation_evidence_runner.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("python", "-m", "pytest"),
                returncode=4,
                stdout="no tests ran\n",
                stderr="ERROR: not found\n",
            ),
        ):
            source_root = Path(tmpdir) / "src"
            source_file = source_root / "pkg" / "mod.py"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("def f():\n    return secure()\n", encoding="utf-8")

            result = runner.run_mutation(
                spec,
                source_root=source_root,
                output_dir=Path(tmpdir) / "out",
                keep_workspace=True,
            )

        self.assertTrue(result.applied)
        self.assertFalse(result.mutation_detected)
        self.assertEqual(result.returncode, 4)
        self.assertIn("ERROR: not found", result.stderr_tail)

    def test_main_returns_success_for_dry_run(self) -> None:
        """dry-run CLI 应返回 0，便于用户预览将执行的 mutation 命令。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            exit_code = runner.main(
                [
                    "--mutation",
                    "skip_replay_reserve",
                    "--output-dir",
                    tmpdir,
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
