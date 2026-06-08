"""Tests for the optional StrictRuntimeAuth TLC checker."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from experiments import tlc_strict_runtime_auth_check as tlc_check


TLC_SUCCESS_OUTPUT = """\
Finished computing initial states: 32 distinct states generated at now.
Model checking completed. No error has been found.
65 states generated, 33 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 2.
"""


class TLCStrictRuntimeAuthCheckTests(unittest.TestCase):
    """验证 StrictRuntimeAuth TLC 分解验收入口的解析、编排和失败语义。"""

    def test_extract_tla_surface_constants_preserves_inventory_order(self) -> None:
        """cfg surface 解析应保留 full inventory 顺序，供 per-surface runner 使用。"""
        text = """
CONSTANTS
    Surfaces = {
        llm_prompt,
        memory_write
    }
"""

        self.assertEqual(
            tlc_check.extract_tla_surface_constants(text),
            ("llm_prompt", "memory_write"),
        )

    def test_write_surface_config_emits_single_surface_cfg(self) -> None:
        """per-surface 临时 cfg 必须只包含一个 surface 和同一 invariant 集合。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = tlc_check.write_surface_config("llm_prompt", tmpdir)
            text = cfg_path.read_text(encoding="utf-8")

        self.assertIn("Surfaces = {llm_prompt}", text)
        self.assertIn("SPECIFICATION Spec", text)
        self.assertIn("ExecuteSurfaceClaim", text)
        self.assertIn("ScopeCheckRequired", text)

    def test_write_surface_config_rejects_unsafe_model_value(self) -> None:
        """临时 cfg 生成必须拒绝非 TLA model value，避免写出错误配置。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError):
                tlc_check.write_surface_config("bad-value", tmpdir)

    def test_parse_tlc_output_extracts_success_statistics(self) -> None:
        """TLC 输出解析应提取成功标记和关键状态空间统计。"""
        stats = tlc_check.parse_tlc_output(TLC_SUCCESS_OUTPUT)

        self.assertTrue(stats["completed"])
        self.assertEqual(stats["initial_states"], 32)
        self.assertEqual(stats["states_generated"], 65)
        self.assertEqual(stats["distinct_states"], 33)
        self.assertEqual(stats["depth"], 2)

    def test_run_check_generates_per_surface_cfgs_and_summary(self) -> None:
        """runner 应为所选 surface 生成 cfg，运行 TLC，并写出 summary JSON。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.tlc_strict_runtime_auth_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("java", "tlc2.TLC"),
                returncode=0,
                stdout=TLC_SUCCESS_OUTPUT,
                stderr="",
            ),
        ) as subprocess_run:
            report = tlc_check.run_tlc_strict_runtime_auth_check(
                output_dir=tmpdir,
                surface_names=("llm_prompt", "llm_prompt", "memory_write"),
                include_pair_smoke=True,
                tla2tools_jar="/tmp/tla2tools.jar",
                java_executable="java",
                timeout_seconds=5,
            )
            summary = json.loads(
                (Path(tmpdir) / "tlc_strict_runtime_auth_summary.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertTrue(report.passed)
        self.assertTrue(summary["passed"])
        self.assertEqual(report.checked_surfaces, ("llm_prompt", "memory_write"))
        self.assertTrue(summary["include_layered_model"])
        self.assertEqual(len(report.results), 4)
        self.assertEqual(subprocess_run.call_count, 4)
        self.assertEqual(report.results[-1].name, "layered_model")
        self.assertTrue(
            report.results[-1].spec_path.endswith("StrictRuntimeAuthLayered.tla")
        )
        commands = [call.args[0] for call in subprocess_run.call_args_list]
        self.assertTrue(all("-config" in command for command in commands))
        self.assertTrue(
            any(
                any("StrictRuntimeAuth_llm_prompt.cfg" in part for part in command)
                for command in commands
            )
        )
        self.assertFalse(
            any(
                command[command.index("-config") + 1].endswith(
                    "StrictRuntimeAuth.cfg"
                )
                for command in commands
            )
        )

    def test_run_check_can_skip_layered_model(self) -> None:
        """CLI/runner 应允许跳过 layered TLC，便于只验证 per-surface 编排。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.tlc_strict_runtime_auth_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("java", "tlc2.TLC"),
                returncode=0,
                stdout=TLC_SUCCESS_OUTPUT,
                stderr="",
            ),
        ) as subprocess_run:
            report = tlc_check.run_tlc_strict_runtime_auth_check(
                output_dir=tmpdir,
                surface_names=("llm_prompt",),
                include_pair_smoke=False,
                include_layered_model=False,
                timeout_seconds=5,
            )

        self.assertTrue(report.passed)
        self.assertFalse(report.include_layered_model)
        self.assertEqual(
            [result.name for result in report.results],
            ["surface:llm_prompt"],
        )
        subprocess_run.assert_called_once()

    def test_run_check_reports_tlc_failure(self) -> None:
        """任何 per-surface TLC 返回非零都必须让 summary fail closed。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.tlc_strict_runtime_auth_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("java", "tlc2.TLC"),
                returncode=1,
                stdout="Error: invariant violated\n",
                stderr="",
            ),
        ):
            report = tlc_check.run_tlc_strict_runtime_auth_check(
                output_dir=tmpdir,
                surface_names=("llm_prompt",),
                include_pair_smoke=False,
                timeout_seconds=5,
            )

        self.assertFalse(report.passed)
        self.assertEqual(report.findings[0].artifact, "surface:llm_prompt")
        self.assertIn("TLC did not complete successfully", report.findings[0].reason)

    def test_run_check_rejects_surface_not_in_full_cfg(self) -> None:
        """CLI 指定的 surface 必须来自 full inventory cfg。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError):
                tlc_check.run_tlc_strict_runtime_auth_check(
                    output_dir=tmpdir,
                    surface_names=("not_a_surface",),
                    include_pair_smoke=False,
                )

    def test_cli_returns_success_when_mocked_tlc_passes(self) -> None:
        """CLI 在所有 TLC 子检查通过时返回 0，并打印 JSON summary。"""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.tlc_strict_runtime_auth_check.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=("java", "tlc2.TLC"),
                returncode=0,
                stdout=TLC_SUCCESS_OUTPUT,
                stderr="",
            ),
        ), mock.patch.object(tlc_check, "print") as print_mock:
            exit_code = tlc_check.main(
                [
                    "--output-dir",
                    tmpdir,
                    "--surface",
                    "llm_prompt",
                    "--skip-pair-smoke",
                    "--skip-layered-model",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(print_mock.call_args.args[0])
        self.assertTrue(payload["passed"])
        self.assertFalse(payload["include_layered_model"])


if __name__ == "__main__":
    unittest.main()
