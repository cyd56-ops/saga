"""Tests for real end-to-end ablation planning and summaries."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments import real_ablation_runner


def _summary(*, runtime_auth_enabled: bool, latency: float = 10.0) -> dict[str, object]:
    """构造最小真实 batch summary fixture。"""
    return {
        "task_count": 1,
        "succeeded_count": 1,
        "failed_count": 0,
        "task_latency_seconds_total": latency,
        "task_latency_seconds_mean": latency,
        "model_call_count": 2,
        "audit_record_count": 0,
        "api_cost_available": False,
        "token_usage_available": False,
        "tasks": [
            {
                "task_name": "schedule_meeting",
                "success": True,
                "runtime_auth_enabled": runtime_auth_enabled,
            }
        ],
    }


class RealAblationRunnerTests(unittest.TestCase):
    """Verify real ablation runner stays explicit about wired and offline-only modes."""

    def test_plan_marks_only_current_live_supported_modes(self) -> None:
        """真实消融计划必须明确普通 PQ / naive neural 尚未接入真实 runtime。"""
        plan = real_ablation_runner.build_real_ablation_plan()

        self.assertEqual(
            plan["live_supported_modes"],
            ["saga_only", "shamir_secured_pq_can"],
        )
        self.assertEqual(
            plan["offline_only_modes"],
            ["ordinary_pq_middleware", "naive_neural_verifier"],
        )
        modes = {row["mode"]: row for row in plan["modes"]}
        self.assertFalse(modes["ordinary_pq_middleware"]["live_supported"])
        self.assertFalse(modes["naive_neural_verifier"]["live_supported"])

    def test_build_batch_command_uses_mode_configs(self) -> None:
        """真实 batch 命令应使用对应 mode 的用户配置和 run_dir。"""
        mode = real_ablation_runner.REAL_ABLATION_MODES_BY_ID["shamir_secured_pq_can"]
        command = real_ablation_runner.build_batch_command(
            mode,
            run_dir="/tmp/run/pqcan",
            task_names=("schedule_meeting", "expense_report"),
            python_executable="/venv/bin/python",
            probe_required_successes=1,
            probe_max_attempts=2,
            probe_interval_seconds=0.5,
            model_probe_timeout_seconds=3.0,
            skip_model_probe=True,
            skip_db_preflight=True,
            skip_seed=True,
            allow_task_failure=True,
        )

        self.assertEqual(command[:2], ["/venv/bin/python", str(real_ablation_runner.DEFAULT_BATCH_SCRIPT)])
        self.assertIn("user_configs/emma_pqcan.yaml", " ".join(command))
        self.assertIn("user_configs/raj_pqcan.yaml", " ".join(command))
        self.assertIn("/tmp/run/pqcan", command)
        self.assertEqual(command.count("--task"), 2)
        self.assertIn("--skip-model-probe", command)
        self.assertIn("--allow-task-failure", command)

    def test_build_batch_command_rejects_offline_only_mode(self) -> None:
        """未接入真实 runtime 的消融 mode 不能构造 live batch 命令。"""
        mode = real_ablation_runner.REAL_ABLATION_MODES_BY_ID["naive_neural_verifier"]

        with self.assertRaisesRegex(ValueError, "not wired"):
            real_ablation_runner.build_batch_command(mode, run_dir="/tmp/run")

    def test_summary_uses_existing_batch_artifacts_and_offline_markers(self) -> None:
        """汇总应读取已有真实 summary，并保留 offline-only 状态行。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline_path = root / "baseline.json"
            pqcan_path = root / "pqcan.json"
            baseline_path.write_text(
                json.dumps(_summary(runtime_auth_enabled=False), sort_keys=True),
                encoding="utf-8",
            )
            pqcan_path.write_text(
                json.dumps(_summary(runtime_auth_enabled=True, latency=12.0), sort_keys=True),
                encoding="utf-8",
            )

            summary = real_ablation_runner.build_real_ablation_summary(
                summary_paths={
                    "saga_only": baseline_path,
                    "shamir_secured_pq_can": pqcan_path,
                }
            )

        rows = {row["mode"]: row for row in summary["rows"]}
        self.assertEqual(rows["saga_only"]["status"], "summary_available")
        self.assertTrue(rows["saga_only"]["runtime_auth_matches_expected"])
        self.assertEqual(rows["shamir_secured_pq_can"]["task_latency_seconds_total"], 12.0)
        self.assertEqual(
            rows["ordinary_pq_middleware"]["status"],
            "offline_only_not_live_wired",
        )
        self.assertIsNone(rows["naive_neural_verifier"]["task_count"])

    def test_summary_marks_missing_live_artifact(self) -> None:
        """live-supported mode 缺少 summary 时应显式标记 missing。"""
        summary = real_ablation_runner.build_real_ablation_summary(
            summary_paths={"saga_only": "/tmp/does-not-exist.json"},
            mode_ids=("saga_only",),
        )

        row = summary["rows"][0]
        self.assertEqual(row["status"], "summary_missing")
        self.assertFalse(row["runtime_auth_matches_expected"])

    def test_live_preflight_config_paths_are_deduplicated(self) -> None:
        """真实消融预检应只检查被选中 live mode 的配置，并去重。"""
        paths = real_ablation_runner.live_real_ablation_config_paths(
            ("saga_only", "ordinary_pq_middleware", "saga_only"),
        )

        labels = [str(path) for path in paths]
        self.assertEqual(len(paths), 2)
        self.assertTrue(labels[0].endswith("user_configs/emma.yaml"))
        self.assertTrue(labels[1].endswith("user_configs/raj.yaml"))

    def test_preflight_report_marks_offline_only_selection_as_not_runnable(self) -> None:
        """只选择 offline-only mode 时，预检报告应明确没有 live 配置可跑。"""
        report = real_ablation_runner.build_real_ablation_preflight_report(
            mode_ids=("ordinary_pq_middleware",),
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "no_live_supported_modes_selected")
        self.assertEqual(report["live_supported_modes"], [])
        self.assertEqual(report["offline_only_modes"], ["ordinary_pq_middleware"])

    def test_preflight_report_serializes_failures_without_starting_batch(self) -> None:
        """预检报告应保留模型端点失败原因，供 live batch 前判断阻塞。"""
        failed = real_ablation_runner.experiment_preflight.CheckResult(
            "model_probe:test",
            False,
            "model endpoint probe failed before running a full experiment",
            ("bad model",),
        )
        with mock.patch.object(
            real_ablation_runner.experiment_preflight,
            "run_preflight_checks",
            return_value=[failed],
        ) as run_checks:
            report = real_ablation_runner.build_real_ablation_preflight_report(
                mode_ids=("saga_only",),
                check_model_backends=True,
                model_probe_timeout_seconds=3.0,
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["failed_checks"], ["model_probe:test"])
        self.assertTrue(report["results"][0]["details"][0].startswith("bad"))
        self.assertTrue(run_checks.call_args.kwargs["check_model_backends"])
        self.assertFalse(run_checks.call_args.kwargs["check_db_sync"])
        self.assertEqual(run_checks.call_args.kwargs["model_probe_timeout_seconds"], 3.0)

    def test_cli_preflight_writes_report_and_returns_failure_code(self) -> None:
        """preflight CLI 应能写出 JSON 报告，并用退出码暴露阻塞。"""
        failed_report = {
            "ok": False,
            "status": "failed",
            "failed_checks": ["model_probe:test"],
        }
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            real_ablation_runner,
            "build_real_ablation_preflight_report",
            return_value=failed_report.copy(),
        ) as build_report, mock.patch.object(real_ablation_runner, "print") as print_mock:
            exit_code = real_ablation_runner.main(
                [
                    "preflight",
                    "--mode",
                    "saga_only",
                    "--model-probe",
                    "--model-probe-timeout",
                    "4",
                    "--output-dir",
                    tmpdir,
                ]
            )

            output_path = Path(tmpdir) / "real_ablation_preflight.json"
            self.assertEqual(exit_code, 1)
            self.assertTrue(output_path.exists())
            printed = json.loads(print_mock.call_args.args[0])
            self.assertEqual(printed["report_path"], str(output_path))
            self.assertEqual(printed["failed_checks"], ["model_probe:test"])

        self.assertEqual(build_report.call_args.kwargs["mode_ids"], ["saga_only"])
        self.assertTrue(build_report.call_args.kwargs["check_model_backends"])
        self.assertEqual(build_report.call_args.kwargs["model_probe_timeout_seconds"], 4)

    def test_run_live_real_ablation_skips_offline_only_modes(self) -> None:
        """run 子命令只应调用已接入真实 runtime 的 mode。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)

            def fake_run(command: list[str], *, check: bool) -> object:
                run_dir = Path(command[command.index("--run-dir") + 1])
                run_dir.mkdir(parents=True, exist_ok=True)
                runtime_auth = run_dir.name == "shamir_secured_pq_can"
                (run_dir / "end_to_end_stats_summary.json").write_text(
                    json.dumps(
                        _summary(runtime_auth_enabled=runtime_auth),
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
                return object()

            with mock.patch.object(real_ablation_runner.subprocess, "run", side_effect=fake_run) as run_mock:
                summary = real_ablation_runner.run_live_real_ablation(
                    output_dir=output_dir,
                    mode_ids=(
                        "saga_only",
                        "ordinary_pq_middleware",
                        "shamir_secured_pq_can",
                    ),
                    task_names=("schedule_meeting",),
                    python_executable="/venv/bin/python",
                    skip_model_probe=True,
                )

            self.assertEqual(run_mock.call_count, 2)
            self.assertTrue((output_dir / "real_ablation_summary.json").exists())
        self.assertEqual(
            summary["offline_only_modes"],
            ["ordinary_pq_middleware"],
        )
        rows = {row["mode"]: row for row in summary["rows"]}
        self.assertEqual(rows["ordinary_pq_middleware"]["status"], "offline_only_not_live_wired")

    def test_cli_summarize_writes_output_file(self) -> None:
        """summarize CLI 应能从 mode=path 参数写出汇总 JSON。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline_path = root / "baseline.json"
            output_dir = root / "out"
            baseline_path.write_text(
                json.dumps(_summary(runtime_auth_enabled=False), sort_keys=True),
                encoding="utf-8",
            )

            with mock.patch.object(real_ablation_runner, "print") as print_mock:
                exit_code = real_ablation_runner.main(
                    [
                        "summarize",
                        "--mode",
                        "saga_only",
                        "--summary",
                        f"saga_only={baseline_path}",
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            printed = json.loads(print_mock.call_args.args[0])
            self.assertEqual(printed["rows"][0]["status"], "summary_available")
            self.assertTrue((output_dir / "real_ablation_summary.json").exists())

    def test_cli_run_defaults_to_single_all_task(self) -> None:
        """run CLI 默认只应把 all task 传给 batch runner 一次。"""
        with tempfile.TemporaryDirectory() as tmpdir:

            def fake_run(command: list[str], *, check: bool) -> object:
                run_dir = Path(command[command.index("--run-dir") + 1])
                run_dir.mkdir(parents=True, exist_ok=True)
                (run_dir / "end_to_end_stats_summary.json").write_text(
                    json.dumps(_summary(runtime_auth_enabled=False), sort_keys=True),
                    encoding="utf-8",
                )
                return object()

            with mock.patch.object(real_ablation_runner.subprocess, "run", side_effect=fake_run) as run_mock, mock.patch.object(real_ablation_runner, "print"):
                exit_code = real_ablation_runner.main(
                    [
                        "run",
                        "--mode",
                        "saga_only",
                        "--output-dir",
                        tmpdir,
                        "--python",
                        "/venv/bin/python",
                    ]
                )

            self.assertEqual(exit_code, 0)
            command = run_mock.call_args.args[0]
            self.assertEqual(command.count("--task"), 1)
            task_index = command.index("--task")
            self.assertEqual(command[task_index + 1], "all")


if __name__ == "__main__":
    unittest.main()
