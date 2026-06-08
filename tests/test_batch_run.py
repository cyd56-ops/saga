"""Tests for the local experiment batch runner."""

from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

from experiments import batch_run
from experiments.preflight import CheckResult


class BatchRunTests(unittest.TestCase):
    """Verify batch runner command construction and probe stability behavior."""

    def _config(self, tmpdir: str, *, required_successes: int = 2) -> batch_run.BatchRunConfig:
        """Build a minimal batch-run config for unit tests."""
        root = Path(tmpdir)
        return batch_run.BatchRunConfig(
            repo_root=root,
            python_executable="/venv/bin/python",
            tasks=(batch_run.TASK_SPECS["schedule_meeting"],),
            initiator_config=root / "user_configs" / "emma.yaml",
            receiver_config=root / "user_configs" / "raj.yaml",
            seed_user_config_dir=root / "user_configs",
            ca_static_dir=root / ".ca_static",
            run_dir=root / "runs" / "one",
            mongo_dbpath=root / ".mongodata",
            mongo_binary=root / ".mongodb" / "bin" / "mongod",
            provider_db_uri="mongodb://localhost:27017/saga",
            probe_required_successes=required_successes,
            probe_max_attempts=5,
            probe_interval_seconds=0,
            model_probe_timeout_seconds=3,
            startup_timeout_seconds=1,
            listener_startup_timeout_seconds=1,
            query_timeout_seconds=1,
            skip_model_probe=False,
            skip_db_preflight=False,
            skip_seed=False,
            allow_task_failure=False,
        )

    def test_selected_tasks_expands_all_in_stable_order(self) -> None:
        """The all sentinel should expand to the three supported experiment tasks."""
        tasks = batch_run._selected_tasks(["all"])

        self.assertEqual(
            [task.name for task in tasks],
            ["schedule_meeting", "expense_report", "create_blogpost"],
        )

    def test_service_and_task_commands_use_expected_entrypoints(self) -> None:
        """Command builders should use the local Python and existing repo entrypoints."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            ports = batch_run.ServicePorts(
                ca_host="127.0.0.1",
                ca_port=8000,
                provider_host="127.0.0.1",
                provider_port=5000,
            )
            task = batch_run.TASK_SPECS["schedule_meeting"]

            self.assertEqual(batch_run._ca_command(config, ports)[:3], ["/venv/bin/python", "-m", "http.server"])
            self.assertEqual(batch_run._provider_command(config), ["/venv/bin/python", "provider.py"])
            self.assertEqual(batch_run._task_command(config, task, "listen")[2], "listen")
            self.assertEqual(batch_run._task_command(config, task, "query")[2], "query")
            self.assertEqual(batch_run._task_command(config, task, "query")[-1], str(config.receiver_config))

    def test_wait_for_stable_model_backend_requires_consecutive_successes(self) -> None:
        """A failed probe should reset the consecutive-success counter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir, required_successes=2)
            config.run_dir.mkdir(parents=True)
            failed = [CheckResult("model_probe:test", False, "timeout")]
            passed = [CheckResult("model_probe:test", True, "ok")]

            with mock.patch.object(
                batch_run,
                "_run_preflight_once",
                side_effect=[failed, passed, failed, passed, passed],
            ) as run_preflight, mock.patch.object(batch_run.time, "sleep"):
                batch_run._wait_for_stable_model_backend(config)

            self.assertEqual(run_preflight.call_count, 5)
            self.assertTrue((config.run_dir / "model_probe_005.json").exists())

    def test_wait_for_stable_model_backend_fails_on_trust_chain_error(self) -> None:
        """Non-model preflight failures should not be treated as transient model instability."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir, required_successes=2)
            config.run_dir.mkdir(parents=True)
            failed = [CheckResult("provider_cert", False, "certificate mismatch")]

            with mock.patch.object(
                batch_run,
                "_run_preflight_once",
                return_value=failed,
            ), mock.patch.object(batch_run.time, "sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "non-model preflight"):
                    batch_run._wait_for_stable_model_backend(config)

            sleep.assert_not_called()

    def test_new_query_success_fails_closed_on_false_success(self) -> None:
        """The runner should treat success=false query records as batch failures."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            task = batch_run.TASK_SPECS["schedule_meeting"]
            results_dir = config.repo_root / "experiments" / "results"
            results_dir.mkdir(parents=True)
            (results_dir / "schedule_meeting.jsonl").write_text(
                '{"task_name":"schedule_meeting","mode":"query","success":false}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "did not succeed"):
                batch_run._assert_new_query_succeeded(
                    config,
                    task,
                    previous_query_count=0,
                )

    def test_new_query_success_ignores_old_success_records(self) -> None:
        """Old query records should not satisfy the current task run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            task = batch_run.TASK_SPECS["schedule_meeting"]
            results_dir = config.repo_root / "experiments" / "results"
            results_dir.mkdir(parents=True)
            (results_dir / "schedule_meeting.jsonl").write_text(
                '{"task_name":"schedule_meeting","mode":"query","success":true}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "new query result"):
                batch_run._assert_new_query_succeeded(
                    config,
                    task,
                    previous_query_count=1,
                )

    def test_latest_new_query_record_returns_current_result(self) -> None:
        """Batch summaries should use the query record written by the current run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            task = batch_run.TASK_SPECS["schedule_meeting"]
            results_dir = config.repo_root / "experiments" / "results"
            results_dir.mkdir(parents=True)
            (results_dir / "schedule_meeting.jsonl").write_text(
                "\n".join(
                    [
                        '{"task_name":"schedule_meeting","mode":"query","success":true,"task_latency_seconds":1}',
                        '{"task_name":"schedule_meeting","mode":"query","success":true,"task_latency_seconds":2}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            record = batch_run._latest_new_query_record(
                config,
                task,
                previous_query_count=1,
            )

        assert record is not None
        self.assertEqual(record["task_latency_seconds"], 2)

    def test_write_end_to_end_stats_summary_aggregates_task_records(self) -> None:
        """Batch runner should emit one run-level JSON summary for real task stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            config.run_dir.mkdir(parents=True)

            summary_path = batch_run._write_end_to_end_stats_summary(
                config,
                [
                    {
                        "task_name": "schedule_meeting",
                        "success": True,
                        "task_latency_seconds": 10.0,
                        "model_call_count": 2,
                        "audit_record_count": 1,
                        "logging_stats_collection_latency_seconds": 0.01,
                        "api_cost_usd": None,
                        "total_tokens": None,
                    },
                    {
                        "task_name": "expense_report",
                        "success": False,
                        "task_latency_seconds": 20.0,
                        "model_call_count": 3,
                        "audit_record_count": 2,
                        "logging_stats_collection_latency_seconds": 0.02,
                        "api_cost_usd": None,
                        "total_tokens": None,
                    },
                ],
            )

            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(summary_path.name, "end_to_end_stats_summary.json")
        self.assertEqual(summary["task_count"], 2)
        self.assertEqual(summary["succeeded_count"], 1)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["task_latency_seconds_total"], 30.0)
        self.assertEqual(summary["task_latency_seconds_mean"], 15.0)
        self.assertEqual(summary["model_call_count"], 5)
        self.assertEqual(summary["audit_record_count"], 3)
        self.assertEqual(summary["logging_stats_collection_latency_seconds_total"], 0.03)
        self.assertFalse(summary["api_cost_available"])
        self.assertIsNone(summary["api_cost_usd_total"])

    def test_run_task_rejects_preexisting_listener_port(self) -> None:
        """The runner should not risk connecting a query to a stale listener."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._config(tmpdir)
            task = batch_run.TASK_SPECS["schedule_meeting"]

            with mock.patch.object(
                batch_run,
                "_receiver_endpoint",
                return_value=("127.0.0.1", 7003),
            ), mock.patch.object(batch_run, "_port_is_open", return_value=True), mock.patch.object(
                batch_run,
                "_start_process",
            ) as start_process:
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    batch_run._run_task(config, task)

            start_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
