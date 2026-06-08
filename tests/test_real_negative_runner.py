"""Tests for the opt-in real-service negative runner."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from pq import ToyLWESignatureScheme
from saga.agent import Agent, enable_toy_lwe_runtime_auth
from saga.messages import parse_request_envelope, sha256_hex

from experiments import real_negative_runner


class RealNegativeRunnerTests(unittest.TestCase):
    """Verify the real-service negative runner without starting live services."""

    def setUp(self) -> None:
        """Create a temporary workdir root for helper-wired Agent shells."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def _agent(self) -> Agent:
        """Create a helper-wired Agent shell for payload-construction tests."""
        scheme = ToyLWESignatureScheme(seed=47)
        alice_keys = scheme.keygen()
        bob_keys = scheme.keygen()
        agent = Agent.__new__(Agent)
        agent.aid = "alice@example.com:calendar_agent"
        agent.workdir = str(Path(self.tempdir.name) / agent.aid)
        agent.provider_id = "https://provider.example.test"
        agent.execution_gate = None
        agent.pq_signature_scheme = None
        agent.pq_public_key = None
        agent.pq_secret_key = None
        agent.local_agent = type(
            "LocalAgentStub",
            (),
            {
                "tool_collections": (
                    type("Tool", (), {"name": "add_calendar_event"})(),
                )
            },
        )()
        enable_toy_lwe_runtime_auth(
            agent,
            scheme=scheme,
            key_pair=alice_keys,
            trusted_public_keys={"bob@example.com:calendar_agent": bob_keys.public_key},
            now_fn=lambda: datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc),
        )
        return agent

    def test_available_scenarios_match_expected_first_real_service_set(self) -> None:
        """确认真实服务负向 runner 暴露完整 opt-in 场景清单。"""
        self.assertEqual(
            real_negative_runner.available_scenarios(),
            (
                "missing_request_envelope",
                "tampered_message",
                "prompt_surface_tool_only",
                "replayed_envelope",
                "wrong_trusted_sender_key",
                "unauthorized_tool_scope",
                "unauthorized_memory_write",
                "unauthorized_delegation",
            ),
        )

    def test_missing_request_envelope_payload_omits_signature_material(self) -> None:
        """The missing-envelope real sample should send no PQ-CAN signature material."""
        payload = real_negative_runner.build_negative_payload(
            self._agent(),
            scenario="missing_request_envelope",
            receiver_aid="bob@example.com:calendar_agent",
            token="enc-token",
            message="hello",
            turn_index=0,
            token_dict={},
        )

        self.assertEqual(payload["action_scope"], "llm_prompt")
        self.assertNotIn("request_envelope", payload)
        self.assertNotIn("pq_signature", payload)

    def test_tampered_message_payload_keeps_signed_digest_for_original_message(self) -> None:
        """Tampered-message sample should mutate transport text after signing."""
        now = datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc)
        payload = real_negative_runner.build_negative_payload(
            self._agent(),
            scenario="tampered_message",
            receiver_aid="bob@example.com:calendar_agent",
            token="enc-token",
            message="hello",
            turn_index=0,
            token_dict={
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
        )

        envelope = parse_request_envelope(payload["request_envelope"])

        self.assertIn("request_envelope", payload)
        self.assertIn("pq_signature", payload)
        self.assertNotEqual(payload["msg"], "hello")
        self.assertEqual(envelope.message_digest, sha256_hex(b"hello"))

    def test_prompt_surface_tool_only_payload_uses_tool_scope(self) -> None:
        """确认 tool-only 样本不会携带已签名的 prompt 授权。"""
        now = datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc)
        payload = real_negative_runner.build_negative_payload(
            self._agent(),
            scenario="prompt_surface_tool_only",
            receiver_aid="bob@example.com:calendar_agent",
            token="enc-token",
            message="hello",
            turn_index=0,
            token_dict={
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
        )

        envelope = parse_request_envelope(payload["request_envelope"])

        self.assertEqual(payload["action_scope"], "tool_call:add_calendar_event")
        self.assertEqual(envelope.action_scope, "tool_call:add_calendar_event")
        self.assertNotIn("llm_prompt", envelope.authorized_scopes)

    def test_wrong_trusted_sender_payload_is_validly_signed_by_initiator(self) -> None:
        """确认 wrong-key 样本只篡改 receiver 信任映射，不篡改传输负载。"""
        now = datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc)
        payload = real_negative_runner.build_negative_payload(
            self._agent(),
            scenario="wrong_trusted_sender_key",
            receiver_aid="bob@example.com:calendar_agent",
            token="enc-token",
            message="hello",
            turn_index=0,
            token_dict={
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
        )

        envelope = parse_request_envelope(payload["request_envelope"])

        self.assertEqual(payload["msg"], "hello")
        self.assertEqual(payload["action_scope"], "llm_prompt")
        self.assertEqual(envelope.message_digest, sha256_hex(b"hello"))

    def test_scope_probe_payloads_enter_prompt_without_unsigned_scope(self) -> None:
        """Scope-probe samples should enter prompt but omit the probed capability."""
        now = datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc)
        scenarios = {
            "unauthorized_tool_scope": "tool_call:add_calendar_event",
            "unauthorized_memory_write": "memory_write",
            "unauthorized_delegation": "delegation",
        }

        for scenario, rejected_scope in scenarios.items():
            with self.subTest(scenario=scenario):
                payload = real_negative_runner.build_negative_payload(
                    self._agent(),
                    scenario=scenario,
                    receiver_aid="bob@example.com:calendar_agent",
                    token="enc-token",
                    message="hello",
                    turn_index=0,
                    token_dict={
                        "issue_timestamp": now.isoformat(),
                        "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
                    },
                )
                envelope = parse_request_envelope(payload["request_envelope"])

                self.assertEqual(payload["action_scope"], "llm_prompt")
                self.assertIn("llm_prompt", envelope.authorized_scopes)
                self.assertNotIn(rejected_scope, envelope.authorized_scopes)

    def test_result_writer_emits_jsonl_and_summary(self) -> None:
        """Result artifacts should be stable JSON files under the selected run dir."""
        results = [
            real_negative_runner.RealNegativeResult(
                scenario="missing_request_envelope",
                passed=True,
                expected_reason="missing_request_envelope",
                observed_reason="missing_request_envelope",
                side_effect_triggered=False,
                local_agent_run_count=0,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            results_path, summary_path = real_negative_runner.write_real_negative_results(
                results,
                tmpdir,
            )

            rows = [
                json.loads(line)
                for line in results_path.read_text(encoding="utf-8").splitlines()
            ]
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(rows[0]["scenario"], "missing_request_envelope")
        self.assertTrue(rows[0]["passed"])
        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["passed_count"], 1)

    def test_listen_and_query_commands_use_internal_runner_entrypoints(self) -> None:
        """Service mode should launch listener and query through this runner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = real_negative_runner.RealNegativeRunConfig(
                repo_root=root,
                python_executable="/venv/bin/python",
                scenarios=("missing_request_envelope",),
                initiator_config=root / "emma.yaml",
                receiver_config=root / "raj.yaml",
                agent_name="calendar_agent",
                run_dir=root / "run",
                ca_static_dir=root / ".ca_static",
                mongo_dbpath=root / ".mongodata",
                mongo_binary=root / ".mongodb" / "bin" / "mongod",
                provider_db_uri="mongodb://localhost:27017/saga",
                startup_timeout_seconds=1,
                listener_startup_timeout_seconds=1,
                query_timeout_seconds=1,
                audit_timeout_seconds=2,
                skip_db_preflight=False,
            )
            side_effect_path = root / "run" / "side_effects.jsonl"

            listen = real_negative_runner._listen_command(
                config,
                side_effect_path=side_effect_path,
            )
            wrong_key_listen = real_negative_runner._listen_command(
                config,
                side_effect_path=side_effect_path,
                wrong_trusted_sender_aid="emma@example.com:calendar_agent",
            )
            scope_probe_listen = real_negative_runner._listen_command(
                config,
                side_effect_path=side_effect_path,
                scope_probe="unauthorized_memory_write",
            )
            query = real_negative_runner._query_command(
                config,
                scenario="missing_request_envelope",
                scenario_dir=root / "run" / "missing_request_envelope",
                side_effect_path=side_effect_path,
            )

        self.assertEqual(listen[:2], ["/venv/bin/python", str(Path(real_negative_runner.__file__).resolve())])
        self.assertIn("listen", listen)
        self.assertIn("--receiver-config", listen)
        self.assertIn("--wrong-trusted-sender-aid", wrong_key_listen)
        self.assertIn("emma@example.com:calendar_agent", wrong_key_listen)
        self.assertIn("--scope-probe", scope_probe_listen)
        self.assertIn("unauthorized_memory_write", scope_probe_listen)
        self.assertIn("query", query)
        self.assertIn("--scenario", query)
        self.assertIn("missing_request_envelope", query)

    def test_listen_command_passes_explicit_sqlite_replay_store(self) -> None:
        """Run mode 应把显式 SQLite replay store 参数传给 listener 子进程。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = real_negative_runner.RealNegativeRunConfig(
                repo_root=root,
                python_executable="/venv/bin/python",
                scenarios=("replayed_envelope",),
                initiator_config=root / "emma.yaml",
                receiver_config=root / "raj.yaml",
                agent_name="calendar_agent",
                run_dir=root / "run",
                ca_static_dir=root / ".ca_static",
                mongo_dbpath=root / ".mongodata",
                mongo_binary=root / ".mongodb" / "bin" / "mongod",
                provider_db_uri="mongodb://localhost:27017/saga",
                startup_timeout_seconds=1,
                listener_startup_timeout_seconds=1,
                query_timeout_seconds=1,
                audit_timeout_seconds=2,
                skip_db_preflight=False,
                replay_store_backend="sqlite",
                replay_store_sqlite_path=root / "run" / "replay.sqlite3",
            )

            listen = real_negative_runner._listen_command(
                config,
                side_effect_path=root / "run" / "side_effects.jsonl",
            )

        self.assertIn("--replay-store-backend", listen)
        self.assertIn("sqlite", listen)
        self.assertIn("--replay-store-sqlite-path", listen)
        self.assertIn(str(root / "run" / "replay.sqlite3"), listen)

    def test_run_config_defaults_sqlite_replay_store_to_run_directory(self) -> None:
        """run CLI 选择 SQLite backend 但不传路径时，应默认写入 run 目录。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run"
            args = real_negative_runner.parse_args(
                [
                    "run",
                    "--scenario",
                    "replayed_envelope",
                    "--run-dir",
                    str(run_dir),
                    "--replay-store-backend",
                    "sqlite",
                ]
            )

            config = real_negative_runner._config_from_run_args(args)

        self.assertEqual(config.replay_store_backend, "sqlite")
        self.assertEqual(config.replay_store_sqlite_path, run_dir / "replay_state.sqlite3")

    def test_runtime_auth_config_is_normalized_for_injected_replay_store(self) -> None:
        """显式 replay store 注入时，runtime auth config 应声明强一致 backend。"""
        runtime_auth_config = real_negative_runner.ToyRuntimeAuthConfig(
            enabled=True,
            replay_state_dir="/tmp/legacy-replay",
        )

        normalized = real_negative_runner._runtime_auth_config_for_injected_replay_store(
            runtime_auth_config
        )

        self.assertIsNotNone(normalized)
        assert normalized is not None
        replay_store = normalized.resolved_replay_store()
        self.assertIsNotNone(replay_store)
        assert replay_store is not None
        self.assertEqual(replay_store.backend, "external_strong_consistency")
        self.assertIsNone(normalized.replay_state_dir)

    def test_replayed_envelope_uses_two_real_connections(self) -> None:
        """确认 replay 样本会对同一 listener 发起两次真实握手。"""
        self.assertEqual(
            real_negative_runner._connect_attempts_for_scenario("replayed_envelope"),
            2,
        )
        self.assertEqual(
            real_negative_runner._connect_attempts_for_scenario("tampered_message"),
            1,
        )

    def test_main_returns_nonzero_when_service_result_fails(self) -> None:
        """Run mode should fail its process status when any real sample fails."""
        bad_result = real_negative_runner.RealNegativeResult(
            scenario="missing_request_envelope",
            passed=False,
            expected_reason="missing_request_envelope",
            observed_reason="authorized",
            side_effect_triggered=True,
            local_agent_run_count=1,
        )

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.real_negative_runner.run_real_negative_services",
            return_value=[bad_result],
        ):
            exit_code = real_negative_runner.main(
                [
                    "run",
                    "--scenario",
                    "missing_request_envelope",
                    "--run-dir",
                    tmpdir,
                ]
            )

        self.assertEqual(exit_code, 1)

    def test_scope_probe_query_uses_local_denied_reason_and_protected_side_effects(self) -> None:
        """Scope-probe query results should allow one prompt run but no protected action."""
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch(
            "experiments.real_negative_runner._agent_aid",
            return_value="bob@example.com:calendar_agent",
        ), mock.patch(
            "experiments.real_negative_runner._agent_workdir_from_config_path",
            return_value=str(Path(tmpdir) / "receiver"),
        ), mock.patch(
            "experiments.real_negative_runner._build_agent_from_config",
        ) as build_agent:
            side_effect_path = Path(tmpdir) / "receiver_local_agent_runs.jsonl"
            protected_path = real_negative_runner._protected_side_effect_path(side_effect_path)
            agent = mock.Mock()
            agent.connect.side_effect = lambda *_args, **_kwargs: side_effect_path.write_text(
                json.dumps({"denied_reason": "unauthorized_memory_write"}) + "\n",
                encoding="utf-8",
            )
            build_agent.return_value = agent

            result = real_negative_runner.run_query(
                scenario="unauthorized_memory_write",
                initiator_config=Path(tmpdir) / "emma.yaml",
                receiver_config=Path(tmpdir) / "raj.yaml",
                agent_name="calendar_agent",
                run_dir=Path(tmpdir) / "run",
                side_effect_path=side_effect_path,
                audit_timeout_seconds=0.1,
            )

        self.assertTrue(result.passed)
        self.assertEqual(result.observed_reason, "unauthorized_memory_write")
        self.assertEqual(result.local_agent_run_count, 1)
        self.assertFalse(result.side_effect_triggered)
        self.assertFalse(protected_path.exists())


if __name__ == "__main__":
    unittest.main()
