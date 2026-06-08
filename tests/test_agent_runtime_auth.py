"""Tests for runtime helper wiring of toy LWE authentication."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from pq import ToyLWESignatureScheme
from saga.agent import (
    Agent,
    enable_toy_lwe_runtime_auth,
    enable_toy_lwe_runtime_auth_from_config,
)
from saga.config import ReplayStoreConfig, ToyRuntimeAuthConfig
from saga.execution_gate import ExecutionGateRequest, SQLiteReplayStateStore
from saga.messages import build_request_envelope, parse_request_envelope


class AgentRuntimeAuthTests(unittest.TestCase):
    """Verify toy LWE runtime wiring for real ``Agent`` instances."""

    def setUp(self) -> None:
        """Create deterministic signing material for two peer agents."""
        self.scheme = ToyLWESignatureScheme(seed=47)
        self.alice_keys = self.scheme.keygen()
        self.bob_keys = self.scheme.keygen()
        self.now = datetime(2026, 5, 11, 12, 0, 0, tzinfo=timezone.utc)
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def _make_agent(self, aid: str) -> Agent:
        """Create a minimal ``Agent`` shell for runtime helper tests."""
        agent = Agent.__new__(Agent)
        agent.aid = aid
        agent.workdir = str(Path(self.tempdir.name) / aid)
        agent.provider_id = "https://provider.example.test"
        agent.execution_gate = None
        agent.pq_signature_scheme = None
        agent.pq_public_key = None
        agent.pq_secret_key = None
        agent.local_agent = None
        return agent

    class _StrictCapabilityLocalAgent:
        """Records strict capability-mode updates from the outer Agent."""

        def __init__(self) -> None:
            self.strict_values: list[bool] = []

        def set_strict_execution_capabilities(self, enabled: bool) -> None:
            """Record whether bottom-layer capabilities should require context."""
            self.strict_values.append(enabled)

    def test_enable_toy_lwe_runtime_auth_sets_signing_and_gate_fields(self) -> None:
        """The runtime helper should populate all toy LWE execution-auth state."""
        alice = self._make_agent("alice@example.com:calendar_agent")
        local_agent = self._StrictCapabilityLocalAgent()
        alice.local_agent = local_agent

        gate = enable_toy_lwe_runtime_auth(
            alice,
            scheme=self.scheme,
            key_pair=self.alice_keys,
            trusted_public_keys={"bob@example.com:email_agent": self.bob_keys.public_key},
            now_fn=lambda: self.now,
        )

        self.assertIs(alice.execution_gate, gate)
        self.assertIs(alice.pq_signature_scheme, self.scheme)
        self.assertEqual(alice.pq_public_key, self.alice_keys.public_key)
        self.assertEqual(alice.pq_secret_key, self.alice_keys.secret_key)
        self.assertTrue(alice.strict_execution_gate)
        self.assertEqual(local_agent.strict_values, [True])

    def test_runtime_auth_requires_persistent_replay_state_by_default(self) -> None:
        """安全模式缺少 workdir 或显式 replay store 时不能退回内存态。"""
        alice = self._make_agent("alice@example.com:calendar_agent")
        delattr(alice, "workdir")

        with self.assertRaisesRegex(RuntimeError, "persistent replay state"):
            enable_toy_lwe_runtime_auth(
                alice,
                scheme=self.scheme,
                key_pair=self.alice_keys,
                trusted_public_keys={"bob@example.com:email_agent": self.bob_keys.public_key},
                now_fn=lambda: self.now,
            )

    def test_runtime_wiring_supports_signed_payload_and_receive_side_authorization(self) -> None:
        """Two helper-configured agents should interoperate over the toy LWE path."""
        alice_aid = "alice@example.com:calendar_agent"
        bob_aid = "bob@example.com:email_agent"
        alice = self._make_agent(alice_aid)
        bob = self._make_agent(bob_aid)

        enable_toy_lwe_runtime_auth(
            alice,
            scheme=self.scheme,
            key_pair=self.alice_keys,
            trusted_public_keys={bob_aid: self.bob_keys.public_key},
            now_fn=lambda: self.now,
        )
        enable_toy_lwe_runtime_auth(
            bob,
            scheme=self.scheme,
            key_pair=self.bob_keys,
            trusted_public_keys={alice_aid: self.alice_keys.public_key},
            now_fn=lambda: self.now,
        )

        payload = alice._build_conversation_payload(
            receiver_aid=bob_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            turn_index=0,
            token_dict={
                "issue_timestamp": self.now.isoformat(),
                "expiration_timestamp": self.now.isoformat(),
            },
        )
        request = ExecutionGateRequest(
            sender_aid=alice_aid,
            receiver_aid=bob_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=payload["request_envelope"],
            pq_signature=payload["pq_signature"],
        )

        assert bob.execution_gate is not None
        self.assertTrue(bob.execution_gate.authorize(request))

    def test_conversation_payload_signs_explicit_tool_authorization_scopes(self) -> None:
        """Conversation envelopes should bind selected downstream tool scopes."""
        alice_aid = "alice@example.com:calendar_agent"
        bob_aid = "bob@example.com:calendar_agent"
        alice = self._make_agent(alice_aid)
        bob = self._make_agent(bob_aid)

        enable_toy_lwe_runtime_auth(
            alice,
            scheme=self.scheme,
            key_pair=self.alice_keys,
            trusted_public_keys={bob_aid: self.bob_keys.public_key},
            now_fn=lambda: self.now,
        )
        enable_toy_lwe_runtime_auth(
            bob,
            scheme=self.scheme,
            key_pair=self.bob_keys,
            trusted_public_keys={alice_aid: self.alice_keys.public_key},
            now_fn=lambda: self.now,
        )

        payload = alice._build_conversation_payload(
            receiver_aid=bob_aid,
            token="enc-token",
            message="schedule this",
            action_scope="llm_prompt",
            authorized_scopes=("tool_call:get_free_time_slots", "tool_call:add_calendar_event"),
            turn_index=0,
            token_dict={
                "issue_timestamp": self.now.isoformat(),
                "expiration_timestamp": self.now.isoformat(),
            },
        )
        request = ExecutionGateRequest(
            sender_aid=alice_aid,
            receiver_aid=bob_aid,
            token="enc-token",
            message="schedule this",
            action_scope="llm_prompt",
            request_envelope=payload["request_envelope"],
            pq_signature=payload["pq_signature"],
        )

        assert bob.execution_gate is not None
        context = bob.execution_gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_tool_call("get_free_time_slots"))
        self.assertTrue(context.authorize_tool_call("add_calendar_event"))
        self.assertFalse(context.authorize_action("memory_write"))
        self.assertFalse(context.authorize_action("delegation"))

    def test_conversation_payload_rejects_unsigned_tool_scope_injection(self) -> None:
        """Adding tool scopes to the envelope after signing must fail verification."""
        alice_aid = "alice@example.com:calendar_agent"
        bob_aid = "bob@example.com:calendar_agent"
        alice = self._make_agent(alice_aid)
        bob = self._make_agent(bob_aid)

        enable_toy_lwe_runtime_auth(
            alice,
            scheme=self.scheme,
            key_pair=self.alice_keys,
            trusted_public_keys={bob_aid: self.bob_keys.public_key},
            now_fn=lambda: self.now,
        )
        enable_toy_lwe_runtime_auth(
            bob,
            scheme=self.scheme,
            key_pair=self.bob_keys,
            trusted_public_keys={alice_aid: self.alice_keys.public_key},
            now_fn=lambda: self.now,
        )
        payload = alice._build_conversation_payload(
            receiver_aid=bob_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            turn_index=0,
            token_dict={
                "issue_timestamp": self.now.isoformat(),
                "expiration_timestamp": self.now.isoformat(),
            },
        )
        envelope_dict = parse_request_envelope(payload["request_envelope"]).as_dict()
        envelope_dict["authorized_scopes"].append("tool_call:add_calendar_event")
        request = ExecutionGateRequest(
            sender_aid=alice_aid,
            receiver_aid=bob_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=json.dumps(envelope_dict, sort_keys=True),
            pq_signature=payload["pq_signature"],
        )

        assert bob.execution_gate is not None
        self.assertFalse(bob.execution_gate.authorize(request))

    def test_runtime_wiring_supports_wrapper_verifier_flavor(self) -> None:
        """The runtime helper should still expose the wrapper verifier path."""
        alice = self._make_agent("alice@example.com:calendar_agent")

        gate = enable_toy_lwe_runtime_auth(
            alice,
            scheme=self.scheme,
            key_pair=self.alice_keys,
            trusted_public_keys={"bob@example.com:email_agent": self.bob_keys.public_key},
            verifier_flavor="wrapper",
            now_fn=lambda: self.now,
        )

        self.assertIs(alice.execution_gate, gate)

    def test_runtime_wiring_can_be_enabled_from_config(self) -> None:
        """The config-driven helper should decode trusted keys and attach runtime auth."""
        alice = self._make_agent("alice@example.com:calendar_agent")
        local_agent = self._StrictCapabilityLocalAgent()
        alice.local_agent = local_agent
        runtime_auth_config = ToyRuntimeAuthConfig(
            enabled=True,
            seed=47,
            verifier_flavor="compiled",
            trusted_public_keys={"bob@example.com:email_agent": "!!!"},
        )

        with self.assertRaisesRegex(ValueError, "invalid base64 trusted public key"):
            enable_toy_lwe_runtime_auth_from_config(alice, runtime_auth_config, now_fn=lambda: self.now)

        runtime_auth_config.trusted_public_keys = {
            "bob@example.com:email_agent": base64.b64encode(self.bob_keys.public_key).decode("utf-8")
        }
        gate = enable_toy_lwe_runtime_auth_from_config(
            alice,
            runtime_auth_config,
            now_fn=lambda: self.now,
        )

        self.assertIs(alice.execution_gate, gate)
        self.assertIsNotNone(alice.pq_signature_scheme)
        self.assertTrue(alice.strict_execution_gate)
        self.assertEqual(runtime_auth_config.resolved_mode(), "toy_compiled_research")
        self.assertEqual(local_agent.strict_values, [True])

    def test_config_replay_state_dir_is_used_as_shared_store(self) -> None:
        """配置中的 replay_state_dir 应覆盖默认 workdir，实现共享 replay 状态。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alice = self._make_agent("alice@example.com:calendar_agent")
            alice.workdir = str(Path(tmpdir) / "alice-workdir")
            alice_second_process = self._make_agent("alice@example.com:calendar_agent")
            alice_second_process.workdir = str(Path(tmpdir) / "alice-second-workdir")
            shared_replay_dir = Path(tmpdir) / "shared-replay"
            runtime_auth_config = ToyRuntimeAuthConfig(
                enabled=True,
                seed=47,
                verifier_flavor="compiled",
                replay_state_dir=str(shared_replay_dir),
                trusted_public_keys={
                    "bob@example.com:email_agent": base64.b64encode(
                        self.bob_keys.public_key
                    ).decode("utf-8")
                },
            )

            enable_toy_lwe_runtime_auth_from_config(alice, runtime_auth_config, now_fn=lambda: self.now)
            enable_toy_lwe_runtime_auth_from_config(
                alice_second_process,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )
            envelope = build_request_envelope(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=self.now,
                expires_at=self.now,
                action_scope="llm_prompt",
                message="hello",
                provider_id="https://provider.example.test",
                timestamp=self.now,
            )
            request = ExecutionGateRequest(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                message="hello",
                action_scope="llm_prompt",
                request_envelope=envelope.canonical_json(),
                pq_signature=base64.b64encode(
                    self.scheme.sign(self.bob_keys.secret_key, envelope.digest())
                ).decode("utf-8"),
            )

            assert alice.execution_gate is not None
            assert alice_second_process.execution_gate is not None
            self.assertTrue(alice.execution_gate.consume_request(request).allowed)
            replay_decision = alice_second_process.execution_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")
            assert alice.execution_gate is not None
            self.assertTrue(any(shared_replay_dir.glob("*.json")))
            self.assertFalse((Path(alice.workdir) / "audit" / "replay").exists())

    def test_config_default_workdir_replay_store_survives_restart(self) -> None:
        """默认安全模式应持久化 replay marker，使重启后的同一 workdir 拒绝重放。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alice = self._make_agent("alice@example.com:calendar_agent")
            alice.workdir = str(Path(tmpdir) / "alice-workdir")
            alice_restarted = self._make_agent("alice@example.com:calendar_agent")
            alice_restarted.workdir = str(Path(tmpdir) / "alice-workdir")
            runtime_auth_config = ToyRuntimeAuthConfig(
                enabled=True,
                seed=47,
                verifier_flavor="compiled",
                trusted_public_keys={
                    "bob@example.com:email_agent": base64.b64encode(
                        self.bob_keys.public_key
                    ).decode("utf-8")
                },
            )

            enable_toy_lwe_runtime_auth_from_config(
                alice,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )
            envelope = build_request_envelope(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=self.now,
                expires_at=self.now,
                action_scope="llm_prompt",
                message="hello",
                provider_id="https://provider.example.test",
                timestamp=self.now,
            )
            request = ExecutionGateRequest(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                message="hello",
                action_scope="llm_prompt",
                request_envelope=envelope.canonical_json(),
                pq_signature=base64.b64encode(
                    self.scheme.sign(self.bob_keys.secret_key, envelope.digest())
                ).decode("utf-8"),
            )

            assert alice.execution_gate is not None
            self.assertTrue(alice.execution_gate.consume_request(request).allowed)
            enable_toy_lwe_runtime_auth_from_config(
                alice_restarted,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )
            assert alice_restarted.execution_gate is not None
            replay_decision = alice_restarted.execution_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")
            self.assertTrue(any((Path(alice.workdir) / "audit" / "replay").glob("*.json")))

    def test_config_replay_store_file_marker_is_used_as_shared_store(self) -> None:
        """显式 replay_store.file_marker 应作为推荐配置路径共享 replay 状态。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alice = self._make_agent("alice@example.com:calendar_agent")
            alice.workdir = str(Path(tmpdir) / "alice-workdir")
            alice_second_process = self._make_agent("alice@example.com:calendar_agent")
            alice_second_process.workdir = str(Path(tmpdir) / "alice-second-workdir")
            shared_replay_dir = Path(tmpdir) / "shared-replay"
            runtime_auth_config = ToyRuntimeAuthConfig(
                enabled=True,
                seed=47,
                verifier_flavor="compiled",
                replay_store=ReplayStoreConfig(
                    backend="file_marker",
                    state_dir=str(shared_replay_dir),
                ),
                trusted_public_keys={
                    "bob@example.com:email_agent": base64.b64encode(
                        self.bob_keys.public_key
                    ).decode("utf-8")
                },
            )

            enable_toy_lwe_runtime_auth_from_config(alice, runtime_auth_config, now_fn=lambda: self.now)
            enable_toy_lwe_runtime_auth_from_config(
                alice_second_process,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )
            envelope = build_request_envelope(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=self.now,
                expires_at=self.now,
                action_scope="llm_prompt",
                message="hello",
                provider_id="https://provider.example.test",
                timestamp=self.now,
            )
            request = ExecutionGateRequest(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                message="hello",
                action_scope="llm_prompt",
                request_envelope=envelope.canonical_json(),
                pq_signature=base64.b64encode(
                    self.scheme.sign(self.bob_keys.secret_key, envelope.digest())
                ).decode("utf-8"),
            )

            assert alice.execution_gate is not None
            assert alice_second_process.execution_gate is not None
            self.assertTrue(alice.execution_gate.consume_request(request).allowed)
            replay_decision = alice_second_process.execution_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")
            self.assertTrue(any(shared_replay_dir.glob("*.json")))
            self.assertFalse((Path(alice.workdir) / "audit" / "replay").exists())

    def test_config_rejects_ambiguous_replay_store_settings(self) -> None:
        """replay_store 与旧 replay_state_dir 不能同时配置，避免 replay 事实源分裂。"""
        with self.assertRaisesRegex(ValueError, "either replay_store or replay_state_dir"):
            ToyRuntimeAuthConfig(
                enabled=True,
                replay_store=ReplayStoreConfig(
                    backend="file_marker",
                    state_dir="/tmp/shared-replay",
                ),
                replay_state_dir="/tmp/legacy-replay",
            )

    def test_external_replay_store_mode_fails_closed_without_backend(self) -> None:
        """强一致 replay 后端未显式注入时，config-driven 路径应拒绝继续。"""
        alice = self._make_agent("alice@example.com:calendar_agent")
        runtime_auth_config = ToyRuntimeAuthConfig(
            enabled=True,
            seed=47,
            verifier_flavor="compiled",
            replay_store=ReplayStoreConfig(backend="external_strong_consistency"),
            trusted_public_keys={
                "bob@example.com:email_agent": base64.b64encode(
                    self.bob_keys.public_key
                ).decode("utf-8")
            },
        )

        with self.assertRaisesRegex(RuntimeError, "external_strong_consistency replay store"):
            enable_toy_lwe_runtime_auth_from_config(
                alice,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )

    def test_external_replay_store_mode_uses_explicit_backend_injection(self) -> None:
        """显式注入 ReplayStateStore 时，强一致 replay 配置可进入 gate wiring。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alice = self._make_agent("alice@example.com:calendar_agent")
            alice.workdir = str(Path(tmpdir) / "alice-workdir")
            alice_second_process = self._make_agent("alice@example.com:calendar_agent")
            alice_second_process.workdir = str(Path(tmpdir) / "alice-second-workdir")
            database_path = Path(tmpdir) / "replay.sqlite3"
            runtime_auth_config = ToyRuntimeAuthConfig(
                enabled=True,
                seed=47,
                verifier_flavor="compiled",
                replay_store=ReplayStoreConfig(backend="external_strong_consistency"),
                trusted_public_keys={
                    "bob@example.com:email_agent": base64.b64encode(
                        self.bob_keys.public_key
                    ).decode("utf-8")
                },
            )

            enable_toy_lwe_runtime_auth_from_config(
                alice,
                runtime_auth_config,
                now_fn=lambda: self.now,
                replay_state_store=SQLiteReplayStateStore(database_path),
            )
            enable_toy_lwe_runtime_auth_from_config(
                alice_second_process,
                runtime_auth_config,
                now_fn=lambda: self.now,
                replay_state_store=SQLiteReplayStateStore(database_path),
            )
            envelope = build_request_envelope(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=self.now,
                expires_at=self.now,
                action_scope="llm_prompt",
                message="hello",
                provider_id="https://provider.example.test",
                timestamp=self.now,
            )
            request = ExecutionGateRequest(
                sender_aid="bob@example.com:email_agent",
                receiver_aid="alice@example.com:calendar_agent",
                token="enc-token",
                message="hello",
                action_scope="llm_prompt",
                request_envelope=envelope.canonical_json(),
                pq_signature=base64.b64encode(
                    self.scheme.sign(self.bob_keys.secret_key, envelope.digest())
                ).decode("utf-8"),
            )

            assert alice.execution_gate is not None
            assert alice_second_process.execution_gate is not None
            self.assertTrue(alice.execution_gate.consume_request(request).allowed)
            replay_decision = alice_second_process.execution_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")
            self.assertTrue(database_path.exists())
            self.assertFalse((Path(alice.workdir) / "audit" / "replay").exists())

    def test_external_replay_store_injection_requires_matching_config(self) -> None:
        """显式 store 注入必须搭配 external_strong_consistency 配置声明。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            alice = self._make_agent("alice@example.com:calendar_agent")
            runtime_auth_config = ToyRuntimeAuthConfig(
                enabled=True,
                seed=47,
                verifier_flavor="compiled",
                trusted_public_keys={
                    "bob@example.com:email_agent": base64.b64encode(
                        self.bob_keys.public_key
                    ).decode("utf-8")
                },
            )

            with self.assertRaisesRegex(ValueError, "external_strong_consistency"):
                enable_toy_lwe_runtime_auth_from_config(
                    alice,
                    runtime_auth_config,
                    now_fn=lambda: self.now,
                    replay_state_store=SQLiteReplayStateStore(Path(tmpdir) / "replay.sqlite3"),
                )

    def test_config_can_disable_strict_execution_gate_for_compatibility(self) -> None:
        """Config can explicitly keep legacy compatibility while runtime auth is enabled."""
        alice = self._make_agent("alice@example.com:calendar_agent")
        runtime_auth_config = ToyRuntimeAuthConfig(
            enabled=True,
            strict_execution_gate=False,
            seed=47,
            verifier_flavor="compiled",
            trusted_public_keys={
                "bob@example.com:email_agent": base64.b64encode(
                    self.bob_keys.public_key
                ).decode("utf-8")
            },
        )

        enable_toy_lwe_runtime_auth_from_config(
            alice,
            runtime_auth_config,
            now_fn=lambda: self.now,
        )

        self.assertFalse(alice.strict_execution_gate)

    def test_config_mode_selects_wrapper_toy_runtime_auth(self) -> None:
        """显式 toy_wrapper mode 应启用 wrapper verifier 路径。"""
        alice = self._make_agent("alice@example.com:calendar_agent")
        runtime_auth_config = ToyRuntimeAuthConfig(
            enabled=True,
            mode="toy_wrapper",
            seed=47,
            verifier_flavor="wrapper",
            trusted_public_keys={
                "bob@example.com:email_agent": base64.b64encode(
                    self.bob_keys.public_key
                ).decode("utf-8")
            },
        )

        gate = enable_toy_lwe_runtime_auth_from_config(
            alice,
            runtime_auth_config,
            now_fn=lambda: self.now,
        )

        self.assertIs(alice.execution_gate, gate)
        self.assertEqual(runtime_auth_config.resolved_mode(), "toy_wrapper")
        self.assertEqual(runtime_auth_config.toy_verifier_flavor(), "wrapper")

    def test_config_rejects_conflicting_mode_and_legacy_flavor(self) -> None:
        """显式 mode 与旧 verifier_flavor 冲突时应拒绝，避免语义混用。"""
        with self.assertRaisesRegex(ValueError, "requires verifier_flavor='compiled'"):
            ToyRuntimeAuthConfig(
                enabled=True,
                mode="toy_compiled_research",
                verifier_flavor="wrapper",
            )

        with self.assertRaisesRegex(ValueError, "requires verifier_flavor='wrapper'"):
            ToyRuntimeAuthConfig(
                enabled=True,
                mode="toy_wrapper",
                verifier_flavor="compiled",
            )

    def test_mldsa_external_config_fails_closed_without_backend_wiring(self) -> None:
        """ML-DSA mode 不能经 toy wiring 静默降级，缺 backend 时必须 fail-closed。"""
        alice = self._make_agent("alice@example.com:calendar_agent")
        runtime_auth_config = ToyRuntimeAuthConfig(
            enabled=True,
            mode="mldsa_external",
            trusted_public_keys={
                "bob@example.com:email_agent": base64.b64encode(
                    self.bob_keys.public_key
                ).decode("utf-8")
            },
        )

        with self.assertRaisesRegex(RuntimeError, "mldsa_external runtime auth requires"):
            enable_toy_lwe_runtime_auth_from_config(
                alice,
                runtime_auth_config,
                now_fn=lambda: self.now,
            )

        self.assertIsNone(alice.execution_gate)


if __name__ == "__main__":
    unittest.main()
