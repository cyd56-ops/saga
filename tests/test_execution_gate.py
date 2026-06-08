"""Tests for signed execution-gate authorization."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from neural import CAN, CompiledToyLWEVerifier
from pq import ToyLWESignatureScheme
from saga.execution_gate import (
    append_execution_gate_audit_record,
    ExecutionAuthorizationError,
    ExecutionGateRequest,
    FileReplayStateStore,
    SignedRequestExecutionGate,
    build_execution_gate_audit_record,
)
from saga.messages import build_request_envelope, sha256_hex


class SignedRequestExecutionGateTests(unittest.TestCase):
    """Verify that signed envelopes are enforced before local execution."""

    def setUp(self) -> None:
        """Create deterministic signing material and a matching CAN gate."""
        self.scheme = ToyLWESignatureScheme(seed=23)
        self.key_pair = self.scheme.keygen()
        self.now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        self.gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
        )

    def _build_request(self, *, message: str = "hello") -> ExecutionGateRequest:
        """Build a valid signed request for the configured gate."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message=message,
            provider_id="https://provider.example.test",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        return ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message=message,
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

    def test_authorize_accepts_valid_signed_request(self) -> None:
        """A valid signed envelope should pass the execution gate."""
        self.assertTrue(self.gate.authorize(self._build_request()))
        decision = self.gate.evaluate_request(self._build_request())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized")
        self.assertEqual(
            decision.formula_terms(),
            {
                "saga_token_valid": None,
                "request_envelope_valid": True,
                "pq_signature_valid": True,
                "can_accept": True,
                "execution_scope_allowed": True,
                "internal_policy_accept": None,
            },
        )

    def test_consume_request_rejects_replayed_envelope(self) -> None:
        """同一个已消费信封再次进入执行路径时必须 replay 拒绝。"""
        request = self._build_request()

        first_decision = self.gate.consume_request(request)
        second_decision = self.gate.consume_request(request)

        self.assertTrue(first_decision.allowed)
        self.assertFalse(second_decision.allowed)
        self.assertEqual(second_decision.reason, "replayed_request_envelope")

    def test_persisted_replay_state_rejects_new_gate_instance(self) -> None:
        """A persisted replay marker should block a fresh gate instance too."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_dir=Path(tmpdir),
            )
            request = self._build_request()

            self.assertTrue(gate.consume_request(request).allowed)

            fresh_gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_dir=Path(tmpdir),
            )
            replay_decision = fresh_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")

    def test_shared_replay_store_rejects_replay_across_workdirs(self) -> None:
        """共享 replay store 应让不同 workdir 的 gate 实例拒绝同一信封。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            shared_store = FileReplayStateStore(Path(tmpdir) / "shared-replay")
            first_gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=shared_store,
            )
            second_gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=shared_store,
            )
            request = self._build_request()

            self.assertTrue(first_gate.consume_request(request).allowed)
            replay_decision = second_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")

    def test_replay_store_and_directory_are_mutually_exclusive(self) -> None:
        """同一个 gate 不能同时配置目录和自定义 store，避免 replay 事实源分裂。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(ValueError, "either replay_state_dir or replay_state_store"):
                SignedRequestExecutionGate(
                    CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                    {"alice@example.com:calendar_agent": self.key_pair.public_key},
                    now_fn=lambda: self.now,
                    replay_state_dir=Path(tmpdir) / "local-replay",
                    replay_state_store=FileReplayStateStore(Path(tmpdir) / "shared-replay"),
                )

    def test_evaluate_request_does_not_consume_replay_state(self) -> None:
        """Pure validation calls should not mark a request as executed."""
        request = self._build_request()

        self.assertTrue(self.gate.evaluate_request(request).allowed)
        self.assertTrue(self.gate.evaluate_request(request).allowed)

        self.assertTrue(self.gate.consume_request(request).allowed)
        self.assertEqual(
            self.gate.consume_request(request).reason,
            "replayed_request_envelope",
        )

    def test_consume_request_fails_closed_when_replay_state_cannot_be_written(self) -> None:
        """Replay persistence failures should reject rather than silently proceed."""
        request = self._build_request()
        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_dir=Path(tmpdir),
            )

            with mock.patch.object(
                gate._replay_state_store,
                "reserve_request",
                side_effect=OSError("disk full"),
            ):
                decision = gate.consume_request(request)

            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "replay_state_persistence_failed")

    def test_authorize_rejects_message_digest_mismatch(self) -> None:
        """Changing the transport message must invalidate the envelope binding."""
        request = self._build_request(message="hello")
        tampered_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message="tampered",
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )
        self.assertFalse(self.gate.authorize(tampered_request))
        self.assertEqual(
            self.gate.evaluate_request(tampered_request).reason,
            "message_digest_mismatch",
        )

    def test_evaluate_request_rejects_untrusted_sender_key(self) -> None:
        """A sender without trusted public key material must fail closed.

        未登记可信公钥的发送方不能进入签名验签路径。
        """
        request = self._build_request()
        untrusted_request = ExecutionGateRequest(
            sender_aid="mallory@example.com:calendar_agent",
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(untrusted_request))
        self.assertEqual(
            self.gate.evaluate_request(untrusted_request).reason,
            "untrusted_sender_aid",
        )

    def test_evaluate_request_rejects_sender_aid_mismatch(self) -> None:
        """The trusted transport sender must match the signed sender identity.

        外层发送方身份必须和签名信封中的 sender 绑定一致。
        """
        request = self._build_request()
        other_key_pair = self.scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {
                "alice@example.com:calendar_agent": self.key_pair.public_key,
                "mallory@example.com:calendar_agent": other_key_pair.public_key,
            },
            now_fn=lambda: self.now,
        )
        mismatch_request = ExecutionGateRequest(
            sender_aid="mallory@example.com:calendar_agent",
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(gate.authorize(mismatch_request))
        self.assertEqual(
            gate.evaluate_request(mismatch_request).reason,
            "sender_aid_mismatch",
        )

    def test_evaluate_request_rejects_receiver_aid_mismatch(self) -> None:
        """The receiving runtime identity must match the signed receiver identity.

        接收端 runtime 只能接受签给自己的信封。
        """
        request = self._build_request()
        mismatch_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid="carol@example.com:email_agent",
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(mismatch_request))
        self.assertEqual(
            self.gate.evaluate_request(mismatch_request).reason,
            "receiver_aid_mismatch",
        )

    def test_evaluate_request_rejects_token_digest_mismatch(self) -> None:
        """A signed envelope cannot be replayed under a different SAGA token.

        token 摘要不匹配时拒绝，防止签名信封跨 token 复用。
        """
        request = self._build_request()
        mismatch_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token="different-token",
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(mismatch_request))
        self.assertEqual(
            self.gate.evaluate_request(mismatch_request).reason,
            "token_digest_mismatch",
        )

    def test_evaluate_request_rejects_invalid_envelope_json(self) -> None:
        """Malformed envelope JSON should produce a stable fail-closed reason.

        畸形信封必须稳定拒绝并产生可审计原因。
        """
        request = self._build_request()
        invalid_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope="{not-json",
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(invalid_request))
        self.assertEqual(
            self.gate.evaluate_request(invalid_request).reason,
            "invalid_request_envelope",
        )

    def test_outer_payload_keeps_signature_detached_from_envelope(self) -> None:
        """The transported signature should remain outside canonical envelope bytes."""
        request = self._build_request()

        self.assertIsInstance(request.request_envelope, str)
        assert isinstance(request.request_envelope, str)
        self.assertNotIn("pq_signature", request.request_envelope)
        self.assertIsInstance(request.pq_signature, str)

    def test_authorize_rejects_expired_envelope(self) -> None:
        """Expired envelopes must fail closed even if the signature is valid."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=10),
            expires_at=self.now - timedelta(minutes=1),
            action_scope="llm_prompt",
            message="hello",
            timestamp=self.now - timedelta(minutes=10),
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )
        self.assertFalse(self.gate.authorize(request))
        self.assertEqual(self.gate.evaluate_request(request).reason, "envelope_expired")

    def test_authorize_rejects_tampered_envelope_field(self) -> None:
        """Changing a signed envelope field must invalidate the detached signature."""
        request = self._build_request()
        assert isinstance(request.request_envelope, str)
        tampered_envelope = request.request_envelope.replace(
            "\"session_id\":\"session-1\"",
            "\"session_id\":\"session-2\"",
        )
        tampered_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=tampered_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(tampered_request))
        self.assertEqual(
            self.gate.evaluate_request(tampered_request).reason,
            "signature_verification_failed",
        )

        decision = self.gate.evaluate_request(tampered_request)
        self.assertTrue(decision.request_envelope_valid)
        self.assertFalse(decision.pq_signature_valid)
        self.assertFalse(decision.can_accept)
        self.assertTrue(decision.execution_scope_allowed)

    def test_evaluate_request_rejects_action_scope_mismatch(self) -> None:
        """Transport action scopes must stay bound to the signed envelope scope."""
        request = self._build_request()
        tampered_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope="tool_call:send_email",
            request_envelope=request.request_envelope,
            pq_signature=request.pq_signature,
        )

        self.assertFalse(self.gate.authorize(tampered_request))
        self.assertEqual(
            self.gate.evaluate_request(tampered_request).reason,
            "action_scope_mismatch",
        )

    def test_build_local_execution_context_allows_tool_specific_descendants(self) -> None:
        """A broad tool scope should authorize qualified calls for individual tools."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call",
            message="use your tools",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="use your tools",
            action_scope="tool_call",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_action("tool_call:send_email"))
        self.assertFalse(context.authorize_action("memory_write"))

    def test_build_local_execution_context_allows_explicit_extra_tool_scope(self) -> None:
        """A prompt envelope may explicitly authorize selected downstream tools."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:get_free_time_slots", "tool_call:add_calendar_event"],
            message="schedule a meeting",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="schedule a meeting",
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_action("llm_prompt"))
        self.assertTrue(context.authorize_tool_call("get_free_time_slots"))
        self.assertTrue(context.authorize_tool_call("add_calendar_event"))
        self.assertFalse(context.authorize_action("tool_call:send_email"))
        self.assertFalse(context.authorize_memory_write())
        self.assertFalse(context.authorize_delegation())

    def test_build_local_execution_context_does_not_treat_prompt_as_tool_scope(self) -> None:
        """A plain prompt scope must not authorize tool calls."""
        request = self._build_request(message="read only")

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_action("llm_prompt"))
        self.assertFalse(context.authorize_tool_call("get_free_time_slots"))
        self.assertFalse(context.authorize_memory_write())
        self.assertFalse(context.authorize_delegation())

    def test_authorize_rejects_tampered_authorized_scopes(self) -> None:
        """Changing the signed extra scope list must invalidate the signature."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            message="hello",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        tampered_envelope = envelope.canonical_json().replace(
            "\"tool_call:send_email\"",
            "\"tool_call:add_calendar_event\"",
        )
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=tampered_envelope,
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        self.assertFalse(self.gate.authorize(request))
        self.assertEqual(
            self.gate.evaluate_request(request).reason,
            "signature_verification_failed",
        )

    def test_build_local_execution_context_restricts_to_exact_qualified_tool_scope(self) -> None:
        """A qualified tool scope should authorize only the named tool."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            message="use only send_email",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="use only send_email",
            action_scope="tool_call:send_email",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_action("tool_call:send_email"))
        self.assertFalse(context.authorize_action("tool_call:add_calendar_event"))

    def test_authorize_rejects_tampered_signature_under_compiled_verifier(self) -> None:
        """The compiled verifier path should reject detached signature tampering."""
        request = self._build_request()
        assert isinstance(request.pq_signature, str)
        signature = bytearray(base64.b64decode(request.pq_signature))
        vector = self.scheme.decode_signature_vector(bytes(signature))
        vector[0] = (vector[0] + 1) % self.scheme.parameters.modulus
        tampered_signature = base64.b64encode(
            b"".join(
                coefficient.to_bytes(2, "little", signed=False)
                for coefficient in vector
            )
        ).decode("utf-8")
        tampered_request = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=tampered_signature,
        )

        self.assertFalse(self.gate.authorize(tampered_request))
        self.assertEqual(
            self.gate.evaluate_request(tampered_request).reason,
            "signature_verification_failed",
        )

    def test_evaluate_request_rejects_missing_signature_material_with_stable_reason(self) -> None:
        """Missing transport signature material should expose stable audit reasons."""
        request = self._build_request()

        missing_envelope = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=None,
            pq_signature=request.pq_signature,
        )
        missing_signature = ExecutionGateRequest(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            token=request.token,
            message=request.message,
            action_scope=request.action_scope,
            request_envelope=request.request_envelope,
            pq_signature=None,
        )

        self.assertEqual(
            self.gate.evaluate_request(missing_envelope).reason,
            "missing_request_envelope",
        )
        self.assertEqual(
            self.gate.evaluate_request(missing_signature).reason,
            "missing_pq_signature",
        )

    def test_evaluate_request_rejects_not_yet_valid_envelope(self) -> None:
        """Future-dated envelopes must fail closed before local execution."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now + timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        self.assertFalse(self.gate.authorize(request))
        self.assertEqual(
            self.gate.evaluate_request(request).reason,
            "envelope_not_yet_valid",
        )

    def test_build_execution_gate_audit_record_captures_reject_shape(self) -> None:
        """Audit records should preserve stable local fields for rejected requests."""
        request = self._build_request()
        decision = self.gate.evaluate_request(
            ExecutionGateRequest(
                sender_aid=request.sender_aid,
                receiver_aid=request.receiver_aid,
                token=request.token,
                message="tampered",
                action_scope=request.action_scope,
                request_envelope=request.request_envelope,
                pq_signature=request.pq_signature,
            )
        )

        record = build_execution_gate_audit_record(request, decision)

        self.assertFalse(record["allowed"])
        self.assertEqual(record["reason"], "message_digest_mismatch")
        self.assertEqual(
            record["authorization_formula"],
            {
                "saga_token_valid": None,
                "request_envelope_valid": False,
                "pq_signature_valid": False,
                "can_accept": False,
                "execution_scope_allowed": False,
                "internal_policy_accept": None,
            },
        )
        self.assertEqual(record["sender_aid"], request.sender_aid)
        self.assertTrue(record["has_request_envelope"])
        self.assertTrue(record["has_pq_signature"])
        self.assertEqual(record["token_digest"], sha256_hex(request.token.encode("utf-8")))

    def test_append_execution_gate_audit_record_writes_jsonl_row(self) -> None:
        """Audit helpers should append structured records to a local JSONL file."""
        request = self._build_request()
        decision = self.gate.evaluate_request(
            ExecutionGateRequest(
                sender_aid=request.sender_aid,
                receiver_aid=request.receiver_aid,
                token=request.token,
                message="tampered",
                action_scope=request.action_scope,
                request_envelope=request.request_envelope,
                pq_signature=request.pq_signature,
            )
        )
        record = build_execution_gate_audit_record(request, decision)

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = append_execution_gate_audit_record(tmpdir, record)

            self.assertEqual(audit_path, Path(tmpdir) / "audit" / "execution_gate.jsonl")
            assert audit_path is not None
            rows = audit_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(rows), 1)
            payload = json.loads(rows[0])
            self.assertEqual(payload["reason"], "message_digest_mismatch")
            self.assertEqual(payload["sender_aid"], request.sender_aid)
            self.assertIn("recorded_at", payload)

    def test_local_execution_context_exposes_memory_and_delegation_helpers(self) -> None:
        """The context should provide explicit helpers for non-tool execution actions."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="memory_read",
            message="inspect your notes",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="inspect your notes",
            action_scope="memory_read",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_memory_read())
        self.assertFalse(context.authorize_memory_write())
        self.assertFalse(context.authorize_delegation())
        context.require_memory_read()
        with self.assertRaisesRegex(PermissionError, "unauthorized_memory_write"):
            context.require_memory_write()
        with self.assertRaisesRegex(PermissionError, "unauthorized_delegation"):
            context.require_delegation()

    def test_local_context_rejection_exposes_stable_reason(self) -> None:
        """本地执行面拒绝应携带稳定 reason，便于和 PQ-CAN gate 拒绝分开统计。"""
        context = self.gate.build_local_execution_context(self._build_request())

        self.assertIsNotNone(context)
        assert context is not None
        with self.assertRaises(ExecutionAuthorizationError) as raised:
            context.require_tool_call("send_email")

        self.assertEqual(raised.exception.reason, "unauthorized_tool_scope")
        self.assertEqual(raised.exception.action_scope, "tool_call:send_email")


if __name__ == "__main__":
    unittest.main()
