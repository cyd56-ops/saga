"""Tests for helper-based execution-gate wiring."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from pq import ToyLWESignatureScheme
from saga.execution_gate import (
    ExecutionGateRequest,
    FileReplayStateStore,
    build_toy_lwe_execution_gate,
)
from saga.messages import build_request_envelope


class ExecutionGateFactoryTests(unittest.TestCase):
    """Verify the helper that wires toy LWE execution gates."""

    def setUp(self) -> None:
        """Create deterministic key material for helper-based gate tests."""
        self.scheme = ToyLWESignatureScheme(seed=43)
        self.key_pair = self.scheme.keygen()
        self.sender_aid = "alice@example.com:calendar_agent"
        self.receiver_aid = "bob@example.com:email_agent"
        self.token = "enc-token"
        self.message = "hello"
        self.now = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)

    def _build_request(self) -> ExecutionGateRequest:
        """Build a valid signed request bound to the fixed test context."""
        envelope = build_request_envelope(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token=self.token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message=self.message,
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        return ExecutionGateRequest(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token=self.token,
            message=self.message,
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

    def test_compiled_factory_authorizes_valid_request(self) -> None:
        """The compiled helper should accept a valid signed request."""
        gate = build_toy_lwe_execution_gate(
            self.scheme,
            {self.sender_aid: self.key_pair.public_key},
            verifier_flavor="compiled",
            now_fn=lambda: self.now,
        )

        self.assertTrue(gate.authorize(self._build_request()))

    def test_wrapper_factory_authorizes_valid_request(self) -> None:
        """The wrapper helper should remain available for comparison testing."""
        gate = build_toy_lwe_execution_gate(
            self.scheme,
            {self.sender_aid: self.key_pair.public_key},
            verifier_flavor="wrapper",
            now_fn=lambda: self.now,
        )

        self.assertTrue(gate.authorize(self._build_request()))

    def test_factory_accepts_shared_replay_store(self) -> None:
        """Factory 传入的共享 replay store 应跨 gate 实例拒绝重复信封。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay_store = FileReplayStateStore(Path(tmpdir) / "shared-replay")
            first_gate = build_toy_lwe_execution_gate(
                self.scheme,
                {self.sender_aid: self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=replay_store,
            )
            second_gate = build_toy_lwe_execution_gate(
                self.scheme,
                {self.sender_aid: self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=replay_store,
            )
            request = self._build_request()

            self.assertTrue(first_gate.consume_request(request).allowed)
            replay_decision = second_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")

    def test_factory_rejects_empty_trusted_key_mapping(self) -> None:
        """The helper should fail clearly when no trusted keys are configured."""
        with self.assertRaisesRegex(ValueError, "non-empty"):
            build_toy_lwe_execution_gate(self.scheme, {})

    def test_factory_rejects_mixed_public_key_lengths(self) -> None:
        """The helper should require a uniform key layout."""
        with self.assertRaisesRegex(ValueError, "uniform public-key length"):
            build_toy_lwe_execution_gate(
                self.scheme,
                {
                    self.sender_aid: self.key_pair.public_key,
                    "mallory@example.com:calendar_agent": self.key_pair.public_key + b"\x00",
                },
            )


if __name__ == "__main__":
    unittest.main()
