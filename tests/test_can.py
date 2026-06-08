"""Tests for the first fixed SAGA-PQ-CAN authentication gate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from neural import BitLayout, CAN, SignatureVerifierWrapper, bytes_to_bits
from pq import ToyLWESignatureScheme
from saga.messages import build_request_envelope


class CANTests(unittest.TestCase):
    """Verify binary correctness and unsafe-input rejection for CAN."""

    def setUp(self) -> None:
        """Create a deterministic toy verifier and matching CAN instance."""
        self.scheme = ToyLWESignatureScheme(seed=5)
        self.key_pair = self.scheme.keygen()
        self.issued_at = datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc)
        self.expires_at = self.issued_at + timedelta(hours=1)

        self.layout = BitLayout(
            public_key_bytes=len(self.key_pair.public_key),
            message_bytes=32,
            signature_bytes=len(self.scheme.sign(self.key_pair.secret_key, b"\x00" * 32)),
        )
        self.verifier = SignatureVerifierWrapper(self.scheme, self.layout)
        self.can = CAN(self.verifier)

    def _envelope_digest(self, *, action_scope: str = "llm_prompt") -> bytes:
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            action_scope=action_scope,
            message="hello",
        )
        return envelope.digest()

    def _compound_bits(self, *, action_scope: str = "llm_prompt") -> list[int]:
        message = self._envelope_digest(action_scope=action_scope)
        signature = self.scheme.sign(self.key_pair.secret_key, message)
        return [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(message),
            *bytes_to_bits(signature),
        ]

    def test_can_accepts_valid_binary_signature(self) -> None:
        """A valid binary toy signature should pass the hard gate."""
        self.assertEqual(self.can.can_accept_compound_bits(self._compound_bits()), 1)

    def test_can_rejects_invalid_binary_signature(self) -> None:
        """A tampered binary signature should be rejected."""
        bits = self._compound_bits()
        bits[-1] ^= 1
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_can_rejects_wrong_action_scope_binding(self) -> None:
        """Changing the execution scope should invalidate the signature context."""
        message = self._envelope_digest(action_scope="tool_call")
        original_message = self._envelope_digest(action_scope="llm_prompt")
        signature = self.scheme.sign(self.key_pair.secret_key, original_message)
        bits = [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(message),
            *bytes_to_bits(signature),
        ]
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_can_rejects_unsafe_real_valued_signature(self) -> None:
        """Unsafe real-valued coordinates must be rejected by the mask gate."""
        bits = [float(bit) for bit in self._compound_bits()]
        bits[-1] = 0.5
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_can_rejects_boundary_real_valued_signature(self) -> None:
        """Non-binary boundary values are outside the binary-input guarantee."""
        bits = [float(bit) for bit in self._compound_bits()]
        bits[-1] = 1.0 / 3.0
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_private_key_not_in_can_state(self) -> None:
        """The CAN module must not retain signing secret material."""
        attributes = vars(self.can)
        self.assertNotIn("secret_key", attributes)
        self.assertNotIn("private_key", attributes)
        self.assertNotIn(self.key_pair.secret_key, attributes.values())


if __name__ == "__main__":
    unittest.main()
