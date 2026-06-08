"""Security tests for real-valued input rejection in the CAN gate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from neural import BitLayout, CAN, SignatureVerifierWrapper, bytes_to_bits
from pq import ToyLWESignatureScheme
from saga.messages import build_request_envelope


class RealValuedRejectionTests(unittest.TestCase):
    """Verify that unsafe real-valued inputs fail closed."""

    def setUp(self) -> None:
        """Create a deterministic CAN instance for security tests."""
        self.scheme = ToyLWESignatureScheme(seed=17)
        self.key_pair = self.scheme.keygen()
        issued_at = datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc)
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1),
            action_scope="llm_prompt",
            message="hello",
        )
        self.message = envelope.digest()
        self.signature = self.scheme.sign(self.key_pair.secret_key, self.message)
        layout = BitLayout(
            public_key_bytes=len(self.key_pair.public_key),
            message_bytes=len(self.message),
            signature_bytes=len(self.signature),
        )
        self.can = CAN(SignatureVerifierWrapper(self.scheme, layout))
        self.base_bits = [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(self.message),
            *bytes_to_bits(self.signature),
        ]

    def test_random_real_valued_coordinate_is_rejected(self) -> None:
        """An unsafe real-valued perturbation must force rejection."""
        bits = [float(bit) for bit in self.base_bits]
        bits[len(bits) // 2] = 0.41
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_midpoint_real_valued_coordinate_is_rejected(self) -> None:
        """A single midpoint coordinate must be sufficient for hard rejection."""
        bits = [float(bit) for bit in self.base_bits]
        bits[len(bits) // 2] = 0.5
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)

    def test_multiple_unsafe_coordinates_are_rejected(self) -> None:
        """Multiple unsafe coordinates must still fail closed."""
        bits = [float(bit) for bit in self.base_bits]
        bits[3] = 0.5
        bits[-4] = 0.6
        self.assertEqual(self.can.can_accept_compound_bits(bits), 0)


if __name__ == "__main__":
    unittest.main()
