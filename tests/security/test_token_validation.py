"""Security-oriented tests for token validation and invalidation paths."""

import base64
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone

import saga.common.crypto as sc
from saga.agent import Agent


def _public_key_b64(public_key) -> str:
    """Encode an X25519 public key in the format used by token metadata."""
    return base64.b64encode(
        public_key.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw,
        )
    ).decode("utf-8")


def _build_minimal_agent() -> Agent:
    """Create an Agent shell with only the state needed by token tests."""
    agent = Agent.__new__(Agent)
    agent.active_tokens = {}
    agent.active_tokens_lock = threading.Lock()
    agent.aid_to_token = {}
    agent.received_tokens = {}
    agent.received_tokens_lock = threading.Lock()
    return agent


def _token_dict(*, expires_in_seconds: int, communication_quota: int, recipient_pac: str) -> dict:
    """Create token metadata with a deterministic UTC timestamp format."""
    expiration = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in_seconds)
    return {
        "expiration_timestamp": expiration.isoformat(),
        "communication_quota": communication_quota,
        "recipient_pac": recipient_pac,
    }


class TokenValidationTests(unittest.TestCase):
    """Cover the token validity semantics needed before PQ-CAN integration."""

    def setUp(self) -> None:
        """Build a minimal Agent and PAC material for each test."""
        self.agent = _build_minimal_agent()
        self.recipient_private_key, self.recipient_public_key = sc.generate_x25519_keypair()
        _, self.other_public_key = sc.generate_x25519_keypair()
        self.token = "enc-token"
        self.recipient_pac_b64 = _public_key_b64(self.recipient_public_key)

    def test_token_is_valid_accepts_active_known_token(self) -> None:
        """A known token with quota and a matching PAC should validate."""
        self.agent.active_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=3,
            recipient_pac=self.recipient_pac_b64,
        )
        self.assertTrue(self.agent.token_is_valid(self.token, self.recipient_public_key))

    def test_token_is_valid_rejects_unknown_token(self) -> None:
        """Unknown initiating-side tokens must be rejected."""
        self.assertFalse(self.agent.token_is_valid(self.token, self.recipient_public_key))

    def test_token_is_valid_rejects_expired_token(self) -> None:
        """Expired initiating-side tokens must be rejected."""
        self.agent.active_tokens[self.token] = _token_dict(
            expires_in_seconds=-1,
            communication_quota=3,
            recipient_pac=self.recipient_pac_b64,
        )
        self.assertFalse(self.agent.token_is_valid(self.token, self.recipient_public_key))

    def test_token_is_valid_rejects_zero_quota(self) -> None:
        """Exhausted initiating-side tokens must be rejected."""
        self.agent.active_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=0,
            recipient_pac=self.recipient_pac_b64,
        )
        self.assertFalse(self.agent.token_is_valid(self.token, self.recipient_public_key))

    def test_token_is_valid_rejects_recipient_pac_mismatch(self) -> None:
        """Tokens are bound to the intended recipient PAC."""
        self.agent.active_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=3,
            recipient_pac=self.recipient_pac_b64,
        )
        self.assertFalse(self.agent.token_is_valid(self.token, self.other_public_key))

    def test_received_token_is_valid_accepts_active_token(self) -> None:
        """A stored received token remains usable while valid."""
        self.agent.received_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=1,
            recipient_pac=self.recipient_pac_b64,
        )
        self.assertTrue(self.agent.received_token_is_valid(self.token))

    def test_received_token_is_valid_rejects_unknown_token(self) -> None:
        """Unknown received-side tokens must be rejected."""
        self.assertFalse(self.agent.received_token_is_valid(self.token))

    def test_retrieve_valid_token_cleans_up_expired_entries(self) -> None:
        """Expired received tokens should be removed from both caches."""
        self.agent.aid_to_token["alice@example.com:calendar_agent"] = self.token
        self.agent.received_tokens[self.token] = _token_dict(
            expires_in_seconds=-1,
            communication_quota=1,
            recipient_pac=self.recipient_pac_b64,
        )
        retrieved = self.agent.retrieve_valid_token("alice@example.com:calendar_agent")
        self.assertIsNone(retrieved)
        self.assertNotIn(self.token, self.agent.received_tokens)
        self.assertNotIn("alice@example.com:calendar_agent", self.agent.aid_to_token)

    def test_retrieve_valid_token_cleans_up_dangling_aid_mapping(self) -> None:
        """A dangling AID-to-token mapping should be removed."""
        self.agent.aid_to_token["alice@example.com:calendar_agent"] = self.token
        retrieved = self.agent.retrieve_valid_token("alice@example.com:calendar_agent")
        self.assertIsNone(retrieved)
        self.assertNotIn("alice@example.com:calendar_agent", self.agent.aid_to_token)

    def test_retrieve_valid_token_uses_unlocked_helper_path(self) -> None:
        """The retrieval path should not recurse through the public locked validator."""
        aid = "alice@example.com:calendar_agent"
        self.agent.aid_to_token[aid] = self.token
        self.agent.received_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=1,
            recipient_pac=self.recipient_pac_b64,
        )

        def fail_if_called(self, token: str) -> bool:
            raise AssertionError("retrieve_valid_token should not call received_token_is_valid()")

        self.agent.received_token_is_valid = types.MethodType(fail_if_called, self.agent)
        self.assertEqual(self.agent.retrieve_valid_token(aid), self.token)

    def test_consume_active_token_allows_only_one_concurrent_quota_consumer(self) -> None:
        """active token 校验和 quota 扣减必须在同一把锁内原子完成。"""
        self.agent.active_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=1,
            recipient_pac=self.recipient_pac_b64,
        )
        barrier = threading.Barrier(3)
        results: list[bool] = []
        results_lock = threading.Lock()

        def consume_once() -> None:
            barrier.wait()
            token_snapshot = self.agent._consume_active_token(
                self.token,
                self.recipient_public_key,
            )
            with results_lock:
                results.append(token_snapshot is not None)

        threads = [threading.Thread(target=consume_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)
        self.assertEqual(
            self.agent.active_tokens[self.token]["communication_quota"],
            0,
        )

    def test_consume_received_token_allows_only_one_concurrent_quota_consumer(self) -> None:
        """received token 校验和 quota 扣减必须防止并发重复使用。"""
        self.agent.received_tokens[self.token] = _token_dict(
            expires_in_seconds=60,
            communication_quota=1,
            recipient_pac=self.recipient_pac_b64,
        )
        barrier = threading.Barrier(3)
        results: list[bool] = []
        results_lock = threading.Lock()

        def consume_once() -> None:
            barrier.wait()
            token_snapshot = self.agent._consume_received_token(self.token)
            with results_lock:
                results.append(token_snapshot is not None)

        threads = [threading.Thread(target=consume_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)
        self.assertEqual(
            self.agent.received_tokens[self.token]["communication_quota"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
