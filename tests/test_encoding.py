"""Tests for canonical SAGA-PQ-CAN request-envelope encoding."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from saga.messages import (
    DEFAULT_ENVELOPE_DOMAIN,
    DEFAULT_MAX_DELEGATION_DEPTH,
    RequestEnvelope,
    action_scope_allows,
    action_scopes_are_attenuated,
    action_scopes_allow,
    build_request_envelope,
    normalize_authorized_scopes,
    parse_action_scope,
    parse_request_envelope,
    sha256_hex,
)


class RequestEnvelopeTests(unittest.TestCase):
    """Verify deterministic encoding and validation for request envelopes."""

    def test_equivalent_timestamps_normalize_to_same_canonical_bytes(self) -> None:
        """Equivalent aware timestamps should canonicalize identically."""
        china_tz = timezone(timedelta(hours=8))
        envelope_a = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 21, 0, 0, tzinfo=china_tz),
            expires_at=datetime(2026, 5, 7, 22, 0, 0, tzinfo=china_tz),
            action_scope="llm_prompt",
            message="hello",
        )
        envelope_b = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            message="hello",
        )

        self.assertEqual(envelope_a.canonical_bytes(), envelope_b.canonical_bytes())
        self.assertEqual(envelope_a.issued_at, "2026-05-07T13:00:00Z")
        self.assertEqual(envelope_a.expires_at, "2026-05-07T14:00:00Z")

    def test_timestamp_defaults_to_issued_at(self) -> None:
        """Missing timestamps should default to the normalized issue time."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            message="hello",
        )

        self.assertEqual(envelope.timestamp, envelope.issued_at)

    def test_build_request_envelope_hashes_token_and_message(self) -> None:
        """The envelope should bind only digests of the token and message."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="tool_call",
            message="hello",
        )

        self.assertEqual(envelope.token_digest, sha256_hex(b"token-1"))
        self.assertEqual(envelope.message_digest, sha256_hex(b"hello"))
        self.assertEqual(envelope.domain, DEFAULT_ENVELOPE_DOMAIN)

    def test_request_envelope_rejects_invalid_action_scope(self) -> None:
        """Unsupported execution scopes must be rejected."""
        with self.assertRaisesRegex(ValueError, "unsupported action_scope"):
            RequestEnvelope(
                sender_aid="alice@example.com:calendar_agent",
                receiver_aid="bob@example.com:email_agent",
                token_digest="a" * 64,
                session_id="session-1",
                turn_id="turn-1",
                issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
                action_scope="calendar_write",
                message_digest="b" * 64,
            )

    def test_request_envelope_rejects_invalid_aid(self) -> None:
        """Invalid AIDs must be rejected before encoding."""
        with self.assertRaisesRegex(ValueError, "sender_aid"):
            RequestEnvelope(
                sender_aid="bad-aid",
                receiver_aid="bob@example.com:email_agent",
                token_digest="a" * 64,
                session_id="session-1",
                turn_id="turn-1",
                issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
                action_scope="llm_prompt",
                message_digest="b" * 64,
            )

    def test_request_envelope_rejects_naive_timestamps(self) -> None:
        """Naive timestamps are ambiguous and must not canonicalize."""
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            RequestEnvelope(
                sender_aid="alice@example.com:calendar_agent",
                receiver_aid="bob@example.com:email_agent",
                token_digest="a" * 64,
                session_id="session-1",
                turn_id="turn-1",
                issued_at=datetime(2026, 5, 7, 13, 0, 0),
                expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
                action_scope="llm_prompt",
                message_digest="b" * 64,
            )

    def test_parse_request_envelope_round_trips_canonical_json(self) -> None:
        """Serialized canonical JSON should parse back into the same envelope."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            message="hello",
        )

        parsed = parse_request_envelope(envelope.canonical_json())

        self.assertEqual(parsed.as_dict(), envelope.as_dict())

    def test_canonical_encoding_excludes_detached_signature_field(self) -> None:
        """Detached signatures must not appear inside the canonical envelope."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            message="hello",
        )

        self.assertNotIn("pq_signature", envelope.as_dict())
        self.assertNotIn("pq_signature", envelope.canonical_json())

    def test_action_scope_parser_accepts_tool_specific_scope(self) -> None:
        """Tool scopes may be qualified down to the tool identity."""
        self.assertEqual(parse_action_scope("tool_call:send_email"), ("tool_call", "send_email"))

    def test_action_scope_allows_tool_specific_descendants(self) -> None:
        """An unqualified tool scope should authorize specific tool calls."""
        self.assertTrue(action_scope_allows("tool_call", "tool_call:send_email"))
        self.assertFalse(action_scope_allows("tool_call:send_email", "tool_call:add_calendar_event"))

    def test_authorized_scopes_default_to_entry_scope(self) -> None:
        """Missing extra scopes should authorize only the signed entry action."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            message="hello",
        )

        self.assertEqual(envelope.authorized_scopes, ("llm_prompt",))
        self.assertTrue(action_scopes_allow(envelope.authorized_scopes, "llm_prompt"))
        self.assertFalse(action_scopes_allow(envelope.authorized_scopes, "tool_call:send_email"))

    def test_authorized_scopes_are_canonicalized_and_signed(self) -> None:
        """Extra scopes should be deduplicated, sorted, and included in canonical JSON."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email", "llm_prompt", "tool_call:send_email"],
            message="hello",
        )

        self.assertEqual(envelope.authorized_scopes, ("llm_prompt", "tool_call:send_email"))
        self.assertIn("\"authorized_scopes\":[\"llm_prompt\",\"tool_call:send_email\"]", envelope.canonical_json())
        self.assertTrue(action_scopes_allow(envelope.authorized_scopes, "tool_call:send_email"))
        self.assertFalse(action_scopes_allow(envelope.authorized_scopes, "memory_write"))

    def test_normalize_authorized_scopes_rejects_invalid_extra_scope(self) -> None:
        """Unsupported extra scopes must fail before signing."""
        with self.assertRaisesRegex(ValueError, "unsupported action_scope"):
            normalize_authorized_scopes("llm_prompt", ["calendar_write"])

    def test_capability_fields_are_canonicalized_and_signed(self) -> None:
        """Capability metadata should be part of the canonical signed envelope."""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            message="hello",
            capability_id="cap-root",
        )

        payload = envelope.as_dict()

        self.assertEqual(payload["capability_id"], "cap-root")
        self.assertEqual(payload["parent_envelope_digest"], "")
        self.assertEqual(payload["parent_authorized_scopes"], [])
        self.assertEqual(payload["delegation_depth"], 0)
        self.assertEqual(payload["max_delegation_depth"], DEFAULT_MAX_DELEGATION_DEPTH)
        self.assertIn("\"capability_id\":\"cap-root\"", envelope.canonical_json())

    def test_child_capability_derives_parent_digest_and_depth(self) -> None:
        """Delegated child envelopes should bind the parent digest and attenuated scopes."""
        parent = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-parent",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="llm_prompt",
            authorized_scopes=["delegation", "tool_call:send_email"],
            message="parent",
            capability_id="cap-parent",
        )

        child = build_request_envelope(
            sender_aid="bob@example.com:email_agent",
            receiver_aid="carol@example.com:email_agent",
            token="token-2",
            session_id="session-1",
            turn_id="turn-child",
            issued_at=datetime(2026, 5, 7, 13, 1, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 13, 30, 0, tzinfo=timezone.utc),
            action_scope="tool_call:send_email",
            message="child",
            parent_envelope=parent,
            capability_id="cap-child",
        )

        self.assertEqual(child.parent_envelope_digest, parent.hex_digest())
        self.assertEqual(child.parent_authorized_scopes, parent.authorized_scopes)
        self.assertEqual(child.delegation_depth, 1)
        self.assertTrue(
            action_scopes_are_attenuated(
                child.parent_authorized_scopes,
                child.authorized_scopes,
            )
        )

    def test_action_scopes_are_attenuated_rejects_scope_expansion(self) -> None:
        """A delegated child scope set must not exceed its parent capability."""
        self.assertTrue(
            action_scopes_are_attenuated(
                ("tool_call", "memory_read"),
                ("tool_call:send_email",),
            )
        )
        self.assertFalse(
            action_scopes_are_attenuated(
                ("tool_call:send_email",),
                ("tool_call:add_calendar_event",),
            )
        )


if __name__ == "__main__":
    unittest.main()
