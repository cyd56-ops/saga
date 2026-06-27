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
    normalize_scope_constraints,
    parse_action_scope,
    parse_request_envelope,
    scope_constraints_allow,
    scope_constraints_are_attenuated,
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

    def test_scope_constraints_are_canonicalized_and_signed(self) -> None:
        """参数级约束应规范化后进入 canonical envelope digest。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="token-1",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
            action_scope="tool_call:send_email",
            message="send",
            scope_constraints={
                "tool_call:send_email": [
                    {"op": "eq", "field": "recipient_domain", "value": "example.com"},
                    {"op": "max_length", "field": "subject", "value": 80},
                ]
            },
        )

        self.assertEqual(
            envelope.scope_constraints,
            {
                "tool_call:send_email": (
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"},
                    {"field": "subject", "op": "max_length", "value": 80},
                )
            },
        )
        self.assertIn("\"scope_constraints\"", envelope.canonical_json())
        parsed = parse_request_envelope(envelope.canonical_json())
        self.assertEqual(parsed.as_dict(), envelope.as_dict())

    def test_scope_constraint_evaluator_accepts_and_rejects_parameters(self) -> None:
        """封闭 predicate evaluator 应按签名约束检查运行时参数。"""
        constraints = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"},
                    {"field": "priority", "op": "in", "values": ["normal", "low"]},
                    {"field": "body", "op": "max_length", "value": 120},
                ]
            }
        )

        self.assertTrue(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                {
                    "recipient_domain": "example.com",
                    "priority": "normal",
                    "body": "short",
                },
            )
        )
        self.assertFalse(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                {
                    "recipient_domain": "evil.test",
                    "priority": "normal",
                    "body": "short",
                },
            )
        )
        self.assertFalse(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                None,
            )
        )

    def test_scope_constraint_evaluator_uses_json_scalar_equality(self) -> None:
        """等值约束应类型敏感，且不能调用对象参数的自定义比较逻辑。"""
        constraints = normalize_scope_constraints(
            {"tool_call:send_email": [{"field": "retry_count", "op": "eq", "value": 1}]}
        )

        class ExplodingComparison:
            """如果 evaluator 调用对象比较，测试应立即失败。"""

            def __eq__(self, other):
                raise AssertionError("custom comparison should not run")

        self.assertTrue(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                {"retry_count": 1},
            )
        )
        self.assertFalse(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                {"retry_count": True},
            )
        )
        self.assertFalse(
            scope_constraints_allow(
                ("tool_call:send_email",),
                constraints,
                "tool_call:send_email",
                {"retry_count": ExplodingComparison()},
            )
        )

    def test_specific_scope_constraints_apply_under_general_tool_grant(self) -> None:
        """泛化 tool_call 授权下的窄 scope 约束仍必须匹配具体工具调用。"""
        constraints = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )

        self.assertTrue(
            scope_constraints_allow(
                ("tool_call",),
                constraints,
                "tool_call:send_email",
                {"recipient_domain": "example.com"},
            )
        )
        self.assertFalse(
            scope_constraints_allow(
                ("tool_call",),
                constraints,
                "tool_call:send_email",
                {"recipient_domain": "evil.test"},
            )
        )
        self.assertTrue(
            scope_constraints_allow(
                ("tool_call",),
                constraints,
                "tool_call:add_calendar_event",
                {"recipient_domain": "evil.test"},
            )
        )

    def test_scope_constraints_reject_unknown_ops_and_uncovered_scopes(self) -> None:
        """约束只允许固定谓词集合，且 key 必须落在已签名 scope 内。"""
        with self.assertRaisesRegex(ValueError, "unsupported scope constraint op"):
            normalize_scope_constraints(
                {"tool_call:send_email": [{"field": "recipient", "op": "regex", "value": ".*"}]}
            )

        with self.assertRaisesRegex(ValueError, "covered by authorized_scopes"):
            build_request_envelope(
                sender_aid="alice@example.com:calendar_agent",
                receiver_aid="bob@example.com:email_agent",
                token="token-1",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=datetime(2026, 5, 7, 13, 0, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 5, 7, 14, 0, 0, tzinfo=timezone.utc),
                action_scope="llm_prompt",
                message="hello",
                scope_constraints={
                    "tool_call:send_email": [
                        {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                    ]
                },
            )

    def test_scope_constraints_reject_non_finite_numbers(self) -> None:
        """约束值只能使用可移植的有限 JSON 数字。"""
        with self.assertRaisesRegex(ValueError, "finite JSON numbers"):
            normalize_scope_constraints(
                {
                    "tool_call:send_email": [
                        {"field": "priority", "op": "lte", "value": float("nan")}
                    ]
                }
            )

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
        self.assertEqual(payload["parent_scope_constraints"], {})
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
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
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
        self.assertEqual(child.parent_scope_constraints, parent.scope_constraints)
        self.assertEqual(child.delegation_depth, 1)
        self.assertTrue(
            action_scopes_are_attenuated(
                child.parent_authorized_scopes,
                child.authorized_scopes,
            )
        )

    def test_scope_constraints_are_attenuated_requires_child_to_preserve_parent_predicates(self) -> None:
        """委托子 capability 必须保留或收窄适用于自身授权面的父参数约束。"""
        parent_constraints = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {
                        "field": "recipient_domain",
                        "op": "in",
                        "values": ["example.com", "corp.test"],
                    },
                    {"field": "body", "op": "max_length", "value": 200},
                ]
            }
        )
        narrowed_child = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"},
                    {"field": "body", "op": "max_length", "value": 120},
                ]
            }
        )
        relaxed_child = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {
                        "field": "recipient_domain",
                        "op": "in",
                        "values": ["example.com", "evil.test"],
                    },
                    {"field": "body", "op": "max_length", "value": 300},
                ]
            }
        )

        self.assertTrue(
            scope_constraints_are_attenuated(
                ("delegation", "tool_call:send_email"),
                parent_constraints,
                ("tool_call:send_email",),
                narrowed_child,
            )
        )
        self.assertFalse(
            scope_constraints_are_attenuated(
                ("delegation", "tool_call:send_email"),
                parent_constraints,
                ("tool_call:send_email",),
                {},
            )
        )
        self.assertFalse(
            scope_constraints_are_attenuated(
                ("delegation", "tool_call:send_email"),
                parent_constraints,
                ("tool_call:send_email",),
                relaxed_child,
            )
        )

    def test_scope_constraints_are_attenuated_rejects_moving_parent_constraint_wider(self) -> None:
        """子 capability 不能把父 narrow scope 约束移动到更宽 scope 上。"""
        parent_constraints = normalize_scope_constraints(
            {
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )
        moved_wider_child = normalize_scope_constraints(
            {
                "tool_call": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )

        self.assertFalse(
            scope_constraints_are_attenuated(
                ("delegation", "tool_call"),
                parent_constraints,
                ("tool_call",),
                moved_wider_child,
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
