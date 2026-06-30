"""Tests for signed execution-gate authorization."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
from unittest import mock
import unittest

from neural import CAN, CompiledToyLWEVerifier
from pq import ToyLWESignatureScheme
from saga.execution_gate import (
    append_execution_gate_audit_record,
    EnforcementMode,
    ExecutionAuthorizationError,
    ExecutionCapabilityFacade,
    ExecutionGateDecision,
    ExecutionGateRequest,
    FileReplayStateStore,
    InMemoryExecutionInvariantMonitor,
    InMemoryRevocationStore,
    JSONLExecutionInvariantMonitor,
    RedisReplayStateStore,
    SignedRequestExecutionGate,
    SQLiteCapabilityStateStore,
    SQLiteReplayStateStore,
    SQLiteRevocationStore,
    build_execution_gate_audit_record,
    validate_execution_gate_audit_chain,
)
from saga.messages import RequestEnvelope, build_request_envelope, parse_request_envelope, sha256_hex


class _FakeRedisClient:
    """测试用 Redis client，模拟 set(nx=True) 与 scan_iter 语义。"""

    def __init__(self) -> None:
        """初始化内存 key-value 存储与调用记录。"""
        self.values: dict[str, str] = {}
        self.set_calls: list[dict[str, object]] = []

    def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool:
        """模拟 Redis SET；nx=True 时已有 key 返回 False。"""
        self.set_calls.append({"key": key, "value": value, "nx": nx, "ex": ex})
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def scan_iter(self, *, match: str) -> list[str]:
        """按 prefix 模拟 Redis SCAN 迭代。"""
        prefix = match[:-1] if match.endswith("*") else match
        return [key for key in self.values if key.startswith(prefix)]


class _UnavailableReplayStateStore:
    """测试用不可写 replay store，模拟持久化后端故障。"""

    def load_consumed_request_ids(self) -> set[str]:
        """返回空状态，使 gate 初始化可以完成。"""
        return set()

    def reserve_request(self, request_id: str, envelope: RequestEnvelope) -> str:
        """模拟后端写入失败，执行路径应 fail-closed。"""
        raise OSError("replay store unavailable")


class _UnavailableCapabilityStateStore:
    """测试用不可用 capability state store，模拟预算后端故障。"""

    def consume_budget(self, envelope: RequestEnvelope, action_scope: str) -> str:
        """模拟后端扣减失败，执行路径应 fail-closed。"""
        raise OSError("capability state unavailable")


class _UnavailableRevocationStore:
    """测试用不可用 revocation store，模拟撤销后端故障。"""

    def revocation_status(self, envelope: RequestEnvelope) -> str:
        """模拟后端查询失败，gate 应 fail-closed。"""
        raise OSError("revocation store unavailable")


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

    def _signed_request_from_envelope(
        self,
        envelope: RequestEnvelope,
        message: str,
        *,
        parameters: dict | None = None,
    ) -> ExecutionGateRequest:
        """用当前测试密钥把指定信封包装成执行 gate 请求。"""
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        return ExecutionGateRequest(
            sender_aid=envelope.sender_aid,
            receiver_aid=envelope.receiver_aid,
            token="enc-token",
            message=message,
            action_scope=envelope.action_scope,
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
            parameters=parameters,
        )

    def _parent_capability_envelope(
        self,
        *,
        authorized_scopes: list[str] | None = None,
        scope_constraints: dict[str, list[dict]] | None = None,
    ) -> RequestEnvelope:
        """构造允许委托和 send_email 的父 capability 信封。"""
        return build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="parent-token",
            session_id="session-1",
            turn_id="turn-parent",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=authorized_scopes or ["delegation", "tool_call:send_email"],
            scope_constraints=scope_constraints,
            message="parent",
            timestamp=self.now,
            capability_id="cap-parent",
        )

    def _delegated_child_envelope(
        self,
        parent: RequestEnvelope,
        *,
        authorized_scopes: list[str] | None = None,
        parent_digest: str | None = None,
        parent_scopes: list[str] | None = None,
        parent_scope_constraints: dict[str, list[dict]] | None = None,
        scope_constraints: dict[str, list[dict]] | None = None,
        delegation_depth: int = 1,
        max_delegation_depth: int = 8,
    ) -> RequestEnvelope:
        """构造绑定父 capability 的委托子信封。"""
        return build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-child",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            authorized_scopes=authorized_scopes,
            scope_constraints=scope_constraints,
            message="child",
            timestamp=self.now,
            capability_id="cap-child",
            parent_envelope_digest=parent.hex_digest() if parent_digest is None else parent_digest,
            parent_authorized_scopes=(
                parent.authorized_scopes if parent_scopes is None else parent_scopes
            ),
            parent_scope_constraints=(
                parent.scope_constraints
                if parent_scope_constraints is None
                else parent_scope_constraints
            ),
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
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

    def test_gate_rejects_revoked_capability_id_after_signature_verification(self) -> None:
        """已撤销 capability id 即使签名/CAN 通过也必须 fail-closed。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-revoked",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=self.now,
            capability_id="cap-revoked",
        )
        request = self._signed_request_from_envelope(envelope, "hello")
        revocations = InMemoryRevocationStore(capability_ids={"cap-revoked"})
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            revocation_store=revocations,
        )

        decision = gate.evaluate_request(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "capability_revoked")
        self.assertTrue(decision.pq_signature_valid)
        self.assertTrue(decision.can_accept)
        self.assertTrue(decision.execution_scope_allowed)
        self.assertIsNone(gate.build_local_execution_context_from_decision(request, decision))

    def test_gate_rejects_child_when_parent_digest_is_revoked(self) -> None:
        """撤销父 envelope digest 应级联拒绝声明该父 digest 的子 capability。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent)
        request = self._signed_request_from_envelope(child, "child")
        revocations = InMemoryRevocationStore(
            parent_envelope_digests={parent.hex_digest()}
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent},
            revocation_store=revocations,
        )

        decision = gate.evaluate_request(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "parent_capability_revoked")
        self.assertTrue(decision.pq_signature_valid)
        self.assertTrue(decision.can_accept)

    def test_sqlite_revocation_store_rejects_revoked_capability(self) -> None:
        """SQLite revocation store 应持久化 capability id 撤销事实。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-sqlite-revoked",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=self.now,
            capability_id="cap-sqlite-revoked",
        )
        request = self._signed_request_from_envelope(envelope, "hello")

        with tempfile.TemporaryDirectory() as tmpdir:
            revocations = SQLiteRevocationStore(Path(tmpdir) / "revocations.sqlite3")
            revocations.revoke_capability_id("cap-sqlite-revoked", reason="operator test")
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                revocation_store=revocations,
            )

            decision = gate.evaluate_request(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "capability_revoked")

    def test_gate_fails_closed_when_revocation_store_is_unavailable(self) -> None:
        """配置了 revocation store 时，查询失败必须拒绝而不是放行。"""
        request = self._build_request()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            revocation_store=_UnavailableRevocationStore(),
        )

        decision = gate.evaluate_request(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "revocation_store_unavailable")
        self.assertTrue(decision.pq_signature_valid)
        self.assertTrue(decision.can_accept)

    def test_enforcement_mode_values_are_stable_for_audit(self) -> None:
        """执行强制模式需要稳定的小写值，供配置和审计 JSON 复用。"""
        self.assertEqual(EnforcementMode.STRICT.value, "strict")
        self.assertEqual(EnforcementMode.PERMISSIVE.value, "permissive")
        self.assertEqual(EnforcementMode.DISABLED.value, "disabled")

    def test_authorize_accepts_delegated_child_capability_when_attenuated(self) -> None:
        """合法委托子 capability 绑定父摘要且 scope 不扩大时应通过。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent)
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )

        decision = gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized")
        self.assertTrue(decision.execution_scope_allowed)

    def test_authorize_rejects_delegated_child_without_known_parent_digest(self) -> None:
        """委托子 capability 的父摘要不在本地事实源中时必须 fail-closed。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent)

        decision = self.gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_parent_envelope_digest")
        self.assertTrue(decision.request_envelope_valid)

    def test_authorize_rejects_delegated_child_missing_parent_digest(self) -> None:
        """delegation_depth>0 但未绑定 parent digest 时应稳定拒绝。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent, parent_digest="")

        decision = self.gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "missing_parent_envelope_digest")

    def test_authorize_rejects_delegated_child_scope_escalation(self) -> None:
        """子 capability 不能把父未授权工具 scope 加进签名授权面。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(
            parent,
            authorized_scopes=["tool_call:add_calendar_event"],
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )

        decision = gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "delegation_scope_escalation")
        self.assertFalse(decision.execution_scope_allowed)

    def test_authorize_rejects_delegated_child_parent_scope_mismatch(self) -> None:
        """子信封中声明的父 scopes 必须匹配本地父 capability 事实源。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent, parent_scopes=["tool_call"])
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )

        decision = gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "parent_authorized_scopes_mismatch")

    def test_parent_capability_store_rejects_constraints_outside_parent_scopes(self) -> None:
        """父 capability fact source 中的参数约束必须落在父 scopes 覆盖内。"""
        with self.assertRaisesRegex(ValueError, "covered by authorized_scopes"):
            SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                parent_capability_store={
                    "a" * 64: {
                        "authorized_scopes": ("delegation",),
                        "scope_constraints": {
                            "tool_call:send_email": [
                                {
                                    "field": "recipient_domain",
                                    "op": "eq",
                                    "value": "example.com",
                                }
                            ]
                        },
                    }
                },
            )

    def test_authorize_accepts_delegated_child_when_constraints_are_narrowed(self) -> None:
        """子 capability 保留或收窄父参数约束时可以通过委托校验。"""
        parent = self._parent_capability_envelope(
            scope_constraints={
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
        child = self._delegated_child_envelope(
            parent,
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"},
                    {"field": "body", "op": "max_length", "value": 120},
                ]
            },
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={
                parent.hex_digest(): {
                    "authorized_scopes": parent.authorized_scopes,
                    "scope_constraints": parent.scope_constraints,
                }
            },
        )

        decision = gate.evaluate_request(
            self._signed_request_from_envelope(
                child,
                "child",
                parameters={"recipient_domain": "example.com", "body": "short"},
            )
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized")

    def test_authorize_rejects_delegated_child_missing_parent_constraints_fact(self) -> None:
        """父 capability 有参数约束时，子信封必须绑定同一份父约束事实。"""
        parent = self._parent_capability_envelope(
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )
        child = self._delegated_child_envelope(
            parent,
            parent_scope_constraints={},
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={
                parent.hex_digest(): {
                    "authorized_scopes": parent.authorized_scopes,
                    "scope_constraints": parent.scope_constraints,
                }
            },
        )

        decision = gate.evaluate_request(
            self._signed_request_from_envelope(
                child,
                "child",
                parameters={"recipient_domain": "example.com"},
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "parent_scope_constraints_mismatch")

    def test_authorize_rejects_delegated_child_constraint_deletion(self) -> None:
        """子 capability 删除适用父约束时必须 fail-closed。"""
        parent = self._parent_capability_envelope(
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )
        child = self._delegated_child_envelope(parent, scope_constraints={})
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={
                parent.hex_digest(): {
                    "authorized_scopes": parent.authorized_scopes,
                    "scope_constraints": parent.scope_constraints,
                }
            },
        )

        decision = gate.evaluate_request(
            self._signed_request_from_envelope(
                child,
                "child",
                parameters={"recipient_domain": "example.com"},
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "delegation_constraint_escalation")

    def test_authorize_rejects_delegated_child_constraint_relaxation(self) -> None:
        """子 capability 放宽父参数约束时必须 fail-closed。"""
        parent = self._parent_capability_envelope(
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            }
        )
        child = self._delegated_child_envelope(
            parent,
            scope_constraints={
                "tool_call:send_email": [
                    {
                        "field": "recipient_domain",
                        "op": "in",
                        "values": ["example.com", "evil.test"],
                    }
                ]
            },
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={
                parent.hex_digest(): {
                    "authorized_scopes": parent.authorized_scopes,
                    "scope_constraints": parent.scope_constraints,
                }
            },
        )

        decision = gate.evaluate_request(
            self._signed_request_from_envelope(
                child,
                "child",
                parameters={"recipient_domain": "example.com"},
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "delegation_constraint_escalation")

    def test_authorize_rejects_delegated_child_constraint_moved_to_wider_scope(self) -> None:
        """子 capability 不能把父 narrow scope 约束移动到更宽 scope。"""
        parent = self._parent_capability_envelope(
            authorized_scopes=["delegation", "tool_call"],
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        child = self._delegated_child_envelope(
            parent,
            authorized_scopes=["tool_call"],
            scope_constraints={
                "tool_call": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={
                parent.hex_digest(): {
                    "authorized_scopes": parent.authorized_scopes,
                    "scope_constraints": parent.scope_constraints,
                }
            },
        )

        decision = gate.evaluate_request(
            self._signed_request_from_envelope(
                child,
                "child",
                parameters={"recipient_domain": "example.com"},
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "delegation_constraint_escalation")

    def test_authorize_rejects_delegation_depth_exceeded(self) -> None:
        """超过最大委托深度的子 capability 必须 fail-closed。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(
            parent,
            delegation_depth=2,
            max_delegation_depth=1,
        )
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )

        decision = gate.evaluate_request(self._signed_request_from_envelope(child, "child"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "delegation_depth_exceeded")

    def test_consume_request_rejects_replayed_envelope(self) -> None:
        """同一个已消费信封再次进入执行路径时必须 replay 拒绝。"""
        request = self._build_request()

        first_decision = self.gate.consume_request(request)
        second_decision = self.gate.consume_request(request)

        self.assertTrue(first_decision.allowed)
        self.assertFalse(second_decision.allowed)
        self.assertEqual(second_decision.reason, "replayed_request_envelope")

    def test_consume_request_allows_only_one_concurrent_consumer(self) -> None:
        """同一 gate 并发消费同一个信封时只能有一个执行授权。"""
        request = self._build_request()
        barrier = threading.Barrier(8)

        def consume_once(_index: int) -> str:
            """同步发起消费请求，放大同一信封的并发竞争窗口。"""
            barrier.wait()
            return self.gate.consume_request(request).reason

        with ThreadPoolExecutor(max_workers=8) as executor:
            reasons = list(executor.map(consume_once, range(8)))

        self.assertEqual(reasons.count("authorized"), 1)
        self.assertEqual(reasons.count("replayed_request_envelope"), 7)

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

    def test_sqlite_replay_store_rejects_replay_across_gate_instances(self) -> None:
        """SQLite replay store 应通过唯一约束让不同 gate 实例共享消费状态。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "replay.sqlite3"
            first_gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=SQLiteReplayStateStore(database_path),
            )
            second_gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                replay_state_store=SQLiteReplayStateStore(database_path),
            )
            request = self._build_request()

            self.assertTrue(first_gate.consume_request(request).allowed)
            replay_decision = second_gate.consume_request(request)

            self.assertFalse(replay_decision.allowed)
            self.assertEqual(replay_decision.reason, "replayed_request_envelope")

    def test_sqlite_replay_store_reserves_request_id_atomically(self) -> None:
        """并发预留同一 request id 时，SQLite 后端只能有一个 reserved 结果。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            envelope = build_request_envelope(
                sender_aid="alice@example.com:calendar_agent",
                receiver_aid="bob@example.com:email_agent",
                token="enc-token",
                session_id="session-1",
                turn_id="turn-1",
                issued_at=self.now - timedelta(minutes=1),
                expires_at=self.now + timedelta(minutes=5),
                action_scope="llm_prompt",
                message="hello",
                provider_id="https://provider.example.test",
                timestamp=self.now,
            )
            database_path = Path(tmpdir) / "replay.sqlite3"
            request_id = envelope.hex_digest()
            stores = [SQLiteReplayStateStore(database_path), SQLiteReplayStateStore(database_path)]
            barrier = threading.Barrier(2)

            def reserve_once(store_index: int) -> str:
                """让两个独立 store 实例同时竞争同一个 request id。"""
                barrier.wait()
                return stores[store_index].reserve_request(request_id, envelope)

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(reserve_once, range(2)))

            self.assertEqual(results.count("reserved"), 1)
            self.assertEqual(results.count("replayed"), 1)
            self.assertEqual(SQLiteReplayStateStore(database_path).load_consumed_request_ids(), {request_id})

    def test_redis_replay_store_uses_set_nx_for_atomic_reservation(self) -> None:
        """Redis replay store 必须通过 SET NX 语义原子预留 request id。"""
        request = self._build_request()
        envelope = parse_request_envelope(request.request_envelope)
        client = _FakeRedisClient()
        store = RedisReplayStateStore(client, ttl_seconds=3600)
        request_id = envelope.hex_digest()

        self.assertEqual(store.reserve_request(request_id, envelope), "reserved")
        self.assertEqual(store.reserve_request(request_id, envelope), "replayed")
        self.assertEqual(client.set_calls[0]["nx"], True)
        self.assertEqual(client.set_calls[0]["ex"], 3600)
        self.assertEqual(store.load_consumed_request_ids(), {request_id})

    def test_redis_replay_store_failures_fail_closed(self) -> None:
        """Redis backend 异常应转为 OSError，让执行路径 fail-closed。"""
        request = self._build_request()
        envelope = parse_request_envelope(request.request_envelope)
        broken_client = mock.Mock()
        broken_client.set.side_effect = RuntimeError("redis down")
        store = RedisReplayStateStore(broken_client)

        with self.assertRaises(OSError):
            store.reserve_request(envelope.hex_digest(), envelope)

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

    def test_consume_request_fails_closed_when_injected_replay_store_is_unavailable(self) -> None:
        """注入 replay store 不可写时，请求必须拒绝而不是只记录内存状态。"""
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            replay_state_store=_UnavailableReplayStateStore(),
        )

        decision = gate.consume_request(self._build_request())

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "replay_state_persistence_failed")

    def test_consume_request_fails_closed_when_allowed_decision_lacks_envelope(self) -> None:
        """即使内部 decision 不变量被破坏，消费路径也必须显式拒绝。"""
        with mock.patch.object(
            self.gate,
            "evaluate_request",
            return_value=ExecutionGateDecision(True, "authorized"),
        ):
            decision = self.gate.consume_request(self._build_request())

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "missing_request_envelope")

    def test_build_local_execution_context_rejects_incomplete_allowed_decision(self) -> None:
        """构造本地执行上下文时不能依赖可被优化移除的 assert。"""
        context = self.gate.build_local_execution_context_from_decision(
            self._build_request(),
            ExecutionGateDecision(True, "authorized"),
        )

        self.assertIsNone(context)

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

    def test_sqlite_capability_state_store_consumes_total_budget(self) -> None:
        """SQLite budget store 应按 signed total budget 原子扣减执行次数。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-budget",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            execution_budget={"total": 1},
            message="budgeted",
            timestamp=self.now,
            capability_id="cap-budget",
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")

        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                capability_state_store=SQLiteCapabilityStateStore(
                    Path(tmpdir) / "capability.sqlite3"
                ),
            )
            context = gate.build_local_execution_context(request)
            assert context is not None

            context.require_tool_call("send_email")
            with self.assertRaisesRegex(ExecutionAuthorizationError, "capability_budget_exhausted"):
                context.require_tool_call("send_email")

    def test_sqlite_capability_state_store_consumes_matching_scope_budget(self) -> None:
        """更窄的 signed scope budget 只限制匹配的执行面。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-scope-budget",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email", "tool_call:add_calendar_event"],
            execution_budget={"tool_call:send_email": 1},
            message="budgeted",
            timestamp=self.now,
            capability_id="cap-scope-budget",
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")

        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                capability_state_store=SQLiteCapabilityStateStore(
                    Path(tmpdir) / "capability.sqlite3"
                ),
            )
            context = gate.build_local_execution_context(request)
            assert context is not None

            context.require_tool_call("send_email")
            with self.assertRaisesRegex(ExecutionAuthorizationError, "capability_budget_exhausted"):
                context.require_tool_call("send_email")
            context.require_tool_call("add_calendar_event")
            context.require_tool_call("add_calendar_event")

    def test_budgeted_context_fails_closed_without_state_store(self) -> None:
        """带预算的 capability 缺少状态后端时必须拒绝受保护动作。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-missing-budget-store",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            execution_budget={"total": 1},
            message="budgeted",
            timestamp=self.now,
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")

        context = self.gate.build_local_execution_context(request)

        assert context is not None
        with self.assertRaisesRegex(ExecutionAuthorizationError, "capability_budget_store_missing"):
            context.require_tool_call("send_email")

    def test_budgeted_context_fails_closed_when_state_store_unavailable(self) -> None:
        """预算状态后端故障时必须 fail-closed，不能放行 protected sink。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-unavailable-budget-store",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            execution_budget={"total": 1},
            message="budgeted",
            timestamp=self.now,
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            capability_state_store=_UnavailableCapabilityStateStore(),
        )

        context = gate.build_local_execution_context(request)

        assert context is not None
        with self.assertRaisesRegex(
            ExecutionAuthorizationError,
            "capability_budget_store_unavailable",
        ):
            context.require_tool_call("send_email")

    def test_sqlite_capability_state_store_allows_only_budgeted_concurrent_consumers(self) -> None:
        """并发消费同一 capability 时，通过次数不得超过 signed total budget。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-concurrent-budget",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            execution_budget={"total": 2},
            message="budgeted",
            timestamp=self.now,
            capability_id="cap-concurrent-budget",
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")

        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                capability_state_store=SQLiteCapabilityStateStore(
                    Path(tmpdir) / "capability.sqlite3",
                    timeout_seconds=10.0,
                ),
            )

            def consume_once() -> str:
                context = gate.build_local_execution_context(request)
                assert context is not None
                try:
                    context.require_tool_call("send_email")
                except ExecutionAuthorizationError as exc:
                    return exc.reason
                return "consumed"

            with ThreadPoolExecutor(max_workers=4) as executor:
                reasons = list(executor.map(lambda _: consume_once(), range(4)))

            self.assertEqual(reasons.count("consumed"), 2)
            self.assertEqual(reasons.count("capability_budget_exhausted"), 2)

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

    def test_entry_scope_constraints_reject_out_of_bounds_parameters(self) -> None:
        """签名约束绑定入口参数，参数越界时 gate 必须 fail-closed。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            message="send mail",
            timestamp=self.now,
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="send mail",
            action_scope="tool_call:send_email",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
            parameters={"recipient_domain": "evil.test"},
        )

        decision = self.gate.evaluate_request(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "execution_scope_not_authorized")
        self.assertFalse(decision.execution_scope_allowed)

    def test_entry_scope_constraints_accept_matching_parameters(self) -> None:
        """参数满足已签名约束时，入口 scope 才能通过。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            message="send mail",
            timestamp=self.now,
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="send mail",
            action_scope="tool_call:send_email",
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
            parameters={"recipient_domain": "example.com"},
        )

        decision = self.gate.evaluate_request(request)

        self.assertTrue(decision.allowed)
        self.assertTrue(decision.execution_scope_allowed)

    def test_authorize_rejects_tampered_scope_constraints(self) -> None:
        """修改约束谓词必须改变 canonical digest 并导致签名验证失败。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-1",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            message="send mail",
            timestamp=self.now,
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        envelope_dict = envelope.as_dict()
        envelope_dict["scope_constraints"]["tool_call:send_email"][0]["value"] = "evil.test"
        tampered_envelope = json.dumps(
            envelope_dict,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="send mail",
            action_scope="tool_call:send_email",
            request_envelope=tampered_envelope,
            pq_signature=base64.b64encode(signature).decode("utf-8"),
            parameters={"recipient_domain": "evil.test"},
        )

        self.assertFalse(self.gate.authorize(request))
        self.assertEqual(
            self.gate.evaluate_request(request).reason,
            "signature_verification_failed",
        )

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
        ).with_formula_values(
            enforcement_mode="permissive",
            downgrade_reason="integration smoke only",
            would_reject=True,
            would_reject_reason="message_digest_mismatch",
        )

        record = build_execution_gate_audit_record(request, decision)

        self.assertFalse(record["allowed"])
        self.assertEqual(record["reason"], "message_digest_mismatch")
        self.assertEqual(record["enforcement_mode"], "permissive")
        self.assertEqual(record["downgrade_reason"], "integration smoke only")
        self.assertTrue(record["would_reject"])
        self.assertEqual(record["would_reject_reason"], "message_digest_mismatch")
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
        """Audit helpers should append hash-chained records to a local JSONL file."""
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
            self.assertEqual(payload["seq"], 0)
            self.assertEqual(payload["prev_hash"], "0" * 64)
            self.assertEqual(len(payload["entry_hash"]), 64)

            validation = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(validation.valid)
            self.assertEqual(validation.reason, "ok")
            self.assertEqual(validation.checked_records, 1)
            self.assertEqual(validation.last_seq, 0)
            self.assertEqual(validation.tail_hash, payload["entry_hash"])

    def test_append_execution_gate_audit_record_links_multiple_rows(self) -> None:
        """连续审计记录应以前一条 entry hash 作为下一条 prev hash。"""
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
            append_execution_gate_audit_record(tmpdir, {**record, "reason": "second"})

            assert audit_path is not None
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[0]["seq"], 0)
            self.assertEqual(rows[1]["seq"], 1)
            self.assertEqual(rows[1]["prev_hash"], rows[0]["entry_hash"])
            self.assertNotEqual(rows[1]["entry_hash"], rows[0]["entry_hash"])

            validation = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(validation.valid)
            self.assertEqual(validation.tail_hash, rows[1]["entry_hash"])

    def test_validate_execution_gate_audit_chain_detects_tampering(self) -> None:
        """篡改已写入记录会导致 entry hash 校验失败。"""
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
            append_execution_gate_audit_record(tmpdir, {**record, "reason": "second"})

            assert audit_path is not None
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            rows[0]["reason"] = "tampered_reason"
            audit_path.write_text(
                "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                encoding="utf-8",
            )

            validation = validate_execution_gate_audit_chain(audit_path)
            self.assertFalse(validation.valid)
            self.assertEqual(validation.reason, "entry_hash_mismatch")
            self.assertEqual(validation.failure_line, 1)

            with self.assertRaisesRegex(RuntimeError, "entry_hash_mismatch"):
                append_execution_gate_audit_record(tmpdir, record)

    def test_validate_execution_gate_audit_chain_uses_external_tail_anchor(self) -> None:
        """本地链只能用外部 tail hash 锚点检测末尾截断。"""
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
            append_execution_gate_audit_record(tmpdir, {**record, "reason": "second"})
            assert audit_path is not None
            original_validation = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(original_validation.valid)
            assert original_validation.tail_hash is not None

            rows = audit_path.read_text(encoding="utf-8").splitlines()
            audit_path.write_text(rows[0] + "\n", encoding="utf-8")

            local_validation = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(local_validation.valid)
            anchored_validation = validate_execution_gate_audit_chain(
                audit_path,
                expected_tail_hash=original_validation.tail_hash,
            )
            self.assertFalse(anchored_validation.valid)
            self.assertEqual(anchored_validation.reason, "tail_hash_mismatch")

    def test_append_execution_gate_audit_record_anchors_legacy_jsonl_prefix(self) -> None:
        """旧普通 JSONL 前缀可作为新 hash chain 的合成锚点。"""
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
            audit_dir = Path(tmpdir) / "audit"
            audit_dir.mkdir()
            audit_path = audit_dir / "execution_gate.jsonl"
            audit_path.write_text(
                json.dumps({"reason": "legacy", "allowed": False}) + "\n",
                encoding="utf-8",
            )

            validation_before = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(validation_before.valid)
            self.assertEqual(validation_before.reason, "legacy_jsonl_without_chain")
            self.assertEqual(validation_before.legacy_prefix_records, 1)

            append_execution_gate_audit_record(tmpdir, record)
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertNotIn("entry_hash", rows[0])
            self.assertEqual(rows[1]["seq"], 1)
            self.assertEqual(rows[1]["prev_hash"], validation_before.tail_hash)

            validation_after = validate_execution_gate_audit_chain(audit_path)
            self.assertTrue(validation_after.valid)
            self.assertEqual(validation_after.reason, "ok_with_legacy_prefix")

    def test_build_execution_gate_audit_record_captures_capability_metadata(self) -> None:
        """审计记录应保留签名 capability 与父 capability 绑定字段。"""
        parent = self._parent_capability_envelope()
        child = self._delegated_child_envelope(parent)
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {"alice@example.com:calendar_agent": self.key_pair.public_key},
            now_fn=lambda: self.now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )
        request = self._signed_request_from_envelope(child, "child")
        decision = gate.evaluate_request(request)

        record = build_execution_gate_audit_record(request, decision)

        self.assertTrue(record["allowed"])
        self.assertEqual(record["signed_capability_id"], "cap-child")
        self.assertEqual(record["signed_parent_envelope_digest"], parent.hex_digest())
        self.assertEqual(
            record["signed_parent_authorized_scopes"],
            list(parent.authorized_scopes),
        )
        self.assertEqual(record["signed_delegation_depth"], 1)
        self.assertEqual(record["signed_max_delegation_depth"], 8)

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

    def test_local_context_enforces_signed_scope_constraints(self) -> None:
        """下游本地执行上下文也必须执行签名参数约束。"""
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
            message="draft mail",
            timestamp=self.now,
            scope_constraints={
                "tool_call:send_email": [
                    {"field": "recipient_domain", "op": "eq", "value": "example.com"}
                ]
            },
        )
        request = self._signed_request_from_envelope(envelope, "draft mail")

        context = self.gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        context.require_tool_call("send_email", {"recipient_domain": "example.com"})
        with self.assertRaises(ExecutionAuthorizationError) as raised:
            context.require_tool_call("send_email", {"recipient_domain": "evil.test"})

        self.assertEqual(raised.exception.reason, "unauthorized_tool_scope")

    def test_local_context_blocks_private_egress_without_declassify_scope(self) -> None:
        """非 public 标签流向 egress sink 时必须有显式 declassify scope。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-ifc-block",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            flow_policy={"egress": {"tool_call:send_email": ["public"]}},
            message="draft private mail",
            timestamp=self.now,
        )
        context = self.gate.build_local_execution_context(
            self._signed_request_from_envelope(envelope, "draft private mail")
        )

        assert context is not None
        with self.assertRaises(ExecutionAuthorizationError) as raised:
            context.require_egress("tool_call:send_email", ("public", "private"))

        self.assertEqual(raised.exception.reason, "ifc_declassify_scope_required")
        self.assertEqual(raised.exception.action_scope, "tool_call:send_email")

    def test_local_context_allows_private_egress_with_signed_declassify_scope(self) -> None:
        """签名 capability 显式携带 declassify:<label> 后才可降密流出。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-ifc-allow",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email", "declassify:private"],
            flow_policy={"egress": {"tool_call:send_email": ["public"]}},
            message="draft private mail",
            timestamp=self.now,
        )
        context = self.gate.build_local_execution_context(
            self._signed_request_from_envelope(envelope, "draft private mail")
        )

        assert context is not None
        self.assertEqual(
            context.join_flow_labels("public", ("private",)),
            ("private", "public"),
        )
        self.assertEqual(
            context.blocked_egress_labels("tool_call:send_email", ("private",)),
            ("private",),
        )
        self.assertTrue(
            context.authorize_egress("tool_call:send_email", ("private",))
        )
        context.require_egress("tool_call:send_email", ("private",))

    def test_facade_egress_wrapper_rejects_before_side_effect(self) -> None:
        """facade egress helper 应在副作用前执行 IFC 与 declassify 检查。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-ifc-facade",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            flow_policy={"egress": {"tool_call:send_email": ["public"]}},
            message="draft private mail",
            timestamp=self.now,
            capability_id="cap-ifc-facade",
        )
        context = self.gate.build_local_execution_context(
            self._signed_request_from_envelope(envelope, "draft private mail")
        )
        assert context is not None
        monitor = InMemoryExecutionInvariantMonitor()
        facade = ExecutionCapabilityFacade(lambda: context, invariant_monitor=monitor)
        side_effects: list[str] = []

        with self.assertRaises(ExecutionAuthorizationError) as raised:
            facade.call_egress(
                "tool_call:send_email",
                ("private",),
                lambda: side_effects.append("sent"),
            )

        self.assertEqual(raised.exception.reason, "ifc_declassify_scope_required")
        self.assertEqual(side_effects, [])
        events = monitor.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "violation")
        self.assertEqual(events[0].reason, "ifc_declassify_scope_required")
        self.assertEqual(events[0].capability_id, "cap-ifc-facade")

    def test_authorize_rejects_tampered_flow_policy(self) -> None:
        """修改已签名 flow_policy 必须导致签名验签失败。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-ifc-tamper",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email", "declassify:private"],
            flow_policy={"egress": {"tool_call:send_email": ["public"]}},
            message="draft private mail",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        envelope_dict = envelope.as_dict()
        envelope_dict["flow_policy"]["egress"]["tool_call:send_email"].append("private")
        tampered_envelope = json.dumps(
            envelope_dict,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        request = ExecutionGateRequest(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            message="draft private mail",
            action_scope="llm_prompt",
            request_envelope=tampered_envelope,
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )

        self.assertFalse(self.gate.authorize(request))
        self.assertEqual(
            self.gate.evaluate_request(request).reason,
            "signature_verification_failed",
        )

    def test_execution_invariant_monitor_records_authorized_and_rejected_sink(self) -> None:
        """capability facade 应把 sink 授权通过和不变式违例记录到 monitor。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-monitor",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            message="draft mail",
            timestamp=self.now,
            capability_id="cap-monitor",
        )
        request = self._signed_request_from_envelope(envelope, "draft mail")
        context = self.gate.build_local_execution_context(request)
        assert context is not None
        monitor = InMemoryExecutionInvariantMonitor()
        facade = ExecutionCapabilityFacade(
            lambda: context,
            invariant_monitor=monitor,
        )

        facade.require_action(
            "tool_call:send_email",
            {"recipient_domain": "example.com", "body": "not logged"},
        )
        with self.assertRaises(ExecutionAuthorizationError):
            facade.require_action("tool_call:add_calendar_event")

        events = monitor.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].status, "authorized")
        self.assertEqual(events[0].reason, "authorized")
        self.assertEqual(events[0].capability_id, "cap-monitor")
        self.assertEqual(events[0].action_scope, "tool_call:send_email")
        self.assertEqual(
            events[0].constraint_parameter_keys,
            ("body", "recipient_domain"),
        )
        self.assertEqual(events[1].status, "violation")
        self.assertEqual(events[1].reason, "unauthorized_tool_scope")
        self.assertEqual(events[1].action_scope, "tool_call:add_calendar_event")

    def test_execution_invariant_monitor_records_missing_context_violation(self) -> None:
        """严格 facade 缺少 LocalExecutionContext 时应记录 violation 并 fail-closed。"""
        monitor = InMemoryExecutionInvariantMonitor()
        facade = ExecutionCapabilityFacade(
            lambda: None,
            context_required=True,
            invariant_monitor=monitor,
        )

        with self.assertRaisesRegex(
            ExecutionAuthorizationError,
            "missing_local_execution_context",
        ):
            facade.require_action("tool_call:send_email")

        events = monitor.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "violation")
        self.assertEqual(events[0].reason, "missing_local_execution_context")
        self.assertEqual(events[0].action_scope, "tool_call:send_email")

    def test_jsonl_execution_invariant_monitor_omits_parameter_values(self) -> None:
        """JSONL monitor 只能记录参数键名，不能写入工具参数值。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-jsonl-monitor",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["delegation"],
            message="delegate",
            timestamp=self.now,
        )
        facade_context = self.gate.build_local_execution_context(
            self._signed_request_from_envelope(envelope, "delegate")
        )
        assert facade_context is not None

        with tempfile.TemporaryDirectory() as tmpdir:
            facade = ExecutionCapabilityFacade(
                lambda: facade_context,
                invariant_monitor=JSONLExecutionInvariantMonitor(tmpdir),
            )
            facade.require_action("delegation", {"secret": "do-not-log"})
            audit_path = Path(tmpdir) / "audit" / "execution_invariants.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[-1]["status"], "authorized")
        self.assertEqual(rows[-1]["constraint_parameter_keys"], ["secret"])
        self.assertNotIn("do-not-log", json.dumps(rows[-1], sort_keys=True))

    def test_require_any_action_consumes_budget_for_selected_scope(self) -> None:
        """候选 scope 授权路径也必须在 protected sink 前消费 signed budget。"""
        envelope = build_request_envelope(
            sender_aid="alice@example.com:calendar_agent",
            receiver_aid="bob@example.com:email_agent",
            token="enc-token",
            session_id="session-1",
            turn_id="turn-any-budget",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:submit_expense_report"],
            execution_budget={"total": 1},
            message="budgeted",
            timestamp=self.now,
            capability_id="cap-any-budget",
        )
        request = self._signed_request_from_envelope(envelope, "budgeted")

        with tempfile.TemporaryDirectory() as tmpdir:
            gate = SignedRequestExecutionGate(
                CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                {"alice@example.com:calendar_agent": self.key_pair.public_key},
                now_fn=lambda: self.now,
                capability_state_store=SQLiteCapabilityStateStore(
                    Path(tmpdir) / "capability.sqlite3"
                ),
            )
            context = gate.build_local_execution_context(request)
            assert context is not None
            monitor = InMemoryExecutionInvariantMonitor()
            facade = ExecutionCapabilityFacade(
                lambda: context,
                invariant_monitor=monitor,
            )

            facade.require_any_action(
                ("tool_call:send_email", "tool_call:submit_expense_report")
            )
            with self.assertRaisesRegex(
                ExecutionAuthorizationError,
                "capability_budget_exhausted",
            ):
                facade.require_any_action(
                    ("tool_call:send_email", "tool_call:submit_expense_report")
                )

        events = monitor.events()
        self.assertEqual(events[0].status, "authorized")
        self.assertEqual(events[0].action_scope, "tool_call:submit_expense_report")
        self.assertEqual(events[1].status, "violation")
        self.assertEqual(events[1].reason, "capability_budget_exhausted")


if __name__ == "__main__":
    unittest.main()
