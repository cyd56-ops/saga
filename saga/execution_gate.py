"""Execution-layer authorization interfaces for SAGA-PQ-CAN."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Literal, ParamSpec, Protocol, TypeVar

from saga.messages import (
    RequestEnvelope,
    action_scopes_are_attenuated,
    action_scopes_allow,
    parse_request_envelope,
    sha256_hex,
)


P = ParamSpec("P")
T = TypeVar("T")
ActionScopeSpec = str | tuple[str, ...] | Callable[..., str | tuple[str, ...]]


def bytes_to_bits(payload: bytes) -> list[int]:
    """把字节串展开为大端序比特列表，避免核心 gate 导入 neural 包。"""
    bits: list[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


@dataclass(frozen=True)
class ExecutionGateRequest:
    """Execution-layer authorization input for a received request."""

    sender_aid: str | None
    receiver_aid: str
    token: str
    message: str
    action_scope: str
    request_envelope: dict | str | bytes | None = None
    pq_signature: str | bytes | None = None


@dataclass(frozen=True)
class ExecutionGateDecision:
    """执行层授权检查的结构化结果，并显式记录最终公式中的各项。"""

    allowed: bool
    """Whether the request may enter the local execution path."""
    reason: str
    """Stable local audit reason for allow/deny handling."""
    protocol_allow: bool | None = None
    """Whether the SAGA token/protocol layer admitted the request when known."""
    request_envelope_valid: bool = False
    """Whether the canonical envelope is present, parseable, and context-bound."""
    pq_signature_valid: bool = False
    """Whether the detached signature material verifies for the envelope."""
    can_accept: bool = False
    """Whether the Shamir-secured CAN returned a hard accept bit."""
    execution_scope_allowed: bool = False
    """Whether the signed scopes authorize the concrete execution surface."""
    internal_policy_accept: bool | None = None
    """Whether the local runtime policy accepted the requested action when known."""
    request_envelope: RequestEnvelope | None = None
    """Parsed request envelope when validation succeeded."""
    pq_signature: bytes | None = None
    """Detached signature bytes when validation succeeded."""
    sender_public_key: bytes | None = None
    """Trusted sender public key used for verification when validation succeeded."""

    def with_formula_values(
        self,
        *,
        protocol_allow: bool | None = None,
        request_envelope_valid: bool | None = None,
        pq_signature_valid: bool | None = None,
        can_accept: bool | None = None,
        execution_scope_allowed: bool | None = None,
        internal_policy_accept: bool | None = None,
    ) -> "ExecutionGateDecision":
        """返回带有更新公式项的新 decision，避免原地修改审计状态。"""
        updates: dict[str, bool | None] = {}
        if protocol_allow is not None:
            updates["protocol_allow"] = protocol_allow
        if request_envelope_valid is not None:
            updates["request_envelope_valid"] = request_envelope_valid
        if pq_signature_valid is not None:
            updates["pq_signature_valid"] = pq_signature_valid
        if can_accept is not None:
            updates["can_accept"] = can_accept
        if execution_scope_allowed is not None:
            updates["execution_scope_allowed"] = execution_scope_allowed
        if internal_policy_accept is not None:
            updates["internal_policy_accept"] = internal_policy_accept
        return replace(self, **updates)

    def formula_terms(self) -> dict[str, bool | None]:
        """导出最终授权公式各项，供测试、审计和论文统计复用。"""
        return {
            "saga_token_valid": self.protocol_allow,
            "request_envelope_valid": self.request_envelope_valid,
            "pq_signature_valid": self.pq_signature_valid,
            "can_accept": self.can_accept,
            "execution_scope_allowed": self.execution_scope_allowed,
            "internal_policy_accept": self.internal_policy_accept,
        }


class ExecutionAuthorizationError(PermissionError):
    """表示本地执行面授权失败，并携带稳定审计 reason。"""

    def __init__(self, reason: str, action_scope: str) -> None:
        """保存被拒绝的动作 scope，供诊断区分 gate 拒绝和工具权限失败。"""
        self.reason = reason
        self.action_scope = action_scope
        super().__init__(f"{reason}: {action_scope}")


def build_execution_gate_audit_record(
    request: ExecutionGateRequest,
    decision: ExecutionGateDecision,
) -> dict[str, object]:
    """Build a stable local audit record for execution-gate decisions.

    审计记录保存签名中的入口动作和授权 scope，便于排查 fail-closed 原因。
    """
    record: dict[str, object] = {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "sender_aid": request.sender_aid,
        "receiver_aid": request.receiver_aid,
        "action_scope": request.action_scope,
        "token_digest": sha256_hex(request.token.encode("utf-8")),
        "has_request_envelope": request.request_envelope is not None,
        "has_pq_signature": request.pq_signature is not None,
    }
    formula_terms = {
        "saga_token_valid": getattr(decision, "protocol_allow", None),
        "request_envelope_valid": getattr(decision, "request_envelope_valid", False),
        "pq_signature_valid": getattr(decision, "pq_signature_valid", False),
        "can_accept": getattr(decision, "can_accept", False),
        "execution_scope_allowed": getattr(decision, "execution_scope_allowed", False),
        "internal_policy_accept": getattr(decision, "internal_policy_accept", None),
    }
    record["authorization_formula"] = formula_terms
    envelope = getattr(decision, "request_envelope", None)
    if envelope is not None:
        record["signed_sender_aid"] = envelope.sender_aid
        record["signed_receiver_aid"] = envelope.receiver_aid
        record["signed_action_scope"] = envelope.action_scope
        record["signed_authorized_scopes"] = list(envelope.authorized_scopes)
        record["signed_capability_id"] = envelope.capability_id
        record["signed_parent_envelope_digest"] = envelope.parent_envelope_digest
        record["signed_parent_authorized_scopes"] = list(envelope.parent_authorized_scopes)
        record["signed_delegation_depth"] = envelope.delegation_depth
        record["signed_max_delegation_depth"] = envelope.max_delegation_depth
    return record


def append_execution_gate_audit_record(
    workdir: str | Path | None,
    record: Mapping[str, object],
) -> Path | None:
    """Append an execution-gate audit record to a local JSONL audit file."""
    if workdir is None:
        return None

    audit_dir = Path(workdir) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "execution_gate.jsonl"
    payload = dict(record)
    payload["recorded_at"] = datetime.now(tz=timezone.utc).isoformat()
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return audit_path


class ExecutionGate(Protocol):
    """Protocol implemented by execution-layer gate adapters."""

    def authorize(self, request: ExecutionGateRequest) -> bool:
        """Return ``True`` only when the request is allowed into the execution path."""


class ReplayStateStore(Protocol):
    """记录已消费 request id 的 replay 状态后端。"""

    def load_consumed_request_ids(self) -> set[str]:
        """返回后端已记录的 request id 集合。"""

    def reserve_request(
        self,
        request_id: str,
        envelope: RequestEnvelope,
    ) -> Literal["reserved", "replayed"]:
        """原子预留 request id；已存在时返回 replayed。"""


class FileReplayStateStore:
    """使用共享目录中的原子 marker 文件保存 replay 状态。"""

    def __init__(self, state_dir: str | Path) -> None:
        """初始化文件型 replay store，并确保目录可用。"""
        self.state_dir = Path(state_dir)
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError("replay state directory is unavailable") from exc

    def load_consumed_request_ids(self) -> set[str]:
        """从 marker 目录恢复已消费 request id，供新 gate 实例复用。"""
        consumed: set[str] = set()
        for marker_path in self.state_dir.glob("*.json"):
            if marker_path.is_file():
                consumed.add(marker_path.stem)
        return consumed

    def reserve_request(
        self,
        request_id: str,
        envelope: RequestEnvelope,
    ) -> Literal["reserved", "replayed"]:
        """用独占创建 marker 的方式原子预留 request id。"""
        marker_path = self._marker_path(request_id)
        payload = {
            "request_id": request_id,
            "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
            "sender_aid": envelope.sender_aid,
            "receiver_aid": envelope.receiver_aid,
            "action_scope": envelope.action_scope,
            "token_digest": envelope.token_digest,
            "message_digest": envelope.message_digest,
        }
        try:
            with marker_path.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True))
                handle.write("\n")
        except FileExistsError:
            return "replayed"
        return "reserved"

    def _marker_path(self, request_id: str) -> Path:
        """返回 request id 对应的 marker 文件路径。"""
        return self.state_dir / f"{request_id}.json"


class SQLiteReplayStateStore:
    """使用 SQLite 唯一约束实现 SQL 风格的 replay 状态预留。"""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 5.0) -> None:
        """初始化 SQLite replay store，并创建记录已消费信封的表。"""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.database_path = Path(database_path)
        if self.database_path.parent != Path("."):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._ensure_schema()

    def load_consumed_request_ids(self) -> set[str]:
        """从 SQLite 表恢复已消费 request id，供新 gate 实例复用。"""
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT request_id FROM saga_replay_requests"
                ).fetchall()
        except sqlite3.Error as exc:
            raise OSError("sqlite replay state database is unavailable") from exc
        return {row[0] for row in rows}

    def reserve_request(
        self,
        request_id: str,
        envelope: RequestEnvelope,
    ) -> Literal["reserved", "replayed"]:
        """用主键唯一插入原子预留 request id；冲突即视为 replay。"""
        payload = (
            request_id,
            datetime.now(tz=timezone.utc).isoformat(),
            envelope.sender_aid,
            envelope.receiver_aid,
            envelope.action_scope,
            envelope.token_digest,
            envelope.message_digest,
        )
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO saga_replay_requests (
                            request_id,
                            recorded_at,
                            sender_aid,
                            receiver_aid,
                            action_scope,
                            token_digest,
                            message_digest
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        payload,
                    )
        except sqlite3.IntegrityError:
            return "replayed"
        except sqlite3.Error as exc:
            raise OSError("sqlite replay state database is unavailable") from exc
        return "reserved"

    def _connect(self) -> sqlite3.Connection:
        """打开短生命周期连接，避免跨线程共享 SQLite connection 状态。"""
        connection = sqlite3.connect(self.database_path, timeout=self.timeout_seconds)
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return connection

    def _ensure_schema(self) -> None:
        """创建 replay 状态表；request_id 主键保证 reserve 原子性。"""
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS saga_replay_requests (
                            request_id TEXT PRIMARY KEY,
                            recorded_at TEXT NOT NULL,
                            sender_aid TEXT NOT NULL,
                            receiver_aid TEXT NOT NULL,
                            action_scope TEXT NOT NULL,
                            token_digest TEXT NOT NULL,
                            message_digest TEXT NOT NULL
                        )
                        """
                    )
        except sqlite3.Error as exc:
            raise RuntimeError("sqlite replay state database is unavailable") from exc


class RedisReplayStateStore:
    """使用 Redis SET NX 实现部署级 replay request id 原子预留。"""

    def __init__(
        self,
        client: object,
        *,
        key_prefix: str = "saga:pqcan:replay:",
        ttl_seconds: int | None = None,
    ) -> None:
        """保存外部 Redis client；真实连接与认证由调用方负责注入。"""
        if not key_prefix:
            raise ValueError("key_prefix must be non-empty")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive when provided")
        self.client = client
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds

    def load_consumed_request_ids(self) -> set[str]:
        """从 Redis keyspace 恢复 request id；不支持 scan_iter 时返回空集合。"""
        scan_iter = getattr(self.client, "scan_iter", None)
        if scan_iter is None:
            return set()
        consumed: set[str] = set()
        try:
            for key in scan_iter(match=f"{self.key_prefix}*"):
                key_text = key.decode("utf-8") if isinstance(key, bytes) else str(key)
                if key_text.startswith(self.key_prefix):
                    consumed.add(key_text[len(self.key_prefix) :])
        except Exception as exc:
            raise OSError("redis replay state backend is unavailable") from exc
        return consumed

    def reserve_request(
        self,
        request_id: str,
        envelope: RequestEnvelope,
    ) -> Literal["reserved", "replayed"]:
        """用 Redis SET NX 原子预留 request id；已存在时返回 replayed。"""
        payload = json.dumps(
            {
                "request_id": request_id,
                "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
                "sender_aid": envelope.sender_aid,
                "receiver_aid": envelope.receiver_aid,
                "action_scope": envelope.action_scope,
                "token_digest": envelope.token_digest,
                "message_digest": envelope.message_digest,
            },
            sort_keys=True,
            ensure_ascii=True,
        )
        try:
            reserved = self.client.set(
                self._key(request_id),
                payload,
                nx=True,
                ex=self.ttl_seconds,
            )
        except Exception as exc:
            raise OSError("redis replay state backend is unavailable") from exc
        return "reserved" if bool(reserved) else "replayed"

    def _key(self, request_id: str) -> str:
        """返回 Redis replay marker key。"""
        return f"{self.key_prefix}{request_id}"


@dataclass(frozen=True)
class LocalExecutionContext:
    """Execution context propagated into local prompt/tool execution."""

    sender_aid: str
    receiver_aid: str
    request_envelope: RequestEnvelope
    pq_signature: bytes

    def authorize_action(self, action_scope: str) -> bool:
        """Return ``True`` only when signed scopes authorize ``action_scope``.

        下游执行权限来自信封中的显式授权列表，而不是入口 ``action_scope`` 的隐式扩展。
        """
        return action_scopes_allow(self.request_envelope.authorized_scopes, action_scope)

    def require_action(self, action_scope: str) -> None:
        """Raise ``PermissionError`` unless ``action_scope`` is authorized."""
        if not self.authorize_action(action_scope):
            raise ExecutionAuthorizationError(
                reason_for_unauthorized_scope(action_scope),
                action_scope,
            )

    def authorize_tool_call(self, tool_name: str) -> bool:
        """Return ``True`` only when the named tool call is authorized."""
        return self.authorize_action(f"tool_call:{tool_name}")

    def require_tool_call(self, tool_name: str) -> None:
        """Raise ``PermissionError`` unless the named tool call is authorized."""
        self.require_action(f"tool_call:{tool_name}")

    def authorize_memory_read(self) -> bool:
        """Return ``True`` only when memory reads are authorized."""
        return self.authorize_action("memory_read")

    def require_memory_read(self) -> None:
        """Raise ``PermissionError`` unless memory reads are authorized."""
        self.require_action("memory_read")

    def authorize_memory_write(self) -> bool:
        """Return ``True`` only when memory writes are authorized."""
        return self.authorize_action("memory_write")

    def require_memory_write(self) -> None:
        """Raise ``PermissionError`` unless memory writes are authorized."""
        self.require_action("memory_write")

    def authorize_delegation(self) -> bool:
        """Return ``True`` only when delegation is authorized."""
        return self.authorize_action("delegation")

    def require_delegation(self) -> None:
        """Raise ``PermissionError`` unless delegation is authorized."""
        self.require_action("delegation")


class ExecutionCapabilityFacade:
    """用本地执行上下文保护 tool、memory 和 delegation 的统一能力 facade。"""

    def __init__(
        self,
        context_provider: Callable[[], LocalExecutionContext | None],
        *,
        context_required: Callable[[], bool] | bool = False,
    ) -> None:
        """保存动态上下文提供者；严格模式下缺少上下文会 fail-closed。"""
        self._context_provider = context_provider
        self._context_required = context_required

    def require_action(self, action_scope: str) -> None:
        """要求当前 capability 覆盖指定执行面，否则抛出稳定授权错误。"""
        context = self._current_context(action_scope)
        if context is None:
            return
        context.require_action(action_scope)

    def require_any_action(self, action_scopes: str | tuple[str, ...]) -> None:
        """要求当前 capability 至少覆盖一个候选执行面 scope。"""
        scopes = self._normalize_action_scopes(action_scopes)
        context = self._current_context(scopes[0])
        if context is None:
            return
        if not any(context.authorize_action(action_scope) for action_scope in scopes):
            raise ExecutionAuthorizationError(
                reason_for_unauthorized_scope(scopes[0]),
                scopes[0],
            )

    def call_action(
        self,
        action_scope: str,
        operation: Callable[P, T],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T:
        """在调用底层操作前检查指定执行面 capability。"""
        self.require_action(action_scope)
        return operation(*args, **kwargs)

    def call_any_action(
        self,
        action_scopes: str | tuple[str, ...],
        operation: Callable[P, T],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T:
        """在调用底层操作前检查候选 capability 集合中的任一授权。"""
        self.require_any_action(action_scopes)
        return operation(*args, **kwargs)

    def call_tool(
        self,
        tool_name: str,
        operation: Callable[P, T],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T:
        """以 ``tool_call:<name>`` scope 保护一个底层工具调用。"""
        return self.call_action(f"tool_call:{tool_name}", operation, *args, **kwargs)

    def read_memory_steps(self, memory: object) -> tuple[Any, ...]:
        """在 ``memory_read`` capability 通过后返回不可变 memory 快照。"""
        self.require_action("memory_read")
        return tuple(getattr(memory, "steps"))

    def append_memory_step(self, memory: object, step: object) -> None:
        """在 ``memory_write`` capability 通过后追加一条 memory step。"""
        self.require_action("memory_write")
        getattr(memory, "steps").append(step)

    def delegate(
        self,
        handler: Callable[..., T],
        target_aid: str,
        message: str,
        **kwargs: Any,
    ) -> T:
        """在 ``delegation`` capability 通过后调用下游委托处理器。"""
        self.require_action("delegation")
        return handler(target_aid, message, **kwargs)

    def _normalize_action_scopes(self, action_scopes: str | tuple[str, ...]) -> tuple[str, ...]:
        """规范化候选 scope，避免空集合导致授权语义不明。"""
        scopes = (action_scopes,) if isinstance(action_scopes, str) else tuple(action_scopes)
        if not scopes:
            raise ValueError("action_scopes must be non-empty")
        return scopes

    def _current_context(self, action_scope: str) -> LocalExecutionContext | None:
        """读取当前上下文；严格 capability 路径缺失上下文时拒绝执行。"""
        context = self._context_provider()
        if context is None and self._context_required_now():
            raise ExecutionAuthorizationError(
                "missing_local_execution_context",
                action_scope,
            )
        return context

    def _context_required_now(self) -> bool:
        """解析动态或静态 strict-context 要求。"""
        if callable(self._context_required):
            return bool(self._context_required())
        return bool(self._context_required)


class GatedExecutionResource:
    """把底层工具 backend 方法包装为 capability 检查后的受保护资源。"""

    def __init__(
        self,
        resource: object,
        capabilities: ExecutionCapabilityFacade,
        method_scopes: Mapping[str, ActionScopeSpec],
    ) -> None:
        """保存底层资源和方法到 scope 的映射，未列出方法保持原行为。"""
        self._resource = resource
        self._capabilities = capabilities
        self._method_scopes = dict(method_scopes)

    def __getattr__(self, name: str) -> Any:
        """按需返回经过 capability 包装的底层方法或原始属性。"""
        attribute = getattr(self._resource, name)
        action_scopes = self._method_scopes.get(name)
        if action_scopes is None or not callable(attribute):
            return attribute

        def gated_method(*args: Any, **kwargs: Any) -> Any:
            """在 backend 方法执行前检查已签名 capability。"""
            resolved_scopes = (
                action_scopes(*args, **kwargs)
                if callable(action_scopes)
                else action_scopes
            )
            return self._capabilities.call_any_action(
                resolved_scopes,
                attribute,
                *args,
                **kwargs,
            )

        return gated_method


def reason_for_unauthorized_scope(action_scope: str) -> str:
    """将未授权执行面 scope 映射为稳定的本地拒绝原因。"""
    if action_scope.startswith("tool_call:") or action_scope == "tool_call":
        return "unauthorized_tool_scope"
    if action_scope == "memory_read":
        return "unauthorized_memory_read"
    if action_scope == "memory_write":
        return "unauthorized_memory_write"
    if action_scope == "delegation":
        return "unauthorized_delegation"
    if action_scope == "llm_prompt":
        return "prompt_scope_not_authorized"
    return "execution_scope_not_authorized"


class SignedRequestExecutionGate:
    """Verify signed request envelopes before local execution.

    This adapter is transport-facing and consumes canonical request envelopes
    plus detached signatures. It does not hold any private signing material.
    replay_state_dir 或 replay_state_store 指定时，已消费信封会持久化到共享后端，用于跨实例重放拒绝。
    """

    def __init__(
        self,
        can_gate: CAN,
        trusted_public_keys: Mapping[str, bytes],
        *,
        now_fn: Callable[[], datetime] | None = None,
        replay_state_dir: str | Path | None = None,
        replay_state_store: ReplayStateStore | None = None,
        parent_capability_store: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        """Store a CAN gate, trusted public keys, and optional shared replay state."""
        if replay_state_dir is not None and replay_state_store is not None:
            raise ValueError("configure either replay_state_dir or replay_state_store, not both")
        self.can_gate = can_gate
        self.trusted_public_keys = dict(trusted_public_keys)
        self.parent_capability_store = {
            digest.lower(): tuple(scopes)
            for digest, scopes in (parent_capability_store or {}).items()
        }
        self._now_fn = now_fn or (lambda: datetime.now(tz=timezone.utc))
        self._seen_request_ids: set[str] = set()
        self._replay_lock = threading.Lock()
        self._replay_state_store = replay_state_store
        if replay_state_dir is not None:
            self._replay_state_store = FileReplayStateStore(replay_state_dir)
        if self._replay_state_store is not None:
            self._load_persisted_request_ids()

    def authorize(self, request: ExecutionGateRequest) -> bool:
        """Return ``True`` only when the signed request envelope verifies."""
        return self.evaluate_request(request).allowed

    def evaluate_request(
        self,
        request: ExecutionGateRequest,
    ) -> ExecutionGateDecision:
        """验证请求并返回逐项公式结果；本层不持有签名私钥。"""
        if request.sender_aid is None:
            return ExecutionGateDecision(False, "missing_sender_aid")
        if request.request_envelope is None:
            return ExecutionGateDecision(False, "missing_request_envelope")
        if request.pq_signature is None:
            return ExecutionGateDecision(False, "missing_pq_signature")

        public_key = self.trusted_public_keys.get(request.sender_aid)
        if public_key is None:
            return ExecutionGateDecision(False, "untrusted_sender_aid")

        try:
            envelope = parse_request_envelope(request.request_envelope)
        except (TypeError, ValueError, json.JSONDecodeError):
            return ExecutionGateDecision(False, "invalid_request_envelope")

        try:
            signature = self._coerce_signature_bytes(request.pq_signature)
        except (TypeError, ValueError, binascii.Error):
            return ExecutionGateDecision(False, "invalid_pq_signature")

        if envelope.sender_aid != request.sender_aid:
            return ExecutionGateDecision(False, "sender_aid_mismatch")
        if envelope.receiver_aid != request.receiver_aid:
            return ExecutionGateDecision(False, "receiver_aid_mismatch")
        if envelope.action_scope != request.action_scope:
            return ExecutionGateDecision(False, "action_scope_mismatch")
        if envelope.token_digest != sha256_hex(request.token.encode("utf-8")):
            return ExecutionGateDecision(False, "token_digest_mismatch")
        if envelope.message_digest != sha256_hex(request.message.encode("utf-8")):
            return ExecutionGateDecision(False, "message_digest_mismatch")

        # 先校验信封时间窗，再进入神经验签路径；失败默认拒绝并审计。
        issued_at = datetime.fromisoformat(envelope.issued_at.replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(envelope.expires_at.replace("Z", "+00:00"))
        now = self._now_fn()
        if issued_at > expires_at:
            return ExecutionGateDecision(False, "invalid_envelope_window")
        if now < issued_at:
            return ExecutionGateDecision(False, "envelope_not_yet_valid")
        if now > expires_at:
            return ExecutionGateDecision(False, "envelope_expired")

        request_envelope_valid = True
        delegation_decision = self._evaluate_delegation_capability(envelope)
        if delegation_decision is not None:
            return delegation_decision

        execution_scope_allowed = action_scopes_allow(
            envelope.authorized_scopes,
            request.action_scope,
        )
        if not execution_scope_allowed:
            return ExecutionGateDecision(
                False,
                "execution_scope_not_authorized",
                request_envelope_valid=request_envelope_valid,
                pq_signature_valid=False,
                can_accept=False,
                execution_scope_allowed=False,
                request_envelope=envelope,
                pq_signature=signature,
                sender_public_key=public_key,
            )

        # CAN 只接收公开密钥、信封摘要和签名字节的 0/1 比特，不接触私钥。
        verified = self.can_gate.can_accept(
            bytes_to_bits(public_key),
            bytes_to_bits(envelope.digest()),
            bytes_to_bits(signature),
        )
        if verified != 1:
            return ExecutionGateDecision(
                False,
                "signature_verification_failed",
                request_envelope_valid=request_envelope_valid,
                pq_signature_valid=False,
                can_accept=False,
                execution_scope_allowed=execution_scope_allowed,
                request_envelope=envelope,
                pq_signature=signature,
                sender_public_key=public_key,
            )
        return ExecutionGateDecision(
            True,
            "authorized",
            request_envelope_valid=request_envelope_valid,
            pq_signature_valid=True,
            can_accept=True,
            execution_scope_allowed=execution_scope_allowed,
            request_envelope=envelope,
            pq_signature=signature,
            sender_public_key=public_key,
        )

    def _evaluate_delegation_capability(
        self,
        envelope: RequestEnvelope,
    ) -> ExecutionGateDecision | None:
        """校验委托子 capability 的父摘要绑定与 scope attenuation 关系。"""
        is_delegated = envelope.delegation_depth > 0 or bool(envelope.parent_envelope_digest)
        if not is_delegated:
            return None
        if not envelope.parent_envelope_digest:
            return ExecutionGateDecision(
                False,
                "missing_parent_envelope_digest",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        parent_scopes = self.parent_capability_store.get(envelope.parent_envelope_digest)
        if parent_scopes is None:
            return ExecutionGateDecision(
                False,
                "unknown_parent_envelope_digest",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if not envelope.parent_authorized_scopes:
            return ExecutionGateDecision(
                False,
                "missing_parent_authorized_scopes",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if tuple(envelope.parent_authorized_scopes) != tuple(parent_scopes):
            return ExecutionGateDecision(
                False,
                "parent_authorized_scopes_mismatch",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if envelope.delegation_depth <= 0:
            return ExecutionGateDecision(
                False,
                "invalid_delegation_depth",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if envelope.delegation_depth > envelope.max_delegation_depth:
            return ExecutionGateDecision(
                False,
                "delegation_depth_exceeded",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if not action_scopes_are_attenuated(
            parent_scopes,
            envelope.authorized_scopes,
        ):
            return ExecutionGateDecision(
                False,
                "delegation_scope_escalation",
                request_envelope_valid=True,
                execution_scope_allowed=False,
                request_envelope=envelope,
            )
        return None

    def consume_request(
        self,
        request: ExecutionGateRequest,
    ) -> ExecutionGateDecision:
        """验证并消费一次签名信封，重复 envelope 会被 replay 拒绝。"""
        decision = self.evaluate_request(request)
        if not decision.allowed:
            return decision

        assert decision.request_envelope is not None
        request_id = self._request_replay_id(decision.request_envelope)
        # 同一 gate 实例内的内存集合也要在锁内检查/写入，避免并发消费双放行。
        with self._replay_lock:
            if request_id in self._seen_request_ids:
                return replace(decision, allowed=False, reason="replayed_request_envelope")

            if self._replay_state_store is not None:
                try:
                    reservation = self._replay_state_store.reserve_request(
                        request_id,
                        decision.request_envelope,
                    )
                except OSError:
                    return replace(decision, allowed=False, reason="replay_state_persistence_failed")
                if reservation == "replayed":
                    self._seen_request_ids.add(request_id)
                    return replace(decision, allowed=False, reason="replayed_request_envelope")

            self._seen_request_ids.add(request_id)
            return decision

    def build_local_execution_context_from_decision(
        self,
        request: ExecutionGateRequest,
        decision: ExecutionGateDecision,
    ) -> LocalExecutionContext | None:
        """从已验证的 gate decision 构造本地执行上下文，不重复消费 replay 状态。"""
        if not decision.allowed:
            return None

        assert decision.request_envelope is not None
        assert decision.pq_signature is not None
        return LocalExecutionContext(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            request_envelope=decision.request_envelope,
            pq_signature=decision.pq_signature,
        )

    def build_local_execution_context(
        self,
        request: ExecutionGateRequest,
    ) -> LocalExecutionContext | None:
        """Build a validated execution context for downstream local actions."""
        decision = self.evaluate_request(request)
        if not decision.allowed:
            return None

        return self.build_local_execution_context_from_decision(request, decision)

    def _coerce_signature_bytes(self, signature: str | bytes) -> bytes:
        """Decode a transported detached signature into raw bytes."""
        if isinstance(signature, bytes):
            return signature
        if isinstance(signature, str):
            return base64.b64decode(signature, validate=True)
        raise TypeError("pq_signature must be bytes or base64 text")

    def _load_persisted_request_ids(self) -> None:
        """从 replay 状态目录恢复已消费信封标识。"""
        if self._replay_state_store is None:
            return
        self._seen_request_ids.update(self._replay_state_store.load_consumed_request_ids())

    def _request_replay_id(self, envelope: RequestEnvelope) -> str:
        """返回用于 replay 防护的稳定信封标识。"""
        return envelope.hex_digest()


def build_toy_lwe_execution_gate(
    scheme: ToyLWESignatureScheme,
    trusted_public_keys: Mapping[str, bytes],
    *,
    verifier_flavor: Literal["compiled", "wrapper"] = "compiled",
    message_bytes: int = 32,
    now_fn: Callable[[], datetime] | None = None,
    replay_state_dir: str | Path | None = None,
    replay_state_store: ReplayStateStore | None = None,
    parent_capability_store: Mapping[str, Iterable[str]] | None = None,
) -> SignedRequestExecutionGate:
    """Build a signed execution gate for the research-only toy LWE scheme.

    This helper centralizes the current prototype wiring so real agent/runtime
    entry points do not need to manually assemble ``CAN`` plus verifier objects.
    replay_state_dir 或 replay_state_store 提供时，会把已消费信封持久化到共享 replay 后端。
    """
    # toy/PQ-CAN 依赖只在启用 research runtime auth 时加载，保持 SAGA 核心导入路径轻量。
    from neural import CAN, CompiledToyLWEVerifier

    public_key_bytes = _validate_trusted_public_keys(trusted_public_keys)
    if verifier_flavor == "compiled":
        verifier = CompiledToyLWEVerifier(scheme, message_bytes=message_bytes)
    elif verifier_flavor == "wrapper":
        verifier = _build_toy_lwe_wrapper_verifier(
            scheme,
            public_key_bytes=public_key_bytes,
            message_bytes=message_bytes,
        )
    else:
        raise ValueError(f"unsupported verifier_flavor: {verifier_flavor}")

    return SignedRequestExecutionGate(
        CAN(verifier),
        trusted_public_keys,
        now_fn=now_fn,
        replay_state_dir=replay_state_dir,
        replay_state_store=replay_state_store,
        parent_capability_store=parent_capability_store,
    )


def _validate_trusted_public_keys(trusted_public_keys: Mapping[str, bytes]) -> int:
    """Validate trusted key material and return the shared public-key length."""
    if not trusted_public_keys:
        raise ValueError("trusted_public_keys must be non-empty")

    key_lengths = {len(public_key) for public_key in trusted_public_keys.values()}
    if 0 in key_lengths:
        raise ValueError("trusted public keys must be non-empty bytes")
    if len(key_lengths) != 1:
        raise ValueError("trusted_public_keys must use a uniform public-key length")
    return next(iter(key_lengths))


def _build_toy_lwe_wrapper_verifier(
    scheme: ToyLWESignatureScheme,
    *,
    public_key_bytes: int,
    message_bytes: int,
) -> SignatureVerifierWrapper:
    """Build the non-compiled verifier wrapper for the toy LWE scheme."""
    from neural import BitLayout, SignatureVerifierWrapper

    sample_key_pair = scheme.keygen()
    sample_signature = scheme.sign(sample_key_pair.secret_key, b"\x00" * message_bytes)
    layout = BitLayout(
        public_key_bytes=public_key_bytes,
        message_bytes=message_bytes,
        signature_bytes=len(sample_signature),
    )
    return SignatureVerifierWrapper(scheme, layout)
