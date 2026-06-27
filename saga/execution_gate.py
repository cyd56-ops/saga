"""Execution-layer authorization interfaces for SAGA-PQ-CAN."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Literal, ParamSpec, Protocol, TypeVar

from saga.messages import (
    EXECUTION_BUDGET_TOTAL_KEY,
    RequestEnvelope,
    action_scopes_are_attenuated,
    action_scopes_allow,
    action_scope_allows,
    normalize_execution_budget,
    normalize_scope_constraints,
    parse_action_scope,
    parse_request_envelope,
    scope_constraints_are_attenuated,
    scope_constraints_allow,
    sha256_hex,
)


P = ParamSpec("P")
T = TypeVar("T")
ActionScopeSpec = str | tuple[str, ...] | Callable[..., str | tuple[str, ...]]
AUDIT_CHAIN_GENESIS_HASH = "0" * 64


class EnforcementMode(str, Enum):
    """执行层 gate 的强制模式；非 strict 模式只用于兼容或离线测试。"""

    STRICT = "strict"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


def normalize_enforcement_mode(mode: EnforcementMode | str) -> EnforcementMode:
    """把配置或调用方传入的 mode 规范化为 ``EnforcementMode``。"""
    if isinstance(mode, EnforcementMode):
        return mode
    try:
        return EnforcementMode(str(mode).lower())
    except ValueError as exc:
        raise ValueError("enforcement_mode must be strict, permissive, or disabled") from exc


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
    parameters: Mapping[str, Any] | None = None


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
    enforcement_mode: str | None = None
    """Runtime enforcement mode used when the decision reached the Agent boundary."""
    downgrade_reason: str | None = None
    """Operator-supplied reason for non-strict compatibility or offline mode."""
    would_reject: bool = False
    """Whether non-strict enforcement allowed a request that strict mode would reject."""
    would_reject_reason: str | None = None
    """Strict-mode reject reason preserved when permissive mode continues execution."""

    def with_formula_values(
        self,
        *,
        protocol_allow: bool | None = None,
        request_envelope_valid: bool | None = None,
        pq_signature_valid: bool | None = None,
        can_accept: bool | None = None,
        execution_scope_allowed: bool | None = None,
        internal_policy_accept: bool | None = None,
        enforcement_mode: str | None = None,
        downgrade_reason: str | None = None,
        would_reject: bool | None = None,
        would_reject_reason: str | None = None,
    ) -> "ExecutionGateDecision":
        """返回带有更新公式项的新 decision，避免原地修改审计状态。"""
        updates: dict[str, bool | str | None] = {}
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
        if enforcement_mode is not None:
            updates["enforcement_mode"] = enforcement_mode
        if downgrade_reason is not None:
            updates["downgrade_reason"] = downgrade_reason
        if would_reject is not None:
            updates["would_reject"] = would_reject
        if would_reject_reason is not None:
            updates["would_reject_reason"] = would_reject_reason
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


@dataclass(frozen=True)
class ExecutionGateAuditChainValidation:
    """execution-gate 本地审计 hash chain 的校验结果。"""

    valid: bool
    reason: str
    checked_records: int
    last_seq: int | None
    tail_hash: str | None
    failure_line: int | None = None
    legacy_prefix_records: int = 0


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
        "enforcement_mode": decision.enforcement_mode,
        "downgrade_reason": decision.downgrade_reason,
        "would_reject": decision.would_reject,
        "would_reject_reason": decision.would_reject_reason,
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
        record["signed_scope_constraints"] = {
            scope: list(constraints)
            for scope, constraints in envelope.scope_constraints.items()
        }
        record["signed_capability_id"] = envelope.capability_id
        record["signed_parent_envelope_digest"] = envelope.parent_envelope_digest
        record["signed_parent_authorized_scopes"] = list(envelope.parent_authorized_scopes)
        record["signed_parent_scope_constraints"] = {
            scope: list(constraints)
            for scope, constraints in envelope.parent_scope_constraints.items()
        }
        record["signed_delegation_depth"] = envelope.delegation_depth
        record["signed_max_delegation_depth"] = envelope.max_delegation_depth
    return record


def append_execution_gate_audit_record(
    workdir: str | Path | None,
    record: Mapping[str, object],
) -> Path | None:
    """向本地 JSONL 审计日志追加 hash-chained execution-gate 记录。"""
    if workdir is None:
        return None

    audit_dir = Path(workdir) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "execution_gate.jsonl"
    chain_state = validate_execution_gate_audit_chain(audit_path)
    if not chain_state.valid:
        raise RuntimeError(
            f"execution gate audit chain is invalid: {chain_state.reason}"
        )
    payload = dict(record)
    payload["recorded_at"] = datetime.now(tz=timezone.utc).isoformat()
    payload["seq"] = 0 if chain_state.last_seq is None else chain_state.last_seq + 1
    payload["prev_hash"] = chain_state.tail_hash or AUDIT_CHAIN_GENESIS_HASH
    payload["entry_hash"] = _execution_gate_audit_entry_hash(payload)
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_execution_gate_audit_json(payload) + "\n")
    return audit_path


def validate_execution_gate_audit_chain(
    audit_path: str | Path,
    *,
    expected_tail_hash: str | None = None,
) -> ExecutionGateAuditChainValidation:
    """校验本地 execution-gate 审计链；外部 tail hash 锚点可检测截断。"""
    path = Path(audit_path)
    if not path.exists():
        return ExecutionGateAuditChainValidation(
            valid=True,
            reason="empty",
            checked_records=0,
            last_seq=None,
            tail_hash=AUDIT_CHAIN_GENESIS_HASH,
        )

    expected_seq = 0
    prev_hash = AUDIT_CHAIN_GENESIS_HASH
    legacy_prefix_records = 0
    saw_chained_record = False
    checked_records = 0

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="blank_audit_line",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="invalid_json",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )
            if not isinstance(payload, dict):
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="audit_record_not_object",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )

            has_seq = "seq" in payload
            has_prev_hash = "prev_hash" in payload
            has_entry_hash = "entry_hash" in payload
            has_all_chain_fields = has_seq and has_prev_hash and has_entry_hash
            has_any_chain_field = has_seq or has_prev_hash or has_entry_hash
            if not has_all_chain_fields:
                if has_any_chain_field:
                    return ExecutionGateAuditChainValidation(
                        valid=False,
                        reason="incomplete_chain_fields",
                        checked_records=checked_records,
                        last_seq=expected_seq - 1 if expected_seq else None,
                        tail_hash=prev_hash,
                        failure_line=line_number,
                        legacy_prefix_records=legacy_prefix_records,
                    )
                if saw_chained_record:
                    return ExecutionGateAuditChainValidation(
                        valid=False,
                        reason="legacy_record_after_chained_record",
                        checked_records=checked_records,
                        last_seq=expected_seq - 1 if expected_seq else None,
                        tail_hash=prev_hash,
                        failure_line=line_number,
                        legacy_prefix_records=legacy_prefix_records,
                    )
                # 旧 JSONL 前缀没有链字段；新链会把该前缀的合成 tail hash 作为锚点。
                synthetic_payload = dict(payload)
                synthetic_payload["seq"] = expected_seq
                synthetic_payload["prev_hash"] = prev_hash
                prev_hash = _execution_gate_audit_entry_hash(synthetic_payload)
                legacy_prefix_records += 1
                expected_seq += 1
                checked_records += 1
                continue

            saw_chained_record = True
            if not isinstance(payload["seq"], int) or payload["seq"] != expected_seq:
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="seq_mismatch",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )
            if payload["prev_hash"] != prev_hash:
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="prev_hash_mismatch",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )
            expected_entry_hash = _execution_gate_audit_entry_hash(payload)
            if payload["entry_hash"] != expected_entry_hash:
                return ExecutionGateAuditChainValidation(
                    valid=False,
                    reason="entry_hash_mismatch",
                    checked_records=checked_records,
                    last_seq=expected_seq - 1 if expected_seq else None,
                    tail_hash=prev_hash,
                    failure_line=line_number,
                    legacy_prefix_records=legacy_prefix_records,
                )
            prev_hash = str(payload["entry_hash"])
            expected_seq += 1
            checked_records += 1

    if expected_tail_hash is not None and prev_hash != expected_tail_hash:
        return ExecutionGateAuditChainValidation(
            valid=False,
            reason="tail_hash_mismatch",
            checked_records=checked_records,
            last_seq=expected_seq - 1 if expected_seq else None,
            tail_hash=prev_hash,
            legacy_prefix_records=legacy_prefix_records,
        )

    if checked_records == 0:
        reason = "empty"
    elif legacy_prefix_records == checked_records:
        reason = "legacy_jsonl_without_chain"
    elif legacy_prefix_records:
        reason = "ok_with_legacy_prefix"
    else:
        reason = "ok"
    return ExecutionGateAuditChainValidation(
        valid=True,
        reason=reason,
        checked_records=checked_records,
        last_seq=expected_seq - 1 if expected_seq else None,
        tail_hash=prev_hash,
        legacy_prefix_records=legacy_prefix_records,
    )


def _canonical_execution_gate_audit_json(payload: Mapping[str, object]) -> str:
    """按稳定 JSON 形式序列化审计记录，避免字段顺序影响 hash。"""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _execution_gate_audit_entry_hash(payload: Mapping[str, object]) -> str:
    """计算单条审计记录的 hash；entry_hash 自身不参与被哈希内容。"""
    hash_payload = dict(payload)
    hash_payload.pop("entry_hash", None)
    return sha256_hex(
        _canonical_execution_gate_audit_json(hash_payload).encode("utf-8")
    )


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


class CapabilityStateStore(Protocol):
    """原子消费 signed capability 执行预算的状态后端。"""

    def consume_budget(
        self,
        envelope: RequestEnvelope,
        action_scope: str,
    ) -> Literal["consumed", "exhausted"]:
        """为指定执行面原子扣减预算；预算耗尽时返回 exhausted。"""


class SQLiteCapabilityStateStore:
    """使用 SQLite 事务实现 capability budget 的本地 SQL-style 状态后端。"""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 5.0) -> None:
        """初始化 SQLite budget store，并创建预算消费表。"""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.database_path = Path(database_path)
        if self.database_path.parent != Path("."):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._ensure_schema()

    def consume_budget(
        self,
        envelope: RequestEnvelope,
        action_scope: str,
    ) -> Literal["consumed", "exhausted"]:
        """在单个 SQLite 事务中扣减 total 与匹配执行面预算。"""
        budget = normalize_execution_budget(envelope.execution_budget)
        budget_scopes = _budget_scopes_for_action(budget, action_scope)
        if not budget_scopes:
            return "consumed"
        rows = [
            (
                envelope.capability_id,
                envelope.hex_digest(),
                budget_scope,
                budget[budget_scope],
            )
            for budget_scope in budget_scopes
        ]
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for capability_id, envelope_digest, budget_scope, limit in rows:
                    row = connection.execute(
                        """
                        SELECT budget_limit, consumed_count
                        FROM saga_capability_budgets
                        WHERE capability_id = ?
                          AND envelope_digest = ?
                          AND budget_scope = ?
                        """,
                        (capability_id, envelope_digest, budget_scope),
                    ).fetchone()
                    if row is None:
                        connection.execute(
                            """
                            INSERT INTO saga_capability_budgets (
                                capability_id,
                                envelope_digest,
                                budget_scope,
                                budget_limit,
                                consumed_count,
                                updated_at
                            )
                            VALUES (?, ?, ?, ?, 0, ?)
                            """,
                            (
                                capability_id,
                                envelope_digest,
                                budget_scope,
                                limit,
                                datetime.now(tz=timezone.utc).isoformat(),
                            ),
                        )
                        consumed_count = 0
                    else:
                        stored_limit, consumed_count = row
                        if stored_limit != limit:
                            connection.rollback()
                            raise OSError("sqlite capability budget limit mismatch")
                    if consumed_count >= limit:
                        connection.rollback()
                        return "exhausted"

                for capability_id, envelope_digest, budget_scope, _limit in rows:
                    connection.execute(
                        """
                        UPDATE saga_capability_budgets
                        SET consumed_count = consumed_count + 1,
                            updated_at = ?
                        WHERE capability_id = ?
                          AND envelope_digest = ?
                          AND budget_scope = ?
                        """,
                        (
                            datetime.now(tz=timezone.utc).isoformat(),
                            capability_id,
                            envelope_digest,
                            budget_scope,
                        ),
                    )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("sqlite capability state database is unavailable") from exc
        return "consumed"

    def _connect(self) -> sqlite3.Connection:
        """打开短生命周期连接，避免跨线程共享 SQLite connection 状态。"""
        connection = sqlite3.connect(self.database_path, timeout=self.timeout_seconds)
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return connection

    def _ensure_schema(self) -> None:
        """创建 capability budget 表；复合主键绑定信封与预算 scope。"""
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS saga_capability_budgets (
                            capability_id TEXT NOT NULL,
                            envelope_digest TEXT NOT NULL,
                            budget_scope TEXT NOT NULL,
                            budget_limit INTEGER NOT NULL,
                            consumed_count INTEGER NOT NULL,
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY (
                                capability_id,
                                envelope_digest,
                                budget_scope
                            )
                        )
                        """
                    )
        except sqlite3.Error as exc:
            raise RuntimeError("sqlite capability state database is unavailable") from exc


RevocationStatus = Literal[
    "active",
    "capability_revoked",
    "parent_capability_revoked",
]


class RevocationStore(Protocol):
    """查询 signed capability 是否已被本地撤销的状态后端。"""

    def revocation_status(self, envelope: RequestEnvelope) -> RevocationStatus:
        """返回 capability 撤销状态；后端故障应抛出 ``OSError``。"""


class InMemoryRevocationStore:
    """进程内撤销事实源，适用于测试或显式注入的小型本地运行。"""

    def __init__(
        self,
        *,
        capability_ids: Iterable[str] | None = None,
        parent_envelope_digests: Iterable[str] | None = None,
    ) -> None:
        """初始化 capability id 与 parent digest 两类撤销集合。"""
        self._capability_ids = set(capability_ids or ())
        self._parent_envelope_digests = {
            digest.lower() for digest in (parent_envelope_digests or ())
        }

    def revoke_capability_id(self, capability_id: str) -> None:
        """按 capability id 撤销已签名 capability。"""
        if not capability_id:
            raise ValueError("capability_id must be non-empty")
        self._capability_ids.add(capability_id)

    def revoke_parent_envelope_digest(self, parent_envelope_digest: str) -> None:
        """按父 envelope digest 撤销所有声明该父 capability 的子 capability。"""
        if not parent_envelope_digest:
            raise ValueError("parent_envelope_digest must be non-empty")
        self._parent_envelope_digests.add(parent_envelope_digest.lower())

    def revocation_status(self, envelope: RequestEnvelope) -> RevocationStatus:
        """检查 capability 自身或其父 capability 是否已被撤销。"""
        if envelope.capability_id in self._capability_ids:
            return "capability_revoked"
        if (
            envelope.parent_envelope_digest
            and envelope.parent_envelope_digest.lower() in self._parent_envelope_digests
        ):
            return "parent_capability_revoked"
        return "active"


class SQLiteRevocationStore:
    """使用 SQLite 保存 capability revocation 状态的本地 SQL-style 后端。"""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 5.0) -> None:
        """初始化 SQLite revocation store，并创建撤销表。"""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.database_path = Path(database_path)
        if self.database_path.parent != Path("."):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._ensure_schema()

    def revoke_capability_id(self, capability_id: str, *, reason: str = "") -> None:
        """按 capability id 写入撤销记录。"""
        if not capability_id:
            raise ValueError("capability_id must be non-empty")
        self._insert_revocation("capability_id", capability_id, reason)

    def revoke_parent_envelope_digest(
        self,
        parent_envelope_digest: str,
        *,
        reason: str = "",
    ) -> None:
        """按 parent envelope digest 写入级联撤销记录。"""
        if not parent_envelope_digest:
            raise ValueError("parent_envelope_digest must be non-empty")
        self._insert_revocation(
            "parent_envelope_digest",
            parent_envelope_digest.lower(),
            reason,
        )

    def revocation_status(self, envelope: RequestEnvelope) -> RevocationStatus:
        """查询 capability 自身或其父 capability 是否已被撤销。"""
        try:
            with closing(self._connect()) as connection:
                if self._revocation_exists(
                    connection,
                    "capability_id",
                    envelope.capability_id,
                ):
                    return "capability_revoked"
                if envelope.parent_envelope_digest and self._revocation_exists(
                    connection,
                    "parent_envelope_digest",
                    envelope.parent_envelope_digest.lower(),
                ):
                    return "parent_capability_revoked"
        except sqlite3.Error as exc:
            raise OSError("sqlite revocation database is unavailable") from exc
        return "active"

    def _insert_revocation(self, revocation_type: str, value: str, reason: str) -> None:
        """以幂等 upsert 方式保存撤销事实。"""
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO saga_capability_revocations (
                            revocation_type,
                            revocation_value,
                            recorded_at,
                            reason
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            revocation_type,
                            value,
                            datetime.now(tz=timezone.utc).isoformat(),
                            reason,
                        ),
                    )
        except sqlite3.Error as exc:
            raise OSError("sqlite revocation database is unavailable") from exc

    def _revocation_exists(
        self,
        connection: sqlite3.Connection,
        revocation_type: str,
        value: str,
    ) -> bool:
        """查询指定撤销事实是否存在。"""
        row = connection.execute(
            """
            SELECT 1
            FROM saga_capability_revocations
            WHERE revocation_type = ?
              AND revocation_value = ?
            LIMIT 1
            """,
            (revocation_type, value),
        ).fetchone()
        return row is not None

    def _connect(self) -> sqlite3.Connection:
        """打开短生命周期连接，避免跨线程共享 SQLite connection 状态。"""
        connection = sqlite3.connect(self.database_path, timeout=self.timeout_seconds)
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return connection

    def _ensure_schema(self) -> None:
        """创建撤销表；复合主键保证撤销事实幂等。"""
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS saga_capability_revocations (
                            revocation_type TEXT NOT NULL,
                            revocation_value TEXT NOT NULL,
                            recorded_at TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            PRIMARY KEY (
                                revocation_type,
                                revocation_value
                            )
                        )
                        """
                    )
        except sqlite3.Error as exc:
            raise RuntimeError("sqlite revocation database is unavailable") from exc


@dataclass(frozen=True)
class LocalExecutionContext:
    """Execution context propagated into local prompt/tool execution."""

    sender_aid: str
    receiver_aid: str
    request_envelope: RequestEnvelope
    pq_signature: bytes
    capability_state_store: CapabilityStateStore | None = None

    def authorize_action(
        self,
        action_scope: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> bool:
        """Return ``True`` only when signed scopes authorize ``action_scope``.

        下游执行权限来自信封中的显式授权列表，而不是入口 ``action_scope`` 的隐式扩展。
        """
        return action_scopes_allow(
            self.request_envelope.authorized_scopes,
            action_scope,
        ) and scope_constraints_allow(
            self.request_envelope.authorized_scopes,
            self.request_envelope.scope_constraints,
            action_scope,
            parameters,
        )

    def require_action(
        self,
        action_scope: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> None:
        """Raise ``PermissionError`` unless ``action_scope`` is authorized and funded."""
        if not self.authorize_action(action_scope, parameters):
            raise ExecutionAuthorizationError(
                reason_for_unauthorized_scope(action_scope),
                action_scope,
            )
        self._consume_budget(action_scope)

    def _consume_budget(self, action_scope: str) -> None:
        """按 signed execution budget 原子扣减本次受保护动作。"""
        if not self.request_envelope.execution_budget:
            return
        if self.capability_state_store is None:
            raise ExecutionAuthorizationError(
                "capability_budget_store_missing",
                action_scope,
            )
        try:
            result = self.capability_state_store.consume_budget(
                self.request_envelope,
                action_scope,
            )
        except OSError as exc:
            raise ExecutionAuthorizationError(
                "capability_budget_store_unavailable",
                action_scope,
            ) from exc
        if result == "exhausted":
            raise ExecutionAuthorizationError(
                "capability_budget_exhausted",
                action_scope,
            )

    def authorize_tool_call(
        self,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> bool:
        """Return ``True`` only when the named tool call is authorized."""
        return self.authorize_action(f"tool_call:{tool_name}", parameters)

    def require_tool_call(
        self,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> None:
        """Raise ``PermissionError`` unless the named tool call is authorized."""
        self.require_action(f"tool_call:{tool_name}", parameters)

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

    def require_action(
        self,
        action_scope: str,
        constraint_parameters: Mapping[str, Any] | None = None,
    ) -> None:
        """要求当前 capability 覆盖指定执行面，否则抛出稳定授权错误。"""
        context = self._current_context(action_scope)
        if context is None:
            return
        context.require_action(action_scope, constraint_parameters)

    def require_any_action(
        self,
        action_scopes: str | tuple[str, ...],
        constraint_parameters: Mapping[str, Any] | None = None,
    ) -> None:
        """要求当前 capability 至少覆盖一个候选执行面 scope。"""
        scopes = self._normalize_action_scopes(action_scopes)
        context = self._current_context(scopes[0])
        if context is None:
            return
        if not any(
            context.authorize_action(action_scope, constraint_parameters)
            for action_scope in scopes
        ):
            raise ExecutionAuthorizationError(
                reason_for_unauthorized_scope(scopes[0]),
                scopes[0],
            )

    def call_action(
        self,
        action_scope: str,
        operation: Callable[P, T],
        *args: P.args,
        constraint_parameters: Mapping[str, Any] | None = None,
        **kwargs: P.kwargs,
    ) -> T:
        """在调用底层操作前检查指定执行面 capability。"""
        self.require_action(action_scope, constraint_parameters)
        return operation(*args, **kwargs)

    def call_any_action(
        self,
        action_scopes: str | tuple[str, ...],
        operation: Callable[P, T],
        *args: P.args,
        constraint_parameters: Mapping[str, Any] | None = None,
        **kwargs: P.kwargs,
    ) -> T:
        """在调用底层操作前检查候选 capability 集合中的任一授权。"""
        self.require_any_action(action_scopes, constraint_parameters)
        return operation(*args, **kwargs)

    def call_tool(
        self,
        tool_name: str,
        operation: Callable[P, T],
        *args: P.args,
        constraint_parameters: Mapping[str, Any] | None = None,
        **kwargs: P.kwargs,
    ) -> T:
        """以 ``tool_call:<name>`` scope 保护一个底层工具调用。"""
        return self.call_action(
            f"tool_call:{tool_name}",
            operation,
            *args,
            constraint_parameters=constraint_parameters,
            **kwargs,
        )

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
            # 参数级约束只读取 JSON 标量参数，不执行任意 callback 逻辑。
            constraint_parameters = dict(kwargs)
            return self._capabilities.call_any_action(
                resolved_scopes,
                attribute,
                *args,
                constraint_parameters=constraint_parameters,
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


def _budget_scopes_for_action(
    execution_budget: Mapping[str, int],
    action_scope: str,
) -> tuple[str, ...]:
    """返回本次动作需要同时扣减的 total 与匹配 scope 预算。"""
    parse_action_scope(action_scope)
    budget_scopes: list[str] = []
    if EXECUTION_BUDGET_TOTAL_KEY in execution_budget:
        budget_scopes.append(EXECUTION_BUDGET_TOTAL_KEY)
    for budget_scope in execution_budget:
        if budget_scope == EXECUTION_BUDGET_TOTAL_KEY:
            continue
        if action_scope_allows(budget_scope, action_scope):
            budget_scopes.append(budget_scope)
    return tuple(budget_scopes)


@dataclass(frozen=True)
class ParentCapabilityFacts:
    """本地已接受父 capability 的事实源，用于校验委托子 capability 收窄关系。"""

    authorized_scopes: tuple[str, ...]
    scope_constraints: dict[str, tuple[dict[str, Any], ...]]


ParentCapabilityStoreValue = (
    ParentCapabilityFacts
    | RequestEnvelope
    | Mapping[str, Any]
    | Iterable[str]
)


def _normalize_parent_capability_store(
    parent_capability_store: Mapping[str, ParentCapabilityStoreValue] | None,
) -> dict[str, ParentCapabilityFacts]:
    """规范化本地父 capability 事实源，兼容旧的 digest -> scopes 映射。"""
    normalized: dict[str, ParentCapabilityFacts] = {}
    for digest, facts in (parent_capability_store or {}).items():
        normalized[digest.lower()] = _normalize_parent_capability_facts(facts)
    return normalized


def _normalize_parent_capability_facts(
    facts: ParentCapabilityStoreValue,
) -> ParentCapabilityFacts:
    """把 RequestEnvelope、结构化映射或旧 scope 列表收敛成父 capability facts。"""
    if isinstance(facts, ParentCapabilityFacts):
        return _build_parent_capability_facts(
            facts.authorized_scopes,
            facts.scope_constraints,
        )
    if isinstance(facts, RequestEnvelope):
        return _build_parent_capability_facts(
            facts.authorized_scopes,
            facts.scope_constraints,
        )
    if isinstance(facts, Mapping):
        if "authorized_scopes" not in facts:
            raise ValueError("parent capability facts require authorized_scopes")
        return _build_parent_capability_facts(
            facts["authorized_scopes"],
            facts.get("scope_constraints"),
        )
    return _build_parent_capability_facts(facts, None)


def _build_parent_capability_facts(
    authorized_scopes: Iterable[str],
    scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None,
) -> ParentCapabilityFacts:
    """构造规范化父 capability facts，并拒绝未被父 scope 覆盖的约束。"""
    normalized_scopes = _normalize_scope_list(authorized_scopes)
    normalized_constraints = normalize_scope_constraints(scope_constraints)
    for constrained_scope in normalized_constraints:
        if not action_scopes_allow(normalized_scopes, constrained_scope):
            raise ValueError("parent scope_constraints keys must be covered by authorized_scopes")
    return ParentCapabilityFacts(
        authorized_scopes=normalized_scopes,
        scope_constraints=normalized_constraints,
    )


def _normalize_scope_list(scopes: Iterable[str]) -> tuple[str, ...]:
    """规范化父 capability scope 列表，避免事实源中出现未知执行面。"""
    if isinstance(scopes, str):
        raise TypeError("authorized_scopes must be an iterable of action-scope strings")
    normalized: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, str):
            raise TypeError("authorized_scopes entries must be strings")
        parse_action_scope(scope)
        normalized.add(scope)
    return tuple(sorted(normalized))


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
        capability_state_store: CapabilityStateStore | None = None,
        revocation_store: RevocationStore | None = None,
        parent_capability_store: Mapping[str, ParentCapabilityStoreValue] | None = None,
    ) -> None:
        """Store a CAN gate, trusted public keys, and optional shared replay state."""
        if replay_state_dir is not None and replay_state_store is not None:
            raise ValueError("configure either replay_state_dir or replay_state_store, not both")
        self.can_gate = can_gate
        self.trusted_public_keys = dict(trusted_public_keys)
        self.capability_state_store = capability_state_store
        self.revocation_store = revocation_store
        self.parent_capability_store = _normalize_parent_capability_store(parent_capability_store)
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
        ) and scope_constraints_allow(
            envelope.authorized_scopes,
            envelope.scope_constraints,
            request.action_scope,
            request.parameters,
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
        if self.revocation_store is not None:
            try:
                revocation_status = self.revocation_store.revocation_status(envelope)
            except OSError:
                return ExecutionGateDecision(
                    False,
                    "revocation_store_unavailable",
                    request_envelope_valid=request_envelope_valid,
                    pq_signature_valid=True,
                    can_accept=True,
                    execution_scope_allowed=execution_scope_allowed,
                    request_envelope=envelope,
                    pq_signature=signature,
                    sender_public_key=public_key,
                )
            if revocation_status != "active":
                return ExecutionGateDecision(
                    False,
                    revocation_status,
                    request_envelope_valid=request_envelope_valid,
                    pq_signature_valid=True,
                    can_accept=True,
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
        parent_facts = self.parent_capability_store.get(envelope.parent_envelope_digest)
        if parent_facts is None:
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
        parent_scopes = parent_facts.authorized_scopes
        if tuple(envelope.parent_authorized_scopes) != tuple(parent_scopes):
            return ExecutionGateDecision(
                False,
                "parent_authorized_scopes_mismatch",
                request_envelope_valid=True,
                request_envelope=envelope,
            )
        if envelope.parent_scope_constraints != parent_facts.scope_constraints:
            return ExecutionGateDecision(
                False,
                "parent_scope_constraints_mismatch",
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
        if not scope_constraints_are_attenuated(
            parent_scopes,
            parent_facts.scope_constraints,
            envelope.authorized_scopes,
            envelope.scope_constraints,
        ):
            return ExecutionGateDecision(
                False,
                "delegation_constraint_escalation",
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

        if decision.request_envelope is None:
            return replace(decision, allowed=False, reason="missing_request_envelope")
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

        if decision.request_envelope is None or decision.pq_signature is None:
            return None
        return LocalExecutionContext(
            sender_aid=request.sender_aid,
            receiver_aid=request.receiver_aid,
            request_envelope=decision.request_envelope,
            pq_signature=decision.pq_signature,
            capability_state_store=self.capability_state_store,
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
    revocation_store: RevocationStore | None = None,
    parent_capability_store: Mapping[str, ParentCapabilityStoreValue] | None = None,
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
        revocation_store=revocation_store,
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
