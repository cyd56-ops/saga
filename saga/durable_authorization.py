"""为 RuntimeAuthCoordinator 提供事务化授权状态与 audit outbox。"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Literal, Protocol

from saga.messages import (
    RequestEnvelope,
    execution_budget_scopes_for_action,
    normalize_execution_budget,
    sha256_hex,
)


DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1 = 1
AuthorizationState = Literal["PENDING", "COMMITTED", "CONSUMED", "REJECTED"]
RevocationStatus = Literal[
    "active",
    "capability_revoked",
    "parent_capability_revoked",
]
CapabilityConsumptionStatus = Literal[
    "consumed",
    "exhausted",
    "authorization_missing",
    "authorization_not_committed",
    "capability_revoked",
    "parent_capability_revoked",
]
DurableAuthorizationPrepareStatus = Literal[
    "prepared",
    "pending",
    "replayed",
    "rejected",
    "conflict",
    "capability_revoked",
    "parent_capability_revoked",
]
DurableAuthorizationCommitStatus = Literal[
    "committed",
    "replayed",
    "rejected",
    "conflict",
    "capability_revoked",
    "parent_capability_revoked",
]


@dataclass(frozen=True)
class DurableAuthorizationCommitV1:
    """描述 Coordinator 准备持久化的公开授权提交事实。"""

    request_id: str
    request_fingerprint: str
    route_id: str
    decision_reason: str
    envelope: RequestEnvelope

    def __post_init__(self) -> None:
        """拒绝错误摘要、空身份或与信封不一致的 request id。"""
        _validate_sha256_hex(self.request_id, "request_id")
        _validate_sha256_hex(self.request_fingerprint, "request_fingerprint")
        if type(self.route_id) is not str or not self.route_id:
            raise ValueError("route_id must be non-empty text")
        if type(self.decision_reason) is not str or not self.decision_reason:
            raise ValueError("decision_reason must be non-empty text")
        if type(self.envelope) is not RequestEnvelope:
            raise TypeError("envelope must be RequestEnvelope")
        if self.request_id != self.envelope.hex_digest():
            raise ValueError("request_id must match the canonical envelope digest")

    def context_fingerprint(self) -> str:
        """生成待发布 Context 的公开、domain-separated 稳定身份摘要。"""
        payload = json.dumps(
            {
                "capability_id": self.envelope.capability_id,
                "decision_reason": self.decision_reason,
                "envelope_digest": self.envelope.hex_digest(),
                "request_fingerprint": self.request_fingerprint,
                "route_id": self.route_id,
                "sender_aid": self.envelope.sender_aid,
                "receiver_aid": self.envelope.receiver_aid,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256_hex(
            b"SAGA-PQ-CAN-DurableLocalExecutionContextV1\x00" + payload
        )


@dataclass(frozen=True)
class DurableAuthorizationRecordV1:
    """记录一个请求的 durable 状态、绑定摘要和稳定原因。"""

    request_id: str
    request_fingerprint: str
    context_fingerprint: str
    envelope_digest: str
    capability_id: str
    route_id: str
    state: AuthorizationState
    state_reason: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AuthorizationOutboxEventV1:
    """表示一个可按 event_id 幂等投递的授权审计 outbox 事件。"""

    sequence: int
    event_id: str
    request_id: str | None
    event_type: str
    payload_json: str
    created_at: str
    delivered_at: str | None

    def payload(self) -> dict[str, object]:
        """把已验证为对象的 canonical JSON payload 解码为新字典。"""
        decoded = json.loads(self.payload_json)
        if type(decoded) is not dict:
            raise ValueError("authorization outbox payload must be a JSON object")
        return decoded


class DurableAuthorizationStateStore(Protocol):
    """定义 Coordinator、revocation、budget 与 outbox 的统一 durable contract。"""

    def commit_authorization(
        self,
        commit: DurableAuthorizationCommitV1,
    ) -> DurableAuthorizationCommitStatus:
        """恢复或提交授权；只有 committed 可以生成新的 Context。"""

    def consume_budget(
        self,
        envelope: RequestEnvelope,
        action_scope: str,
    ) -> CapabilityConsumptionStatus:
        """原子检查授权/撤销、扣减预算并将首次使用标记为 CONSUMED。"""

    def revocation_status(self, envelope: RequestEnvelope) -> RevocationStatus:
        """返回 capability 自身或父 capability 的当前撤销状态。"""

    def pending_outbox_events(
        self,
        *,
        limit: int = 100,
    ) -> tuple[AuthorizationOutboxEventV1, ...]:
        """按稳定序号返回尚未确认投递的 outbox 事件。"""

    def mark_outbox_delivered(self, event_id: str) -> None:
        """幂等标记一个 outbox 事件已经由外部消费者处理。"""


class SQLiteDurableAuthorizationStateStore:
    """用 SQLite 事务统一授权状态、撤销、预算和 audit outbox。"""

    def __init__(
        self,
        database_path: str | Path,
        *,
        timeout_seconds: float = 5.0,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        """初始化数据库；短连接和 BEGIN IMMEDIATE 支持线程/进程竞争。"""
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if now_fn is not None and not callable(now_fn):
            raise TypeError("now_fn must be callable")
        self.database_path = Path(database_path)
        if self.database_path.parent != Path("."):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = float(timeout_seconds)
        self._now_fn = now_fn or (lambda: datetime.now(tz=timezone.utc))
        self._ensure_schema()

    def prepare_authorization(
        self,
        commit: DurableAuthorizationCommitV1,
    ) -> DurableAuthorizationPrepareStatus:
        """原子 reserve PENDING；同 fingerprint 的 PENDING 可由重启后恢复。"""
        if type(commit) is not DurableAuthorizationCommitV1:
            raise TypeError("commit must be DurableAuthorizationCommitV1")
        timestamp = self._timestamp()
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._authorization_identity(connection, commit.request_id)
                if existing is not None:
                    (
                        existing_fingerprint,
                        existing_context_fingerprint,
                        existing_state,
                    ) = existing
                    connection.rollback()
                    if (
                        existing_fingerprint != commit.request_fingerprint
                        or existing_context_fingerprint
                        != commit.context_fingerprint()
                    ):
                        return "conflict"
                    if existing_state == "PENDING":
                        return "pending"
                    if existing_state == "REJECTED":
                        return "rejected"
                    return "replayed"

                revocation = self._revocation_status(connection, commit.envelope)
                state: AuthorizationState = (
                    "PENDING" if revocation == "active" else "REJECTED"
                )
                state_reason = (
                    "authorization_pending"
                    if revocation == "active"
                    else revocation
                )
                self._insert_authorization(
                    connection,
                    commit,
                    state=state,
                    state_reason=state_reason,
                    timestamp=timestamp,
                )
                self._insert_authorization_outbox(
                    connection,
                    commit,
                    event_type=(
                        "authorization_pending"
                        if state == "PENDING"
                        else "authorization_rejected"
                    ),
                    state=state,
                    reason=state_reason,
                    timestamp=timestamp,
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        if revocation != "active":
            return revocation
        return "prepared"

    def commit_authorization(
        self,
        commit: DurableAuthorizationCommitV1,
    ) -> DurableAuthorizationCommitStatus:
        """恢复 PENDING 并将 COMMITTED 与 audit outbox 写入同一事务。"""
        preparation = self.prepare_authorization(commit)
        if preparation not in ("prepared", "pending"):
            return preparation
        timestamp = self._timestamp()
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._authorization_identity(connection, commit.request_id)
                if existing is None:
                    connection.rollback()
                    return "conflict"
                (
                    existing_fingerprint,
                    existing_context_fingerprint,
                    existing_state,
                ) = existing
                if (
                    existing_fingerprint != commit.request_fingerprint
                    or existing_context_fingerprint != commit.context_fingerprint()
                ):
                    connection.rollback()
                    return "conflict"
                if existing_state in ("COMMITTED", "CONSUMED"):
                    connection.rollback()
                    return "replayed"
                if existing_state == "REJECTED":
                    connection.rollback()
                    return "rejected"

                revocation = self._revocation_status(connection, commit.envelope)
                if revocation != "active":
                    self._transition_authorization(
                        connection,
                        commit.request_id,
                        state="REJECTED",
                        reason=revocation,
                        timestamp=timestamp,
                    )
                    self._insert_authorization_outbox(
                        connection,
                        commit,
                        event_type="authorization_rejected",
                        state="REJECTED",
                        reason=revocation,
                        timestamp=timestamp,
                    )
                    connection.commit()
                    return revocation

                self._transition_authorization(
                    connection,
                    commit.request_id,
                    state="COMMITTED",
                    reason=commit.decision_reason,
                    timestamp=timestamp,
                )
                self._insert_authorization_outbox(
                    connection,
                    commit,
                    event_type="authorization_committed",
                    state="COMMITTED",
                    reason=commit.decision_reason,
                    timestamp=timestamp,
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        return "committed"

    def reject_pending(
        self,
        request_id: str,
        request_fingerprint: str,
        *,
        reason: str,
    ) -> Literal["rejected", "missing", "conflict"]:
        """显式终止未完成 PENDING；已提交 authority 不允许回滚重标记。"""
        _validate_sha256_hex(request_id, "request_id")
        _validate_sha256_hex(request_fingerprint, "request_fingerprint")
        if type(reason) is not str or not reason:
            raise ValueError("reason must be non-empty text")
        timestamp = self._timestamp()
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT request_fingerprint, state, route_id, decision_reason
                    FROM saga_authorization_requests
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    return "missing"
                stored_fingerprint, state, route_id, decision_reason = row
                if stored_fingerprint != request_fingerprint or state in (
                    "COMMITTED",
                    "CONSUMED",
                ):
                    connection.rollback()
                    return "conflict"
                if state == "REJECTED":
                    connection.rollback()
                    return "rejected"
                self._transition_authorization(
                    connection,
                    request_id,
                    state="REJECTED",
                    reason=reason,
                    timestamp=timestamp,
                )
                self._insert_outbox(
                    connection,
                    event_id=_event_id("authorization_rejected", request_id),
                    request_id=request_id,
                    event_type="authorization_rejected",
                    payload={
                        "schema_version": DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1,
                        "event_type": "authorization_rejected",
                        "request_id": request_id,
                        "request_fingerprint": request_fingerprint,
                        "route_id": route_id,
                        "decision_reason": decision_reason,
                        "state": "REJECTED",
                        "reason": reason,
                    },
                    timestamp=timestamp,
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        return "rejected"

    def authorization_record(
        self,
        request_id: str,
    ) -> DurableAuthorizationRecordV1 | None:
        """读取单个请求的 durable 状态快照，不返回业务正文或签名材料。"""
        _validate_sha256_hex(request_id, "request_id")
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT request_id, request_fingerprint, context_fingerprint,
                           envelope_digest, capability_id, route_id, state, state_reason,
                           created_at, updated_at
                    FROM saga_authorization_requests
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        if row is None:
            return None
        return DurableAuthorizationRecordV1(*row)

    def load_consumed_request_ids(self) -> set[str]:
        """返回所有已 reserve 的状态，供兼容性 replay 诊断读取。"""
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT request_id FROM saga_authorization_requests"
                ).fetchall()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        return {str(row[0]) for row in rows}

    def consume_budget(
        self,
        envelope: RequestEnvelope,
        action_scope: str,
    ) -> CapabilityConsumptionStatus:
        """在同一事务检查状态/撤销、扣减预算并标记首次 Context 使用。"""
        if type(envelope) is not RequestEnvelope:
            raise TypeError("envelope must be RequestEnvelope")
        budget = normalize_execution_budget(envelope.execution_budget)
        budget_scopes = execution_budget_scopes_for_action(budget, action_scope)
        request_id = envelope.hex_digest()
        timestamp = self._timestamp()
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT request_fingerprint, capability_id, state, route_id,
                           decision_reason
                    FROM saga_authorization_requests
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    return "authorization_missing"
                request_fingerprint, capability_id, state, route_id, decision_reason = row
                if capability_id != envelope.capability_id or state not in (
                    "COMMITTED",
                    "CONSUMED",
                ):
                    connection.rollback()
                    return "authorization_not_committed"

                revocation = self._revocation_status(connection, envelope)
                if revocation != "active":
                    if state == "COMMITTED":
                        self._transition_authorization(
                            connection,
                            request_id,
                            state="REJECTED",
                            reason=revocation,
                            timestamp=timestamp,
                        )
                        self._insert_outbox(
                            connection,
                            event_id=_event_id("authorization_rejected", request_id),
                            request_id=request_id,
                            event_type="authorization_rejected",
                            payload={
                                "schema_version": DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1,
                                "event_type": "authorization_rejected",
                                "request_id": request_id,
                                "request_fingerprint": request_fingerprint,
                                "route_id": route_id,
                                "state": "REJECTED",
                                "reason": revocation,
                            },
                            timestamp=timestamp,
                        )
                        connection.commit()
                    else:
                        connection.rollback()
                    return revocation

                if not self._consume_budget_rows(
                    connection,
                    envelope,
                    budget,
                    budget_scopes,
                    timestamp,
                ):
                    connection.rollback()
                    return "exhausted"

                if state == "COMMITTED":
                    self._transition_authorization(
                        connection,
                        request_id,
                        state="CONSUMED",
                        reason="authorization_context_consumed",
                        timestamp=timestamp,
                    )
                    self._insert_outbox(
                        connection,
                        event_id=_event_id("authorization_consumed", request_id),
                        request_id=request_id,
                        event_type="authorization_consumed",
                        payload={
                            "schema_version": DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1,
                            "event_type": "authorization_consumed",
                            "request_id": request_id,
                            "request_fingerprint": request_fingerprint,
                            "route_id": route_id,
                            "decision_reason": decision_reason,
                            "state": "CONSUMED",
                            "action_scope": action_scope,
                        },
                        timestamp=timestamp,
                    )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        return "consumed"

    def revoke_capability_id(self, capability_id: str, *, reason: str = "") -> None:
        """事务化写入 capability-id 撤销事实和对应 outbox 事件。"""
        self._write_revocation("capability_id", capability_id, reason)

    def revoke_parent_envelope_digest(
        self,
        parent_envelope_digest: str,
        *,
        reason: str = "",
    ) -> None:
        """事务化写入 parent-digest 级联撤销事实和 outbox 事件。"""
        _validate_sha256_hex(parent_envelope_digest, "parent_envelope_digest")
        self._write_revocation(
            "parent_envelope_digest",
            parent_envelope_digest.lower(),
            reason,
        )

    def revocation_status(self, envelope: RequestEnvelope) -> RevocationStatus:
        """查询 capability 自身或其父 capability 是否已经撤销。"""
        if type(envelope) is not RequestEnvelope:
            raise TypeError("envelope must be RequestEnvelope")
        try:
            with closing(self._connect()) as connection:
                return self._revocation_status(connection, envelope)
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc

    def pending_outbox_events(
        self,
        *,
        limit: int = 100,
    ) -> tuple[AuthorizationOutboxEventV1, ...]:
        """按写入顺序返回未投递事件；payload 不含签名、token 或消息原文。"""
        if type(limit) is not int or limit <= 0:
            raise ValueError("limit must be a positive built-in integer")
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT sequence, event_id, request_id, event_type,
                           payload_json, created_at, delivered_at
                    FROM saga_authorization_outbox
                    WHERE delivered_at IS NULL
                    ORDER BY sequence
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc
        return tuple(AuthorizationOutboxEventV1(*row) for row in rows)

    def mark_outbox_delivered(self, event_id: str) -> None:
        """幂等确认 outbox 事件；投递者必须用 event_id 去重以支持 at-least-once。"""
        _validate_sha256_hex(event_id, "event_id")
        timestamp = self._timestamp()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    cursor = connection.execute(
                        """
                        UPDATE saga_authorization_outbox
                        SET delivered_at = COALESCE(delivered_at, ?)
                        WHERE event_id = ?
                        """,
                        (timestamp, event_id),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("unknown authorization outbox event_id")
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc

    def _consume_budget_rows(
        self,
        connection: sqlite3.Connection,
        envelope: RequestEnvelope,
        budget: dict[str, int],
        budget_scopes: tuple[str, ...],
        timestamp: str,
    ) -> bool:
        """在调用方事务内检查并扣减全部匹配预算，任一耗尽则不写入。"""
        rows = [
            (
                envelope.capability_id,
                envelope.hex_digest(),
                budget_scope,
                budget[budget_scope],
            )
            for budget_scope in budget_scopes
        ]
        for capability_id, envelope_digest, budget_scope, limit in rows:
            row = connection.execute(
                """
                SELECT budget_limit, consumed_count
                FROM saga_capability_budgets
                WHERE capability_id = ? AND envelope_digest = ? AND budget_scope = ?
                """,
                (capability_id, envelope_digest, budget_scope),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO saga_capability_budgets (
                        capability_id, envelope_digest, budget_scope,
                        budget_limit, consumed_count, updated_at
                    ) VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (capability_id, envelope_digest, budget_scope, limit, timestamp),
                )
                consumed_count = 0
            else:
                stored_limit, consumed_count = row
                if stored_limit != limit:
                    raise sqlite3.IntegrityError("capability budget limit mismatch")
            if consumed_count >= limit:
                return False
        for capability_id, envelope_digest, budget_scope, _limit in rows:
            connection.execute(
                """
                UPDATE saga_capability_budgets
                SET consumed_count = consumed_count + 1, updated_at = ?
                WHERE capability_id = ? AND envelope_digest = ? AND budget_scope = ?
                """,
                (timestamp, capability_id, envelope_digest, budget_scope),
            )
        return True

    def _write_revocation(
        self,
        revocation_type: str,
        value: str,
        reason: str,
    ) -> None:
        """在单个事务内幂等保存撤销事实与审计 outbox。"""
        if type(value) is not str or not value:
            raise ValueError("revocation value must be non-empty text")
        if type(reason) is not str:
            raise TypeError("reason must be text")
        timestamp = self._timestamp()
        event_type = (
            "capability_revoked"
            if revocation_type == "capability_id"
            else "parent_capability_revoked"
        )
        event_id = _event_id(event_type, f"{revocation_type}:{value}")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT OR IGNORE INTO saga_capability_revocations (
                        revocation_type, revocation_value, recorded_at, reason
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (revocation_type, value, timestamp, reason),
                )
                self._insert_outbox(
                    connection,
                    event_id=event_id,
                    request_id=None,
                    event_type=event_type,
                    payload={
                        "schema_version": DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1,
                        "event_type": event_type,
                        "revocation_type": revocation_type,
                        "revocation_value": value,
                        "reason": reason,
                    },
                    timestamp=timestamp,
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise OSError("durable authorization database is unavailable") from exc

    def _revocation_status(
        self,
        connection: sqlite3.Connection,
        envelope: RequestEnvelope,
    ) -> RevocationStatus:
        """在调用方连接内读取撤销事实，避免 prepare/commit 检查跨事务。"""
        if self._revocation_exists(connection, "capability_id", envelope.capability_id):
            return "capability_revoked"
        if (
            envelope.parent_envelope_digest
            and self._revocation_exists(
                connection,
                "parent_envelope_digest",
                envelope.parent_envelope_digest.lower(),
            )
        ):
            return "parent_capability_revoked"
        return "active"

    def _revocation_exists(
        self,
        connection: sqlite3.Connection,
        revocation_type: str,
        value: str,
    ) -> bool:
        """查询调用方事务内是否存在指定撤销键。"""
        row = connection.execute(
            """
            SELECT 1 FROM saga_capability_revocations
            WHERE revocation_type = ? AND revocation_value = ? LIMIT 1
            """,
            (revocation_type, value),
        ).fetchone()
        return row is not None

    def _insert_authorization(
        self,
        connection: sqlite3.Connection,
        commit: DurableAuthorizationCommitV1,
        *,
        state: AuthorizationState,
        state_reason: str,
        timestamp: str,
    ) -> None:
        """插入一个完整绑定的授权状态行。"""
        envelope = commit.envelope
        connection.execute(
            """
            INSERT INTO saga_authorization_requests (
                request_id, request_fingerprint, context_fingerprint,
                envelope_digest, capability_id, parent_envelope_digest,
                sender_aid, receiver_aid, action_scope, route_id,
                decision_reason, state, state_reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                commit.request_id,
                commit.request_fingerprint,
                commit.context_fingerprint(),
                envelope.hex_digest(),
                envelope.capability_id,
                envelope.parent_envelope_digest,
                envelope.sender_aid,
                envelope.receiver_aid,
                envelope.action_scope,
                commit.route_id,
                commit.decision_reason,
                state,
                state_reason,
                timestamp,
                timestamp,
            ),
        )

    def _authorization_identity(
        self,
        connection: sqlite3.Connection,
        request_id: str,
    ) -> tuple[str, str, AuthorizationState] | None:
        """返回并发恢复所需的 request/context fingerprint 与状态。"""
        row = connection.execute(
            """
            SELECT request_fingerprint, context_fingerprint, state
            FROM saga_authorization_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1]), row[2]

    def _transition_authorization(
        self,
        connection: sqlite3.Connection,
        request_id: str,
        *,
        state: AuthorizationState,
        reason: str,
        timestamp: str,
    ) -> None:
        """在调用方事务内更新状态与稳定原因。"""
        connection.execute(
            """
            UPDATE saga_authorization_requests
            SET state = ?, state_reason = ?, updated_at = ?
            WHERE request_id = ?
            """,
            (state, reason, timestamp, request_id),
        )

    def _insert_authorization_outbox(
        self,
        connection: sqlite3.Connection,
        commit: DurableAuthorizationCommitV1,
        *,
        event_type: str,
        state: AuthorizationState,
        reason: str,
        timestamp: str,
    ) -> None:
        """写入不含签名或正文的授权状态 outbox 事件。"""
        self._insert_outbox(
            connection,
            event_id=_event_id(event_type, commit.request_id),
            request_id=commit.request_id,
            event_type=event_type,
            payload={
                "schema_version": DURABLE_AUTHORIZATION_SCHEMA_VERSION_V1,
                "event_type": event_type,
                "request_id": commit.request_id,
                "request_fingerprint": commit.request_fingerprint,
                "context_fingerprint": commit.context_fingerprint(),
                "envelope_digest": commit.envelope.hex_digest(),
                "capability_id": commit.envelope.capability_id,
                "route_id": commit.route_id,
                "state": state,
                "reason": reason,
            },
            timestamp=timestamp,
        )

    def _insert_outbox(
        self,
        connection: sqlite3.Connection,
        *,
        event_id: str,
        request_id: str | None,
        event_type: str,
        payload: dict[str, object],
        timestamp: str,
    ) -> None:
        """以确定性 event_id 幂等插入 canonical JSON outbox 行。"""
        payload_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO saga_authorization_outbox (
                event_id, request_id, event_type, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, request_id, event_type, payload_json, timestamp),
        )

    def _connect(self) -> sqlite3.Connection:
        """打开启用外键和 busy timeout 的短生命周期连接。"""
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.timeout_seconds,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}"
        )
        return connection

    def _timestamp(self) -> str:
        """返回规范 UTC 时间；拒绝测试或调用方提供的 naive datetime。"""
        value = self._now_fn()
        if type(value) is not datetime or value.tzinfo is None:
            raise ValueError("now_fn must return a timezone-aware datetime")
        return value.astimezone(timezone.utc).isoformat()

    def _ensure_schema(self) -> None:
        """创建 durable 状态、预算、撤销和 outbox 表及其约束。"""
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("PRAGMA journal_mode = WAL")
                    connection.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS saga_authorization_requests (
                            request_id TEXT PRIMARY KEY,
                            request_fingerprint TEXT NOT NULL,
                            context_fingerprint TEXT NOT NULL,
                            envelope_digest TEXT NOT NULL,
                            capability_id TEXT NOT NULL,
                            parent_envelope_digest TEXT NOT NULL,
                            sender_aid TEXT NOT NULL,
                            receiver_aid TEXT NOT NULL,
                            action_scope TEXT NOT NULL,
                            route_id TEXT NOT NULL,
                            decision_reason TEXT NOT NULL,
                            state TEXT NOT NULL CHECK (
                                state IN ('PENDING', 'COMMITTED', 'CONSUMED', 'REJECTED')
                            ),
                            state_reason TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        );

                        CREATE TABLE IF NOT EXISTS saga_capability_budgets (
                            capability_id TEXT NOT NULL,
                            envelope_digest TEXT NOT NULL,
                            budget_scope TEXT NOT NULL,
                            budget_limit INTEGER NOT NULL,
                            consumed_count INTEGER NOT NULL,
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY (capability_id, envelope_digest, budget_scope)
                        );

                        CREATE TABLE IF NOT EXISTS saga_capability_revocations (
                            revocation_type TEXT NOT NULL,
                            revocation_value TEXT NOT NULL,
                            recorded_at TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            PRIMARY KEY (revocation_type, revocation_value)
                        );

                        CREATE TABLE IF NOT EXISTS saga_authorization_outbox (
                            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                            event_id TEXT NOT NULL UNIQUE,
                            request_id TEXT,
                            event_type TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            delivered_at TEXT
                        );

                        CREATE INDEX IF NOT EXISTS saga_authorization_outbox_pending
                        ON saga_authorization_outbox (delivered_at, sequence);
                        """
                    )
        except sqlite3.Error as exc:
            raise RuntimeError("durable authorization database is unavailable") from exc


def dispatch_authorization_outbox(
    store: DurableAuthorizationStateStore,
    deliver: Callable[[AuthorizationOutboxEventV1], None],
    *,
    limit: int = 100,
) -> int:
    """按 at-least-once 语义投递 outbox；失败事件保持 pending 供重试。"""
    if not callable(deliver):
        raise TypeError("deliver must be callable")
    events = store.pending_outbox_events(limit=limit)
    delivered_count = 0
    for event in events:
        deliver(event)
        store.mark_outbox_delivered(event.event_id)
        delivered_count += 1
    return delivered_count


def _event_id(event_type: str, identity: str) -> str:
    """生成 domain-separated 稳定事件 ID，供 outbox 消费者幂等去重。"""
    return sha256_hex(
        b"SAGA-PQ-CAN-DurableAuthorizationOutboxV1\x00"
        + event_type.encode("utf-8")
        + b"\x00"
        + identity.encode("utf-8")
    )


def _validate_sha256_hex(value: str, field_name: str) -> None:
    """验证小写 SHA-256 十六进制摘要，拒绝模糊或非规范标识。"""
    if type(value) is not str or len(value) != 64 or value.lower() != value:
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex") from exc
