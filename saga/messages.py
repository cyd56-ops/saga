"""Canonical request-envelope helpers for SAGA-PQ-CAN."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from saga.common.contact_policy import check_aid


DEFAULT_ENVELOPE_DOMAIN = "SAGA-PQ-CAN-v1"
BASE_ACTION_SCOPES = frozenset(
    {
        "llm_prompt",
        "memory_read",
        "memory_write",
        "tool_call",
        "delegation",
    }
)
ACTION_SCOPE_RE = re.compile(
    r"^(?P<base>llm_prompt|memory_read|memory_write|tool_call|delegation)"
    r"(?::(?P<detail>[A-Za-z0-9_.-]+))?$"
)


def sha256_hex(payload: bytes) -> str:
    """Return the lowercase SHA-256 hex digest for ``payload``."""
    return hashlib.sha256(payload).hexdigest()


def parse_action_scope(action_scope: str) -> tuple[str, str | None]:
    """Parse and validate an action scope.

    Supported forms:
    - ``llm_prompt``
    - ``memory_read``
    - ``memory_write``
    - ``tool_call``
    - ``delegation``
    - ``tool_call:<tool_name>`` for tool-specific authorization
    """
    match = ACTION_SCOPE_RE.fullmatch(action_scope)
    if match is None:
        raise ValueError(f"unsupported action_scope: {action_scope}")
    return match.group("base"), match.group("detail")


def action_scope_allows(granted_scope: str, requested_scope: str) -> bool:
    """Return ``True`` when ``granted_scope`` authorizes ``requested_scope``.

    An unqualified scope such as ``tool_call`` authorizes any request with the
    same base scope, including qualified forms like ``tool_call:send_email``.
    A qualified scope authorizes only an exact match.

    该函数只比较同一动作族，避免 ``llm_prompt`` 被解释为工具或内存权限。
    """
    granted_base, granted_detail = parse_action_scope(granted_scope)
    requested_base, requested_detail = parse_action_scope(requested_scope)
    if granted_base != requested_base:
        return False
    if granted_detail is None:
        return True
    return granted_detail == requested_detail


def normalize_authorized_scopes(
    action_scope: str,
    authorized_scopes: Iterable[str] | None,
) -> tuple[str, ...]:
    """Normalize the signed authorization scopes carried by an envelope.

    信封总是包含入口 ``action_scope``，额外能力以规范化 scope 集合形式签名绑定。
    """
    parse_action_scope(action_scope)
    scopes = {action_scope}
    if authorized_scopes is not None:
        for scope in authorized_scopes:
            if not isinstance(scope, str):
                raise TypeError("authorized_scopes entries must be strings")
            parse_action_scope(scope)
            scopes.add(scope)
    return tuple(sorted(scopes))


def action_scopes_allow(granted_scopes: Iterable[str], requested_scope: str) -> bool:
    """Return ``True`` when any signed scope authorizes ``requested_scope``.

    下游工具、内存和委托检查只根据显式签名的 scope 列表授权。
    """
    return any(action_scope_allows(granted_scope, requested_scope) for granted_scope in granted_scopes)


def _normalize_timestamp(value: datetime | str, field_name: str) -> str:
    """Normalize a timestamp to a canonical UTC RFC3339-like string."""
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise TypeError(f"{field_name} must be a datetime or ISO-8601 string")

    # 请求信封必须使用带时区时间，避免不同节点按本地时区解释有效期。
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")

    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class RequestEnvelope:
    """Canonical execution-authentication envelope for SAGA-PQ-CAN.

    信封绑定入口动作、额外授权 scope、消息摘要和 token 摘要，供 PQ-CAN 验签。
    """

    sender_aid: str
    receiver_aid: str
    token_digest: str
    session_id: str
    turn_id: str
    issued_at: datetime | str
    expires_at: datetime | str
    action_scope: str
    message_digest: str
    authorized_scopes: tuple[str, ...] | list[str] | None = None
    domain: str = DEFAULT_ENVELOPE_DOMAIN
    content_type: str = "text"
    provider_id: str = ""
    timestamp: datetime | str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the envelope into a deterministic form.

        所有 scope 和时间戳在签名前规范化，确保不同节点得到相同摘要。
        """
        if not check_aid(self.sender_aid):
            raise ValueError("sender_aid must be a valid AID")
        if not check_aid(self.receiver_aid):
            raise ValueError("receiver_aid must be a valid AID")
        authorized_scopes = normalize_authorized_scopes(self.action_scope, self.authorized_scopes)
        if not self.domain:
            raise ValueError("domain must be non-empty")
        if not self.session_id:
            raise ValueError("session_id must be non-empty")
        if not self.turn_id:
            raise ValueError("turn_id must be non-empty")
        if not self.token_digest:
            raise ValueError("token_digest must be non-empty")
        if not self.message_digest:
            raise ValueError("message_digest must be non-empty")
        if not self.content_type:
            raise ValueError("content_type must be non-empty")

        issued_at = _normalize_timestamp(self.issued_at, "issued_at")
        expires_at = _normalize_timestamp(self.expires_at, "expires_at")
        timestamp = issued_at if self.timestamp is None else _normalize_timestamp(
            self.timestamp, "timestamp"
        )

        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "token_digest", self.token_digest.lower())
        object.__setattr__(self, "message_digest", self.message_digest.lower())
        object.__setattr__(self, "authorized_scopes", authorized_scopes)

    def as_dict(self) -> dict[str, Any]:
        """Return the canonical dictionary representation of the envelope.

        字典字段是签名覆盖面，新增授权能力必须显式出现在这里。
        """
        return {
            "action_scope": self.action_scope,
            "authorized_scopes": list(self.authorized_scopes),
            "content_type": self.content_type,
            "domain": self.domain,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "message_digest": self.message_digest,
            "provider_id": self.provider_id,
            "receiver_aid": self.receiver_aid,
            "sender_aid": self.sender_aid,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "token_digest": self.token_digest,
            "turn_id": self.turn_id,
        }

    def canonical_bytes(self) -> bytes:
        """Serialize the envelope using canonical JSON rules."""
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def canonical_json(self) -> str:
        """Return the canonical JSON string representation of the envelope."""
        return self.canonical_bytes().decode("utf-8")

    def digest(self) -> bytes:
        """Return the SHA-256 digest of the canonical envelope bytes."""
        return hashlib.sha256(self.canonical_bytes()).digest()

    def hex_digest(self) -> str:
        """Return the lowercase SHA-256 hex digest of the canonical envelope."""
        return self.digest().hex()


def build_request_envelope(
    *,
    sender_aid: str,
    receiver_aid: str,
    token: str | bytes,
    session_id: str,
    turn_id: str,
    issued_at: datetime | str,
    expires_at: datetime | str,
    action_scope: str,
    authorized_scopes: Iterable[str] | None = None,
    message: str | bytes,
    domain: str = DEFAULT_ENVELOPE_DOMAIN,
    content_type: str = "text",
    provider_id: str = "",
    timestamp: datetime | str | None = None,
) -> RequestEnvelope:
    """Build a request envelope by hashing the token and message payload.

    调用方可传入额外 ``authorized_scopes``，它们会和入口动作一起进入签名信封。
    """
    token_bytes = token.encode("utf-8") if isinstance(token, str) else token
    message_bytes = message.encode("utf-8") if isinstance(message, str) else message

    return RequestEnvelope(
        sender_aid=sender_aid,
        receiver_aid=receiver_aid,
        token_digest=sha256_hex(token_bytes),
        session_id=session_id,
        turn_id=turn_id,
        issued_at=issued_at,
        expires_at=expires_at,
        action_scope=action_scope,
        authorized_scopes=tuple(authorized_scopes) if authorized_scopes is not None else None,
        message_digest=sha256_hex(message_bytes),
        domain=domain,
        content_type=content_type,
        provider_id=provider_id,
        timestamp=timestamp,
    )


def parse_request_envelope(value: RequestEnvelope | Mapping[str, Any] | str | bytes) -> RequestEnvelope:
    """Parse a serialized request envelope into a validated ``RequestEnvelope``."""
    if isinstance(value, RequestEnvelope):
        return value

    decoded: Mapping[str, Any]
    if isinstance(value, bytes):
        decoded = json.loads(value.decode("utf-8"))
    elif isinstance(value, str):
        decoded = json.loads(value)
    elif isinstance(value, Mapping):
        decoded = value
    else:
        raise TypeError("request envelope must be a RequestEnvelope, mapping, JSON string, or bytes")

    return RequestEnvelope(**dict(decoded))
