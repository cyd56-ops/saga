"""Canonical request-envelope helpers for SAGA-PQ-CAN."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any

from saga.common.contact_policy import check_aid


DEFAULT_ENVELOPE_DOMAIN = "SAGA-PQ-CAN-v1"
DEFAULT_MAX_DELEGATION_DEPTH = 8
BASE_ACTION_SCOPES = frozenset(
    {
        "llm_prompt",
        "memory_read",
        "memory_write",
        "tool_call",
        "delegation",
    }
)
SUPPORTED_SCOPE_CONSTRAINT_OPS = frozenset({"eq", "in", "lte", "gte", "max_length"})
CONSTRAINT_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
MISSING_CONSTRAINT_VALUE = object()
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


def normalize_scope_constraints(
    scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None,
) -> dict[str, tuple[dict[str, Any], ...]]:
    """规范化 scope 参数约束，只允许封闭谓词集合进入签名信封。"""
    if scope_constraints is None:
        return {}

    normalized: dict[str, tuple[dict[str, Any], ...]] = {}
    for scope, constraints in scope_constraints.items():
        if not isinstance(scope, str):
            raise TypeError("scope_constraints keys must be action-scope strings")
        parse_action_scope(scope)
        normalized_constraints = tuple(
            sorted(
                (_normalize_scope_constraint(constraint) for constraint in constraints),
                key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
            )
        )
        if normalized_constraints:
            normalized[scope] = normalized_constraints
    return dict(sorted(normalized.items()))


def scope_constraints_allow(
    granted_scopes: Iterable[str],
    scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None,
    requested_scope: str,
    parameters: Mapping[str, Any] | None = None,
) -> bool:
    """判断请求参数是否满足匹配 signed scope 上绑定的所有封闭约束。"""
    parse_action_scope(requested_scope)
    normalized_constraints = normalize_scope_constraints(scope_constraints)
    granted_scope_tuple = tuple(granted_scopes)
    matching_constraints: list[Mapping[str, Any]] = []
    for constrained_scope, constraints in normalized_constraints.items():
        if action_scopes_allow(granted_scope_tuple, constrained_scope) and action_scope_allows(
            constrained_scope,
            requested_scope,
        ):
            matching_constraints.extend(constraints)
    if not matching_constraints:
        return True
    if parameters is None:
        return False
    return all(_scope_constraint_allows(constraint, parameters) for constraint in matching_constraints)


def action_scopes_are_attenuated(
    parent_scopes: Iterable[str],
    child_scopes: Iterable[str],
) -> bool:
    """Return ``True`` when every child scope is authorized by the parent set.

    委托子 capability 只能缩小父 capability 的授权面，不能新增动作族或工具细分权限。
    """
    parent_scope_tuple = tuple(parent_scopes)
    return all(action_scopes_allow(parent_scope_tuple, child_scope) for child_scope in child_scopes)


def scope_constraints_are_attenuated(
    parent_scopes: Iterable[str],
    parent_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None,
    child_scopes: Iterable[str],
    child_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None,
) -> bool:
    """判断委托子 capability 的参数约束是否只保留或收窄父 capability。

    父约束适用于子授权面时，子 capability 必须提供同字段且能蕴含父谓词的约束；
    子约束可以放到更窄 scope 上，但不能移到更宽 scope 或直接删除。
    """
    parent_scope_tuple = tuple(parent_scopes)
    child_scope_tuple = tuple(child_scopes)
    if not action_scopes_are_attenuated(parent_scope_tuple, child_scope_tuple):
        return False

    normalized_parent = normalize_scope_constraints(parent_constraints)
    normalized_child = normalize_scope_constraints(child_constraints)
    for parent_scope, constraints in normalized_parent.items():
        for child_scope in child_scope_tuple:
            obligation_scope = _constraint_obligation_scope(parent_scope, child_scope)
            if obligation_scope is None:
                continue
            for parent_constraint in constraints:
                if not _has_attenuating_child_constraint(
                    parent_scope,
                    obligation_scope,
                    parent_constraint,
                    normalized_child,
                ):
                    return False
    return True


def _constraint_obligation_scope(
    parent_constrained_scope: str,
    child_authorized_scope: str,
) -> str | None:
    """计算父约束和子授权 scope 的交集代表；无交集时返回 None。"""
    if action_scope_allows(parent_constrained_scope, child_authorized_scope):
        return child_authorized_scope
    if action_scope_allows(child_authorized_scope, parent_constrained_scope):
        return parent_constrained_scope
    return None


def _has_attenuating_child_constraint(
    parent_constrained_scope: str,
    obligation_scope: str,
    parent_constraint: Mapping[str, Any],
    child_constraints: Mapping[str, Iterable[Mapping[str, Any]]],
) -> bool:
    """查找一个不宽于父 scope 且蕴含父谓词的子约束。"""
    for child_constrained_scope, constraints in child_constraints.items():
        if not action_scope_allows(parent_constrained_scope, child_constrained_scope):
            continue
        if not action_scope_allows(child_constrained_scope, obligation_scope):
            continue
        if any(
            _scope_constraint_implies(child_constraint, parent_constraint)
            for child_constraint in constraints
        ):
            return True
    return False


def _scope_constraint_implies(
    child_constraint: Mapping[str, Any],
    parent_constraint: Mapping[str, Any],
) -> bool:
    """判断单条子谓词是否确定性蕴含父谓词。"""
    if child_constraint["field"] != parent_constraint["field"]:
        return False

    child_op = child_constraint["op"]
    parent_op = parent_constraint["op"]
    if child_op == "eq":
        return _constraint_value_satisfies_parent(
            child_constraint["value"],
            parent_constraint,
        )
    if child_op == "in":
        return all(
            _constraint_value_satisfies_parent(value, parent_constraint)
            for value in child_constraint["values"]
        )
    if child_op == "lte":
        return parent_op == "lte" and child_constraint["value"] <= parent_constraint["value"]
    if child_op == "gte":
        return parent_op == "gte" and child_constraint["value"] >= parent_constraint["value"]
    if child_op == "max_length":
        return (
            parent_op == "max_length"
            and child_constraint["value"] <= parent_constraint["value"]
        )
    return False


def _constraint_value_satisfies_parent(
    value: str | int | float | bool | None,
    parent_constraint: Mapping[str, Any],
) -> bool:
    """判断一个具体 JSON 标量值是否满足父约束谓词。"""
    parent_op = parent_constraint["op"]
    if parent_op == "eq":
        return _json_scalar_equal(value, parent_constraint["value"])
    if parent_op == "in":
        return any(_json_scalar_equal(value, candidate) for candidate in parent_constraint["values"])
    if parent_op == "lte":
        return _is_number(value) and value <= parent_constraint["value"]
    if parent_op == "gte":
        return _is_number(value) and value >= parent_constraint["value"]
    if parent_op == "max_length":
        return isinstance(value, str) and len(value) <= parent_constraint["value"]
    return False


def _normalize_scope_constraint(constraint: Mapping[str, Any]) -> dict[str, Any]:
    """规范化单条参数约束，拒绝 callback 或任意表达式。"""
    if not isinstance(constraint, Mapping):
        raise TypeError("scope constraint entries must be mappings")
    field = constraint.get("field")
    op = constraint.get("op")
    if not isinstance(field, str) or not CONSTRAINT_FIELD_RE.fullmatch(field):
        raise ValueError("scope constraint field must be a simple dotted identifier")
    if not isinstance(op, str) or op not in SUPPORTED_SCOPE_CONSTRAINT_OPS:
        raise ValueError("unsupported scope constraint op")
    if op == "in":
        values = constraint.get("values")
        if not isinstance(values, list | tuple) or not values:
            raise ValueError("in constraint requires non-empty values")
        normalized_values = tuple(
            sorted(
                (_normalize_constraint_value(value) for value in values),
                key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
            )
        )
        return {"field": field, "op": op, "values": list(normalized_values)}
    value = constraint.get("value")
    normalized_value = _normalize_constraint_value(value)
    if op in {"lte", "gte"} and not _is_number(normalized_value):
        raise ValueError(f"{op} constraint requires a numeric value")
    if op == "max_length":
        if not isinstance(normalized_value, int) or normalized_value < 0:
            raise ValueError("max_length constraint requires a non-negative integer")
    return {"field": field, "op": op, "value": normalized_value}


def _normalize_constraint_value(value: Any) -> str | int | float | bool | None:
    """只允许 JSON 标量作为约束值，避免执行任意对象逻辑。"""
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("scope constraint numbers must be finite JSON numbers")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TypeError("scope constraint values must be JSON scalars")


def _scope_constraint_allows(
    constraint: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> bool:
    """执行单条封闭谓词检查；字段缺失或类型不匹配一律拒绝。"""
    field_value = _normalize_runtime_constraint_value(
        _extract_constraint_field(parameters, str(constraint["field"]))
    )
    if field_value is MISSING_CONSTRAINT_VALUE:
        return False
    op = constraint["op"]
    if op == "eq":
        return _json_scalar_equal(field_value, constraint["value"])
    if op == "in":
        return any(_json_scalar_equal(field_value, value) for value in constraint["values"])
    if op == "lte":
        return _is_number(field_value) and field_value <= constraint["value"]
    if op == "gte":
        return _is_number(field_value) and field_value >= constraint["value"]
    if op == "max_length":
        return isinstance(field_value, str) and len(field_value) <= constraint["value"]
    return False


def _extract_constraint_field(parameters: Mapping[str, Any], field: str) -> Any:
    """按点分路径从参数映射中读取字段；缺失字段 fail-closed。"""
    current: Any = parameters
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return MISSING_CONSTRAINT_VALUE
        current = current[part]
    return current


def _normalize_runtime_constraint_value(value: Any) -> str | int | float | bool | None | object:
    """把运行时参数收窄为 JSON 标量；对象参数不参与比较以避免执行自定义逻辑。"""
    if value is MISSING_CONSTRAINT_VALUE:
        return MISSING_CONSTRAINT_VALUE
    try:
        return _normalize_constraint_value(value)
    except (TypeError, ValueError):
        return MISSING_CONSTRAINT_VALUE


def _json_scalar_equal(left: Any, right: Any) -> bool:
    """按 JSON 标量类型做等值比较，避免 ``True`` 被当作数字 ``1``。"""
    if _is_number(left) and _is_number(right):
        return left == right
    if type(left) is not type(right):
        return False
    return left == right


def _is_number(value: Any) -> bool:
    """判断值是否为非 bool 数字，避免 True/False 被当作 1/0。"""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and not (isinstance(value, float) and not math.isfinite(value))
    )


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
    """Canonical signed intent-capability envelope for SAGA-PQ-CAN.

    信封绑定入口动作、额外授权 scope、消息摘要、token 摘要和委托 capability 关系。
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
    scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None = None
    domain: str = DEFAULT_ENVELOPE_DOMAIN
    content_type: str = "text"
    provider_id: str = ""
    timestamp: datetime | str | None = None
    capability_id: str = ""
    parent_envelope_digest: str = ""
    parent_authorized_scopes: tuple[str, ...] | list[str] | None = None
    parent_scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None = None
    delegation_depth: int = 0
    max_delegation_depth: int = DEFAULT_MAX_DELEGATION_DEPTH

    def __post_init__(self) -> None:
        """Validate and normalize the envelope into a deterministic form.

        所有 scope、capability 关系和时间戳在签名前规范化，确保不同节点得到相同摘要。
        """
        if not check_aid(self.sender_aid):
            raise ValueError("sender_aid must be a valid AID")
        if not check_aid(self.receiver_aid):
            raise ValueError("receiver_aid must be a valid AID")
        authorized_scopes = normalize_authorized_scopes(self.action_scope, self.authorized_scopes)
        scope_constraints = normalize_scope_constraints(self.scope_constraints)
        for constrained_scope in scope_constraints:
            if not action_scopes_allow(authorized_scopes, constrained_scope):
                raise ValueError("scope_constraints keys must be covered by authorized_scopes")
        parent_authorized_scopes = self._normalize_parent_authorized_scopes(
            self.parent_authorized_scopes
        )
        parent_scope_constraints = normalize_scope_constraints(self.parent_scope_constraints)
        for constrained_scope in parent_scope_constraints:
            if not action_scopes_allow(parent_authorized_scopes, constrained_scope):
                raise ValueError(
                    "parent_scope_constraints keys must be covered by parent_authorized_scopes"
                )
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
        capability_id = self.capability_id or self.turn_id
        if not capability_id:
            raise ValueError("capability_id must be non-empty")
        parent_envelope_digest = self.parent_envelope_digest.lower()
        if parent_envelope_digest and not self._is_sha256_hex(parent_envelope_digest):
            raise ValueError("parent_envelope_digest must be a SHA-256 hex digest")
        if self.delegation_depth < 0:
            raise ValueError("delegation_depth must be non-negative")
        if self.max_delegation_depth < 0:
            raise ValueError("max_delegation_depth must be non-negative")
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
        object.__setattr__(self, "scope_constraints", scope_constraints)
        object.__setattr__(self, "capability_id", capability_id)
        object.__setattr__(self, "parent_envelope_digest", parent_envelope_digest)
        object.__setattr__(self, "parent_authorized_scopes", parent_authorized_scopes)
        object.__setattr__(self, "parent_scope_constraints", parent_scope_constraints)

    def as_dict(self) -> dict[str, Any]:
        """Return the canonical dictionary representation of the envelope.

        字典字段是签名覆盖面，新增授权能力必须显式出现在这里。
        """
        return {
            "action_scope": self.action_scope,
            "authorized_scopes": list(self.authorized_scopes),
            "capability_id": self.capability_id,
            "content_type": self.content_type,
            "delegation_depth": self.delegation_depth,
            "domain": self.domain,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "max_delegation_depth": self.max_delegation_depth,
            "message_digest": self.message_digest,
            "parent_authorized_scopes": list(self.parent_authorized_scopes),
            "parent_envelope_digest": self.parent_envelope_digest,
            "parent_scope_constraints": {
                scope: list(constraints)
                for scope, constraints in self.parent_scope_constraints.items()
            },
            "provider_id": self.provider_id,
            "receiver_aid": self.receiver_aid,
            "sender_aid": self.sender_aid,
            "session_id": self.session_id,
            "scope_constraints": {
                scope: list(constraints)
                for scope, constraints in self.scope_constraints.items()
            },
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
            allow_nan=False,
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

    @staticmethod
    def _is_sha256_hex(value: str) -> bool:
        """校验字段是否为规范小写或大写 SHA-256 hex 文本。"""
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))

    @staticmethod
    def _normalize_parent_authorized_scopes(
        parent_authorized_scopes: Iterable[str] | None,
    ) -> tuple[str, ...]:
        """规范化父 capability scope 列表，供 scope attenuation 检查使用。"""
        if parent_authorized_scopes is None:
            return ()
        scopes: set[str] = set()
        for scope in parent_authorized_scopes:
            if not isinstance(scope, str):
                raise TypeError("parent_authorized_scopes entries must be strings")
            parse_action_scope(scope)
            scopes.add(scope)
        return tuple(sorted(scopes))


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
    scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    message: str | bytes,
    domain: str = DEFAULT_ENVELOPE_DOMAIN,
    content_type: str = "text",
    provider_id: str = "",
    timestamp: datetime | str | None = None,
    capability_id: str = "",
    parent_envelope: RequestEnvelope | None = None,
    parent_envelope_digest: str = "",
    parent_authorized_scopes: Iterable[str] | None = None,
    parent_scope_constraints: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    delegation_depth: int = 0,
    max_delegation_depth: int = DEFAULT_MAX_DELEGATION_DEPTH,
) -> RequestEnvelope:
    """Build a request envelope by hashing the token and message payload.

    调用方可传入额外 ``authorized_scopes``、参数约束和父 capability，用于签名绑定能力边界。
    """
    token_bytes = token.encode("utf-8") if isinstance(token, str) else token
    message_bytes = message.encode("utf-8") if isinstance(message, str) else message
    effective_parent_digest = parent_envelope_digest
    effective_parent_scopes = parent_authorized_scopes
    effective_parent_constraints = parent_scope_constraints
    effective_delegation_depth = delegation_depth
    if parent_envelope is not None:
        effective_parent_digest = parent_envelope.hex_digest()
        effective_parent_scopes = parent_envelope.authorized_scopes
        effective_parent_constraints = parent_envelope.scope_constraints
        effective_delegation_depth = parent_envelope.delegation_depth + 1

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
        scope_constraints=scope_constraints,
        message_digest=sha256_hex(message_bytes),
        domain=domain,
        content_type=content_type,
        provider_id=provider_id,
        timestamp=timestamp,
        capability_id=capability_id,
        parent_envelope_digest=effective_parent_digest,
        parent_authorized_scopes=(
            tuple(effective_parent_scopes)
            if effective_parent_scopes is not None
            else None
        ),
        parent_scope_constraints=effective_parent_constraints,
        delegation_depth=effective_delegation_depth,
        max_delegation_depth=max_delegation_depth,
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
