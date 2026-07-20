"""路线 B B2 原始授权关系的固定 Linear/ReLU 电路。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Literal, Sequence

from neural.fixed_policy import FixedCircuitComplexity
from neural.shamir_layers import FixedLinear, FixedReLU


RAW_AUTHORIZATION_LAYOUT_ID_V1 = "saga-route-b-raw-authorization-layout"
RAW_AUTHORIZATION_LAYOUT_VERSION_V1 = 1
FIXED_AUTHORIZATION_CIRCUIT_PROFILE_ID_V1 = (
    "saga-route-b-fixed-authorization-relations"
)
FIXED_AUTHORIZATION_CIRCUIT_PROFILE_VERSION_V1 = 1
RAW_AUTHORIZATION_SCOPE_FAMILIES_V1 = (
    "llm_prompt",
    "memory_read",
    "memory_write",
    "tool_call",
    "delegation",
    "declassify",
)
RAW_AUTHORIZATION_FLOW_LABELS_V1 = (
    "public",
    "internal",
    "private",
    "confidential",
    "restricted",
    "secret",
    "__unknown__",
)
RAW_AUTHORIZATION_DIGEST_RELATIONS_V1 = (
    "envelope",
    "sender",
    "receiver",
    "token",
    "message",
    "action_scope",
)
RAW_AUTHORIZATION_DIGEST_BYTES = 32
RAW_AUTHORIZATION_MAX_DEPTH = 255
RAW_AUTHORIZATION_MAX_EPOCH_SECONDS = (1 << 32) - 1
RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1 = 900

RawAuthorizationRelationName = Literal[
    "standard_signature_valid",
    "scope_subset",
    "flow_subset",
    "delegation_relation",
    "time_window_relation",
    "digest_bindings_equal",
]

RAW_AUTHORIZATION_RELATION_NAMES: tuple[RawAuthorizationRelationName, ...] = (
    "standard_signature_valid",
    "scope_subset",
    "flow_subset",
    "delegation_relation",
    "time_window_relation",
    "digest_bindings_equal",
)

_RAW_RELATION_REASONS: dict[RawAuthorizationRelationName, str] = {
    "standard_signature_valid": "standard_signature_invalid",
    "scope_subset": "scope_not_authorized",
    "flow_subset": "flow_policy_denied",
    "delegation_relation": "delegation_policy_denied",
    "time_window_relation": "time_window_invalid",
    "digest_bindings_equal": "request_envelope_mismatch",
}


@dataclass(frozen=True)
class RouteBRawAuthorizationInputV1:
    """保存 B2 电路直接消费的固定宽度原始授权关系输入。"""

    layout_id: str
    layout_version: int
    standard_signature_valid: bool
    requested_scope_bits: bytes
    authorized_scope_bits: bytes
    flow_label_bits: bytes
    allowed_flow_label_bits: bytes
    parent_allowed_flow_label_bits: bytes
    parent_present: bool
    delegation_depth: int
    parent_delegation_depth: int
    max_delegation_depth: int
    parent_max_delegation_depth: int
    signed_parent_digest: bytes
    observed_parent_digest: bytes
    parent_scope_bits: bytes
    issued_at_epoch: int
    observed_at_epoch: int
    expires_at_epoch: int
    parent_issued_at_epoch: int
    parent_expires_at_epoch: int
    max_ttl_seconds: int
    bound_digests: tuple[bytes, ...]
    observed_digests: tuple[bytes, ...]

    def __post_init__(self) -> None:
        """在进入电路前拒绝浮点、非二值、错误宽度和未知版本。"""
        if self.layout_id != RAW_AUTHORIZATION_LAYOUT_ID_V1:
            raise ValueError("unsupported raw authorization layout id")
        if (
            type(self.layout_version) is not int
            or self.layout_version != RAW_AUTHORIZATION_LAYOUT_VERSION_V1
        ):
            raise ValueError("unsupported raw authorization layout version")
        if type(self.standard_signature_valid) is not bool:
            raise TypeError("standard_signature_valid must be a built-in bool")
        if type(self.parent_present) is not bool:
            raise TypeError("parent_present must be a built-in bool")
        _validate_binary_vector(
            self.requested_scope_bits,
            len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1),
            "requested_scope_bits",
        )
        _validate_binary_vector(
            self.authorized_scope_bits,
            len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1),
            "authorized_scope_bits",
        )
        _validate_binary_vector(
            self.parent_scope_bits,
            len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1),
            "parent_scope_bits",
        )
        _validate_binary_vector(
            self.flow_label_bits,
            len(RAW_AUTHORIZATION_FLOW_LABELS_V1),
            "flow_label_bits",
        )
        _validate_binary_vector(
            self.allowed_flow_label_bits,
            len(RAW_AUTHORIZATION_FLOW_LABELS_V1),
            "allowed_flow_label_bits",
        )
        _validate_binary_vector(
            self.parent_allowed_flow_label_bits,
            len(RAW_AUTHORIZATION_FLOW_LABELS_V1),
            "parent_allowed_flow_label_bits",
        )
        for field_name, value in (
            ("delegation_depth", self.delegation_depth),
            ("parent_delegation_depth", self.parent_delegation_depth),
            ("max_delegation_depth", self.max_delegation_depth),
            ("parent_max_delegation_depth", self.parent_max_delegation_depth),
        ):
            _validate_uint(value, RAW_AUTHORIZATION_MAX_DEPTH, field_name)
        for field_name, value in (
            ("issued_at_epoch", self.issued_at_epoch),
            ("observed_at_epoch", self.observed_at_epoch),
            ("expires_at_epoch", self.expires_at_epoch),
            ("parent_issued_at_epoch", self.parent_issued_at_epoch),
            ("parent_expires_at_epoch", self.parent_expires_at_epoch),
        ):
            _validate_uint(
                value,
                RAW_AUTHORIZATION_MAX_EPOCH_SECONDS,
                field_name,
            )
        if (
            type(self.max_ttl_seconds) is not int
            or self.max_ttl_seconds != RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1
        ):
            raise ValueError("max_ttl_seconds must use the fixed V1 profile limit")
        _validate_digest(self.signed_parent_digest, "signed_parent_digest")
        _validate_digest(self.observed_parent_digest, "observed_parent_digest")
        _validate_digest_tuple(self.bound_digests, "bound_digests")
        _validate_digest_tuple(self.observed_digests, "observed_digests")

    def canonical_bytes(self) -> bytes:
        """生成版本化固定输入的确定性 JSON 编码，供 provenance 和 trace 摘要使用。"""
        payload = {
            "allowed_flow_label_bits": list(self.allowed_flow_label_bits),
            "authorized_scope_bits": list(self.authorized_scope_bits),
            "bound_digests": [digest.hex() for digest in self.bound_digests],
            "delegation_depth": self.delegation_depth,
            "expires_at_epoch": self.expires_at_epoch,
            "flow_label_bits": list(self.flow_label_bits),
            "issued_at_epoch": self.issued_at_epoch,
            "layout_id": self.layout_id,
            "layout_version": self.layout_version,
            "max_delegation_depth": self.max_delegation_depth,
            "max_ttl_seconds": self.max_ttl_seconds,
            "observed_at_epoch": self.observed_at_epoch,
            "observed_digests": [digest.hex() for digest in self.observed_digests],
            "observed_parent_digest": self.observed_parent_digest.hex(),
            "parent_allowed_flow_label_bits": list(
                self.parent_allowed_flow_label_bits
            ),
            "parent_delegation_depth": self.parent_delegation_depth,
            "parent_expires_at_epoch": self.parent_expires_at_epoch,
            "parent_issued_at_epoch": self.parent_issued_at_epoch,
            "parent_max_delegation_depth": self.parent_max_delegation_depth,
            "parent_present": self.parent_present,
            "parent_scope_bits": list(self.parent_scope_bits),
            "requested_scope_bits": list(self.requested_scope_bits),
            "signed_parent_digest": self.signed_parent_digest.hex(),
            "standard_signature_valid": self.standard_signature_valid,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def digest(self) -> bytes:
        """返回 domain-separated B2 输入摘要，不把原始输入复制进 evidence。"""
        return hashlib.sha256(
            b"SAGA-PQ-CAN-RouteBRawAuthorizationV1\x00" + self.canonical_bytes()
        ).digest()


@dataclass(frozen=True)
class RawAuthorizationPredicateEvaluation:
    """记录一个 B2 原始关系谓词的精确 0/1 输出与稳定拒绝原因。"""

    relation_name: RawAuthorizationRelationName
    output: int
    reject_reason: str

    def __post_init__(self) -> None:
        """拒绝未知关系、非精确整数位或错误 reason mapping。"""
        if self.relation_name not in RAW_AUTHORIZATION_RELATION_NAMES:
            raise ValueError("unknown raw authorization relation")
        if type(self.output) is not int or self.output not in (0, 1):
            raise ValueError("raw authorization relation output must be integer 0 or 1")
        if self.reject_reason != _RAW_RELATION_REASONS[self.relation_name]:
            raise ValueError("raw authorization relation reason mismatch")

    def as_dict(self) -> dict[str, int | str]:
        """导出稳定的单关系机器可读摘要。"""
        return {
            "relation_name": self.relation_name,
            "output": self.output,
            "reject_reason": self.reject_reason,
        }


@dataclass(frozen=True)
class ReferenceAuthorizationRelationDecision:
    """记录普通整数/集合 reference oracle 对 B2 输入的判定。"""

    accepted: bool
    reason: str
    output: int
    predicates: tuple[RawAuthorizationPredicateEvaluation, ...]


@dataclass(frozen=True)
class FixedAuthorizationRelationTrace:
    """记录 B2 固定关系输出、输入摘要和最终硬聚合结果。"""

    input_valid: bool
    input_digest: bytes
    predicates: tuple[RawAuthorizationPredicateEvaluation, ...]
    accept_output: int
    reason: str

    def __post_init__(self) -> None:
        """拒绝非规范输入摘要、谓词集合和非精确 0/1 聚合输出。"""
        if type(self.input_valid) is not bool:
            raise TypeError("input_valid must be a built-in bool")
        if type(self.input_digest) is not bytes or len(self.input_digest) != 32:
            raise ValueError("input_digest must be exactly 32 bytes")
        if type(self.predicates) is not tuple or any(
            type(predicate) is not RawAuthorizationPredicateEvaluation
            for predicate in self.predicates
        ):
            raise TypeError("predicates must use the fixed predicate type")
        if self.input_valid and len(self.predicates) != len(
            RAW_AUTHORIZATION_RELATION_NAMES
        ):
            raise ValueError("valid trace must contain every B2 relation")
        if not self.input_valid and self.predicates:
            raise ValueError("invalid-input trace cannot contain predicates")
        if type(self.accept_output) is not int or self.accept_output not in (0, 1):
            raise ValueError("accept_output must be integer 0 or 1")
        if type(self.reason) is not str or not self.reason:
            raise ValueError("trace reason must be non-empty text")

    def as_dict(self) -> dict[str, object]:
        """导出不包含 AID、token、message 或签名原文的电路 trace。"""
        return {
            "input_valid": self.input_valid,
            "input_digest": self.input_digest.hex(),
            "predicates": [predicate.as_dict() for predicate in self.predicates],
            "accept_output": self.accept_output,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FixedAuthorizationRelationDecision:
    """记录 B2 fixed circuit 判定与结构复杂度。"""

    accepted: bool
    reason: str
    output: int
    trace: FixedAuthorizationRelationTrace
    complexity: FixedCircuitComplexity

    def __post_init__(self) -> None:
        """绑定接受位、硬输出、trace 与复杂度，拒绝不一致 decision。"""
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be a built-in bool")
        if type(self.output) is not int or self.output not in (0, 1):
            raise ValueError("fixed authorization output must be integer 0 or 1")
        if type(self.trace) is not FixedAuthorizationRelationTrace:
            raise TypeError("trace must be FixedAuthorizationRelationTrace")
        if type(self.complexity) is not FixedCircuitComplexity:
            raise TypeError("complexity must be FixedCircuitComplexity")
        if self.accepted is not (self.output == 1):
            raise ValueError("accepted must match the exact integer output")
        if self.trace.accept_output != self.output or self.trace.reason != self.reason:
            raise ValueError("decision must match its trace")

    def as_dict(self) -> dict[str, object]:
        """导出 B2 判定、trace 与结构复杂度。"""
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "output": self.output,
            "trace": self.trace.as_dict(),
            "complexity": self.complexity.as_dict(),
        }


class ReferenceAuthorizationRelationsV1:
    """用普通整数和集合关系实现 B2 fixed circuit 的 reference oracle。"""

    def evaluate(
        self,
        raw_input: RouteBRawAuthorizationInputV1,
    ) -> ReferenceAuthorizationRelationDecision:
        """直接计算原始关系，保持与 fixed circuit 相同的谓词顺序和 reason。"""
        if type(raw_input) is not RouteBRawAuthorizationInputV1:
            return ReferenceAuthorizationRelationDecision(
                False,
                "raw_authorization_input_invalid",
                0,
                (),
            )
        zero_digest = bytes(RAW_AUTHORIZATION_DIGEST_BYTES)
        zero_parent_scopes = bytes(len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1))
        zero_parent_flow = bytes(len(RAW_AUTHORIZATION_FLOW_LABELS_V1))
        root_delegation = (
            not raw_input.parent_present
            and raw_input.delegation_depth == 0
            and raw_input.parent_delegation_depth == 0
            and raw_input.parent_max_delegation_depth == 0
            and raw_input.signed_parent_digest == zero_digest
            and raw_input.observed_parent_digest == zero_digest
            and raw_input.parent_scope_bits == zero_parent_scopes
            and raw_input.parent_allowed_flow_label_bits == zero_parent_flow
            and raw_input.parent_issued_at_epoch == 0
            and raw_input.parent_expires_at_epoch == 0
        )
        delegated = (
            raw_input.parent_present
            and raw_input.signed_parent_digest == raw_input.observed_parent_digest
            and raw_input.delegation_depth
            == raw_input.parent_delegation_depth + 1
            and raw_input.delegation_depth <= raw_input.max_delegation_depth
            and raw_input.max_delegation_depth
            <= raw_input.parent_max_delegation_depth
            and _reference_subset(
                raw_input.authorized_scope_bits,
                raw_input.parent_scope_bits,
            )
            and _reference_subset(
                raw_input.allowed_flow_label_bits,
                raw_input.parent_allowed_flow_label_bits,
            )
            and raw_input.parent_issued_at_epoch <= raw_input.issued_at_epoch
            and raw_input.expires_at_epoch <= raw_input.parent_expires_at_epoch
        )
        outputs = (
            int(raw_input.standard_signature_valid),
            int(
                _reference_subset(
                    raw_input.requested_scope_bits,
                    raw_input.authorized_scope_bits,
                )
            ),
            int(
                _reference_subset(
                    raw_input.flow_label_bits,
                    raw_input.allowed_flow_label_bits,
                )
            ),
            int(root_delegation or delegated),
            int(
                raw_input.issued_at_epoch
                <= raw_input.observed_at_epoch
                <= raw_input.expires_at_epoch
                <= raw_input.issued_at_epoch + raw_input.max_ttl_seconds
            ),
            int(raw_input.bound_digests == raw_input.observed_digests),
        )
        predicates = _predicate_evaluations(outputs)
        reason = _first_reject_reason(predicates)
        accepted = reason is None
        return ReferenceAuthorizationRelationDecision(
            accepted,
            reason or "reference_authorization_relations_accept",
            int(accepted),
            predicates,
        )


class FixedAuthorizationCircuitV1:
    """用固定 Linear/ReLU 直接计算 B2 scope/flow/delegation/time/digest 关系。"""

    def __init__(self) -> None:
        """编译固定关系门和最终 AND，不创建训练状态或执行 authority。"""
        scope_width = len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1)
        flow_width = len(RAW_AUTHORIZATION_FLOW_LABELS_V1)
        digest_width = (
            len(RAW_AUTHORIZATION_DIGEST_RELATIONS_V1)
            * RAW_AUTHORIZATION_DIGEST_BYTES
        )
        self.scope_subset = _FixedVectorSubset(scope_width)
        self.flow_subset = _FixedVectorSubset(flow_width)
        self.delegation_relation = _FixedDelegationRelation(scope_width, flow_width)
        self.time_relation = _FixedTimeWindowRelation()
        self.digest_equality = _FixedVectorEquality(digest_width)
        self.accept_all = _FixedAll(len(RAW_AUTHORIZATION_RELATION_NAMES))
        self.requires_grad = False

    def evaluate(
        self,
        raw_input: RouteBRawAuthorizationInputV1,
    ) -> FixedAuthorizationRelationDecision:
        """求值 B2 原始关系，并且只接受最终精确内建整数 1。"""
        complexity = self.complexity_manifest()
        if type(raw_input) is not RouteBRawAuthorizationInputV1:
            trace = FixedAuthorizationRelationTrace(
                input_valid=False,
                input_digest=bytes(RAW_AUTHORIZATION_DIGEST_BYTES),
                predicates=(),
                accept_output=0,
                reason="raw_authorization_input_invalid",
            )
            return FixedAuthorizationRelationDecision(
                False,
                trace.reason,
                0,
                trace,
                complexity,
            )

        digest_left = b"".join(raw_input.bound_digests)
        digest_right = b"".join(raw_input.observed_digests)
        outputs = (
            int(raw_input.standard_signature_valid),
            self.scope_subset(
                raw_input.requested_scope_bits,
                raw_input.authorized_scope_bits,
            ),
            self.flow_subset(
                raw_input.flow_label_bits,
                raw_input.allowed_flow_label_bits,
            ),
            self.delegation_relation(
                parent_present=raw_input.parent_present,
                delegation_depth=raw_input.delegation_depth,
                parent_delegation_depth=raw_input.parent_delegation_depth,
                max_delegation_depth=raw_input.max_delegation_depth,
                parent_max_delegation_depth=(
                    raw_input.parent_max_delegation_depth
                ),
                signed_parent_digest=raw_input.signed_parent_digest,
                observed_parent_digest=raw_input.observed_parent_digest,
                child_scope_bits=raw_input.authorized_scope_bits,
                parent_scope_bits=raw_input.parent_scope_bits,
                child_allowed_flow_bits=raw_input.allowed_flow_label_bits,
                parent_allowed_flow_bits=(
                    raw_input.parent_allowed_flow_label_bits
                ),
                issued_at_epoch=raw_input.issued_at_epoch,
                expires_at_epoch=raw_input.expires_at_epoch,
                parent_issued_at_epoch=raw_input.parent_issued_at_epoch,
                parent_expires_at_epoch=raw_input.parent_expires_at_epoch,
            ),
            self.time_relation(
                raw_input.issued_at_epoch,
                raw_input.observed_at_epoch,
                raw_input.expires_at_epoch,
                raw_input.max_ttl_seconds,
            ),
            self.digest_equality(digest_left, digest_right),
        )
        predicates = _predicate_evaluations(outputs)
        aggregate_output = self.accept_all(outputs)
        accept_output = 1 if aggregate_output == 1.0 else 0
        accepted = type(accept_output) is int and accept_output == 1
        reason = _first_reject_reason(predicates) or (
            "fixed_authorization_circuit_accept"
            if accepted
            else "fixed_authorization_output_invalid"
        )
        trace = FixedAuthorizationRelationTrace(
            input_valid=True,
            input_digest=raw_input.digest(),
            predicates=predicates,
            accept_output=accept_output,
            reason=reason,
        )
        return FixedAuthorizationRelationDecision(
            accepted,
            reason,
            accept_output,
            trace,
            complexity,
        )

    def complexity_manifest(self) -> FixedCircuitComplexity:
        """统计当前对象图中的固定 Linear/ReLU 层和参数数量。"""
        linear_layers, relu_layers, parameters = _fixed_layer_stats(self.submodules())
        input_count = (
            2 * len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1)
            + 2 * len(RAW_AUTHORIZATION_FLOW_LABELS_V1)
            + len(RAW_AUTHORIZATION_FLOW_LABELS_V1)
            + len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1)
            + 2 * len(RAW_AUTHORIZATION_DIGEST_RELATIONS_V1)
            * RAW_AUTHORIZATION_DIGEST_BYTES
            + 2 * RAW_AUTHORIZATION_DIGEST_BYTES
            + 12
        )
        input_bytes = (
            3 * len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1)
            + 2 * len(RAW_AUTHORIZATION_FLOW_LABELS_V1)
            + len(RAW_AUTHORIZATION_FLOW_LABELS_V1)
            + 2
            + 4
            + 6 * 4
            + 2 * RAW_AUTHORIZATION_DIGEST_BYTES
            + 2
            * len(RAW_AUTHORIZATION_DIGEST_RELATIONS_V1)
            * RAW_AUTHORIZATION_DIGEST_BYTES
        )
        return FixedCircuitComplexity(
            circuit_profile_id=FIXED_AUTHORIZATION_CIRCUIT_PROFILE_ID_V1,
            circuit_profile_version=FIXED_AUTHORIZATION_CIRCUIT_PROFILE_VERSION_V1,
            input_count=input_count,
            input_bytes=input_bytes,
            predicate_count=len(RAW_AUTHORIZATION_RELATION_NAMES),
            fixed_linear_layers=linear_layers,
            fixed_relu_layers=relu_layers,
            fixed_parameter_count=parameters,
            circuit_depth=8,
        )

    def submodules(self) -> tuple[object, ...]:
        """返回 B2 全部固定子模块，供无训练状态审计。"""
        return (
            self.scope_subset,
            self.flow_subset,
            self.delegation_relation,
            self.time_relation,
            self.digest_equality,
            self.accept_all,
        )


class _FixedAll:
    """仅当固定宽度输入全部为 1 时输出 1。"""

    def __init__(self, width: int) -> None:
        self.width = width
        self.linear = FixedLinear(
            tuple(1.0 for _ in range(width)),
            bias=-float(width - 1),
        )
        self.relu = FixedReLU()

    def __call__(self, bits: Sequence[int | float]) -> float:
        if len(bits) != self.width:
            raise ValueError("fixed AND input width mismatch")
        return self.relu(self.linear(bits))

    def submodules(self) -> tuple[object, ...]:
        return (self.linear, self.relu)


class _FixedAny:
    """仅当固定宽度输入至少一个为 1 时输出 1。"""

    def __init__(self, width: int) -> None:
        self.width = width
        self.sum_linear = FixedLinear(tuple(1.0 for _ in range(width)))
        self.shift_one = FixedLinear((1.0,), bias=-1.0)
        self.relu = FixedReLU()
        self.combine = FixedLinear((1.0, -1.0))

    def __call__(self, bits: Sequence[int | float]) -> float:
        if len(bits) != self.width:
            raise ValueError("fixed OR input width mismatch")
        total = self.relu(self.sum_linear(bits))
        excess = self.relu(self.shift_one(total))
        return self.combine((total, excess))

    def submodules(self) -> tuple[object, ...]:
        return (self.sum_linear, self.shift_one, self.relu, self.combine)


class _FixedVectorSubset:
    """直接检查 requested bit vector 是否为 authorized vector 的子集。"""

    def __init__(self, width: int) -> None:
        self.width = width
        self.differences = tuple(FixedLinear((1.0, -1.0)) for _ in range(width))
        self.relu = FixedReLU()
        self.no_violation = FixedLinear(
            tuple(-1.0 for _ in range(width)),
            bias=1.0,
        )

    def __call__(self, requested: bytes, authorized: bytes) -> int:
        if len(requested) != self.width or len(authorized) != self.width:
            raise ValueError("fixed subset input width mismatch")
        violations = tuple(
            self.relu(layer((requested_bit, authorized_bit)))
            for layer, requested_bit, authorized_bit in zip(
                self.differences,
                requested,
                authorized,
                strict=True,
            )
        )
        output = self.relu(self.no_violation(violations))
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (*self.differences, self.relu, self.no_violation)


class _FixedVectorEquality:
    """对固定宽度 uint8/int 向量直接计算逐坐标绝对差为零。"""

    def __init__(self, width: int) -> None:
        self.width = width
        self.left_differences = tuple(
            FixedLinear((1.0, -1.0)) for _ in range(width)
        )
        self.right_differences = tuple(
            FixedLinear((-1.0, 1.0)) for _ in range(width)
        )
        self.relu = FixedReLU()
        self.no_difference = FixedLinear(
            tuple(-1.0 for _ in range(width * 2)),
            bias=1.0,
        )

    def __call__(self, left: Sequence[int], right: Sequence[int]) -> int:
        if len(left) != self.width or len(right) != self.width:
            raise ValueError("fixed equality input width mismatch")
        differences: list[float] = []
        for left_layer, right_layer, left_value, right_value in zip(
            self.left_differences,
            self.right_differences,
            left,
            right,
            strict=True,
        ):
            differences.append(self.relu(left_layer((left_value, right_value))))
            differences.append(self.relu(right_layer((left_value, right_value))))
        output = self.relu(self.no_difference(differences))
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (
            *self.left_differences,
            *self.right_differences,
            self.relu,
            self.no_difference,
        )


class _FixedIntegerLessEqual:
    """对有界整数直接计算 left <= right。"""

    def __init__(self) -> None:
        self.delta = FixedLinear((-1.0, 1.0))
        self.margin = FixedLinear((-1.0, 1.0), bias=1.0)
        self.relu = FixedReLU()
        self.combine = FixedLinear((1.0, -1.0))

    def __call__(self, left: int, right: int) -> int:
        margin = self.relu(self.margin((left, right)))
        delta = self.relu(self.delta((left, right)))
        output = self.combine((margin, delta))
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (self.delta, self.margin, self.relu, self.combine)


class _FixedIntegerEquality:
    """通过两个固定小于等于门计算有界整数相等。"""

    def __init__(self) -> None:
        self.left_leq_right = _FixedIntegerLessEqual()
        self.right_leq_left = _FixedIntegerLessEqual()
        self.both = _FixedAll(2)

    def __call__(self, left: int, right: int) -> int:
        output = self.both(
            (
                self.left_leq_right(left, right),
                self.right_leq_left(right, left),
            )
        )
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (self.left_leq_right, self.right_leq_left, self.both)


class _FixedDelegationRelation:
    """直接计算 root 或单步衰减 delegation 的 digest/depth/scope 关系。"""

    def __init__(self, scope_width: int, flow_width: int) -> None:
        self.scope_width = scope_width
        self.flow_width = flow_width
        self.integer_equal = _FixedIntegerEquality()
        self.digest_equal = _FixedVectorEquality(RAW_AUTHORIZATION_DIGEST_BYTES)
        self.scope_equal_zero = _FixedVectorEquality(scope_width)
        self.scope_subset = _FixedVectorSubset(scope_width)
        self.flow_equal_zero = _FixedVectorEquality(flow_width)
        self.flow_subset = _FixedVectorSubset(flow_width)
        self.within_max = _FixedIntegerLessEqual()
        self.max_attenuated = _FixedIntegerLessEqual()
        self.parent_issued_before_child = _FixedIntegerLessEqual()
        self.child_expires_before_parent = _FixedIntegerLessEqual()
        self.parent_plus_one = FixedLinear((1.0,), bias=1.0)
        self.not_parent_present = FixedLinear((-1.0,), bias=1.0)
        self.root_all = _FixedAll(10)
        self.delegated_all = _FixedAll(9)
        self.root_or_delegated = _FixedAny(2)

    def __call__(
        self,
        *,
        parent_present: bool,
        delegation_depth: int,
        parent_delegation_depth: int,
        max_delegation_depth: int,
        parent_max_delegation_depth: int,
        signed_parent_digest: bytes,
        observed_parent_digest: bytes,
        child_scope_bits: bytes,
        parent_scope_bits: bytes,
        child_allowed_flow_bits: bytes,
        parent_allowed_flow_bits: bytes,
        issued_at_epoch: int,
        expires_at_epoch: int,
        parent_issued_at_epoch: int,
        parent_expires_at_epoch: int,
    ) -> int:
        zero_digest = bytes(RAW_AUTHORIZATION_DIGEST_BYTES)
        zero_scopes = bytes(self.scope_width)
        zero_flow = bytes(self.flow_width)
        root = self.root_all(
            (
                self.not_parent_present(int(parent_present)),
                self.integer_equal(delegation_depth, 0),
                self.integer_equal(parent_delegation_depth, 0),
                self.integer_equal(parent_max_delegation_depth, 0),
                self.digest_equal(signed_parent_digest, zero_digest),
                self.digest_equal(observed_parent_digest, zero_digest),
                self.scope_equal_zero(parent_scope_bits, zero_scopes),
                self.flow_equal_zero(parent_allowed_flow_bits, zero_flow),
                self.integer_equal(parent_issued_at_epoch, 0),
                self.integer_equal(parent_expires_at_epoch, 0),
            )
        )
        expected_child_depth = int(self.parent_plus_one(parent_delegation_depth))
        delegated = self.delegated_all(
            (
                int(parent_present),
                self.digest_equal(signed_parent_digest, observed_parent_digest),
                self.integer_equal(delegation_depth, expected_child_depth),
                self.within_max(delegation_depth, max_delegation_depth),
                self.max_attenuated(
                    max_delegation_depth,
                    parent_max_delegation_depth,
                ),
                self.scope_subset(child_scope_bits, parent_scope_bits),
                self.flow_subset(
                    child_allowed_flow_bits,
                    parent_allowed_flow_bits,
                ),
                self.parent_issued_before_child(
                    parent_issued_at_epoch,
                    issued_at_epoch,
                ),
                self.child_expires_before_parent(
                    expires_at_epoch,
                    parent_expires_at_epoch,
                ),
            )
        )
        output = self.root_or_delegated((root, delegated))
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (
            self.integer_equal,
            self.digest_equal,
            self.scope_equal_zero,
            self.scope_subset,
            self.flow_equal_zero,
            self.flow_subset,
            self.within_max,
            self.max_attenuated,
            self.parent_issued_before_child,
            self.child_expires_before_parent,
            self.parent_plus_one,
            self.not_parent_present,
            self.root_all,
            self.delegated_all,
            self.root_or_delegated,
        )


class _FixedTimeWindowRelation:
    """直接计算 issued <= observed <= expires 与有界 TTL。"""

    def __init__(self) -> None:
        self.less_equal = tuple(_FixedIntegerLessEqual() for _ in range(3))
        self.ttl_limit = FixedLinear((1.0, 1.0))
        self.all_relations = _FixedAll(3)

    def __call__(
        self,
        issued_at: int,
        observed_at: int,
        expires_at: int,
        max_ttl_seconds: int,
    ) -> int:
        latest_expiry = int(self.ttl_limit((issued_at, max_ttl_seconds)))
        output = self.all_relations(
            (
                self.less_equal[0](issued_at, observed_at),
                self.less_equal[1](observed_at, expires_at),
                self.less_equal[2](expires_at, latest_expiry),
            )
        )
        return 1 if output == 1.0 else 0

    def submodules(self) -> tuple[object, ...]:
        return (*self.less_equal, self.ttl_limit, self.all_relations)


def _predicate_evaluations(
    outputs: Sequence[int],
) -> tuple[RawAuthorizationPredicateEvaluation, ...]:
    """按固定顺序把关系输出绑定到稳定 reason。"""
    return tuple(
        RawAuthorizationPredicateEvaluation(
            relation_name=name,
            output=output,
            reject_reason=_RAW_RELATION_REASONS[name],
        )
        for name, output in zip(
            RAW_AUTHORIZATION_RELATION_NAMES,
            outputs,
            strict=True,
        )
    )


def _first_reject_reason(
    predicates: Sequence[RawAuthorizationPredicateEvaluation],
) -> str | None:
    """返回固定谓词顺序中的首个拒绝原因。"""
    for predicate in predicates:
        if predicate.output != 1:
            return predicate.reject_reason
    return None


def _reference_subset(requested: bytes, authorized: bytes) -> bool:
    """实现 reference bitset subset，供 fixed circuit differential 使用。"""
    return all(
        requested_bit <= authorized_bit
        for requested_bit, authorized_bit in zip(
            requested,
            authorized,
            strict=True,
        )
    )


def _validate_binary_vector(value: bytes, width: int, field_name: str) -> None:
    """验证固定长度的二值 uint8 向量。"""
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes")
    if len(value) != width:
        raise ValueError(f"{field_name} has the wrong width")
    if any(item not in (0, 1) for item in value):
        raise ValueError(f"{field_name} must contain only 0 or 1")


def _validate_uint(value: int, maximum: int, field_name: str) -> None:
    """验证有界内建无符号整数，拒绝 bool 和浮点替代。"""
    if type(value) is not int:
        raise TypeError(f"{field_name} must be a built-in integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{field_name} is outside the supported range")


def _validate_digest(value: bytes, field_name: str) -> None:
    """验证一个固定 SHA-256 长度摘要。"""
    if type(value) is not bytes or len(value) != RAW_AUTHORIZATION_DIGEST_BYTES:
        raise ValueError(f"{field_name} must be exactly 32 bytes")


def _validate_digest_tuple(value: tuple[bytes, ...], field_name: str) -> None:
    """验证固定顺序的全部 digest relation 输入。"""
    if type(value) is not tuple:
        raise TypeError(f"{field_name} must be a tuple")
    if len(value) != len(RAW_AUTHORIZATION_DIGEST_RELATIONS_V1):
        raise ValueError(f"{field_name} has the wrong relation count")
    for digest in value:
        _validate_digest(digest, field_name)


def _fixed_layer_stats(modules: Sequence[object]) -> tuple[int, int, int]:
    """递归统计固定 Linear/ReLU 层与固定参数数量。"""
    seen: set[int] = set()
    linear_layers = 0
    relu_layers = 0
    parameters = 0

    def visit(module: object) -> None:
        nonlocal linear_layers, relu_layers, parameters
        module_id = id(module)
        if module_id in seen:
            return
        seen.add(module_id)
        if type(module) is FixedLinear:
            linear_layers += 1
            parameters += len(module.weights) + 1
            return
        if type(module) is FixedReLU:
            relu_layers += 1
            return
        children = getattr(module, "submodules", None)
        if callable(children):
            for child in children():
                visit(child)

    for item in modules:
        visit(item)
    return linear_layers, relu_layers, parameters
