"""路线 B 的 typed authorization facts 与 B1 固定策略 shadow 电路。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable, Literal

from neural.shamir_layers import FixedLinear, FixedReLU
from pq.mldsa_route_b import MLDSARouteBVerificationEvidence


AUTHORIZATION_LAYOUT_ID_V1 = "saga-route-b-authorization-layout"
AUTHORIZATION_LAYOUT_VERSION_V1 = 1
AUTHORIZATION_POLICY_PROFILE_ID_V1 = "saga-route-b-reference-policy"
AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1 = (
    "saga-route-b-reference-policy-mutation"
)
AUTHORIZATION_POLICY_PROFILE_VERSION_V1 = 1
FIXED_POLICY_CIRCUIT_PROFILE_ID_V1 = "saga-route-b-fixed-policy-aggregator"
FIXED_POLICY_CIRCUIT_PROFILE_VERSION_V1 = 1

AuthorizationFactName = Literal[
    "standard_signature_valid",
    "request_envelope_valid",
    "scope_authorized",
    "flow_allowed",
    "delegation_allowed",
    "time_window_valid",
]
AuthorizationPredicateOperation = Literal["require_true"]

AUTHORIZATION_FACT_NAMES: tuple[AuthorizationFactName, ...] = (
    "standard_signature_valid",
    "request_envelope_valid",
    "scope_authorized",
    "flow_allowed",
    "delegation_allowed",
    "time_window_valid",
)

_STABLE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")


class AuthorizationFactSource(str, Enum):
    """限定每个授权事实只能来自受信运行时中的固定检查器。"""

    STANDARD_MLDSA_VERIFIER = "standard_mldsa_verifier"
    CANONICAL_ENVELOPE_VALIDATOR = "canonical_envelope_validator"
    LOCAL_SCOPE_POLICY = "local_scope_policy"
    LOCAL_FLOW_POLICY = "local_flow_policy"
    LOCAL_DELEGATION_POLICY = "local_delegation_policy"
    LOCAL_TIME_VALIDATOR = "local_time_validator"


_EXPECTED_FACT_SOURCES: dict[AuthorizationFactName, AuthorizationFactSource] = {
    "standard_signature_valid": AuthorizationFactSource.STANDARD_MLDSA_VERIFIER,
    "request_envelope_valid": AuthorizationFactSource.CANONICAL_ENVELOPE_VALIDATOR,
    "scope_authorized": AuthorizationFactSource.LOCAL_SCOPE_POLICY,
    "flow_allowed": AuthorizationFactSource.LOCAL_FLOW_POLICY,
    "delegation_allowed": AuthorizationFactSource.LOCAL_DELEGATION_POLICY,
    "time_window_valid": AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
}


@dataclass(frozen=True)
class AuthorizationFactProvenance:
    """记录内部事实检查器版本和对应 evidence 摘要。"""

    source: AuthorizationFactSource
    source_version: str
    evidence_digest: bytes

    def __post_init__(self) -> None:
        """拒绝未知来源、非规范版本和非 SHA-256 长度摘要。"""
        if not isinstance(self.source, AuthorizationFactSource):
            raise TypeError("source must use AuthorizationFactSource")
        if type(self.source_version) is not str or not _STABLE_ID_RE.fullmatch(
            self.source_version
        ):
            raise ValueError("source_version must be a stable non-empty identifier")
        if type(self.evidence_digest) is not bytes or len(self.evidence_digest) != 32:
            raise ValueError("evidence_digest must be exactly 32 bytes")


@dataclass(frozen=True)
class AuthorizationFact:
    """封装一个严格布尔授权事实及其受信内部来源。"""

    name: AuthorizationFactName
    value: bool
    provenance: AuthorizationFactProvenance

    def __post_init__(self) -> None:
        """拒绝未知事实、非原生布尔值和来源错配。"""
        if self.name not in AUTHORIZATION_FACT_NAMES:
            raise ValueError("unknown authorization fact name")
        if type(self.value) is not bool:
            raise TypeError("authorization fact value must be a built-in bool")
        if type(self.provenance) is not AuthorizationFactProvenance:
            raise TypeError("provenance must be AuthorizationFactProvenance")
        expected_source = _EXPECTED_FACT_SOURCES[self.name]
        if self.provenance.source is not expected_source:
            raise ValueError("authorization fact provenance source mismatch")


@dataclass(frozen=True)
class AuthorizationFactSet:
    """保存与版本化 layout 绑定且无重复项的授权事实集合。"""

    layout_id: str
    layout_version: int
    facts: tuple[AuthorizationFact, ...]

    def __post_init__(self) -> None:
        """在进入 reference policy 或 fixed circuit 前拒绝畸形集合。"""
        if type(self.layout_id) is not str or not self.layout_id:
            raise ValueError("layout_id must be non-empty text")
        if type(self.layout_version) is not int or self.layout_version <= 0:
            raise ValueError("layout_version must be a positive built-in integer")
        if type(self.facts) is not tuple:
            raise TypeError("facts must be a tuple")
        names: list[AuthorizationFactName] = []
        for fact in self.facts:
            if type(fact) is not AuthorizationFact:
                raise TypeError("facts must contain AuthorizationFact values")
            names.append(fact.name)
        if len(set(names)) != len(names):
            raise ValueError("authorization facts must not contain duplicates")

    def fact_map(self) -> dict[AuthorizationFactName, AuthorizationFact]:
        """按事实名导出新字典，供严格 layout 和 policy 查询。"""
        return {fact.name: fact for fact in self.facts}


@dataclass(frozen=True)
class AuthorizationInputField:
    """描述 V1 layout 中一个固定偏移的 uint8 布尔输入。"""

    name: AuthorizationFactName
    offset: int
    encoding: Literal["bool_uint8"] = "bool_uint8"

    def __post_init__(self) -> None:
        """确保字段名、偏移和编码均为 V1 支持的规范形式。"""
        if self.name not in AUTHORIZATION_FACT_NAMES:
            raise ValueError("unknown authorization input field")
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("field offset must be a non-negative built-in integer")
        if self.encoding != "bool_uint8":
            raise ValueError("V1 authorization fields must use bool_uint8")


@dataclass(frozen=True)
class AuthorizationInputLayout:
    """固定 V1 授权输入的字段顺序、长度和 uint8 编码边界。"""

    layout_id: str
    version: int
    fields: tuple[AuthorizationInputField, ...]

    def __post_init__(self) -> None:
        """未知版本、重复字段和非连续偏移在电路前 fail-closed。"""
        if self.layout_id != AUTHORIZATION_LAYOUT_ID_V1:
            raise ValueError("unsupported authorization layout id")
        if type(self.version) is not int or self.version != AUTHORIZATION_LAYOUT_VERSION_V1:
            raise ValueError("unsupported authorization layout version")
        if type(self.fields) is not tuple or not self.fields:
            raise ValueError("authorization layout fields must be a non-empty tuple")
        names: list[AuthorizationFactName] = []
        for expected_offset, field in enumerate(self.fields):
            if type(field) is not AuthorizationInputField:
                raise TypeError("layout fields must use AuthorizationInputField")
            if field.offset != expected_offset:
                raise ValueError("authorization layout offsets must be contiguous")
            names.append(field.name)
        if len(set(names)) != len(names):
            raise ValueError("authorization layout fields must be unique")
        if tuple(names) != AUTHORIZATION_FACT_NAMES:
            raise ValueError("V1 authorization layout must contain all facts in order")

    @property
    def encoded_bytes(self) -> int:
        """返回固定编码长度；V1 每个布尔事实占一个 uint8。"""
        return len(self.fields)

    def encode(self, fact_set: AuthorizationFactSet) -> bytes:
        """验证 layout、完整性和 provenance 后生成规范 uint8 输入。"""
        if type(fact_set) is not AuthorizationFactSet:
            raise TypeError("fact_set must be AuthorizationFactSet")
        if (
            fact_set.layout_id != self.layout_id
            or fact_set.layout_version != self.version
        ):
            raise ValueError("authorization fact-set layout mismatch")
        fact_map = fact_set.fact_map()
        expected_names = tuple(field.name for field in self.fields)
        if set(fact_map) != set(expected_names):
            raise ValueError("authorization fact set has missing or unknown fields")
        payload = bytes(1 if fact_map[name].value else 0 for name in expected_names)
        self.validate_encoded(payload)
        return payload

    def validate_encoded(self, payload: bytes) -> tuple[int, ...]:
        """拒绝非 bytes、错误长度和非二值 uint8，并返回整数向量。"""
        if type(payload) is not bytes:
            raise TypeError("encoded authorization input must be bytes")
        if len(payload) != self.encoded_bytes:
            raise ValueError("encoded authorization input has the wrong length")
        if any(value not in (0, 1) for value in payload):
            raise ValueError("encoded authorization input must contain only 0 or 1")
        return tuple(payload)


@dataclass(frozen=True)
class AuthorizationPredicate:
    """描述 predicate IR 中一个只接受真实布尔事实的固定谓词。"""

    predicate_id: str
    fact_name: AuthorizationFactName
    operation: AuthorizationPredicateOperation
    reject_reason: str

    def __post_init__(self) -> None:
        """拒绝未知事实、操作或不稳定的 predicate/reason 标识。"""
        if type(self.predicate_id) is not str or not _STABLE_ID_RE.fullmatch(
            self.predicate_id
        ):
            raise ValueError("predicate_id must be a stable identifier")
        if self.fact_name not in AUTHORIZATION_FACT_NAMES:
            raise ValueError("predicate references an unknown authorization fact")
        if self.operation != "require_true":
            raise ValueError("unsupported authorization predicate operation")
        if type(self.reject_reason) is not str or not _STABLE_ID_RE.fullmatch(
            self.reject_reason
        ):
            raise ValueError("reject_reason must be a stable identifier")


@dataclass(frozen=True)
class AuthorizationPredicateIR:
    """绑定 layout、policy profile 与有序 require-true 谓词列表。"""

    policy_profile_id: str
    policy_profile_version: int
    layout_id: str
    layout_version: int
    predicates: tuple[AuthorizationPredicate, ...]

    def __post_init__(self) -> None:
        """未知 profile/layout、空列表和重复谓词均在编译前拒绝。"""
        if self.policy_profile_id not in {
            AUTHORIZATION_POLICY_PROFILE_ID_V1,
            AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1,
        }:
            raise ValueError("unsupported authorization policy profile id")
        if (
            type(self.policy_profile_version) is not int
            or self.policy_profile_version != AUTHORIZATION_POLICY_PROFILE_VERSION_V1
        ):
            raise ValueError("unsupported authorization policy profile version")
        if self.layout_id != AUTHORIZATION_LAYOUT_ID_V1:
            raise ValueError("predicate IR layout id mismatch")
        if (
            type(self.layout_version) is not int
            or self.layout_version != AUTHORIZATION_LAYOUT_VERSION_V1
        ):
            raise ValueError("predicate IR layout version mismatch")
        if type(self.predicates) is not tuple or not self.predicates:
            raise ValueError("predicate IR must contain at least one predicate")
        predicate_ids: list[str] = []
        fact_names: list[AuthorizationFactName] = []
        for predicate in self.predicates:
            if type(predicate) is not AuthorizationPredicate:
                raise TypeError("predicate IR entries must use AuthorizationPredicate")
            predicate_ids.append(predicate.predicate_id)
            fact_names.append(predicate.fact_name)
        if len(set(predicate_ids)) != len(predicate_ids):
            raise ValueError("predicate IR predicate ids must be unique")
        if len(set(fact_names)) != len(fact_names):
            raise ValueError("predicate IR fact references must be unique")
        if self.policy_profile_id == AUTHORIZATION_POLICY_PROFILE_ID_V1:
            if tuple(fact_names) != AUTHORIZATION_FACT_NAMES:
                raise ValueError(
                    "canonical V1 policy must contain all predicates in order"
                )
        else:
            canonical_offsets = tuple(
                AUTHORIZATION_FACT_NAMES.index(name) for name in fact_names
            )
            if (
                len(fact_names) >= len(AUTHORIZATION_FACT_NAMES)
                or canonical_offsets != tuple(sorted(canonical_offsets))
            ):
                raise ValueError(
                    "research mutation policy must be an ordered strict subset"
                )


@dataclass(frozen=True)
class PredicateEvaluation:
    """记录 reference/fixed policy 对单个谓词的可定位结果。"""

    predicate_id: str
    fact_name: AuthorizationFactName
    input_value: int
    output: int
    reject_reason: str


@dataclass(frozen=True)
class ReferenceAuthorizationDecision:
    """记录普通 reference policy 的接受结果和稳定 reason mapping。"""

    accepted: bool
    reason: str
    predicates: tuple[PredicateEvaluation, ...]


@dataclass(frozen=True)
class FixedCircuitComplexity:
    """记录 B1 固定聚合器的结构复杂度，不伪装成运行时测量。"""

    circuit_profile_id: str
    circuit_profile_version: int
    input_count: int
    input_bytes: int
    predicate_count: int
    fixed_linear_layers: int
    fixed_relu_layers: int
    fixed_parameter_count: int
    circuit_depth: int

    def as_dict(self) -> dict[str, int | str]:
        """导出稳定、可序列化的结构复杂度 manifest。"""
        return {
            "circuit_profile_id": self.circuit_profile_id,
            "circuit_profile_version": self.circuit_profile_version,
            "input_count": self.input_count,
            "input_bytes": self.input_bytes,
            "predicate_count": self.predicate_count,
            "fixed_linear_layers": self.fixed_linear_layers,
            "fixed_relu_layers": self.fixed_relu_layers,
            "fixed_parameter_count": self.fixed_parameter_count,
            "circuit_depth": self.circuit_depth,
        }


@dataclass(frozen=True)
class FixedPolicyTrace:
    """记录 B1 输入、逐谓词输出、固定层中间值和最终硬输出。"""

    input_valid: bool
    layout_id: str
    layout_version: int
    policy_profile_id: str
    policy_profile_version: int
    circuit_profile_id: str
    circuit_profile_version: int
    encoded_input: tuple[int, ...]
    predicates: tuple[PredicateEvaluation, ...]
    affine_output: float
    relu_output: float
    accept_output: int
    reason: str


@dataclass(frozen=True)
class FixedPolicyDecision:
    """记录固定聚合器结果；只有内建整数 1 对应 accepted=True。"""

    accepted: bool
    reason: str
    output: int
    trace: FixedPolicyTrace
    complexity: FixedCircuitComplexity


@dataclass(frozen=True)
class FixedPolicyShadowEvidence:
    """记录 B1 reference equivalence；shadow evidence 永远不授予执行权。"""

    mode: Literal["shadow_only"]
    equivalent: bool
    reason_mapping_equivalent: bool
    outside_standard_signature_valid: bool
    signature_fact_matches_outside: bool
    reference_decision: ReferenceAuthorizationDecision
    fixed_decision: FixedPolicyDecision
    authority_granted: Literal[False]
    reason: str

    def __post_init__(self) -> None:
        """禁止任何调用方把 B1 shadow evidence 标记为可执行 authority。"""
        if self.mode != "shadow_only":
            raise ValueError("B1 evidence mode must remain shadow_only")
        if self.authority_granted is not False:
            raise ValueError("B1 shadow evidence cannot grant authority")


@dataclass(frozen=True)
class FixedPolicyShadowMismatch:
    """记录 corpus 中一项 reference/fixed 不一致，不保存请求材料。"""

    case_index: int
    reference_accepted: bool
    reference_reason: str
    fixed_accepted: bool
    fixed_reason: str
    shadow_reason: str


@dataclass(frozen=True)
class PredicateCoverage:
    """统计一个 predicate 在 shadow corpus 中的 true/false 覆盖。"""

    predicate_id: str
    true_count: int
    false_count: int


@dataclass(frozen=True)
class FixedPolicyEquivalenceManifest:
    """汇总 B1 shadow corpus 的等价性、覆盖和结构复杂度。"""

    mode: Literal["shadow_only"]
    total_cases: int
    equivalent_cases: int
    mismatch_count: int
    authority_granted_count: int
    predicate_coverage: tuple[PredicateCoverage, ...]
    mismatches: tuple[FixedPolicyShadowMismatch, ...]
    complexity: FixedCircuitComplexity

    @property
    def all_equivalent(self) -> bool:
        """仅当 corpus 非空且没有不一致时返回 True。"""
        return self.total_cases > 0 and self.mismatch_count == 0

    def as_dict(self) -> dict[str, object]:
        """导出可机器读取的 preliminary reference-equivalence manifest。"""
        return {
            "mode": self.mode,
            "total_cases": self.total_cases,
            "equivalent_cases": self.equivalent_cases,
            "mismatch_count": self.mismatch_count,
            "authority_granted_count": self.authority_granted_count,
            "all_equivalent": self.all_equivalent,
            "predicate_coverage": [
                {
                    "predicate_id": coverage.predicate_id,
                    "true_count": coverage.true_count,
                    "false_count": coverage.false_count,
                }
                for coverage in self.predicate_coverage
            ],
            "mismatches": [
                {
                    "case_index": mismatch.case_index,
                    "reference_accepted": mismatch.reference_accepted,
                    "reference_reason": mismatch.reference_reason,
                    "fixed_accepted": mismatch.fixed_accepted,
                    "fixed_reason": mismatch.fixed_reason,
                    "shadow_reason": mismatch.shadow_reason,
                }
                for mismatch in self.mismatches
            ],
            "complexity": self.complexity.as_dict(),
        }


class ReferenceAuthorizationPolicy:
    """按完整 V1 predicate IR 顺序计算普通布尔 reference decision。"""

    def __init__(
        self,
        layout: AuthorizationInputLayout,
        predicate_ir: AuthorizationPredicateIR,
    ) -> None:
        """绑定规范 layout，并要求 reference policy 覆盖全部 V1 事实。"""
        _validate_layout_ir_pair(layout, predicate_ir)
        if predicate_ir.policy_profile_id != AUTHORIZATION_POLICY_PROFILE_ID_V1:
            raise ValueError("reference policy must cover all V1 facts in order")
        self.layout = layout
        self.predicate_ir = predicate_ir

    def evaluate(self, fact_set: AuthorizationFactSet) -> ReferenceAuthorizationDecision:
        """严格验证 typed facts，并返回普通 reference policy 结果。"""
        try:
            encoded = self.layout.validate_encoded(self.layout.encode(fact_set))
        except (TypeError, ValueError):
            return ReferenceAuthorizationDecision(
                False,
                "reference_policy_input_invalid",
                (),
            )
        values = {
            field.name: encoded[field.offset]
            for field in self.layout.fields
        }
        predicates, first_reject = _evaluate_predicates(self.predicate_ir, values)
        return ReferenceAuthorizationDecision(
            first_reject is None,
            first_reject or "reference_policy_accept",
            predicates,
        )


class FixedPolicyAggregator:
    """用固定 Linear+ReLU 对 typed predicate bits 执行 B1 AND 聚合。"""

    def __init__(
        self,
        layout: AuthorizationInputLayout,
        predicate_ir: AuthorizationPredicateIR,
    ) -> None:
        """编译固定全一权重和阈值，不创建训练参数或执行 authority。"""
        _validate_layout_ir_pair(layout, predicate_ir)
        self.layout = layout
        self.predicate_ir = predicate_ir
        predicate_count = len(predicate_ir.predicates)
        self.and_linear = FixedLinear(
            tuple(1.0 for _ in range(predicate_count)),
            bias=-float(predicate_count - 1),
        )
        self.and_relu = FixedReLU()
        self.requires_grad = False

    def evaluate(self, fact_set: AuthorizationFactSet) -> FixedPolicyDecision:
        """验证 typed/provenanced facts，并且只接受固定电路精确输出整数 1。"""
        complexity = self.complexity_manifest()
        try:
            encoded = self.layout.validate_encoded(self.layout.encode(fact_set))
        except (TypeError, ValueError):
            trace = self._invalid_trace("fixed_policy_input_invalid")
            return FixedPolicyDecision(False, trace.reason, 0, trace, complexity)

        values = {
            field.name: encoded[field.offset]
            for field in self.layout.fields
        }
        predicates, first_reject = _evaluate_predicates(self.predicate_ir, values)
        predicate_outputs = tuple(predicate.output for predicate in predicates)
        affine_output = self.and_linear(predicate_outputs)
        relu_output = self.and_relu(affine_output)
        accept_output = 1 if relu_output == 1.0 else 0
        accepted = type(accept_output) is int and accept_output == 1
        reason = first_reject or (
            "fixed_policy_accept" if accepted else "fixed_policy_output_invalid"
        )
        trace = FixedPolicyTrace(
            input_valid=True,
            layout_id=self.layout.layout_id,
            layout_version=self.layout.version,
            policy_profile_id=self.predicate_ir.policy_profile_id,
            policy_profile_version=self.predicate_ir.policy_profile_version,
            circuit_profile_id=FIXED_POLICY_CIRCUIT_PROFILE_ID_V1,
            circuit_profile_version=FIXED_POLICY_CIRCUIT_PROFILE_VERSION_V1,
            encoded_input=encoded,
            predicates=predicates,
            affine_output=affine_output,
            relu_output=relu_output,
            accept_output=accept_output,
            reason=reason,
        )
        return FixedPolicyDecision(accepted, reason, accept_output, trace, complexity)

    def complexity_manifest(self) -> FixedCircuitComplexity:
        """返回固定层数、参数数和输入尺寸的结构 manifest。"""
        predicate_count = len(self.predicate_ir.predicates)
        return FixedCircuitComplexity(
            circuit_profile_id=FIXED_POLICY_CIRCUIT_PROFILE_ID_V1,
            circuit_profile_version=FIXED_POLICY_CIRCUIT_PROFILE_VERSION_V1,
            input_count=len(self.layout.fields),
            input_bytes=self.layout.encoded_bytes,
            predicate_count=predicate_count,
            fixed_linear_layers=1,
            fixed_relu_layers=1,
            fixed_parameter_count=predicate_count + 1,
            circuit_depth=2,
        )

    def submodules(self) -> tuple[object, ...]:
        """返回固定 Linear/ReLU 子模块，供不可训练状态审计。"""
        return (self.and_linear, self.and_relu)

    def _invalid_trace(self, reason: str) -> FixedPolicyTrace:
        """构造不含异常文本或请求材料的统一输入拒绝 trace。"""
        return FixedPolicyTrace(
            input_valid=False,
            layout_id=self.layout.layout_id,
            layout_version=self.layout.version,
            policy_profile_id=self.predicate_ir.policy_profile_id,
            policy_profile_version=self.predicate_ir.policy_profile_version,
            circuit_profile_id=FIXED_POLICY_CIRCUIT_PROFILE_ID_V1,
            circuit_profile_version=FIXED_POLICY_CIRCUIT_PROFILE_VERSION_V1,
            encoded_input=(),
            predicates=(),
            affine_output=0.0,
            relu_output=0.0,
            accept_output=0,
            reason=reason,
        )


class FixedPolicyShadowEvaluator:
    """比较 reference 与 B1 fixed policy，且不暴露 Context 或 sink 回调。"""

    def __init__(
        self,
        reference_policy: ReferenceAuthorizationPolicy,
        aggregator: FixedPolicyAggregator,
    ) -> None:
        """要求两条 shadow 路径绑定完全相同的 layout 和 predicate IR。"""
        if type(reference_policy) is not ReferenceAuthorizationPolicy:
            raise TypeError("reference_policy must be ReferenceAuthorizationPolicy")
        if type(aggregator) is not FixedPolicyAggregator:
            raise TypeError("aggregator must be FixedPolicyAggregator")
        if (
            reference_policy.layout != aggregator.layout
            or reference_policy.predicate_ir != aggregator.predicate_ir
        ):
            raise ValueError("shadow paths must use the same layout and predicate IR")
        self.reference_policy = reference_policy
        self.aggregator = aggregator

    def evaluate(
        self,
        fact_set: AuthorizationFactSet,
        standard_signature_evidence: MLDSARouteBVerificationEvidence,
    ) -> FixedPolicyShadowEvidence:
        """生成不授予执行权的单样本 reference-equivalence evidence。"""
        outside_signature_valid = (
            type(standard_signature_evidence) is MLDSARouteBVerificationEvidence
            and standard_signature_evidence.accepted is True
            and standard_signature_evidence.reason == "signature_valid"
        )
        signature_fact_value = _signature_fact_value(fact_set)
        signature_fact_matches_outside = (
            signature_fact_value is not None
            and signature_fact_value is outside_signature_valid
        )
        reference_decision = self.reference_policy.evaluate(fact_set)
        fixed_decision = self.aggregator.evaluate(fact_set)
        reason_mapping_equivalent = (
            reference_decision.accepted
            and fixed_decision.accepted
        ) or (
            not reference_decision.accepted
            and not fixed_decision.accepted
            and reference_decision.reason == fixed_decision.reason
        )
        equivalent = (
            reference_decision.accepted == fixed_decision.accepted
            and reason_mapping_equivalent
        )
        if not signature_fact_matches_outside:
            reason = "standard_signature_fact_mismatch"
            equivalent = False
        elif not equivalent:
            reason = "reference_equivalence_mismatch"
        else:
            reason = "reference_equivalent"
        return FixedPolicyShadowEvidence(
            mode="shadow_only",
            equivalent=equivalent,
            reason_mapping_equivalent=reason_mapping_equivalent,
            outside_standard_signature_valid=outside_signature_valid,
            signature_fact_matches_outside=signature_fact_matches_outside,
            reference_decision=reference_decision,
            fixed_decision=fixed_decision,
            authority_granted=False,
            reason=reason,
        )

    def evaluate_corpus(
        self,
        cases: Iterable[
            tuple[AuthorizationFactSet, MLDSARouteBVerificationEvidence]
        ],
    ) -> FixedPolicyEquivalenceManifest:
        """汇总固定顺序 corpus 的等价性、predicate 覆盖和 shadow 无授权证据。"""
        coverage_counts = {
            predicate.predicate_id: [0, 0]
            for predicate in self.reference_policy.predicate_ir.predicates
        }
        mismatches: list[FixedPolicyShadowMismatch] = []
        total_cases = 0
        equivalent_cases = 0
        authority_granted_count = 0
        for case_index, (fact_set, signature_evidence) in enumerate(cases):
            evidence = self.evaluate(fact_set, signature_evidence)
            total_cases += 1
            equivalent_cases += int(evidence.equivalent)
            authority_granted_count += int(evidence.authority_granted)
            for predicate in evidence.reference_decision.predicates:
                counts = coverage_counts[predicate.predicate_id]
                counts[0 if predicate.output == 1 else 1] += 1
            if not evidence.equivalent:
                mismatches.append(
                    FixedPolicyShadowMismatch(
                        case_index=case_index,
                        reference_accepted=evidence.reference_decision.accepted,
                        reference_reason=evidence.reference_decision.reason,
                        fixed_accepted=evidence.fixed_decision.accepted,
                        fixed_reason=evidence.fixed_decision.reason,
                        shadow_reason=evidence.reason,
                    )
                )
        coverage = tuple(
            PredicateCoverage(
                predicate_id=predicate.predicate_id,
                true_count=coverage_counts[predicate.predicate_id][0],
                false_count=coverage_counts[predicate.predicate_id][1],
            )
            for predicate in self.reference_policy.predicate_ir.predicates
        )
        return FixedPolicyEquivalenceManifest(
            mode="shadow_only",
            total_cases=total_cases,
            equivalent_cases=equivalent_cases,
            mismatch_count=len(mismatches),
            authority_granted_count=authority_granted_count,
            predicate_coverage=coverage,
            mismatches=tuple(mismatches),
            complexity=self.aggregator.complexity_manifest(),
        )


def build_authorization_input_layout_v1() -> AuthorizationInputLayout:
    """构造路线 B B0.5 的规范六字段 typed input layout。"""
    return AuthorizationInputLayout(
        layout_id=AUTHORIZATION_LAYOUT_ID_V1,
        version=AUTHORIZATION_LAYOUT_VERSION_V1,
        fields=tuple(
            AuthorizationInputField(name=name, offset=offset)
            for offset, name in enumerate(AUTHORIZATION_FACT_NAMES)
        ),
    )


def build_authorization_predicate_ir_v1() -> AuthorizationPredicateIR:
    """构造与 V1 layout 同序且带稳定拒绝 reason 的 reference predicate IR。"""
    reject_reasons = {
        "standard_signature_valid": "standard_signature_invalid",
        "request_envelope_valid": "request_envelope_invalid",
        "scope_authorized": "scope_not_authorized",
        "flow_allowed": "flow_policy_denied",
        "delegation_allowed": "delegation_policy_denied",
        "time_window_valid": "time_window_invalid",
    }
    return AuthorizationPredicateIR(
        policy_profile_id=AUTHORIZATION_POLICY_PROFILE_ID_V1,
        policy_profile_version=AUTHORIZATION_POLICY_PROFILE_VERSION_V1,
        layout_id=AUTHORIZATION_LAYOUT_ID_V1,
        layout_version=AUTHORIZATION_LAYOUT_VERSION_V1,
        predicates=tuple(
            AuthorizationPredicate(
                predicate_id=name,
                fact_name=name,
                operation="require_true",
                reject_reason=reject_reasons[name],
            )
            for name in AUTHORIZATION_FACT_NAMES
        ),
    )


def build_reference_authorization_policy_v1() -> ReferenceAuthorizationPolicy:
    """构造完整 V1 reference policy，作为 B1 shadow 的普通软件 oracle。"""
    return ReferenceAuthorizationPolicy(
        build_authorization_input_layout_v1(),
        build_authorization_predicate_ir_v1(),
    )


def build_fixed_policy_aggregator_v1() -> FixedPolicyAggregator:
    """构造 B1 固定聚合器；该对象本身不连接 Coordinator 或 protected sink。"""
    return FixedPolicyAggregator(
        build_authorization_input_layout_v1(),
        build_authorization_predicate_ir_v1(),
    )


def build_fixed_policy_shadow_evaluator_v1() -> FixedPolicyShadowEvaluator:
    """构造共享同一 layout/IR 的 reference 与 fixed shadow 比较器。"""
    layout = build_authorization_input_layout_v1()
    predicate_ir = build_authorization_predicate_ir_v1()
    return FixedPolicyShadowEvaluator(
        ReferenceAuthorizationPolicy(layout, predicate_ir),
        FixedPolicyAggregator(layout, predicate_ir),
    )


def _validate_layout_ir_pair(
    layout: AuthorizationInputLayout,
    predicate_ir: AuthorizationPredicateIR,
) -> None:
    """确认编译器只组合相同版本的严格 layout 与 predicate IR。"""
    if type(layout) is not AuthorizationInputLayout:
        raise TypeError("layout must be AuthorizationInputLayout")
    if type(predicate_ir) is not AuthorizationPredicateIR:
        raise TypeError("predicate_ir must be AuthorizationPredicateIR")
    if (
        layout.layout_id != predicate_ir.layout_id
        or layout.version != predicate_ir.layout_version
    ):
        raise ValueError("authorization layout and predicate IR do not match")
    layout_names = {field.name for field in layout.fields}
    if any(predicate.fact_name not in layout_names for predicate in predicate_ir.predicates):
        raise ValueError("predicate IR references a fact outside the layout")


def _evaluate_predicates(
    predicate_ir: AuthorizationPredicateIR,
    values: dict[AuthorizationFactName, int],
) -> tuple[tuple[PredicateEvaluation, ...], str | None]:
    """按固定顺序计算 require-true 谓词并保留第一个稳定拒绝原因。"""
    evaluations: list[PredicateEvaluation] = []
    first_reject: str | None = None
    for predicate in predicate_ir.predicates:
        input_value = values[predicate.fact_name]
        output = 1 if input_value == 1 else 0
        if output != 1 and first_reject is None:
            first_reject = predicate.reject_reason
        evaluations.append(
            PredicateEvaluation(
                predicate_id=predicate.predicate_id,
                fact_name=predicate.fact_name,
                input_value=input_value,
                output=output,
                reject_reason=predicate.reject_reason,
            )
        )
    return tuple(evaluations), first_reject


def _signature_fact_value(fact_set: object) -> bool | None:
    """安全读取标准签名事实；畸形集合只返回 None。"""
    if type(fact_set) is not AuthorizationFactSet:
        return None
    fact = fact_set.fact_map().get("standard_signature_valid")
    if type(fact) is not AuthorizationFact or type(fact.value) is not bool:
        return None
    return fact.value
