"""把真实 Route B 签名与 runtime 请求编译为 B1 facts 和 B2 原始关系。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal

from neural.fixed_authorization import (
    RAW_AUTHORIZATION_FLOW_LABELS_V1,
    RAW_AUTHORIZATION_LAYOUT_ID_V1,
    RAW_AUTHORIZATION_LAYOUT_VERSION_V1,
    RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1,
    RAW_AUTHORIZATION_SCOPE_FAMILIES_V1,
    FixedAuthorizationCircuitV1,
    FixedAuthorizationRelationDecision,
    RouteBRawAuthorizationInputV1,
)
from neural.fixed_policy import (
    AUTHORIZATION_FACT_NAMES,
    AUTHORIZATION_LAYOUT_ID_V1,
    AUTHORIZATION_LAYOUT_VERSION_V1,
    AuthorizationFact,
    AuthorizationFactName,
    AuthorizationFactProvenance,
    AuthorizationFactSet,
    AuthorizationFactSource,
    FixedPolicyAggregator,
    FixedPolicyDecision,
    FixedPolicyShadowEvidence,
    FixedPolicyShadowEvaluator,
    build_fixed_policy_aggregator_v1,
    build_fixed_policy_shadow_evaluator_v1,
)
from pq.mldsa_route_b import (
    MLDSABackendDescriptorV1,
    MLDSARouteBVerificationEvidence,
    MLDSARouteBVerifier,
)
from pq.signature_binding import SignatureBindingV1, SignatureRouteId
from saga.messages import (
    RequestEnvelope,
    action_scopes_are_attenuated,
    action_scopes_allow,
    flow_policy_allowed_labels,
    flow_policy_allows_egress,
    normalize_flow_labels,
    parse_action_scope,
    scope_constraints_allow,
    scope_constraints_are_attenuated,
)


ROUTE_B_FACT_COMPILER_ID_V1 = "saga-route-b-trusted-fact-compiler"
ROUTE_B_FACT_COMPILER_VERSION_V1 = 1
ROUTE_B_RAW_AUTHORIZATION_COMPILER_ID_V1 = (
    "saga-route-b-raw-authorization-compiler"
)
ROUTE_B_RAW_AUTHORIZATION_COMPILER_VERSION_V1 = 1


@dataclass(frozen=True)
class RouteBShadowRequest:
    """保存 B1 shadow 所需的 canonical envelope 和 transport 摘要快照。"""

    binding: SignatureBindingV1
    envelope: RequestEnvelope
    sender_aid: str
    receiver_aid: str
    token_digest: bytes
    message_digest: bytes
    action_scope: str
    observed_at: datetime
    parameters: Mapping[str, Any] | None = None
    flow_labels: tuple[str, ...] = ("public",)
    parent_envelope: RequestEnvelope | None = None

    def __post_init__(self) -> None:
        """冻结 JSON 参数、标签和 UTC 时间，拒绝非规范 runtime snapshot。"""
        if type(self.binding) is not SignatureBindingV1:
            raise TypeError("binding must be SignatureBindingV1")
        if type(self.envelope) is not RequestEnvelope:
            raise TypeError("envelope must be RequestEnvelope")
        for field_name, value in (
            ("sender_aid", self.sender_aid),
            ("receiver_aid", self.receiver_aid),
        ):
            if type(value) is not str or not value:
                raise ValueError(f"{field_name} must be non-empty text")
        for field_name, value in (
            ("token_digest", self.token_digest),
            ("message_digest", self.message_digest),
        ):
            if type(value) is not bytes or len(value) != 32:
                raise ValueError(f"{field_name} must be exactly 32 bytes")
        if type(self.action_scope) is not str:
            raise TypeError("action_scope must be text")
        parse_action_scope(self.action_scope)
        if type(self.observed_at) is not datetime or self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be a timezone-aware datetime")
        if self.parent_envelope is not None and type(self.parent_envelope) is not RequestEnvelope:
            raise TypeError("parent_envelope must be RequestEnvelope or None")
        if self.parameters is not None and not isinstance(self.parameters, Mapping):
            raise TypeError("parameters must be a mapping or None")
        try:
            parameters_json = json.dumps(
                dict(self.parameters or {}),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            parameters = json.loads(parameters_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("parameters must be canonical JSON values") from exc
        if type(self.flow_labels) is not tuple:
            raise TypeError("flow_labels must be a tuple")
        normalized_labels = normalize_flow_labels(self.flow_labels)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "flow_labels", normalized_labels)
        object.__setattr__(
            self,
            "observed_at",
            self.observed_at.astimezone(timezone.utc),
        )


@dataclass(frozen=True)
class RouteBFactCompilationTrace:
    """记录一个 runtime fact 的稳定结果、reason、来源和 evidence 摘要。"""

    fact_name: AuthorizationFactName
    value: bool
    reason: str
    source: AuthorizationFactSource
    evidence_digest: bytes

    def as_dict(self) -> dict[str, object]:
        """导出不包含 token/message/signature 原文的机器可读 trace。"""
        return {
            "fact_name": self.fact_name,
            "value": self.value,
            "reason": self.reason,
            "source": self.source.value,
            "evidence_digest": self.evidence_digest.hex(),
        }


@dataclass(frozen=True)
class RouteBCompiledAuthorizationFacts:
    """汇总受信 compiler 生成的规范 fact set 与逐事实 trace。"""

    compiler_id: str
    compiler_version: int
    fact_set: AuthorizationFactSet
    traces: tuple[RouteBFactCompilationTrace, ...]

    def trace_map(self) -> dict[AuthorizationFactName, RouteBFactCompilationTrace]:
        """按固定事实名导出 trace 字典，便于 shadow corpus 统计。"""
        return {trace.fact_name: trace for trace in self.traces}

    def as_dict(self) -> dict[str, object]:
        """导出 compiler 身份和非敏感事实摘要。"""
        return {
            "compiler_id": self.compiler_id,
            "compiler_version": self.compiler_version,
            "traces": [trace.as_dict() for trace in self.traces],
        }


@dataclass(frozen=True)
class RouteBCompiledRawAuthorizationInput:
    """封装受信 compiler 生成的 B2 原始关系输入与 provenance 摘要。"""

    compiler_id: str
    compiler_version: int
    raw_input: RouteBRawAuthorizationInputV1
    source_digest: bytes

    def __post_init__(self) -> None:
        """拒绝错误 compiler 身份、布局类型或非 SHA-256 provenance。"""
        if self.compiler_id != ROUTE_B_RAW_AUTHORIZATION_COMPILER_ID_V1:
            raise ValueError("unsupported raw authorization compiler id")
        if (
            type(self.compiler_version) is not int
            or self.compiler_version
            != ROUTE_B_RAW_AUTHORIZATION_COMPILER_VERSION_V1
        ):
            raise ValueError("unsupported raw authorization compiler version")
        if type(self.raw_input) is not RouteBRawAuthorizationInputV1:
            raise TypeError("raw_input must be RouteBRawAuthorizationInputV1")
        if type(self.source_digest) is not bytes or len(self.source_digest) != 32:
            raise ValueError("source_digest must be exactly 32 bytes")
        if self.source_digest != self.raw_input.digest():
            raise ValueError("source_digest must match the canonical raw input")

    def as_dict(self) -> dict[str, object]:
        """导出 compiler、布局和摘要，不复制请求身份或 transport 原文。"""
        return {
            "compiler_id": self.compiler_id,
            "compiler_version": self.compiler_version,
            "layout_id": self.raw_input.layout_id,
            "layout_version": self.raw_input.layout_version,
            "source_digest": self.source_digest.hex(),
        }


@dataclass(frozen=True)
class RouteBFixedPolicyShadowRouteEvidence:
    """组合 R6 标准验签与 B1 shadow，且永远不携带执行 authority。"""

    mode: Literal["route_b_fixed_policy_shadow"]
    signature_evidence: MLDSARouteBVerificationEvidence
    compiled_facts: RouteBCompiledAuthorizationFacts
    shadow_evidence: FixedPolicyShadowEvidence
    authority_granted: Literal[False]

    def __post_init__(self) -> None:
        """禁止 Route B shadow adapter 被重标记为 enforcement evidence。"""
        if self.mode != "route_b_fixed_policy_shadow":
            raise ValueError("Route B fixed-policy route must remain shadow-only")
        if self.authority_granted is not False:
            raise ValueError("Route B fixed-policy shadow cannot grant authority")

    def as_dict(self) -> dict[str, object]:
        """导出不包含 public key、签名或 backend 异常文本的 evidence 摘要。"""
        return {
            "mode": self.mode,
            "signature_accepted": self.signature_evidence.accepted,
            "signature_reason": self.signature_evidence.reason,
            "compiled_facts": self.compiled_facts.as_dict(),
            "reference_accepted": self.shadow_evidence.reference_decision.accepted,
            "reference_reason": self.shadow_evidence.reference_decision.reason,
            "fixed_accepted": self.shadow_evidence.fixed_decision.accepted,
            "fixed_reason": self.shadow_evidence.fixed_decision.reason,
            "equivalent": self.shadow_evidence.equivalent,
            "authority_granted": self.authority_granted,
        }


@dataclass(frozen=True)
class RouteBFixedPolicyEnforcementEvidence:
    """记录 B1.5 强制 AND 结果，但不创建或携带执行 authority。"""

    mode: Literal["route_b_fixed_policy_enforced"]
    accepted: bool
    reason: str
    signature_evidence: MLDSARouteBVerificationEvidence
    compiled_facts: RouteBCompiledAuthorizationFacts
    fixed_decision: FixedPolicyDecision
    outside_standard_signature_valid: bool
    signature_fact_matches_outside: bool
    coordinator_commit_required: Literal[True]
    authority_granted: Literal[False]

    def __post_init__(self) -> None:
        """重算强制公式，拒绝伪造接受位、非精确整数输出或 authority 标记。"""
        if self.mode != "route_b_fixed_policy_enforced":
            raise ValueError("Route B enforcement evidence requires the B1.5 mode")
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be a built-in bool")
        if type(self.signature_evidence) is not MLDSARouteBVerificationEvidence:
            raise TypeError("signature_evidence must be MLDSARouteBVerificationEvidence")
        if type(self.compiled_facts) is not RouteBCompiledAuthorizationFacts:
            raise TypeError("compiled_facts must be RouteBCompiledAuthorizationFacts")
        if type(self.fixed_decision) is not FixedPolicyDecision:
            raise TypeError("fixed_decision must be FixedPolicyDecision")
        if type(self.outside_standard_signature_valid) is not bool:
            raise TypeError("outside_standard_signature_valid must be a built-in bool")
        if type(self.signature_fact_matches_outside) is not bool:
            raise TypeError("signature_fact_matches_outside must be a built-in bool")
        if self.coordinator_commit_required is not True:
            raise ValueError("Route B evidence must require Coordinator commit")
        if self.authority_granted is not False:
            raise ValueError("Route B evidence cannot grant execution authority")

        signature_fact = _compiled_signature_fact_value(self.compiled_facts)
        outside_valid = _outside_signature_valid(self.signature_evidence)
        signature_fact_matches = (
            signature_fact is not None and signature_fact is outside_valid
        )
        fixed_output_is_one = (
            type(self.fixed_decision.output) is int
            and self.fixed_decision.output == 1
        )
        expected_accept = (
            outside_valid
            and signature_fact_matches
            and self.fixed_decision.accepted is True
            and fixed_output_is_one
        )
        expected_reason = _route_b_enforcement_reason(
            outside_valid=outside_valid,
            signature_fact_matches=signature_fact_matches,
            fixed_decision=self.fixed_decision,
            accepted=expected_accept,
        )
        if self.outside_standard_signature_valid is not outside_valid:
            raise ValueError("outside signature result does not match strict evidence")
        if self.signature_fact_matches_outside is not signature_fact_matches:
            raise ValueError("signature fact match flag is inconsistent")
        if self.accepted is not expected_accept:
            raise ValueError("accepted does not match the Route B enforcement formula")
        if self.reason != expected_reason:
            raise ValueError("reason does not match the Route B enforcement formula")

    def as_dict(self) -> dict[str, object]:
        """导出不含密钥、签名、token 或 message 原文的强制判定摘要。"""
        return {
            "mode": self.mode,
            "accepted": self.accepted,
            "reason": self.reason,
            "signature_accepted": self.signature_evidence.accepted,
            "signature_reason": self.signature_evidence.reason,
            "compiled_facts": self.compiled_facts.as_dict(),
            "fixed_accepted": self.fixed_decision.accepted,
            "fixed_reason": self.fixed_decision.reason,
            "fixed_output": self.fixed_decision.output,
            "outside_standard_signature_valid": (
                self.outside_standard_signature_valid
            ),
            "signature_fact_matches_outside": self.signature_fact_matches_outside,
            "coordinator_commit_required": self.coordinator_commit_required,
            "authority_granted": self.authority_granted,
        }


@dataclass(frozen=True)
class RouteBFixedAuthorizationCircuitEvidence:
    """组合 B1.5 与 B2 原始关系电路，且不携带执行 authority。"""

    mode: Literal["route_b_fixed_authorization_circuit"]
    accepted: bool
    reason: str
    policy_evidence: RouteBFixedPolicyEnforcementEvidence
    compiled_raw_input: RouteBCompiledRawAuthorizationInput
    relation_decision: FixedAuthorizationRelationDecision
    raw_signature_matches_outside: bool
    coordinator_commit_required: Literal[True]
    authority_granted: Literal[False]

    def __post_init__(self) -> None:
        """重算 B1.5/B2 AND，防止伪造签名位、输出位或 authority。"""
        if self.mode != "route_b_fixed_authorization_circuit":
            raise ValueError("Route B B2 evidence requires the fixed-circuit mode")
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be a built-in bool")
        if type(self.policy_evidence) is not RouteBFixedPolicyEnforcementEvidence:
            raise TypeError(
                "policy_evidence must be RouteBFixedPolicyEnforcementEvidence"
            )
        if type(self.compiled_raw_input) is not RouteBCompiledRawAuthorizationInput:
            raise TypeError(
                "compiled_raw_input must be RouteBCompiledRawAuthorizationInput"
            )
        if type(self.relation_decision) is not FixedAuthorizationRelationDecision:
            raise TypeError(
                "relation_decision must be FixedAuthorizationRelationDecision"
            )
        if type(self.raw_signature_matches_outside) is not bool:
            raise TypeError("raw_signature_matches_outside must be a built-in bool")
        if self.coordinator_commit_required is not True:
            raise ValueError("Route B B2 evidence must require Coordinator commit")
        if self.authority_granted is not False:
            raise ValueError("Route B B2 evidence cannot grant execution authority")

        outside_valid = self.policy_evidence.outside_standard_signature_valid
        raw_signature_matches = (
            self.compiled_raw_input.raw_input.standard_signature_valid
            is outside_valid
        )
        relation_output_is_one = (
            type(self.relation_decision.output) is int
            and self.relation_decision.output == 1
        )
        expected_accept = (
            self.policy_evidence.accepted is True
            and raw_signature_matches
            and self.relation_decision.accepted is True
            and relation_output_is_one
        )
        expected_reason = _route_b_fixed_authorization_reason(
            policy_evidence=self.policy_evidence,
            raw_signature_matches=raw_signature_matches,
            relation_decision=self.relation_decision,
            accepted=expected_accept,
        )
        if self.raw_signature_matches_outside is not raw_signature_matches:
            raise ValueError("raw signature match flag is inconsistent")
        if self.accepted is not expected_accept:
            raise ValueError("accepted does not match the Route B B2 formula")
        if self.reason != expected_reason:
            raise ValueError("reason does not match the Route B B2 formula")

    def as_dict(self) -> dict[str, object]:
        """导出不含密钥、签名、AID、token 或 message 原文的 B2 摘要。"""
        return {
            "mode": self.mode,
            "accepted": self.accepted,
            "reason": self.reason,
            "policy_evidence": self.policy_evidence.as_dict(),
            "compiled_raw_input": self.compiled_raw_input.as_dict(),
            "relation_decision": self.relation_decision.as_dict(),
            "raw_signature_matches_outside": self.raw_signature_matches_outside,
            "coordinator_commit_required": self.coordinator_commit_required,
            "authority_granted": self.authority_granted,
        }


@dataclass(frozen=True)
class RouteBShadowCorpusCaseSummary:
    """记录一个真实 Route B shadow case 的非敏感结果摘要。"""

    case_id: str
    signature_accepted: bool
    fixed_accepted: bool
    fixed_reason: str
    equivalent: bool
    authority_granted: bool
    false_facts: tuple[AuthorizationFactName, ...]

    def as_dict(self) -> dict[str, object]:
        """导出不含 public key、签名或 transport 原文的 case summary。"""
        return {
            "case_id": self.case_id,
            "signature_accepted": self.signature_accepted,
            "fixed_accepted": self.fixed_accepted,
            "fixed_reason": self.fixed_reason,
            "equivalent": self.equivalent,
            "authority_granted": self.authority_granted,
            "false_facts": list(self.false_facts),
        }


@dataclass(frozen=True)
class RouteBShadowCorpusManifest:
    """汇总真实 Route B shadow corpus 的等价性、事实覆盖和无 authority 证据。"""

    mode: Literal["route_b_fixed_policy_shadow"]
    total_cases: int
    signature_accepted_count: int
    fixed_accepted_count: int
    equivalent_count: int
    mismatch_count: int
    authority_granted_count: int
    fact_false_counts: tuple[tuple[AuthorizationFactName, int], ...]
    cases: tuple[RouteBShadowCorpusCaseSummary, ...]

    @property
    def all_equivalent(self) -> bool:
        """仅当 corpus 非空且所有 case 等价时返回 True。"""
        return self.total_cases > 0 and self.mismatch_count == 0

    def as_dict(self) -> dict[str, object]:
        """导出稳定 JSON manifest，供后续 runner 和论文统计复用。"""
        return {
            "mode": self.mode,
            "total_cases": self.total_cases,
            "signature_accepted_count": self.signature_accepted_count,
            "fixed_accepted_count": self.fixed_accepted_count,
            "equivalent_count": self.equivalent_count,
            "mismatch_count": self.mismatch_count,
            "authority_granted_count": self.authority_granted_count,
            "all_equivalent": self.all_equivalent,
            "fact_false_counts": dict(self.fact_false_counts),
            "cases": [case.as_dict() for case in self.cases],
        }


class RouteBTrustedFactCompiler:
    """由受信软件检查 canonical runtime facts，并生成带 provenance 的 B1 输入。"""

    def compile(
        self,
        request: RouteBShadowRequest,
        signature_evidence: MLDSARouteBVerificationEvidence,
    ) -> RouteBCompiledAuthorizationFacts:
        """计算六项事实；不确定输入只产生 false fact，不授予 authority。"""
        if type(request) is not RouteBShadowRequest:
            raise TypeError("request must be RouteBShadowRequest")
        if type(signature_evidence) is not MLDSARouteBVerificationEvidence:
            raise TypeError(
                "signature_evidence must be MLDSARouteBVerificationEvidence"
            )
        traces = (
            self._signature_trace(request, signature_evidence),
            self._envelope_trace(request),
            self._scope_trace(request),
            self._flow_trace(request),
            self._delegation_trace(request),
            self._time_trace(request),
        )
        facts = tuple(
            AuthorizationFact(
                name=trace.fact_name,
                value=trace.value,
                provenance=AuthorizationFactProvenance(
                    source=trace.source,
                    source_version=f"{ROUTE_B_FACT_COMPILER_ID_V1}-v1",
                    evidence_digest=trace.evidence_digest,
                ),
            )
            for trace in traces
        )
        return RouteBCompiledAuthorizationFacts(
            compiler_id=ROUTE_B_FACT_COMPILER_ID_V1,
            compiler_version=ROUTE_B_FACT_COMPILER_VERSION_V1,
            fact_set=AuthorizationFactSet(
                layout_id=AUTHORIZATION_LAYOUT_ID_V1,
                layout_version=AUTHORIZATION_LAYOUT_VERSION_V1,
                facts=facts,
            ),
            traces=traces,
        )

    def _signature_trace(
        self,
        request: RouteBShadowRequest,
        evidence: MLDSARouteBVerificationEvidence,
    ) -> RouteBFactCompilationTrace:
        """只把带匹配 descriptor 的严格 R6 valid evidence 编译为 true。"""
        descriptor = evidence.descriptor
        value = (
            evidence.accepted is True
            and evidence.reason == "signature_valid"
            and type(descriptor) is MLDSABackendDescriptorV1
            and descriptor.available is True
            and descriptor.algorithm_id is request.binding.algorithm_id
            and descriptor.profile_id is request.binding.profile_id
        )
        reason = "standard_signature_valid" if value else "standard_signature_invalid"
        descriptor_payload: dict[str, object] | None = None
        if type(descriptor) is MLDSABackendDescriptorV1:
            descriptor_payload = {
                "backend_name": descriptor.backend_name,
                "backend_version": descriptor.backend_version,
                "provider_name": descriptor.provider_name,
                "provider_version": descriptor.provider_version,
                "api_version": descriptor.api_version,
                "algorithm_id": int(descriptor.algorithm_id),
                "profile_id": int(descriptor.profile_id),
                "context_digest": hashlib.sha256(descriptor.context).hexdigest(),
                "available": descriptor.available,
            }
        return _trace(
            "standard_signature_valid",
            value,
            reason,
            AuthorizationFactSource.STANDARD_MLDSA_VERIFIER,
            {
                "binding_digest": hashlib.sha256(
                    request.binding.canonical_bytes()
                ).hexdigest(),
                "descriptor": descriptor_payload,
                "evidence_reason": evidence.reason,
            },
        )

    def _envelope_trace(
        self,
        request: RouteBShadowRequest,
    ) -> RouteBFactCompilationTrace:
        """核对 binding digest 与 transport sender/receiver/token/message/action。"""
        envelope = request.envelope
        checks = {
            "route_b_binding": request.binding.route_id
            is SignatureRouteId.ROUTE_B_STANDARD,
            "binding_digest": request.binding.envelope_digest == envelope.digest(),
            "sender_aid": envelope.sender_aid == request.sender_aid,
            "receiver_aid": envelope.receiver_aid == request.receiver_aid,
            "token_digest": envelope.token_digest == request.token_digest.hex(),
            "message_digest": envelope.message_digest == request.message_digest.hex(),
            "action_scope": envelope.action_scope == request.action_scope,
        }
        value = all(checks.values())
        reason = "request_envelope_valid" if value else "request_envelope_mismatch"
        return _trace(
            "request_envelope_valid",
            value,
            reason,
            AuthorizationFactSource.CANONICAL_ENVELOPE_VALIDATOR,
            {
                "binding_envelope_digest": request.binding.envelope_digest.hex(),
                "envelope_digest": envelope.hex_digest(),
                "transport_token_digest": request.token_digest.hex(),
                "transport_message_digest": request.message_digest.hex(),
                "checks": checks,
            },
        )

    def _scope_trace(
        self,
        request: RouteBShadowRequest,
    ) -> RouteBFactCompilationTrace:
        """用 signed scope 和封闭参数约束计算本地 scope 软件事实。"""
        try:
            value = action_scopes_allow(
                request.envelope.authorized_scopes,
                request.action_scope,
            ) and scope_constraints_allow(
                request.envelope.authorized_scopes,
                request.envelope.scope_constraints,
                request.action_scope,
                request.parameters,
            )
            reason = "scope_authorized" if value else "scope_not_authorized"
        except (TypeError, ValueError):
            value = False
            reason = "scope_input_invalid"
        return _trace(
            "scope_authorized",
            value,
            reason,
            AuthorizationFactSource.LOCAL_SCOPE_POLICY,
            {
                "envelope_digest": request.envelope.hex_digest(),
                "action_scope": request.action_scope,
                "parameters_digest": _json_digest(request.parameters),
            },
        )

    def _flow_trace(
        self,
        request: RouteBShadowRequest,
    ) -> RouteBFactCompilationTrace:
        """按 signed flow policy 与 runtime labels 计算 egress 软件事实。"""
        try:
            value = flow_policy_allows_egress(
                request.envelope.flow_policy,
                request.action_scope,
                request.flow_labels,
            )
            reason = "flow_allowed" if value else "flow_policy_denied"
        except (TypeError, ValueError):
            value = False
            reason = "flow_input_invalid"
        return _trace(
            "flow_allowed",
            value,
            reason,
            AuthorizationFactSource.LOCAL_FLOW_POLICY,
            {
                "envelope_digest": request.envelope.hex_digest(),
                "action_scope": request.action_scope,
                "flow_labels": list(request.flow_labels),
            },
        )

    def _delegation_trace(
        self,
        request: RouteBShadowRequest,
    ) -> RouteBFactCompilationTrace:
        """核对父 digest/scope/constraint 与 delegation depth 收窄关系。"""
        envelope = request.envelope
        parent = request.parent_envelope
        is_delegated = envelope.delegation_depth > 0 or bool(
            envelope.parent_envelope_digest
        )
        if not is_delegated:
            value = (
                parent is None
                and envelope.delegation_depth == 0
                and not envelope.parent_envelope_digest
                and not envelope.parent_authorized_scopes
                and not envelope.parent_scope_constraints
            )
        elif parent is None:
            value = False
        else:
            value = (
                envelope.parent_envelope_digest == parent.hex_digest()
                and tuple(envelope.parent_authorized_scopes)
                == tuple(parent.authorized_scopes)
                and envelope.parent_scope_constraints == parent.scope_constraints
                and envelope.delegation_depth == parent.delegation_depth + 1
                and envelope.delegation_depth <= envelope.max_delegation_depth
                and action_scopes_are_attenuated(
                    parent.authorized_scopes,
                    envelope.authorized_scopes,
                )
                and scope_constraints_are_attenuated(
                    parent.authorized_scopes,
                    parent.scope_constraints,
                    envelope.authorized_scopes,
                    envelope.scope_constraints,
                )
            )
        reason = "delegation_allowed" if value else "delegation_policy_denied"
        return _trace(
            "delegation_allowed",
            value,
            reason,
            AuthorizationFactSource.LOCAL_DELEGATION_POLICY,
            {
                "envelope_digest": envelope.hex_digest(),
                "parent_digest": parent.hex_digest() if parent is not None else None,
                "signed_parent_digest": envelope.parent_envelope_digest,
                "delegation_depth": envelope.delegation_depth,
                "max_delegation_depth": envelope.max_delegation_depth,
            },
        )

    def _time_trace(
        self,
        request: RouteBShadowRequest,
    ) -> RouteBFactCompilationTrace:
        """按 UTC observed time 检查 issued/expires 有序且包含当前时间。"""
        issued_at = datetime.fromisoformat(
            request.envelope.issued_at.replace("Z", "+00:00")
        )
        expires_at = datetime.fromisoformat(
            request.envelope.expires_at.replace("Z", "+00:00")
        )
        value = issued_at <= request.observed_at <= expires_at
        reason = "time_window_valid" if value else "time_window_invalid"
        return _trace(
            "time_window_valid",
            value,
            reason,
            AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
            {
                "envelope_digest": request.envelope.hex_digest(),
                "issued_at": request.envelope.issued_at,
                "expires_at": request.envelope.expires_at,
                "observed_at": request.observed_at.isoformat(),
            },
        )


class RouteBRawAuthorizationCompiler:
    """把 signed envelope 与 runtime snapshot 编译为 B2 固定宽度原始输入。"""

    def compile(
        self,
        request: RouteBShadowRequest,
        signature_evidence: MLDSARouteBVerificationEvidence,
    ) -> RouteBCompiledRawAuthorizationInput:
        """直接编码 scope/flow/delegation/time/digest 关系，不预计算授权结果。"""
        if type(request) is not RouteBShadowRequest:
            raise TypeError("request must be RouteBShadowRequest")
        if type(signature_evidence) is not MLDSARouteBVerificationEvidence:
            raise TypeError(
                "signature_evidence must be MLDSARouteBVerificationEvidence"
            )
        envelope = request.envelope
        parent = request.parent_envelope
        issued_at = _timestamp_epoch(envelope.issued_at)
        expires_at = _timestamp_epoch(envelope.expires_at)
        observed_at = _timestamp_epoch(request.observed_at)
        requested_scope_base, _ = parse_action_scope(request.action_scope)
        requested_scope_bits = _scope_family_bits((requested_scope_base,))
        authorized_scope_bits = _scope_family_bits(envelope.authorized_scopes)
        parent_scope_bits = _scope_family_bits(
            parent.authorized_scopes if parent is not None else ()
        )
        flow_label_bits = _flow_label_bits(request.flow_labels, reject_unknown=True)
        allowed_flow_label_bits = _flow_label_bits(
            flow_policy_allowed_labels(envelope.flow_policy, request.action_scope),
            reject_unknown=False,
        )
        parent_allowed_flow_label_bits = _flow_label_bits(
            flow_policy_allowed_labels(parent.flow_policy, request.action_scope)
            if parent is not None
            else (),
            reject_unknown=False,
        )
        zero_digest = bytes(32)
        raw_input = RouteBRawAuthorizationInputV1(
            layout_id=RAW_AUTHORIZATION_LAYOUT_ID_V1,
            layout_version=RAW_AUTHORIZATION_LAYOUT_VERSION_V1,
            standard_signature_valid=_strict_signature_input_value(
                request,
                signature_evidence,
            ),
            requested_scope_bits=requested_scope_bits,
            authorized_scope_bits=authorized_scope_bits,
            flow_label_bits=flow_label_bits,
            allowed_flow_label_bits=allowed_flow_label_bits,
            parent_allowed_flow_label_bits=parent_allowed_flow_label_bits,
            parent_present=parent is not None,
            delegation_depth=envelope.delegation_depth,
            parent_delegation_depth=(
                parent.delegation_depth if parent is not None else 0
            ),
            max_delegation_depth=envelope.max_delegation_depth,
            parent_max_delegation_depth=(
                parent.max_delegation_depth if parent is not None else 0
            ),
            signed_parent_digest=(
                _decode_digest(envelope.parent_envelope_digest)
                if envelope.parent_envelope_digest
                else zero_digest
            ),
            observed_parent_digest=(parent.digest() if parent is not None else zero_digest),
            parent_scope_bits=parent_scope_bits,
            issued_at_epoch=issued_at,
            observed_at_epoch=observed_at,
            expires_at_epoch=expires_at,
            parent_issued_at_epoch=(
                _timestamp_epoch(parent.issued_at) if parent is not None else 0
            ),
            parent_expires_at_epoch=(
                _timestamp_epoch(parent.expires_at) if parent is not None else 0
            ),
            max_ttl_seconds=RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1,
            bound_digests=(
                request.binding.envelope_digest,
                _text_digest(envelope.sender_aid),
                _text_digest(envelope.receiver_aid),
                _decode_digest(envelope.token_digest),
                _decode_digest(envelope.message_digest),
                _text_digest(envelope.action_scope),
            ),
            observed_digests=(
                envelope.digest(),
                _text_digest(request.sender_aid),
                _text_digest(request.receiver_aid),
                request.token_digest,
                request.message_digest,
                _text_digest(request.action_scope),
            ),
        )
        return RouteBCompiledRawAuthorizationInput(
            compiler_id=ROUTE_B_RAW_AUTHORIZATION_COMPILER_ID_V1,
            compiler_version=ROUTE_B_RAW_AUTHORIZATION_COMPILER_VERSION_V1,
            raw_input=raw_input,
            source_digest=raw_input.digest(),
        )


class RouteBFixedPolicyShadowRoute:
    """组合严格 R6 verifier、受信 fact compiler 和 B1 shadow evaluator。"""

    def __init__(
        self,
        signature_verifier: MLDSARouteBVerifier,
        *,
        fact_compiler: RouteBTrustedFactCompiler | None = None,
        shadow_evaluator: FixedPolicyShadowEvaluator | None = None,
    ) -> None:
        """保存无状态 evaluate 组件；不接收 replay store 或 Context factory。"""
        if type(signature_verifier) is not MLDSARouteBVerifier:
            raise TypeError("signature_verifier must be MLDSARouteBVerifier")
        if fact_compiler is not None and type(fact_compiler) is not RouteBTrustedFactCompiler:
            raise TypeError("fact_compiler must be RouteBTrustedFactCompiler")
        if (
            shadow_evaluator is not None
            and type(shadow_evaluator) is not FixedPolicyShadowEvaluator
        ):
            raise TypeError("shadow_evaluator must be FixedPolicyShadowEvaluator")
        self.signature_verifier = signature_verifier
        self.fact_compiler = fact_compiler or RouteBTrustedFactCompiler()
        self.shadow_evaluator = (
            shadow_evaluator or build_fixed_policy_shadow_evaluator_v1()
        )

    def evaluate(
        self,
        request: RouteBShadowRequest,
        public_key: bytes,
        signature: bytes,
    ) -> RouteBFixedPolicyShadowRouteEvidence:
        """先执行 R6 标准验签，再生成 B1 shadow evidence；不提交任何状态。"""
        if type(request) is not RouteBShadowRequest:
            raise TypeError("request must be RouteBShadowRequest")
        signature_evidence = self.signature_verifier.verify(
            request.binding,
            public_key,
            signature,
        )
        compiled_facts = self.fact_compiler.compile(request, signature_evidence)
        shadow_evidence = self.shadow_evaluator.evaluate(
            compiled_facts.fact_set,
            signature_evidence,
        )
        return RouteBFixedPolicyShadowRouteEvidence(
            mode="route_b_fixed_policy_shadow",
            signature_evidence=signature_evidence,
            compiled_facts=compiled_facts,
            shadow_evidence=shadow_evidence,
            authority_granted=False,
        )


class RouteBFixedPolicyEnforcedRoute:
    """执行 B1.5 标准验签与固定授权策略的无状态强制 AND。"""

    def __init__(
        self,
        signature_verifier: MLDSARouteBVerifier,
        *,
        fact_compiler: RouteBTrustedFactCompiler | None = None,
        fixed_policy: FixedPolicyAggregator | None = None,
    ) -> None:
        """保存受信组件；replay reserve 和 Context 创建仍只属于 Coordinator。"""
        if type(signature_verifier) is not MLDSARouteBVerifier:
            raise TypeError("signature_verifier must be MLDSARouteBVerifier")
        if fact_compiler is not None and type(fact_compiler) is not RouteBTrustedFactCompiler:
            raise TypeError("fact_compiler must be RouteBTrustedFactCompiler")
        if fixed_policy is not None and type(fixed_policy) is not FixedPolicyAggregator:
            raise TypeError("fixed_policy must be FixedPolicyAggregator")
        self.signature_verifier = signature_verifier
        self.fact_compiler = fact_compiler or RouteBTrustedFactCompiler()
        self.fixed_policy = fixed_policy or build_fixed_policy_aggregator_v1()

    def evaluate(
        self,
        request: RouteBShadowRequest,
        public_key: bytes,
        signature: bytes,
    ) -> RouteBFixedPolicyEnforcementEvidence:
        """计算标准验签与 fixed policy 的 AND，不提交 replay 或执行状态。"""
        if type(request) is not RouteBShadowRequest:
            raise TypeError("request must be RouteBShadowRequest")
        signature_evidence = self.signature_verifier.verify(
            request.binding,
            public_key,
            signature,
        )
        compiled_facts = self.fact_compiler.compile(request, signature_evidence)
        fixed_decision = self.fixed_policy.evaluate(compiled_facts.fact_set)
        return _build_fixed_policy_enforcement_evidence(
            signature_evidence=signature_evidence,
            compiled_facts=compiled_facts,
            fixed_decision=fixed_decision,
        )


class RouteBFixedAuthorizationCircuitRoute:
    """执行标准 ML-DSA、B1.5 软件事实 AND 与 B2 原始关系固定电路。"""

    def __init__(
        self,
        signature_verifier: MLDSARouteBVerifier,
        *,
        fact_compiler: RouteBTrustedFactCompiler | None = None,
        fixed_policy: FixedPolicyAggregator | None = None,
        raw_compiler: RouteBRawAuthorizationCompiler | None = None,
        relation_circuit: FixedAuthorizationCircuitV1 | None = None,
    ) -> None:
        """保存无状态受信组件；replay reserve 与 Context 仍只属于 Coordinator。"""
        if type(signature_verifier) is not MLDSARouteBVerifier:
            raise TypeError("signature_verifier must be MLDSARouteBVerifier")
        if fact_compiler is not None and type(fact_compiler) is not RouteBTrustedFactCompiler:
            raise TypeError("fact_compiler must be RouteBTrustedFactCompiler")
        if fixed_policy is not None and type(fixed_policy) is not FixedPolicyAggregator:
            raise TypeError("fixed_policy must be FixedPolicyAggregator")
        if raw_compiler is not None and type(raw_compiler) is not RouteBRawAuthorizationCompiler:
            raise TypeError("raw_compiler must be RouteBRawAuthorizationCompiler")
        if (
            relation_circuit is not None
            and type(relation_circuit) is not FixedAuthorizationCircuitV1
        ):
            raise TypeError(
                "relation_circuit must be FixedAuthorizationCircuitV1"
            )
        self.signature_verifier = signature_verifier
        self.fact_compiler = fact_compiler or RouteBTrustedFactCompiler()
        self.fixed_policy = fixed_policy or build_fixed_policy_aggregator_v1()
        self.raw_compiler = raw_compiler or RouteBRawAuthorizationCompiler()
        self.relation_circuit = relation_circuit or FixedAuthorizationCircuitV1()

    def evaluate(
        self,
        request: RouteBShadowRequest,
        public_key: bytes,
        signature: bytes,
    ) -> RouteBFixedAuthorizationCircuitEvidence:
        """对一次严格验签同时计算 B1.5 与 B2，最终仅返回待提交 evidence。"""
        if type(request) is not RouteBShadowRequest:
            raise TypeError("request must be RouteBShadowRequest")
        signature_evidence = self.signature_verifier.verify(
            request.binding,
            public_key,
            signature,
        )
        compiled_facts = self.fact_compiler.compile(request, signature_evidence)
        fixed_decision = self.fixed_policy.evaluate(compiled_facts.fact_set)
        policy_evidence = _build_fixed_policy_enforcement_evidence(
            signature_evidence=signature_evidence,
            compiled_facts=compiled_facts,
            fixed_decision=fixed_decision,
        )
        compiled_raw_input = self.raw_compiler.compile(
            request,
            signature_evidence,
        )
        relation_decision = self.relation_circuit.evaluate(
            compiled_raw_input.raw_input
        )
        raw_signature_matches = (
            compiled_raw_input.raw_input.standard_signature_valid
            is policy_evidence.outside_standard_signature_valid
        )
        relation_output_is_one = (
            type(relation_decision.output) is int
            and relation_decision.output == 1
        )
        accepted = (
            policy_evidence.accepted is True
            and raw_signature_matches
            and relation_decision.accepted is True
            and relation_output_is_one
        )
        reason = _route_b_fixed_authorization_reason(
            policy_evidence=policy_evidence,
            raw_signature_matches=raw_signature_matches,
            relation_decision=relation_decision,
            accepted=accepted,
        )
        return RouteBFixedAuthorizationCircuitEvidence(
            mode="route_b_fixed_authorization_circuit",
            accepted=accepted,
            reason=reason,
            policy_evidence=policy_evidence,
            compiled_raw_input=compiled_raw_input,
            relation_decision=relation_decision,
            raw_signature_matches_outside=raw_signature_matches,
            coordinator_commit_required=True,
            authority_granted=False,
        )


def summarize_route_b_shadow_corpus(
    cases: Iterable[tuple[str, RouteBFixedPolicyShadowRouteEvidence]],
) -> RouteBShadowCorpusManifest:
    """汇总已完成的真实 shadow evidence，并拒绝重复或非规范 case id。"""
    summaries: list[RouteBShadowCorpusCaseSummary] = []
    seen_ids: set[str] = set()
    false_counts = {name: 0 for name in AUTHORIZATION_FACT_NAMES}
    signature_accepted_count = 0
    fixed_accepted_count = 0
    equivalent_count = 0
    authority_granted_count = 0
    for case_id, evidence in cases:
        if type(case_id) is not str or not case_id or case_id in seen_ids:
            raise ValueError("shadow corpus case ids must be unique non-empty text")
        if type(evidence) is not RouteBFixedPolicyShadowRouteEvidence:
            raise TypeError(
                "shadow corpus cases must use RouteBFixedPolicyShadowRouteEvidence"
            )
        seen_ids.add(case_id)
        trace_map = evidence.compiled_facts.trace_map()
        false_facts = tuple(
            name for name in AUTHORIZATION_FACT_NAMES if not trace_map[name].value
        )
        for name in false_facts:
            false_counts[name] += 1
        signature_accepted_count += int(evidence.signature_evidence.accepted)
        fixed_accepted_count += int(evidence.shadow_evidence.fixed_decision.accepted)
        equivalent_count += int(evidence.shadow_evidence.equivalent)
        authority_granted_count += int(evidence.authority_granted)
        summaries.append(
            RouteBShadowCorpusCaseSummary(
                case_id=case_id,
                signature_accepted=evidence.signature_evidence.accepted,
                fixed_accepted=evidence.shadow_evidence.fixed_decision.accepted,
                fixed_reason=evidence.shadow_evidence.fixed_decision.reason,
                equivalent=evidence.shadow_evidence.equivalent,
                authority_granted=evidence.authority_granted,
                false_facts=false_facts,
            )
        )
    total_cases = len(summaries)
    return RouteBShadowCorpusManifest(
        mode="route_b_fixed_policy_shadow",
        total_cases=total_cases,
        signature_accepted_count=signature_accepted_count,
        fixed_accepted_count=fixed_accepted_count,
        equivalent_count=equivalent_count,
        mismatch_count=total_cases - equivalent_count,
        authority_granted_count=authority_granted_count,
        fact_false_counts=tuple(
            (name, false_counts[name]) for name in AUTHORIZATION_FACT_NAMES
        ),
        cases=tuple(summaries),
    )


def _build_fixed_policy_enforcement_evidence(
    *,
    signature_evidence: MLDSARouteBVerificationEvidence,
    compiled_facts: RouteBCompiledAuthorizationFacts,
    fixed_decision: FixedPolicyDecision,
) -> RouteBFixedPolicyEnforcementEvidence:
    """按唯一公式构造 B1.5 evidence，供 B1.5 和 B2 route 共同复用。"""
    outside_valid = _outside_signature_valid(signature_evidence)
    signature_fact = _compiled_signature_fact_value(compiled_facts)
    signature_fact_matches = (
        signature_fact is not None and signature_fact is outside_valid
    )
    fixed_output_is_one = (
        type(fixed_decision.output) is int and fixed_decision.output == 1
    )
    accepted = (
        outside_valid
        and signature_fact_matches
        and fixed_decision.accepted is True
        and fixed_output_is_one
    )
    reason = _route_b_enforcement_reason(
        outside_valid=outside_valid,
        signature_fact_matches=signature_fact_matches,
        fixed_decision=fixed_decision,
        accepted=accepted,
    )
    return RouteBFixedPolicyEnforcementEvidence(
        mode="route_b_fixed_policy_enforced",
        accepted=accepted,
        reason=reason,
        signature_evidence=signature_evidence,
        compiled_facts=compiled_facts,
        fixed_decision=fixed_decision,
        outside_standard_signature_valid=outside_valid,
        signature_fact_matches_outside=signature_fact_matches,
        coordinator_commit_required=True,
        authority_granted=False,
    )


def _strict_signature_input_value(
    request: RouteBShadowRequest,
    evidence: MLDSARouteBVerificationEvidence,
) -> bool:
    """只把匹配 binding profile 的严格标准验签 evidence 编译为 B2 输入 1。"""
    descriptor = evidence.descriptor
    return (
        evidence.accepted is True
        and evidence.reason == "signature_valid"
        and type(descriptor) is MLDSABackendDescriptorV1
        and descriptor.available is True
        and descriptor.algorithm_id is request.binding.algorithm_id
        and descriptor.profile_id is request.binding.profile_id
    )


def _scope_family_bits(scopes: Iterable[str]) -> bytes:
    """把动作 scope 映射为固定族 bitset；限定符仍由 B1.5 精确检查。"""
    indexes = {
        scope: index
        for index, scope in enumerate(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1)
    }
    bits = bytearray(len(RAW_AUTHORIZATION_SCOPE_FAMILIES_V1))
    for scope in scopes:
        base, _ = parse_action_scope(scope)
        bits[indexes[base]] = 1
    return bytes(bits)


def _flow_label_bits(labels: Iterable[str], *, reject_unknown: bool) -> bytes:
    """把固定 IFC 标签编码为 bitset；运行时自定义标签映射到拒绝位。"""
    unknown_index = RAW_AUTHORIZATION_FLOW_LABELS_V1.index("__unknown__")
    indexes = {
        label: index
        for index, label in enumerate(RAW_AUTHORIZATION_FLOW_LABELS_V1)
        if label != "__unknown__"
    }
    bits = bytearray(len(RAW_AUTHORIZATION_FLOW_LABELS_V1))
    for label in labels:
        index = indexes.get(label)
        if index is None:
            if reject_unknown:
                bits[unknown_index] = 1
            continue
        bits[index] = 1
    return bytes(bits)


def _timestamp_epoch(value: datetime | str) -> int:
    """把规范 UTC 秒级时间转换为 B2 有界整数坐标。"""
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if type(value) is str
        else value
    )
    if type(parsed) is not datetime or parsed.tzinfo is None:
        raise ValueError("B2 timestamps must be timezone-aware")
    return int(parsed.astimezone(timezone.utc).timestamp())


def _decode_digest(value: str) -> bytes:
    """解码 signed SHA-256 hex；非规范字段映射为稳定不匹配摘要。"""
    if type(value) is str:
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            decoded = b""
        if len(decoded) == 32 and value == value.lower() and len(value) == 64:
            return decoded
        invalid_material = value.encode("utf-8", errors="replace")
    else:
        invalid_material = type(value).__name__.encode("ascii", errors="replace")
    return hashlib.sha256(
        b"SAGA-PQ-CAN-InvalidSignedDigestV1\x00" + invalid_material
    ).digest()


def _text_digest(value: str) -> bytes:
    """将 identity/action 文本编码为固定 SHA-256 宽度关系输入。"""
    return hashlib.sha256(value.encode("utf-8")).digest()


def _trace(
    fact_name: AuthorizationFactName,
    value: bool,
    reason: str,
    source: AuthorizationFactSource,
    payload: Mapping[str, object],
) -> RouteBFactCompilationTrace:
    """构造 domain-separated evidence 摘要，不保存 transport 或签名原文。"""
    evidence_payload = {
        "compiler_id": ROUTE_B_FACT_COMPILER_ID_V1,
        "compiler_version": ROUTE_B_FACT_COMPILER_VERSION_V1,
        "fact_name": fact_name,
        "value": value,
        "reason": reason,
        "source": source.value,
        "payload": dict(payload),
    }
    encoded = json.dumps(
        evidence_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return RouteBFactCompilationTrace(
        fact_name=fact_name,
        value=value,
        reason=reason,
        source=source,
        evidence_digest=hashlib.sha256(
            b"SAGA-PQ-CAN-RouteBFactV1\x00" + encoded
        ).digest(),
    )


def _json_digest(value: object) -> str:
    """对已冻结 JSON-compatible runtime 参数生成稳定 SHA-256 摘要。"""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _outside_signature_valid(
    evidence: MLDSARouteBVerificationEvidence,
) -> bool:
    """只把严格 R6 evidence 的原生接受结果视为电路外签名成立。"""
    return (
        type(evidence) is MLDSARouteBVerificationEvidence
        and evidence.accepted is True
        and evidence.reason == "signature_valid"
    )


def _compiled_signature_fact_value(
    compiled_facts: RouteBCompiledAuthorizationFacts,
) -> bool | None:
    """从受信 compiler 结果读取签名事实；任何结构漂移均返回 None。"""
    try:
        fact = compiled_facts.fact_set.fact_map().get("standard_signature_valid")
    except (AttributeError, TypeError, ValueError):
        return None
    if type(fact) is not AuthorizationFact or type(fact.value) is not bool:
        return None
    return fact.value


def _route_b_enforcement_reason(
    *,
    outside_valid: bool,
    signature_fact_matches: bool,
    fixed_decision: FixedPolicyDecision,
    accepted: bool,
) -> str:
    """按安全优先级生成 B1.5 稳定 reason，避免电路错误遮蔽签名失败。"""
    if not signature_fact_matches:
        return "standard_signature_fact_mismatch"
    if not outside_valid:
        return "standard_signature_invalid"
    if accepted:
        return "route_b_fixed_policy_accept"
    fixed_output_is_one = (
        type(fixed_decision.output) is int and fixed_decision.output == 1
    )
    if (
        type(fixed_decision.accepted) is not bool
        or (fixed_decision.accepted is True) is not fixed_output_is_one
        or type(fixed_decision.reason) is not str
        or not fixed_decision.reason
    ):
        return "fixed_policy_output_invalid"
    return fixed_decision.reason


def _route_b_fixed_authorization_reason(
    *,
    policy_evidence: RouteBFixedPolicyEnforcementEvidence,
    raw_signature_matches: bool,
    relation_decision: FixedAuthorizationRelationDecision,
    accepted: bool,
) -> str:
    """按安全优先级生成 B2 reason，先保留 B1.5 与外部签名失败。"""
    if not policy_evidence.accepted:
        return policy_evidence.reason
    if not raw_signature_matches:
        return "raw_standard_signature_mismatch"
    if accepted:
        return "route_b_fixed_authorization_accept"
    relation_output_is_one = (
        type(relation_decision.output) is int
        and relation_decision.output == 1
    )
    if (
        type(relation_decision.accepted) is not bool
        or (relation_decision.accepted is True) is not relation_output_is_one
        or type(relation_decision.reason) is not str
        or not relation_decision.reason
    ):
        return "fixed_authorization_output_invalid"
    return relation_decision.reason
