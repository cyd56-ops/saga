"""把真实 Route B 签名 evidence 和 runtime 请求编译为 B1 shadow facts。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal

from neural.fixed_policy import (
    AUTHORIZATION_FACT_NAMES,
    AUTHORIZATION_LAYOUT_ID_V1,
    AUTHORIZATION_LAYOUT_VERSION_V1,
    AuthorizationFact,
    AuthorizationFactName,
    AuthorizationFactProvenance,
    AuthorizationFactSet,
    AuthorizationFactSource,
    FixedPolicyShadowEvidence,
    FixedPolicyShadowEvaluator,
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
    flow_policy_allows_egress,
    normalize_flow_labels,
    parse_action_scope,
    scope_constraints_allow,
    scope_constraints_are_attenuated,
)


ROUTE_B_FACT_COMPILER_ID_V1 = "saga-route-b-trusted-fact-compiler"
ROUTE_B_FACT_COMPILER_VERSION_V1 = 1


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
