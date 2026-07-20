"""组合 Route B authority、Route A research 路线与 durable Coordinator。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Literal, Protocol

from neural.fixed_policy_runtime import (
    RouteBFixedAuthorizationCircuitEvidence,
    RouteBShadowRequest,
)
from neural.shadow_queue import (
    A0ShadowJob,
    A0ShadowSubmission,
    A0ShadowVerifier,
)
from saga.durable_authorization import DurableAuthorizationStateStore
from saga.execution_gate import (
    ExecutionGateDecision,
    ExecutionGateRequest,
    LocalExecutionContext,
    RuntimeAuthCoordinator,
    SignedRequestExecutionGate,
)
from saga.messages import parse_request_envelope, sha256_hex


DualRouteMode = Literal[
    "route_b_only",
    "route_b_with_a_shadow",
    "dual_required_research",
    "offline_compare",
]
RouteAObservationStatus = Literal[
    "not_requested",
    "planned",
    "accepted",
    "rejected",
    "missing",
    "untrusted_key",
    "error",
    "invalid_output",
]

_DUAL_ROUTE_MODES = frozenset(
    {
        "route_b_only",
        "route_b_with_a_shadow",
        "dual_required_research",
        "offline_compare",
    }
)
_MAX_SIGNATURE_BYTES = 1 << 20


class RouteBFixedAuthorizationEvaluator(Protocol):
    """定义 integration 所需的无状态 Route B B2/B3 evaluator。"""

    def evaluate(
        self,
        request: RouteBShadowRequest,
        public_key: bytes,
        signature: bytes,
    ) -> RouteBFixedAuthorizationCircuitEvidence:
        """仅返回无 authority 的 Route B evidence。"""


class RouteAShadowSubmitter(Protocol):
    """定义默认模式使用的非阻塞 Route A shadow 提交接口。"""

    def submit(self, job: A0ShadowJob) -> A0ShadowSubmission:
        """提交公开材料 job，且不得返回执行 authority。"""


@dataclass(frozen=True)
class DualRouteAuthorizationRequestV1:
    """绑定同一 canonical envelope 的 Route B 请求与可选 Route A 签名。"""

    execution_request: ExecutionGateRequest
    route_b_request: RouteBShadowRequest
    route_a_key_id: bytes | None = None
    route_a_signature: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """拒绝重复签名来源、超长材料和非 canonical runtime 参数。"""
        if type(self.execution_request) is not ExecutionGateRequest:
            raise TypeError("execution_request must be ExecutionGateRequest")
        if type(self.route_b_request) is not RouteBShadowRequest:
            raise TypeError("route_b_request must be RouteBShadowRequest")
        route_b_signature = self.execution_request.pq_signature
        if type(route_b_signature) is not bytes or not route_b_signature:
            raise ValueError("execution_request.pq_signature must contain Route B bytes")
        if len(route_b_signature) > _MAX_SIGNATURE_BYTES:
            raise ValueError("Route B signature exceeds the integration limit")
        if (self.route_a_key_id is None) != (self.route_a_signature is None):
            raise ValueError("Route A key id and signature must be supplied together")
        if self.route_a_key_id is not None and (
            type(self.route_a_key_id) is not bytes or not self.route_a_key_id
        ):
            raise ValueError("route_a_key_id must be non-empty bytes")
        if self.route_a_signature is not None and (
            type(self.route_a_signature) is not bytes
            or not self.route_a_signature
            or len(self.route_a_signature) > _MAX_SIGNATURE_BYTES
        ):
            raise ValueError("route_a_signature must be non-empty bounded bytes")
        _canonical_parameters(self.execution_request.parameters)


@dataclass(frozen=True)
class RouteBIntegrationEvidenceV1:
    """封装 Route B 结果和本地 key-id 选择，不携带执行 authority。"""

    accepted: bool
    reason: str
    key_id_digest: str
    evidence: RouteBFixedAuthorizationCircuitEvidence | None = field(
        default=None,
        repr=False,
    )
    error_type: str | None = None
    authority_granted: Literal[False] = False

    def __post_init__(self) -> None:
        """确保包装结果与 Route B 自校验 evidence 完全一致。"""
        if type(self.accepted) is not bool:
            raise TypeError("Route B accepted must be a built-in bool")
        _validate_sha256_hex(self.key_id_digest, "key_id_digest")
        if self.authority_granted is not False:
            raise ValueError("Route B integration evidence cannot grant authority")
        if self.evidence is None:
            if self.accepted:
                raise ValueError("accepted Route B evidence requires route detail")
            return
        if type(self.evidence) is not RouteBFixedAuthorizationCircuitEvidence:
            raise TypeError("Route B detail must use fixed authorization evidence")
        if self.evidence.authority_granted is not False:
            raise ValueError("Route B detail cannot carry authority")
        if (
            self.accepted is not self.evidence.accepted
            or self.reason != self.evidence.reason
        ):
            raise ValueError("Route B integration summary does not match detail")

    def as_dict(self) -> dict[str, object]:
        """导出不含公钥、签名或业务原文的 Route B 摘要。"""
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "key_id_digest": self.key_id_digest,
            "error_type": self.error_type,
            "authority_granted": self.authority_granted,
            "evidence": self.evidence.as_dict() if self.evidence is not None else None,
        }


@dataclass(frozen=True)
class RouteAIntegrationEvidenceV1:
    """记录 Route A 同步研究结果或待异步提交状态，固定零 authority。"""

    status: RouteAObservationStatus
    reason: str
    accepted: bool | None
    key_id_digest: str | None
    job_digest: str | None
    error_type: str | None = None
    authority_granted: Literal[False] = False

    def __post_init__(self) -> None:
        """限制状态、接受位和摘要组合，防止 shadow 结果被重标记。"""
        if self.status not in {
            "not_requested",
            "planned",
            "accepted",
            "rejected",
            "missing",
            "untrusted_key",
            "error",
            "invalid_output",
        }:
            raise ValueError("unsupported Route A observation status")
        if self.accepted is not None and type(self.accepted) is not bool:
            raise TypeError("Route A accepted must be a built-in bool or None")
        if self.status == "accepted" and self.accepted is not True:
            raise ValueError("accepted Route A status requires accepted=True")
        if self.status == "rejected" and self.accepted is not False:
            raise ValueError("rejected Route A status requires accepted=False")
        if self.status in {
            "not_requested",
            "planned",
            "missing",
            "untrusted_key",
            "error",
            "invalid_output",
        }:
            if self.accepted is not None:
                raise ValueError("non-terminal Route A status cannot carry acceptance")
        for field_name, value in (
            ("key_id_digest", self.key_id_digest),
            ("job_digest", self.job_digest),
        ):
            if value is not None:
                _validate_sha256_hex(value, field_name)
        if self.authority_granted is not False:
            raise ValueError("Route A evidence cannot grant authority")

    def as_dict(self) -> dict[str, object]:
        """导出不含 Route A 公钥或签名字节的研究摘要。"""
        return {
            "status": self.status,
            "reason": self.reason,
            "accepted": self.accepted,
            "key_id_digest": self.key_id_digest,
            "job_digest": self.job_digest,
            "error_type": self.error_type,
            "authority_granted": self.authority_granted,
        }


@dataclass(frozen=True)
class DualRouteCompositeEvidenceV1:
    """汇总四种 integration mode 的纯 evidence 与可提交公式。"""

    mode: DualRouteMode
    request_fingerprint: str
    route_b: RouteBIntegrationEvidenceV1
    route_a: RouteAIntegrationEvidenceV1
    formula_accept: bool
    committable: bool
    reason: str
    decision: ExecutionGateDecision
    request: DualRouteAuthorizationRequestV1 = field(repr=False, compare=False)
    authority_granted: Literal[False] = False

    def __post_init__(self) -> None:
        """重算 mode 公式，保证 offline/shadow evidence 不能伪造 authority。"""
        if self.mode not in _DUAL_ROUTE_MODES:
            raise ValueError("unsupported dual-route mode")
        _validate_sha256_hex(self.request_fingerprint, "request_fingerprint")
        if type(self.route_b) is not RouteBIntegrationEvidenceV1:
            raise TypeError("route_b must use RouteBIntegrationEvidenceV1")
        if type(self.route_a) is not RouteAIntegrationEvidenceV1:
            raise TypeError("route_a must use RouteAIntegrationEvidenceV1")
        if type(self.decision) is not ExecutionGateDecision:
            raise TypeError("decision must be ExecutionGateDecision")
        if type(self.request) is not DualRouteAuthorizationRequestV1:
            raise TypeError("request must be DualRouteAuthorizationRequestV1")
        expected_formula = _mode_formula_accept(self.mode, self.route_b, self.route_a)
        expected_committable = self.mode != "offline_compare" and expected_formula
        expected_reason = _mode_reason(
            self.mode,
            self.route_b,
            self.route_a,
            expected_formula,
        )
        if type(self.formula_accept) is not bool or self.formula_accept is not expected_formula:
            raise ValueError("formula_accept does not match the selected mode")
        if type(self.committable) is not bool or self.committable is not expected_committable:
            raise ValueError("committable does not match the selected mode")
        if self.reason != expected_reason:
            raise ValueError("reason does not match the selected mode")
        if self.decision.allowed is not expected_committable or self.decision.reason != expected_reason:
            raise ValueError("decision does not match the dual-route formula")
        if self.decision.local_execution_context is not None:
            raise ValueError("evaluate evidence cannot contain a Context")
        if self.authority_granted is not False:
            raise ValueError("dual-route evidence cannot grant authority")

    def as_dict(self) -> dict[str, object]:
        """导出四模式结果，不序列化请求、公钥、签名或 Context。"""
        return {
            "mode": self.mode,
            "request_fingerprint": self.request_fingerprint,
            "route_b": self.route_b.as_dict(),
            "route_a": self.route_a.as_dict(),
            "formula_accept": self.formula_accept,
            "committable": self.committable,
            "reason": self.reason,
            "authority_granted": self.authority_granted,
        }


@dataclass(frozen=True)
class DualRouteCommitResultV1:
    """记录唯一 Coordinator commit 结果及非权威 shadow 提交状态。"""

    committed: bool
    reason: str
    decision: ExecutionGateDecision
    context: LocalExecutionContext | None = None
    shadow_submission: A0ShadowSubmission | None = None
    shadow_reason: str | None = None

    def __post_init__(self) -> None:
        """保证成功提交必有 Context，shadow submission 永远零 authority。"""
        if type(self.committed) is not bool:
            raise TypeError("committed must be a built-in bool")
        if type(self.decision) is not ExecutionGateDecision:
            raise TypeError("decision must be ExecutionGateDecision")
        if self.reason != self.decision.reason:
            raise ValueError("commit result reason must match its decision")
        if self.committed != (self.context is not None):
            raise ValueError("committed result and Context presence must match")
        if self.context is not self.decision.local_execution_context:
            raise ValueError("commit result and decision must share one Context")
        if self.shadow_submission is not None and (
            type(self.shadow_submission) is not A0ShadowSubmission
            or self.shadow_submission.authority_granted is not False
        ):
            raise ValueError("shadow submission cannot carry authority")


class _DenyAllCAN:
    """为 commit-only state gate 提供不可接受任何签名的占位验证器。"""

    def can_accept(
        self,
        _public_key_bits: object,
        _message_bits: object,
        _signature_bits: object,
    ) -> int:
        """始终返回硬拒绝，避免 single-route Coordinator 成为旁路。"""
        return 0


class DualRouteRuntimeAuthCoordinator(RuntimeAuthCoordinator):
    """在四种模式下重评估 A/B，并复用 R17 durable commit 发布 Context。"""

    def __init__(
        self,
        state_gate: SignedRequestExecutionGate,
        *,
        mode: DualRouteMode,
        route_b_evaluator: RouteBFixedAuthorizationEvaluator,
        route_b_public_keys: Mapping[bytes, bytes],
        route_a_public_keys: Mapping[bytes, bytes] | None = None,
        route_a_verifier: A0ShadowVerifier | None = None,
        route_a_shadow_submitter: RouteAShadowSubmitter | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        """固定本地 mode/trust registry，并接管 state gate 的唯一 Coordinator。"""
        if mode not in _DUAL_ROUTE_MODES:
            raise ValueError("unsupported dual-route mode")
        if type(state_gate) is not SignedRequestExecutionGate:
            raise TypeError("state_gate must be SignedRequestExecutionGate")
        if state_gate.coordinator_mode != "strict":
            raise ValueError("dual-route integration requires strict state gate")
        if state_gate._durable_authorization_state_store is None:
            raise ValueError("dual-route integration requires R17 durable state")
        if state_gate.trusted_public_keys:
            raise ValueError("dual-route state gate must not expose a single-route trust registry")
        if not callable(getattr(route_b_evaluator, "evaluate", None)):
            raise TypeError("route_b_evaluator must expose evaluate")
        self.mode = mode
        self.state_gate = state_gate
        self.route_b_evaluator = route_b_evaluator
        self.route_b_public_keys = _copy_public_key_registry(
            route_b_public_keys,
            "route_b_public_keys",
        )
        self.route_a_public_keys = _copy_public_key_registry(
            route_a_public_keys or {},
            "route_a_public_keys",
        )
        self.route_a_verifier = route_a_verifier
        self.route_a_shadow_submitter = route_a_shadow_submitter
        self._now_fn = now_fn or (lambda: datetime.now(tz=timezone.utc))
        if mode == "route_b_with_a_shadow":
            if not self.route_a_public_keys or not callable(
                getattr(route_a_shadow_submitter, "submit", None)
            ):
                raise ValueError("Route A shadow mode requires local keys and a submitter")
        if mode in {"dual_required_research", "offline_compare"}:
            if not self.route_a_public_keys or not callable(
                getattr(route_a_verifier, "verify_bytes", None)
            ):
                raise ValueError("dual/offline mode requires local Route A keys and verifier")
        super().__init__(state_gate, route_id=f"dual_route_runtime_v1:{mode}")
        # state gate 不保留另一个可调用的 single-route Coordinator。
        state_gate.runtime_auth_coordinator = self

    def evaluate(
        self,
        request: DualRouteAuthorizationRequestV1,
    ) -> DualRouteCompositeEvidenceV1:
        """纯计算 mode evidence；默认 shadow job 在成功 durable commit 后才提交。"""
        if type(request) is not DualRouteAuthorizationRequestV1:
            raise TypeError("request must be DualRouteAuthorizationRequestV1")
        request_fingerprint = self._request_fingerprint(request)
        route_b = self._evaluate_route_b(request)
        route_a = self._evaluate_route_a(request, route_b)
        formula_accept = _mode_formula_accept(self.mode, route_b, route_a)
        committable = self.mode != "offline_compare" and formula_accept
        reason = _mode_reason(self.mode, route_b, route_a, formula_accept)
        decision = _build_execution_decision(
            request,
            route_b,
            route_a,
            allowed=committable,
            reason=reason,
            mode=self.mode,
            route_b_public_key=self._route_b_public_key(request),
        )
        return DualRouteCompositeEvidenceV1(
            mode=self.mode,
            request_fingerprint=request_fingerprint,
            route_b=route_b,
            route_a=route_a,
            formula_accept=formula_accept,
            committable=committable,
            reason=reason,
            decision=decision,
            request=request,
            authority_granted=False,
        )

    def commit(self, evidence: object) -> DualRouteCommitResultV1:
        """重评估 A/B/current time，并且只经 R17 durable commit 发布 Context。"""
        if type(evidence) is not DualRouteCompositeEvidenceV1 or evidence.mode != self.mode:
            return self._reject("invalid_dual_route_evidence")
        if self.mode == "offline_compare":
            return self._reject("offline_compare_no_authority", evidence.decision)
        if not evidence.committable:
            return DualRouteCommitResultV1(False, evidence.reason, evidence.decision)

        try:
            current = self.evaluate(evidence.request)
        except (TypeError, ValueError):
            return self._reject("dual_route_request_not_canonical")
        if (
            current.request_fingerprint != evidence.request_fingerprint
            or current.route_b.accepted is not evidence.route_b.accepted
            or current.route_a.accepted is not evidence.route_a.accepted
            or current.committable is not evidence.committable
            or current.reason != evidence.reason
        ):
            return self._reject("dual_route_evidence_changed", current.decision)
        if not current.committable:
            return DualRouteCommitResultV1(False, current.reason, current.decision)

        context = self._gate._build_context_from_committed_decision(
            current.decision,
            coordinator_committed=True,
        )
        if context is None:
            return self._reject("local_execution_context_creation_failed", current.decision)
        committed_decision = self._commit_durable_authorization(
            current.decision,
            request_fingerprint=current.request_fingerprint,
        )
        if not committed_decision.allowed:
            return DualRouteCommitResultV1(
                False,
                committed_decision.reason,
                committed_decision,
            )
        committed_decision = replace(
            committed_decision,
            local_execution_context=context,
        )
        shadow_submission, shadow_reason = self._submit_route_a_shadow(
            current.request,
            current.route_b,
        )
        return DualRouteCommitResultV1(
            True,
            committed_decision.reason,
            committed_decision,
            context,
            shadow_submission,
            shadow_reason,
        )

    def _evaluate_route_b(
        self,
        request: DualRouteAuthorizationRequestV1,
    ) -> RouteBIntegrationEvidenceV1:
        """使用本地 B key registry 和当前可信时间计算 B2/B3 evidence。"""
        key_id = request.route_b_request.binding.key_id
        key_id_digest = sha256_hex(key_id)
        public_key = self.route_b_public_keys.get(key_id)
        if public_key is None:
            return RouteBIntegrationEvidenceV1(
                False,
                "route_b_key_untrusted",
                key_id_digest,
            )
        binding_reason = _integration_binding_reason(request)
        if binding_reason is not None:
            return RouteBIntegrationEvidenceV1(
                False,
                binding_reason,
                key_id_digest,
            )
        try:
            current_request = replace(
                request.route_b_request,
                observed_at=self._now(),
            )
            result = self.route_b_evaluator.evaluate(
                current_request,
                public_key,
                request.execution_request.pq_signature,
            )
        except Exception as exc:
            return RouteBIntegrationEvidenceV1(
                False,
                "route_b_evaluation_error",
                key_id_digest,
                error_type=type(exc).__name__,
            )
        if type(result) is not RouteBFixedAuthorizationCircuitEvidence:
            return RouteBIntegrationEvidenceV1(
                False,
                "route_b_output_invalid",
                key_id_digest,
                error_type=type(result).__name__,
            )
        return RouteBIntegrationEvidenceV1(
            result.accepted,
            result.reason,
            key_id_digest,
            result,
        )

    def _evaluate_route_a(
        self,
        request: DualRouteAuthorizationRequestV1,
        route_b: RouteBIntegrationEvidenceV1,
    ) -> RouteAIntegrationEvidenceV1:
        """按 mode 规划异步 shadow，或同步计算 research-only A 结果。"""
        if self.mode == "route_b_only":
            return RouteAIntegrationEvidenceV1(
                "not_requested",
                "route_a_not_requested",
                None,
                None,
                None,
            )
        job, reason, key_id_digest = self._route_a_job(request, route_b.accepted)
        if job is None:
            status: RouteAObservationStatus = (
                "untrusted_key" if reason == "route_a_key_untrusted" else "missing"
            )
            return RouteAIntegrationEvidenceV1(
                status,
                reason,
                None,
                key_id_digest,
                None,
            )
        if self.mode == "route_b_with_a_shadow":
            return RouteAIntegrationEvidenceV1(
                "planned",
                "route_a_shadow_planned",
                None,
                key_id_digest,
                job.digest(),
            )
        assert self.route_a_verifier is not None
        try:
            output = self.route_a_verifier.verify_bytes(
                job.public_key,
                job.message,
                job.signature,
            )
        except Exception as exc:
            return RouteAIntegrationEvidenceV1(
                "error",
                "route_a_evaluation_error",
                None,
                key_id_digest,
                job.digest(),
                type(exc).__name__,
            )
        if type(output) is not int or output not in (0, 1):
            return RouteAIntegrationEvidenceV1(
                "invalid_output",
                "route_a_output_invalid",
                None,
                key_id_digest,
                job.digest(),
                type(output).__name__,
            )
        accepted = output == 1
        return RouteAIntegrationEvidenceV1(
            "accepted" if accepted else "rejected",
            "route_a_accepted" if accepted else "route_a_rejected",
            accepted,
            key_id_digest,
            job.digest(),
        )

    def _route_a_job(
        self,
        request: DualRouteAuthorizationRequestV1,
        reference_accept: bool,
    ) -> tuple[A0ShadowJob | None, str, str | None]:
        """仅从本地 A trust registry 构造绑定同一 envelope digest 的公开 job。"""
        if request.route_a_key_id is None or request.route_a_signature is None:
            return None, "route_a_material_missing", None
        key_id_digest = sha256_hex(request.route_a_key_id)
        public_key = self.route_a_public_keys.get(request.route_a_key_id)
        if public_key is None:
            return None, "route_a_key_untrusted", key_id_digest
        envelope = request.route_b_request.envelope
        return (
            A0ShadowJob(
                job_id=f"{envelope.hex_digest()}:{self.mode}",
                public_key=public_key,
                message=envelope.digest(),
                signature=request.route_a_signature,
                reference_accept=reference_accept,
            ),
            "route_a_job_ready",
            key_id_digest,
        )

    def _submit_route_a_shadow(
        self,
        request: DualRouteAuthorizationRequestV1,
        route_b: RouteBIntegrationEvidenceV1,
    ) -> tuple[A0ShadowSubmission | None, str | None]:
        """durable commit 后非阻塞提交 A job；任何失败都不回滚 B authority。"""
        if self.mode != "route_b_with_a_shadow":
            return None, None
        job, reason, _key_id_digest = self._route_a_job(request, route_b.accepted)
        if job is None or self.route_a_shadow_submitter is None:
            return None, reason
        try:
            submission = self.route_a_shadow_submitter.submit(job)
        except Exception:
            return None, "route_a_shadow_submit_error"
        if type(submission) is not A0ShadowSubmission:
            return None, "route_a_shadow_submission_invalid"
        if submission.job_digest != job.digest():
            return None, "route_a_shadow_submission_mismatch"
        return submission, submission.reason

    def _route_b_public_key(
        self,
        request: DualRouteAuthorizationRequestV1,
    ) -> bytes | None:
        """按 binding key id 查询固定的本地 Route B trust registry。"""
        return self.route_b_public_keys.get(request.route_b_request.binding.key_id)

    def _request_fingerprint(
        self,
        request: DualRouteAuthorizationRequestV1,
    ) -> str:
        """绑定 mode、A/B 签名摘要、transport、envelope 与 runtime 参数。"""
        execution = request.execution_request
        route_b = request.route_b_request
        payload = {
            "mode": self.mode,
            "sender_aid": execution.sender_aid,
            "receiver_aid": execution.receiver_aid,
            "token_digest": sha256_hex(execution.token.encode("utf-8")),
            "message_digest": sha256_hex(execution.message.encode("utf-8")),
            "action_scope": execution.action_scope,
            "parameters": _canonical_parameters(execution.parameters),
            "binding_digest": sha256_hex(route_b.binding.canonical_bytes()),
            "envelope_digest": route_b.envelope.hex_digest(),
            "route_b_signature_digest": sha256_hex(execution.pq_signature),
            "route_b_public_key_digest": (
                sha256_hex(self._route_b_public_key(request))
                if self._route_b_public_key(request) is not None
                else None
            ),
            "route_b_snapshot": {
                "sender_aid": route_b.sender_aid,
                "receiver_aid": route_b.receiver_aid,
                "token_digest": route_b.token_digest.hex(),
                "message_digest": route_b.message_digest.hex(),
                "action_scope": route_b.action_scope,
                "parameters": _canonical_parameters(route_b.parameters),
                "flow_labels": list(route_b.flow_labels),
                "parent_envelope_digest": (
                    route_b.parent_envelope.hex_digest()
                    if route_b.parent_envelope is not None
                    else None
                ),
            },
            "route_a_key_id_digest": (
                sha256_hex(request.route_a_key_id)
                if request.route_a_key_id is not None
                else None
            ),
            "route_a_signature_digest": (
                sha256_hex(request.route_a_signature)
                if request.route_a_signature is not None
                else None
            ),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return sha256_hex(b"SAGA-PQ-CAN-DualRouteRequestV1\x00" + encoded)

    def _now(self) -> datetime:
        """返回规范 UTC 当前时间，拒绝 naive 或错误时钟类型。"""
        value = self._now_fn()
        if type(value) is not datetime or value.tzinfo is None:
            raise ValueError("now_fn must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _reject(
        reason: str,
        decision: ExecutionGateDecision | None = None,
    ) -> DualRouteCommitResultV1:
        """构造不含 Context 的稳定 Coordinator 拒绝结果。"""
        rejected = replace(decision, allowed=False, reason=reason) if decision else (
            ExecutionGateDecision(False, reason)
        )
        return DualRouteCommitResultV1(False, reason, rejected)


def build_dual_route_runtime_coordinator(
    *,
    mode: DualRouteMode,
    durable_authorization_state_store: DurableAuthorizationStateStore,
    route_b_evaluator: RouteBFixedAuthorizationEvaluator,
    route_b_public_keys: Mapping[bytes, bytes],
    route_a_public_keys: Mapping[bytes, bytes] | None = None,
    route_a_verifier: A0ShadowVerifier | None = None,
    route_a_shadow_submitter: RouteAShadowSubmitter | None = None,
    now_fn: Callable[[], datetime] | None = None,
) -> DualRouteRuntimeAuthCoordinator:
    """构造没有 single-route 信任旁路、只使用 R17 durable state 的四模式 Coordinator。"""
    state_gate = SignedRequestExecutionGate(
        _DenyAllCAN(),  # type: ignore[arg-type]
        {},
        now_fn=now_fn,
        durable_authorization_state_store=durable_authorization_state_store,
        coordinator_mode="strict",
    )
    return DualRouteRuntimeAuthCoordinator(
        state_gate,
        mode=mode,
        route_b_evaluator=route_b_evaluator,
        route_b_public_keys=route_b_public_keys,
        route_a_public_keys=route_a_public_keys,
        route_a_verifier=route_a_verifier,
        route_a_shadow_submitter=route_a_shadow_submitter,
        now_fn=now_fn,
    )


def _integration_binding_reason(
    request: DualRouteAuthorizationRequestV1,
) -> str | None:
    """核对 transport request 与 Route B snapshot 确实绑定同一 canonical 请求。"""
    execution = request.execution_request
    route_b = request.route_b_request
    try:
        envelope = parse_request_envelope(execution.request_envelope)
    except (TypeError, ValueError, json.JSONDecodeError):
        return "integration_envelope_invalid"
    if envelope != route_b.envelope:
        return "integration_envelope_mismatch"
    if route_b.binding.envelope_digest != envelope.digest():
        return "integration_binding_mismatch"
    if execution.sender_aid != route_b.sender_aid:
        return "integration_sender_mismatch"
    if execution.receiver_aid != route_b.receiver_aid:
        return "integration_receiver_mismatch"
    if hashlib.sha256(execution.token.encode("utf-8")).digest() != route_b.token_digest:
        return "integration_token_mismatch"
    if hashlib.sha256(execution.message.encode("utf-8")).digest() != route_b.message_digest:
        return "integration_message_mismatch"
    if execution.action_scope != route_b.action_scope:
        return "integration_action_scope_mismatch"
    if _canonical_parameters(execution.parameters) != _canonical_parameters(route_b.parameters):
        return "integration_parameters_mismatch"
    return None


def _build_execution_decision(
    request: DualRouteAuthorizationRequestV1,
    route_b: RouteBIntegrationEvidenceV1,
    route_a: RouteAIntegrationEvidenceV1,
    *,
    allowed: bool,
    reason: str,
    mode: DualRouteMode,
    route_b_public_key: bytes | None,
) -> ExecutionGateDecision:
    """把 A/B 公式映射为现有 Context/audit 所需的结构化 decision。"""
    route_b_detail = route_b.evidence
    signature_valid = bool(
        route_b_detail is not None
        and route_b_detail.policy_evidence.outside_standard_signature_valid
    )
    hard_gate_accept = route_b.accepted and (
        mode not in {"dual_required_research", "offline_compare"}
        or route_a.accepted is True
    )
    return ExecutionGateDecision(
        allowed,
        reason,
        request_envelope_valid=route_b.accepted,
        pq_signature_valid=signature_valid,
        can_accept=hard_gate_accept,
        execution_scope_allowed=route_b.accepted,
        internal_policy_accept=route_b.accepted,
        request_envelope=request.route_b_request.envelope,
        pq_signature=request.execution_request.pq_signature,
        sender_public_key=route_b_public_key,
        enforcement_mode="strict",
    )


def _mode_formula_accept(
    mode: DualRouteMode,
    route_b: RouteBIntegrationEvidenceV1,
    route_a: RouteAIntegrationEvidenceV1,
) -> bool:
    """按固定四模式规则计算 would-authorize，不允许 A OR B。"""
    if mode in {"route_b_only", "route_b_with_a_shadow"}:
        return route_b.accepted
    return route_b.accepted and route_a.accepted is True


def _mode_reason(
    mode: DualRouteMode,
    route_b: RouteBIntegrationEvidenceV1,
    route_a: RouteAIntegrationEvidenceV1,
    formula_accept: bool,
) -> str:
    """返回稳定 mode reason，Route A 永不覆盖 Route B 拒绝。"""
    if not route_b.accepted:
        return "route_b_rejected"
    if mode == "dual_required_research" and route_a.accepted is not True:
        return route_a.reason
    if mode == "offline_compare":
        return "offline_compare_no_authority"
    if formula_accept and mode == "route_b_only":
        return "route_b_authorized"
    if formula_accept and mode == "route_b_with_a_shadow":
        return "route_b_authorized_a_shadow_planned"
    if formula_accept and mode == "dual_required_research":
        return "dual_routes_authorized_research"
    return "dual_route_rejected"


def _copy_public_key_registry(
    registry: Mapping[bytes, bytes],
    field_name: str,
) -> dict[bytes, bytes]:
    """复制并验证本地 key-id registry，禁止空键或可变材料。"""
    if not isinstance(registry, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    copied: dict[bytes, bytes] = {}
    for key_id, public_key in registry.items():
        if type(key_id) is not bytes or not key_id:
            raise ValueError(f"{field_name} key ids must be non-empty bytes")
        if type(public_key) is not bytes or not public_key:
            raise ValueError(f"{field_name} public keys must be non-empty bytes")
        copied[key_id] = public_key
    if field_name == "route_b_public_keys" and not copied:
        raise ValueError("route_b_public_keys must be non-empty")
    return copied


def _canonical_parameters(parameters: Mapping[str, object] | None) -> str:
    """把 runtime 参数编码成稳定 JSON，拒绝非 JSON 或非有限值。"""
    if parameters is not None and not isinstance(parameters, Mapping):
        raise TypeError("parameters must be a mapping or None")
    try:
        return json.dumps(
            dict(parameters or {}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("parameters must contain canonical JSON values") from exc


def _validate_sha256_hex(value: str, field_name: str) -> None:
    """验证 integration evidence 使用规范小写 SHA-256 十六进制摘要。"""
    if type(value) is not str or len(value) != 64 or value.lower() != value:
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex") from exc
