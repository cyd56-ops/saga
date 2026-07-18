"""运行真实 ML-DSA-44 Route B fixed-policy shadow corpus。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import cryptography

from neural import (
    RouteBFixedPolicyShadowRoute,
    RouteBShadowCorpusManifest,
    RouteBShadowRequest,
    summarize_route_b_shadow_corpus,
)
from pq import (
    CryptographyMLDSABackend,
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    MLDSABackendContractV1,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)
from saga.messages import RequestEnvelope, build_request_envelope


_SENDER_AID = "alice@example.com:email_agent"
_RECEIVER_AID = "bob@example.com:email_agent"
_TOKEN = b"route-b-shadow-runner-token"
_MESSAGE = b"send the report"
_ACTION_SCOPE = "tool_call:send_email"
_OBSERVED_AT = datetime(2026, 7, 18, 12, 30, tzinfo=timezone.utc)


@dataclass(frozen=True)
class RealRouteBShadowReport:
    """汇总真实 backend 身份、shadow manifest、reason 校验和残余边界。"""

    backend: dict[str, object]
    manifest: RouteBShadowCorpusManifest
    expected_reason_mismatches: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def all_passed(self) -> bool:
        """要求全等价、全事实负向覆盖、零 authority 且 reason 全匹配。"""
        return (
            self.manifest.all_equivalent
            and self.manifest.authority_granted_count == 0
            and all(count > 0 for _name, count in self.manifest.fact_false_counts)
            and not self.expected_reason_mismatches
        )

    def as_dict(self) -> dict[str, object]:
        """导出不包含公私钥或签名字节的机器可读报告。"""
        return {
            "all_passed": self.all_passed,
            "backend": dict(self.backend),
            "manifest": self.manifest.as_dict(),
            "expected_reason_mismatches": list(self.expected_reason_mismatches),
            "limitations": list(self.limitations),
        }


def run_real_route_b_shadow_corpus() -> RealRouteBShadowReport:
    """以内存短生命周期密钥运行八个真实 ML-DSA signed-envelope shadow case。"""
    backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
    descriptor = backend.descriptor()
    if not descriptor.available:
        raise RuntimeError("cryptography/OpenSSL ML-DSA-44 backend is unavailable")
    contract = MLDSABackendContractV1(
        backend_name="cryptography",
        backend_version=cryptography.__version__,
        provider_name="OpenSSL",
        provider_version=descriptor.provider_version,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        timeout_seconds=1.0,
    )
    route = RouteBFixedPolicyShadowRoute(MLDSARouteBVerifier(backend, contract))
    key_pair = backend.keygen_pair()
    evaluated = []
    expected_reason_mismatches: list[str] = []
    for case_id, request, expected_reason, corrupt_signature in _runtime_cases():
        signature = backend.sign(
            key_pair.secret_key,
            request.binding.canonical_bytes(),
        )
        if corrupt_signature:
            signature = bytes((signature[0] ^ 1,)) + signature[1:]
        evidence = route.evaluate(request, key_pair.public_key, signature)
        evaluated.append((case_id, evidence))
        if evidence.shadow_evidence.fixed_decision.reason != expected_reason:
            expected_reason_mismatches.append(case_id)
    manifest = summarize_route_b_shadow_corpus(evaluated)
    return RealRouteBShadowReport(
        backend={
            "backend_name": descriptor.backend_name,
            "backend_version": descriptor.backend_version,
            "provider_name": descriptor.provider_name,
            "provider_version": descriptor.provider_version,
            "algorithm_id": int(descriptor.algorithm_id),
            "profile_id": int(descriptor.profile_id),
            "context_digest": hashlib.sha256(descriptor.context).hexdigest(),
        },
        manifest=manifest,
        expected_reason_mismatches=tuple(expected_reason_mismatches),
        limitations=(
            "in-process object-level shadow corpus; no Agent network path is invoked",
            "the generated ML-DSA private seed and signatures remain memory-only",
            "the report cannot authorize execution or approve B1.5 enforcement",
            "latency, memory, crash recovery, and sustained shadow load remain unmeasured",
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析真实 Route B shadow runner 的可选 JSON 输出路径。"""
    parser = argparse.ArgumentParser(
        description="Run the real ML-DSA-44 Route B fixed-policy shadow corpus."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path; stdout is always emitted.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """运行真实 corpus、可选写盘，并以非零状态表示 evidence 未通过。"""
    args = parse_args(argv)
    report = run_real_route_b_shadow_corpus()
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report.all_passed else 1


def _runtime_cases(
) -> tuple[tuple[str, RouteBShadowRequest, str, bool], ...]:
    """构造覆盖六事实和两个正向路径的固定真实 shadow corpus。"""
    constrained = _envelope(
        scope_constraints={
            _ACTION_SCOPE: [
                {
                    "field": "recipient_domain",
                    "op": "eq",
                    "value": "example.com",
                }
            ]
        },
        flow_policy={"egress": {_ACTION_SCOPE: ["public"]}},
        turn_id="runner-constrained",
    )
    parent = _envelope(
        action_scope="tool_call",
        authorized_scopes=("tool_call",),
        turn_id="runner-parent",
    )
    child = _envelope(parent_envelope=parent, turn_id="runner-child")
    allowed_parameters = {"recipient_domain": "example.com"}
    return (
        (
            "valid",
            _request(constrained, parameters=allowed_parameters),
            "fixed_policy_accept",
            False,
        ),
        (
            "scope_denied",
            _request(constrained, parameters={"recipient_domain": "evil.test"}),
            "scope_not_authorized",
            False,
        ),
        (
            "flow_denied",
            _request(
                constrained,
                parameters=allowed_parameters,
                flow_labels=("private",),
            ),
            "flow_policy_denied",
            False,
        ),
        (
            "time_expired",
            _request(
                constrained,
                parameters=allowed_parameters,
                observed_at=_OBSERVED_AT + timedelta(hours=1),
            ),
            "time_window_invalid",
            False,
        ),
        (
            "transport_digest_mismatch",
            _request(
                constrained,
                parameters=allowed_parameters,
                message_digest=b"X" * 32,
            ),
            "request_envelope_invalid",
            False,
        ),
        (
            "delegation_parent_missing",
            _request(child),
            "delegation_policy_denied",
            False,
        ),
        (
            "valid_delegation",
            _request(child, parent_envelope=parent),
            "fixed_policy_accept",
            False,
        ),
        (
            "signature_invalid",
            _request(constrained, parameters=allowed_parameters),
            "standard_signature_invalid",
            True,
        ),
    )


def _envelope(
    *,
    action_scope: str = _ACTION_SCOPE,
    authorized_scopes: tuple[str, ...] | None = None,
    scope_constraints: dict[str, list[dict[str, object]]] | None = None,
    flow_policy: dict[str, object] | None = None,
    parent_envelope: RequestEnvelope | None = None,
    turn_id: str,
) -> RequestEnvelope:
    """构造 runner 使用的 canonical envelope。"""
    return build_request_envelope(
        sender_aid=_SENDER_AID,
        receiver_aid=_RECEIVER_AID,
        token=_TOKEN,
        session_id="session-route-b-shadow-runner",
        turn_id=turn_id,
        issued_at=_OBSERVED_AT - timedelta(minutes=5),
        expires_at=_OBSERVED_AT + timedelta(minutes=5),
        action_scope=action_scope,
        authorized_scopes=authorized_scopes,
        scope_constraints=scope_constraints,
        flow_policy=flow_policy,
        message=_MESSAGE,
        parent_envelope=parent_envelope,
    )


def _request(
    envelope: RequestEnvelope,
    *,
    parameters: dict[str, object] | None = None,
    flow_labels: tuple[str, ...] = ("public",),
    observed_at: datetime = _OBSERVED_AT,
    parent_envelope: RequestEnvelope | None = None,
    message_digest: bytes | None = None,
) -> RouteBShadowRequest:
    """构造只包含 transport 摘要的 runner request snapshot。"""
    binding = SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        key_id=b"route-b-shadow-runner-key",
        profile_id=SignatureProfileId.ML_DSA_PURE,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=envelope.digest(),
    )
    return RouteBShadowRequest(
        binding=binding,
        envelope=envelope,
        sender_aid=_SENDER_AID,
        receiver_aid=_RECEIVER_AID,
        token_digest=hashlib.sha256(_TOKEN).digest(),
        message_digest=message_digest or hashlib.sha256(_MESSAGE).digest(),
        action_scope=envelope.action_scope,
        observed_at=observed_at,
        parameters=parameters,
        flow_labels=flow_labels,
        parent_envelope=parent_envelope,
    )


if __name__ == "__main__":
    raise SystemExit(main())
