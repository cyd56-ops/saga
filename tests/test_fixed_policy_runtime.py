"""Tests for trusted Route B runtime fact compilation and real ML-DSA shadow."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from typing import cast
import unittest

import cryptography

from neural import (
    AUTHORIZATION_FACT_NAMES,
    RouteBFixedPolicyShadowRoute,
    RouteBShadowRequest,
    RouteBTrustedFactCompiler,
    summarize_route_b_shadow_corpus,
)
from pq import (
    CryptographyMLDSABackend,
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    MLDSABackendContractV1,
    MLDSABackendDescriptorV1,
    MLDSARouteBVerificationEvidence,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)
from saga.messages import RequestEnvelope, build_request_envelope


_SENDER_AID = "alice@example.com:email_agent"
_RECEIVER_AID = "bob@example.com:email_agent"
_TOKEN = b"route-b-runtime-token"
_MESSAGE = b"send the report"
_ACTION_SCOPE = "tool_call:send_email"
_NOW = datetime(2026, 7, 18, 12, 30, tzinfo=timezone.utc)


def _envelope(
    *,
    action_scope: str = _ACTION_SCOPE,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    scope_constraints: dict[str, list[dict[str, object]]] | None = None,
    flow_policy: dict[str, object] | None = None,
    parent_envelope: RequestEnvelope | None = None,
    authorized_scopes: tuple[str, ...] | None = None,
    turn_id: str = "turn-route-b-shadow",
) -> RequestEnvelope:
    """构造 canonical Route B runtime envelope，不生成或保存签名密钥。"""
    return build_request_envelope(
        sender_aid=_SENDER_AID,
        receiver_aid=_RECEIVER_AID,
        token=_TOKEN,
        session_id="session-route-b-shadow",
        turn_id=turn_id,
        issued_at=issued_at or (_NOW - timedelta(minutes=5)),
        expires_at=expires_at or (_NOW + timedelta(minutes=5)),
        action_scope=action_scope,
        authorized_scopes=authorized_scopes,
        scope_constraints=scope_constraints,
        flow_policy=flow_policy,
        message=_MESSAGE,
        parent_envelope=parent_envelope,
    )


def _binding(envelope: RequestEnvelope) -> SignatureBindingV1:
    """把 pure ML-DSA-44 profile 绑定到指定 canonical envelope digest。"""
    return SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        key_id=b"route-b-runtime-shadow-key",
        profile_id=SignatureProfileId.ML_DSA_PURE,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=envelope.digest(),
    )


def _request(
    envelope: RequestEnvelope,
    *,
    binding: SignatureBindingV1 | None = None,
    observed_at: datetime = _NOW,
    parameters: dict[str, object] | None = None,
    flow_labels: tuple[str, ...] = ("public",),
    parent_envelope: RequestEnvelope | None = None,
    message_digest: bytes | None = None,
) -> RouteBShadowRequest:
    """构造只携带 token/message 摘要的 runtime shadow snapshot。"""
    return RouteBShadowRequest(
        binding=binding or _binding(envelope),
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


def _descriptor() -> MLDSABackendDescriptorV1:
    """构造 compiler 单元测试使用的严格 R6 descriptor。"""
    return MLDSABackendDescriptorV1(
        backend_name="fake-vetted-mldsa",
        backend_version="1.2.3",
        provider_name="fake-provider",
        provider_version="9.8.7",
        api_version="saga-mldsa-backend-v1",
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        available=True,
    )


def _signature_evidence(valid: bool = True) -> MLDSARouteBVerificationEvidence:
    """构造带 descriptor 的 R6 wiring evidence，用于隔离 compiler 单元测试。"""
    return MLDSARouteBVerificationEvidence(
        accepted=valid,
        reason="signature_valid" if valid else "signature_invalid",
        descriptor=_descriptor(),
    )


def _real_contract(
    backend: CryptographyMLDSABackend,
) -> MLDSABackendContractV1:
    """从当前真实 provider 版本构造显式批准的测试 contract。"""
    descriptor = backend.descriptor()
    return MLDSABackendContractV1(
        backend_name="cryptography",
        backend_version=cryptography.__version__,
        provider_name="OpenSSL",
        provider_version=descriptor.provider_version,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        timeout_seconds=1.0,
    )


class RouteBTrustedFactCompilerTests(unittest.TestCase):
    """验证真实 runtime snapshot 到六项 provenance facts 的 fail-closed 编译。"""

    def setUp(self) -> None:
        """构造不持有密码状态的 compiler。"""
        self.compiler = RouteBTrustedFactCompiler()

    def test_valid_runtime_snapshot_compiles_all_six_provenanced_true_facts(self) -> None:
        """匹配的 binding/envelope/transport/policy/time 应生成六项 true facts。"""
        envelope = _envelope()
        result = self.compiler.compile(_request(envelope), _signature_evidence())
        fact_map = result.fact_set.fact_map()
        trace_map = result.trace_map()

        self.assertEqual(tuple(fact_map), AUTHORIZATION_FACT_NAMES)
        self.assertTrue(all(fact.value for fact in fact_map.values()))
        self.assertEqual(tuple(trace_map), AUTHORIZATION_FACT_NAMES)
        for name in AUTHORIZATION_FACT_NAMES:
            self.assertEqual(
                fact_map[name].provenance.evidence_digest,
                trace_map[name].evidence_digest,
            )
            self.assertEqual(len(trace_map[name].evidence_digest), 32)
        payload = json.dumps(result.as_dict(), sort_keys=True)
        self.assertNotIn(_TOKEN.decode("ascii"), payload)
        self.assertNotIn(_MESSAGE.decode("ascii"), payload)
        self.assertNotIn("signature", payload.lower().replace("signature_", ""))

    def test_each_runtime_check_produces_the_expected_false_fact(self) -> None:
        """签名、transport、scope、flow、delegation 和 time 各自可独立拒绝。"""
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
            turn_id="turn-constrained",
        )
        child = _envelope(
            parent_envelope=_envelope(turn_id="parent-for-missing"),
            turn_id="child-missing-parent",
        )
        cases = (
            (
                "signature",
                _request(constrained, parameters={"recipient_domain": "example.com"}),
                _signature_evidence(False),
                "standard_signature_valid",
                "standard_signature_invalid",
            ),
            (
                "envelope",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    message_digest=b"M" * 32,
                ),
                _signature_evidence(),
                "request_envelope_valid",
                "request_envelope_mismatch",
            ),
            (
                "scope",
                _request(constrained, parameters={"recipient_domain": "evil.test"}),
                _signature_evidence(),
                "scope_authorized",
                "scope_not_authorized",
            ),
            (
                "flow",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    flow_labels=("private",),
                ),
                _signature_evidence(),
                "flow_allowed",
                "flow_policy_denied",
            ),
            (
                "delegation",
                _request(child),
                _signature_evidence(),
                "delegation_allowed",
                "delegation_policy_denied",
            ),
            (
                "time",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    observed_at=_NOW + timedelta(hours=1),
                ),
                _signature_evidence(),
                "time_window_valid",
                "time_window_invalid",
            ),
        )

        for label, request, evidence, fact_name, reason in cases:
            with self.subTest(case=label):
                result = self.compiler.compile(request, evidence)
                trace = result.trace_map()[cast(object, fact_name)]
                self.assertFalse(trace.value)
                self.assertEqual(trace.reason, reason)

    def test_delegated_child_must_match_parent_and_attenuate_scope(self) -> None:
        """合法子 capability 通过；缺父或新增动作族形成 delegation false fact。"""
        parent = _envelope(
            action_scope="tool_call",
            authorized_scopes=("tool_call",),
            turn_id="parent-tool",
        )
        child = _envelope(
            action_scope=_ACTION_SCOPE,
            authorized_scopes=(_ACTION_SCOPE,),
            parent_envelope=parent,
            turn_id="child-email",
        )
        valid = self.compiler.compile(
            _request(child, parent_envelope=parent),
            _signature_evidence(),
        )
        self.assertTrue(valid.trace_map()["delegation_allowed"].value)

        escalation = _envelope(
            action_scope="memory_write",
            authorized_scopes=("memory_write",),
            parent_envelope=parent,
            turn_id="child-escalation",
        )
        invalid = self.compiler.compile(
            _request(escalation, parent_envelope=parent),
            _signature_evidence(),
        )
        self.assertFalse(invalid.trace_map()["delegation_allowed"].value)

    def test_request_snapshot_rejects_mutable_or_noncanonical_boundary_values(self) -> None:
        """Naive 时间、错误 digest、非 tuple labels 和 NaN 参数不能形成 snapshot。"""
        envelope = _envelope()
        valid = _request(envelope)
        invalid_changes = (
            {"observed_at": datetime(2026, 7, 18, 12, 30)},
            {"token_digest": b"T" * 31},
            {"message_digest": bytearray(b"M" * 32)},
            {"flow_labels": cast(tuple[str, ...], ["public"])},
            {"parameters": {"score": math.nan}},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaises((TypeError, ValueError)):
                    replace(valid, **changes)


class RouteBRealMLDSAFixedPolicyShadowTests(unittest.TestCase):
    """使用真实 cryptography/OpenSSL ML-DSA-44 验证 Route B shadow corpus。"""

    def test_real_mldsa_signed_runtime_corpus_is_equivalent_and_has_no_authority(self) -> None:
        """真实签名正负样本必须等价，且始终无执行副作用入口。"""
        backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        descriptor = backend.descriptor()
        self.assertTrue(descriptor.available)
        verifier = MLDSARouteBVerifier(backend, _real_contract(backend))
        route = RouteBFixedPolicyShadowRoute(verifier)
        key_pair = backend.keygen_pair()

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
            turn_id="real-constrained",
        )
        parent = _envelope(
            action_scope="tool_call",
            authorized_scopes=("tool_call",),
            turn_id="real-parent",
        )
        child = _envelope(
            parent_envelope=parent,
            turn_id="real-child",
        )
        corpus = (
            (
                "valid",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                ),
                "fixed_policy_accept",
                False,
            ),
            (
                "scope",
                _request(
                    constrained,
                    parameters={"recipient_domain": "evil.test"},
                ),
                "scope_not_authorized",
                False,
            ),
            (
                "flow",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    flow_labels=("private",),
                ),
                "flow_policy_denied",
                False,
            ),
            (
                "time",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    observed_at=_NOW + timedelta(hours=1),
                ),
                "time_window_invalid",
                False,
            ),
            (
                "transport",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                    message_digest=b"X" * 32,
                ),
                "request_envelope_invalid",
                False,
            ),
            (
                "delegation",
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
                "invalid_signature",
                _request(
                    constrained,
                    parameters={"recipient_domain": "example.com"},
                ),
                "standard_signature_invalid",
                True,
            ),
        )

        results = []
        for label, request, expected_reason, corrupt_signature in corpus:
            binding = request.binding
            signature = backend.sign(key_pair.secret_key, binding.canonical_bytes())
            if corrupt_signature:
                signature = bytes((signature[0] ^ 1,)) + signature[1:]
            evidence = route.evaluate(request, key_pair.public_key, signature)
            results.append((label, evidence))
            with self.subTest(case=label):
                self.assertTrue(evidence.shadow_evidence.equivalent)
                self.assertEqual(
                    evidence.shadow_evidence.fixed_decision.reason,
                    expected_reason,
                )
                self.assertFalse(evidence.authority_granted)
                self.assertFalse(evidence.shadow_evidence.authority_granted)
                payload = json.dumps(evidence.as_dict(), sort_keys=True)
                self.assertNotIn(key_pair.public_key.hex(), payload)
                self.assertNotIn(signature.hex(), payload)

        manifest = summarize_route_b_shadow_corpus(results)
        self.assertEqual(manifest.total_cases, 8)
        self.assertEqual(manifest.signature_accepted_count, 7)
        self.assertEqual(manifest.fixed_accepted_count, 2)
        self.assertEqual(manifest.equivalent_count, 8)
        self.assertEqual(manifest.mismatch_count, 0)
        self.assertEqual(manifest.authority_granted_count, 0)
        self.assertTrue(manifest.all_equivalent)
        self.assertTrue(
            all(count > 0 for _name, count in manifest.fact_false_counts)
        )
        manifest_payload = json.dumps(manifest.as_dict(), sort_keys=True)
        self.assertNotIn(key_pair.public_key.hex(), manifest_payload)
        self.assertFalse(hasattr(route, "commit"))
        self.assertFalse(hasattr(route, "authorize"))

    def test_shadow_corpus_manifest_rejects_duplicate_case_ids(self) -> None:
        """机器可读 manifest 不允许重复 case id 混淆证据计数。"""
        backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        route = RouteBFixedPolicyShadowRoute(
            MLDSARouteBVerifier(backend, _real_contract(backend))
        )
        key_pair = backend.keygen_pair()
        request = _request(_envelope(turn_id="manifest-duplicate"))
        signature = backend.sign(
            key_pair.secret_key,
            request.binding.canonical_bytes(),
        )
        evidence = route.evaluate(request, key_pair.public_key, signature)

        with self.assertRaises(ValueError):
            summarize_route_b_shadow_corpus(
                (("duplicate", evidence), ("duplicate", evidence))
            )


if __name__ == "__main__":
    unittest.main()
