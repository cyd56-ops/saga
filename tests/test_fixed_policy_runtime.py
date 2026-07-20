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
    FixedAuthorizationCircuitV1,
    MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1,
    RouteBCompiledRawAuthorizationInput,
    RouteBFixedAuthorizationCircuitEvidence,
    RouteBFixedAuthorizationCircuitRoute,
    RouteBFixedPolicyEnforcedRoute,
    RouteBFixedPolicyEnforcementEvidence,
    RouteBFixedPolicyShadowRoute,
    RouteBAuthorizationPolicyCompilerV1,
    RouteBRawAuthorizationCompiler,
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
    max_delegation_depth: int = 8,
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
        max_delegation_depth=max_delegation_depth,
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


class RouteBFixedPolicyEnforcementTests(unittest.TestCase):
    """验证 B1.5 强制 AND 与 Coordinator-only authority 边界。"""

    def setUp(self) -> None:
        """构造真实 ML-DSA-44 backend、无状态 enforcement route 和临时密钥对。"""
        self.backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        self.route = RouteBFixedPolicyEnforcedRoute(
            MLDSARouteBVerifier(self.backend, _real_contract(self.backend))
        )
        self.key_pair = self.backend.keygen_pair()

    def _evaluate(
        self,
        request: RouteBShadowRequest,
        *,
        corrupt_signature: bool = False,
    ) -> RouteBFixedPolicyEnforcementEvidence:
        """对 binding 生成一次测试签名，并可确定性破坏首字节。"""
        signature = self.backend.sign(
            self.key_pair.secret_key,
            request.binding.canonical_bytes(),
        )
        if corrupt_signature:
            signature = bytes((signature[0] ^ 1,)) + signature[1:]
        return self.route.evaluate(request, self.key_pair.public_key, signature)

    def test_valid_request_requires_coordinator_after_route_b_accepts(self) -> None:
        """六项事实和外部验签均成立时只生成待 Coordinator 提交的接受 evidence。"""
        evidence = self._evaluate(_request(_envelope(turn_id="enforced-valid")))

        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "route_b_fixed_policy_accept")
        self.assertTrue(evidence.outside_standard_signature_valid)
        self.assertTrue(evidence.signature_fact_matches_outside)
        self.assertEqual(evidence.fixed_decision.output, 1)
        self.assertTrue(evidence.coordinator_commit_required)
        self.assertFalse(evidence.authority_granted)
        self.assertFalse(hasattr(self.route, "commit"))
        self.assertFalse(hasattr(self.route, "authorize"))
        self.assertFalse(hasattr(self.route, "build_local_execution_context"))

    def test_fixed_policy_rejection_blocks_valid_standard_signature(self) -> None:
        """标准签名有效但 scope predicate 失败时，B1.5 必须拒绝。"""
        envelope = _envelope(
            scope_constraints={
                _ACTION_SCOPE: [
                    {
                        "field": "recipient_domain",
                        "op": "eq",
                        "value": "example.com",
                    }
                ]
            },
            turn_id="enforced-scope-reject",
        )
        evidence = self._evaluate(
            _request(envelope, parameters={"recipient_domain": "evil.test"})
        )

        self.assertTrue(evidence.outside_standard_signature_valid)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "scope_not_authorized")
        self.assertEqual(evidence.fixed_decision.output, 0)

    def test_external_signature_remains_independent_when_compiler_facts_are_forged(self) -> None:
        """即使 compiler/fixed 路径被伪造成接受，电路外无效签名仍必须拒绝。"""
        request = _request(_envelope(turn_id="enforced-signature-independent"))
        forged_facts = self.route.fact_compiler.compile(
            request,
            _signature_evidence(True),
        )
        self.route.fact_compiler.compile = lambda _request, _evidence: forged_facts  # type: ignore[method-assign]

        evidence = self._evaluate(request, corrupt_signature=True)

        self.assertFalse(evidence.outside_standard_signature_valid)
        self.assertTrue(evidence.fixed_decision.accepted)
        self.assertEqual(evidence.fixed_decision.output, 1)
        self.assertFalse(evidence.signature_fact_matches_outside)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "standard_signature_fact_mismatch")

    def test_non_integer_fixed_output_cannot_authorize(self) -> None:
        """即使 accepted 位为真，布尔或浮点 1 也不能冒充精确整数电路输出。"""
        request = _request(_envelope(turn_id="enforced-output-type"))
        original_evaluate = self.route.fixed_policy.evaluate
        original = original_evaluate(
            self.route.fact_compiler.compile(request, _signature_evidence(True)).fact_set
        )
        invalid_decisions = (
            (True, True),
            (True, 1.0),
            (False, 1),
        )
        for invalid_accepted, invalid_output in invalid_decisions:
            with self.subTest(
                accepted=invalid_accepted,
                output=repr(invalid_output),
            ):
                self.route.fixed_policy.evaluate = (  # type: ignore[method-assign]
                    lambda _facts,
                    accepted=invalid_accepted,
                    output=invalid_output: replace(
                        original,
                        accepted=accepted,
                        output=cast(int, output),
                    )
                )
                evidence = self._evaluate(request)
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, "fixed_policy_output_invalid")
        self.route.fixed_policy.evaluate = original_evaluate  # type: ignore[method-assign]

    def test_enforcement_evidence_rejects_accepted_or_authority_relabeling(self) -> None:
        """冻结 evidence 不能把拒绝翻转为接受，也不能自行携带 authority。"""
        rejected = self._evaluate(
            _request(_envelope(turn_id="enforced-evidence-relabel")),
            corrupt_signature=True,
        )
        with self.assertRaises(ValueError):
            replace(rejected, accepted=True)
        with self.assertRaises(ValueError):
            replace(rejected, authority_granted=cast(object, True))
        with self.assertRaises(ValueError):
            replace(rejected, coordinator_commit_required=cast(object, False))


class RouteBFixedAuthorizationCircuitRouteTests(unittest.TestCase):
    """验证真实 ML-DSA、B1.5 与 B2 原始关系的无状态联合强制路径。"""

    def setUp(self) -> None:
        """构造真实 ML-DSA-44 backend、B2 route 和仅驻留内存的测试密钥。"""
        self.backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        self.route = RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(self.backend, _real_contract(self.backend))
        )
        self.key_pair = self.backend.keygen_pair()

    def _evaluate(
        self,
        request: RouteBShadowRequest,
        *,
        corrupt_signature: bool = False,
    ) -> RouteBFixedAuthorizationCircuitEvidence:
        """签署 request binding，并可确定性破坏签名字节形成负向样本。"""
        signature = self.backend.sign(
            self.key_pair.secret_key,
            request.binding.canonical_bytes(),
        )
        if corrupt_signature:
            signature = bytes((signature[0] ^ 1,)) + signature[1:]
        return self.route.evaluate(request, self.key_pair.public_key, signature)

    def test_valid_request_accepts_b1_and_b2_but_cannot_commit_authority(self) -> None:
        """真实签名与全部关系成立时只生成待 Coordinator 提交的 B2 evidence。"""
        evidence = self._evaluate(_request(_envelope(turn_id="b2-valid")))

        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "route_b_fixed_authorization_accept")
        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertTrue(evidence.relation_decision.accepted)
        self.assertEqual(evidence.relation_decision.output, 1)
        self.assertTrue(evidence.raw_signature_matches_outside)
        self.assertTrue(evidence.coordinator_commit_required)
        self.assertFalse(evidence.authority_granted)
        self.assertFalse(hasattr(self.route, "commit"))
        self.assertFalse(hasattr(self.route, "authorize"))
        self.assertFalse(hasattr(self.route, "build_local_execution_context"))

    def test_b1_exact_scope_constraints_remain_required_beside_b2_family_bits(self) -> None:
        """B2 动作族包含成立时，B1.5 的精确参数约束失败仍必须拒绝。"""
        envelope = _envelope(
            scope_constraints={
                _ACTION_SCOPE: [
                    {
                        "field": "recipient_domain",
                        "op": "eq",
                        "value": "example.com",
                    }
                ]
            },
            turn_id="b2-b1-constraint",
        )
        evidence = self._evaluate(
            _request(envelope, parameters={"recipient_domain": "evil.test"})
        )

        self.assertFalse(evidence.policy_evidence.accepted)
        self.assertTrue(evidence.relation_decision.accepted)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "scope_not_authorized")

    def test_b2_digest_relation_rejects_even_if_b1_facts_are_forged_true(self) -> None:
        """B1 facts 被替换为全真时，B2 仍直接发现 transport message 摘要不匹配。"""
        valid_request = _request(_envelope(turn_id="b2-forged-b1-source"))
        forged_facts = self.route.fact_compiler.compile(
            valid_request,
            _signature_evidence(True),
        )
        self.route.fact_compiler.compile = (  # type: ignore[method-assign]
            lambda _request, _evidence: forged_facts
        )
        mismatched_request = _request(
            _envelope(turn_id="b2-digest-mismatch"),
            message_digest=b"M" * 32,
        )

        evidence = self._evaluate(mismatched_request)

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(
            evidence.relation_decision.reason,
            "request_envelope_mismatch",
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "request_envelope_mismatch")

    def test_external_signature_is_necessary_even_if_b1_and_b2_inputs_are_forged(self) -> None:
        """B1/B2 compiler 均被伪造成有效时，电路外无效 ML-DSA 仍阻断接受。"""
        request = _request(_envelope(turn_id="b2-signature-independent"))
        forged_facts = self.route.fact_compiler.compile(
            request,
            _signature_evidence(True),
        )
        forged_raw = self.route.raw_compiler.compile(
            request,
            _signature_evidence(True),
        )
        self.route.fact_compiler.compile = (  # type: ignore[method-assign]
            lambda _request, _evidence: forged_facts
        )
        self.route.raw_compiler.compile = (  # type: ignore[method-assign]
            lambda _request, _evidence: forged_raw
        )

        evidence = self._evaluate(request, corrupt_signature=True)

        self.assertFalse(evidence.policy_evidence.outside_standard_signature_valid)
        self.assertTrue(evidence.policy_evidence.fixed_decision.accepted)
        self.assertTrue(evidence.relation_decision.accepted)
        self.assertFalse(evidence.raw_signature_matches_outside)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "standard_signature_fact_mismatch")

    def test_raw_signature_bit_must_match_valid_external_signature(self) -> None:
        """外部签名有效但 B2 签名位被降为 0 时，显式一致性检查拒绝。"""
        request = _request(_envelope(turn_id="b2-raw-signature-mismatch"))
        compiled = self.route.raw_compiler.compile(
            request,
            _signature_evidence(True),
        )
        raw_input = replace(compiled.raw_input, standard_signature_valid=False)
        forged = RouteBCompiledRawAuthorizationInput(
            compiler_id=compiled.compiler_id,
            compiler_version=compiled.compiler_version,
            raw_input=raw_input,
            source_digest=raw_input.digest(),
        )
        self.route.raw_compiler.compile = (  # type: ignore[method-assign]
            lambda _request, _evidence: forged
        )

        evidence = self._evaluate(request)

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.raw_signature_matches_outside)
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "raw_standard_signature_mismatch")

    def test_custom_runtime_flow_label_fails_closed_until_next_layout(self) -> None:
        """B1 可识别的自定义 IFC 标签在 B2 V1 未建模时必须 fail closed。"""
        envelope = _envelope(
            flow_policy={"egress": {_ACTION_SCOPE: ["partner"]}},
            turn_id="b2-custom-flow",
        )
        evidence = self._evaluate(
            _request(envelope, flow_labels=("partner",))
        )

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(evidence.relation_decision.reason, "flow_policy_denied")
        self.assertFalse(evidence.accepted)

    def test_b2_fixed_ttl_rejects_long_lived_b1_valid_envelope(self) -> None:
        """软件时间事实成立但有效期超过 B2 固定 900 秒时，time relation 必须拒绝。"""
        envelope = _envelope(
            issued_at=_NOW - timedelta(minutes=5),
            expires_at=_NOW + timedelta(minutes=11),
            turn_id="b2-ttl-limit",
        )
        evidence = self._evaluate(_request(envelope))

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(evidence.relation_decision.reason, "time_window_invalid")
        self.assertFalse(evidence.accepted)

    def test_b2_rejects_child_that_expands_parent_max_delegation_depth(self) -> None:
        """B1 事实成立但子 capability 调大父最大深度时，B2 delegation 必须拒绝。"""
        parent = _envelope(
            action_scope="tool_call",
            authorized_scopes=("tool_call",),
            max_delegation_depth=1,
            turn_id="b2-depth-parent",
        )
        child = _envelope(
            parent_envelope=parent,
            max_delegation_depth=8,
            turn_id="b2-depth-child",
        )
        evidence = self._evaluate(
            _request(child, parent_envelope=parent)
        )

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(
            evidence.relation_decision.reason,
            "delegation_policy_denied",
        )
        self.assertFalse(evidence.accepted)

    def test_b2_rejects_child_that_expands_parent_flow_policy(self) -> None:
        """子 capability 新增父未允许的已知 flow label 时，B2 delegation 必须拒绝。"""
        parent = _envelope(
            action_scope="tool_call",
            authorized_scopes=("tool_call",),
            turn_id="b2-flow-parent",
        )
        child = _envelope(
            parent_envelope=parent,
            flow_policy={"egress": {_ACTION_SCOPE: ["private"]}},
            turn_id="b2-flow-child",
        )
        evidence = self._evaluate(
            _request(child, parent_envelope=parent, flow_labels=("public",))
        )

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(
            evidence.relation_decision.reason,
            "delegation_policy_denied",
        )

    def test_b2_rejects_child_time_window_outside_parent_window(self) -> None:
        """子 capability 晚于父到期时间时，即使当前均有效也必须拒绝。"""
        parent = _envelope(
            action_scope="tool_call",
            authorized_scopes=("tool_call",),
            issued_at=_NOW - timedelta(minutes=10),
            expires_at=_NOW + timedelta(minutes=5),
            turn_id="b2-time-parent",
        )
        child = _envelope(
            parent_envelope=parent,
            issued_at=_NOW - timedelta(minutes=5),
            expires_at=_NOW + timedelta(minutes=10),
            turn_id="b2-time-child",
        )
        evidence = self._evaluate(
            _request(child, parent_envelope=parent)
        )

        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertFalse(evidence.relation_decision.accepted)
        self.assertEqual(
            evidence.relation_decision.reason,
            "delegation_policy_denied",
        )

    def test_b2_evidence_rejects_acceptance_or_authority_relabeling(self) -> None:
        """冻结 B2 evidence 不能翻转拒绝结果或自行移除 Coordinator 边界。"""
        rejected = self._evaluate(
            _request(_envelope(turn_id="b2-evidence-relabel")),
            corrupt_signature=True,
        )
        with self.assertRaises(ValueError):
            replace(rejected, accepted=True)
        with self.assertRaises(ValueError):
            replace(rejected, authority_granted=cast(object, True))
        with self.assertRaises(ValueError):
            replace(rejected, coordinator_commit_required=cast(object, False))

    def test_memory_profile_reuses_real_mldsa_route_and_enforces_short_policy(self) -> None:
        """第二 profile 复用同一 runtime route，并直接限制 memory scope、TTL 和 depth。"""
        compiled = RouteBAuthorizationPolicyCompilerV1().compile(
            MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1
        )
        memory_route = RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(self.backend, _real_contract(self.backend)),
            raw_compiler=RouteBRawAuthorizationCompiler(compiled.profile),
            relation_circuit=compiled.circuit,
        )
        envelope = _envelope(
            action_scope="memory_write",
            authorized_scopes=("memory_read", "memory_write"),
            issued_at=_NOW - timedelta(minutes=2),
            expires_at=_NOW + timedelta(minutes=2),
            max_delegation_depth=2,
            turn_id="b3-memory-valid",
        )
        request = _request(envelope)
        signature = self.backend.sign(
            self.key_pair.secret_key,
            request.binding.canonical_bytes(),
        )

        evidence = memory_route.evaluate(
            request,
            self.key_pair.public_key,
            signature,
        )

        self.assertTrue(evidence.accepted)
        self.assertTrue(evidence.policy_evidence.accepted)
        self.assertTrue(evidence.relation_decision.accepted)
        self.assertFalse(evidence.authority_granted)
        self.assertFalse(hasattr(memory_route, "commit"))

    def test_memory_profile_rejects_tool_surface_and_long_ttl(self) -> None:
        """B1.5 可接受的 tool 或长时 memory 请求仍被第二 profile 的 B2 常量拒绝。"""
        compiled = RouteBAuthorizationPolicyCompilerV1().compile(
            MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1
        )
        memory_route = RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(self.backend, _real_contract(self.backend)),
            raw_compiler=RouteBRawAuthorizationCompiler(compiled.profile),
            relation_circuit=compiled.circuit,
        )
        envelopes = (
            _envelope(
                issued_at=_NOW - timedelta(minutes=2),
                expires_at=_NOW + timedelta(minutes=2),
                max_delegation_depth=2,
                turn_id="b3-memory-tool-reject",
            ),
            _envelope(
                action_scope="memory_read",
                issued_at=_NOW - timedelta(minutes=3),
                expires_at=_NOW + timedelta(minutes=3),
                max_delegation_depth=2,
                turn_id="b3-memory-ttl-reject",
            ),
        )
        expected_reasons = ("scope_not_authorized", "time_window_invalid")
        for envelope, expected_reason in zip(
            envelopes,
            expected_reasons,
            strict=True,
        ):
            request = _request(envelope)
            signature = self.backend.sign(
                self.key_pair.secret_key,
                request.binding.canonical_bytes(),
            )
            with self.subTest(reason=expected_reason):
                evidence = memory_route.evaluate(
                    request,
                    self.key_pair.public_key,
                    signature,
                )
                self.assertTrue(evidence.policy_evidence.accepted)
                self.assertFalse(evidence.relation_decision.accepted)
                self.assertEqual(evidence.relation_decision.reason, expected_reason)
                self.assertFalse(evidence.accepted)

    def test_runtime_route_rejects_mismatched_compiler_and_circuit_profiles(self) -> None:
        """raw compiler 与 fixed circuit profile 不一致时构造 route 即 fail closed。"""
        with self.assertRaises(ValueError):
            RouteBFixedAuthorizationCircuitRoute(
                MLDSARouteBVerifier(self.backend, _real_contract(self.backend)),
                raw_compiler=RouteBRawAuthorizationCompiler(
                    MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1
                ),
                relation_circuit=FixedAuthorizationCircuitV1(),
            )


if __name__ == "__main__":
    unittest.main()
