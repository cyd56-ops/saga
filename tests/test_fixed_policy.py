"""Tests for Route B B0.5 typed facts and B1 fixed-policy shadow evaluation."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import itertools
import math
import random
from typing import cast
import unittest

from neural import (
    AUTHORIZATION_FACT_NAMES,
    AUTHORIZATION_LAYOUT_ID_V1,
    AUTHORIZATION_LAYOUT_VERSION_V1,
    AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1,
    AUTHORIZATION_POLICY_PROFILE_ID_V1,
    AUTHORIZATION_POLICY_PROFILE_VERSION_V1,
    AuthorizationFact,
    AuthorizationFactName,
    AuthorizationFactProvenance,
    AuthorizationFactSet,
    AuthorizationFactSource,
    AuthorizationInputField,
    AuthorizationInputLayout,
    AuthorizationPredicate,
    AuthorizationPredicateIR,
    FixedPolicyAggregator,
    FixedPolicyShadowEvidence,
    FixedPolicyShadowEvaluator,
    ReferenceAuthorizationPolicy,
    assert_fixed_circuit,
    build_authorization_input_layout_v1,
    build_authorization_predicate_ir_v1,
    build_fixed_policy_aggregator_v1,
    build_fixed_policy_shadow_evaluator_v1,
    build_reference_authorization_policy_v1,
    find_trainable_state,
)
from pq import MLDSARouteBVerificationEvidence


_FACT_SOURCES: dict[AuthorizationFactName, AuthorizationFactSource] = {
    "standard_signature_valid": AuthorizationFactSource.STANDARD_MLDSA_VERIFIER,
    "request_envelope_valid": AuthorizationFactSource.CANONICAL_ENVELOPE_VALIDATOR,
    "scope_authorized": AuthorizationFactSource.LOCAL_SCOPE_POLICY,
    "flow_allowed": AuthorizationFactSource.LOCAL_FLOW_POLICY,
    "delegation_allowed": AuthorizationFactSource.LOCAL_DELEGATION_POLICY,
    "time_window_valid": AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
}


def _fact(name: AuthorizationFactName, value: bool, *, nonce: int = 0) -> AuthorizationFact:
    """构造带确定性内部 evidence 摘要的测试事实。"""
    evidence_digest = hashlib.sha256(
        f"{name}:{value}:{nonce}".encode("ascii")
    ).digest()
    return AuthorizationFact(
        name=name,
        value=value,
        provenance=AuthorizationFactProvenance(
            source=_FACT_SOURCES[name],
            source_version="test-validator-v1",
            evidence_digest=evidence_digest,
        ),
    )


def _fact_set(
    values: tuple[bool, ...] | None = None,
    *,
    nonce: int = 0,
) -> AuthorizationFactSet:
    """按规范 V1 顺序构造完整事实集合。"""
    resolved_values = values or tuple(True for _ in AUTHORIZATION_FACT_NAMES)
    return AuthorizationFactSet(
        layout_id=AUTHORIZATION_LAYOUT_ID_V1,
        layout_version=AUTHORIZATION_LAYOUT_VERSION_V1,
        facts=tuple(
            _fact(name, value, nonce=nonce)
            for name, value in zip(
                AUTHORIZATION_FACT_NAMES,
                resolved_values,
                strict=True,
            )
        ),
    )


def _signature_evidence(valid: bool) -> MLDSARouteBVerificationEvidence:
    """构造严格原生布尔签名结果，用于 shadow 外部必要条件检查。"""
    return MLDSARouteBVerificationEvidence(
        accepted=valid,
        reason="signature_valid" if valid else "signature_invalid",
    )


class AuthorizationInputLayoutTests(unittest.TestCase):
    """验证 typed layout、provenance 和版本边界。"""

    def test_v1_layout_encodes_complete_provenanced_boolean_facts(self) -> None:
        """规范事实集合应编码成固定六字节 0/1 向量。"""
        layout = build_authorization_input_layout_v1()
        values = (True, False, True, False, True, False)

        encoded = layout.encode(_fact_set(values))

        self.assertEqual(encoded, b"\x01\x00\x01\x00\x01\x00")
        self.assertEqual(layout.encoded_bytes, 6)
        self.assertEqual(layout.validate_encoded(encoded), (1, 0, 1, 0, 1, 0))

    def test_fact_values_require_builtin_bool_and_matching_internal_source(self) -> None:
        """整数、浮点、NaN/Inf 和错配来源均不能冒充内部布尔事实。"""
        valid_provenance = AuthorizationFactProvenance(
            source=AuthorizationFactSource.LOCAL_SCOPE_POLICY,
            source_version="scope-v1",
            evidence_digest=b"E" * 32,
        )
        invalid_values = (1, 0, 1.0, 0.0, math.nan, math.inf, "true")
        for value in invalid_values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    AuthorizationFact(
                        name="scope_authorized",
                        value=cast(bool, value),
                        provenance=valid_provenance,
                    )

        wrong_source = replace(
            valid_provenance,
            source=AuthorizationFactSource.LOCAL_FLOW_POLICY,
        )
        with self.assertRaises(ValueError):
            AuthorizationFact("scope_authorized", True, wrong_source)

    def test_provenance_rejects_unknown_version_and_wrong_digest_length(self) -> None:
        """来源版本和 evidence digest 必须是稳定规范值。"""
        for version in ("", "bad version", "x" * 65):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    AuthorizationFactProvenance(
                        AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
                        version,
                        b"D" * 32,
                    )
        for digest in (b"", b"D" * 31, b"D" * 33, bytearray(b"D" * 32)):
            with self.subTest(length=len(digest)):
                with self.assertRaises(ValueError):
                    AuthorizationFactProvenance(
                        AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
                        "time-v1",
                        cast(bytes, digest),
                    )

    def test_layout_and_fact_set_reject_duplicates_missing_unknown_and_version_drift(self) -> None:
        """重复、缺失、未知字段和 layout/version 漂移全部 fail-closed。"""
        layout = build_authorization_input_layout_v1()
        valid = _fact_set()
        with self.assertRaises(ValueError):
            replace(valid, facts=(*valid.facts, valid.facts[0]))

        missing = replace(valid, facts=valid.facts[:-1])
        self.assertEqual(
            build_fixed_policy_aggregator_v1().evaluate(missing).reason,
            "fixed_policy_input_invalid",
        )

        unknown_layout = replace(valid, layout_id="future-layout")
        self.assertEqual(
            build_fixed_policy_aggregator_v1().evaluate(unknown_layout).reason,
            "fixed_policy_input_invalid",
        )
        unknown_version = replace(valid, layout_version=2)
        self.assertEqual(
            build_reference_authorization_policy_v1().evaluate(unknown_version).reason,
            "reference_policy_input_invalid",
        )

        with self.assertRaises(ValueError):
            replace(layout, layout_id="future-layout")
        with self.assertRaises(ValueError):
            replace(layout, version=2)
        with self.assertRaises(ValueError):
            replace(layout, fields=(layout.fields[0], layout.fields[0]))
        with self.assertRaises(ValueError):
            replace(layout, fields=layout.fields[:-1])

    def test_encoded_boundary_rejects_wrong_type_length_and_non_binary_uint8(self) -> None:
        """固定电路入口只接受正确长度且每字节为 0/1 的 bytes。"""
        layout = build_authorization_input_layout_v1()
        invalid_payloads = (
            bytearray(b"\x01" * 6),
            b"\x01" * 5,
            b"\x01" * 7,
            b"\x01\x01\x01\x01\x01\x02",
            b"\x01\x01\x01\x01\x01\xff",
        )
        for payload in invalid_payloads:
            with self.subTest(payload=repr(payload)):
                with self.assertRaises((TypeError, ValueError)):
                    layout.validate_encoded(cast(bytes, payload))

    def test_predicate_ir_rejects_unknown_profiles_operations_and_duplicates(self) -> None:
        """IR profile、操作、谓词 ID 和事实引用必须版本化且无重复。"""
        predicate_ir = build_authorization_predicate_ir_v1()
        with self.assertRaises(ValueError):
            replace(predicate_ir, policy_profile_id="future-policy")
        with self.assertRaises(ValueError):
            replace(predicate_ir, policy_profile_version=2)
        with self.assertRaises(ValueError):
            replace(predicate_ir, predicates=(predicate_ir.predicates[0],) * 2)
        with self.assertRaises(ValueError):
            replace(predicate_ir.predicates[0], operation=cast(object, "or"))

        duplicate_fact = replace(
            predicate_ir.predicates[1],
            predicate_id="different-id",
            fact_name=predicate_ir.predicates[0].fact_name,
        )
        with self.assertRaises(ValueError):
            replace(
                predicate_ir,
                predicates=(predicate_ir.predicates[0], duplicate_fact),
            )


class FixedPolicyAggregatorTests(unittest.TestCase):
    """验证 B1 固定 AND、trace、complexity 和 reference equivalence。"""

    def setUp(self) -> None:
        """构造共享规范 layout/IR 的 reference 与 fixed 路径。"""
        self.layout = build_authorization_input_layout_v1()
        self.predicate_ir = build_authorization_predicate_ir_v1()
        self.reference = ReferenceAuthorizationPolicy(self.layout, self.predicate_ir)
        self.aggregator = FixedPolicyAggregator(self.layout, self.predicate_ir)

    def test_exhaustive_boolean_space_matches_reference_and_stable_reason_mapping(self) -> None:
        """六事实全部 64 种组合必须与 reference 接受位和 reason 完全对应。"""
        for values in itertools.product((False, True), repeat=len(AUTHORIZATION_FACT_NAMES)):
            with self.subTest(values=values):
                facts = _fact_set(values)
                reference = self.reference.evaluate(facts)
                fixed = self.aggregator.evaluate(facts)
                self.assertEqual(fixed.accepted, reference.accepted)
                self.assertIs(type(fixed.output), int)
                self.assertIn(fixed.output, (0, 1))
                if reference.accepted:
                    self.assertEqual(reference.reason, "reference_policy_accept")
                    self.assertEqual(fixed.reason, "fixed_policy_accept")
                    self.assertEqual(fixed.output, 1)
                else:
                    self.assertEqual(fixed.reason, reference.reason)
                    self.assertEqual(fixed.output, 0)

    def test_trace_locates_first_reject_and_complexity_is_stable(self) -> None:
        """Trace 应定位首个失败谓词并输出固定结构复杂度。"""
        decision = self.aggregator.evaluate(
            _fact_set((True, True, False, False, True, True))
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "scope_not_authorized")
        self.assertEqual(decision.trace.encoded_input, (1, 1, 0, 0, 1, 1))
        self.assertEqual(decision.trace.affine_output, -1.0)
        self.assertEqual(decision.trace.relu_output, 0.0)
        self.assertEqual(decision.trace.accept_output, 0)
        self.assertEqual(
            tuple(item.predicate_id for item in decision.trace.predicates),
            AUTHORIZATION_FACT_NAMES,
        )
        self.assertEqual(
            decision.complexity.as_dict(),
            {
                "circuit_profile_id": "saga-route-b-fixed-policy-aggregator",
                "circuit_profile_version": 1,
                "input_count": 6,
                "input_bytes": 6,
                "predicate_count": 6,
                "fixed_linear_layers": 1,
                "fixed_relu_layers": 1,
                "fixed_parameter_count": 7,
                "circuit_depth": 2,
            },
        )

    def test_fixed_aggregator_has_no_trainable_state(self) -> None:
        """B1 固定 Linear/ReLU 在求值前后都不能出现梯度或训练入口。"""
        assert_fixed_circuit(self.aggregator)
        self.assertEqual(find_trainable_state(self.aggregator), ())
        self.assertTrue(self.aggregator.evaluate(_fact_set()).accepted)
        assert_fixed_circuit(self.aggregator)
        self.assertEqual(find_trainable_state(self.aggregator), ())

    def test_shadow_corpus_fixed_seed_matches_and_never_grants_authority(self) -> None:
        """固定种子差分 corpus 必须零不一致且 shadow authority 计数为零。"""
        evaluator = build_fixed_policy_shadow_evaluator_v1()
        rng = random.Random(20260718)
        cases = []
        for nonce in range(256):
            values = tuple(bool(rng.getrandbits(1)) for _ in AUTHORIZATION_FACT_NAMES)
            cases.append((_fact_set(values, nonce=nonce), _signature_evidence(values[0])))

        manifest = evaluator.evaluate_corpus(cases)

        self.assertTrue(manifest.all_equivalent)
        self.assertEqual(manifest.total_cases, 256)
        self.assertEqual(manifest.equivalent_cases, 256)
        self.assertEqual(manifest.mismatch_count, 0)
        self.assertEqual(manifest.authority_granted_count, 0)
        self.assertEqual(manifest.mismatches, ())
        for coverage in manifest.predicate_coverage:
            self.assertGreater(coverage.true_count, 0)
            self.assertGreater(coverage.false_count, 0)
        machine_readable = manifest.as_dict()
        self.assertTrue(machine_readable["all_equivalent"])
        self.assertEqual(machine_readable["authority_granted_count"], 0)

    def test_shadow_rejects_inside_outside_signature_fact_mismatch(self) -> None:
        """电路内签名事实与外部标准 evidence 不一致时必须标记不等价。"""
        evaluator = build_fixed_policy_shadow_evaluator_v1()
        evidence = evaluator.evaluate(_fact_set(), _signature_evidence(False))

        self.assertFalse(evidence.equivalent)
        self.assertFalse(evidence.signature_fact_matches_outside)
        self.assertEqual(evidence.reason, "standard_signature_fact_mismatch")
        self.assertFalse(evidence.authority_granted)

        invalid_values = (False, True, True, True, True, True)
        matched_reject = evaluator.evaluate(
            _fact_set(invalid_values),
            _signature_evidence(False),
        )
        self.assertTrue(matched_reject.equivalent)
        self.assertEqual(matched_reject.reference_decision.reason, "standard_signature_invalid")
        self.assertEqual(matched_reject.fixed_decision.reason, "standard_signature_invalid")
        self.assertFalse(matched_reject.authority_granted)

    def test_shadow_evidence_cannot_be_relabelled_as_authority(self) -> None:
        """B1 evidence dataclass 本身也必须拒绝非 shadow 模式或 authority=True。"""
        valid = build_fixed_policy_shadow_evaluator_v1().evaluate(
            _fact_set(),
            _signature_evidence(True),
        )
        with self.assertRaises(ValueError):
            replace(valid, mode=cast(object, "enforced"))
        with self.assertRaises(ValueError):
            replace(valid, authority_granted=cast(object, True))

    def test_deleting_each_required_predicate_is_detected_by_reference_corpus(self) -> None:
        """删除任一检查都应不等价，且不能接入正式 shadow evaluator。"""
        for deleted_index, deleted in enumerate(self.predicate_ir.predicates):
            with self.subTest(predicate=deleted.predicate_id):
                mutated_ir = replace(
                    self.predicate_ir,
                    policy_profile_id=AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1,
                    predicates=tuple(
                        predicate
                        for index, predicate in enumerate(self.predicate_ir.predicates)
                        if index != deleted_index
                    ),
                )
                mutated = FixedPolicyAggregator(self.layout, mutated_ir)
                values = tuple(
                    index != deleted_index
                    for index in range(len(AUTHORIZATION_FACT_NAMES))
                )
                facts = _fact_set(values)
                reference = self.reference.evaluate(facts)
                fixed = mutated.evaluate(facts)

                mutation_detected = reference.accepted != fixed.accepted
                self.assertTrue(mutation_detected)
                self.assertFalse(reference.accepted)
                self.assertTrue(fixed.accepted)
                with self.assertRaises(ValueError):
                    FixedPolicyShadowEvaluator(self.reference, mutated)
                self.assertFalse(hasattr(mutated, "commit"))
                self.assertFalse(hasattr(mutated, "authorize"))

    def test_reference_policy_requires_the_complete_canonical_predicate_set(self) -> None:
        """普通 reference oracle 不能被构造成缺少必要谓词的宽松策略。"""
        with self.assertRaises(ValueError):
            replace(
                self.predicate_ir,
                predicates=self.predicate_ir.predicates[:-1],
            )


class FixedPolicyApiContractTests(unittest.TestCase):
    """验证公共工厂和 dataclass contract 不产生隐式降级。"""

    def test_public_fact_and_layout_types_reject_malformed_construction(self) -> None:
        """公开类型不得接受非 tuple facts、bool 版本或错误 offset。"""
        with self.assertRaises(TypeError):
            AuthorizationFactSet(
                AUTHORIZATION_LAYOUT_ID_V1,
                AUTHORIZATION_LAYOUT_VERSION_V1,
                cast(tuple[AuthorizationFact, ...], []),
            )
        with self.assertRaises(ValueError):
            AuthorizationFactSet(
                AUTHORIZATION_LAYOUT_ID_V1,
                cast(int, True),
                (),
            )
        with self.assertRaises(ValueError):
            AuthorizationInputField("scope_authorized", cast(int, True))

    def test_public_factories_bind_identical_layout_and_ir(self) -> None:
        """规范 reference、fixed 和 shadow 工厂必须冻结相同版本化 contract。"""
        reference = build_reference_authorization_policy_v1()
        aggregator = build_fixed_policy_aggregator_v1()
        shadow = build_fixed_policy_shadow_evaluator_v1()

        self.assertEqual(reference.layout, aggregator.layout)
        self.assertEqual(reference.predicate_ir, aggregator.predicate_ir)
        self.assertEqual(shadow.reference_policy.layout, shadow.aggregator.layout)
        self.assertEqual(
            reference.predicate_ir.policy_profile_id,
            AUTHORIZATION_POLICY_PROFILE_ID_V1,
        )
        self.assertEqual(
            reference.predicate_ir.policy_profile_version,
            AUTHORIZATION_POLICY_PROFILE_VERSION_V1,
        )


if __name__ == "__main__":
    unittest.main()
