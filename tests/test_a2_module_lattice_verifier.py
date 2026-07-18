"""Tests for the Route A A2 fixed negacyclic-convolution verifier."""

from __future__ import annotations

import math
from unittest import mock
import unittest

from neural import (
    A2ModuleLatticeVerifierCore,
    CAN,
    FixedModuleLatticeVerifier,
    assert_fixed_circuit,
    audit_a2_claimed_source,
    bytes_to_bits,
)
from pq import ToyModuleLatticeSignatureScheme


class FixedModuleLatticeVerifierTests(unittest.TestCase):
    """验证 A2 正负路径、边界、固定状态、范围/范数和 bit contract。"""

    @classmethod
    def setUpClass(cls) -> None:
        """只编译一次默认 rank-2、degree-4 A2 core。"""

        cls.scheme = ToyModuleLatticeSignatureScheme(seed=2026)
        cls.keys = cls.scheme.keygen()
        cls.message = b"A" * 32
        cls.signature = cls.scheme.sign(cls.keys.secret_key, cls.message)
        cls.verifier = FixedModuleLatticeVerifier(cls.scheme, message_bytes=32)

    def test_valid_relation_accepts_without_calling_reference_verify(self) -> None:
        """A2 运行路径不得调用普通 reference ``verify``。"""

        with mock.patch.object(
            self.scheme,
            "verify",
            side_effect=AssertionError("reference verifier called"),
        ):
            result = self.verifier.verify_bytes(
                self.keys.public_key,
                self.message,
                self.signature,
            )
        self.assertEqual(result, 1)

    def test_wrong_message_rejects_with_traceable_relation_mismatch(self) -> None:
        """选择不同 challenge 的消息后，fixed equality 必须拒绝。"""

        wrong_message = next(
            candidate.to_bytes(32, "little")
            for candidate in range(1, 1024)
            if self.scheme.challenge_vector(candidate.to_bytes(32, "little"))
            != self.scheme.challenge_vector(self.message)
        )
        trace = self.verifier.trace_verification(
            self.keys.public_key,
            wrong_message,
            self.signature,
        )

        self.assertEqual(trace.accept, 0)
        self.assertEqual(trace.equality_accept, 0)
        self.assertIn(0, trace.equality_bits)
        self.assertEqual(
            trace.challenge_source,
            "deterministic_sha256_preprocessing:not_neural_hash",
        )

    def test_boundary_excludes_hash_parser_ntt_and_production_security(self) -> None:
        """A2 claim 必须覆盖环卷积，同时排除 parser/hash/NTT/ML-DSA。"""

        boundary = self.verifier.compilation_boundary()
        self.assertIn(
            "fixed_negacyclic_matrix_projection",
            boundary.claimed_fixed_circuit_steps,
        )
        self.assertIn(
            "compile_time_negacyclic_matrix_expansion",
            boundary.deterministic_preprocessing_steps,
        )
        self.assertEqual(boundary.deterministic_hard_gate_steps, ())
        self.assertIn("ntt_backend", boundary.excluded_from_claim)
        self.assertIn("ml_dsa_verifier", boundary.excluded_from_claim)
        self.assertIn(
            "production_post_quantum_security",
            boundary.excluded_from_claim,
        )

    def test_source_closure_covers_shared_and_a2_evaluators(self) -> None:
        """A2 claimed source 不得包含 `%`、普通等值、数据分支或 verifier 调用。"""

        report = audit_a2_claimed_source()
        self.assertTrue(report.passed)
        self.assertEqual(report.python_modulo_findings, ())
        self.assertEqual(report.python_equality_findings, ())
        self.assertEqual(report.data_branch_findings, ())
        self.assertEqual(report.verifier_call_findings, ())
        self.assertEqual(len(report.claimed_symbols), 10)

    def test_compound_bits_reject_real_valued_and_nonfinite_inputs(self) -> None:
        """A2 verifier/CAN 必须拒绝 bool、中间实数、越界与非有限 bit。"""

        valid_bits = [
            *bytes_to_bits(self.keys.public_key),
            *bytes_to_bits(self.message),
            *bytes_to_bits(self.signature),
        ]
        can = CAN(self.verifier)
        self.assertEqual(can.can_accept_compound_bits(valid_bits), 1)
        for invalid in (True, 0.5, -1.0, 2.0, math.nan, math.inf, -math.inf):
            with self.subTest(invalid=invalid):
                bits = list(valid_bits)
                bits[len(bits) // 2] = invalid
                self.assertEqual(self.verifier.verify_compound_bits(bits), 0)
                self.assertEqual(can.can_accept_compound_bits(bits), 0)

    def test_response_norm_gate_rejects_relation_consistent_witness(self) -> None:
        """即使环等式成立，超 L1 响应仍必须由 fixed range/norm gate 拒绝。"""

        parameters = self.scheme.parameters
        response = tuple(
            (parameters.response_bound,) * parameters.ring_degree
            for _ in range(parameters.module_rank)
        )
        challenge = self.scheme.challenge_vector(b"norm-witness")
        zero_target = tuple(
            (0,) * parameters.ring_degree
            for _ in range(parameters.module_rank)
        )
        recovered = self.verifier.core.trace_relation(
            zero_target,
            response,
            challenge,
        ).recovered_target
        trace = self.verifier.core.trace_relation(recovered, response, challenge)

        self.assertEqual(trace.equality_accept, 1)
        self.assertEqual(trace.input_range_traces[1].l1_bit, 0)
        self.assertEqual(trace.accept, 0)

    def test_zero_challenge_rejects_even_when_ring_relation_matches(self) -> None:
        """challenge L1 必须精确为一，不能把全零向量当成 one-hot。"""

        parameters = self.scheme.parameters
        zero_vector = tuple(
            (0,) * parameters.ring_degree
            for _ in range(parameters.module_rank)
        )
        trace = self.verifier.core.trace_relation(
            zero_vector,
            zero_vector,
            zero_vector,
        )

        self.assertEqual(trace.equality_accept, 1)
        self.assertEqual(trace.challenge_weight_bit, 0)
        self.assertEqual(trace.accept, 0)

    def test_complexity_uses_rank_squared_negacyclic_projectors(self) -> None:
        """A2 manifest 必须记录 rank^2 环 projector、精确界限和无私钥固定状态。"""

        complexity = self.verifier.complexity()
        self.assertEqual(
            complexity.negacyclic_projector_count,
            self.scheme.parameters.module_rank**2,
        )
        self.assertEqual(
            complexity.projector_backend,
            "tiny-negacyclic-fixed-matrix-v1",
        )
        self.assertLessEqual(
            complexity.max_intermediate_abs,
            complexity.exact_integer_limit,
        )
        self.assertGreater(complexity.structural_fixed_parameter_count, 0)
        self.assertNotIn(self.keys.secret_key, vars(self.verifier).values())
        assert_fixed_circuit(self.verifier)

    def test_parser_and_constructor_fail_closed(self) -> None:
        """错误 wire 长度、超响应和畸形 module matrix 必须拒绝。"""

        self.assertEqual(
            self.verifier.verify_bytes(
                self.keys.public_key,
                self.message[:-1],
                self.signature,
            ),
            0,
        )
        oversized = (
            (self.scheme.parameters.response_bound + 1).to_bytes(
                2,
                "little",
                signed=True,
            )
            + self.signature[2:]
        )
        self.assertEqual(
            self.verifier.verify_bytes(
                self.keys.public_key,
                self.message,
                oversized,
            ),
            0,
        )
        with self.assertRaises(ValueError):
            A2ModuleLatticeVerifierCore(
                (((1, 2),),),
                self.scheme.parameters,
            )


if __name__ == "__main__":
    unittest.main()
