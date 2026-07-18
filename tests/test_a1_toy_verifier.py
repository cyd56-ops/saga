"""Tests for the Route A A1 full fixed-ReLU toy arithmetic verifier."""

from __future__ import annotations

from itertools import product
import math
from unittest import mock
import unittest

from neural import (
    CAN,
    FixedToyLWEVerifierCore,
    FullReLUToyLWEVerifier,
    audit_a1_claimed_source,
    assert_fixed_circuit,
    bytes_to_bits,
)
from pq import ToyLWEParameters, ToyLWESignatureScheme


def _encode_vector(values: tuple[int, ...]) -> bytes:
    """把 tiny exhaustive coefficient vector 编码为 toy scheme wire bytes。"""
    return b"".join(value.to_bytes(2, "little") for value in values)


class FullReLUToyLWEVerifierTests(unittest.TestCase):
    """验证默认 toy 参数上的 A1 正负路径、边界、复杂度和固定状态。"""

    @classmethod
    def setUpClass(cls) -> None:
        """只编译一次默认参数 A1 core，避免重复展开固定 modulo 阈值。"""
        cls.scheme = ToyLWESignatureScheme(seed=919)
        cls.key_pair = cls.scheme.keygen()
        cls.message = b"A" * 32
        cls.signature = cls.scheme.sign(cls.key_pair.secret_key, cls.message)
        cls.verifier = FullReLUToyLWEVerifier(cls.scheme, message_bytes=32)

    def test_valid_signature_accepts_without_calling_reference_verify(self) -> None:
        """A1 运行路径只用 parse/hash 与 fixed core，不得调用 ``scheme.verify``。"""
        with mock.patch.object(
            self.scheme,
            "verify",
            side_effect=AssertionError("reference verifier called"),
        ):
            result = self.verifier.verify_bytes(
                self.key_pair.public_key,
                self.message,
                self.signature,
            )
        self.assertEqual(result, 1)

    def test_tampered_signature_rejects_with_traceable_equality_bit(self) -> None:
        """签名坐标篡改必须使至少一个 fixed equality bit 归零。"""
        values = self.scheme.decode_signature_vector(self.signature)
        values[-1] = (values[-1] + 1) % self.scheme.parameters.modulus
        tampered = _encode_vector(tuple(values))

        trace = self.verifier.trace_verification(
            self.key_pair.public_key,
            self.message,
            tampered,
        )

        self.assertEqual(trace.accept, 0)
        self.assertIn(0, trace.equality_bits)
        self.assertEqual(
            trace.challenge_source,
            "deterministic_sha256_preprocessing:not_neural_hash",
        )

    def test_boundary_excludes_parser_hash_and_production_security(self) -> None:
        """A1 claim 必须覆盖 arithmetic core，但明确排除 parser/hash 与生产安全。"""
        boundary = self.verifier.compilation_boundary()
        self.assertIn(
            "bounded_integer_modulo_relu",
            boundary.claimed_fixed_circuit_steps,
        )
        self.assertEqual(boundary.deterministic_hard_gate_steps, ())
        self.assertIn(
            "sha256_domain_separated_challenge_derivation",
            boundary.deterministic_preprocessing_steps,
        )
        self.assertIn("byte_parser_circuit", boundary.excluded_from_claim)
        self.assertIn(
            "production_post_quantum_security",
            boundary.excluded_from_claim,
        )

    def test_source_closure_has_no_forbidden_claimed_operations(self) -> None:
        """AG3 静态清单不得发现 `%`、普通等值、数据分支或 reference verify。"""
        report = audit_a1_claimed_source()
        self.assertTrue(report.passed)
        self.assertEqual(report.python_modulo_findings, ())
        self.assertEqual(report.python_equality_findings, ())
        self.assertEqual(report.data_branch_findings, ())
        self.assertEqual(report.verifier_call_findings, ())
        self.assertEqual(len(report.claimed_symbols), 8)

    def test_compound_bit_path_rejects_software_domain_hazards(self) -> None:
        """A1 parser/CAN 必须拒绝 bool、中间实数、区间外和非有限输入。"""
        valid_bits = [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(self.message),
            *bytes_to_bits(self.signature),
        ]
        can = CAN(self.verifier)
        self.assertEqual(can.can_accept_compound_bits(valid_bits), 1)
        for invalid in (True, 0.5, -1.0, 2.0, math.nan, math.inf, -math.inf):
            with self.subTest(invalid=invalid):
                bits = list(valid_bits)
                bits[len(bits) // 2] = invalid
                self.assertEqual(can.can_accept_compound_bits(bits), 0)
                self.assertEqual(self.verifier.verify_compound_bits(bits), 0)

    def test_core_range_gate_rejects_one_past_modulus_witness(self) -> None:
        """固定 range gate 必须拒绝软件编译域内但不属于 Z_q 的 q 系数。"""
        dimension = self.scheme.parameters.dimension
        public_vector = (0,) * dimension
        signature_vector = (self.scheme.parameters.modulus, *((0,) * (dimension - 1)))
        challenge_vector = (0,) * dimension

        trace = self.verifier.core.trace_vectors(
            public_vector,
            signature_vector,
            challenge_vector,
        )

        self.assertEqual(trace.equality_accept, 1)
        self.assertEqual(trace.input_range_traces[1].accept, 0)
        self.assertEqual(trace.accept, 0)

    def test_complexity_is_exact_bounded_and_state_has_no_private_key(self) -> None:
        """A1 manifest 必须给出精确整数界限，固定对象不得保存签名私钥。"""
        complexity = self.verifier.complexity()
        self.assertGreater(complexity.modulo_threshold_count, 0)
        self.assertEqual(complexity.fixed_layer_depth, 23)
        self.assertLessEqual(
            complexity.max_intermediate_abs,
            complexity.exact_integer_limit,
        )
        self.assertGreater(complexity.structural_fixed_parameter_count, 0)
        self.assertNotIn(self.key_pair.secret_key, vars(self.verifier).values())
        assert_fixed_circuit(self.verifier)

    def test_byte_parser_fails_closed_on_wrong_length_and_coefficients(self) -> None:
        """A1 wrapper 在 claimed core 前拒绝错误长度和超模数编码。"""
        self.assertEqual(
            self.verifier.verify_bytes(
                self.key_pair.public_key,
                self.message[:-1],
                self.signature,
            ),
            0,
        )
        malformed = (
            self.scheme.parameters.modulus.to_bytes(2, "little")
            + self.signature[2:]
        )
        self.assertEqual(
            self.verifier.verify_bytes(
                self.key_pair.public_key,
                self.message,
                malformed,
            ),
            0,
        )

    def test_core_rejects_non_zq_or_non_square_matrix(self) -> None:
        """A1 构造期只接受固定宽度的非负 Z_q 方阵。"""
        with self.assertRaises(ValueError):
            FixedToyLWEVerifierCore(((1, 2),), 3)
        with self.assertRaises(ValueError):
            FixedToyLWEVerifierCore(((1, -1), (0, 1)), 3)
        with self.assertRaises(ValueError):
            FixedToyLWEVerifierCore(((1, 3), (0, 1)), 3)


class TinyA1ExhaustiveEquivalenceTests(unittest.TestCase):
    """穷举 tiny toy 字节消息域、public vector 与 signature vector 的 AG2 等价性。"""

    @classmethod
    def setUpClass(cls) -> None:
        """创建 dimension=2、q=3 的 tiny reference 与 A1 verifier。"""
        parameters = ToyLWEParameters(dimension=2, modulus=3, matrix_seed=17)
        cls.scheme = ToyLWESignatureScheme(seed=23, parameters=parameters)
        cls.verifier = FullReLUToyLWEVerifier(cls.scheme, message_bytes=1)

    def test_exhaustive_one_byte_relation_matches_reference(self) -> None:
        """全部 20736 个 tiny pk/message/signature 组合必须与 reference 一致。"""
        vectors = tuple(product(range(3), repeat=2))
        mismatches: list[tuple[tuple[int, ...], int, tuple[int, ...]]] = []
        for public_vector in vectors:
            public_key = _encode_vector(public_vector)
            for message_value in range(256):
                message = bytes((message_value,))
                for signature_vector in vectors:
                    signature = _encode_vector(signature_vector)
                    expected = int(
                        self.scheme.verify(public_key, message, signature)
                    )
                    actual = self.verifier.verify_bytes(
                        public_key,
                        message,
                        signature,
                    )
                    if actual != expected:
                        mismatches.append(
                            (public_vector, message_value, signature_vector)
                        )
        self.assertEqual(mismatches, [])


if __name__ == "__main__":
    unittest.main()
