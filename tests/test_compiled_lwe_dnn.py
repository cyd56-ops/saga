"""Tests for the first-phase compiled DNN verifier over the toy LWE scheme."""

from __future__ import annotations

import hashlib
import unittest

from neural import (
    CAN,
    CompiledToyLWEVerifier,
    CompiledVerifierBoundary,
    FixedEqualityAggregator,
    FixedEqualityGate,
    FixedModSubtractor,
    assert_fixed_circuit,
    bytes_to_bits,
    find_trainable_state,
)
from pq import ToyLWESignatureScheme


class CompiledToyLWEVerifierTests(unittest.TestCase):
    """Verify the fixed linear-algebra core compiled from the toy scheme."""

    def setUp(self) -> None:
        """Create a deterministic scheme instance and matching compiled verifier."""
        self.scheme = ToyLWESignatureScheme(seed=19)
        self.key_pair = self.scheme.keygen()
        self.message = hashlib.sha256(b"compiled-lwe-dnn").digest()
        self.signature = self.scheme.sign(self.key_pair.secret_key, self.message)
        self.verifier = CompiledToyLWEVerifier(
            self.scheme,
            message_bytes=len(self.message),
        )

    def test_verify_bytes_accepts_valid_signature(self) -> None:
        """A valid toy signature should satisfy the compiled verifier."""
        self.assertEqual(
            self.verifier.verify_bytes(
                self.key_pair.public_key,
                self.message,
                self.signature,
            ),
            1,
        )

    def test_verify_compound_bits_rejects_tampered_signature(self) -> None:
        """Changing the signature bits must force rejection."""
        vector = self.scheme.decode_signature_vector(self.signature)
        vector[0] = (vector[0] + 1) % self.scheme.parameters.modulus
        signature = b"".join(
            coefficient.to_bytes(2, "little", signed=False) for coefficient in vector
        )
        bits = [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(self.message),
            *bytes_to_bits(signature),
        ]
        self.assertEqual(self.verifier.verify_compound_bits(bits), 0)

    def test_compiled_verifier_matches_scheme_on_fixed_messages(self) -> None:
        """The compiled verifier should match the scheme API on valid inputs."""
        for counter in range(4):
            message = hashlib.sha256(
                b"compiled-lwe-dnn-message"
                + counter.to_bytes(2, "little", signed=False)
            ).digest()
            signature = self.scheme.sign(self.key_pair.secret_key, message)
            expected = int(
                self.scheme.verify(self.key_pair.public_key, message, signature)
            )
            self.assertEqual(
                self.verifier.verify_bytes(self.key_pair.public_key, message, signature),
                expected,
            )

    def test_matrix_projector_rows_are_non_trainable(self) -> None:
        """Compiled matrix rows must stay fixed and non-trainable."""
        for row in self.verifier.signature_projector.submodules():
            self.assertFalse(row.requires_grad)

    def test_compiled_verifier_has_no_trainable_state(self) -> None:
        """递归检查 compiled verifier 的固定子模块不可训练。"""
        assert_fixed_circuit(self.verifier)
        self.assertEqual(find_trainable_state(self.verifier), ())

    def test_can_with_compiled_verifier_has_no_trainable_state(self) -> None:
        """递归检查 CAN 与 compiled verifier 组合后仍无训练入口。"""
        can = CAN(self.verifier)
        assert_fixed_circuit(can)
        self.assertEqual(find_trainable_state(can), ())

    def test_trace_verification_recovers_public_vector(self) -> None:
        """The projection trace should recover the expected public key vector."""
        trace = self.verifier.trace_verification(
            self.key_pair.public_key,
            self.message,
            self.signature,
        )
        self.assertEqual(trace.recovered_public, trace.public_vector)
        self.assertEqual(trace.accept, 1)
        self.assertEqual(
            trace.challenge_source,
            "deterministic_sha256_preprocessing:not_neural_hash",
        )
        self.assertEqual(
            trace.equality_bits,
            tuple(1 for _ in range(self.scheme.parameters.dimension)),
        )

    def test_compilation_boundary_documents_challenge_preprocessing(self) -> None:
        """编译边界必须明确 challenge 派生不是神经哈希电路。"""
        boundary = self.verifier.compilation_boundary()
        self.assertIsInstance(boundary, CompiledVerifierBoundary)
        self.assertEqual(
            boundary.compiled_fixed_circuit_steps,
            (
                "public_matrix_times_signature",
                "public_matrix_times_challenge",
            ),
        )
        self.assertIn(
            "sha256_domain_separated_challenge_derivation",
            boundary.deterministic_preprocessing_steps,
        )
        self.assertIn(
            "modular_subtraction",
            boundary.deterministic_hard_gate_steps,
        )
        self.assertNotIn(
            "sha256_domain_separated_challenge_derivation",
            boundary.compiled_fixed_circuit_steps,
        )

    def test_can_accepts_valid_signature_with_compiled_verifier(self) -> None:
        """The compiled verifier should plug into the existing CAN gate."""
        can = CAN(self.verifier)
        bits = [
            *bytes_to_bits(self.key_pair.public_key),
            *bytes_to_bits(self.message),
            *bytes_to_bits(self.signature),
        ]
        self.assertEqual(can.can_accept_compound_bits(bits), 1)

    def test_fixed_mod_subtractor_applies_hard_modulus(self) -> None:
        """The modular subtractor should wrap values into ``Z_q``."""
        gate = FixedModSubtractor(self.scheme.parameters.modulus)
        self.assertEqual(gate(3, 5), self.scheme.parameters.modulus - 2)
        self.assertFalse(gate.requires_grad)

    def test_fixed_equality_gates_are_hard_binary_modules(self) -> None:
        """Equality gates and aggregators should emit exact hard bits."""
        gate = FixedEqualityGate()
        aggregator = FixedEqualityAggregator(3)
        self.assertEqual(gate(4, 4), 1)
        self.assertEqual(gate(4, 5), 0)
        self.assertEqual(aggregator((1, 1, 1)), 1)
        self.assertEqual(aggregator((1, 0, 1)), 0)
        self.assertFalse(gate.requires_grad)
        self.assertFalse(aggregator.requires_grad)

    def test_trace_rejects_tampered_signature_with_zero_equality_bit(self) -> None:
        """A bad signature should flip at least one equality bit to zero."""
        vector = self.scheme.decode_signature_vector(self.signature)
        vector[-1] = (vector[-1] + 1) % self.scheme.parameters.modulus
        signature = b"".join(
            coefficient.to_bytes(2, "little", signed=False) for coefficient in vector
        )
        trace = self.verifier.trace_verification(
            self.key_pair.public_key,
            self.message,
            signature,
        )
        self.assertEqual(trace.accept, 0)
        self.assertIn(0, trace.equality_bits)

    def test_fixed_circuit_audit_reports_trainable_child(self) -> None:
        """固定电路审计应能发现嵌套子模块中的可训练标记。"""

        class TrainableChild:
            requires_grad = True

        class Parent:
            def __init__(self) -> None:
                self.child = TrainableChild()

        findings = find_trainable_state(Parent())
        self.assertEqual(len(findings), 1)
        self.assertIn("requires_grad", findings[0].reason)


if __name__ == "__main__":
    unittest.main()
