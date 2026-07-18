"""Tests for the research-only Route A A2 module-lattice reference relation."""

from __future__ import annotations

import unittest

from pq import ToyModuleLatticeParameters, ToyModuleLatticeSignatureScheme


class ToyModuleLatticeSignatureSchemeTests(unittest.TestCase):
    """验证 toy module relation 的确定性、wire contract 和非生产边界。"""

    def test_valid_relation_is_deterministic_and_wrong_message_rejects(self) -> None:
        """相同 seed 应生成相同材料，有效响应通过且错误消息拒绝。"""

        first = ToyModuleLatticeSignatureScheme(seed=73)
        second = ToyModuleLatticeSignatureScheme(seed=73)
        first_keys = first.keygen()
        second_keys = second.keygen()
        message = b"route-a-a2"
        signature = first.sign(first_keys.secret_key, message)

        self.assertEqual(first_keys, second_keys)
        self.assertEqual(signature, second.sign(second_keys.secret_key, message))
        self.assertTrue(first.verify(first_keys.public_key, message, signature))
        self.assertFalse(first.verify(first_keys.public_key, b"wrong", signature))
        self.assertTrue(first.research_only)
        self.assertFalse(first.production_ready)

    def test_response_tampering_and_noncanonical_public_target_reject(self) -> None:
        """响应篡改、错误长度和大于等于 q 的公开系数必须 fail-closed。"""

        scheme = ToyModuleLatticeSignatureScheme(seed=91)
        keys = scheme.keygen()
        message = b"a2"
        signature = bytearray(scheme.sign(keys.secret_key, message))
        signature[0] ^= 1

        self.assertFalse(
            scheme.verify(keys.public_key, message, bytes(signature))
        )
        self.assertFalse(scheme.verify(keys.public_key[:-1], message, bytes(signature)))
        malformed_public = (
            scheme.parameters.modulus.to_bytes(2, "little")
            + keys.public_key[2:]
        )
        self.assertFalse(scheme.verify(malformed_public, message, bytes(signature)))

    def test_reference_relation_rejects_norm_and_challenge_domain_violations(self) -> None:
        """reference oracle 必须独立拒绝超响应范数和非 one-hot challenge。"""

        scheme = ToyModuleLatticeSignatureScheme(seed=11)
        keys = scheme.keygen()
        target = scheme.decode_public_target(keys.public_key)
        width = scheme.parameters.module_width
        degree = scheme.parameters.ring_degree
        oversized_flat = (scheme.parameters.response_bound + 1,) + (0,) * (width - 1)
        oversized = tuple(
            tuple(oversized_flat[offset : offset + degree])
            for offset in range(0, width, degree)
        )
        zero_challenge = tuple(
            (0,) * degree for _ in range(scheme.parameters.module_rank)
        )

        self.assertFalse(
            scheme.verify_relation(target, oversized, scheme.challenge_vector(b"x"))
        )
        self.assertFalse(scheme.verify_relation(target, oversized, zero_challenge))

    def test_parameter_validation_enforces_small_power_of_two_ring(self) -> None:
        """A2 参数必须保持 small research ring 与 int16/uint16 编码边界。"""

        with self.assertRaises(ValueError):
            ToyModuleLatticeParameters(ring_degree=3)
        with self.assertRaises(ValueError):
            ToyModuleLatticeParameters(module_rank=0)
        with self.assertRaises(ValueError):
            ToyModuleLatticeParameters(modulus=2)
        with self.assertRaises(TypeError):
            ToyModuleLatticeParameters(ring_degree=4.0)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
