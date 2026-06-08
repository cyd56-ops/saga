"""Tests for the research-only toy lattice signature abstraction."""

import unittest

from pq import MLDSAAdapter, ToyLWESignatureScheme


class ToyLWESignatureSchemeTests(unittest.TestCase):
    """Verify the deterministic toy signature scheme contract."""

    def test_round_trip_accepts_valid_signature(self) -> None:
        """A freshly produced signature should verify."""
        scheme = ToyLWESignatureScheme(seed=7)
        key_pair = scheme.keygen()
        message = b"saga-pq-can"

        signature = scheme.sign(key_pair.secret_key, message)

        self.assertTrue(scheme.verify(key_pair.public_key, message, signature))

    def test_verify_rejects_tampered_message(self) -> None:
        """Changing the message must invalidate the signature."""
        scheme = ToyLWESignatureScheme(seed=7)
        key_pair = scheme.keygen()
        signature = scheme.sign(key_pair.secret_key, b"original")

        self.assertFalse(scheme.verify(key_pair.public_key, b"modified", signature))

    def test_verify_rejects_tampered_signature(self) -> None:
        """Changing the signature bytes must invalidate verification."""
        scheme = ToyLWESignatureScheme(seed=7)
        key_pair = scheme.keygen()
        signature = bytearray(scheme.sign(key_pair.secret_key, b"original"))
        signature[0] ^= 0x01

        self.assertFalse(
            scheme.verify(key_pair.public_key, b"original", bytes(signature))
        )

    def test_key_generation_is_deterministic_for_a_fixed_seed(self) -> None:
        """Separate scheme instances with the same seed should match."""
        scheme_a = ToyLWESignatureScheme(seed=11)
        scheme_b = ToyLWESignatureScheme(seed=11)

        self.assertEqual(scheme_a.keygen(), scheme_b.keygen())


class _FakeMLDSABackend:
    """Tiny deterministic backend stub used only to test adapter delegation.

    该假 backend 只用于测试适配器转发，不表示真实 ML-DSA 实现。
    """

    def keygen(self) -> tuple[bytes, bytes]:
        """Return byte-oriented test key material.

        生成固定测试密钥，便于断言 adapter 的类型转换行为。
        """
        return b"pk", b"sk"

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Return a deterministic test signature.

        签名格式故意简单，只验证 adapter 是否调用了 backend。
        """
        return b"sig:" + secret_key + b":" + message

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Accept only the matching deterministic test signature.

        只接受固定关系，确保负向断言可重复。
        """
        return public_key == b"pk" and signature == b"sig:sk:" + message


class MLDSAAdapterTests(unittest.TestCase):
    """Verify the production-facing adapter fails closed or delegates safely."""

    def test_adapter_raises_clear_error_without_backend(self) -> None:
        """The adapter should fail clearly until a vetted backend is wired in."""
        adapter = MLDSAAdapter()

        with self.assertRaisesRegex(RuntimeError, "backend not installed"):
            adapter.verify(b"pk", b"message", b"signature")

    def test_adapter_delegates_to_explicit_backend(self) -> None:
        """An explicitly supplied backend should handle keygen, sign, and verify.

        显式 backend 存在时，adapter 应只做转发和类型规范化。
        """
        adapter = MLDSAAdapter(_FakeMLDSABackend())

        key_pair = adapter.keygen()
        signature = adapter.sign(key_pair.secret_key, b"message")

        self.assertEqual(key_pair.public_key, b"pk")
        self.assertEqual(key_pair.secret_key, b"sk")
        self.assertTrue(adapter.verify(key_pair.public_key, b"message", signature))
        self.assertFalse(adapter.verify(key_pair.public_key, b"tampered", signature))

    def test_adapter_rejects_incomplete_backend(self) -> None:
        """A malformed backend should not be treated as a usable ML-DSA provider.

        缺少必要方法的对象不能被当作可用 ML-DSA backend。
        """
        adapter = MLDSAAdapter(object())

        with self.assertRaisesRegex(TypeError, "missing required methods"):
            adapter.keygen()


if __name__ == "__main__":
    unittest.main()
