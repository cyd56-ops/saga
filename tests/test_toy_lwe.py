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


class _FixedVerifyResultBackend(_FakeMLDSABackend):
    """返回调用方指定对象，用于验证 adapter 不执行 truthy 强制转换。"""

    def __init__(self, result: object) -> None:
        """保存要由 ``verify`` 原样返回的测试对象。"""
        self.result = result

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> object:
        """原样返回测试对象，模拟畸形或严格布尔 backend 结果。"""
        return self.result


class _RaisingVerifyBackend(_FakeMLDSABackend):
    """模拟外部 backend 在验签阶段抛出操作异常。"""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """抛出固定异常，验证 adapter 生成稳定的拒绝 evidence。"""
        raise TimeoutError("backend diagnostic must not enter evidence")


class MLDSAAdapterTests(unittest.TestCase):
    """Verify the production-facing adapter fails closed or delegates safely."""

    def test_adapter_rejects_without_backend_with_stable_evidence(self) -> None:
        """未接入 backend 时验签必须拒绝并给出稳定 evidence。"""
        adapter = MLDSAAdapter()

        evidence = adapter.verify_with_evidence(b"pk", b"message", b"signature")

        self.assertFalse(adapter.verify(b"pk", b"message", b"signature"))
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "backend_unavailable")

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

        valid_evidence = adapter.verify_with_evidence(
            key_pair.public_key,
            b"message",
            signature,
        )
        invalid_evidence = adapter.verify_with_evidence(
            key_pair.public_key,
            b"tampered",
            signature,
        )
        self.assertEqual(valid_evidence.reason, "signature_valid")
        self.assertEqual(invalid_evidence.reason, "signature_invalid")

    def test_adapter_rejects_truthy_non_boolean_backend_results(self) -> None:
        """字符串、整数和对象等 truthy 返回都不能被解释为验签成功。"""
        malformed_results = ("valid", 1, object())

        for result in malformed_results:
            with self.subTest(result_type=type(result).__name__):
                adapter = MLDSAAdapter(_FixedVerifyResultBackend(result))

                evidence = adapter.verify_with_evidence(
                    b"pk",
                    b"message",
                    b"signature",
                )

                self.assertFalse(adapter.verify(b"pk", b"message", b"signature"))
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, "backend_result_invalid")
                self.assertEqual(
                    evidence.backend_result_type,
                    type(result).__name__,
                )

    def test_adapter_accepts_only_builtin_true(self) -> None:
        """只有内建 bool 的 ``True`` 才能形成接受 evidence。"""
        evidence = MLDSAAdapter(
            _FixedVerifyResultBackend(True)
        ).verify_with_evidence(b"pk", b"message", b"signature")

        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "signature_valid")

    def test_adapter_rejects_backend_exception_with_stable_evidence(self) -> None:
        """Backend 异常必须 fail-closed，且 evidence 不泄露异常消息。"""
        adapter = MLDSAAdapter(_RaisingVerifyBackend())

        evidence = adapter.verify_with_evidence(b"pk", b"message", b"signature")

        self.assertFalse(adapter.verify(b"pk", b"message", b"signature"))
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "backend_verification_error")
        self.assertEqual(evidence.backend_error_type, "TimeoutError")
        self.assertNotIn("diagnostic", repr(evidence))

    def test_adapter_rejects_incomplete_backend_during_verification(self) -> None:
        """验签 evidence 路径必须拒绝缺少方法的 backend。"""
        evidence = MLDSAAdapter(object()).verify_with_evidence(
            b"pk",
            b"message",
            b"signature",
        )

        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "backend_interface_invalid")
        self.assertEqual(evidence.missing_methods, ("keygen", "sign", "verify"))

    def test_adapter_rejects_incomplete_backend(self) -> None:
        """A malformed backend should not be treated as a usable ML-DSA provider.

        缺少必要方法的对象不能被当作可用 ML-DSA backend。
        """
        adapter = MLDSAAdapter(object())

        with self.assertRaisesRegex(TypeError, "missing required methods"):
            adapter.keygen()


if __name__ == "__main__":
    unittest.main()
