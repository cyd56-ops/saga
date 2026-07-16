"""Tests for the strict Route B ML-DSA backend contract."""

from __future__ import annotations

from dataclasses import replace
import math
import threading
import unittest

from pq import (
    ML_DSA_CONTEXT_V1,
    MLDSA_BACKEND_API_VERSION_V1,
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    MLDSABackendContractV1,
    MLDSABackendDescriptorV1,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)


_PUBLIC_KEY_BYTES = {
    SignatureAlgorithmId.ML_DSA_44: 1312,
    SignatureAlgorithmId.ML_DSA_65: 1952,
    SignatureAlgorithmId.ML_DSA_87: 2592,
}
_SIGNATURE_BYTES = {
    SignatureAlgorithmId.ML_DSA_44: 2420,
    SignatureAlgorithmId.ML_DSA_65: 3309,
    SignatureAlgorithmId.ML_DSA_87: 4627,
}


def _binding(
    *,
    algorithm_id: SignatureAlgorithmId = SignatureAlgorithmId.ML_DSA_44,
    profile_id: SignatureProfileId = SignatureProfileId.ML_DSA_PURE,
) -> SignatureBindingV1:
    """构造固定 route B binding，供 backend contract 测试复用。"""
    return SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=algorithm_id,
        key_id=b"route-b-test-key",
        profile_id=profile_id,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=b"D" * 32,
    )


def _route_a_binding() -> SignatureBindingV1:
    """构造合法 route A binding，用于证明 B verifier 不接受跨路线材料。"""
    return SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_A_NEURAL,
        algorithm_id=SignatureAlgorithmId.TOY_LWE_RESEARCH,
        key_id=b"route-a-test-key",
        profile_id=SignatureProfileId.TOY_DIRECT,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=b"A" * 32,
    )


def _descriptor(**changes: object) -> MLDSABackendDescriptorV1:
    """构造可按字段替换的固定 fake backend descriptor。"""
    descriptor = MLDSABackendDescriptorV1(
        backend_name="fake-vetted-mldsa",
        backend_version="1.2.3",
        provider_name="fake-provider",
        provider_version="9.8.7",
        api_version=MLDSA_BACKEND_API_VERSION_V1,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        available=True,
    )
    return replace(descriptor, **changes)


def _contract(
    descriptor: MLDSABackendDescriptorV1 | None = None,
    *,
    timeout_seconds: float = 0.25,
) -> MLDSABackendContractV1:
    """从测试批准值构造严格 contract，不用于生产动态信任发现。"""
    approved = descriptor or _descriptor()
    return MLDSABackendContractV1(
        backend_name=approved.backend_name,
        backend_version=approved.backend_version,
        provider_name=approved.provider_name,
        provider_version=approved.provider_version,
        algorithm_id=approved.algorithm_id,
        profile_id=approved.profile_id,
        context=approved.context,
        timeout_seconds=timeout_seconds,
    )


class _FakeVettedBackend:
    """模拟已注入 backend，仅验证路线 B contract，不实现密码算法。"""

    def __init__(
        self,
        *,
        descriptor: object | None = None,
        result: object = True,
        error: BaseException | None = None,
        wait_event: threading.Event | None = None,
    ) -> None:
        """保存 descriptor、结果、异常或阻塞事件。"""
        self.descriptor_value = descriptor or _descriptor()
        self.result = result
        self.error = error
        self.wait_event = wait_event
        self.verify_calls = 0
        self.last_message: bytes | None = None

    def descriptor(self) -> object:
        """返回调用方指定的 descriptor 或畸形对象。"""
        return self.descriptor_value

    def keygen(self) -> tuple[bytes, bytes]:
        """返回固定测试材料，不表示真实密钥生成。"""
        return b"P" * 1312, b"S" * 32

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """返回固定长度占位签名，不表示真实 ML-DSA 签名。"""
        del secret_key, message
        return b"G" * 2420

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> object:
        """记录调用后返回或抛出预设结果，用于覆盖 fail-closed 分支。"""
        del public_key, signature
        self.verify_calls += 1
        self.last_message = message
        if self.wait_event is not None:
            self.wait_event.wait()
        if self.error is not None:
            raise self.error
        return self.result


class _DescriptorErrorBackend(_FakeVettedBackend):
    """模拟 descriptor 查询阶段发生异常的 backend。"""

    def descriptor(self) -> object:
        """抛出固定异常，验证 evidence 不复制异常消息。"""
        raise RuntimeError("descriptor diagnostic must remain private")


class MLDSARouteBVerifierTests(unittest.TestCase):
    """验证路线 B backend pinning、输入边界、超时与稳定 evidence。"""

    def setUp(self) -> None:
        """准备 ML-DSA-44 固定 binding 与标准长度占位材料。"""
        self.binding = _binding()
        self.public_key = b"P" * _PUBLIC_KEY_BYTES[self.binding.algorithm_id]
        self.signature = b"S" * _SIGNATURE_BYTES[self.binding.algorithm_id]

    def test_accepts_only_builtin_true_from_matching_backend(self) -> None:
        """完全匹配 contract 且返回原生 True 时才形成接受 evidence。"""
        backend = _FakeVettedBackend(result=True)
        verifier = MLDSARouteBVerifier(backend, _contract())

        evidence = verifier.verify(self.binding, self.public_key, self.signature)

        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "signature_valid")
        self.assertEqual(backend.verify_calls, 1)
        self.assertEqual(backend.last_message, self.binding.canonical_bytes())

    def test_builtin_false_is_an_ordinary_invalid_signature(self) -> None:
        """Backend 原生 False 应映射为普通签名无效而非操作错误。"""
        evidence = MLDSARouteBVerifier(
            _FakeVettedBackend(result=False),
            _contract(),
        ).verify(self.binding, self.public_key, self.signature)

        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "signature_invalid")

    def test_rejects_binding_and_input_mismatches_before_backend_call(self) -> None:
        """跨路线、parameter set 漂移与非规范 key/signature 在 backend 前拒绝。"""
        backend = _FakeVettedBackend()
        verifier = MLDSARouteBVerifier(backend, _contract())
        cases = (
            ("route", _route_a_binding(), self.public_key, self.signature, "binding_invalid"),
            (
                "algorithm",
                _binding(algorithm_id=SignatureAlgorithmId.ML_DSA_65),
                self.public_key,
                self.signature,
                "binding_contract_mismatch",
            ),
            ("public_type", self.binding, bytearray(self.public_key), self.signature, "public_key_input_invalid"),
            ("public_length", self.binding, self.public_key[:-1], self.signature, "public_key_input_invalid"),
            ("signature_type", self.binding, self.public_key, bytearray(self.signature), "signature_input_invalid"),
            ("signature_length", self.binding, self.public_key, self.signature[:-1], "signature_input_invalid"),
        )

        for label, binding, public_key, signature, reason in cases:
            with self.subTest(case=label):
                evidence = verifier.verify(  # type: ignore[arg-type]
                    binding,
                    public_key,
                    signature,
                )
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, reason)
        self.assertEqual(backend.verify_calls, 0)

    def test_rejects_missing_malformed_or_failing_descriptor(self) -> None:
        """缺接口、畸形 descriptor 与 descriptor 异常均稳定 fail-closed。"""
        cases = (
            (object(), "backend_interface_invalid", None),
            (_FakeVettedBackend(descriptor="invalid"), "backend_descriptor_invalid", None),
            (_DescriptorErrorBackend(), "backend_descriptor_error", "RuntimeError"),
        )

        for backend, reason, error_type in cases:
            with self.subTest(reason=reason):
                evidence = MLDSARouteBVerifier(backend, _contract()).verify(
                    self.binding,
                    self.public_key,
                    self.signature,
                )
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, reason)
                self.assertEqual(evidence.backend_error_type, error_type)
                self.assertNotIn("diagnostic", repr(evidence))

    def test_rejects_descriptor_identity_version_and_capability_drift(self) -> None:
        """API、身份、版本、parameter/profile/context 漂移和 unavailable 均拒绝。"""
        cases = (
            ("api", {"api_version": "future-api"}, "backend_api_version_mismatch"),
            ("backend_identity", {"backend_name": "other"}, "backend_identity_mismatch"),
            ("provider_identity", {"provider_name": "other"}, "backend_identity_mismatch"),
            ("backend_version", {"backend_version": "2.0.0"}, "backend_version_mismatch"),
            ("provider_version", {"provider_version": "10.0"}, "backend_version_mismatch"),
            (
                "algorithm",
                {"algorithm_id": SignatureAlgorithmId.ML_DSA_65},
                "backend_capability_mismatch",
            ),
            (
                "profile",
                {"profile_id": SignatureProfileId.HASH_ML_DSA_SHA256},
                "backend_capability_mismatch",
            ),
            ("context", {"context": b"other-context"}, "backend_capability_mismatch"),
            ("unavailable", {"available": False}, "backend_unavailable"),
        )

        for label, changes, reason in cases:
            with self.subTest(case=label):
                backend = _FakeVettedBackend(descriptor=_descriptor(**changes))
                evidence = MLDSARouteBVerifier(backend, _contract()).verify(
                    self.binding,
                    self.public_key,
                    self.signature,
                )
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, reason)
                self.assertEqual(backend.verify_calls, 0)

    def test_rejects_exception_timeout_and_non_boolean_backend_results(self) -> None:
        """异常、TimeoutError 与所有非布尔结果必须使用稳定 reason 拒绝。"""
        cases = (
            (_FakeVettedBackend(error=RuntimeError("private diagnostic")), "backend_verification_error", "RuntimeError"),
            (_FakeVettedBackend(error=TimeoutError("private timeout")), "backend_timeout", "TimeoutError"),
            (_FakeVettedBackend(result="valid"), "backend_result_invalid", None),
            (_FakeVettedBackend(result=1), "backend_result_invalid", None),
            (_FakeVettedBackend(result=None), "backend_result_invalid", None),
        )

        for backend, reason, error_type in cases:
            with self.subTest(reason=reason, result_type=type(backend.result).__name__):
                evidence = MLDSARouteBVerifier(backend, _contract()).verify(
                    self.binding,
                    self.public_key,
                    self.signature,
                )
                self.assertFalse(evidence.accepted)
                self.assertEqual(evidence.reason, reason)
                self.assertEqual(evidence.backend_error_type, error_type)
                self.assertNotIn("private", repr(evidence))

    def test_wall_timeout_quarantines_same_backend_instance(self) -> None:
        """在途调用超时后，同一 verifier 不得并发启动第二个 backend 调用。"""
        release = threading.Event()
        self.addCleanup(release.set)
        backend = _FakeVettedBackend(wait_event=release)
        verifier = MLDSARouteBVerifier(
            backend,
            _contract(timeout_seconds=0.01),
        )

        first = verifier.verify(self.binding, self.public_key, self.signature)
        second = verifier.verify(self.binding, self.public_key, self.signature)

        self.assertEqual(first.reason, "backend_timeout")
        self.assertEqual(second.reason, "backend_timeout")
        self.assertEqual(backend.verify_calls, 1)

    def test_contract_rejects_unpinned_or_invalid_values(self) -> None:
        """空版本、toy profile、非固定 context 与非有限超时不能形成 contract。"""
        invalid_changes = (
            {"backend_version": ""},
            {"algorithm_id": SignatureAlgorithmId.TOY_LWE_RESEARCH},
            {"profile_id": SignatureProfileId.TOY_DIRECT},
            {"context": b"other"},
            {"timeout_seconds": True},
            {"timeout_seconds": 0.0},
            {"timeout_seconds": math.inf},
            {"timeout_seconds": math.nan},
        )

        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaises((TypeError, ValueError)):
                    replace(_contract(), **changes)

if __name__ == "__main__":
    unittest.main()
