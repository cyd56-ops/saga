"""Tests for the cryptography-backed ML-DSA Route B adapter."""

from __future__ import annotations

import unittest

import cryptography

from pq import (
    CryptographyMLDSABackend,
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    MLDSABackendContractV1,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)


def _binding() -> SignatureBindingV1:
    """构造 cryptography pure ML-DSA-44 测试使用的固定 binding。"""
    return SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        key_id=b"cryptography-route-b-key",
        profile_id=SignatureProfileId.ML_DSA_PURE,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=b"C" * 32,
    )


def _contract(backend: CryptographyMLDSABackend) -> MLDSABackendContractV1:
    """用测试中显式批准的真实环境版本构造 contract。"""
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


class CryptographyMLDSABackendTests(unittest.TestCase):
    """验证真实库 shim 的 pure-only contract 与 provider availability。"""

    def test_reports_real_provider_availability(self) -> None:
        """受支持 wheel 必须完成真实 pure ML-DSA keygen/sign/verify round-trip。"""
        backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        descriptor = backend.descriptor()
        verifier = MLDSARouteBVerifier(backend, _contract(backend))
        binding = _binding()

        self.assertEqual(descriptor.backend_name, "cryptography")
        self.assertEqual(descriptor.backend_version, cryptography.__version__)
        self.assertEqual(descriptor.provider_name, "OpenSSL")
        self.assertTrue(
            descriptor.available,
            "Route B requires cryptography with an ML-DSA-capable OpenSSL backend",
        )

        key_pair = backend.keygen_pair()
        signature = backend.sign(key_pair.secret_key, binding.canonical_bytes())
        evidence = verifier.verify(binding, key_pair.public_key, signature)

        self.assertEqual(len(key_pair.public_key), 1312)
        self.assertEqual(len(key_pair.secret_key), 32)
        self.assertEqual(len(signature), 2420)
        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.reason, "signature_valid")

    def test_refuses_hash_profile_or_wrong_context(self) -> None:
        """缺少 HashML-DSA API 时不得手工预哈希冒充该 profile。"""
        with self.assertRaisesRegex(ValueError, "only pure ML-DSA"):
            CryptographyMLDSABackend(
                SignatureAlgorithmId.ML_DSA_44,
                profile_id=SignatureProfileId.HASH_ML_DSA_SHA256,
            )
        with self.assertRaisesRegex(ValueError, "ML_DSA_CONTEXT_V1"):
            CryptographyMLDSABackend(
                SignatureAlgorithmId.ML_DSA_44,
                context=b"wrong-context",
            )


if __name__ == "__main__":
    unittest.main()
