"""Adapter from cryptography 48+ pure ML-DSA to the Route B backend contract."""

from __future__ import annotations

from pq.mldsa_route_b import (
    MLDSA_BACKEND_API_VERSION_V1,
    MLDSABackendDescriptorV1,
)
from pq.signature_binding import (
    ML_DSA_CONTEXT_V1,
    SignatureAlgorithmId,
    SignatureProfileId,
)
from pq.signature_scheme import KeyPair


_ML_DSA_ALGORITHMS = frozenset(
    {
        SignatureAlgorithmId.ML_DSA_44,
        SignatureAlgorithmId.ML_DSA_65,
        SignatureAlgorithmId.ML_DSA_87,
    }
)


class CryptographyMLDSABackend:
    """将 ``cryptography`` 48+ 的 OpenSSL pure ML-DSA API 适配为 backend V1。

    当前 cryptography API 不提供 HashML-DSA profile，因此本适配器只接受
    ``ML_DSA_PURE``，不会由调用方手工预哈希来模拟标准 profile。
    """

    def __init__(
        self,
        algorithm_id: SignatureAlgorithmId,
        *,
        profile_id: SignatureProfileId = SignatureProfileId.ML_DSA_PURE,
        context: bytes = ML_DSA_CONTEXT_V1,
    ) -> None:
        """固定 parameter set、pure profile 与 V1 application context。"""
        if not isinstance(algorithm_id, SignatureAlgorithmId):
            raise TypeError("algorithm_id must use SignatureAlgorithmId")
        if algorithm_id not in _ML_DSA_ALGORITHMS:
            raise ValueError("cryptography backend requires an ML-DSA algorithm")
        if profile_id is not SignatureProfileId.ML_DSA_PURE:
            raise ValueError("cryptography OpenSSL backend supports only pure ML-DSA")
        if type(context) is not bytes or context != ML_DSA_CONTEXT_V1:
            raise ValueError("cryptography backend must use ML_DSA_CONTEXT_V1")
        self.algorithm_id = algorithm_id
        self.profile_id = profile_id
        self.context = context

    def descriptor(self) -> MLDSABackendDescriptorV1:
        """报告 cryptography/OpenSSL 精确版本及当前 provider 的 ML-DSA 能力。"""
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend

        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa

            api_available = all(
                hasattr(mldsa, class_name)
                for class_name in (
                    "MLDSA44PrivateKey",
                    "MLDSA44PublicKey",
                    "MLDSA65PrivateKey",
                    "MLDSA65PublicKey",
                    "MLDSA87PrivateKey",
                    "MLDSA87PublicKey",
                )
            )
            available = api_available and bool(backend.mldsa_supported())
        except (AttributeError, ImportError):
            available = False
        return MLDSABackendDescriptorV1(
            backend_name="cryptography",
            backend_version=cryptography.__version__,
            provider_name="OpenSSL",
            provider_version=backend.openssl_version_text(),
            api_version=MLDSA_BACKEND_API_VERSION_V1,
            algorithm_id=self.algorithm_id,
            profile_id=self.profile_id,
            context=self.context,
            available=available,
        )

    def keygen(self) -> tuple[bytes, bytes]:
        """通过 cryptography 生成 raw public key 与 32-byte private seed。"""
        self._require_available()
        private_key_class, _public_key_class = self._key_classes()
        private_key = private_key_class.generate()
        return (
            bytes(private_key.public_key().public_bytes_raw()),
            bytes(private_key.private_bytes_raw()),
        )

    def keygen_pair(self) -> KeyPair:
        """生成与仓库 ``SignatureScheme`` 抽象一致的 key pair。"""
        public_key, secret_key = self.keygen()
        return KeyPair(public_key=public_key, secret_key=secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """用 32-byte seed 恢复私钥，并对完整 binding bytes 做 pure ML-DSA 签名。"""
        self._require_available()
        if type(secret_key) is not bytes or len(secret_key) != 32:
            raise ValueError("ML-DSA private seed must be exactly 32 bytes")
        if type(message) is not bytes:
            raise TypeError("ML-DSA message must be bytes")
        private_key_class, _public_key_class = self._key_classes()
        private_key = private_key_class.from_seed_bytes(secret_key)
        return bytes(private_key.sign(message, self.context))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """用 cryptography 验证 pure ML-DSA；普通 InvalidSignature 返回 ``False``。"""
        self._require_available()
        if type(public_key) is not bytes:
            raise TypeError("ML-DSA public key must be bytes")
        if type(message) is not bytes:
            raise TypeError("ML-DSA message must be bytes")
        if type(signature) is not bytes:
            raise TypeError("ML-DSA signature must be bytes")
        from cryptography.exceptions import InvalidSignature

        _private_key_class, public_key_class = self._key_classes()
        loaded_public_key = public_key_class.from_public_bytes(public_key)
        try:
            loaded_public_key.verify(signature, message, self.context)
        except InvalidSignature:
            return False
        return True

    def _require_available(self) -> None:
        """当前 OpenSSL provider 不支持 ML-DSA 时在任何密码操作前拒绝。"""
        if not self.descriptor().available:
            raise RuntimeError(
                "cryptography ML-DSA is unavailable in the active OpenSSL provider"
            )

    def _key_classes(self) -> tuple[type, type]:
        """返回所选 parameter set 的 cryptography private/public key 类。"""
        from cryptography.hazmat.primitives.asymmetric import mldsa

        classes = {
            SignatureAlgorithmId.ML_DSA_44: (
                mldsa.MLDSA44PrivateKey,
                mldsa.MLDSA44PublicKey,
            ),
            SignatureAlgorithmId.ML_DSA_65: (
                mldsa.MLDSA65PrivateKey,
                mldsa.MLDSA65PublicKey,
            ),
            SignatureAlgorithmId.ML_DSA_87: (
                mldsa.MLDSA87PrivateKey,
                mldsa.MLDSA87PublicKey,
            ),
        }
        return classes[self.algorithm_id]
