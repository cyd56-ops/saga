"""Route B integration for vetted external ML-DSA backends.

This module does not implement ML-DSA. It pins a locally trusted backend to a
versioned contract and converts its verification result into fail-closed route
evidence before later fixed-authorization-circuit stages are introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from queue import Empty, Queue
import threading
from typing import Literal, Protocol

from pq.signature_binding import (
    ML_DSA_CONTEXT_V1,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)


MLDSA_BACKEND_API_VERSION_V1 = "saga-mldsa-backend-v1"

_ML_DSA_PUBLIC_KEY_BYTES = {
    SignatureAlgorithmId.ML_DSA_44: 1312,
    SignatureAlgorithmId.ML_DSA_65: 1952,
    SignatureAlgorithmId.ML_DSA_87: 2592,
}
_ML_DSA_SIGNATURE_BYTES = {
    SignatureAlgorithmId.ML_DSA_44: 2420,
    SignatureAlgorithmId.ML_DSA_65: 3309,
    SignatureAlgorithmId.ML_DSA_87: 4627,
}

MLDSARouteBReason = Literal[
    "signature_valid",
    "signature_invalid",
    "binding_invalid",
    "binding_contract_mismatch",
    "public_key_input_invalid",
    "signature_input_invalid",
    "backend_interface_invalid",
    "backend_descriptor_error",
    "backend_descriptor_invalid",
    "backend_api_version_mismatch",
    "backend_identity_mismatch",
    "backend_version_mismatch",
    "backend_capability_mismatch",
    "backend_unavailable",
    "backend_timeout",
    "backend_verification_error",
    "backend_result_invalid",
]


@dataclass(frozen=True)
class MLDSABackendDescriptorV1:
    """描述注入 backend 的固定身份、版本、provider 与单一 profile 能力。"""

    backend_name: str
    backend_version: str
    provider_name: str
    provider_version: str
    api_version: str
    algorithm_id: SignatureAlgorithmId
    profile_id: SignatureProfileId
    context: bytes
    available: bool

    def __post_init__(self) -> None:
        """拒绝空身份、非 typed profile 和不规范 context/availability。"""
        text_fields = (
            ("backend_name", self.backend_name),
            ("backend_version", self.backend_version),
            ("provider_name", self.provider_name),
            ("provider_version", self.provider_version),
            ("api_version", self.api_version),
        )
        for field_name, value in text_fields:
            if type(value) is not str or not value.strip():
                raise ValueError(f"{field_name} must be non-empty text")
        if not isinstance(self.algorithm_id, SignatureAlgorithmId):
            raise TypeError("algorithm_id must use SignatureAlgorithmId")
        if self.algorithm_id not in _ML_DSA_PUBLIC_KEY_BYTES:
            raise ValueError("backend descriptor requires an ML-DSA algorithm")
        if not isinstance(self.profile_id, SignatureProfileId):
            raise TypeError("profile_id must use SignatureProfileId")
        if self.profile_id is SignatureProfileId.TOY_DIRECT:
            raise ValueError("backend descriptor cannot advertise the toy profile")
        if type(self.context) is not bytes or len(self.context) > 255:
            raise ValueError("backend context must be bytes of at most 255 bytes")
        if type(self.available) is not bool:
            raise TypeError("backend availability must be a built-in bool")


@dataclass(frozen=True)
class MLDSABackendContractV1:
    """固定本地部署批准的 backend/provider 版本和签名 profile。"""

    backend_name: str
    backend_version: str
    provider_name: str
    provider_version: str
    algorithm_id: SignatureAlgorithmId
    profile_id: SignatureProfileId
    context: bytes = ML_DSA_CONTEXT_V1
    timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        """要求显式版本 pin、固定 V1 context 和有限正超时。"""
        text_fields = (
            ("backend_name", self.backend_name),
            ("backend_version", self.backend_version),
            ("provider_name", self.provider_name),
            ("provider_version", self.provider_version),
        )
        for field_name, value in text_fields:
            if type(value) is not str or not value.strip():
                raise ValueError(f"{field_name} must be non-empty text")
        if not isinstance(self.algorithm_id, SignatureAlgorithmId):
            raise TypeError("algorithm_id must use SignatureAlgorithmId")
        if self.algorithm_id not in _ML_DSA_PUBLIC_KEY_BYTES:
            raise ValueError("backend contract requires an ML-DSA algorithm")
        if not isinstance(self.profile_id, SignatureProfileId):
            raise TypeError("profile_id must use SignatureProfileId")
        if self.profile_id is SignatureProfileId.TOY_DIRECT:
            raise ValueError("backend contract cannot use the toy profile")
        if type(self.context) is not bytes or self.context != ML_DSA_CONTEXT_V1:
            raise ValueError("backend contract must use ML_DSA_CONTEXT_V1")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive")


@dataclass(frozen=True)
class MLDSARouteBVerificationEvidence:
    """记录标准 ML-DSA route 的严格结果，不复制 backend 异常文本。"""

    accepted: bool
    reason: MLDSARouteBReason
    descriptor: MLDSABackendDescriptorV1 | None = None
    backend_result_type: str | None = None
    backend_error_type: str | None = None
    missing_methods: tuple[str, ...] = ()


class MLDSABackendV1(Protocol):
    """定义路线 B 可注入的版本化 ML-DSA backend 最小接口。"""

    def descriptor(self) -> MLDSABackendDescriptorV1:
        """返回 backend/provider 身份、版本和已配置 profile。"""
        ...

    def keygen(self) -> tuple[bytes, bytes]:
        """生成 raw public key 与 32-byte private seed。"""
        ...

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """按 descriptor 固定的 profile/context 签名完整 binding bytes。"""
        ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """按 descriptor 固定的 profile/context 返回原生布尔验签结果。"""
        ...


@dataclass(frozen=True)
class _BackendCallOutcome:
    """在线程边界内传递结果或稳定异常类型，不携带异常消息。"""

    result: object | None = None
    error_type: str | None = None
    timeout_error: bool = False
    call_timed_out: bool = False


class MLDSARouteBVerifier:
    """按本地固定 contract 调用标准 ML-DSA backend 并生成 route evidence。"""

    _REQUIRED_METHODS = ("descriptor", "keygen", "sign", "verify")

    def __init__(
        self,
        backend: object,
        contract: MLDSABackendContractV1,
    ) -> None:
        """保存显式 backend/contract，并限制每个 verifier 最多一个在途调用。"""
        if not isinstance(contract, MLDSABackendContractV1):
            raise TypeError("contract must be MLDSABackendContractV1")
        self._backend = backend
        self.contract = contract
        self._call_slot = threading.BoundedSemaphore(value=1)

    def verify(
        self,
        binding: SignatureBindingV1,
        public_key: bytes,
        signature: bytes,
    ) -> MLDSARouteBVerificationEvidence:
        """严格验证 binding、backend contract 和签名，任何不确定状态均拒绝。"""
        if (
            type(binding) is not SignatureBindingV1
            or binding.route_id is not SignatureRouteId.ROUTE_B_STANDARD
        ):
            return self._reject("binding_invalid")
        if (
            binding.algorithm_id is not self.contract.algorithm_id
            or binding.profile_id is not self.contract.profile_id
        ):
            return self._reject("binding_contract_mismatch")
        if type(public_key) is not bytes or len(public_key) != _ML_DSA_PUBLIC_KEY_BYTES[
            binding.algorithm_id
        ]:
            return self._reject("public_key_input_invalid")
        if type(signature) is not bytes or len(signature) != _ML_DSA_SIGNATURE_BYTES[
            binding.algorithm_id
        ]:
            return self._reject("signature_input_invalid")

        missing_methods = tuple(
            method_name
            for method_name in self._REQUIRED_METHODS
            if not callable(getattr(self._backend, method_name, None))
        )
        if missing_methods:
            return self._reject(
                "backend_interface_invalid",
                missing_methods=missing_methods,
            )

        try:
            descriptor = self._backend.descriptor()
        except Exception as exc:
            return self._reject(
                "backend_descriptor_error",
                backend_error_type=type(exc).__name__,
            )
        if type(descriptor) is not MLDSABackendDescriptorV1:
            return self._reject(
                "backend_descriptor_invalid",
                backend_result_type=type(descriptor).__name__,
            )
        descriptor_reason = self._descriptor_reject_reason(descriptor)
        if descriptor_reason is not None:
            return self._reject(descriptor_reason, descriptor=descriptor)
        if not descriptor.available:
            return self._reject("backend_unavailable", descriptor=descriptor)

        outcome = self._verify_with_timeout(
            public_key,
            binding.canonical_bytes(),
            signature,
        )
        if outcome.call_timed_out or outcome.timeout_error:
            return self._reject(
                "backend_timeout",
                descriptor=descriptor,
                backend_error_type=outcome.error_type,
            )
        if outcome.error_type is not None:
            return self._reject(
                "backend_verification_error",
                descriptor=descriptor,
                backend_error_type=outcome.error_type,
            )
        if type(outcome.result) is not bool:
            return self._reject(
                "backend_result_invalid",
                descriptor=descriptor,
                backend_result_type=type(outcome.result).__name__,
            )
        if outcome.result:
            return MLDSARouteBVerificationEvidence(
                True,
                "signature_valid",
                descriptor=descriptor,
            )
        return self._reject("signature_invalid", descriptor=descriptor)

    def _descriptor_reject_reason(
        self,
        descriptor: MLDSABackendDescriptorV1,
    ) -> MLDSARouteBReason | None:
        """按 API、身份、版本、能力的固定顺序检查 backend descriptor。"""
        if descriptor.api_version != MLDSA_BACKEND_API_VERSION_V1:
            return "backend_api_version_mismatch"
        if (
            descriptor.backend_name != self.contract.backend_name
            or descriptor.provider_name != self.contract.provider_name
        ):
            return "backend_identity_mismatch"
        if (
            descriptor.backend_version != self.contract.backend_version
            or descriptor.provider_version != self.contract.provider_version
        ):
            return "backend_version_mismatch"
        if (
            descriptor.algorithm_id is not self.contract.algorithm_id
            or descriptor.profile_id is not self.contract.profile_id
            or descriptor.context != self.contract.context
        ):
            return "backend_capability_mismatch"
        return None

    def _verify_with_timeout(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> _BackendCallOutcome:
        """在有界 daemon worker 中调用 backend；超时后隔离同实例后续调用。"""
        if not self._call_slot.acquire(blocking=False):
            return _BackendCallOutcome(call_timed_out=True)
        outcomes: Queue[_BackendCallOutcome] = Queue(maxsize=1)

        # worker 只转移结果类型；异常文本和密钥材料不进入 evidence。
        def invoke_backend() -> None:
            try:
                result = self._backend.verify(public_key, message, signature)
                outcome = _BackendCallOutcome(result=result)
            except BaseException as exc:
                outcome = _BackendCallOutcome(
                    error_type=type(exc).__name__,
                    timeout_error=isinstance(exc, TimeoutError),
                )
            finally:
                self._call_slot.release()
            outcomes.put(outcome)

        worker = threading.Thread(
            target=invoke_backend,
            name="saga-mldsa-route-b-verify",
            daemon=True,
        )
        try:
            worker.start()
        except Exception as exc:
            self._call_slot.release()
            return _BackendCallOutcome(error_type=type(exc).__name__)
        try:
            return outcomes.get(timeout=float(self.contract.timeout_seconds))
        except Empty:
            return _BackendCallOutcome(call_timed_out=True)

    @staticmethod
    def _reject(
        reason: MLDSARouteBReason,
        *,
        descriptor: MLDSABackendDescriptorV1 | None = None,
        backend_result_type: str | None = None,
        backend_error_type: str | None = None,
        missing_methods: tuple[str, ...] = (),
    ) -> MLDSARouteBVerificationEvidence:
        """构造统一 fail-closed evidence，避免各拒绝路径遗漏 accepted=False。"""
        return MLDSARouteBVerificationEvidence(
            False,
            reason,
            descriptor=descriptor,
            backend_result_type=backend_result_type,
            backend_error_type=backend_error_type,
            missing_methods=missing_methods,
        )
