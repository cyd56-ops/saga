"""Production-facing ML-DSA adapter.

The research prototype can wire real post-quantum libraries through this
adapter, but it must not implement ML-DSA from scratch in this repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pq.signature_scheme import KeyPair


@dataclass(frozen=True)
class MLDSAVerificationEvidence:
    """记录一次外部 ML-DSA 验签的严格结果与稳定失败原因。

    Backend 异常文本可能包含实现细节，因此 evidence 只保留异常类型和返回
    类型，不保存异常消息。调用方只能在 ``accepted`` 为 ``True`` 时放行。
    """

    accepted: bool
    reason: Literal[
        "signature_valid",
        "signature_invalid",
        "backend_unavailable",
        "backend_interface_invalid",
        "backend_verification_error",
        "backend_result_invalid",
    ]
    backend_result_type: str | None = None
    backend_error_type: str | None = None
    missing_methods: tuple[str, ...] = ()


class MLDSAAdapter:
    """Adapter around a vetted external ML-DSA backend.

    Security invariant:
    - This adapter does not implement ML-DSA itself.
    - Without an explicitly supplied backend it fails closed.
    - A backend must expose ``keygen()``, ``sign(secret_key, message)``, and
      ``verify(public_key, message, signature)`` methods with byte-oriented
      signatures.
    """

    def __init__(self, backend: object | None = None) -> None:
        """Store an optional vetted backend object supplied by the caller.

        生产风格 ML-DSA 只能通过外部审查过的 backend 接入，仓库内不手写算法。
        """
        self.backend = backend

    def keygen(self) -> KeyPair:
        """Generate a key pair using the configured external backend.

        密钥生成完全委托外部 backend，本适配器只规范返回类型。
        """
        backend = self._require_backend()
        public_key, secret_key = backend.keygen()
        return KeyPair(public_key=bytes(public_key), secret_key=bytes(secret_key))

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign ``message`` using the configured external backend.

        签名计算由外部 ML-DSA backend 完成，仓库内不实现算法细节。
        """
        backend = self._require_backend()
        return bytes(backend.sign(secret_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` using the configured external backend.

        只有 backend 返回内建 ``bool`` 类型的 ``True`` 才接受；缺失、异常、
        畸形接口和 truthy 非布尔返回都统一 fail-closed 为 ``False``。
        """
        return self.verify_with_evidence(public_key, message, signature).accepted

    def verify_with_evidence(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> MLDSAVerificationEvidence:
        """严格验签并返回不提交本地授权状态的可审计 backend evidence。

        普通签名无效与 backend 操作错误使用不同 reason；两者均拒绝。这里不
        把非布尔返回强制转换为布尔值，防止字符串、整数等 truthy 对象被误接受；
        外部 backend 自身的实现行为仍属于后续接入时需要审计的边界。
        """
        if self.backend is None:
            return MLDSAVerificationEvidence(False, "backend_unavailable")

        missing_methods = self._missing_backend_methods(self.backend)
        if missing_methods:
            return MLDSAVerificationEvidence(
                False,
                "backend_interface_invalid",
                missing_methods=missing_methods,
            )

        try:
            result = self.backend.verify(public_key, message, signature)
        except Exception as exc:
            return MLDSAVerificationEvidence(
                False,
                "backend_verification_error",
                backend_error_type=type(exc).__name__,
            )

        if type(result) is not bool:
            return MLDSAVerificationEvidence(
                False,
                "backend_result_invalid",
                backend_result_type=type(result).__name__,
            )
        if result:
            return MLDSAVerificationEvidence(True, "signature_valid")
        return MLDSAVerificationEvidence(False, "signature_invalid")

    def _require_backend(self) -> object:
        """Return the backend or fail closed when none has been configured.

        这里集中检查 backend 形状，避免无意使用空实现或错误对象。
        """
        if self.backend is None:
            raise RuntimeError(
                "ML-DSA backend not installed. This adapter must wrap a vetted external implementation."
            )
        missing = self._missing_backend_methods(self.backend)
        if missing:
            raise TypeError(
                "ML-DSA backend is missing required methods: "
                + ", ".join(missing)
            )
        return self.backend

    @staticmethod
    def _missing_backend_methods(backend: object) -> tuple[str, ...]:
        """返回 backend 缺失的必需方法，供命令路径与 evidence 路径共用。"""
        required_methods = ("keygen", "sign", "verify")
        return tuple(
            method_name
            for method_name in required_methods
            if not callable(getattr(backend, method_name, None))
        )
