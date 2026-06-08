"""Production-facing ML-DSA adapter.

The research prototype can wire real post-quantum libraries through this
adapter, but it must not implement ML-DSA from scratch in this repository.
"""

from __future__ import annotations

from pq.signature_scheme import KeyPair


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

        验签结果被收敛为布尔值，backend 缺失或畸形时不会静默降级。
        """
        backend = self._require_backend()
        return bool(backend.verify(public_key, message, signature))

    def _require_backend(self) -> object:
        """Return the backend or fail closed when none has been configured.

        这里集中检查 backend 形状，避免无意使用空实现或错误对象。
        """
        if self.backend is None:
            raise RuntimeError(
                "ML-DSA backend not installed. This adapter must wrap a vetted external implementation."
            )
        required_methods = ("keygen", "sign", "verify")
        missing = [
            method_name
            for method_name in required_methods
            if not callable(getattr(self.backend, method_name, None))
        ]
        if missing:
            raise TypeError(
                "ML-DSA backend is missing required methods: "
                + ", ".join(missing)
            )
        return self.backend
