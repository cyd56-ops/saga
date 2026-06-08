"""Signature scheme interfaces used by the SAGA-PQ-CAN prototype."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class KeyPair:
    """Byte-serialized public and secret key material for a signature scheme."""

    public_key: bytes
    secret_key: bytes


class SignatureScheme(Protocol):
    """Protocol implemented by all signature scheme backends used in the prototype."""

    def keygen(self) -> KeyPair:
        """Generate a fresh key pair."""

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Produce a signature over ``message`` using ``secret_key``."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return ``True`` only when ``signature`` is valid for ``message`` and ``public_key``."""
