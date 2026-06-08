"""Deterministic verifier wrappers used by the first SAGA-PQ-CAN CAN prototype."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from pq.signature_scheme import SignatureScheme


class CompoundBitVerifier(Protocol):
    """Protocol implemented by fixed verifiers over concatenated bit vectors."""

    def verify_compound_bits(self, bits: Sequence[int | float]) -> int:
        """Verify a concatenated ``pk || message || signature`` bit vector."""


def bytes_to_bits(payload: bytes) -> list[int]:
    """Expand ``payload`` into a big-endian bit vector."""
    bits: list[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: Sequence[int | float]) -> bytes:
    """Pack a binary bit vector into bytes.

    Every coordinate must be exactly ``0`` or ``1``.
    """
    if len(bits) % 8 != 0:
        raise ValueError("bit vector length must be a multiple of 8")

    encoded = bytearray()
    for offset in range(0, len(bits), 8):
        byte = 0
        for bit in bits[offset : offset + 8]:
            if bit not in (0, 1):
                raise ValueError("bit vector must contain only exact 0/1 values")
            byte = (byte << 1) | int(bit)
        encoded.append(byte)
    return bytes(encoded)


@dataclass(frozen=True)
class BitLayout:
    """Fixed layout describing how a concatenated bit vector is partitioned."""

    public_key_bytes: int
    message_bytes: int
    signature_bytes: int

    @property
    def public_key_bits(self) -> int:
        """Return the public-key segment length in bits."""
        return self.public_key_bytes * 8

    @property
    def message_bits(self) -> int:
        """Return the message segment length in bits."""
        return self.message_bytes * 8

    @property
    def signature_bits(self) -> int:
        """Return the signature segment length in bits."""
        return self.signature_bytes * 8

    @property
    def total_bits(self) -> int:
        """Return the total concatenated bit length."""
        return self.public_key_bits + self.message_bits + self.signature_bits


class SignatureVerifierWrapper:
    """Wrap a byte-based signature scheme with deterministic bit-vector parsing."""

    def __init__(self, scheme: SignatureScheme, layout: BitLayout) -> None:
        """Store the signature scheme and expected input layout."""
        self.scheme = scheme
        self.layout = layout

    def split_bits(
        self, bits: Sequence[int | float]
    ) -> tuple[list[int | float], list[int | float], list[int | float]]:
        """Split a concatenated bit vector into ``pk``, ``message``, and ``signature``."""
        if len(bits) != self.layout.total_bits:
            raise ValueError(
                f"expected {self.layout.total_bits} total bits, received {len(bits)}"
            )

        public_key_end = self.layout.public_key_bits
        message_end = public_key_end + self.layout.message_bits
        return (
            list(bits[:public_key_end]),
            list(bits[public_key_end:message_end]),
            list(bits[message_end:]),
        )

    def verify_bits(
        self,
        public_key_bits: Sequence[int | float],
        message_bits: Sequence[int | float],
        signature_bits: Sequence[int | float],
    ) -> int:
        """Verify a bit-encoded signature and return a hard ``0`` or ``1`` result."""
        public_key = bits_to_bytes(public_key_bits)
        message = bits_to_bytes(message_bits)
        signature = bits_to_bytes(signature_bits)
        return int(self.scheme.verify(public_key, message, signature))

    def verify_compound_bits(self, bits: Sequence[int | float]) -> int:
        """Verify a concatenated ``pk || message || signature`` bit vector."""
        public_key_bits, message_bits, signature_bits = self.split_bits(bits)
        return self.verify_bits(public_key_bits, message_bits, signature_bits)
