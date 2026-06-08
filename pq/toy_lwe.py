"""Toy lattice-style signatures for research tests only.

This module is intentionally non-production. The construction is a simplified
linear algebra toy that helps exercise verifier integration and deterministic
tests, but it does not provide real post-quantum security.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random

from pq.signature_scheme import KeyPair


@dataclass(frozen=True)
class ToyLWEParameters:
    """Parameters for the non-production toy lattice-style signature scheme."""

    dimension: int = 8
    modulus: int = 257
    matrix_seed: int = 0


class ToyLWESignatureScheme:
    """Non-production toy LWE/SIS-style signature scheme for tests only.

    Security invariant:
    - Use this scheme only for research wiring and regression tests.
    - The scheme is intentionally simple and should never be used for real
      authentication or cryptographic deployments.
    """

    def __init__(self, seed: int = 0, parameters: ToyLWEParameters | None = None) -> None:
        """Build a deterministic toy scheme instance.

        Args:
            seed: Seed for deterministic test key generation.
            parameters: Optional scheme parameters.
        """
        self.parameters = parameters or ToyLWEParameters()
        if self.parameters.dimension <= 0:
            raise ValueError("dimension must be positive")
        if self.parameters.modulus <= 1 or self.parameters.modulus >= 65536:
            raise ValueError("modulus must be in the range [2, 65535]")
        self._rng = random.Random(seed)
        self._matrix = self._build_matrix()

    def keygen(self) -> KeyPair:
        """Generate a deterministic key pair for the configured toy scheme."""
        secret_vector = [
            self._rng.randrange(self.parameters.modulus)
            for _ in range(self.parameters.dimension)
        ]
        public_vector = self._matrix_vector_mul(self._matrix, secret_vector)
        return KeyPair(
            public_key=self._encode_vector(public_vector),
            secret_key=self._encode_vector(secret_vector),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Return a toy signature over ``message``.

        The signature is a simple linear relation used only to exercise the
        verifier API. It is not secure and must remain test-only.
        """
        secret_vector = self._decode_vector(secret_key)
        challenge = self._challenge_vector(message)
        signature = [
            (secret_coeff + challenge_coeff) % self.parameters.modulus
            for secret_coeff, challenge_coeff in zip(secret_vector, challenge, strict=True)
        ]
        return self._encode_vector(signature)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a toy signature against ``public_key`` and ``message``."""
        try:
            public_vector = self.decode_public_vector(public_key)
            signature_vector = self.decode_signature_vector(signature)
        except ValueError:
            return False

        challenge = self.challenge_vector(message)
        left = self._matrix_vector_mul(self._matrix, signature_vector)
        challenge_projection = self._matrix_vector_mul(self._matrix, challenge)
        recovered_public = [
            (left_coeff - challenge_coeff) % self.parameters.modulus
            for left_coeff, challenge_coeff in zip(left, challenge_projection, strict=True)
        ]
        return recovered_public == public_vector

    @property
    def vector_bytes(self) -> int:
        """Return the serialized byte length of one lattice vector."""
        return self.parameters.dimension * 2

    def public_matrix(self) -> tuple[tuple[int, ...], ...]:
        """Return the deterministic public matrix as an immutable structure."""
        return tuple(tuple(row) for row in self._matrix)

    def challenge_vector(self, message: bytes) -> list[int]:
        """Return the deterministic challenge vector derived from ``message``."""
        return self._challenge_vector(message)

    def decode_public_vector(self, public_key: bytes) -> list[int]:
        """Decode a serialized public key into a lattice vector."""
        return self._decode_vector(public_key)

    def decode_signature_vector(self, signature: bytes) -> list[int]:
        """Decode a serialized signature into a lattice vector."""
        return self._decode_vector(signature)

    def _build_matrix(self) -> list[list[int]]:
        """Derive a deterministic square matrix from the configured seed."""
        matrix = []
        seed_bytes = self.parameters.matrix_seed.to_bytes(8, "little", signed=False)
        for row_index in range(self.parameters.dimension):
            row = []
            for column_index in range(self.parameters.dimension):
                digest = hashlib.sha256(
                    b"toy-lwe-matrix"
                    + seed_bytes
                    + row_index.to_bytes(2, "little", signed=False)
                    + column_index.to_bytes(2, "little", signed=False)
                ).digest()
                row.append(int.from_bytes(digest[:2], "little") % self.parameters.modulus)
            matrix.append(row)
        return matrix

    def _challenge_vector(self, message: bytes) -> list[int]:
        """Map ``message`` to a deterministic vector in ``Z_q^n``."""
        return [
            int.from_bytes(chunk, "little") % self.parameters.modulus
            for chunk in self._expand_chunks(
                domain=b"toy-lwe-challenge",
                payload=message,
                count=self.parameters.dimension,
            )
        ]

    def _expand_chunks(self, *, domain: bytes, payload: bytes, count: int) -> list[bytes]:
        """Expand hashed material into ``count`` 2-byte chunks."""
        chunks = []
        counter = 0
        while len(chunks) < count:
            digest = hashlib.sha256(
                domain + counter.to_bytes(4, "little", signed=False) + payload
            ).digest()
            for offset in range(0, len(digest), 2):
                if len(chunks) == count:
                    break
                chunks.append(digest[offset : offset + 2])
            counter += 1
        return chunks

    def _matrix_vector_mul(self, matrix: list[list[int]], vector: list[int]) -> list[int]:
        """Multiply a square matrix by a vector in ``Z_q``."""
        return [
            sum(coeff * value for coeff, value in zip(row, vector, strict=True))
            % self.parameters.modulus
            for row in matrix
        ]

    def _encode_vector(self, vector: list[int]) -> bytes:
        """Serialize a vector as little-endian uint16 coefficients."""
        return b"".join(
            coeff.to_bytes(2, "little", signed=False) for coeff in vector
        )

    def _decode_vector(self, encoded: bytes) -> list[int]:
        """Deserialize a vector from little-endian uint16 coefficients."""
        expected_length = self.parameters.dimension * 2
        if len(encoded) != expected_length:
            raise ValueError(
                f"expected {expected_length} bytes, received {len(encoded)}"
            )
        vector = []
        for offset in range(0, len(encoded), 2):
            coeff = int.from_bytes(encoded[offset : offset + 2], "little", signed=False)
            if coeff >= self.parameters.modulus:
                raise ValueError("encoded coefficient is out of range")
            vector.append(coeff)
        return vector
