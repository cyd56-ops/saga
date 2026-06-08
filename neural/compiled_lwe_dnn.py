"""First-phase compiled DNN verifier for the toy LWE research scheme.

This module intentionally compiles the toy verifier's public matrix projection
into fixed linear layers and keeps the remaining verifier steps as explicit
deterministic preprocessing or hard gates. In particular, SHA-256 challenge
derivation is not represented as a neural hash circuit in the current prototype.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from neural.shamir_layers import FixedLinear, FixedSum
from neural.verifier_wrapper import BitLayout, bits_to_bytes
from pq.toy_lwe import ToyLWESignatureScheme


@dataclass(frozen=True)
class CompiledVerifierBoundary:
    """记录当前 compiled verifier 哪些步骤已经下沉到固定电路。"""

    compiled_fixed_circuit_steps: tuple[str, ...]
    deterministic_preprocessing_steps: tuple[str, ...]
    deterministic_hard_gate_steps: tuple[str, ...]


@dataclass(frozen=True)
class ProjectionTrace:
    """Intermediate vectors produced by the compiled toy LWE verifier core."""

    public_vector: tuple[int, ...]
    signature_vector: tuple[int, ...]
    challenge_vector: tuple[int, ...]
    challenge_source: str
    signature_projection: tuple[int, ...]
    challenge_projection: tuple[int, ...]
    recovered_public: tuple[int, ...]
    equality_bits: tuple[int, ...]
    accept: int


class FixedMatrixProjector:
    """Apply a public matrix using non-trainable fixed linear rows."""

    def __init__(self, matrix: Sequence[Sequence[int]]) -> None:
        """Compile each matrix row into a fixed affine map."""
        self.rows = tuple(
            FixedLinear(tuple(float(coefficient) for coefficient in row))
            for row in matrix
        )

    def __call__(self, vector: Sequence[int]) -> list[int]:
        """Project ``vector`` through all compiled rows."""
        values = tuple(float(value) for value in vector)
        return [int(row(values)) for row in self.rows]

    def submodules(self) -> tuple[FixedLinear, ...]:
        """Return the fixed row projectors backing this matrix operator."""
        return self.rows


@dataclass(frozen=True)
class FixedModSubtractor:
    """A fixed hard gate for modular subtraction."""

    modulus: int
    requires_grad: bool = False

    def __call__(self, left: int, right: int) -> int:
        """Return ``(left - right) mod modulus``."""
        return (int(left) - int(right)) % self.modulus


@dataclass(frozen=True)
class FixedEqualityGate:
    """A fixed hard gate returning ``1`` exactly on equality."""

    requires_grad: bool = False

    def __call__(self, left: int, right: int) -> int:
        """Return a hard equality bit."""
        return int(int(left) == int(right))


class FixedEqualityAggregator:
    """Aggregate coordinate-wise equality bits into one hard accept bit."""

    def __init__(self, width: int) -> None:
        """Build the fixed sum and remember the expected all-ones width."""
        self.width = width
        self.sum_layer = FixedSum()
        self.requires_grad = False

    def __call__(self, equality_bits: Sequence[int]) -> int:
        """仅当所有等式比特均为 ``1`` 时返回硬接受。"""
        if len(equality_bits) != self.width:
            raise ValueError(f"expected {self.width} equality bits, received {len(equality_bits)}")
        total = self.sum_layer(float(bit) for bit in equality_bits)
        return int(total == float(self.width))

    def submodules(self) -> tuple[FixedSum, ...]:
        """返回聚合器内部的固定求和层。"""
        return (self.sum_layer,)


class CompiledToyLWEVerifier:
    """Verify toy LWE signatures with a partially compiled deterministic circuit.

    Security invariant:
    - This verifier is strictly research-only because the underlying toy scheme
      is non-production.
    - The compiled fixed-circuit portion covers the public matrix projections.
    - Challenge derivation remains explicit deterministic preprocessing.
    - Modular subtraction, equality comparison, and acceptance aggregation are
      deterministic hard gates instead of trainable neural components.
    """

    BOUNDARY = CompiledVerifierBoundary(
        compiled_fixed_circuit_steps=(
            "public_matrix_times_signature",
            "public_matrix_times_challenge",
        ),
        deterministic_preprocessing_steps=(
            "sha256_domain_separated_challenge_derivation",
            "byte_vector_decoding",
        ),
        deterministic_hard_gate_steps=(
            "modular_subtraction",
            "coordinate_equality",
            "all_coordinates_equal_aggregation",
        ),
    )

    def __init__(self, scheme: ToyLWESignatureScheme, message_bytes: int) -> None:
        """Compile the toy scheme's public matrix into fixed linear layers."""
        self.scheme = scheme
        self.layout = BitLayout(
            public_key_bytes=scheme.vector_bytes,
            message_bytes=message_bytes,
            signature_bytes=scheme.vector_bytes,
        )
        self.modulus = scheme.parameters.modulus
        self.signature_projector = FixedMatrixProjector(scheme.public_matrix())
        self.mod_subtractor = FixedModSubtractor(self.modulus)
        self.equality_gate = FixedEqualityGate()
        self.accept_aggregator = FixedEqualityAggregator(scheme.parameters.dimension)

    def compilation_boundary(self) -> CompiledVerifierBoundary:
        """返回当前验签器的固定电路、预处理与硬门控边界。"""
        return self.BOUNDARY

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

    def trace_verification(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> ProjectionTrace:
        """Return the deterministic intermediate vectors for one verification."""
        public_vector = tuple(self.scheme.decode_public_vector(public_key))
        signature_vector = tuple(self.scheme.decode_signature_vector(signature))
        challenge_vector = tuple(self.scheme.challenge_vector(message))
        challenge_source = "deterministic_sha256_preprocessing:not_neural_hash"
        signature_projection = tuple(self.signature_projector(signature_vector))
        challenge_projection = tuple(self.signature_projector(challenge_vector))
        # 恢复公钥只使用公开矩阵、签名向量和消息挑战，不包含签名私钥。
        recovered_public = tuple(
            self.mod_subtractor(left_coeff, challenge_coeff)
            for left_coeff, challenge_coeff in zip(
                signature_projection, challenge_projection, strict=True
            )
        )
        equality_bits = tuple(
            self.equality_gate(recovered_coeff, public_coeff)
            for recovered_coeff, public_coeff in zip(
                recovered_public,
                public_vector,
                strict=True,
            )
        )
        accept = self.accept_aggregator(equality_bits)
        return ProjectionTrace(
            public_vector=public_vector,
            signature_vector=signature_vector,
            challenge_vector=challenge_vector,
            challenge_source=challenge_source,
            signature_projection=signature_projection,
            challenge_projection=challenge_projection,
            recovered_public=recovered_public,
            equality_bits=equality_bits,
            accept=accept,
        )

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """Verify byte-encoded material and return a hard ``0`` or ``1``."""
        try:
            trace = self.trace_verification(public_key, message, signature)
        except ValueError:
            return 0
        return trace.accept

    def verify_bits(
        self,
        public_key_bits: Sequence[int | float],
        message_bits: Sequence[int | float],
        signature_bits: Sequence[int | float],
    ) -> int:
        """Verify bit-encoded material and return a hard ``0`` or ``1``."""
        try:
            public_key = bits_to_bytes(public_key_bits)
            message = bits_to_bytes(message_bits)
            signature = bits_to_bytes(signature_bits)
        except ValueError:
            return 0
        return self.verify_bytes(public_key, message, signature)

    def verify_compound_bits(self, bits: Sequence[int | float]) -> int:
        """Verify a concatenated ``pk || message || signature`` bit vector."""
        public_key_bits, message_bits, signature_bits = self.split_bits(bits)
        return self.verify_bits(public_key_bits, message_bits, signature_bits)

    def submodules(self) -> tuple[object, ...]:
        """返回 toy LWE 编译验签器中的固定电路子模块。"""
        return (
            self.signature_projector,
            self.mod_subtractor,
            self.equality_gate,
            self.accept_aggregator,
        )
