"""Fixed neural building blocks for the SAGA-PQ-CAN research prototype."""

from neural.can import CAN
from neural.compiled_lwe_dnn import (
    CompiledVerifierBoundary,
    CompiledToyLWEVerifier,
    FixedEqualityAggregator,
    FixedEqualityGate,
    FixedMatrixProjector,
    FixedModSubtractor,
    ProjectionTrace,
)
from neural.fixed_circuit import (
    TrainableStateFinding,
    assert_fixed_circuit,
    find_trainable_state,
)
from neural.shamir_layers import (
    MASK,
    RECT13,
    STEP13,
    FixedLinear,
    FixedReLU,
    FixedSum,
)
from neural.verifier_wrapper import (
    BitLayout,
    CompoundBitVerifier,
    SignatureVerifierWrapper,
    bits_to_bytes,
    bytes_to_bits,
)

__all__ = [
    "BitLayout",
    "CAN",
    "CompiledVerifierBoundary",
    "CompiledToyLWEVerifier",
    "CompoundBitVerifier",
    "FixedEqualityAggregator",
    "FixedEqualityGate",
    "FixedLinear",
    "FixedMatrixProjector",
    "FixedModSubtractor",
    "FixedReLU",
    "FixedSum",
    "STEP13",
    "RECT13",
    "MASK",
    "ProjectionTrace",
    "TrainableStateFinding",
    "SignatureVerifierWrapper",
    "assert_fixed_circuit",
    "bits_to_bytes",
    "bytes_to_bits",
    "find_trainable_state",
]
