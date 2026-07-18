"""Post-quantum signature abstractions for the SAGA-PQ-CAN research prototype."""

from pq.mldsa_adapter import MLDSAAdapter, MLDSAVerificationEvidence
from pq.signature_binding import (
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)
from pq.signature_scheme import KeyPair, SignatureScheme
from pq.toy_lwe import ToyLWEParameters, ToyLWESignatureScheme
from pq.toy_module_lattice import (
    ModuleMatrix,
    ModuleVector,
    Polynomial,
    ToyModuleLatticeParameters,
    ToyModuleLatticeSignatureScheme,
)

__all__ = [
    "EnvelopeCanonicalizationId",
    "EnvelopeDigestAlgorithmId",
    "KeyPair",
    "ML_DSA_CONTEXT_V1",
    "MLDSAAdapter",
    "MLDSAVerificationEvidence",
    "ModuleMatrix",
    "ModuleVector",
    "Polynomial",
    "SignatureAlgorithmId",
    "SignatureBindingV1",
    "SignatureProfileId",
    "SignatureRouteId",
    "SignatureScheme",
    "ToyLWEParameters",
    "ToyLWESignatureScheme",
    "ToyModuleLatticeParameters",
    "ToyModuleLatticeSignatureScheme",
]
