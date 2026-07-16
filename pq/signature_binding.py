"""Versioned binary signature binding for dual-route runtime authentication."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct


SIGNATURE_BINDING_MAGIC = b"SAGA-SIG"
SIGNATURE_BINDING_VERSION = 1
SIGNATURE_BINDING_FIELD_COUNT = 7
MAX_KEY_ID_BYTES = 64
MAX_SIGNATURE_BINDING_BYTES = 132
ML_DSA_CONTEXT_V1 = b"SAGA-PQ-CAN-SignatureBindingV1"

_HEADER = struct.Struct(">8sBB")
_TLV_HEADER = struct.Struct(">BH")
_FIELD_TAGS = (1, 2, 3, 4, 5, 6, 7)


class SignatureRouteId(IntEnum):
    """标识双路线认证中产生签名 evidence 的固定路线。"""

    ROUTE_A_NEURAL = 1
    ROUTE_B_STANDARD = 2


class SignatureAlgorithmId(IntEnum):
    """标识 V1 允许绑定的签名算法或研究 relation。"""

    TOY_LWE_RESEARCH = 1
    ML_DSA_44 = 44
    ML_DSA_65 = 65
    ML_DSA_87 = 87


class SignatureProfileId(IntEnum):
    """标识 backend 必须使用的 pure 或 pre-hash 签名接口。"""

    TOY_DIRECT = 1
    ML_DSA_PURE = 2
    HASH_ML_DSA_SHA256 = 3
    HASH_ML_DSA_SHA512 = 4
    HASH_ML_DSA_SHAKE128 = 5
    HASH_ML_DSA_SHAKE256 = 6


class EnvelopeDigestAlgorithmId(IntEnum):
    """标识 canonical request envelope 的摘要算法。"""

    SHA256 = 1


class EnvelopeCanonicalizationId(IntEnum):
    """标识 request envelope 转换为摘要输入的规范化规则。"""

    SAGA_REQUEST_ENVELOPE_JSON_V1 = 1


_ML_DSA_ALGORITHMS = frozenset(
    {
        SignatureAlgorithmId.ML_DSA_44,
        SignatureAlgorithmId.ML_DSA_65,
        SignatureAlgorithmId.ML_DSA_87,
    }
)
_ML_DSA_PROFILES = frozenset(
    {
        SignatureProfileId.ML_DSA_PURE,
        SignatureProfileId.HASH_ML_DSA_SHA256,
        SignatureProfileId.HASH_ML_DSA_SHA512,
        SignatureProfileId.HASH_ML_DSA_SHAKE128,
        SignatureProfileId.HASH_ML_DSA_SHAKE256,
    }
)


@dataclass(frozen=True)
class SignatureBindingV1:
    """把路线、算法、密钥和 canonical envelope 摘要无歧义地绑定。

    ``canonical_bytes()`` 是提交给所选签名 profile 的完整消息。Pure ML-DSA
    直接签这些字节；HashML-DSA 必须由 vetted backend 按 profile 执行标准
    pre-hash，不允许调用方先手工哈希后再冒充 HashML-DSA。
    """

    route_id: SignatureRouteId
    algorithm_id: SignatureAlgorithmId
    key_id: bytes
    profile_id: SignatureProfileId
    digest_algorithm_id: EnvelopeDigestAlgorithmId
    canonicalization_id: EnvelopeCanonicalizationId
    envelope_digest: bytes

    def __post_init__(self) -> None:
        """验证字段类型、长度和路线/profile 组合，拒绝语义不一致绑定。"""
        enum_fields = (
            ("route_id", self.route_id, SignatureRouteId),
            ("algorithm_id", self.algorithm_id, SignatureAlgorithmId),
            ("profile_id", self.profile_id, SignatureProfileId),
            (
                "digest_algorithm_id",
                self.digest_algorithm_id,
                EnvelopeDigestAlgorithmId,
            ),
            (
                "canonicalization_id",
                self.canonicalization_id,
                EnvelopeCanonicalizationId,
            ),
        )
        for field_name, value, enum_type in enum_fields:
            if not isinstance(value, enum_type):
                raise TypeError(f"{field_name} must use its declared enum type")
        if type(self.key_id) is not bytes:
            raise TypeError("key_id must be bytes")
        if not self.key_id:
            raise ValueError("key_id must be non-empty")
        if len(self.key_id) > MAX_KEY_ID_BYTES:
            raise ValueError("key_id exceeds the V1 maximum length")
        if type(self.envelope_digest) is not bytes:
            raise TypeError("envelope_digest must be bytes")
        if self.digest_algorithm_id is EnvelopeDigestAlgorithmId.SHA256:
            if len(self.envelope_digest) != 32:
                raise ValueError("SHA-256 envelope_digest must be exactly 32 bytes")
        self._validate_route_profile()

    def canonical_bytes(self) -> bytes:
        """返回 V1 严格有序 TLV 编码，作为签名 backend 的完整消息。"""
        fields = (
            (1, bytes((int(self.route_id),))),
            (2, bytes((int(self.algorithm_id),))),
            (3, self.key_id),
            (4, bytes((int(self.profile_id),))),
            (5, bytes((int(self.digest_algorithm_id),))),
            (6, bytes((int(self.canonicalization_id),))),
            (7, self.envelope_digest),
        )
        encoded = bytearray(
            _HEADER.pack(
                SIGNATURE_BINDING_MAGIC,
                SIGNATURE_BINDING_VERSION,
                SIGNATURE_BINDING_FIELD_COUNT,
            )
        )
        for tag, value in fields:
            encoded.extend(_TLV_HEADER.pack(tag, len(value)))
            encoded.extend(value)
        return bytes(encoded)

    @classmethod
    def from_bytes(cls, payload: bytes) -> SignatureBindingV1:
        """解析严格 V1 编码；未知、重复、乱序或非规范字段全部 fail-closed。"""
        if type(payload) is not bytes:
            raise TypeError("signature binding payload must be bytes")
        if len(payload) > MAX_SIGNATURE_BINDING_BYTES:
            raise ValueError("signature binding exceeds the V1 maximum length")
        if len(payload) < _HEADER.size:
            raise ValueError("signature binding header is truncated")

        magic, version, field_count = _HEADER.unpack_from(payload)
        if magic != SIGNATURE_BINDING_MAGIC:
            raise ValueError("invalid signature binding magic")
        if version != SIGNATURE_BINDING_VERSION:
            raise ValueError("unsupported signature binding version")
        if field_count != SIGNATURE_BINDING_FIELD_COUNT:
            raise ValueError("signature binding field count must be exactly 7")

        fields: dict[int, bytes] = {}
        offset = _HEADER.size
        for expected_tag in _FIELD_TAGS:
            if offset + _TLV_HEADER.size > len(payload):
                raise ValueError("signature binding TLV header is truncated")
            tag, value_length = _TLV_HEADER.unpack_from(payload, offset)
            offset += _TLV_HEADER.size
            if tag != expected_tag:
                if tag in fields:
                    raise ValueError("signature binding contains a duplicate field")
                if tag not in _FIELD_TAGS:
                    raise ValueError("signature binding contains an unknown field")
                raise ValueError("signature binding fields are not in canonical order")
            value_end = offset + value_length
            if value_end > len(payload):
                raise ValueError("signature binding TLV value is truncated")
            fields[tag] = payload[offset:value_end]
            offset = value_end
        if offset != len(payload):
            raise ValueError("signature binding contains trailing bytes")

        route_value = _decode_single_byte(fields[1], "route_id")
        algorithm_value = _decode_single_byte(fields[2], "algorithm_id")
        profile_value = _decode_single_byte(fields[4], "profile_id")
        digest_value = _decode_single_byte(fields[5], "digest_algorithm_id")
        canonicalization_value = _decode_single_byte(fields[6], "canonicalization_id")
        try:
            route_id = SignatureRouteId(route_value)
        except ValueError as exc:
            raise ValueError("unknown signature route_id") from exc
        try:
            algorithm_id = SignatureAlgorithmId(algorithm_value)
        except ValueError as exc:
            raise ValueError("unknown signature algorithm_id") from exc
        try:
            profile_id = SignatureProfileId(profile_value)
        except ValueError as exc:
            raise ValueError("unknown signature profile_id") from exc
        try:
            digest_algorithm_id = EnvelopeDigestAlgorithmId(digest_value)
        except ValueError as exc:
            raise ValueError("unknown envelope digest_algorithm_id") from exc
        try:
            canonicalization_id = EnvelopeCanonicalizationId(canonicalization_value)
        except ValueError as exc:
            raise ValueError("unknown envelope canonicalization_id") from exc

        return cls(
            route_id=route_id,
            algorithm_id=algorithm_id,
            key_id=fields[3],
            profile_id=profile_id,
            digest_algorithm_id=digest_algorithm_id,
            canonicalization_id=canonicalization_id,
            envelope_digest=fields[7],
        )

    def _validate_route_profile(self) -> None:
        """限制路线、算法和 profile 组合，防止标准路线降级到 toy relation。"""
        if self.route_id is SignatureRouteId.ROUTE_A_NEURAL:
            if self.algorithm_id is not SignatureAlgorithmId.TOY_LWE_RESEARCH:
                raise ValueError("route A V1 requires the toy LWE research algorithm")
            if self.profile_id is not SignatureProfileId.TOY_DIRECT:
                raise ValueError("route A V1 requires the toy direct profile")
            return
        if self.algorithm_id not in _ML_DSA_ALGORITHMS:
            raise ValueError("route B V1 requires an ML-DSA algorithm")
        if self.profile_id not in _ML_DSA_PROFILES:
            raise ValueError("route B V1 requires a pure or HashML-DSA profile")


def _decode_single_byte(value: bytes, field_name: str) -> int:
    """解码固定单字节枚举字段，拒绝零长或过长编码。"""
    if len(value) != 1:
        raise ValueError(f"{field_name} must be encoded as exactly one byte")
    return value[0]
