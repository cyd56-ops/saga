"""Tests for the versioned dual-route signature binding."""

from __future__ import annotations

import unittest

from pq import (
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
)
from pq.signature_binding import (
    MAX_KEY_ID_BYTES,
    MAX_SIGNATURE_BINDING_BYTES,
    SIGNATURE_BINDING_MAGIC,
)


def _route_b_binding(
    *,
    profile_id: SignatureProfileId = SignatureProfileId.ML_DSA_PURE,
    key_id: bytes = b"receiver-key-01",
) -> SignatureBindingV1:
    """构造固定 route B binding，供 canonical 与负向解析测试复用。"""
    return SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_65,
        key_id=key_id,
        profile_id=profile_id,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1,
        envelope_digest=bytes(range(32)),
    )


def _replace_tlv_tag(payload: bytes, field_index: int, new_tag: int) -> bytes:
    """替换指定 TLV tag，不改变其余编码，用于重复/未知/乱序负向样本。"""
    mutated = bytearray(payload)
    offset = 10
    for current_index in range(7):
        if current_index == field_index:
            mutated[offset] = new_tag
            return bytes(mutated)
        value_length = int.from_bytes(mutated[offset + 1 : offset + 3], "big")
        offset += 3 + value_length
    raise AssertionError("field_index is outside the V1 field set")


def _replace_tlv_value(payload: bytes, field_index: int, replacement: bytes) -> bytes:
    """等长替换指定 TLV value，便于构造未知枚举值测试。"""
    mutated = bytearray(payload)
    offset = 10
    for current_index in range(7):
        value_length = int.from_bytes(mutated[offset + 1 : offset + 3], "big")
        value_start = offset + 3
        if current_index == field_index:
            if len(replacement) != value_length:
                raise AssertionError("replacement must preserve TLV length")
            mutated[value_start : value_start + value_length] = replacement
            return bytes(mutated)
        offset = value_start + value_length
    raise AssertionError("field_index is outside the V1 field set")


def _resize_tlv_value(payload: bytes, field_index: int, replacement: bytes) -> bytes:
    """改变指定 TLV 的 value 和长度，用于非规范宽度与边界长度测试。"""
    offset = 10
    for current_index in range(7):
        value_length = int.from_bytes(payload[offset + 1 : offset + 3], "big")
        value_start = offset + 3
        value_end = value_start + value_length
        if current_index == field_index:
            return (
                payload[: offset + 1]
                + len(replacement).to_bytes(2, "big")
                + replacement
                + payload[value_end:]
            )
        offset = value_end
    raise AssertionError("field_index is outside the V1 field set")


class SignatureBindingV1Tests(unittest.TestCase):
    """验证 V1 编码稳定性、profile 语义和 fail-closed 解析规则。"""

    def test_route_b_binding_round_trips_canonical_bytes(self) -> None:
        """规范 V1 bytes 必须解析回完全相同的 binding。"""
        binding = _route_b_binding()

        encoded = binding.canonical_bytes()

        self.assertEqual(SignatureBindingV1.from_bytes(encoded), binding)
        self.assertEqual(SignatureBindingV1.from_bytes(encoded).canonical_bytes(), encoded)

    def test_canonical_encoding_has_stable_golden_bytes(self) -> None:
        """Golden bytes 固定字段顺序、长度前缀和整数编码。"""
        encoded = _route_b_binding().canonical_bytes()

        self.assertTrue(encoded.startswith(SIGNATURE_BINDING_MAGIC))
        self.assertEqual(
            encoded.hex(),
            "534147412d5349470107010001020200014103000f72656365697665722d6b6579"
            "2d3031040001020500010106000101070020000102030405060708090a0b0c0d0e"
            "0f101112131415161718191a1b1c1d1e1f",
        )

    def test_all_standard_mldsa_profiles_are_distinct_and_valid(self) -> None:
        """Pure 与每个 HashML-DSA prehash profile 必须得到不同 canonical bytes。"""
        profiles = (
            SignatureProfileId.ML_DSA_PURE,
            SignatureProfileId.HASH_ML_DSA_SHA256,
            SignatureProfileId.HASH_ML_DSA_SHA512,
            SignatureProfileId.HASH_ML_DSA_SHAKE128,
            SignatureProfileId.HASH_ML_DSA_SHAKE256,
        )

        encodings = {_route_b_binding(profile_id=profile).canonical_bytes() for profile in profiles}

        self.assertEqual(len(encodings), len(profiles))

    def test_mldsa_context_is_fixed_and_within_standard_limit(self) -> None:
        """R6 backend shim 必须使用 V1 固定且不超过 255 字节的 application context。"""
        self.assertEqual(ML_DSA_CONTEXT_V1, b"SAGA-PQ-CAN-SignatureBindingV1")
        self.assertLessEqual(len(ML_DSA_CONTEXT_V1), 255)

    def test_maximum_key_id_round_trips_at_exact_wire_limit(self) -> None:
        """64 字节 key ID 必须恰好落在 V1 总编码上限内。"""
        binding = _route_b_binding(key_id=b"k" * MAX_KEY_ID_BYTES)

        encoded = binding.canonical_bytes()

        self.assertEqual(len(encoded), MAX_SIGNATURE_BINDING_BYTES)
        self.assertEqual(SignatureBindingV1.from_bytes(encoded), binding)

    def test_route_a_accepts_only_toy_research_profile(self) -> None:
        """Route A V1 只能绑定明确标注 research-only 的 toy relation。"""
        binding = SignatureBindingV1(
            route_id=SignatureRouteId.ROUTE_A_NEURAL,
            algorithm_id=SignatureAlgorithmId.TOY_LWE_RESEARCH,
            key_id=b"toy-key",
            profile_id=SignatureProfileId.TOY_DIRECT,
            digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
            canonicalization_id=EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1,
            envelope_digest=b"d" * 32,
        )

        self.assertEqual(SignatureBindingV1.from_bytes(binding.canonical_bytes()), binding)

        with self.assertRaisesRegex(ValueError, "route A V1 requires"):
            SignatureBindingV1(
                route_id=SignatureRouteId.ROUTE_A_NEURAL,
                algorithm_id=SignatureAlgorithmId.ML_DSA_65,
                key_id=b"wrong-route-key",
                profile_id=SignatureProfileId.ML_DSA_PURE,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"d" * 32,
            )

        with self.assertRaisesRegex(ValueError, "toy direct profile"):
            SignatureBindingV1(
                route_id=SignatureRouteId.ROUTE_A_NEURAL,
                algorithm_id=SignatureAlgorithmId.TOY_LWE_RESEARCH,
                key_id=b"wrong-profile-key",
                profile_id=SignatureProfileId.ML_DSA_PURE,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"d" * 32,
            )

    def test_route_b_rejects_toy_algorithm_and_profile(self) -> None:
        """标准执行路线不能降级到 toy algorithm 或 toy profile。"""
        with self.assertRaisesRegex(ValueError, "route B V1 requires an ML-DSA"):
            SignatureBindingV1(
                route_id=SignatureRouteId.ROUTE_B_STANDARD,
                algorithm_id=SignatureAlgorithmId.TOY_LWE_RESEARCH,
                key_id=b"key",
                profile_id=SignatureProfileId.TOY_DIRECT,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"d" * 32,
            )

        with self.assertRaisesRegex(ValueError, "pure or HashML-DSA profile"):
            SignatureBindingV1(
                route_id=SignatureRouteId.ROUTE_B_STANDARD,
                algorithm_id=SignatureAlgorithmId.ML_DSA_65,
                key_id=b"key",
                profile_id=SignatureProfileId.TOY_DIRECT,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"d" * 32,
            )

    def test_binding_rejects_invalid_key_and_digest_lengths(self) -> None:
        """空/超长 key ID 与非 32 字节 SHA-256 digest 必须在编码前拒绝。"""
        for key_id in (b"", b"k" * (MAX_KEY_ID_BYTES + 1)):
            with self.subTest(key_length=len(key_id)):
                with self.assertRaises(ValueError):
                    SignatureBindingV1(
                        route_id=SignatureRouteId.ROUTE_B_STANDARD,
                        algorithm_id=SignatureAlgorithmId.ML_DSA_65,
                        key_id=key_id,
                        profile_id=SignatureProfileId.ML_DSA_PURE,
                        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                        canonicalization_id=(
                            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                        ),
                        envelope_digest=b"d" * 32,
                    )

        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            SignatureBindingV1(
                route_id=SignatureRouteId.ROUTE_B_STANDARD,
                algorithm_id=SignatureAlgorithmId.ML_DSA_65,
                key_id=b"key",
                profile_id=SignatureProfileId.ML_DSA_PURE,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"short",
            )

    def test_parser_rejects_unknown_duplicate_and_out_of_order_fields(self) -> None:
        """未知 tag、重复 tag 与非规范字段顺序均 fail-closed。"""
        encoded = _route_b_binding().canonical_bytes()
        cases = (
            (_replace_tlv_tag(encoded, 0, 99), "unknown field"),
            (_replace_tlv_tag(encoded, 1, 1), "duplicate field"),
            (_replace_tlv_tag(encoded, 0, 2), "canonical order"),
        )

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_rejects_unknown_route_algorithm_and_profile(self) -> None:
        """未登记 route、algorithm 或 profile ID 不能进入后续 backend 选择。"""
        encoded = _route_b_binding().canonical_bytes()
        cases = (
            (_replace_tlv_value(encoded, 0, b"\xff"), "unknown signature route_id"),
            (_replace_tlv_value(encoded, 1, b"\xff"), "unknown signature algorithm_id"),
            (_replace_tlv_value(encoded, 3, b"\xff"), "unknown signature profile_id"),
        )

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_rejects_unknown_digest_and_canonicalization(self) -> None:
        """未知 digest 或 canonicalization 版本必须在验签前拒绝。"""
        encoded = _route_b_binding().canonical_bytes()
        cases = (
            (_replace_tlv_value(encoded, 4, b"\xff"), "unknown envelope digest"),
            (
                _replace_tlv_value(encoded, 5, b"\xff"),
                "unknown envelope canonicalization",
            ),
        )

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_rejects_noncanonical_enum_width(self) -> None:
        """单字节枚举使用零字节或多字节编码时必须拒绝。"""
        encoded = _route_b_binding().canonical_bytes()
        cases = (
            (_resize_tlv_value(encoded, 0, b""), "exactly one byte"),
            (_resize_tlv_value(encoded, 3, b"\x02\x00"), "exactly one byte"),
        )

        for payload, reason in cases:
            with self.subTest(payload_length=len(payload)):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_rejects_wrong_magic_version_and_field_count(self) -> None:
        """Magic、版本和 mandatory field count 任一不匹配都必须拒绝。"""
        encoded = bytearray(_route_b_binding().canonical_bytes())
        cases: list[tuple[bytes, str]] = []
        wrong_magic = encoded.copy()
        wrong_magic[0] ^= 1
        cases.append((bytes(wrong_magic), "invalid signature binding magic"))
        wrong_version = encoded.copy()
        wrong_version[8] = 2
        cases.append((bytes(wrong_version), "unsupported signature binding version"))
        wrong_count = encoded.copy()
        wrong_count[9] = 6
        cases.append((bytes(wrong_count), "field count must be exactly 7"))

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_rejects_truncated_trailing_and_oversized_payloads(self) -> None:
        """截断、尾随数据和超过 V1 上限的 payload 都不能被宽松解析。"""
        encoded = _route_b_binding().canonical_bytes()
        cases = (
            (encoded[:5], "header is truncated"),
            (encoded[:-1], "TLV value is truncated"),
            (encoded + b"\x00", "trailing bytes"),
            (b"x" * (MAX_SIGNATURE_BINDING_BYTES + 1), "exceeds the V1 maximum"),
        )

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    SignatureBindingV1.from_bytes(payload)

    def test_parser_requires_bytes_and_constructor_requires_enum_types(self) -> None:
        """文本、bytearray 与裸整数不能绕过 typed V1 输入边界。"""
        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            SignatureBindingV1.from_bytes(bytearray(_route_b_binding().canonical_bytes()))  # type: ignore[arg-type]

        with self.assertRaisesRegex(TypeError, "route_id must use"):
            SignatureBindingV1(
                route_id=2,  # type: ignore[arg-type]
                algorithm_id=SignatureAlgorithmId.ML_DSA_65,
                key_id=b"key",
                profile_id=SignatureProfileId.ML_DSA_PURE,
                digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
                canonicalization_id=(
                    EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
                ),
                envelope_digest=b"d" * 32,
            )


if __name__ == "__main__":
    unittest.main()
