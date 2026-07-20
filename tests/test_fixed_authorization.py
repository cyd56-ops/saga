"""Tests for Route B B2 raw authorization relations and fixed circuit."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import random
from typing import cast
import unittest

from neural import (
    GENERAL_AUTHORIZATION_CIRCUIT_PROFILE_V1,
    MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1,
    MEMORY_AUTHORIZATION_LAYOUT_ID_V1,
    MEMORY_AUTHORIZATION_MAX_TTL_SECONDS_V1,
    RAW_AUTHORIZATION_LAYOUT_ID_V1,
    RAW_AUTHORIZATION_LAYOUT_VERSION_V1,
    RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1,
    FixedAuthorizationCircuitV1,
    ReferenceAuthorizationRelationsV1,
    RouteBAuthorizationPolicyCompilerV1,
    RouteBRawAuthorizationInputV1,
    assert_fixed_circuit,
    find_trainable_state,
)


_TOOL_SCOPE_BITS = b"\x00\x00\x00\x01\x00\x00"
_ZERO_SCOPE_BITS = bytes(6)
_PUBLIC_FLOW_BITS = b"\x01\x00\x00\x00\x00\x00\x00"
_ZERO_DIGEST = bytes(32)


def _digests(prefix: str) -> tuple[bytes, ...]:
    """生成六个确定性 SHA-256 测试摘要。"""
    return tuple(
        hashlib.sha256(f"{prefix}:{index}".encode("ascii")).digest()
        for index in range(6)
    )


def _valid_raw_input() -> RouteBRawAuthorizationInputV1:
    """构造所有 B2 原始关系均成立的 root capability 输入。"""
    bound_digests = _digests("valid")
    return RouteBRawAuthorizationInputV1(
        layout_id=RAW_AUTHORIZATION_LAYOUT_ID_V1,
        layout_version=RAW_AUTHORIZATION_LAYOUT_VERSION_V1,
        standard_signature_valid=True,
        requested_scope_bits=_TOOL_SCOPE_BITS,
        authorized_scope_bits=_TOOL_SCOPE_BITS,
        flow_label_bits=_PUBLIC_FLOW_BITS,
        allowed_flow_label_bits=_PUBLIC_FLOW_BITS,
        parent_allowed_flow_label_bits=bytes(7),
        parent_present=False,
        delegation_depth=0,
        parent_delegation_depth=0,
        max_delegation_depth=8,
        parent_max_delegation_depth=0,
        signed_parent_digest=_ZERO_DIGEST,
        observed_parent_digest=_ZERO_DIGEST,
        parent_scope_bits=_ZERO_SCOPE_BITS,
        issued_at_epoch=100,
        observed_at_epoch=150,
        expires_at_epoch=200,
        parent_issued_at_epoch=0,
        parent_expires_at_epoch=0,
        max_ttl_seconds=RAW_AUTHORIZATION_MAX_TTL_SECONDS_V1,
        bound_digests=bound_digests,
        observed_digests=bound_digests,
    )


def _valid_memory_raw_input() -> RouteBRawAuthorizationInputV1:
    """构造 memory profile 下全部关系均成立的 root capability 输入。"""
    return replace(
        _valid_raw_input(),
        layout_id=MEMORY_AUTHORIZATION_LAYOUT_ID_V1,
        requested_scope_bits=b"\x00\x00\x01\x00\x00\x00",
        authorized_scope_bits=b"\x00\x01\x01\x00\x00\x00",
        max_delegation_depth=2,
        max_ttl_seconds=MEMORY_AUTHORIZATION_MAX_TTL_SECONDS_V1,
    )


class FixedAuthorizationCircuitTests(unittest.TestCase):
    """验证 B2 固定关系、电路硬输出、差分等价与无训练状态。"""

    def setUp(self) -> None:
        """构造无状态 reference oracle 和固定 Linear/ReLU 电路。"""
        self.reference = ReferenceAuthorizationRelationsV1()
        self.circuit = FixedAuthorizationCircuitV1()

    def test_valid_root_input_is_accepted_with_exact_hard_output(self) -> None:
        """完整 root 关系应由 reference/fixed 同时接受并输出精确整数 1。"""
        raw_input = _valid_raw_input()

        reference = self.reference.evaluate(raw_input)
        fixed = self.circuit.evaluate(raw_input)

        self.assertTrue(reference.accepted)
        self.assertTrue(fixed.accepted)
        self.assertIs(type(fixed.output), int)
        self.assertEqual(fixed.output, 1)
        self.assertEqual(fixed.trace.accept_output, 1)
        self.assertEqual(
            fixed.complexity.as_dict(),
            {
                "circuit_profile_id": "saga-route-b-fixed-authorization-relations",
                "circuit_profile_version": 1,
                "input_count": 499,
                "input_bytes": 517,
                "predicate_count": 6,
                "fixed_linear_layers": fixed.complexity.fixed_linear_layers,
                "fixed_relu_layers": fixed.complexity.fixed_relu_layers,
                "fixed_parameter_count": fixed.complexity.fixed_parameter_count,
                "circuit_depth": 8,
            },
        )
        self.assertGreater(fixed.complexity.fixed_linear_layers, 0)
        self.assertGreater(fixed.complexity.fixed_relu_layers, 0)
        self.assertGreater(fixed.complexity.fixed_parameter_count, 0)

    def test_each_raw_relation_has_a_stable_fail_closed_reason(self) -> None:
        """签名、scope、flow、delegation、time 与 digest 可独立触发稳定拒绝。"""
        valid = _valid_raw_input()
        mismatched_digests = list(valid.observed_digests)
        mismatched_digests[-1] = b"X" * 32
        cases = (
            (
                "signature",
                replace(valid, standard_signature_valid=False),
                "standard_signature_invalid",
            ),
            (
                "scope",
                replace(
                    valid,
                    requested_scope_bits=b"\x00\x01\x00\x00\x00\x00",
                ),
                "scope_not_authorized",
            ),
            (
                "flow",
                replace(
                    valid,
                    flow_label_bits=b"\x00\x00\x01\x00\x00\x00\x00",
                ),
                "flow_policy_denied",
            ),
            (
                "delegation",
                replace(valid, parent_present=True),
                "delegation_policy_denied",
            ),
            (
                "time",
                replace(valid, observed_at_epoch=201),
                "time_window_invalid",
            ),
            (
                "digest",
                replace(valid, observed_digests=tuple(mismatched_digests)),
                "request_envelope_mismatch",
            ),
        )

        for label, raw_input, expected_reason in cases:
            with self.subTest(case=label):
                reference = self.reference.evaluate(raw_input)
                fixed = self.circuit.evaluate(raw_input)
                self.assertFalse(reference.accepted)
                self.assertFalse(fixed.accepted)
                self.assertEqual(reference.reason, expected_reason)
                self.assertEqual(fixed.reason, expected_reason)
                self.assertEqual(fixed.output, 0)

    def test_delegated_relation_binds_parent_digest_depth_and_scope_subset(self) -> None:
        """合法单步衰减通过，父摘要、深度或父 scope 不匹配均拒绝。"""
        parent_digest = hashlib.sha256(b"parent").digest()
        delegated = replace(
            _valid_raw_input(),
            parent_present=True,
            delegation_depth=2,
            parent_delegation_depth=1,
            parent_max_delegation_depth=8,
            signed_parent_digest=parent_digest,
            observed_parent_digest=parent_digest,
            parent_scope_bits=_TOOL_SCOPE_BITS,
            parent_allowed_flow_label_bits=_PUBLIC_FLOW_BITS,
            parent_issued_at_epoch=50,
            parent_expires_at_epoch=300,
        )
        self.assertTrue(self.circuit.evaluate(delegated).accepted)

        invalid_inputs = (
            replace(delegated, observed_parent_digest=b"P" * 32),
            replace(delegated, delegation_depth=3),
            replace(delegated, max_delegation_depth=1),
            replace(delegated, max_delegation_depth=9),
            replace(delegated, parent_scope_bits=_ZERO_SCOPE_BITS),
            replace(delegated, parent_allowed_flow_label_bits=bytes(7)),
            replace(delegated, parent_issued_at_epoch=101),
            replace(delegated, parent_expires_at_epoch=199),
        )
        for raw_input in invalid_inputs:
            with self.subTest(raw_input_digest=raw_input.digest().hex()):
                decision = self.circuit.evaluate(raw_input)
                self.assertFalse(decision.accepted)
                self.assertEqual(decision.reason, "delegation_policy_denied")

    def test_ttl_profile_boundary_is_closed_and_not_caller_extensible(self) -> None:
        """900 秒边界可接受，超过边界的 expiry 或可变 profile 上限均拒绝。"""
        boundary = replace(
            _valid_raw_input(),
            observed_at_epoch=1000,
            expires_at_epoch=1000,
            issued_at_epoch=100,
        )
        self.assertTrue(self.circuit.evaluate(boundary).accepted)
        too_late = replace(boundary, expires_at_epoch=1001, observed_at_epoch=1001)
        self.assertEqual(
            self.circuit.evaluate(too_late).reason,
            "time_window_invalid",
        )
        with self.assertRaises(ValueError):
            replace(boundary, max_ttl_seconds=901)

    def test_seeded_raw_relation_differential_matches_reference(self) -> None:
        """固定种子 256 个原始关系输入必须与普通 reference 判定完全等价。"""
        rng = random.Random(20260720)
        for case_index in range(256):
            bound = tuple(rng.randbytes(32) for _ in range(6))
            observed = tuple(
                digest if rng.randrange(2) else rng.randbytes(32)
                for digest in bound
            )
            raw_input = replace(
                _valid_raw_input(),
                standard_signature_valid=bool(rng.randrange(2)),
                requested_scope_bits=bytes(rng.randrange(2) for _ in range(6)),
                authorized_scope_bits=bytes(rng.randrange(2) for _ in range(6)),
                flow_label_bits=bytes(rng.randrange(2) for _ in range(7)),
                allowed_flow_label_bits=bytes(rng.randrange(2) for _ in range(7)),
                parent_allowed_flow_label_bits=bytes(
                    rng.randrange(2) for _ in range(7)
                ),
                parent_present=bool(rng.randrange(2)),
                delegation_depth=rng.randrange(5),
                parent_delegation_depth=rng.randrange(5),
                max_delegation_depth=rng.randrange(5),
                parent_max_delegation_depth=rng.randrange(5),
                signed_parent_digest=rng.randbytes(32),
                observed_parent_digest=rng.randbytes(32),
                parent_scope_bits=bytes(rng.randrange(2) for _ in range(6)),
                issued_at_epoch=rng.randrange(1000),
                observed_at_epoch=rng.randrange(1000),
                expires_at_epoch=rng.randrange(1000),
                parent_issued_at_epoch=rng.randrange(1000),
                parent_expires_at_epoch=rng.randrange(1000),
                bound_digests=bound,
                observed_digests=observed,
            )
            reference = self.reference.evaluate(raw_input)
            fixed = self.circuit.evaluate(raw_input)
            with self.subTest(case=case_index):
                self.assertEqual(fixed.accepted, reference.accepted)
                self.assertEqual(fixed.output, reference.output)
                self.assertEqual(
                    tuple(item.output for item in fixed.trace.predicates),
                    tuple(item.output for item in reference.predicates),
                )
                if not reference.accepted:
                    self.assertEqual(fixed.reason, reference.reason)

    def test_layout_rejects_real_valued_nonbinary_and_version_drift(self) -> None:
        """浮点、bool 整数、非二值字节、错误宽度和版本漂移不能进入电路。"""
        valid = _valid_raw_input()
        invalid_changes = (
            {"standard_signature_valid": cast(bool, 1)},
            {"requested_scope_bits": b"\x02" + bytes(5)},
            {"authorized_scope_bits": bytes(5)},
            {"delegation_depth": cast(int, 1.0)},
            {"delegation_depth": cast(int, True)},
            {"issued_at_epoch": -1},
            {"signed_parent_digest": cast(bytes, bytearray(32))},
            {"bound_digests": cast(tuple[bytes, ...], list(valid.bound_digests))},
            {"layout_id": "future-layout"},
            {"layout_version": 2},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaises((TypeError, ValueError)):
                    replace(valid, **changes)

        invalid = self.circuit.evaluate(cast(RouteBRawAuthorizationInputV1, object()))
        self.assertFalse(invalid.accepted)
        self.assertEqual(invalid.reason, "raw_authorization_input_invalid")

    def test_fixed_circuit_has_no_trainable_state_and_trace_redacts_raw_values(self) -> None:
        """全部固定权重不可训练，trace 只包含输入摘要和关系输出。"""
        assert_fixed_circuit(self.circuit)
        self.assertEqual(find_trainable_state(self.circuit), ())
        payload = str(self.circuit.evaluate(_valid_raw_input()).trace.as_dict())
        self.assertNotIn(_digests("valid")[0].hex(), payload)
        self.assertNotIn("sender", payload)
        self.assertNotIn("token", payload)


class RouteBAuthorizationPolicyCompilerTests(unittest.TestCase):
    """验证 B3 单一 compiler 对 general/memory profile 的真实复用与隔离。"""

    def setUp(self) -> None:
        """编译两个注册 profile，供 BG7 结构与策略差异测试。"""
        self.compiler = RouteBAuthorizationPolicyCompilerV1()
        self.general, self.memory = self.compiler.compile_registered_profiles()

    def test_two_profiles_share_ir_schema_circuit_and_gadget_classes(self) -> None:
        """两个 profile 必须复用主体而保持独立版本身份和 policy 常量。"""
        self.assertEqual(type(self.general.reference), type(self.memory.reference))
        self.assertEqual(type(self.general.circuit), type(self.memory.circuit))
        self.assertEqual(self.general.predicate_ir, self.memory.predicate_ir)
        self.assertEqual(
            self.general.predicate_ir.digest(),
            self.memory.predicate_ir.digest(),
        )
        self.assertEqual(self.general.gadget_classes(), self.memory.gadget_classes())
        self.assertNotEqual(self.general.profile_digest, self.memory.profile_digest)
        self.assertNotEqual(
            self.general.profile.layout_id,
            self.memory.profile.layout_id,
        )
        self.assertEqual(
            self.memory.profile.permitted_scope_families,
            ("memory_read", "memory_write"),
        )
        self.assertEqual(self.memory.profile.max_ttl_seconds, 300)
        self.assertEqual(self.memory.profile.max_delegation_depth, 2)

    def test_memory_profile_accepts_memory_input_with_exact_fixed_output(self) -> None:
        """memory scope、窄 flow、300 秒 TTL 与 depth 上限满足时 reference/fixed 接受。"""
        raw_input = _valid_memory_raw_input()
        reference = self.memory.reference.evaluate(raw_input)
        fixed = self.memory.circuit.evaluate(raw_input)

        self.assertTrue(reference.accepted)
        self.assertTrue(fixed.accepted)
        self.assertIs(type(fixed.output), int)
        self.assertEqual(fixed.output, 1)
        self.assertEqual(
            fixed.complexity.circuit_profile_id,
            MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1.circuit_profile_id,
        )

    def test_memory_profile_directly_rejects_scope_flow_and_depth_expansion(self) -> None:
        """memory profile 的固定 mask 和 depth 常量不能由 signed input 扩大。"""
        valid = _valid_memory_raw_input()
        cases = (
            (
                replace(
                    valid,
                    requested_scope_bits=_TOOL_SCOPE_BITS,
                    authorized_scope_bits=_TOOL_SCOPE_BITS,
                ),
                "scope_not_authorized",
            ),
            (
                replace(
                    valid,
                    allowed_flow_label_bits=(
                        b"\x01\x00\x00\x00\x01\x00\x00"
                    ),
                ),
                "flow_policy_denied",
            ),
            (
                replace(valid, max_delegation_depth=3),
                "delegation_policy_denied",
            ),
        )
        for raw_input, reason in cases:
            with self.subTest(reason=reason):
                reference = self.memory.reference.evaluate(raw_input)
                fixed = self.memory.circuit.evaluate(raw_input)
                self.assertFalse(reference.accepted)
                self.assertFalse(fixed.accepted)
                self.assertEqual(reference.reason, reason)
                self.assertEqual(fixed.reason, reason)

    def test_profile_layout_ttl_and_registration_drift_fail_closed(self) -> None:
        """跨 profile 输入、TTL 漂移和未注册 profile 不能进入已编译电路。"""
        memory_input = _valid_memory_raw_input()
        cross_profile = self.general.circuit.evaluate(memory_input)
        self.assertFalse(cross_profile.accepted)
        self.assertEqual(cross_profile.reason, "raw_authorization_input_invalid")

        with self.assertRaises(ValueError):
            replace(memory_input, max_ttl_seconds=301)
        future = replace(
            MEMORY_AUTHORIZATION_CIRCUIT_PROFILE_V1,
            policy_profile_id="saga-route-b-future-memory-policy",
        )
        with self.assertRaises(ValueError):
            self.compiler.compile(future)
        with self.assertRaises(ValueError):
            replace(future, permitted_scope_families=("memory_write", "memory_read"))

    def test_all_compiled_profiles_have_no_trainable_state(self) -> None:
        """PolicyCompiler 生成的每个 fixed circuit 都必须保持 requires_grad=False。"""
        for compiled in (self.general, self.memory):
            with self.subTest(profile=compiled.profile.policy_profile_id):
                assert_fixed_circuit(compiled.circuit)
                self.assertEqual(find_trainable_state(compiled.circuit), ())
                self.assertEqual(
                    compiled.as_dict()["layout_schema"],
                    "RouteBRawAuthorizationInputV1",
                )
        self.assertEqual(
            self.general.profile,
            GENERAL_AUTHORIZATION_CIRCUIT_PROFILE_V1,
        )


if __name__ == "__main__":
    unittest.main()
