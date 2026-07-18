"""Tests for the reusable Route A A0.5 fixed-circuit toolchain."""

from __future__ import annotations

from dataclasses import replace
from itertools import product
import math
from typing import cast
import unittest

from neural import (
    FIXED_PROJECTOR_CORE_ID,
    MAX_EXACT_FLOAT_INTEGER,
    MAX_FIXED_MODULO_THRESHOLDS,
    MASK,
    BinaryInputGuard,
    DenseFixedProjector,
    FixedBoundedModulo,
    FixedBooleanAggregator,
    FixedEquality,
    FixedModReduce,
    FixedProjector,
    FixedRangeNormCheck,
    TinyNegacyclicProjector,
    UnitIntervalInputGuard,
    assert_fixed_circuit,
)


def _dense_reference(
    matrix: tuple[tuple[int, ...], ...],
    values: tuple[int, ...],
) -> tuple[int, ...]:
    """用普通整数算术计算 dense projector reference。"""
    return tuple(
        sum(
            coefficient * value
            for coefficient, value in zip(row, values, strict=True)
        )
        for row in matrix
    )


def _negacyclic_reference(
    multiplier: tuple[int, ...],
    values: tuple[int, ...],
) -> tuple[int, ...]:
    """直接按 ``x^n = -1`` 计算 tiny negacyclic reference。"""
    width = len(multiplier)
    output = [0 for _ in range(width)]
    for left_index, coefficient in enumerate(multiplier):
        for right_index, value in enumerate(values):
            degree = left_index + right_index
            if degree < width:
                output[degree] += coefficient * value
            else:
                output[degree - width] -= coefficient * value
    return tuple(output)


class FixedToolchainGadgetTests(unittest.TestCase):
    """穷举 A0.5 gadget 的小型有界定义域与输入边界。"""

    def test_binary_guard_accepts_exact_domain_and_rejects_software_hazards(
        self,
    ) -> None:
        """二进制 guard 接受精确 0/1，并拒绝 bool、实数中间值和非有限数。"""
        guard = BinaryInputGuard()
        self.assertEqual(guard((0, 1, 0.0, 1.0)), (0, 1, 0, 1))
        for invalid in (True, False, -1, 2, 0.5, math.nan, math.inf, -math.inf):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    guard((cast(int | float, invalid),))
        self.assertIn(
            "strict_binary_domain_validation",
            guard.boundary().software_guard_steps,
        )

    def test_mod_reduce_matches_integer_reference_exhaustively(self) -> None:
        """模约简在声明的小型整数域内与 reference 全部一致。"""
        gadget = FixedModReduce(7, max_input_abs=20)
        for value in range(-20, 21):
            self.assertEqual(gadget(value), value % 7)
        self.assertIn(
            "python_integer_modulo_a0_5",
            gadget.boundary().deterministic_hard_gate_steps,
        )
        with self.assertRaises(TypeError):
            gadget(cast(int, 1.0))
        with self.assertRaises(ValueError):
            gadget(21)

    def test_fixed_bounded_modulo_matches_signed_domain_exhaustively(self) -> None:
        """A1 ReLU modulo 在含负数的完整编译域内与整数 reference 一致。"""
        gadget = FixedBoundedModulo(7, min_input=-20, max_input=20)
        for value in range(-20, 21):
            self.assertEqual(gadget(value), value % 7)
        self.assertEqual(gadget.boundary().deterministic_hard_gate_steps, ())
        self.assertGreater(gadget.complexity().threshold_count, 0)
        with self.assertRaises(TypeError):
            gadget(cast(int, 1.0))
        with self.assertRaises(ValueError):
            gadget(21)
        assert_fixed_circuit(gadget)
        with self.assertRaises(ValueError):
            FixedBoundedModulo(
                2,
                min_input=0,
                max_input=2 * (MAX_FIXED_MODULO_THRESHOLDS + 1),
            )

    def test_unit_interval_guard_accepts_mask_domain_and_rejects_hazards(
        self,
    ) -> None:
        """Shamir 软件 guard 接受有限 [0,1] 实数并拒绝特殊值与区间外值。"""
        guard = UnitIntervalInputGuard()
        self.assertEqual(guard((0, 0.25, 1.0)), (0.0, 0.25, 1.0))
        for invalid in (True, -0.01, 1.01, math.nan, math.inf, -math.inf):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    guard((cast(int | float, invalid),))

    def test_fixed_equality_matches_reference_exhaustively(self) -> None:
        """固定 ReLU 等值 gadget 在有界整数笛卡尔积上精确输出 0/1。"""
        gadget = FixedEquality(max_abs=4)
        for left, right in product(range(-4, 5), repeat=2):
            self.assertEqual(gadget(left, right), int(left == right))
        with self.assertRaises(TypeError):
            gadget(cast(int, True), 1)
        with self.assertRaises(ValueError):
            gadget(5, 1)
        assert_fixed_circuit(gadget)

    def test_boolean_aggregator_matches_and_exhaustively(self) -> None:
        """固定聚合器在四比特空间中仅接受全一向量。"""
        gadget = FixedBooleanAggregator(4)
        for bits in product((0, 1), repeat=4):
            self.assertEqual(gadget(bits), int(all(bits)))
        self.assertEqual(gadget((1.0, 1, 1, 1)), 1)
        with self.assertRaises(ValueError):
            gadget((1, 1, 1))
        with self.assertRaises(ValueError):
            gadget((1, 1, 0.5, 1))
        assert_fixed_circuit(gadget)

    def test_range_norm_matches_reference_exhaustively(self) -> None:
        """范围/范数 gadget 在二维小域内同时匹配坐标界和 L1 reference。"""
        gadget = FixedRangeNormCheck(
            2,
            input_max_abs=3,
            coordinate_bound=2,
            l1_bound=3,
        )
        for values in product(range(-3, 4), repeat=2):
            expected = int(
                all(abs(value) <= 2 for value in values)
                and sum(abs(value) for value in values) <= 3
            )
            self.assertEqual(gadget(values), expected)
        trace = gadget.trace((-2, 1))
        self.assertEqual(trace.absolute_values, (2, 1))
        self.assertEqual(trace.coordinate_bits, (1, 1))
        self.assertEqual(trace.l1_norm, 3)
        self.assertEqual(trace.accept, 1)
        assert_fixed_circuit(gadget)

    def test_required_gadget_deletion_witnesses_change_results(self) -> None:
        """mod/equality/range/norm/MASK/aggregation 均有能检测删除 mutation 的 witness。"""
        mod_output = FixedModReduce(7, max_input_abs=8)(8)
        self.assertNotEqual(mod_output, 8)
        self.assertEqual(FixedEquality(max_abs=2)(1, 2), 0)

        range_check = FixedRangeNormCheck(
            2,
            input_max_abs=4,
            coordinate_bound=2,
            l1_bound=8,
        )
        self.assertEqual(range_check((3, 0)), 0)
        norm_check = FixedRangeNormCheck(
            2,
            input_max_abs=4,
            coordinate_bound=4,
            l1_bound=3,
        )
        self.assertEqual(norm_check((2, 2)), 0)
        self.assertNotEqual(MASK()((0.5,)), 0.0)
        self.assertEqual(FixedBooleanAggregator(3)((1, 0, 1)), 0)


class FixedToolchainProjectorTests(unittest.TestCase):
    """验证 dense/ring backend 共用 core、trace、界限和 manifest 接口。"""

    def test_dense_projector_matches_reference_exhaustively(self) -> None:
        """Dense backend 在有界输入空间内与普通矩阵乘法一致。"""
        matrix = ((2, -1, 0), (1, 3, -2))
        projector = DenseFixedProjector(matrix, max_input_abs=2)
        for values in product(range(-2, 3), repeat=3):
            self.assertEqual(
                projector.project(values),
                _dense_reference(matrix, values),
            )
        assert_fixed_circuit(projector)

    def test_tiny_negacyclic_projector_matches_reference_exhaustively(self) -> None:
        """Tiny ring backend 在全量三值输入上正确处理 ``x^n = -1`` 回绕。"""
        multiplier = (1, -2, 0, 1)
        projector = TinyNegacyclicProjector(multiplier, max_input_abs=1)
        for values in product((-1, 0, 1), repeat=4):
            self.assertEqual(
                projector.project(values),
                _negacyclic_reference(multiplier, values),
            )
        self.assertEqual(
            projector.project((0, 0, 0, 1)),
            (2, 0, -1, 1),
        )
        assert_fixed_circuit(projector)

    def test_projectors_share_protocol_core_and_manifest_shape(self) -> None:
        """两个 backend 使用同一 protocol/core，并输出包含 AG8 字段的 manifest。"""
        dense = DenseFixedProjector(((1, 2), (-1, 3)), max_input_abs=2)
        ring = TinyNegacyclicProjector((1, 2), max_input_abs=2)
        for projector in (dense, ring):
            self.assertIsInstance(projector, FixedProjector)
            self.assertEqual(projector.core.core_id, FIXED_PROJECTOR_CORE_ID)
            self.assertEqual(
                projector.boundary().core_id,
                FIXED_PROJECTOR_CORE_ID,
            )
            trace = projector.trace((1, -1))
            self.assertEqual(trace.core_id, FIXED_PROJECTOR_CORE_ID)
            complexity = projector.complexity()
            self.assertLess(
                complexity.max_output_abs,
                MAX_EXACT_FLOAT_INTEGER,
            )
            manifest = projector.manifest(
                reference_equivalence_cases=9,
                reference_mismatches=0,
                latency_seconds=0.001,
                peak_memory_bytes=1024,
            )
            payload = manifest.as_dict()
            self.assertEqual(payload["stage"], "A0.5-preliminary")
            self.assertFalse(payload["production_ready"])
            self.assertIn("boundary", payload)
            self.assertIn("complexity", payload)
            with self.assertRaises(ValueError):
                replace(manifest, production_ready=cast(bool, True))

    def test_projector_rejects_invalid_shape_type_range_and_unsafe_bound(self) -> None:
        """Projector 对形状、bool、输入越界和浮点精度风险 fail-closed。"""
        with self.assertRaises(ValueError):
            DenseFixedProjector(((1, 2), (3,)), max_input_abs=2)
        with self.assertRaises(TypeError):
            DenseFixedProjector(
                ((cast(int, True),),),
                max_input_abs=2,
            )
        projector = DenseFixedProjector(((1, 2),), max_input_abs=2)
        with self.assertRaises(TypeError):
            projector.project((cast(int, 1.0), 1))
        with self.assertRaises(ValueError):
            projector.project((3, 1))
        with self.assertRaises(ValueError):
            DenseFixedProjector(
                ((MAX_EXACT_FLOAT_INTEGER, 1),),
                max_input_abs=2,
            )


if __name__ == "__main__":
    unittest.main()
