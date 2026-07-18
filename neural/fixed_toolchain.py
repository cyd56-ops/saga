"""路线 A A0.5 的可复用固定 gadget、projector 与 manifest 工具链。"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Protocol, Sequence, runtime_checkable

from neural.shamir_layers import FixedLinear, FixedReLU, FixedSum


MAX_EXACT_FLOAT_INTEGER = (1 << 53) - 1
FIXED_PROJECTOR_CORE_ID = "fixed-linear-projector-core-v1"


def _require_builtin_int(value: object, *, name: str, max_abs: int) -> int:
    """校验固定电路整数入口，拒绝 bool、浮点和超出已声明界限的值。"""
    if type(value) is not int:
        raise TypeError(f"{name} must be a built-in integer")
    if abs(value) > max_abs:
        raise ValueError(f"{name} exceeds the declared absolute bound")
    return value


def _require_positive_int(value: object, *, name: str) -> int:
    """校验构造期使用的原生正整数参数。"""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive built-in integer")
    return value


@dataclass(frozen=True)
class GadgetBoundary:
    """声明 A0.5 gadget 的固定层、软件 guard 与普通 hard gate 边界。"""

    fixed_circuit_steps: tuple[str, ...]
    software_guard_steps: tuple[str, ...]
    deterministic_hard_gate_steps: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """导出稳定且可机器读取的 gadget boundary。"""
        return {
            "fixed_circuit_steps": list(self.fixed_circuit_steps),
            "software_guard_steps": list(self.software_guard_steps),
            "deterministic_hard_gate_steps": list(
                self.deterministic_hard_gate_steps
            ),
        }


class BinaryInputGuard:
    """把精确二进制整数或实数规范化为不可训练的硬 0/1 整数。"""

    requires_grad = False

    def __call__(self, values: Sequence[int | float]) -> tuple[int, ...]:
        """接受原生 ``0/1`` 与 ``0.0/1.0``，拒绝 bool、NaN、Inf 和越界值。"""
        normalized: list[int] = []
        for value in values:
            if type(value) not in (int, float):
                raise TypeError("binary input must contain built-in int or float values")
            numeric = float(value)
            if not math.isfinite(numeric):
                raise ValueError("binary input must be finite")
            if numeric not in (0.0, 1.0):
                raise ValueError("binary input must contain only exact zero or one")
            normalized.append(int(numeric))
        return tuple(normalized)

    def boundary(self) -> GadgetBoundary:
        """声明二进制域检查位于固定电路之前的软件输入边界。"""
        return GadgetBoundary(
            fixed_circuit_steps=(),
            software_guard_steps=("strict_binary_domain_validation",),
            deterministic_hard_gate_steps=(),
        )


class FixedModReduce:
    """提供有界整数模约简；A0.5 中仍明确属于普通 Python hard gate。"""

    requires_grad = False

    def __init__(self, modulus: int, *, max_input_abs: int) -> None:
        """固定模数与输入绝对值上界，不接受隐式数值类型。"""
        self.modulus = _require_positive_int(modulus, name="modulus")
        self.max_input_abs = _require_positive_int(
            max_input_abs,
            name="max_input_abs",
        )

    def __call__(self, value: int) -> int:
        """在已声明整数范围内返回 ``value mod modulus``。"""
        integer = _require_builtin_int(
            value,
            name="modular input",
            max_abs=self.max_input_abs,
        )
        return integer % self.modulus

    def boundary(self) -> GadgetBoundary:
        """明确 A0.5 模约简尚未关闭 AG3 的 Python ``%`` 边界。"""
        return GadgetBoundary(
            fixed_circuit_steps=(),
            software_guard_steps=("bounded_builtin_integer_validation",),
            deterministic_hard_gate_steps=("python_integer_modulo_a0_5",),
        )


class FixedEquality:
    """用固定 Linear/ReLU 在有界整数域计算精确等值比特。"""

    requires_grad = False

    def __init__(self, *, max_abs: int) -> None:
        """固定操作数绝对值上界并构造 ``1 - min(1, |x-y|)`` 电路。"""
        self.max_abs = _require_positive_int(max_abs, name="max_abs")
        if 2 * self.max_abs > MAX_EXACT_FLOAT_INTEGER:
            raise ValueError("equality difference exceeds the exact float integer range")
        self.subtract = FixedLinear((1.0, -1.0))
        self.negate = FixedLinear((-1.0,))
        self.relu = FixedReLU()
        self.absolute_sum = FixedLinear((1.0, 1.0))
        self.shift_one = FixedLinear((1.0,), bias=-1.0)
        self.combine = FixedLinear((-1.0, 1.0), bias=1.0)

    def __call__(self, left: int, right: int) -> int:
        """仅当两个已校验整数相等时返回硬整数 ``1``。"""
        left_value = _require_builtin_int(left, name="left", max_abs=self.max_abs)
        right_value = _require_builtin_int(
            right,
            name="right",
            max_abs=self.max_abs,
        )
        difference = self.subtract((left_value, right_value))
        magnitude = self.absolute_sum(
            (
                self.relu(difference),
                self.relu(self.negate(difference)),
            )
        )
        result = self.combine(
            (
                self.relu(magnitude),
                self.relu(self.shift_one(magnitude)),
            )
        )
        if result not in (0.0, 1.0):
            raise ArithmeticError("fixed equality left the hard binary range")
        return int(result)

    def boundary(self) -> GadgetBoundary:
        """声明等值核心由固定 Linear/ReLU 组成，类型与范围检查在电路外。"""
        return GadgetBoundary(
            fixed_circuit_steps=("bounded_integer_equality_relu",),
            software_guard_steps=("bounded_builtin_integer_validation",),
            deterministic_hard_gate_steps=(),
        )

    def submodules(self) -> tuple[object, ...]:
        """返回等值 gadget 的全部固定子模块。"""
        return (
            self.subtract,
            self.negate,
            self.relu,
            self.absolute_sum,
            self.shift_one,
            self.combine,
        )


class FixedBooleanAggregator:
    """用固定 Linear/ReLU 把固定宽度二进制向量聚合为硬 AND。"""

    requires_grad = False

    def __init__(self, width: int) -> None:
        """固定输入宽度并构造仅在总和等于宽度时为一的阶跃。"""
        self.width = _require_positive_int(width, name="width")
        if self.width > MAX_EXACT_FLOAT_INTEGER:
            raise ValueError("Boolean width exceeds the exact float integer range")
        self.guard = BinaryInputGuard()
        self.sum_layer = FixedSum()
        self.shift_accept = FixedLinear(
            (1.0,),
            bias=-float(self.width - 1),
        )
        self.shift_saturate = FixedLinear((1.0,), bias=-float(self.width))
        self.relu = FixedReLU()
        self.combine = FixedLinear((1.0, -1.0))

    def __call__(self, bits: Sequence[int | float]) -> int:
        """严格校验宽度和二进制域，仅当所有输入均为一时返回 ``1``。"""
        if len(bits) != self.width:
            raise ValueError(f"expected {self.width} bits, received {len(bits)}")
        normalized = self.guard(bits)
        total = self.sum_layer(normalized)
        result = self.combine(
            (
                self.relu(self.shift_accept(total)),
                self.relu(self.shift_saturate(total)),
            )
        )
        if result not in (0.0, 1.0):
            raise ArithmeticError("fixed Boolean aggregation left the binary range")
        return int(result)

    def boundary(self) -> GadgetBoundary:
        """声明聚合核心和前置二进制 guard 的边界。"""
        return GadgetBoundary(
            fixed_circuit_steps=("fixed_width_boolean_and_relu",),
            software_guard_steps=("strict_binary_domain_validation",),
            deterministic_hard_gate_steps=(),
        )

    def submodules(self) -> tuple[object, ...]:
        """返回聚合器的固定 guard、求和、线性层与 ReLU。"""
        return (
            self.guard,
            self.sum_layer,
            self.shift_accept,
            self.shift_saturate,
            self.relu,
            self.combine,
        )


class _FixedLessEqual:
    """在整数域用两个 ReLU 实现 ``value <= bound``。"""

    requires_grad = False

    def __init__(self, bound: int) -> None:
        self.bound = bound
        self.shift_bound = FixedLinear((1.0,), bias=-float(bound))
        self.shift_next = FixedLinear((1.0,), bias=-float(bound + 1))
        self.relu = FixedReLU()
        self.combine = FixedLinear((-1.0, 1.0), bias=1.0)

    def __call__(self, value: int) -> int:
        result = self.combine(
            (
                self.relu(self.shift_bound(value)),
                self.relu(self.shift_next(value)),
            )
        )
        if result not in (0.0, 1.0):
            raise ArithmeticError("fixed less-equal left the binary range")
        return int(result)

    def submodules(self) -> tuple[object, ...]:
        return (
            self.shift_bound,
            self.shift_next,
            self.relu,
            self.combine,
        )


@dataclass(frozen=True)
class RangeNormTrace:
    """记录范围/范数 gadget 的有界中间值与最终硬比特。"""

    absolute_values: tuple[int, ...]
    coordinate_bits: tuple[int, ...]
    l1_norm: int
    l1_bit: int
    accept: int

    def as_dict(self) -> dict[str, object]:
        """导出范围、L1 范数和接受位的稳定 trace。"""
        return {
            "absolute_values": list(self.absolute_values),
            "coordinate_bits": list(self.coordinate_bits),
            "l1_norm": self.l1_norm,
            "l1_bit": self.l1_bit,
            "accept": self.accept,
        }


class FixedRangeNormCheck:
    """用固定 Linear/ReLU 同时检查整数坐标范围和 L1 范数。"""

    requires_grad = False

    def __init__(
        self,
        width: int,
        *,
        input_max_abs: int,
        coordinate_bound: int,
        l1_bound: int,
    ) -> None:
        """固定向量宽度、入口界限、坐标界限与 L1 范数界限。"""
        self.width = _require_positive_int(width, name="width")
        self.input_max_abs = _require_positive_int(
            input_max_abs,
            name="input_max_abs",
        )
        if type(coordinate_bound) is not int or coordinate_bound < 0:
            raise ValueError("coordinate_bound must be a non-negative integer")
        if type(l1_bound) is not int or l1_bound < 0:
            raise ValueError("l1_bound must be a non-negative integer")
        if coordinate_bound > input_max_abs:
            raise ValueError("coordinate_bound cannot exceed input_max_abs")
        if self.width * self.input_max_abs > MAX_EXACT_FLOAT_INTEGER:
            raise ValueError("L1 intermediate exceeds the exact float integer range")
        if l1_bound > MAX_EXACT_FLOAT_INTEGER:
            raise ValueError("l1_bound exceeds the exact float integer range")
        self.coordinate_bound = coordinate_bound
        self.l1_bound = l1_bound
        self.identity = FixedLinear((1.0,))
        self.negate = FixedLinear((-1.0,))
        self.relu = FixedReLU()
        self.absolute_sum = FixedLinear((1.0, 1.0))
        self.sum_layer = FixedSum()
        self.coordinate_check = _FixedLessEqual(coordinate_bound)
        self.l1_check = _FixedLessEqual(l1_bound)
        self.aggregator = FixedBooleanAggregator(self.width + 1)

    def trace(self, values: Sequence[int]) -> RangeNormTrace:
        """计算坐标绝对值、范围比特、L1 范数和聚合接受位。"""
        if len(values) != self.width:
            raise ValueError(f"expected {self.width} values, received {len(values)}")
        checked = tuple(
            _require_builtin_int(
                value,
                name=f"values[{index}]",
                max_abs=self.input_max_abs,
            )
            for index, value in enumerate(values)
        )
        absolute_values = tuple(
            int(
                self.absolute_sum(
                    (
                        self.relu(self.identity(value)),
                        self.relu(self.negate(value)),
                    )
                )
            )
            for value in checked
        )
        coordinate_bits = tuple(
            self.coordinate_check(value) for value in absolute_values
        )
        l1_norm = int(self.sum_layer(absolute_values))
        l1_bit = self.l1_check(l1_norm)
        accept = self.aggregator((*coordinate_bits, l1_bit))
        return RangeNormTrace(
            absolute_values=absolute_values,
            coordinate_bits=coordinate_bits,
            l1_norm=l1_norm,
            l1_bit=l1_bit,
            accept=accept,
        )

    def __call__(self, values: Sequence[int]) -> int:
        """仅当所有坐标与 L1 范数均满足声明界限时返回 ``1``。"""
        return self.trace(values).accept

    def boundary(self) -> GadgetBoundary:
        """声明范围、范数和聚合核心以及软件整数入口 guard。"""
        return GadgetBoundary(
            fixed_circuit_steps=(
                "fixed_integer_absolute_value_relu",
                "coordinate_less_equal_relu",
                "l1_sum",
                "l1_less_equal_relu",
                "fixed_width_boolean_and_relu",
            ),
            software_guard_steps=("bounded_builtin_integer_validation",),
            deterministic_hard_gate_steps=(),
        )

    def submodules(self) -> tuple[object, ...]:
        """返回范围/范数 gadget 的全部固定子模块。"""
        return (
            self.identity,
            self.negate,
            self.relu,
            self.absolute_sum,
            self.sum_layer,
            self.coordinate_check,
            self.l1_check,
            self.aggregator,
        )


@dataclass(frozen=True)
class ProjectorBoundary:
    """声明 projector backend 与共享 fixed-linear core 的编译边界。"""

    backend: str
    core_id: str
    fixed_circuit_steps: tuple[str, ...]
    deterministic_preprocessing_steps: tuple[str, ...]
    software_guard_steps: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """导出 projector 编译边界。"""
        return {
            "backend": self.backend,
            "core_id": self.core_id,
            "fixed_circuit_steps": list(self.fixed_circuit_steps),
            "deterministic_preprocessing_steps": list(
                self.deterministic_preprocessing_steps
            ),
            "software_guard_steps": list(self.software_guard_steps),
        }


@dataclass(frozen=True)
class ProjectorComplexity:
    """记录 projector 的层数、固定参数量和整数精确性上界。"""

    input_width: int
    output_width: int
    fixed_layer_depth: int
    fixed_linear_layers: int
    fixed_parameter_count: int
    max_input_abs: int
    max_output_abs: int
    exact_integer_limit: int = MAX_EXACT_FLOAT_INTEGER

    def as_dict(self) -> dict[str, int]:
        """导出 projector 结构与数值复杂度。"""
        return {
            "input_width": self.input_width,
            "output_width": self.output_width,
            "fixed_layer_depth": self.fixed_layer_depth,
            "fixed_linear_layers": self.fixed_linear_layers,
            "fixed_parameter_count": self.fixed_parameter_count,
            "max_input_abs": self.max_input_abs,
            "max_output_abs": self.max_output_abs,
            "exact_integer_limit": self.exact_integer_limit,
        }


@dataclass(frozen=True)
class ProjectorTrace:
    """记录一次 projector 调用的 backend、输入、输出和观测上界。"""

    backend: str
    core_id: str
    input_vector: tuple[int, ...]
    output_vector: tuple[int, ...]
    max_observed_abs: int

    def as_dict(self) -> dict[str, object]:
        """导出可定位 projector backend 的确定性 trace。"""
        return {
            "backend": self.backend,
            "core_id": self.core_id,
            "input_vector": list(self.input_vector),
            "output_vector": list(self.output_vector),
            "max_observed_abs": self.max_observed_abs,
        }


@dataclass(frozen=True)
class ProjectorManifest:
    """汇总 projector boundary、复杂度、等价样本、延迟和峰值内存。"""

    schema_version: str
    stage: str
    backend: str
    core_id: str
    boundary: ProjectorBoundary
    complexity: ProjectorComplexity
    reference_equivalence_cases: int
    reference_mismatches: int
    latency_seconds: float
    peak_memory_bytes: int
    production_ready: bool = False

    def __post_init__(self) -> None:
        """拒绝负计数、非有限延迟或被误标为 production-ready 的 A0.5 manifest。"""
        for name, value in (
            ("reference_equivalence_cases", self.reference_equivalence_cases),
            ("reference_mismatches", self.reference_mismatches),
            ("peak_memory_bytes", self.peak_memory_bytes),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.reference_mismatches > self.reference_equivalence_cases:
            raise ValueError("reference mismatches cannot exceed measured cases")
        if (
            type(self.latency_seconds) not in (int, float)
            or not math.isfinite(float(self.latency_seconds))
            or self.latency_seconds < 0
        ):
            raise ValueError("latency_seconds must be finite and non-negative")
        if self.production_ready is not False:
            raise ValueError("the Route A A0.5 toolchain is research-only")

    def as_dict(self) -> dict[str, object]:
        """导出 AG8 preliminary 使用的机器可读 manifest。"""
        return {
            "schema_version": self.schema_version,
            "stage": self.stage,
            "backend": self.backend,
            "core_id": self.core_id,
            "boundary": self.boundary.as_dict(),
            "complexity": self.complexity.as_dict(),
            "reference_equivalence_cases": self.reference_equivalence_cases,
            "reference_mismatches": self.reference_mismatches,
            "latency_seconds": self.latency_seconds,
            "peak_memory_bytes": self.peak_memory_bytes,
            "production_ready": self.production_ready,
        }


class FixedProjectorCore:
    """把有界整数矩阵编译为共享的固定、不可训练 Linear 行集合。"""

    core_id = FIXED_PROJECTOR_CORE_ID
    requires_grad = False

    def __init__(
        self,
        matrix: Sequence[Sequence[int]],
        *,
        max_input_abs: int,
    ) -> None:
        """校验矩阵形状和数值界限，再编译固定 Linear 行。"""
        self.max_input_abs = _require_positive_int(
            max_input_abs,
            name="max_input_abs",
        )
        if not matrix or not matrix[0]:
            raise ValueError("projector matrix must be non-empty")
        input_width = len(matrix[0])
        normalized_rows: list[tuple[int, ...]] = []
        for row_index, row in enumerate(matrix):
            if len(row) != input_width:
                raise ValueError("projector matrix must be rectangular")
            normalized_rows.append(
                tuple(
                    _require_builtin_int(
                        coefficient,
                        name=f"matrix[{row_index}][{column_index}]",
                        max_abs=MAX_EXACT_FLOAT_INTEGER,
                    )
                    for column_index, coefficient in enumerate(row)
                )
            )
        self.matrix = tuple(normalized_rows)
        self.input_width = input_width
        self.output_width = len(self.matrix)
        output_bounds = tuple(
            sum(abs(coefficient) for coefficient in row) * self.max_input_abs
            for row in self.matrix
        )
        self.max_output_abs = max(output_bounds)
        if self.max_output_abs > MAX_EXACT_FLOAT_INTEGER:
            raise ValueError("projector output exceeds the exact float integer range")
        self.rows = tuple(
            FixedLinear(tuple(float(coefficient) for coefficient in row))
            for row in self.matrix
        )

    def project(self, values: Sequence[int]) -> tuple[int, ...]:
        """严格校验输入并执行共享 fixed-linear projector core。"""
        if len(values) != self.input_width:
            raise ValueError(
                f"expected {self.input_width} values, received {len(values)}"
            )
        checked = tuple(
            _require_builtin_int(
                value,
                name=f"values[{index}]",
                max_abs=self.max_input_abs,
            )
            for index, value in enumerate(values)
        )
        output: list[int] = []
        for row in self.rows:
            projected = row(checked)
            if not math.isfinite(projected) or not projected.is_integer():
                raise ArithmeticError("projector left the exact integer domain")
            output.append(int(projected))
        return tuple(output)

    def complexity(self) -> ProjectorComplexity:
        """返回共享 core 的层数、固定参数量和数值上界。"""
        return ProjectorComplexity(
            input_width=self.input_width,
            output_width=self.output_width,
            fixed_layer_depth=1,
            fixed_linear_layers=self.output_width,
            fixed_parameter_count=self.output_width * (self.input_width + 1),
            max_input_abs=self.max_input_abs,
            max_output_abs=self.max_output_abs,
        )

    def submodules(self) -> tuple[FixedLinear, ...]:
        """返回矩阵每一行对应的不可训练固定 Linear 层。"""
        return self.rows


@runtime_checkable
class FixedProjector(Protocol):
    """定义 scheme-independent projector backend 的公共接口。"""

    backend: str
    core: FixedProjectorCore

    def project(self, values: Sequence[int]) -> tuple[int, ...]:
        """把有界整数输入投影为确定性整数输出。"""
        ...

    def trace(self, values: Sequence[int]) -> ProjectorTrace:
        """返回一次投影的稳定 trace。"""
        ...

    def boundary(self) -> ProjectorBoundary:
        """返回 backend 预处理与共享 core 的边界。"""
        ...

    def complexity(self) -> ProjectorComplexity:
        """返回 backend 的结构和数值复杂度。"""
        ...

    def manifest(
        self,
        *,
        reference_equivalence_cases: int,
        reference_mismatches: int,
        latency_seconds: float,
        peak_memory_bytes: int,
    ) -> ProjectorManifest:
        """构造包含测量结果的 A0.5 preliminary manifest。"""
        ...

    def submodules(self) -> tuple[FixedProjectorCore, ...]:
        """返回 backend 复用的 fixed projector core。"""
        ...


class _ProjectorBackend:
    """复用 trace、complexity 与 manifest 的 projector backend 基类。"""

    requires_grad = False

    def project(self, values: Sequence[int]) -> tuple[int, ...]:
        """把 backend 输入交给共享 fixed-linear core。"""
        return self.core.project(values)

    def trace(self, values: Sequence[int]) -> ProjectorTrace:
        """记录 backend 标识、共享 core 标识和投影向量。"""
        input_vector = tuple(values)
        output_vector = self.project(input_vector)
        return ProjectorTrace(
            backend=self.backend,
            core_id=self.core.core_id,
            input_vector=input_vector,
            output_vector=output_vector,
            max_observed_abs=max((abs(value) for value in output_vector), default=0),
        )

    def complexity(self) -> ProjectorComplexity:
        """复用共享 core 的结构和数值复杂度。"""
        return self.core.complexity()

    def manifest(
        self,
        *,
        reference_equivalence_cases: int,
        reference_mismatches: int,
        latency_seconds: float,
        peak_memory_bytes: int,
    ) -> ProjectorManifest:
        """把外部测量结果与共享 boundary/complexity 组合成 manifest。"""
        return ProjectorManifest(
            schema_version="saga-route-a-projector-manifest-v1",
            stage="A0.5-preliminary",
            backend=self.backend,
            core_id=self.core.core_id,
            boundary=self.boundary(),
            complexity=self.complexity(),
            reference_equivalence_cases=reference_equivalence_cases,
            reference_mismatches=reference_mismatches,
            latency_seconds=latency_seconds,
            peak_memory_bytes=peak_memory_bytes,
            production_ready=False,
        )

    def submodules(self) -> tuple[FixedProjectorCore, ...]:
        """只暴露当前 backend 复用的共享 core。"""
        return (self.core,)


class DenseFixedProjector(_ProjectorBackend):
    """使用显式整数矩阵和共享 core 的 dense projector backend。"""

    backend = "dense-fixed-matrix-v1"

    def __init__(
        self,
        matrix: Sequence[Sequence[int]],
        *,
        max_input_abs: int,
    ) -> None:
        """把 dense 矩阵直接交给 scheme-independent fixed projector core。"""
        self.core = FixedProjectorCore(
            matrix,
            max_input_abs=max_input_abs,
        )

    def boundary(self) -> ProjectorBoundary:
        """声明 dense backend 无额外运行期预处理。"""
        return ProjectorBoundary(
            backend=self.backend,
            core_id=self.core.core_id,
            fixed_circuit_steps=("fixed_dense_matrix_projection",),
            deterministic_preprocessing_steps=(),
            software_guard_steps=("bounded_builtin_integer_vector_validation",),
        )


class TinyNegacyclicProjector(_ProjectorBackend):
    """研究用 tiny ``Z[x]/(x^n+1)`` 固定负循环卷积 projector。"""

    backend = "tiny-negacyclic-fixed-matrix-v1"

    def __init__(
        self,
        multiplier: Sequence[int],
        *,
        max_input_abs: int,
    ) -> None:
        """在构造期展开固定多项式，再复用与 dense backend 相同的 core。"""
        if not multiplier:
            raise ValueError("negacyclic multiplier must be non-empty")
        normalized = tuple(
            _require_builtin_int(
                coefficient,
                name=f"multiplier[{index}]",
                max_abs=MAX_EXACT_FLOAT_INTEGER,
            )
            for index, coefficient in enumerate(multiplier)
        )
        self.multiplier = normalized
        self.core = FixedProjectorCore(
            self._expand_negacyclic_matrix(normalized),
            max_input_abs=max_input_abs,
        )

    @staticmethod
    def _expand_negacyclic_matrix(
        multiplier: Sequence[int],
    ) -> tuple[tuple[int, ...], ...]:
        # x^n = -1，因此超过 n-1 次的乘积项回绕后符号取反。
        width = len(multiplier)
        matrix = [[0 for _ in range(width)] for _ in range(width)]
        for left_index, coefficient in enumerate(multiplier):
            for right_index in range(width):
                degree = left_index + right_index
                if degree < width:
                    matrix[degree][right_index] += coefficient
                else:
                    matrix[degree - width][right_index] -= coefficient
        return tuple(tuple(row) for row in matrix)

    def boundary(self) -> ProjectorBoundary:
        """声明负循环矩阵在构造期展开，运行期走共享 projector core。"""
        return ProjectorBoundary(
            backend=self.backend,
            core_id=self.core.core_id,
            fixed_circuit_steps=("fixed_negacyclic_matrix_projection",),
            deterministic_preprocessing_steps=(
                "compile_time_negacyclic_matrix_expansion",
            ),
            software_guard_steps=("bounded_builtin_integer_vector_validation",),
        )
