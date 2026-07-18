"""路线 A A1 的 research-only toy verifier fixed-ReLU arithmetic core。"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import inspect
import textwrap
from typing import Callable, Sequence

import neural.fixed_toolchain as fixed_toolchain
from neural.fixed_toolchain import (
    BinaryInputGuard,
    DenseFixedProjector,
    FixedBooleanAggregator,
    FixedBoundedModulo,
    FixedEquality,
    FixedRangeNormCheck,
    MAX_EXACT_FLOAT_INTEGER,
    ProjectorComplexity,
    RangeNormTrace,
)
from neural.shamir_layers import FixedLinear
from neural.verifier_wrapper import BitLayout, bits_to_bytes
from pq.toy_lwe import ToyLWESignatureScheme


@dataclass(frozen=True)
class A1ToyVerifierBoundary:
    """声明 A1 fixed arithmetic core、软件 guard 与 parse/hash 排除边界。"""

    claimed_fixed_circuit_steps: tuple[str, ...]
    deterministic_preprocessing_steps: tuple[str, ...]
    software_guard_steps: tuple[str, ...]
    excluded_from_claim: tuple[str, ...]
    deterministic_hard_gate_steps: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        """导出机器可读 A1 circuit boundary。"""
        return {
            "claimed_fixed_circuit_steps": list(self.claimed_fixed_circuit_steps),
            "deterministic_preprocessing_steps": list(
                self.deterministic_preprocessing_steps
            ),
            "software_guard_steps": list(self.software_guard_steps),
            "excluded_from_claim": list(self.excluded_from_claim),
            "deterministic_hard_gate_steps": list(
                self.deterministic_hard_gate_steps
            ),
        }


@dataclass(frozen=True)
class A1ToyVerifierComplexity:
    """记录 A1 core 的固定结构、运行期 ReLU 次数与数值上界。"""

    dimension: int
    modulus: int
    projector: ProjectorComplexity
    modulo_threshold_count: int
    fixed_layer_depth: int
    structural_fixed_parameter_count: int
    fixed_relu_calls_per_verification: int
    max_intermediate_abs: int
    exact_integer_limit: int = MAX_EXACT_FLOAT_INTEGER

    def as_dict(self) -> dict[str, object]:
        """导出 A1 结构和数值复杂度 manifest。"""
        return {
            "dimension": self.dimension,
            "modulus": self.modulus,
            "projector": self.projector.as_dict(),
            "modulo_threshold_count": self.modulo_threshold_count,
            "fixed_layer_depth": self.fixed_layer_depth,
            "structural_fixed_parameter_count": (
                self.structural_fixed_parameter_count
            ),
            "fixed_relu_calls_per_verification": (
                self.fixed_relu_calls_per_verification
            ),
            "max_intermediate_abs": self.max_intermediate_abs,
            "exact_integer_limit": self.exact_integer_limit,
        }


@dataclass(frozen=True)
class A1ToyVerificationTrace:
    """记录 A1 toy verifier fixed core 的输入界限、算术中间值和硬结果。"""

    public_vector: tuple[int, ...]
    signature_vector: tuple[int, ...]
    challenge_vector: tuple[int, ...]
    challenge_source: str
    input_range_traces: tuple[RangeNormTrace, ...]
    signature_projection: tuple[int, ...]
    challenge_projection: tuple[int, ...]
    projection_differences: tuple[int, ...]
    recovered_public: tuple[int, ...]
    equality_bits: tuple[int, ...]
    equality_accept: int
    accept: int

    def as_dict(self) -> dict[str, object]:
        """导出不含私钥的 A1 fixed arithmetic trace。"""
        return {
            "public_vector": list(self.public_vector),
            "signature_vector": list(self.signature_vector),
            "challenge_vector": list(self.challenge_vector),
            "challenge_source": self.challenge_source,
            "input_range_traces": [
                trace.as_dict() for trace in self.input_range_traces
            ],
            "signature_projection": list(self.signature_projection),
            "challenge_projection": list(self.challenge_projection),
            "projection_differences": list(self.projection_differences),
            "recovered_public": list(self.recovered_public),
            "equality_bits": list(self.equality_bits),
            "equality_accept": self.equality_accept,
            "accept": self.accept,
        }


@dataclass(frozen=True)
class A1SourceClosureReport:
    """记录 claimed evaluator 禁用运算与数据分支的静态审计结果。"""

    claimed_symbols: tuple[str, ...]
    source_sha256: str
    python_modulo_findings: tuple[str, ...]
    python_equality_findings: tuple[str, ...]
    data_branch_findings: tuple[str, ...]
    verifier_call_findings: tuple[str, ...]
    passed: bool

    def as_dict(self) -> dict[str, object]:
        """导出 AG3 使用的 claimed-source closure evidence。"""
        return {
            "claimed_symbols": list(self.claimed_symbols),
            "source_sha256": self.source_sha256,
            "python_modulo_findings": list(self.python_modulo_findings),
            "python_equality_findings": list(self.python_equality_findings),
            "data_branch_findings": list(self.data_branch_findings),
            "verifier_call_findings": list(self.verifier_call_findings),
            "passed": self.passed,
        }


class FixedToyLWEVerifierCore:
    """编译 toy LWE 验签关系的完整有界 fixed-ReLU arithmetic core。"""

    requires_grad = False

    def __init__(self, matrix: Sequence[Sequence[int]], modulus: int) -> None:
        """固定矩阵/模数并编译 projector、mod、equality、range/norm 与聚合。"""
        if type(modulus) is not int or modulus <= 1:
            raise ValueError("modulus must be a built-in integer greater than one")
        if not matrix or len(matrix) != len(matrix[0]):
            raise ValueError("A1 toy verifier matrix must be non-empty and square")
        self.dimension = len(matrix)
        self.modulus = modulus
        for row in matrix:
            if len(row) != self.dimension:
                raise ValueError("A1 toy verifier matrix must be square")
            for coefficient in row:
                if type(coefficient) is not int:
                    raise TypeError("A1 matrix coefficients must be integers")
                if coefficient < 0 or coefficient >= modulus:
                    raise ValueError("A1 matrix coefficients must belong to Z_q")
        # 允许 q 作为 fixed range rejection witness；合法向量仍位于 [0, q-1]。
        self.projector = DenseFixedProjector(matrix, max_input_abs=modulus)
        projection_bound = self.projector.complexity().max_output_abs
        self.subtract = FixedLinear((1.0, -1.0))
        self.modulo = FixedBoundedModulo(
            modulus,
            min_input=-projection_bound,
            max_input=projection_bound,
        )
        self.equality = FixedEquality(max_abs=modulus)
        self.range_norm = FixedRangeNormCheck(
            self.dimension,
            input_max_abs=modulus,
            coordinate_bound=modulus - 1,
            l1_bound=self.dimension * (modulus - 1),
        )
        self.equality_aggregator = FixedBooleanAggregator(self.dimension)
        self.final_aggregator = FixedBooleanAggregator(5)

    def _validated_vector(
        self,
        values: Sequence[int],
        *,
        name: str,
    ) -> tuple[int, ...]:
        """校验 A1 软件入口的固定宽度、原生整数和非负有限编译域。"""
        if len(values) != self.dimension:
            raise ValueError(
                f"{name} must contain exactly {self.dimension} coefficients"
            )
        checked: list[int] = []
        for value in values:
            if type(value) is not int:
                raise TypeError(f"{name} coefficients must be built-in integers")
            if value < 0 or value > self.modulus:
                raise ValueError(f"{name} exceeds the compiled coefficient domain")
            checked.append(value)
        return tuple(checked)

    def trace_vectors(
        self,
        public_vector: Sequence[int],
        signature_vector: Sequence[int],
        challenge_vector: Sequence[int],
    ) -> A1ToyVerificationTrace:
        """校验软件输入 contract 后执行完整 fixed arithmetic core。"""
        public_values = self._validated_vector(public_vector, name="public_vector")
        signature_values = self._validated_vector(
            signature_vector,
            name="signature_vector",
        )
        challenge_values = self._validated_vector(
            challenge_vector,
            name="challenge_vector",
        )
        return self._trace_fixed(
            public_values,
            signature_values,
            challenge_values,
        )

    def _trace_fixed(
        self,
        public_vector: tuple[int, ...],
        signature_vector: tuple[int, ...],
        challenge_vector: tuple[int, ...],
    ) -> A1ToyVerificationTrace:
        # 本方法和 AG3 清单中的 evaluator 只调用固定层，不按数据值分支。
        range_traces = tuple(
            self.range_norm._trace_fixed(vector)
            for vector in (public_vector, signature_vector, challenge_vector)
        )
        signature_projection = tuple(
            int(value)
            for value in self.projector.core._project_fixed(signature_vector)
        )
        challenge_projection = tuple(
            int(value)
            for value in self.projector.core._project_fixed(challenge_vector)
        )
        differences = tuple(
            int(self.subtract((left, right)))
            for left, right in zip(
                signature_projection,
                challenge_projection,
                strict=True,
            )
        )
        recovered_public = tuple(
            self.modulo._evaluate_fixed(value) for value in differences
        )
        recovered_range = self.range_norm._trace_fixed(recovered_public)
        equality_bits = tuple(
            self.equality._evaluate_fixed(recovered, expected)
            for recovered, expected in zip(
                recovered_public,
                public_vector,
                strict=True,
            )
        )
        equality_accept = self.equality_aggregator._evaluate_fixed(equality_bits)
        accept = self.final_aggregator._evaluate_fixed(
            (
                *(trace.accept for trace in range_traces),
                recovered_range.accept,
                equality_accept,
            )
        )
        return A1ToyVerificationTrace(
            public_vector=public_vector,
            signature_vector=signature_vector,
            challenge_vector=challenge_vector,
            challenge_source="caller_supplied_preprocessed_vector",
            input_range_traces=(*range_traces, recovered_range),
            signature_projection=signature_projection,
            challenge_projection=challenge_projection,
            projection_differences=differences,
            recovered_public=recovered_public,
            equality_bits=equality_bits,
            equality_accept=equality_accept,
            accept=accept,
        )

    def verify_vectors(
        self,
        public_vector: Sequence[int],
        signature_vector: Sequence[int],
        challenge_vector: Sequence[int],
    ) -> int:
        """对预处理向量返回硬 ``0/1``；软件 contract 失败时 fail-closed。"""
        try:
            return self.trace_vectors(
                public_vector,
                signature_vector,
                challenge_vector,
            ).accept
        except (ArithmeticError, TypeError, ValueError):
            return 0

    def complexity(self) -> A1ToyVerifierComplexity:
        """汇总 projector/modulo/gadget 的结构参数、ReLU 调用和数值上界。"""
        projector_complexity = self.projector.complexity()
        modulo_complexity = self.modulo.complexity()
        structural_parameters = (
            projector_complexity.fixed_parameter_count
            + modulo_complexity.fixed_parameter_count
            + 13  # equality
            + 28  # shared range/norm
            + 7  # equality aggregator
            + 7  # final aggregator
            + 3  # projection subtraction
        )
        relu_calls = (
            (2 * modulo_complexity.threshold_count * self.dimension)
            + (20 * self.dimension)
            + 20
        )
        max_intermediate = max(
            projector_complexity.max_output_abs,
            modulo_complexity.max_intermediate_abs,
            self.dimension * self.modulus,
        )
        return A1ToyVerifierComplexity(
            dimension=self.dimension,
            modulus=self.modulus,
            projector=projector_complexity,
            modulo_threshold_count=modulo_complexity.threshold_count,
            fixed_layer_depth=23,
            structural_fixed_parameter_count=structural_parameters,
            fixed_relu_calls_per_verification=relu_calls,
            max_intermediate_abs=max_intermediate,
        )

    def submodules(self) -> tuple[object, ...]:
        """返回 A1 arithmetic core 的全部固定、不可训练子模块。"""
        return (
            self.projector,
            self.subtract,
            self.modulo,
            self.equality,
            self.range_norm,
            self.equality_aggregator,
            self.final_aggregator,
        )


class FullReLUToyLWEVerifier:
    """包装 A1 fixed arithmetic core，并显式保留 byte parse/hash 预处理边界。

    该 verifier 与底层 toy scheme 均为研究用途，绝不能用于生产认证。
    名称中的
    ``FullReLU`` 只描述已声明 arithmetic core，不包含 SHA-256 或 byte parser。
    """

    BOUNDARY = A1ToyVerifierBoundary(
        claimed_fixed_circuit_steps=(
            "public_matrix_projection",
            "projection_subtraction",
            "bounded_integer_modulo_relu",
            "bounded_integer_equality_relu",
            "coefficient_range_and_l1_norm_relu",
            "fixed_boolean_aggregation_relu",
        ),
        deterministic_preprocessing_steps=(
            "strict_byte_vector_decoding",
            "sha256_domain_separated_challenge_derivation",
            "strict_binary_bit_packing",
        ),
        software_guard_steps=(
            "fixed_width_byte_layout_validation",
            "strict_binary_domain_validation",
            "bounded_builtin_integer_vector_validation",
        ),
        excluded_from_claim=(
            "sha256_hash_to_challenge_circuit",
            "byte_parser_circuit",
            "production_post_quantum_security",
        ),
    )

    def __init__(self, scheme: ToyLWESignatureScheme, message_bytes: int) -> None:
        """保存公开 toy 参数并编译不含签名私钥的 A1 arithmetic core。"""
        if type(message_bytes) is not int or message_bytes <= 0:
            raise ValueError("message_bytes must be a positive built-in integer")
        self.scheme = scheme
        self.layout = BitLayout(
            public_key_bytes=scheme.vector_bytes,
            message_bytes=message_bytes,
            signature_bytes=scheme.vector_bytes,
        )
        self.binary_guard = BinaryInputGuard()
        self.core = FixedToyLWEVerifierCore(
            scheme.public_matrix(),
            scheme.parameters.modulus,
        )

    def compilation_boundary(self) -> A1ToyVerifierBoundary:
        """返回 A1 arithmetic claim 与 parse/hash/software guard 的明确边界。"""
        return self.BOUNDARY

    def trace_verification(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> A1ToyVerificationTrace:
        """执行显式 parse/hash 预处理，再返回 fixed arithmetic trace。"""
        if type(public_key) is not bytes or type(message) is not bytes:
            raise TypeError("public_key and message must be built-in bytes")
        if type(signature) is not bytes:
            raise TypeError("signature must be built-in bytes")
        if len(message) != self.layout.message_bytes:
            raise ValueError("message length does not match the compiled layout")
        public_vector = self.scheme.decode_public_vector(public_key)
        signature_vector = self.scheme.decode_signature_vector(signature)
        challenge_vector = self.scheme.challenge_vector(message)
        trace = self.core.trace_vectors(
            public_vector,
            signature_vector,
            challenge_vector,
        )
        return A1ToyVerificationTrace(
            public_vector=trace.public_vector,
            signature_vector=trace.signature_vector,
            challenge_vector=trace.challenge_vector,
            challenge_source="deterministic_sha256_preprocessing:not_neural_hash",
            input_range_traces=trace.input_range_traces,
            signature_projection=trace.signature_projection,
            challenge_projection=trace.challenge_projection,
            projection_differences=trace.projection_differences,
            recovered_public=trace.recovered_public,
            equality_bits=trace.equality_bits,
            equality_accept=trace.equality_accept,
            accept=trace.accept,
        )

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """对 byte 编码材料返回硬 ``0/1``，任何 parse/core 错误均 fail-closed。"""
        try:
            return self.trace_verification(public_key, message, signature).accept
        except (ArithmeticError, TypeError, ValueError):
            return 0

    def verify_bits(
        self,
        public_key_bits: Sequence[int | float],
        message_bits: Sequence[int | float],
        signature_bits: Sequence[int | float],
    ) -> int:
        """严格校验二进制域并把三段 bit material 交给 byte/A1 路径。"""
        try:
            public_key = bits_to_bytes(self.binary_guard(public_key_bits))
            message = bits_to_bytes(self.binary_guard(message_bits))
            signature = bits_to_bytes(self.binary_guard(signature_bits))
        except (TypeError, ValueError):
            return 0
        return self.verify_bytes(public_key, message, signature)

    def verify_compound_bits(self, bits: Sequence[int | float]) -> int:
        """按固定 layout 拆分 compound bits，长度或二进制域错误时拒绝。"""
        if len(bits) != self.layout.total_bits:
            return 0
        public_key_end = self.layout.public_key_bits
        message_end = public_key_end + self.layout.message_bits
        return self.verify_bits(
            bits[:public_key_end],
            bits[public_key_end:message_end],
            bits[message_end:],
        )

    def complexity(self) -> A1ToyVerifierComplexity:
        """返回 A1 arithmetic core 的结构、ReLU 与数值复杂度。"""
        return self.core.complexity()

    def submodules(self) -> tuple[object, ...]:
        """返回二进制软件 guard 与不含私钥的 fixed arithmetic core。"""
        return (self.binary_guard, self.core)


def _claimed_evaluators() -> tuple[tuple[str, Callable[..., object]], ...]:
    """返回 AG3 静态审计覆盖的固定 evaluator 源码符号。"""
    return (
        (
            "FixedProjectorCore._project_fixed",
            fixed_toolchain.FixedProjectorCore._project_fixed,
        ),
        (
            "_FixedIntegerStepAtLeast._evaluate_fixed",
            fixed_toolchain._FixedIntegerStepAtLeast._evaluate_fixed,
        ),
        (
            "FixedBoundedModulo._evaluate_fixed",
            fixed_toolchain.FixedBoundedModulo._evaluate_fixed,
        ),
        (
            "FixedEquality._evaluate_fixed",
            fixed_toolchain.FixedEquality._evaluate_fixed,
        ),
        (
            "_FixedLessEqual._evaluate_fixed",
            fixed_toolchain._FixedLessEqual._evaluate_fixed,
        ),
        (
            "FixedRangeNormCheck._trace_fixed",
            fixed_toolchain.FixedRangeNormCheck._trace_fixed,
        ),
        (
            "FixedBooleanAggregator._evaluate_fixed",
            fixed_toolchain.FixedBooleanAggregator._evaluate_fixed,
        ),
        (
            "FixedToyLWEVerifierCore._trace_fixed",
            FixedToyLWEVerifierCore._trace_fixed,
        ),
    )


def audit_a1_claimed_source() -> A1SourceClosureReport:
    """静态确认 claimed evaluator 不含 ``%``、``==``、普通 verifier 或数据分支。"""
    modulo_findings: list[str] = []
    equality_findings: list[str] = []
    branch_findings: list[str] = []
    verifier_findings: list[str] = []
    source_parts: list[str] = []
    symbols = _claimed_evaluators()
    for symbol_name, function in symbols:
        source = textwrap.dedent(inspect.getsource(function))
        source_parts.append(f"{symbol_name}\n{source}")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            line = getattr(node, "lineno", 0)
            finding = f"{symbol_name}:{line}"
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                modulo_findings.append(finding)
            if isinstance(node, ast.Compare) and any(
                isinstance(operator, (ast.Eq, ast.NotEq))
                for operator in node.ops
            ):
                equality_findings.append(finding)
            if isinstance(node, (ast.If, ast.IfExp, ast.Match, ast.While)):
                branch_findings.append(finding)
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "verify")
                or (isinstance(node.func, ast.Name) and node.func.id == "verify")
            ):
                verifier_findings.append(finding)
    source_sha256 = hashlib.sha256(
        "\n".join(source_parts).encode("utf-8")
    ).hexdigest()
    passed = not (
        modulo_findings
        or equality_findings
        or branch_findings
        or verifier_findings
    )
    return A1SourceClosureReport(
        claimed_symbols=tuple(name for name, _ in symbols),
        source_sha256=source_sha256,
        python_modulo_findings=tuple(modulo_findings),
        python_equality_findings=tuple(equality_findings),
        data_branch_findings=tuple(branch_findings),
        verifier_call_findings=tuple(verifier_findings),
        passed=passed,
    )
