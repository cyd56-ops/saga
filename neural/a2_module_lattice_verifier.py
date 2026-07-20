"""路线 A A2 的 research-only module-lattice fixed verifier。"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import inspect
import textwrap
from typing import Callable, Sequence

from neural.a1_toy_verifier import audit_a1_claimed_source
from neural.fixed_toolchain import (
    BinaryInputGuard,
    FIXED_PROJECTOR_CORE_ID,
    FixedBooleanAggregator,
    FixedBoundedModulo,
    FixedEquality,
    FixedRangeNormCheck,
    MAX_EXACT_FLOAT_INTEGER,
    RangeNormTrace,
    TinyNegacyclicProjector,
)
from neural.shamir_layers import FixedLinear, FixedSum
from neural.verifier_wrapper import BitLayout, bits_to_bytes
from pq.toy_module_lattice import (
    ModuleMatrix,
    ModuleVector,
    ToyModuleLatticeParameters,
    ToyModuleLatticeSignatureScheme,
)


@dataclass(frozen=True)
class A2ModuleLatticeBoundary:
    """声明 A2 环算术 claim、预处理、软件 guard 与排除项。"""

    claimed_fixed_circuit_steps: tuple[str, ...]
    deterministic_preprocessing_steps: tuple[str, ...]
    software_guard_steps: tuple[str, ...]
    excluded_from_claim: tuple[str, ...]
    deterministic_hard_gate_steps: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        """导出机器可读 A2 circuit boundary。"""

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
class A2ModuleLatticeComplexity:
    """记录 A2 module/ring 结构、固定参数、ReLU 调用和数值界限。"""

    ring_degree: int
    module_rank: int
    modulus: int
    projector_backend: str
    projector_core_id: str
    negacyclic_projector_count: int
    modulo_threshold_count: int
    fixed_layer_depth: int
    structural_fixed_parameter_count: int
    fixed_relu_calls_per_verification: int
    max_module_projection_abs: int
    max_intermediate_abs: int
    exact_integer_limit: int = MAX_EXACT_FLOAT_INTEGER

    def as_dict(self) -> dict[str, object]:
        """导出 A2 结构、环 backend 和精确整数复杂度 manifest。"""

        return {
            "ring_degree": self.ring_degree,
            "module_rank": self.module_rank,
            "modulus": self.modulus,
            "projector_backend": self.projector_backend,
            "projector_core_id": self.projector_core_id,
            "negacyclic_projector_count": self.negacyclic_projector_count,
            "modulo_threshold_count": self.modulo_threshold_count,
            "fixed_layer_depth": self.fixed_layer_depth,
            "structural_fixed_parameter_count": (
                self.structural_fixed_parameter_count
            ),
            "fixed_relu_calls_per_verification": (
                self.fixed_relu_calls_per_verification
            ),
            "max_module_projection_abs": self.max_module_projection_abs,
            "max_intermediate_abs": self.max_intermediate_abs,
            "exact_integer_limit": self.exact_integer_limit,
        }


@dataclass(frozen=True)
class A2ModuleLatticeTrace:
    """记录 A2 relation 的 module 输入、环投影、范围检查和硬接受位。"""

    public_target: ModuleVector
    response: ModuleVector
    challenge: ModuleVector
    challenge_source: str
    input_range_traces: tuple[RangeNormTrace, ...]
    response_projection: ModuleVector
    challenge_projection: ModuleVector
    projection_differences: ModuleVector
    recovered_target: ModuleVector
    equality_bits: tuple[int, ...]
    equality_accept: int
    challenge_weight_bit: int
    accept: int

    def as_dict(self) -> dict[str, object]:
        """导出不含私钥的 A2 fixed relation trace。"""

        def nested(vector: ModuleVector) -> list[list[int]]:
            return [list(polynomial) for polynomial in vector]

        return {
            "public_target": nested(self.public_target),
            "response": nested(self.response),
            "challenge": nested(self.challenge),
            "challenge_source": self.challenge_source,
            "input_range_traces": [
                trace.as_dict() for trace in self.input_range_traces
            ],
            "response_projection": nested(self.response_projection),
            "challenge_projection": nested(self.challenge_projection),
            "projection_differences": nested(self.projection_differences),
            "recovered_target": nested(self.recovered_target),
            "equality_bits": list(self.equality_bits),
            "equality_accept": self.equality_accept,
            "challenge_weight_bit": self.challenge_weight_bit,
            "accept": self.accept,
        }


@dataclass(frozen=True)
class A2SourceClosureReport:
    """记录 A2 claimed evaluator 的禁用运算和数据分支审计结果。"""

    claimed_symbols: tuple[str, ...]
    source_sha256: str
    python_modulo_findings: tuple[str, ...]
    python_equality_findings: tuple[str, ...]
    data_branch_findings: tuple[str, ...]
    verifier_call_findings: tuple[str, ...]
    passed: bool

    def as_dict(self) -> dict[str, object]:
        """导出 A2 claimed-source closure evidence。"""

        return {
            "claimed_symbols": list(self.claimed_symbols),
            "source_sha256": self.source_sha256,
            "python_modulo_findings": list(self.python_modulo_findings),
            "python_equality_findings": list(self.python_equality_findings),
            "data_branch_findings": list(self.data_branch_findings),
            "verifier_call_findings": list(self.verifier_call_findings),
            "passed": self.passed,
        }


class A2ModuleLatticeVerifierCore:
    """编译 ``A(z-c) mod q = t`` 的 fixed negacyclic-convolution core。"""

    requires_grad = False

    def __init__(
        self,
        matrix: ModuleMatrix,
        parameters: ToyModuleLatticeParameters,
    ) -> None:
        """固定公开 module matrix，并组合环投影、mod、等值和范数 gadget。"""

        self.parameters = parameters
        self.ring_degree = parameters.ring_degree
        self.module_rank = parameters.module_rank
        self.module_width = parameters.module_width
        self.modulus = parameters.modulus
        normalized_matrix = self._validate_matrix(matrix)
        self.response_input_abs = parameters.response_bound + 1
        self.challenge_input_abs = 2
        projector_input_abs = max(
            self.response_input_abs,
            self.challenge_input_abs,
        )
        self.projectors = tuple(
            tuple(
                TinyNegacyclicProjector(
                    multiplier,
                    max_input_abs=projector_input_abs,
                )
                for multiplier in row
            )
            for row in normalized_matrix
        )
        self.module_sum = FixedSum()
        self.subtract = FixedLinear((1.0, -1.0))
        row_projection_bounds = tuple(
            sum(projector.complexity().max_output_abs for projector in row)
            for row in self.projectors
        )
        self.max_module_projection_abs = max(row_projection_bounds)
        self.modulo = FixedBoundedModulo(
            self.modulus,
            min_input=-(2 * self.max_module_projection_abs),
            max_input=2 * self.max_module_projection_abs,
        )
        self.equality = FixedEquality(max_abs=self.modulus)
        self.public_range = FixedRangeNormCheck(
            self.module_width,
            input_max_abs=self.modulus,
            coordinate_bound=self.modulus - 1,
            l1_bound=self.module_width * (self.modulus - 1),
        )
        self.response_range = FixedRangeNormCheck(
            self.module_width,
            input_max_abs=self.response_input_abs,
            coordinate_bound=parameters.response_bound,
            l1_bound=parameters.response_l1_bound,
        )
        self.challenge_range = FixedRangeNormCheck(
            self.module_width,
            input_max_abs=self.challenge_input_abs,
            coordinate_bound=1,
            l1_bound=1,
        )
        self.challenge_weight_equality = FixedEquality(
            max_abs=self.module_width * self.challenge_input_abs,
        )
        self.equality_aggregator = FixedBooleanAggregator(self.module_width)
        self.final_aggregator = FixedBooleanAggregator(6)

    def _validate_matrix(self, matrix: ModuleMatrix) -> ModuleMatrix:
        """校验 module matrix 的 rank、degree、原生整数与 canonical ``Z_q`` 域。"""

        if len(matrix) != self.module_rank:
            raise ValueError("A2 matrix has the wrong module row count")
        normalized_rows: list[tuple[tuple[int, ...], ...]] = []
        for row in matrix:
            if len(row) != self.module_rank:
                raise ValueError("A2 matrix must be square over the module rank")
            normalized_polynomials: list[tuple[int, ...]] = []
            for polynomial in row:
                if len(polynomial) != self.ring_degree:
                    raise ValueError("A2 matrix polynomial has the wrong degree")
                checked: list[int] = []
                for coefficient in polynomial:
                    if type(coefficient) is not int:
                        raise TypeError("A2 matrix coefficients must be integers")
                    if coefficient < 0 or coefficient >= self.modulus:
                        raise ValueError("A2 matrix coefficients must belong to Z_q")
                    checked.append(coefficient)
                normalized_polynomials.append(tuple(checked))
            normalized_rows.append(tuple(normalized_polynomials))
        return tuple(normalized_rows)

    def _validated_vector(
        self,
        values: Sequence[Sequence[int]],
        *,
        name: str,
        min_value: int,
        max_value: int,
    ) -> ModuleVector:
        """校验 A2 软件入口的 module/ring 形状、类型和编译域。"""

        if len(values) != self.module_rank:
            raise ValueError(f"{name} has the wrong module rank")
        normalized: list[tuple[int, ...]] = []
        for polynomial in values:
            if len(polynomial) != self.ring_degree:
                raise ValueError(f"{name} has the wrong ring degree")
            checked: list[int] = []
            for value in polynomial:
                if type(value) is not int:
                    raise TypeError(f"{name} coefficients must be built-in integers")
                if value < min_value or value > max_value:
                    raise ValueError(f"{name} exceeds the compiled coefficient domain")
                checked.append(value)
            normalized.append(tuple(checked))
        return tuple(normalized)

    def trace_relation(
        self,
        public_target: Sequence[Sequence[int]],
        response: Sequence[Sequence[int]],
        challenge: Sequence[Sequence[int]],
    ) -> A2ModuleLatticeTrace:
        """校验软件 contract 后执行完整 A2 fixed arithmetic core。"""

        public_values = self._validated_vector(
            public_target,
            name="public_target",
            min_value=0,
            max_value=self.modulus,
        )
        response_values = self._validated_vector(
            response,
            name="response",
            min_value=-self.response_input_abs,
            max_value=self.response_input_abs,
        )
        challenge_values = self._validated_vector(
            challenge,
            name="challenge",
            min_value=-self.challenge_input_abs,
            max_value=self.challenge_input_abs,
        )
        return self._trace_fixed(public_values, response_values, challenge_values)

    def _project_module_fixed(self, values: ModuleVector) -> ModuleVector:
        # projectors 的 module/ring 形状在构造期固定，运行期只执行固定行投影与求和。
        products = tuple(
            tuple(
                projector.core._project_fixed(values[column_index])
                for column_index, projector in enumerate(row)
            )
            for row in self.projectors
        )
        return tuple(
            tuple(
                int(
                    self.module_sum(
                        product[coefficient_index] for product in row_products
                    )
                )
                for coefficient_index in range(self.ring_degree)
            )
            for row_products in products
        )

    def _trace_fixed(
        self,
        public_target: ModuleVector,
        response: ModuleVector,
        challenge: ModuleVector,
    ) -> A2ModuleLatticeTrace:
        # claimed 路径只组合固定 projector/gadget，不按输入数据选择控制流。
        public_flat = tuple(value for polynomial in public_target for value in polynomial)
        response_flat = tuple(value for polynomial in response for value in polynomial)
        challenge_flat = tuple(value for polynomial in challenge for value in polynomial)
        public_range = self.public_range._trace_fixed(public_flat)
        response_range = self.response_range._trace_fixed(response_flat)
        challenge_range = self.challenge_range._trace_fixed(challenge_flat)
        response_projection = self._project_module_fixed(response)
        challenge_projection = self._project_module_fixed(challenge)
        differences = tuple(
            tuple(
                int(self.subtract((left, right)))
                for left, right in zip(left_poly, right_poly, strict=True)
            )
            for left_poly, right_poly in zip(
                response_projection,
                challenge_projection,
                strict=True,
            )
        )
        recovered_flat = tuple(
            self.modulo._evaluate_fixed(value)
            for polynomial in differences
            for value in polynomial
        )
        recovered_target = tuple(
            tuple(
                recovered_flat[
                    row_index * self.ring_degree : (row_index + 1)
                    * self.ring_degree
                ]
            )
            for row_index in range(self.module_rank)
        )
        recovered_range = self.public_range._trace_fixed(recovered_flat)
        equality_bits = tuple(
            self.equality._evaluate_fixed(recovered, expected)
            for recovered, expected in zip(
                recovered_flat,
                public_flat,
                strict=True,
            )
        )
        equality_accept = self.equality_aggregator._evaluate_fixed(equality_bits)
        challenge_weight_bit = self.challenge_weight_equality._evaluate_fixed(
            challenge_range.l1_norm,
            1,
        )
        accept = self.final_aggregator._evaluate_fixed(
            (
                public_range.accept,
                response_range.accept,
                challenge_range.accept,
                recovered_range.accept,
                equality_accept,
                challenge_weight_bit,
            )
        )
        return A2ModuleLatticeTrace(
            public_target=public_target,
            response=response,
            challenge=challenge,
            challenge_source="caller_supplied_preprocessed_module_vector",
            input_range_traces=(
                public_range,
                response_range,
                challenge_range,
                recovered_range,
            ),
            response_projection=response_projection,
            challenge_projection=challenge_projection,
            projection_differences=differences,
            recovered_target=recovered_target,
            equality_bits=equality_bits,
            equality_accept=equality_accept,
            challenge_weight_bit=challenge_weight_bit,
            accept=accept,
        )

    def verify_relation(
        self,
        public_target: Sequence[Sequence[int]],
        response: Sequence[Sequence[int]],
        challenge: Sequence[Sequence[int]],
    ) -> int:
        """返回硬 ``0/1``，形状、类型、数值或 fixed arithmetic 错误均拒绝。"""

        try:
            return self.trace_relation(public_target, response, challenge).accept
        except (ArithmeticError, TypeError, ValueError):
            return 0

    def complexity(self) -> A2ModuleLatticeComplexity:
        """汇总环 projector、modulo、范围与聚合的结构和数值界限。"""

        projector_complexities = tuple(
            projector.complexity()
            for row in self.projectors
            for projector in row
        )
        modulo_complexity = self.modulo.complexity()
        projector_parameters = sum(
            complexity.fixed_parameter_count
            for complexity in projector_complexities
        )
        structural_parameters = (
            projector_parameters
            + modulo_complexity.fixed_parameter_count
            + 3  # projection subtraction
            + 13  # equality
            + 13  # challenge L1 == 1 equality
            + 84  # public/response/challenge range-norm structures
            + 14  # equality/final Boolean aggregators
        )
        range_relu_calls = (16 * self.module_width) + 16
        relu_calls = (
            (2 * modulo_complexity.threshold_count * self.module_width)
            + (4 * self.module_width)
            + range_relu_calls
            + 8
        )
        max_intermediate = max(
            2 * self.max_module_projection_abs,
            modulo_complexity.max_intermediate_abs,
            self.module_width * self.modulus,
        )
        return A2ModuleLatticeComplexity(
            ring_degree=self.ring_degree,
            module_rank=self.module_rank,
            modulus=self.modulus,
            projector_backend=TinyNegacyclicProjector.backend,
            projector_core_id=FIXED_PROJECTOR_CORE_ID,
            negacyclic_projector_count=len(projector_complexities),
            modulo_threshold_count=modulo_complexity.threshold_count,
            fixed_layer_depth=25,
            structural_fixed_parameter_count=structural_parameters,
            fixed_relu_calls_per_verification=relu_calls,
            max_module_projection_abs=self.max_module_projection_abs,
            max_intermediate_abs=max_intermediate,
        )

    def submodules(self) -> tuple[object, ...]:
        """返回 A2 arithmetic core 的全部固定、不可训练子模块。"""

        return (
            *(projector for row in self.projectors for projector in row),
            self.module_sum,
            self.subtract,
            self.modulo,
            self.equality,
            self.public_range,
            self.response_range,
            self.challenge_range,
            self.challenge_weight_equality,
            self.equality_aggregator,
            self.final_aggregator,
        )


class FixedModuleLatticeVerifier:
    """包装 A2 fixed ring core，并显式保留 byte parse/hash 预处理边界。

    verifier 和 reference scheme 均为 research-only，不提供生产后量子安全。
    """

    BOUNDARY = A2ModuleLatticeBoundary(
        claimed_fixed_circuit_steps=(
            "fixed_negacyclic_matrix_projection",
            "fixed_module_component_sum",
            "projection_subtraction",
            "bounded_integer_modulo_relu",
            "bounded_integer_equality_relu",
            "coefficient_range_and_l1_norm_relu",
            "fixed_boolean_aggregation_relu",
        ),
        deterministic_preprocessing_steps=(
            "compile_time_negacyclic_matrix_expansion",
            "strict_uint16_public_target_decoding",
            "strict_int16_response_decoding",
            "sha256_one_hot_module_challenge_derivation",
            "strict_binary_bit_packing",
        ),
        software_guard_steps=(
            "fixed_width_byte_layout_validation",
            "strict_binary_domain_validation",
            "bounded_builtin_integer_module_validation",
        ),
        excluded_from_claim=(
            "sha256_hash_to_challenge_circuit",
            "byte_parser_circuit",
            "ntt_backend",
            "ml_dsa_verifier",
            "production_post_quantum_security",
        ),
    )

    def __init__(
        self,
        scheme: ToyModuleLatticeSignatureScheme,
        message_bytes: int,
    ) -> None:
        """保存公开 research 参数并编译不含签名私钥的 A2 ring core。"""

        if type(message_bytes) is not int or message_bytes <= 0:
            raise ValueError("message_bytes must be a positive built-in integer")
        self.scheme = scheme
        self.layout = BitLayout(
            public_key_bytes=scheme.public_key_bytes,
            message_bytes=message_bytes,
            signature_bytes=scheme.signature_bytes,
        )
        self.binary_guard = BinaryInputGuard()
        self.core = A2ModuleLatticeVerifierCore(
            scheme.public_module_matrix(),
            scheme.parameters,
        )

    def compilation_boundary(self) -> A2ModuleLatticeBoundary:
        """返回 A2 ring arithmetic claim 与 parse/hash/software guard 边界。"""

        return self.BOUNDARY

    def trace_verification(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> A2ModuleLatticeTrace:
        """执行显式 parse/hash 预处理，再返回 A2 fixed relation trace。"""

        if type(public_key) is not bytes or type(message) is not bytes:
            raise TypeError("public_key and message must be built-in bytes")
        if type(signature) is not bytes:
            raise TypeError("signature must be built-in bytes")
        if len(message) != self.layout.message_bytes:
            raise ValueError("message length does not match the compiled layout")
        trace = self.core.trace_relation(
            self.scheme.decode_public_target(public_key),
            self.scheme.decode_response(signature),
            self.scheme.challenge_vector(message),
        )
        return A2ModuleLatticeTrace(
            public_target=trace.public_target,
            response=trace.response,
            challenge=trace.challenge,
            challenge_source="deterministic_sha256_preprocessing:not_neural_hash",
            input_range_traces=trace.input_range_traces,
            response_projection=trace.response_projection,
            challenge_projection=trace.challenge_projection,
            projection_differences=trace.projection_differences,
            recovered_target=trace.recovered_target,
            equality_bits=trace.equality_bits,
            equality_accept=trace.equality_accept,
            challenge_weight_bit=trace.challenge_weight_bit,
            accept=trace.accept,
        )

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """对 byte 编码材料返回硬 ``0/1``，parse/core 错误均 fail-closed。"""

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
        """严格校验二进制域，再把三段公开 bit material 交给 A2 路径。"""

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

    def complexity(self) -> A2ModuleLatticeComplexity:
        """返回 A2 ring arithmetic core 的结构、ReLU 与数值复杂度。"""

        return self.core.complexity()

    def submodules(self) -> tuple[object, ...]:
        """返回二进制软件 guard 与不含私钥的 A2 fixed arithmetic core。"""

        return (self.binary_guard, self.core)


def _a2_claimed_evaluators() -> tuple[tuple[str, Callable[..., object]], ...]:
    """返回 A2 新增 module/ring evaluator 的静态审计符号。"""

    return (
        (
            "A2ModuleLatticeVerifierCore._project_module_fixed",
            A2ModuleLatticeVerifierCore._project_module_fixed,
        ),
        (
            "A2ModuleLatticeVerifierCore._trace_fixed",
            A2ModuleLatticeVerifierCore._trace_fixed,
        ),
    )


def audit_a2_claimed_source() -> A2SourceClosureReport:
    """确认 A2 与继承 gadget 不含 ``%``、普通等值、数据分支或 verifier 调用。"""

    inherited = audit_a1_claimed_source()
    modulo_findings = list(inherited.python_modulo_findings)
    equality_findings = list(inherited.python_equality_findings)
    branch_findings = list(inherited.data_branch_findings)
    verifier_findings = list(inherited.verifier_call_findings)
    source_parts = [f"A1:{inherited.source_sha256}"]
    symbols = _a2_claimed_evaluators()
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
    return A2SourceClosureReport(
        claimed_symbols=(*inherited.claimed_symbols, *(name for name, _ in symbols)),
        source_sha256=source_sha256,
        python_modulo_findings=tuple(modulo_findings),
        python_equality_findings=tuple(equality_findings),
        data_branch_findings=tuple(branch_findings),
        verifier_call_findings=tuple(verifier_findings),
        passed=passed,
    )
