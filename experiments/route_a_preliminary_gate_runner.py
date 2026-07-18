"""生成路线 A A0.5 的 AG1、AG4-AG8 preliminary gate evidence。"""

from __future__ import annotations

import argparse
from itertools import product
import json
from pathlib import Path
import time
import tracemalloc
from typing import Callable, Sequence

from neural import (
    MAX_EXACT_FLOAT_INTEGER,
    MASK,
    BinaryInputGuard,
    DenseFixedProjector,
    FixedBooleanAggregator,
    FixedEquality,
    FixedModReduce,
    FixedProjector,
    FixedRangeNormCheck,
    TinyNegacyclicProjector,
)


def _dense_reference(
    matrix: tuple[tuple[int, ...], ...],
    values: tuple[int, ...],
) -> tuple[int, ...]:
    """用普通整数矩阵乘法提供 dense reference oracle。"""
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
    """按 ``x^n = -1`` 提供 tiny negacyclic reference oracle。"""
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


def _is_rejected(operation: Callable[[], object]) -> bool:
    """返回输入边界操作是否以预期的类型或数值异常拒绝。"""
    try:
        operation()
    except (TypeError, ValueError):
        return True
    return False


def _build_gadget_evidence() -> dict[str, object]:
    """穷举小型 gadget 定义域并汇总 mismatch 数。"""
    mod = FixedModReduce(7, max_input_abs=16)
    equality = FixedEquality(max_abs=3)
    aggregator = FixedBooleanAggregator(3)
    range_norm = FixedRangeNormCheck(
        2,
        input_max_abs=3,
        coordinate_bound=2,
        l1_bound=3,
    )
    checks: dict[str, tuple[int, int]] = {}

    mod_values = tuple(range(-16, 17))
    checks["mod_reduce"] = (
        len(mod_values),
        sum(mod(value) != value % 7 for value in mod_values),
    )
    equality_values = tuple(product(range(-3, 4), repeat=2))
    checks["equality"] = (
        len(equality_values),
        sum(
            equality(left, right) != int(left == right)
            for left, right in equality_values
        ),
    )
    bit_values = tuple(product((0, 1), repeat=3))
    checks["boolean_aggregator"] = (
        len(bit_values),
        sum(aggregator(bits) != int(all(bits)) for bits in bit_values),
    )
    vector_values = tuple(product(range(-3, 4), repeat=2))
    checks["range_norm"] = (
        len(vector_values),
        sum(
            range_norm(values)
            != int(
                all(abs(value) <= 2 for value in values)
                and sum(abs(value) for value in values) <= 3
            )
            for values in vector_values
        ),
    )
    return {
        "case_count": sum(case_count for case_count, _ in checks.values()),
        "mismatch_count": sum(mismatches for _, mismatches in checks.values()),
        "gadgets": {
            name: {"case_count": counts[0], "mismatch_count": counts[1]}
            for name, counts in checks.items()
        },
    }


def _build_input_boundary_evidence() -> dict[str, object]:
    """验证二进制、实数、NaN/Inf、类型和越界输入均有明确结果。"""
    guard = BinaryInputGuard()
    equality = FixedEquality(max_abs=2)
    projector = DenseFixedProjector(((1, 2),), max_input_abs=2)
    checks = {
        "binary_integer_domain": guard((0, 1)) == (0, 1),
        "binary_real_endpoints": guard((0.0, 1.0)) == (0, 1),
        "reject_real_midpoint": _is_rejected(lambda: guard((0.5,))),
        "reject_nan": _is_rejected(lambda: guard((float("nan"),))),
        "reject_positive_inf": _is_rejected(lambda: guard((float("inf"),))),
        "reject_negative_inf": _is_rejected(lambda: guard((float("-inf"),))),
        "reject_bool": _is_rejected(lambda: guard((True,))),
        "reject_equality_float": _is_rejected(lambda: equality(1.0, 1)),
        "reject_equality_out_of_range": _is_rejected(lambda: equality(3, 1)),
        "reject_projector_out_of_range": _is_rejected(
            lambda: projector.project((3, 0))
        ),
    }
    return {
        "checks": checks,
        "all_passed": all(checks.values()),
    }


def _build_mutation_evidence() -> dict[str, object]:
    """构造删除关键 gadget 时能改变安全结果的最小 witness。"""
    range_check = FixedRangeNormCheck(
        2,
        input_max_abs=4,
        coordinate_bound=2,
        l1_bound=8,
    )
    norm_check = FixedRangeNormCheck(
        2,
        input_max_abs=4,
        coordinate_bound=4,
        l1_bound=3,
    )
    checks = {
        "delete_mod_reduce": FixedModReduce(7, max_input_abs=8)(8) != 8,
        "delete_equality": FixedEquality(max_abs=2)(1, 2) != 1,
        "delete_range_check": range_check((3, 0)) != 1,
        "delete_norm_check": norm_check((2, 2)) != 1,
        "delete_mask": MASK()((0.5,)) != 0.0,
        "delete_aggregation": FixedBooleanAggregator(3)((1, 0, 1)) != 1,
    }
    return {
        "witnesses": checks,
        "detected_count": sum(checks.values()),
        "mutation_count": len(checks),
        "all_detected": all(checks.values()),
    }


def _measure_projector(
    projector: FixedProjector,
    cases: Sequence[tuple[int, ...]],
    reference: Callable[[tuple[int, ...]], tuple[int, ...]],
) -> dict[str, object]:
    """测量 projector 批次延迟、峰值 Python 内存和 reference mismatch。"""
    tracemalloc.start()
    started_at = time.perf_counter()
    mismatches = sum(
        projector.project(values) != reference(values) for values in cases
    )
    latency_seconds = time.perf_counter() - started_at
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return projector.manifest(
        reference_equivalence_cases=len(cases),
        reference_mismatches=mismatches,
        latency_seconds=latency_seconds,
        peak_memory_bytes=peak_memory_bytes,
    ).as_dict()


def _build_projector_evidence() -> dict[str, object]:
    """生成 dense 与 tiny negacyclic 的迁移、等价和复杂度 evidence。"""
    dense_matrix = ((2, -1, 0), (1, 3, -2))
    dense = DenseFixedProjector(dense_matrix, max_input_abs=2)
    dense_cases = tuple(product(range(-2, 3), repeat=3))
    dense_manifest = _measure_projector(
        dense,
        dense_cases,
        lambda values: _dense_reference(dense_matrix, values),
    )

    multiplier = (1, -2, 0, 1)
    ring = TinyNegacyclicProjector(multiplier, max_input_abs=1)
    ring_cases = tuple(product((-1, 0, 1), repeat=4))
    ring_manifest = _measure_projector(
        ring,
        ring_cases,
        lambda values: _negacyclic_reference(multiplier, values),
    )
    manifests = (dense_manifest, ring_manifest)
    same_core = dense.core.core_id == ring.core.core_id
    all_equivalent = all(
        manifest["reference_mismatches"] == 0 for manifest in manifests
    )
    numeric_bounds_valid = all(
        manifest["complexity"]["max_output_abs"]
        <= manifest["complexity"]["exact_integer_limit"]
        for manifest in manifests
    )
    return {
        "same_core_id": same_core,
        "all_reference_equivalent": all_equivalent,
        "numeric_bounds_valid": numeric_bounds_valid,
        "manifests": list(manifests),
    }


def build_preliminary_gate_report() -> dict[str, object]:
    """构造 A0.5 preliminary report，明确不关闭 A1 专属 AG2/AG3。"""
    gadget_evidence = _build_gadget_evidence()
    input_evidence = _build_input_boundary_evidence()
    mutation_evidence = _build_mutation_evidence()
    projector_evidence = _build_projector_evidence()
    manifests = projector_evidence["manifests"]
    manifest_fields_complete = all(
        {
            "boundary",
            "complexity",
            "latency_seconds",
            "peak_memory_bytes",
            "reference_equivalence_cases",
            "reference_mismatches",
        }.issubset(manifest)
        for manifest in manifests
    )
    statuses = {
        "AG1": "preliminary_pass"
        if gadget_evidence["mismatch_count"] == 0
        else "fail",
        "AG2": "open_requires_a1_end_to_end_equivalence",
        "AG3": "open_requires_a1_circuit_closure",
        "AG4": "preliminary_pass" if input_evidence["all_passed"] else "fail",
        "AG5": "preliminary_pass"
        if projector_evidence["numeric_bounds_valid"]
        else "fail",
        "AG6": "preliminary_pass"
        if mutation_evidence["all_detected"]
        else "fail",
        "AG7": "preliminary_pass"
        if (
            projector_evidence["same_core_id"]
            and projector_evidence["all_reference_equivalent"]
        )
        else "fail",
        "AG8": "preliminary_pass" if manifest_fields_complete else "fail",
    }
    preliminary_keys = ("AG1", "AG4", "AG5", "AG6", "AG7", "AG8")
    return {
        "schema_version": "saga-route-a-a0-5-preliminary-gates-v1",
        "route": "A",
        "stage": "A0.5",
        "research_only": True,
        "production_ready": False,
        "gate_status": statuses,
        "preliminary_gates_passed": all(
            statuses[key] == "preliminary_pass" for key in preliminary_keys
        ),
        "all_ag1_ag8_passed": False,
        "open_gate_reasons": {
            "AG2": "A0.5 has no end-to-end A1 verifier closure",
            "AG3": (
                "FixedModReduce still declares python_integer_modulo_a0_5; "
                "A1 must remove ordinary claimed-circuit operations"
            ),
        },
        "gadget_evidence": gadget_evidence,
        "input_boundary_evidence": input_evidence,
        "mutation_evidence": mutation_evidence,
        "projector_evidence": projector_evidence,
        "exact_integer_limit": MAX_EXACT_FLOAT_INTEGER,
    }


def write_preliminary_gate_report(
    report: dict[str, object],
    output_path: Path,
) -> None:
    """把 preliminary gate report 写为稳定缩进 JSON。"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析可选 JSON 输出路径。"""
    parser = argparse.ArgumentParser(
        description="Generate Route A A0.5 preliminary AG evidence.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the machine-readable JSON report.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """运行 preliminary gate evidence，并在任一阶段门失败时返回非零。"""
    args = parse_args(argv)
    report = build_preliminary_gate_report()
    if args.output is not None:
        write_preliminary_gate_report(report, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["preliminary_gates_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
