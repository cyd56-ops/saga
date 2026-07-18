"""生成路线 A A1 toy arithmetic closure 的最终 AG1-AG8 gate report。"""

from __future__ import annotations

import argparse
from itertools import product
import json
from pathlib import Path
import random
import time
import tracemalloc
from typing import Sequence

from experiments.route_a_preliminary_gate_runner import (
    build_preliminary_gate_report,
)
from neural import (
    FixedBoundedModulo,
    FullReLUToyLWEVerifier,
    audit_a1_claimed_source,
)
from pq import ToyLWEParameters, ToyLWESignatureScheme


def _encode_vector(values: Sequence[int]) -> bytes:
    """把 toy coefficient vector 编码为 little-endian uint16 bytes。"""
    return b"".join(value.to_bytes(2, "little") for value in values)


def _build_a1_modulo_evidence() -> dict[str, object]:
    """穷举较宽 signed domain，验证 A1 ReLU modulo 与整数 oracle 一致。"""
    gadget = FixedBoundedModulo(17, min_input=-512, max_input=512)
    values = tuple(range(-512, 513))
    mismatches = sum(gadget(value) != value % 17 for value in values)
    return {
        "case_count": len(values),
        "mismatch_count": mismatches,
        "complexity": gadget.complexity().as_dict(),
        "ordinary_python_modulo_in_claimed_evaluator": False,
    }


def _build_tiny_exhaustive_evidence() -> dict[str, object]:
    """穷举 dimension=2、q=3 与完整一字节消息域的端到端关系。"""
    parameters = ToyLWEParameters(dimension=2, modulus=3, matrix_seed=17)
    scheme = ToyLWESignatureScheme(seed=23, parameters=parameters)
    verifier = FullReLUToyLWEVerifier(scheme, message_bytes=1)
    vectors = tuple(product(range(parameters.modulus), repeat=parameters.dimension))
    case_count = 0
    mismatch_count = 0
    for public_vector in vectors:
        public_key = _encode_vector(public_vector)
        for message_value in range(256):
            message = bytes((message_value,))
            for signature_vector in vectors:
                signature = _encode_vector(signature_vector)
                expected = int(scheme.verify(public_key, message, signature))
                actual = verifier.verify_bytes(public_key, message, signature)
                case_count += 1
                mismatch_count += int(actual != expected)
    return {
        "parameters": {
            "dimension": parameters.dimension,
            "modulus": parameters.modulus,
            "message_bytes": 1,
        },
        "case_count": case_count,
        "mismatch_count": mismatch_count,
        "complete_domains": (
            "all_zq_public_vectors",
            "all_one_byte_messages",
            "all_zq_signature_vectors",
        ),
    }


def _build_normal_differential_evidence() -> dict[str, object]:
    """在默认参数上运行固定种子的 valid/tampered/arbitrary 差分 corpus。"""
    scheme = ToyLWESignatureScheme(seed=1701)
    key_pair = scheme.keygen()
    verifier = FullReLUToyLWEVerifier(scheme, message_bytes=32)
    rng = random.Random(20260718)
    cases: list[tuple[bytes, bytes, bytes]] = []
    for index in range(8):
        message = bytes(rng.randrange(256) for _ in range(32))
        signature = scheme.sign(key_pair.secret_key, message)
        cases.append((key_pair.public_key, message, signature))
        tampered_vector = scheme.decode_signature_vector(signature)
        coordinate = index % scheme.parameters.dimension
        tampered_vector[coordinate] = (
            tampered_vector[coordinate] + 1
        ) % scheme.parameters.modulus
        cases.append(
            (
                key_pair.public_key,
                message,
                _encode_vector(tampered_vector),
            )
        )
    for _ in range(16):
        public_vector = tuple(
            rng.randrange(scheme.parameters.modulus)
            for _ in range(scheme.parameters.dimension)
        )
        signature_vector = tuple(
            rng.randrange(scheme.parameters.modulus)
            for _ in range(scheme.parameters.dimension)
        )
        message = bytes(rng.randrange(256) for _ in range(32))
        cases.append(
            (
                _encode_vector(public_vector),
                message,
                _encode_vector(signature_vector),
            )
        )

    tracemalloc.start()
    started_at = time.perf_counter()
    mismatch_count = sum(
        verifier.verify_bytes(public_key, message, signature)
        != int(scheme.verify(public_key, message, signature))
        for public_key, message, signature in cases
    )
    latency_seconds = time.perf_counter() - started_at
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "seed": 20260718,
        "case_count": len(cases),
        "valid_case_count": 8,
        "tampered_case_count": 8,
        "arbitrary_case_count": 16,
        "mismatch_count": mismatch_count,
        "batch_latency_seconds": latency_seconds,
        "peak_memory_bytes": peak_memory_bytes,
        "complexity": verifier.complexity().as_dict(),
        "boundary": verifier.compilation_boundary().as_dict(),
    }


def build_a1_gate_report() -> dict[str, object]:
    """汇总 A0.5 preliminary 与 A1 closure，逐项判定 AG1-AG8。"""
    preliminary = build_preliminary_gate_report()
    modulo = _build_a1_modulo_evidence()
    tiny = _build_tiny_exhaustive_evidence()
    normal = _build_normal_differential_evidence()
    source_closure = audit_a1_claimed_source().as_dict()
    preliminary_status = preliminary["gate_status"]
    a1_complexity = normal["complexity"]

    gate_checks = {
        "AG1": (
            preliminary["gadget_evidence"]["mismatch_count"] == 0
            and modulo["mismatch_count"] == 0
        ),
        "AG2": (
            tiny["mismatch_count"] == 0
            and normal["mismatch_count"] == 0
        ),
        "AG3": source_closure["passed"] is True,
        "AG4": preliminary_status["AG4"] == "preliminary_pass",
        "AG5": (
            preliminary_status["AG5"] == "preliminary_pass"
            and a1_complexity["max_intermediate_abs"]
            <= a1_complexity["exact_integer_limit"]
        ),
        "AG6": preliminary_status["AG6"] == "preliminary_pass",
        "AG7": preliminary_status["AG7"] == "preliminary_pass",
        "AG8": (
            preliminary_status["AG8"] == "preliminary_pass"
            and normal["batch_latency_seconds"] >= 0.0
            and normal["peak_memory_bytes"] > 0
        ),
    }
    gate_status = {
        gate: "pass" if passed else "fail"
        for gate, passed in gate_checks.items()
    }
    all_passed = all(gate_checks.values())
    return {
        "schema_version": "saga-route-a-a1-gates-v1",
        "route": "A",
        "stage": "A1-toy-arithmetic-closure",
        "research_only": True,
        "production_ready": False,
        "parse_hash_inside_claimed_circuit": False,
        "gate_status": gate_status,
        "all_ag1_ag8_passed": all_passed,
        "a2_stage_gate_open": all_passed,
        "a0_5_preliminary": preliminary,
        "a1_modulo_evidence": modulo,
        "a1_tiny_exhaustive_evidence": tiny,
        "a1_normal_differential_evidence": normal,
        "a1_source_closure": source_closure,
        "claim_limits": (
            "toy_lwe_research_only",
            "fixed_arithmetic_core_only",
            "byte_parse_and_sha256_challenge_are_preprocessing",
            "not_production_post_quantum_security",
        ),
    }


def write_a1_gate_report(report: dict[str, object], output_path: Path) -> None:
    """把 A1 gate report 写为稳定缩进 JSON。"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析 A1 gate runner 的可选 JSON 输出路径。"""
    parser = argparse.ArgumentParser(
        description="Generate the Route A A1 final AG1-AG8 report.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the machine-readable JSON report.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """运行 A1 gate report；任一 AG gate 失败时返回非零。"""
    args = parse_args(argv)
    report = build_a1_gate_report()
    if args.output is not None:
        write_a1_gate_report(report, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_ag1_ag8_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
