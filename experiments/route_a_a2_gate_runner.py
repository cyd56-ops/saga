"""生成路线 A A2 module-lattice/ring fixed verifier 的机器可读证据。"""

from __future__ import annotations

import argparse
from itertools import product
import json
import math
from pathlib import Path
import random
import time
import tracemalloc
from typing import Callable, Sequence

from neural import (
    A2ModuleLatticeTrace,
    A2ModuleLatticeVerifierCore,
    FixedModuleLatticeVerifier,
    assert_fixed_circuit,
    audit_a2_claimed_source,
    bytes_to_bits,
)
from pq import ToyModuleLatticeParameters, ToyModuleLatticeSignatureScheme


def _module_from_flat(
    values: Sequence[int],
    parameters: ToyModuleLatticeParameters,
) -> tuple[tuple[int, ...], ...]:
    """把 coefficient 序列按固定 rank/degree 恢复为 module vector。"""

    if len(values) != parameters.module_width:
        raise ValueError("flat module vector has the wrong width")
    return tuple(
        tuple(values[offset : offset + parameters.ring_degree])
        for offset in range(0, len(values), parameters.ring_degree)
    )


def _flatten(values: Sequence[Sequence[int]]) -> tuple[int, ...]:
    """按 module row-major 顺序展开多项式向量。"""

    return tuple(value for polynomial in values for value in polynomial)


def _encode_public(values: Sequence[Sequence[int]]) -> bytes:
    """把 canonical public target 编码为 uint16 wire bytes。"""

    return b"".join(value.to_bytes(2, "little") for value in _flatten(values))


def _encode_response(values: Sequence[Sequence[int]]) -> bytes:
    """把 signed response 编码为 int16 wire bytes。"""

    return b"".join(
        value.to_bytes(2, "little", signed=True) for value in _flatten(values)
    )


def _is_rejected(operation: Callable[[], object]) -> bool:
    """执行零参数 callable，并判断是否以输入 contract 异常拒绝。"""

    try:
        operation()
    except (TypeError, ValueError):
        return True
    return False


def _build_tiny_ring_exhaustive_evidence() -> dict[str, object]:
    """穷举 degree-2/rank-1 的 public/response/challenge relation 全域。"""

    parameters = ToyModuleLatticeParameters(
        ring_degree=2,
        module_rank=1,
        modulus=3,
        matrix_seed=17,
        secret_bound=1,
    )
    scheme = ToyModuleLatticeSignatureScheme(seed=23, parameters=parameters)
    core = A2ModuleLatticeVerifierCore(
        scheme.public_module_matrix(),
        parameters,
    )
    targets = tuple(product(range(parameters.modulus), repeat=parameters.module_width))
    responses = tuple(
        product(
            range(-parameters.response_bound, parameters.response_bound + 1),
            repeat=parameters.module_width,
        )
    )
    challenges = tuple(product((-1, 0, 1), repeat=parameters.module_width))
    mismatches = 0
    accepted_count = 0
    started_at = time.perf_counter()
    tracemalloc.start()
    for target_flat in targets:
        target = _module_from_flat(target_flat, parameters)
        for response_flat in responses:
            response = _module_from_flat(response_flat, parameters)
            for challenge_flat in challenges:
                challenge = _module_from_flat(challenge_flat, parameters)
                expected = int(
                    scheme.verify_relation(target, response, challenge)
                )
                actual = core.verify_relation(target, response, challenge)
                mismatches += int(actual != expected)
                accepted_count += actual
    latency_seconds = time.perf_counter() - started_at
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "parameters": {
            "ring_degree": parameters.ring_degree,
            "module_rank": parameters.module_rank,
            "modulus": parameters.modulus,
        },
        "case_count": len(targets) * len(responses) * len(challenges),
        "accepted_count": accepted_count,
        "mismatch_count": mismatches,
        "latency_seconds": latency_seconds,
        "peak_memory_bytes": peak_memory_bytes,
    }


def _next_distinct_challenge_message(
    scheme: ToyModuleLatticeSignatureScheme,
    message: bytes,
) -> bytes:
    """确定性寻找与给定消息 one-hot challenge 不同的同长度消息。"""

    challenge = scheme.challenge_vector(message)
    for counter in range(1, 4097):
        candidate = counter.to_bytes(len(message), "little")
        if scheme.challenge_vector(candidate) != challenge:
            return candidate
    raise RuntimeError("failed to find a distinct challenge message")


def _build_rank_two_differential_evidence() -> dict[str, object]:
    """在默认 degree-4/rank-2 relation 上生成固定种子正负差分 corpus。"""

    seed = 20260718
    rng = random.Random(seed)
    parameters = ToyModuleLatticeParameters(matrix_seed=29)
    scheme = ToyModuleLatticeSignatureScheme(seed=31, parameters=parameters)
    verifier = FixedModuleLatticeVerifier(scheme, message_bytes=16)
    cases: list[tuple[bytes, bytes, bytes, str]] = []
    for case_index in range(16):
        keys = scheme.keygen()
        message = rng.randbytes(16)
        signature = scheme.sign(keys.secret_key, message)
        cases.append((keys.public_key, message, signature, f"valid-{case_index}"))
        cases.append(
            (
                keys.public_key,
                _next_distinct_challenge_message(scheme, message),
                signature,
                f"wrong-message-{case_index}",
            )
        )
        response = list(_flatten(scheme.decode_response(signature)))
        response[0] += 1
        cases.append(
            (
                keys.public_key,
                message,
                _encode_response(_module_from_flat(response, parameters)),
                f"tampered-response-{case_index}",
            )
        )
        arbitrary_target = _module_from_flat(
            tuple(rng.randrange(parameters.modulus) for _ in range(parameters.module_width)),
            parameters,
        )
        arbitrary_response = _module_from_flat(
            tuple(
                rng.randint(-parameters.response_bound, parameters.response_bound)
                for _ in range(parameters.module_width)
            ),
            parameters,
        )
        cases.append(
            (
                _encode_public(arbitrary_target),
                message,
                _encode_response(arbitrary_response),
                f"arbitrary-{case_index}",
            )
        )
    tracemalloc.start()
    started_at = time.perf_counter()
    mismatches: list[str] = []
    accepted_count = 0
    for public_key, message, signature, label in cases:
        expected = int(scheme.verify(public_key, message, signature))
        actual = verifier.verify_bytes(public_key, message, signature)
        accepted_count += actual
        if actual != expected:
            mismatches.append(label)
    latency_seconds = time.perf_counter() - started_at
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "seed": seed,
        "parameters": {
            "ring_degree": parameters.ring_degree,
            "module_rank": parameters.module_rank,
            "modulus": parameters.modulus,
        },
        "case_count": len(cases),
        "accepted_count": accepted_count,
        "mismatch_count": len(mismatches),
        "mismatch_labels": mismatches,
        "latency_seconds": latency_seconds,
        "peak_memory_bytes": peak_memory_bytes,
        "boundary": verifier.compilation_boundary().as_dict(),
        "complexity": verifier.complexity().as_dict(),
    }


def _build_input_boundary_evidence() -> dict[str, object]:
    """验证 A2 bytes/bits/module 入口拒绝实数、特殊值、错长和错形状。"""

    scheme = ToyModuleLatticeSignatureScheme(seed=41)
    keys = scheme.keygen()
    message = b"B" * 16
    signature = scheme.sign(keys.secret_key, message)
    verifier = FixedModuleLatticeVerifier(scheme, message_bytes=16)
    valid_bits = [
        *bytes_to_bits(keys.public_key),
        *bytes_to_bits(message),
        *bytes_to_bits(signature),
    ]
    invalid_values = (True, 0.5, -1.0, 2.0, math.nan, math.inf, -math.inf)
    bit_checks: dict[str, bool] = {}
    for index, invalid in enumerate(invalid_values):
        candidate = list(valid_bits)
        candidate[len(candidate) // 2] = invalid
        bit_checks[f"reject_invalid_bit_{index}"] = (
            verifier.verify_compound_bits(candidate) == 0
        )
    parameters = scheme.parameters
    zero_vector = tuple(
        (0,) * parameters.ring_degree for _ in range(parameters.module_rank)
    )
    checks = {
        "valid_binary_material": verifier.verify_compound_bits(valid_bits) == 1,
        "reject_wrong_compound_length": verifier.verify_compound_bits(valid_bits[:-1])
        == 0,
        "reject_wrong_message_length": verifier.verify_bytes(
            keys.public_key,
            message[:-1],
            signature,
        )
        == 0,
        "reject_float_module_coefficient": _is_rejected(
            lambda: verifier.core.trace_relation(
                zero_vector,
                ((0.5, *(0 for _ in range(parameters.ring_degree - 1))),)
                + zero_vector[1:],
                scheme.challenge_vector(message),
            )
        ),
        **bit_checks,
    }
    return {"checks": checks, "all_passed": all(checks.values())}


def _find_valid_mutation_trace() -> tuple[
    ToyModuleLatticeSignatureScheme,
    A2ModuleLatticeVerifierCore,
    A2ModuleLatticeTrace,
]:
    """寻找同时暴露卷积与模约简删除错误的确定性有效 witness。"""

    scheme = ToyModuleLatticeSignatureScheme(seed=53)
    core = A2ModuleLatticeVerifierCore(
        scheme.public_module_matrix(),
        scheme.parameters,
    )
    for counter in range(1, 65):
        keys = scheme.keygen()
        message = counter.to_bytes(4, "little")
        response = scheme.decode_response(scheme.sign(keys.secret_key, message))
        trace = core.trace_relation(
            scheme.decode_public_target(keys.public_key),
            response,
            scheme.challenge_vector(message),
        )
        raw_difference = _flatten(trace.projection_differences)
        target = _flatten(trace.public_target)
        naive = tuple(
            (left - right) % scheme.parameters.modulus
            for left, right in zip(
                _flatten(trace.response),
                _flatten(trace.challenge),
                strict=True,
            )
        )
        if trace.accept == 1 and raw_difference != target and naive != target:
            return scheme, core, trace
    raise RuntimeError("failed to find deterministic A2 mutation witness")


def _build_mutation_evidence() -> dict[str, object]:
    """生成删除环卷积、mod、等值、范数、challenge 权重和聚合的 witness。"""

    scheme, core, valid = _find_valid_mutation_trace()
    parameters = scheme.parameters
    target_flat = list(_flatten(valid.public_target))
    target_flat[0] = (target_flat[0] + 1) % parameters.modulus
    wrong_target = _module_from_flat(target_flat, parameters)
    wrong_target_trace = core.trace_relation(
        wrong_target,
        valid.response,
        valid.challenge,
    )

    norm_response = tuple(
        (parameters.response_bound,) * parameters.ring_degree
        for _ in range(parameters.module_rank)
    )
    zero_target = tuple(
        (0,) * parameters.ring_degree for _ in range(parameters.module_rank)
    )
    provisional_norm = core.trace_relation(
        zero_target,
        norm_response,
        valid.challenge,
    )
    norm_trace = core.trace_relation(
        provisional_norm.recovered_target,
        norm_response,
        valid.challenge,
    )
    zero_challenge = zero_target
    provisional_zero = core.trace_relation(
        zero_target,
        zero_target,
        zero_challenge,
    )
    zero_challenge_trace = core.trace_relation(
        provisional_zero.recovered_target,
        zero_target,
        zero_challenge,
    )
    raw_difference = _flatten(valid.projection_differences)
    target = _flatten(valid.public_target)
    naive = tuple(
        (left - right) % parameters.modulus
        for left, right in zip(
            _flatten(valid.response),
            _flatten(valid.challenge),
            strict=True,
        )
    )
    witnesses = {
        "delete_negacyclic_convolution": valid.accept == 1 and naive != target,
        "delete_modulo": (
            valid.accept == 1
            and raw_difference != target
            and _flatten(valid.recovered_target) == target
        ),
        "delete_equality": (
            wrong_target_trace.equality_accept == 0
            and wrong_target_trace.accept == 0
        ),
        "delete_response_norm": (
            norm_trace.equality_accept == 1
            and norm_trace.input_range_traces[1].l1_bit == 0
            and norm_trace.accept == 0
        ),
        "delete_challenge_weight": (
            zero_challenge_trace.equality_accept == 1
            and zero_challenge_trace.challenge_weight_bit == 0
            and zero_challenge_trace.accept == 0
        ),
        "delete_final_aggregation": (
            core.final_aggregator._evaluate_fixed((1, 1, 0, 1, 1, 1)) == 0
        ),
    }
    return {
        "witnesses": witnesses,
        "detected_count": sum(witnesses.values()),
        "mutation_count": len(witnesses),
        "all_detected": all(witnesses.values()),
    }


def build_a2_gate_report() -> dict[str, object]:
    """汇总 A2 ring relation、source、输入、mutation 与复杂度证据。"""

    tiny = _build_tiny_ring_exhaustive_evidence()
    normal = _build_rank_two_differential_evidence()
    source = audit_a2_claimed_source().as_dict()
    inputs = _build_input_boundary_evidence()
    mutations = _build_mutation_evidence()
    complexity = normal["complexity"]
    fixed_state_scheme = ToyModuleLatticeSignatureScheme(seed=61)
    fixed_state_verifier = FixedModuleLatticeVerifier(
        fixed_state_scheme,
        message_bytes=16,
    )
    try:
        assert_fixed_circuit(fixed_state_verifier)
        fixed_state_passed = True
    except AssertionError:
        fixed_state_passed = False
    gate_checks = {
        "A2G1_tiny_ring_reference_equivalence": tiny["mismatch_count"] == 0,
        "A2G2_rank_two_differential_equivalence": normal["mismatch_count"] == 0,
        "A2G3_claimed_source_closure": source["passed"] is True,
        "A2G4_binary_real_and_wire_contract": inputs["all_passed"] is True,
        "A2G5_numeric_bounds": (
            complexity["max_intermediate_abs"]
            <= complexity["exact_integer_limit"]
        ),
        "A2G6_mutation_detection": mutations["all_detected"] is True,
        "A2G7_fixed_negacyclic_toolchain": (
            fixed_state_passed
            and complexity["projector_backend"]
            == "tiny-negacyclic-fixed-matrix-v1"
            and complexity["projector_core_id"]
            == "fixed-linear-projector-core-v1"
            and complexity["negacyclic_projector_count"]
            == normal["parameters"]["module_rank"] ** 2
        ),
        "A2G8_machine_readable_manifest": (
            normal["latency_seconds"] >= 0.0
            and normal["peak_memory_bytes"] > 0
            and {"boundary", "complexity"}.issubset(normal)
        ),
    }
    gate_status = {
        gate: "pass" if passed else "fail" for gate, passed in gate_checks.items()
    }
    all_passed = all(gate_checks.values())
    return {
        "schema_version": "saga-route-a-a2-gates-v1",
        "route": "A",
        "stage": "A2-module-lattice-negacyclic-verifier",
        "relation": "A_times_z_minus_c_mod_q_equals_t",
        "ring": "R_q=Z_q[x]/(x^n+1)",
        "research_only": True,
        "production_ready": False,
        "ntt_implemented": False,
        "ml_dsa_neuralized": False,
        "parse_hash_inside_claimed_circuit": False,
        "gate_status": gate_status,
        "all_a2_gates_passed": all_passed,
        "r16_first_stage_complete": all_passed,
        "tiny_ring_exhaustive_evidence": tiny,
        "rank_two_differential_manifest": normal,
        "a2_source_closure": source,
        "input_boundary_evidence": inputs,
        "mutation_evidence": mutations,
        "claim_limits": (
            "toy_module_lattice_relation_is_not_unforgeable",
            "fixed_ring_arithmetic_core_only",
            "byte_parse_and_sha256_challenge_are_preprocessing",
            "no_ntt_or_ml_dsa_neuralization",
            "not_production_post_quantum_security",
        ),
    }


def write_a2_gate_report(report: dict[str, object], output_path: Path) -> None:
    """把 A2 gate report 写为稳定缩进 JSON。"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析 A2 gate runner 的可选 JSON 输出路径。"""

    parser = argparse.ArgumentParser(
        description="Generate the Route A A2 module-lattice gate report.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the machine-readable JSON report.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """运行 A2 gate report；任一 A2 gate 失败时返回非零。"""

    args = parse_args(argv)
    report = build_a2_gate_report()
    if args.output is not None:
        write_a2_gate_report(report, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_a2_gates_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
