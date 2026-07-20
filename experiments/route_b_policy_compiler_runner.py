"""生成 Route B B3 PolicyCompiler 的 BG7/BG8 机器可读证据。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import random
from statistics import mean, median
import time
import tracemalloc
from typing import Callable, Mapping

from neural.fixed_authorization import (
    RAW_AUTHORIZATION_DIGEST_BYTES,
    AuthorizationCircuitProfileV1,
    CompiledAuthorizationCircuitProfileV1,
    RouteBAuthorizationPolicyCompilerV1,
    RouteBRawAuthorizationInputV1,
)
from neural.fixed_circuit import find_trainable_state


POLICY_COMPILER_GATE_REPORT_VERSION_V1 = 1
POLICY_COMPILER_GATE_STAGE_V1 = "B3_portable_policy_compiler_preliminary"


@dataclass(frozen=True)
class OperationLatencyV1:
    """记录一个本地微基准操作的纳秒延迟分布。"""

    iterations: int
    mean_ns: int
    median_ns: int
    p95_ns: int
    min_ns: int
    max_ns: int

    def as_dict(self) -> dict[str, int]:
        """导出稳定字段名的延迟统计。"""
        return {
            "iterations": self.iterations,
            "mean_ns": self.mean_ns,
            "median_ns": self.median_ns,
            "p95_ns": self.p95_ns,
            "min_ns": self.min_ns,
            "max_ns": self.max_ns,
        }


@dataclass(frozen=True)
class ProfilePortabilityEvidenceV1:
    """记录一个编译 profile 的差分、覆盖、复杂度和本地开销。"""

    profile: AuthorizationCircuitProfileV1
    profile_digest: bytes
    predicate_ir_digest: bytes
    total_cases: int
    mismatch_count: int
    predicate_coverage: tuple[tuple[str, int, int], ...]
    complexity: Mapping[str, int | str]
    reference_latency: OperationLatencyV1
    fixed_latency: OperationLatencyV1
    fixed_peak_python_bytes: int
    trainable_finding_count: int
    authority_granted_count: int

    @property
    def all_equivalent(self) -> bool:
        """仅当 corpus 非空且 reference/fixed 无差异时返回 True。"""
        return self.total_cases > 0 and self.mismatch_count == 0

    @property
    def coverage_complete(self) -> bool:
        """仅当每个关系在 corpus 中都出现 true 和 false 时返回 True。"""
        return bool(self.predicate_coverage) and all(
            true_count > 0 and false_count > 0
            for _name, true_count, false_count in self.predicate_coverage
        )

    def as_dict(self) -> dict[str, object]:
        """导出不含请求、签名或密钥材料的单 profile 证据。"""
        return {
            "profile": self.profile.as_dict(),
            "profile_digest": self.profile_digest.hex(),
            "predicate_ir_digest": self.predicate_ir_digest.hex(),
            "total_cases": self.total_cases,
            "mismatch_count": self.mismatch_count,
            "all_equivalent": self.all_equivalent,
            "coverage_complete": self.coverage_complete,
            "predicate_coverage": [
                {
                    "relation_name": name,
                    "true_count": true_count,
                    "false_count": false_count,
                }
                for name, true_count, false_count in self.predicate_coverage
            ],
            "complexity": dict(self.complexity),
            "reference_latency": self.reference_latency.as_dict(),
            "fixed_latency": self.fixed_latency.as_dict(),
            "fixed_peak_python_bytes": self.fixed_peak_python_bytes,
            "memory_measurement_scope": "tracemalloc_python_allocator_peak",
            "trainable_finding_count": self.trainable_finding_count,
            "authority_granted_count": self.authority_granted_count,
        }


@dataclass(frozen=True)
class RouteBPolicyCompilerGateReportV1:
    """汇总两个 profile 对 BG7 portability 与 BG8 manifest 的证据。"""

    report_version: int
    stage: str
    seed: int
    differential_cases_per_profile: int
    latency_iterations: int
    compiler_id: str
    compiler_version: int
    shared_predicate_ir_digest: bytes
    shared_layout_schema: str
    shared_reference_class: str
    shared_circuit_class: str
    shared_gadget_classes: tuple[str, ...]
    bg7_passed: bool
    bg8_passed: bool
    profiles: tuple[ProfilePortabilityEvidenceV1, ...]
    limitations: tuple[str, ...]

    @property
    def all_passed(self) -> bool:
        """仅当 BG7 和 BG8 第一阶段证据同时通过时返回 True。"""
        return self.bg7_passed and self.bg8_passed

    def as_dict(self) -> dict[str, object]:
        """导出可归档的 B3 preliminary manifest。"""
        return {
            "report_version": self.report_version,
            "stage": self.stage,
            "seed": self.seed,
            "differential_cases_per_profile": self.differential_cases_per_profile,
            "latency_iterations": self.latency_iterations,
            "compiler_id": self.compiler_id,
            "compiler_version": self.compiler_version,
            "shared_predicate_ir_digest": self.shared_predicate_ir_digest.hex(),
            "shared_layout_schema": self.shared_layout_schema,
            "shared_reference_class": self.shared_reference_class,
            "shared_circuit_class": self.shared_circuit_class,
            "shared_gadget_classes": list(self.shared_gadget_classes),
            "profile_count": len(self.profiles),
            "bg7_passed": self.bg7_passed,
            "bg8_passed": self.bg8_passed,
            "all_passed": self.all_passed,
            "profiles": [profile.as_dict() for profile in self.profiles],
            "limitations": list(self.limitations),
        }


def build_policy_compiler_gate_report(
    *,
    seed: int = 20260720,
    differential_cases_per_profile: int = 256,
    latency_iterations: int = 200,
) -> RouteBPolicyCompilerGateReportV1:
    """编译两个 profile，运行跨 profile 差分、覆盖和本地开销测量。"""
    if type(seed) is not int:
        raise TypeError("seed must be a built-in integer")
    for field_name, value in (
        ("differential_cases_per_profile", differential_cases_per_profile),
        ("latency_iterations", latency_iterations),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{field_name} must be a positive built-in integer")

    compiler = RouteBAuthorizationPolicyCompilerV1()
    compiled_profiles = compiler.compile_registered_profiles()
    rng = random.Random(seed)
    evidence = tuple(
        _evaluate_profile(
            compiled,
            rng=rng,
            differential_cases=differential_cases_per_profile,
            latency_iterations=latency_iterations,
        )
        for compiled in compiled_profiles
    )

    first = compiled_profiles[0]
    ir_digests = {compiled.predicate_ir.digest() for compiled in compiled_profiles}
    layout_schemas = {
        str(compiled.as_dict()["layout_schema"])
        for compiled in compiled_profiles
    }
    reference_classes = {type(compiled.reference).__name__ for compiled in compiled_profiles}
    circuit_classes = {type(compiled.circuit).__name__ for compiled in compiled_profiles}
    gadget_classes = {compiled.gadget_classes() for compiled in compiled_profiles}
    policy_constants = {
        (
            compiled.profile.permitted_scope_families,
            compiled.profile.permitted_flow_labels,
            compiled.profile.max_delegation_depth,
            compiled.profile.max_ttl_seconds,
        )
        for compiled in compiled_profiles
    }
    bg7_passed = (
        len(compiled_profiles) >= 2
        and len({compiled.compiler_id for compiled in compiled_profiles}) == 1
        and len(ir_digests) == 1
        and len(layout_schemas) == 1
        and len(reference_classes) == 1
        and len(circuit_classes) == 1
        and len(gadget_classes) == 1
        and len({compiled.profile_digest for compiled in compiled_profiles})
        == len(compiled_profiles)
        and len(policy_constants) == len(compiled_profiles)
    )
    bg8_passed = all(
        item.all_equivalent
        and item.coverage_complete
        and item.trainable_finding_count == 0
        and item.authority_granted_count == 0
        and int(item.complexity["fixed_linear_layers"]) > 0
        and int(item.complexity["fixed_relu_layers"]) > 0
        and int(item.complexity["fixed_parameter_count"]) > 0
        and item.reference_latency.min_ns > 0
        and item.fixed_latency.min_ns > 0
        and item.fixed_peak_python_bytes > 0
        for item in evidence
    )
    return RouteBPolicyCompilerGateReportV1(
        report_version=POLICY_COMPILER_GATE_REPORT_VERSION_V1,
        stage=POLICY_COMPILER_GATE_STAGE_V1,
        seed=seed,
        differential_cases_per_profile=differential_cases_per_profile,
        latency_iterations=latency_iterations,
        compiler_id=first.compiler_id,
        compiler_version=first.compiler_version,
        shared_predicate_ir_digest=first.predicate_ir.digest(),
        shared_layout_schema=next(iter(layout_schemas)),
        shared_reference_class=next(iter(reference_classes)),
        shared_circuit_class=next(iter(circuit_classes)),
        shared_gadget_classes=next(iter(gadget_classes)),
        bg7_passed=bg7_passed,
        bg8_passed=bg8_passed,
        profiles=evidence,
        limitations=(
            "latency is an in-process Python microbenchmark, not Agent end-to-end latency",
            "memory is tracemalloc Python-allocator peak, not process RSS or accelerator memory",
            "the memory profile is a second authorization surface, not a second signature scheme",
            "the report creates no replay commit, LocalExecutionContext, or execution authority",
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 B3 gate runner 的固定种子、样本数、迭代数和输出路径。"""
    parser = argparse.ArgumentParser(
        description="Build Route B B3 PolicyCompiler BG7/BG8 evidence."
    )
    parser.add_argument("--seed", type=int, default=20260720)
    parser.add_argument("--differential-cases", type=int, default=256)
    parser.add_argument("--latency-iterations", type=int, default=200)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """生成 B3 manifest、可选写盘，并以非零状态表示 gate 未通过。"""
    args = parse_args(argv)
    report = build_policy_compiler_gate_report(
        seed=args.seed,
        differential_cases_per_profile=args.differential_cases,
        latency_iterations=args.latency_iterations,
    )
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report.all_passed else 1


def _evaluate_profile(
    compiled: CompiledAuthorizationCircuitProfileV1,
    *,
    rng: random.Random,
    differential_cases: int,
    latency_iterations: int,
) -> ProfilePortabilityEvidenceV1:
    """运行一个 profile 的 targeted coverage、固定种子差分和开销测量。"""
    valid = _valid_profile_input(compiled.profile)
    cases = [valid, *_targeted_negative_cases(valid)]
    cases.extend(
        _random_profile_input(valid, rng)
        for _ in range(differential_cases)
    )
    relation_names = compiled.predicate_ir.relation_names
    true_counts = {name: 0 for name in relation_names}
    false_counts = {name: 0 for name in relation_names}
    mismatch_count = 0
    for raw_input in cases:
        reference = compiled.reference.evaluate(raw_input)
        fixed = compiled.circuit.evaluate(raw_input)
        predicate_outputs_match = tuple(
            predicate.output for predicate in reference.predicates
        ) == tuple(predicate.output for predicate in fixed.trace.predicates)
        reason_matches = reference.accepted and fixed.accepted or (
            not reference.accepted
            and not fixed.accepted
            and reference.reason == fixed.reason
        )
        if (
            reference.accepted != fixed.accepted
            or reference.output != fixed.output
            or not predicate_outputs_match
            or not reason_matches
        ):
            mismatch_count += 1
        for predicate in fixed.trace.predicates:
            if predicate.output == 1:
                true_counts[predicate.relation_name] += 1
            else:
                false_counts[predicate.relation_name] += 1

    for _ in range(8):
        compiled.reference.evaluate(valid)
        compiled.circuit.evaluate(valid)
    reference_latency = _measure_latency(
        lambda: compiled.reference.evaluate(valid),
        latency_iterations,
    )
    fixed_latency = _measure_latency(
        lambda: compiled.circuit.evaluate(valid),
        latency_iterations,
    )
    peak_python_bytes = _measure_peak_python_bytes(
        lambda: compiled.circuit.evaluate(valid)
    )
    return ProfilePortabilityEvidenceV1(
        profile=compiled.profile,
        profile_digest=compiled.profile_digest,
        predicate_ir_digest=compiled.predicate_ir.digest(),
        total_cases=len(cases),
        mismatch_count=mismatch_count,
        predicate_coverage=tuple(
            (name, true_counts[name], false_counts[name])
            for name in relation_names
        ),
        complexity=compiled.circuit.complexity_manifest().as_dict(),
        reference_latency=reference_latency,
        fixed_latency=fixed_latency,
        fixed_peak_python_bytes=peak_python_bytes,
        trainable_finding_count=len(find_trainable_state(compiled.circuit)),
        authority_granted_count=0,
    )


def _valid_profile_input(
    profile: AuthorizationCircuitProfileV1,
) -> RouteBRawAuthorizationInputV1:
    """构造一个满足所选 profile 固定常量的 root raw input。"""
    requested_family = (
        "memory_write"
        if "memory_write" in profile.permitted_scope_families
        and profile.execution_surface_id == "memory_access"
        else profile.permitted_scope_families[0]
    )
    requested_scope_bits = _named_bits(profile.scope_families, (requested_family,))
    allowed_flow = profile.permitted_flow_labels[0]
    flow_bits = _named_bits(profile.flow_labels, (allowed_flow,))
    digests = tuple(
        hashlib.sha256(
            f"{profile.policy_profile_id}:{name}".encode("ascii")
        ).digest()
        for name in profile.digest_relations
    )
    issued_at = 1_000
    expires_at = issued_at + min(profile.max_ttl_seconds, 200)
    return RouteBRawAuthorizationInputV1(
        layout_id=profile.layout_id,
        layout_version=profile.layout_version,
        standard_signature_valid=True,
        requested_scope_bits=requested_scope_bits,
        authorized_scope_bits=requested_scope_bits,
        flow_label_bits=flow_bits,
        allowed_flow_label_bits=flow_bits,
        parent_allowed_flow_label_bits=bytes(len(profile.flow_labels)),
        parent_present=False,
        delegation_depth=0,
        parent_delegation_depth=0,
        max_delegation_depth=min(profile.max_delegation_depth, 8),
        parent_max_delegation_depth=0,
        signed_parent_digest=bytes(RAW_AUTHORIZATION_DIGEST_BYTES),
        observed_parent_digest=bytes(RAW_AUTHORIZATION_DIGEST_BYTES),
        parent_scope_bits=bytes(len(profile.scope_families)),
        issued_at_epoch=issued_at,
        observed_at_epoch=issued_at + 100,
        expires_at_epoch=expires_at,
        parent_issued_at_epoch=0,
        parent_expires_at_epoch=0,
        max_ttl_seconds=profile.max_ttl_seconds,
        bound_digests=digests,
        observed_digests=digests,
    )


def _targeted_negative_cases(
    valid: RouteBRawAuthorizationInputV1,
) -> tuple[RouteBRawAuthorizationInputV1, ...]:
    """生成六项关系各自单独失败的稳定 coverage corpus。"""
    mismatched_digests = list(valid.observed_digests)
    mismatched_digests[-1] = b"X" * RAW_AUTHORIZATION_DIGEST_BYTES
    unknown_flow = bytearray(len(valid.flow_label_bits))
    unknown_flow[-1] = 1
    return (
        replace(valid, standard_signature_valid=False),
        replace(valid, authorized_scope_bits=bytes(len(valid.authorized_scope_bits))),
        replace(valid, flow_label_bits=bytes(unknown_flow)),
        replace(valid, parent_present=True),
        replace(valid, observed_at_epoch=valid.expires_at_epoch + 1),
        replace(valid, observed_digests=tuple(mismatched_digests)),
    )


def _random_profile_input(
    valid: RouteBRawAuthorizationInputV1,
    rng: random.Random,
) -> RouteBRawAuthorizationInputV1:
    """按固定 RNG 生成有界二值、整数和摘要关系输入。"""
    bound = tuple(rng.randbytes(RAW_AUTHORIZATION_DIGEST_BYTES) for _ in valid.bound_digests)
    observed = tuple(
        digest if rng.randrange(2) else rng.randbytes(RAW_AUTHORIZATION_DIGEST_BYTES)
        for digest in bound
    )
    return replace(
        valid,
        standard_signature_valid=bool(rng.randrange(2)),
        requested_scope_bits=bytes(
            rng.randrange(2) for _ in valid.requested_scope_bits
        ),
        authorized_scope_bits=bytes(
            rng.randrange(2) for _ in valid.authorized_scope_bits
        ),
        flow_label_bits=bytes(rng.randrange(2) for _ in valid.flow_label_bits),
        allowed_flow_label_bits=bytes(
            rng.randrange(2) for _ in valid.allowed_flow_label_bits
        ),
        parent_allowed_flow_label_bits=bytes(
            rng.randrange(2) for _ in valid.parent_allowed_flow_label_bits
        ),
        parent_present=bool(rng.randrange(2)),
        delegation_depth=rng.randrange(5),
        parent_delegation_depth=rng.randrange(5),
        max_delegation_depth=rng.randrange(5),
        parent_max_delegation_depth=rng.randrange(5),
        signed_parent_digest=rng.randbytes(RAW_AUTHORIZATION_DIGEST_BYTES),
        observed_parent_digest=rng.randbytes(RAW_AUTHORIZATION_DIGEST_BYTES),
        parent_scope_bits=bytes(rng.randrange(2) for _ in valid.parent_scope_bits),
        issued_at_epoch=rng.randrange(2_000),
        observed_at_epoch=rng.randrange(2_000),
        expires_at_epoch=rng.randrange(2_000),
        parent_issued_at_epoch=rng.randrange(2_000),
        parent_expires_at_epoch=rng.randrange(2_000),
        bound_digests=bound,
        observed_digests=observed,
    )


def _named_bits(axis: tuple[str, ...], selected: tuple[str, ...]) -> bytes:
    """按 profile 共享轴把固定名称集合编码为二值 bitset。"""
    selected_set = set(selected)
    return bytes(int(name in selected_set) for name in axis)


def _measure_latency(
    operation: Callable[[], object],
    iterations: int,
) -> OperationLatencyV1:
    """用 perf_counter_ns 测量本地操作的 mean/median/p95/min/max。"""
    durations: list[int] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        durations.append(time.perf_counter_ns() - started)
    ordered = sorted(durations)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return OperationLatencyV1(
        iterations=iterations,
        mean_ns=int(mean(durations)),
        median_ns=int(median(durations)),
        p95_ns=ordered[p95_index],
        min_ns=ordered[0],
        max_ns=ordered[-1],
    )


def _measure_peak_python_bytes(operation: Callable[[], object]) -> int:
    """用 tracemalloc 测量一次 fixed evaluation 的 Python allocator 峰值。"""
    already_tracing = tracemalloc.is_tracing()
    if not already_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()
    operation()
    _current, peak = tracemalloc.get_traced_memory()
    if not already_tracing:
        tracemalloc.stop()
    return peak


if __name__ == "__main__":
    raise SystemExit(main())
