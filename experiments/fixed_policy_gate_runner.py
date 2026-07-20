"""生成路线 B B0.5/B1 的机器可读 preliminary gate evidence。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import itertools
import json
from pathlib import Path
import random
from typing import Mapping

from neural import (
    AUTHORIZATION_FACT_NAMES,
    AUTHORIZATION_LAYOUT_ID_V1,
    AUTHORIZATION_LAYOUT_VERSION_V1,
    AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1,
    AuthorizationFact,
    AuthorizationFactName,
    AuthorizationFactProvenance,
    AuthorizationFactSet,
    AuthorizationFactSource,
    AuthorizationInputLayout,
    AuthorizationPredicateIR,
    FixedPolicyAggregator,
    FixedPolicyShadowEvaluator,
    ReferenceAuthorizationPolicy,
    build_authorization_input_layout_v1,
    build_authorization_predicate_ir_v1,
    find_trainable_state,
)
from pq import MLDSARouteBVerificationEvidence


PRELIMINARY_GATE_REPORT_VERSION = 1

_FACT_SOURCES: dict[AuthorizationFactName, AuthorizationFactSource] = {
    "standard_signature_valid": AuthorizationFactSource.STANDARD_MLDSA_VERIFIER,
    "request_envelope_valid": AuthorizationFactSource.CANONICAL_ENVELOPE_VALIDATOR,
    "scope_authorized": AuthorizationFactSource.LOCAL_SCOPE_POLICY,
    "flow_allowed": AuthorizationFactSource.LOCAL_FLOW_POLICY,
    "delegation_allowed": AuthorizationFactSource.LOCAL_DELEGATION_POLICY,
    "time_window_valid": AuthorizationFactSource.LOCAL_TIME_VALIDATOR,
}


@dataclass(frozen=True)
class PreliminaryGateResult:
    """记录一个 BG preliminary gate 的通过状态和非敏感证据摘要。"""

    gate_id: str
    passed: bool
    evidence: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        """导出稳定 JSON 字段，避免写入请求或 backend 私有诊断。"""
        return {
            "gate_id": self.gate_id,
            "passed": self.passed,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class FixedPolicyPreliminaryGateReport:
    """汇总 BG1-BG6 的 deterministic shadow preliminary evidence。"""

    report_version: int
    stage: str
    seed: int
    differential_cases: int
    gates: tuple[PreliminaryGateResult, ...]
    limitations: tuple[str, ...]

    @property
    def all_passed(self) -> bool:
        """仅当六项 preliminary gate 均存在且通过时返回 True。"""
        return len(self.gates) == 6 and all(gate.passed for gate in self.gates)

    def as_dict(self) -> dict[str, object]:
        """导出可归档但不代表 B1.5 enforcement approval 的 JSON 报告。"""
        return {
            "report_version": self.report_version,
            "stage": self.stage,
            "seed": self.seed,
            "differential_cases": self.differential_cases,
            "all_passed": self.all_passed,
            "gates": [gate.as_dict() for gate in self.gates],
            "limitations": list(self.limitations),
        }


def build_preliminary_gate_report(
    *,
    seed: int = 20260718,
    differential_cases: int = 256,
) -> FixedPolicyPreliminaryGateReport:
    """运行合成穷举、差分和 mutation 检查，生成 BG1-BG6 preliminary 报告。"""
    if type(seed) is not int:
        raise TypeError("seed must be a built-in integer")
    if type(differential_cases) is not int or differential_cases <= 0:
        raise ValueError("differential_cases must be a positive built-in integer")

    layout = build_authorization_input_layout_v1()
    predicate_ir = build_authorization_predicate_ir_v1()
    reference = ReferenceAuthorizationPolicy(layout, predicate_ir)
    aggregator = FixedPolicyAggregator(layout, predicate_ir)
    shadow = FixedPolicyShadowEvaluator(reference, aggregator)

    gates = (
        _check_bg1_provenance(layout, aggregator),
        _check_bg2_layout(layout, predicate_ir, aggregator),
        _check_bg3_equivalence(
            shadow,
            seed=seed,
            differential_cases=differential_cases,
        ),
        _check_bg4_signature_necessity(shadow),
        _check_bg5_mutations(layout, predicate_ir, reference),
        _check_bg6_fixed_trace(aggregator),
    )
    return FixedPolicyPreliminaryGateReport(
        report_version=PRELIMINARY_GATE_REPORT_VERSION,
        stage="B1_shadow_preliminary",
        seed=seed,
        differential_cases=differential_cases,
        gates=gates,
        limitations=(
            "synthetic typed-fact corpus; no Agent/runtime shadow traffic is included",
            "B1 shadow evidence cannot create LocalExecutionContext or call a protected sink",
            "all_passed is not approval to enter B1.5 enforcement",
            "latency and memory measurements remain for the later BG8 experiment manifest",
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 deterministic preliminary gate runner 参数。"""
    parser = argparse.ArgumentParser(
        description="Build Route B B0.5/B1 preliminary BG1-BG6 evidence."
    )
    parser.add_argument("--seed", type=int, default=20260718)
    parser.add_argument("--differential-cases", type=int, default=256)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path; stdout is always emitted.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """生成报告、可选写盘，并以非零状态表示 preliminary gate 未全部通过。"""
    args = parse_args(argv)
    report = build_preliminary_gate_report(
        seed=args.seed,
        differential_cases=args.differential_cases,
    )
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report.all_passed else 1


def _check_bg1_provenance(
    layout: AuthorizationInputLayout,
    aggregator: FixedPolicyAggregator,
) -> PreliminaryGateResult:
    """验证所有事实来源固定，且 raw mapping 不能直接进入聚合器。"""
    facts = _fact_set(tuple(True for _ in AUTHORIZATION_FACT_NAMES), nonce=1)
    encoded = layout.encode(facts)
    raw_mapping_decision = aggregator.evaluate(  # type: ignore[arg-type]
        {name: True for name in AUTHORIZATION_FACT_NAMES}
    )
    sources = {fact.provenance.source.value for fact in facts.facts}
    passed = (
        len(facts.facts) == len(AUTHORIZATION_FACT_NAMES)
        and len(sources) == len(AUTHORIZATION_FACT_NAMES)
        and len(encoded) == len(AUTHORIZATION_FACT_NAMES)
        and not raw_mapping_decision.accepted
        and raw_mapping_decision.reason == "fixed_policy_input_invalid"
    )
    return PreliminaryGateResult(
        "BG1_preliminary",
        passed,
        {
            "typed_fact_count": len(facts.facts),
            "distinct_internal_source_count": len(sources),
            "raw_mapping_rejected": not raw_mapping_decision.accepted,
        },
    )


def _check_bg2_layout(
    layout: AuthorizationInputLayout,
    predicate_ir: AuthorizationPredicateIR,
    aggregator: FixedPolicyAggregator,
) -> PreliminaryGateResult:
    """验证错误长度、非二值编码和未知 layout 版本均被拒绝。"""
    invalid_payloads = (
        b"\x01" * (layout.encoded_bytes - 1),
        b"\x01" * (layout.encoded_bytes + 1),
        b"\x01" * (layout.encoded_bytes - 1) + b"\x02",
    )
    rejected_payloads = sum(
        _raises_input_error(lambda payload=payload: layout.validate_encoded(payload))
        for payload in invalid_payloads
    )
    version_rejected = _raises_input_error(lambda: replace(layout, version=2))
    id_rejected = _raises_input_error(lambda: replace(layout, layout_id="future-layout"))
    valid_facts = _fact_set(
        tuple(True for _ in AUTHORIZATION_FACT_NAMES),
        nonce=201,
    )
    missing_fact_rejected = not aggregator.evaluate(
        replace(valid_facts, facts=valid_facts.facts[:-1])
    ).accepted
    duplicate_fact_rejected = bool(
        _raises_input_error(
            lambda: replace(
                valid_facts,
                facts=(*valid_facts.facts, valid_facts.facts[0]),
            )
        )
    )
    canonical_ir_deletion_rejected = bool(
        _raises_input_error(
            lambda: replace(
                predicate_ir,
                predicates=predicate_ir.predicates[:-1],
            )
        )
    )
    passed = (
        rejected_payloads == len(invalid_payloads)
        and version_rejected == 1
        and id_rejected == 1
        and missing_fact_rejected
        and duplicate_fact_rejected
        and canonical_ir_deletion_rejected
    )
    return PreliminaryGateResult(
        "BG2_preliminary",
        passed,
        {
            "invalid_payload_count": len(invalid_payloads),
            "invalid_payload_rejected_count": rejected_payloads,
            "unknown_version_rejected": bool(version_rejected),
            "unknown_layout_id_rejected": bool(id_rejected),
            "missing_fact_rejected": missing_fact_rejected,
            "duplicate_fact_rejected": duplicate_fact_rejected,
            "canonical_ir_deletion_rejected": canonical_ir_deletion_rejected,
        },
    )


def _check_bg3_equivalence(
    shadow: FixedPolicyShadowEvaluator,
    *,
    seed: int,
    differential_cases: int,
) -> PreliminaryGateResult:
    """运行完整布尔空间和固定种子差分 corpus 的 reference equivalence。"""
    cases: list[tuple[AuthorizationFactSet, MLDSARouteBVerificationEvidence]] = []
    for nonce, values in enumerate(
        itertools.product((False, True), repeat=len(AUTHORIZATION_FACT_NAMES))
    ):
        cases.append((_fact_set(values, nonce=nonce), _signature_evidence(values[0])))
    exhaustive_count = len(cases)
    rng = random.Random(seed)
    for offset in range(differential_cases):
        values = tuple(bool(rng.getrandbits(1)) for _ in AUTHORIZATION_FACT_NAMES)
        cases.append(
            (
                _fact_set(values, nonce=exhaustive_count + offset),
                _signature_evidence(values[0]),
            )
        )
    manifest = shadow.evaluate_corpus(cases)
    full_coverage = all(
        item.true_count > 0 and item.false_count > 0
        for item in manifest.predicate_coverage
    )
    passed = (
        manifest.all_equivalent
        and full_coverage
        and manifest.authority_granted_count == 0
    )
    evidence = manifest.as_dict()
    evidence["exhaustive_cases"] = exhaustive_count
    evidence["fixed_seed_differential_cases"] = differential_cases
    return PreliminaryGateResult("BG3_preliminary", passed, evidence)


def _check_bg4_signature_necessity(
    shadow: FixedPolicyShadowEvaluator,
) -> PreliminaryGateResult:
    """验证电路内签名事实、外部 evidence 和 shadow 无 authority 三重约束。"""
    invalid_values = (False, True, True, True, True, True)
    matched_invalid = shadow.evaluate(
        _fact_set(invalid_values, nonce=401),
        _signature_evidence(False),
    )
    mismatch = shadow.evaluate(
        _fact_set(tuple(True for _ in AUTHORIZATION_FACT_NAMES), nonce=402),
        _signature_evidence(False),
    )
    valid = shadow.evaluate(
        _fact_set(tuple(True for _ in AUTHORIZATION_FACT_NAMES), nonce=403),
        _signature_evidence(True),
    )
    passed = (
        matched_invalid.equivalent
        and not matched_invalid.fixed_decision.accepted
        and matched_invalid.fixed_decision.reason == "standard_signature_invalid"
        and not mismatch.equivalent
        and mismatch.reason == "standard_signature_fact_mismatch"
        and valid.equivalent
        and valid.fixed_decision.accepted
        and not any(
            item.authority_granted for item in (matched_invalid, mismatch, valid)
        )
    )
    return PreliminaryGateResult(
        "BG4_preliminary",
        passed,
        {
            "invalid_signature_rejected_inside": not matched_invalid.fixed_decision.accepted,
            "inside_outside_mismatch_detected": not mismatch.equivalent,
            "outside_valid_required_for_matching_accept": valid.outside_standard_signature_valid,
            "authority_granted_count": sum(
                int(item.authority_granted)
                for item in (matched_invalid, mismatch, valid)
            ),
        },
    )


def _check_bg5_mutations(
    layout: AuthorizationInputLayout,
    predicate_ir: AuthorizationPredicateIR,
    reference: ReferenceAuthorizationPolicy,
) -> PreliminaryGateResult:
    """删除每个必要谓词并确认 reference corpus 检出且无 authority API。"""
    detected: list[str] = []
    authority_api_count = 0
    for deleted_index, deleted in enumerate(predicate_ir.predicates):
        mutated_ir = replace(
            predicate_ir,
            policy_profile_id=AUTHORIZATION_POLICY_MUTATION_PROFILE_ID_V1,
            predicates=tuple(
                predicate
                for index, predicate in enumerate(predicate_ir.predicates)
                if index != deleted_index
            ),
        )
        mutated = FixedPolicyAggregator(layout, mutated_ir)
        values = tuple(
            index != deleted_index for index in range(len(AUTHORIZATION_FACT_NAMES))
        )
        facts = _fact_set(values, nonce=500 + deleted_index)
        if reference.evaluate(facts).accepted != mutated.evaluate(facts).accepted:
            detected.append(deleted.predicate_id)
        authority_api_count += int(hasattr(mutated, "commit") or hasattr(mutated, "authorize"))
    passed = (
        len(detected) == len(predicate_ir.predicates)
        and authority_api_count == 0
    )
    return PreliminaryGateResult(
        "BG5_preliminary",
        passed,
        {
            "mutation_count": len(predicate_ir.predicates),
            "detected_count": len(detected),
            "detected_predicates": detected,
            "authority_api_count": authority_api_count,
            "protected_sink_side_effect_count": 0,
        },
    )


def _check_bg6_fixed_trace(
    aggregator: FixedPolicyAggregator,
) -> PreliminaryGateResult:
    """验证不可训练状态、精确 0/1 输出、trace reason 覆盖和复杂度 manifest。"""
    decisions = [
        aggregator.evaluate(_fact_set(values, nonce=600 + index))
        for index, values in enumerate(
            itertools.product((False, True), repeat=len(AUTHORIZATION_FACT_NAMES))
        )
    ]
    output_types_valid = all(type(decision.output) is int for decision in decisions)
    outputs_binary = all(decision.output in (0, 1) for decision in decisions)
    observed_reasons = {decision.reason for decision in decisions}
    expected_reasons = {
        predicate.reject_reason for predicate in aggregator.predicate_ir.predicates
    } | {"fixed_policy_accept"}
    trainable_findings = find_trainable_state(aggregator)
    passed = (
        output_types_valid
        and outputs_binary
        and observed_reasons == expected_reasons
        and not trainable_findings
    )
    return PreliminaryGateResult(
        "BG6_preliminary",
        passed,
        {
            "output_count": len(decisions),
            "all_outputs_builtin_int": output_types_valid,
            "all_outputs_binary": outputs_binary,
            "trace_reason_coverage": sorted(observed_reasons),
            "trainable_finding_count": len(trainable_findings),
            "complexity": aggregator.complexity_manifest().as_dict(),
        },
    )


def _fact_set(values: tuple[bool, ...], *, nonce: int) -> AuthorizationFactSet:
    """构造仅用于 deterministic gate runner 的 typed synthetic facts。"""
    return AuthorizationFactSet(
        layout_id=AUTHORIZATION_LAYOUT_ID_V1,
        layout_version=AUTHORIZATION_LAYOUT_VERSION_V1,
        facts=tuple(
            AuthorizationFact(
                name=name,
                value=value,
                provenance=AuthorizationFactProvenance(
                    source=_FACT_SOURCES[name],
                    source_version="preliminary-evidence-v1",
                    evidence_digest=hashlib.sha256(
                        f"{name}:{value}:{nonce}".encode("ascii")
                    ).digest(),
                ),
            )
            for name, value in zip(AUTHORIZATION_FACT_NAMES, values, strict=True)
        ),
    )


def _signature_evidence(valid: bool) -> MLDSARouteBVerificationEvidence:
    """构造 wiring-only 标准签名 evidence；不作为密码正确性证据。"""
    return MLDSARouteBVerificationEvidence(
        accepted=valid,
        reason="signature_valid" if valid else "signature_invalid",
    )


def _raises_input_error(call: object) -> int:
    """执行无参检查并将预期 typed input 异常转换为确定性计数。"""
    if not callable(call):
        return 0
    try:
        call()
    except (TypeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
