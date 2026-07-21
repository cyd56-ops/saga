"""生成 R18 双路线公平实验、shadow 负载和 durable 恢复证据。"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
from importlib import metadata
import json
import math
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
from typing import Callable, Literal

import cryptography

from neural import (
    BoundedA0ShadowQueue,
    CompiledToyLWEVerifier,
    InMemoryA0ShadowOutbox,
    ReferenceAuthorizationRelationsV1,
    RouteBFixedAuthorizationCircuitEvidence,
    RouteBFixedAuthorizationCircuitRoute,
    RouteBShadowRequest,
    build_fixed_policy_shadow_evaluator_v1,
)
from pq import (
    CryptographyMLDSABackend,
    EnvelopeCanonicalizationId,
    EnvelopeDigestAlgorithmId,
    ML_DSA_CONTEXT_V1,
    MLDSABackendContractV1,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureBindingV1,
    SignatureProfileId,
    SignatureRouteId,
    ToyLWESignatureScheme,
)
from saga.durable_authorization import (
    DurableAuthorizationCommitV1,
    SQLiteDurableAuthorizationStateStore,
)
from saga.dual_route_runtime import (
    DualRouteAuthorizationRequestV1,
    DualRouteMode,
    build_dual_route_runtime_coordinator,
)
from saga.execution_gate import ExecutionGateRequest
from saga.messages import build_request_envelope


DUAL_ROUTE_FAIR_REPORT_SCHEMA_V1 = "saga-pq-can-dual-route-fair-report-v1"
DUAL_ROUTE_FAIR_WORKLOAD_ID_V1 = "r18-four-quadrant-llm-prompt-v1"

_MODES: tuple[DualRouteMode, ...] = (
    "route_b_only",
    "route_b_with_a_shadow",
    "dual_required_research",
    "offline_compare",
)
_NOW = datetime(2026, 7, 21, 9, 0, tzinfo=timezone.utc)
_SENDER_AID = "alice@example.com:calendar_agent"
_RECEIVER_AID = "bob@example.com:email_agent"
_TOKEN = "dual-route-fair-token"
_MESSAGE = "authorize the fixed experiment task"
_ROUTE_A_KEY_ID = b"route-a-fair-runner-key"
_ROUTE_B_KEY_ID = b"route-b-fair-runner-key"


@dataclass(frozen=True)
class LatencySummaryV1:
    """汇总一组非负有限延迟，并固定 nearest-rank 分位数口径。"""

    sample_count: int
    minimum_seconds: float | None
    maximum_seconds: float | None
    mean_seconds: float | None
    p50_seconds: float | None
    p95_seconds: float | None
    p99_seconds: float | None

    def as_dict(self) -> dict[str, object]:
        """导出机器可读延迟摘要。"""
        return {
            "sample_count": self.sample_count,
            "minimum_seconds": self.minimum_seconds,
            "maximum_seconds": self.maximum_seconds,
            "mean_seconds": self.mean_seconds,
            "p50_seconds": self.p50_seconds,
            "p95_seconds": self.p95_seconds,
            "p99_seconds": self.p99_seconds,
            "percentile_method": "nearest_rank",
        }


@dataclass(frozen=True)
class DualRouteFairCaseResultV1:
    """记录同一逻辑输入在一个 integration mode 下的无敏感材料结果。"""

    case_id: str
    mode: DualRouteMode
    envelope_digest: str
    expected_route_a_accept: bool
    expected_route_b_accept: bool
    route_a_observed_accept: bool | None
    route_b_observed_accept: bool
    route_a_reference_equivalent: bool | None
    route_b_reference_equivalent: bool
    formula_accept: bool
    committable: bool
    evaluate_reason: str
    committed: bool
    commit_reason: str
    replay_probed: bool
    replay_rejected: bool | None
    protected_sink_effect_count: int
    evaluate_seconds: float
    commit_seconds: float
    route_a_evaluate_seconds: float | None
    route_b_evaluate_seconds: float
    route_a_commit_seconds: float | None
    route_b_commit_seconds: float | None

    def as_dict(self) -> dict[str, object]:
        """导出不含 token、消息、公钥或签名字节的 case 摘要。"""
        return {
            "case_id": self.case_id,
            "mode": self.mode,
            "envelope_digest": self.envelope_digest,
            "expected_route_a_accept": self.expected_route_a_accept,
            "expected_route_b_accept": self.expected_route_b_accept,
            "route_a_observed_accept": self.route_a_observed_accept,
            "route_b_observed_accept": self.route_b_observed_accept,
            "route_a_reference_equivalent": self.route_a_reference_equivalent,
            "route_b_reference_equivalent": self.route_b_reference_equivalent,
            "formula_accept": self.formula_accept,
            "committable": self.committable,
            "evaluate_reason": self.evaluate_reason,
            "committed": self.committed,
            "commit_reason": self.commit_reason,
            "replay_probed": self.replay_probed,
            "replay_rejected": self.replay_rejected,
            "protected_sink_effect_count": self.protected_sink_effect_count,
            "latency_seconds": {
                "evaluate": self.evaluate_seconds,
                "commit": self.commit_seconds,
                "route_a_evaluate": self.route_a_evaluate_seconds,
                "route_b_evaluate": self.route_b_evaluate_seconds,
                "route_a_commit": self.route_a_commit_seconds,
                "route_b_commit": self.route_b_commit_seconds,
            },
        }


@dataclass(frozen=True)
class DualRouteFairExperimentReportV1:
    """汇总公平核心、负载、恢复、安全检查和论文边界。"""

    generated_at: str
    environment: dict[str, object]
    workload: dict[str, object]
    cases: tuple[DualRouteFairCaseResultV1, ...]
    quadrants: dict[str, int]
    reference_equivalence: dict[str, int]
    latency: dict[str, LatencySummaryV1]
    authority: dict[str, object]
    replay: dict[str, int]
    shadow_core: dict[str, object]
    shadow_load: dict[str, object]
    crash_recovery: dict[str, object]
    gate_checks: dict[str, bool]
    limitations: tuple[str, ...]
    schema_version: Literal[
        "saga-pq-can-dual-route-fair-report-v1"
    ] = DUAL_ROUTE_FAIR_REPORT_SCHEMA_V1

    @property
    def all_passed(self) -> bool:
        """仅当所有安全与公平检查通过时返回 True。"""
        return bool(self.gate_checks) and all(self.gate_checks.values())

    def as_dict(self) -> dict[str, object]:
        """导出版本化报告，不序列化任何密钥、签名、token 或消息原文。"""
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "all_passed": self.all_passed,
            "environment": dict(self.environment),
            "workload": dict(self.workload),
            "quadrants": dict(self.quadrants),
            "reference_equivalence": dict(self.reference_equivalence),
            "latency": {
                name: summary.as_dict() for name, summary in self.latency.items()
            },
            "authority": dict(self.authority),
            "replay": dict(self.replay),
            "shadow_core": dict(self.shadow_core),
            "shadow_load": dict(self.shadow_load),
            "crash_recovery": dict(self.crash_recovery),
            "gate_checks": dict(self.gate_checks),
            "cases": [case.as_dict() for case in self.cases],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class _LogicalCase:
    """保存四模式共同使用的单一 immutable 请求。"""

    case_id: str
    route_a_accept: bool
    route_b_accept: bool
    request: DualRouteAuthorizationRequestV1 = field(repr=False)


@dataclass(frozen=True)
class _RouteAObservation:
    """记录固定 Route A 与 toy reference 的单次结果。"""

    accepted: bool
    reference_accepted: bool
    equivalent: bool
    latency_seconds: float


@dataclass(frozen=True)
class _RouteBObservation:
    """记录 Route B fixed path 与 B1/B2 reference 的单次结果。"""

    accepted: bool
    reference_accepted: bool
    equivalent: bool
    latency_seconds: float


@dataclass(frozen=True)
class _Materials:
    """保存一次 runner 进程内的短生命周期 A/B 密钥与 evaluator。"""

    route_a_scheme: ToyLWESignatureScheme = field(repr=False)
    route_a_public_key: bytes = field(repr=False)
    route_a_secret_key: bytes = field(repr=False)
    route_a_verifier: CompiledToyLWEVerifier = field(repr=False)
    route_b_backend: CryptographyMLDSABackend = field(repr=False)
    route_b_public_key: bytes = field(repr=False)
    route_b_secret_key: bytes = field(repr=False)
    route_b_evaluator: RouteBFixedAuthorizationCircuitRoute = field(repr=False)
    backend_environment: dict[str, object]


class _TimedRouteA:
    """测量 fixed Route A，并同步计算不参与授权的 toy reference。"""

    def __init__(
        self,
        verifier: CompiledToyLWEVerifier,
        scheme: ToyLWESignatureScheme,
        *,
        delay_seconds: float = 0.0,
    ) -> None:
        """绑定 verifier/reference 和仅用于 shadow 压力探针的显式延迟。"""
        self.verifier = verifier
        self.scheme = scheme
        self.delay_seconds = delay_seconds
        self.observations: list[_RouteAObservation] = []

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """返回原始硬 0/1，并记录 fixed/reference 等价性与延迟。"""
        started_at = time.perf_counter()
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        output = self.verifier.verify_bytes(public_key, message, signature)
        latency_seconds = time.perf_counter() - started_at
        reference = self.scheme.verify(public_key, message, signature)
        accepted = type(output) is int and output == 1
        self.observations.append(
            _RouteAObservation(
                accepted=accepted,
                reference_accepted=reference,
                equivalent=type(output) is int
                and output in (0, 1)
                and accepted is reference,
                latency_seconds=latency_seconds,
            )
        )
        return output


class _TimedRouteB:
    """测量真实 ML-DSA + fixed policy/relation，并重算 reference oracle。"""

    def __init__(self, evaluator: RouteBFixedAuthorizationCircuitRoute) -> None:
        """绑定无状态 Route B evaluator 并初始化调用观测。"""
        self.evaluator = evaluator
        self.observations: list[_RouteBObservation] = []

    def evaluate(
        self,
        request: RouteBShadowRequest,
        public_key: bytes,
        signature: bytes,
    ) -> RouteBFixedAuthorizationCircuitEvidence:
        """返回原始 Route B evidence，并记录 B1/B2 reference equivalence。"""
        started_at = time.perf_counter()
        evidence = self.evaluator.evaluate(request, public_key, signature)
        latency_seconds = time.perf_counter() - started_at
        reference_accepted, equivalent = _route_b_reference(evidence)
        self.observations.append(
            _RouteBObservation(
                accepted=evidence.accepted,
                reference_accepted=reference_accepted,
                equivalent=equivalent,
                latency_seconds=latency_seconds,
            )
        )
        return evidence


def build_dual_route_fair_report(
    *,
    seed: int = 20260721,
    shadow_load_cases: int = 8,
    shadow_queue_capacity: int = 2,
    shadow_delay_seconds: float = 0.05,
) -> DualRouteFairExperimentReportV1:
    """运行相同四象限语料、shadow 压力和 durable PENDING 恢复探针。"""
    _validate_runner_options(
        seed=seed,
        shadow_load_cases=shadow_load_cases,
        shadow_queue_capacity=shadow_queue_capacity,
        shadow_delay_seconds=shadow_delay_seconds,
    )
    materials = _build_materials(seed)
    logical_cases = _build_logical_cases(materials)
    with tempfile.TemporaryDirectory(prefix="saga-r18-fair-") as temporary_directory:
        root = Path(temporary_directory)
        core = _run_fair_core(root, materials, logical_cases)
        shadow_load = _run_shadow_load_probe(
            root,
            materials,
            case_count=shadow_load_cases,
            queue_capacity=shadow_queue_capacity,
            delay_seconds=float(shadow_delay_seconds),
        )
        crash_recovery = _run_crash_recovery_probe(root, materials)

    cases = tuple(core["cases"])
    quadrants = _quadrant_counts(cases)
    reference = _reference_summary(cases)
    authority = _authority_summary(cases, shadow_load)
    replay = _replay_summary(cases)
    latency = _latency_summaries(cases, core["shadow_latencies"])
    workload = _workload_manifest(logical_cases)
    environment = _environment_manifest(materials.backend_environment)
    expected_core_commits = sum(
        int(
            case.mode != "offline_compare"
            and case.formula_accept
        )
        for case in cases
    )
    gate_checks = {
        "same_logical_inputs_across_modes": _same_inputs_across_modes(cases),
        "all_four_quadrants_observed": quadrants
        == {"a0_b0": 1, "a0_b1": 1, "a1_b0": 1, "a1_b1": 1},
        "route_outputs_match_expected_quadrants": all(
            case.route_b_observed_accept is case.expected_route_b_accept
            and (
                case.route_a_observed_accept is None
                or case.route_a_observed_accept is case.expected_route_a_accept
            )
            for case in cases
        ),
        "route_a_reference_equivalent": reference["route_a_mismatch_count"] == 0,
        "route_b_reference_equivalent": reference["route_b_mismatch_count"] == 0,
        "no_route_a_false_rejects": reference["route_a_false_reject_count"] == 0,
        "no_route_b_false_rejects": reference["route_b_false_reject_count"] == 0,
        "mode_formula_commits_match": authority["core_commit_count"]
        == expected_core_commits
        and all(
            case.committed
            is (case.mode != "offline_compare" and case.formula_accept)
            for case in cases
        ),
        "replay_rejected_after_restart": replay["probe_count"] > 0
        and replay["rejected_count"] == replay["probe_count"],
        "rejected_cases_have_no_sink_effect": authority[
            "unexpected_core_sink_effect_count"
        ]
        == 0,
        "core_shadow_late_matches_quadrants": core["shadow_core"][
            "terminal_status_counts"
        ]["completed"]
        == 2
        and core["shadow_core"]["route_a_b_disagreement_count"] == 1,
        "core_shadow_zero_authority": core["shadow_core"][
            "authority_granted_count"
        ]
        == 0,
        "shadow_never_changes_authority": bool(shadow_load["authority_isolated"]),
        "shadow_load_accounted": bool(shadow_load["all_submissions_accounted"]),
        "shadow_load_routes_agree": shadow_load[
            "route_a_b_disagreement_count"
        ]
        == 0,
        "durable_pending_recovery_passed": bool(crash_recovery["passed"]),
    }
    return DualRouteFairExperimentReportV1(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        environment=environment,
        workload=workload,
        cases=cases,
        quadrants=quadrants,
        reference_equivalence=reference,
        latency=latency,
        authority=authority,
        replay=replay,
        shadow_core=core["shadow_core"],
        shadow_load=shadow_load,
        crash_recovery=crash_recovery,
        gate_checks=gate_checks,
        limitations=(
            "object-level local runner; the Agent network receive path is not invoked",
            "Route A uses the research-only toy LWE compiled verifier and has no production cryptographic claim",
            "ML-DSA keys and signatures are short-lived in memory and are never serialized into the report",
            "shadow_load artificial delay is isolated from the fair four-mode core and recorded explicitly",
            "SQLite recovery is local single-host evidence, not distributed consensus or high availability",
            "latency is process-local and includes interpreter/runtime noise; repeat runs are required for paper statistics",
        ),
    )


def parse_args(argv: list[str] | tuple[str, ...] | None = None) -> argparse.Namespace:
    """解析公平 runner 的负载参数和可选 JSON 输出路径。"""
    parser = argparse.ArgumentParser(
        description="Run the R18 dual-route fair experiment and recovery probes."
    )
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--shadow-load-cases", type=int, default=8)
    parser.add_argument("--shadow-queue-capacity", type=int, default=2)
    parser.add_argument("--shadow-delay-seconds", type=float, default=0.05)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path; stdout is always emitted.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | tuple[str, ...] | None = None) -> int:
    """运行并输出报告；任一公平或安全检查失败时返回非零状态。"""
    args = parse_args(argv)
    report = build_dual_route_fair_report(
        seed=args.seed,
        shadow_load_cases=args.shadow_load_cases,
        shadow_queue_capacity=args.shadow_queue_capacity,
        shadow_delay_seconds=args.shadow_delay_seconds,
    )
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report.all_passed else 1


def _validate_runner_options(
    *,
    seed: int,
    shadow_load_cases: int,
    shadow_queue_capacity: int,
    shadow_delay_seconds: float,
) -> None:
    """拒绝会产生不明确或无界实验语义的参数。"""
    if type(seed) is not int:
        raise TypeError("seed must be a built-in integer")
    for field_name, value in (
        ("shadow_load_cases", shadow_load_cases),
        ("shadow_queue_capacity", shadow_queue_capacity),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{field_name} must be a positive built-in integer")
    if (
        type(shadow_delay_seconds) not in (int, float)
        or isinstance(shadow_delay_seconds, bool)
        or not math.isfinite(float(shadow_delay_seconds))
        or shadow_delay_seconds < 0
    ):
        raise ValueError("shadow_delay_seconds must be finite and non-negative")


def _build_materials(seed: int) -> _Materials:
    """创建内存短生命周期 ML-DSA 与确定性 toy Route A 材料。"""
    route_b_backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
    descriptor = route_b_backend.descriptor()
    if not descriptor.available:
        raise RuntimeError("cryptography/OpenSSL ML-DSA-44 backend is unavailable")
    contract = MLDSABackendContractV1(
        backend_name="cryptography",
        backend_version=cryptography.__version__,
        provider_name="OpenSSL",
        provider_version=descriptor.provider_version,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        timeout_seconds=1.0,
    )
    route_b_public_key, route_b_secret_key = route_b_backend.keygen()
    route_a_scheme = ToyLWESignatureScheme(seed=seed)
    route_a_keys = route_a_scheme.keygen()
    return _Materials(
        route_a_scheme=route_a_scheme,
        route_a_public_key=route_a_keys.public_key,
        route_a_secret_key=route_a_keys.secret_key,
        route_a_verifier=CompiledToyLWEVerifier(route_a_scheme, message_bytes=32),
        route_b_backend=route_b_backend,
        route_b_public_key=route_b_public_key,
        route_b_secret_key=route_b_secret_key,
        route_b_evaluator=RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(route_b_backend, contract)
        ),
        backend_environment={
            "backend_name": descriptor.backend_name,
            "backend_version": descriptor.backend_version,
            "provider_name": descriptor.provider_name,
            "provider_version": descriptor.provider_version,
            "algorithm_id": int(descriptor.algorithm_id),
            "profile_id": int(descriptor.profile_id),
            "context_digest": hashlib.sha256(descriptor.context).hexdigest(),
        },
    )


def _build_logical_cases(materials: _Materials) -> tuple[_LogicalCase, ...]:
    """构造四个 envelope/signature 固定、覆盖全部 A/B 象限的逻辑输入。"""
    cases = []
    for route_a_accept, route_b_accept in (
        (False, False),
        (False, True),
        (True, False),
        (True, True),
    ):
        case_id = f"a{int(route_a_accept)}-b{int(route_b_accept)}"
        request = _build_request(
            materials,
            turn_id=f"fair-{case_id}",
            route_a_accept=route_a_accept,
            route_b_accept=route_b_accept,
        )
        cases.append(
            _LogicalCase(case_id, route_a_accept, route_b_accept, request)
        )
    return tuple(cases)


def _build_request(
    materials: _Materials,
    *,
    turn_id: str,
    route_a_accept: bool,
    route_b_accept: bool,
) -> DualRouteAuthorizationRequestV1:
    """为同一 canonical envelope 构造独立 A/B detached signature。"""
    envelope = build_request_envelope(
        sender_aid=_SENDER_AID,
        receiver_aid=_RECEIVER_AID,
        token=_TOKEN,
        session_id="session-dual-route-fair-v1",
        turn_id=turn_id,
        issued_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(minutes=4),
        action_scope="llm_prompt",
        message=_MESSAGE,
        capability_id=f"cap-{turn_id}",
        timestamp=_NOW,
    )
    binding = SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        key_id=_ROUTE_B_KEY_ID,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1,
        envelope_digest=envelope.digest(),
    )
    route_b_signature = materials.route_b_backend.sign(
        materials.route_b_secret_key,
        binding.canonical_bytes(),
    )
    if not route_b_accept:
        route_b_signature = _first_invalid_signature(
            route_b_signature,
            lambda candidate: materials.route_b_backend.verify(
                materials.route_b_public_key,
                binding.canonical_bytes(),
                candidate,
            ),
        )
    route_a_signature = materials.route_a_scheme.sign(
        materials.route_a_secret_key,
        envelope.digest(),
    )
    if not route_a_accept:
        route_a_signature = _first_invalid_signature(
            route_a_signature,
            lambda candidate: materials.route_a_scheme.verify(
                materials.route_a_public_key,
                envelope.digest(),
                candidate,
            ),
        )
    route_b_request = RouteBShadowRequest(
        binding=binding,
        envelope=envelope,
        sender_aid=_SENDER_AID,
        receiver_aid=_RECEIVER_AID,
        token_digest=hashlib.sha256(_TOKEN.encode("utf-8")).digest(),
        message_digest=hashlib.sha256(_MESSAGE.encode("utf-8")).digest(),
        action_scope="llm_prompt",
        observed_at=_NOW,
        flow_labels=("public",),
    )
    return DualRouteAuthorizationRequestV1(
        execution_request=ExecutionGateRequest(
            sender_aid=_SENDER_AID,
            receiver_aid=_RECEIVER_AID,
            token=_TOKEN,
            message=_MESSAGE,
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=route_b_signature,
        ),
        route_b_request=route_b_request,
        route_a_key_id=_ROUTE_A_KEY_ID,
        route_a_signature=route_a_signature,
    )


def _first_invalid_signature(
    signature: bytes,
    verify: Callable[[bytes], bool],
) -> bytes:
    """确定性寻找单 bit 变异，避免把概率假设写入四象限语料。"""
    for index in range(len(signature)):
        candidate = (
            signature[:index]
            + bytes((signature[index] ^ 1,))
            + signature[index + 1 :]
        )
        if verify(candidate) is False:
            return candidate
    raise RuntimeError("failed to derive a deterministic invalid signature")


def _store(path: Path) -> SQLiteDurableAuthorizationStateStore:
    """构造使用固定可信时间的本地 durable store。"""
    return SQLiteDurableAuthorizationStateStore(path, now_fn=lambda: _NOW)


def _coordinator(
    *,
    mode: DualRouteMode,
    database_path: Path,
    materials: _Materials,
    route_a: _TimedRouteA,
    route_b: _TimedRouteB,
    shadow_queue: BoundedA0ShadowQueue | None = None,
):
    """按 mode 构造只使用本地 trust registry 的 R18 Coordinator。"""
    return build_dual_route_runtime_coordinator(
        mode=mode,
        durable_authorization_state_store=_store(database_path),
        route_b_evaluator=route_b,
        route_b_public_keys={_ROUTE_B_KEY_ID: materials.route_b_public_key},
        route_a_public_keys={_ROUTE_A_KEY_ID: materials.route_a_public_key},
        route_a_verifier=route_a,
        route_a_shadow_submitter=shadow_queue,
        now_fn=lambda: _NOW,
    )


def _run_fair_core(
    root: Path,
    materials: _Materials,
    logical_cases: tuple[_LogicalCase, ...],
) -> dict[str, object]:
    """在四模式上运行完全相同的四个逻辑输入并采集阶段延迟。"""
    results: list[DualRouteFairCaseResultV1] = []
    shadow_core: dict[str, object] = {}
    shadow_latencies: list[float] = []
    for mode in _MODES:
        database_path = root / f"core-{mode}.sqlite3"
        route_a = _TimedRouteA(materials.route_a_verifier, materials.route_a_scheme)
        route_b = _TimedRouteB(materials.route_b_evaluator)
        outbox = InMemoryA0ShadowOutbox(capacity=32)
        queue = (
            BoundedA0ShadowQueue(route_a, outbox, queue_capacity=4)
            if mode == "route_b_with_a_shadow"
            else None
        )
        try:
            coordinator = _coordinator(
                mode=mode,
                database_path=database_path,
                materials=materials,
                route_a=route_a,
                route_b=route_b,
                shadow_queue=queue,
            )
            for logical_case in logical_cases:
                results.append(
                    _run_core_case(
                        coordinator=coordinator,
                        mode=mode,
                        database_path=database_path,
                        materials=materials,
                        route_a=route_a,
                        route_b=route_b,
                        shadow_queue=queue,
                        logical_case=logical_case,
                    )
                )
            if queue is not None:
                idle = queue.await_idle(5.0)
                evidence = outbox.snapshot()
                shadow_latencies.extend(
                    item.latency_seconds
                    for item in evidence
                    if item.status == "completed"
                )
                shadow_core = {
                    "idle_before_timeout": idle,
                    "queue_stats": queue.stats().as_dict(),
                    "outbox_stats": outbox.stats(),
                    "terminal_status_counts": _status_counts(evidence),
                    "route_a_b_disagreement_count": sum(
                        item.agrees_with_reference is False for item in evidence
                    ),
                    "authority_granted_count": sum(
                        int(item.authority_granted) for item in evidence
                    ),
                }
        finally:
            if queue is not None:
                queue.close()
    return {
        "cases": results,
        "shadow_core": shadow_core,
        "shadow_latencies": shadow_latencies,
    }


def _run_core_case(
    *,
    coordinator: object,
    mode: DualRouteMode,
    database_path: Path,
    materials: _Materials,
    route_a: _TimedRouteA,
    route_b: _TimedRouteB,
    shadow_queue: BoundedA0ShadowQueue | None,
    logical_case: _LogicalCase,
) -> DualRouteFairCaseResultV1:
    """运行单个 evaluate/commit/sink/restart-replay 序列。"""
    evaluate_a_start = len(route_a.observations)
    evaluate_b_start = len(route_b.observations)
    started_at = time.perf_counter()
    evidence = coordinator.evaluate(logical_case.request)  # type: ignore[attr-defined]
    evaluate_seconds = time.perf_counter() - started_at
    evaluate_a = _new_observation(route_a.observations, evaluate_a_start)
    evaluate_b = _new_observation(route_b.observations, evaluate_b_start)
    assert type(evaluate_b) is _RouteBObservation

    commit_a_start = len(route_a.observations)
    commit_b_start = len(route_b.observations)
    started_at = time.perf_counter()
    commit = coordinator.commit(evidence)  # type: ignore[attr-defined]
    commit_seconds = time.perf_counter() - started_at
    commit_a = _new_observation(route_a.observations, commit_a_start)
    commit_b = _new_observation(route_b.observations, commit_b_start)

    sink_effect_count = 0
    if commit.context is not None:
        commit.context.require_action("llm_prompt")
        sink_effect_count = 1

    replay_probed = commit.committed
    replay_rejected: bool | None = None
    if replay_probed:
        restarted = _coordinator(
            mode=mode,
            database_path=database_path,
            materials=materials,
            route_a=route_a,
            route_b=route_b,
            shadow_queue=shadow_queue,
        )
        replay_evidence = restarted.evaluate(logical_case.request)
        replay = restarted.commit(replay_evidence)
        replay_rejected = (
            not replay.committed
            and replay.context is None
            and replay.reason == "replayed_request_envelope"
        )

    return DualRouteFairCaseResultV1(
        case_id=logical_case.case_id,
        mode=mode,
        envelope_digest=logical_case.request.route_b_request.envelope.hex_digest(),
        expected_route_a_accept=logical_case.route_a_accept,
        expected_route_b_accept=logical_case.route_b_accept,
        route_a_observed_accept=(
            evaluate_a.accepted
            if type(evaluate_a) is _RouteAObservation
            else None
        ),
        route_b_observed_accept=evidence.route_b.accepted,
        route_a_reference_equivalent=(
            evaluate_a.equivalent
            if type(evaluate_a) is _RouteAObservation
            else None
        ),
        route_b_reference_equivalent=evaluate_b.equivalent,
        formula_accept=evidence.formula_accept,
        committable=evidence.committable,
        evaluate_reason=evidence.reason,
        committed=commit.committed,
        commit_reason=commit.reason,
        replay_probed=replay_probed,
        replay_rejected=replay_rejected,
        protected_sink_effect_count=sink_effect_count,
        evaluate_seconds=evaluate_seconds,
        commit_seconds=commit_seconds,
        route_a_evaluate_seconds=(
            evaluate_a.latency_seconds
            if type(evaluate_a) is _RouteAObservation
            else None
        ),
        route_b_evaluate_seconds=evaluate_b.latency_seconds,
        route_a_commit_seconds=(
            commit_a.latency_seconds
            if type(commit_a) is _RouteAObservation
            else None
        ),
        route_b_commit_seconds=(
            commit_b.latency_seconds
            if type(commit_b) is _RouteBObservation
            else None
        ),
    )


def _new_observation(observations: list[object], start: int) -> object | None:
    """返回当前阶段新增的首个观测；零调用阶段返回 None。"""
    return observations[start] if len(observations) > start else None


def _run_shadow_load_probe(
    root: Path,
    materials: _Materials,
    *,
    case_count: int,
    queue_capacity: int,
    delay_seconds: float,
) -> dict[str, object]:
    """隔离运行可配置 bounded shadow 压力，不污染公平核心延迟。"""
    database_path = root / "shadow-load.sqlite3"
    route_a = _TimedRouteA(
        materials.route_a_verifier,
        materials.route_a_scheme,
        delay_seconds=delay_seconds,
    )
    route_b = _TimedRouteB(materials.route_b_evaluator)
    outbox = InMemoryA0ShadowOutbox(capacity=max(32, case_count * 2))
    queue = BoundedA0ShadowQueue(
        route_a,
        outbox,
        queue_capacity=queue_capacity,
        job_timeout_seconds=max(1.0, delay_seconds * 4 + 0.1),
    )
    committed_count = 0
    sink_effect_count = 0
    queued_submission_count = 0
    dropped_submission_count = 0
    peak_pending_count = 0
    try:
        coordinator = _coordinator(
            mode="route_b_with_a_shadow",
            database_path=database_path,
            materials=materials,
            route_a=route_a,
            route_b=route_b,
            shadow_queue=queue,
        )
        for index in range(case_count):
            request = _build_request(
                materials,
                turn_id=f"shadow-load-{index}",
                route_a_accept=True,
                route_b_accept=True,
            )
            result = coordinator.commit(coordinator.evaluate(request))
            committed_count += int(result.committed)
            if result.context is not None:
                result.context.require_action("llm_prompt")
                sink_effect_count += 1
            submission = result.shadow_submission
            if submission is not None and submission.queued:
                queued_submission_count += 1
            elif submission is not None:
                dropped_submission_count += 1
            peak_pending_count = max(peak_pending_count, queue.stats().pending_count)
        idle = queue.await_idle(max(5.0, case_count * delay_seconds * 2))
        stats = queue.stats()
        evidence = outbox.snapshot()
    finally:
        queue.close()
    status_counts = _status_counts(evidence)
    error_count = status_counts.get("error", 0) + status_counts.get("timeout", 0)
    all_accounted = (
        queued_submission_count + dropped_submission_count == case_count
        and stats.queued_count == queued_submission_count
        and stats.queue_full_drop_count + stats.closed_drop_count
        == dropped_submission_count
    )
    return {
        "case_count": case_count,
        "queue_capacity": queue_capacity,
        "artificial_verifier_delay_seconds": delay_seconds,
        "idle_before_timeout": idle,
        "peak_pending_count": peak_pending_count,
        "queued_submission_count": queued_submission_count,
        "dropped_submission_count": dropped_submission_count,
        "error_or_timeout_count": error_count,
        "route_a_b_disagreement_count": sum(
            item.agrees_with_reference is False for item in evidence
        ),
        "queue_stats": stats.as_dict(),
        "outbox_stats": outbox.stats(),
        "terminal_status_counts": status_counts,
        "late_latency": _latency_summary(
            item.latency_seconds
            for item in evidence
            if item.status == "completed"
        ).as_dict(),
        "committed_authority_count": committed_count,
        "protected_sink_effect_count": sink_effect_count,
        "authority_isolated": committed_count == case_count
        and sink_effect_count == case_count,
        "all_submissions_accounted": all_accounted,
    }


def _run_crash_recovery_probe(root: Path, materials: _Materials) -> dict[str, object]:
    """模拟 prepare 后进程退出，验证相同 fingerprint 可恢复且不能重复提交。"""
    database_path = root / "crash-recovery.sqlite3"
    route_a = _TimedRouteA(materials.route_a_verifier, materials.route_a_scheme)
    route_b = _TimedRouteB(materials.route_b_evaluator)
    coordinator = _coordinator(
        mode="dual_required_research",
        database_path=database_path,
        materials=materials,
        route_a=route_a,
        route_b=route_b,
    )
    request = _build_request(
        materials,
        turn_id="crash-recovery-probe",
        route_a_accept=True,
        route_b_accept=True,
    )
    evidence = coordinator.evaluate(request)
    envelope = evidence.decision.request_envelope
    if envelope is None:
        raise RuntimeError("crash recovery probe requires a canonical envelope")
    durable_commit = DurableAuthorizationCommitV1(
        request_id=envelope.hex_digest(),
        request_fingerprint=evidence.request_fingerprint,
        route_id=coordinator.route_id,
        decision_reason=evidence.reason,
        envelope=envelope,
    )
    first_store = _store(database_path)
    prepare_status = first_store.prepare_authorization(durable_commit)
    pending = first_store.authorization_record(durable_commit.request_id)
    restarted_store = _store(database_path)
    recovery_status = restarted_store.commit_authorization(durable_commit)
    recovered = restarted_store.authorization_record(durable_commit.request_id)
    replay_status = restarted_store.commit_authorization(durable_commit)
    passed = (
        prepare_status == "prepared"
        and pending is not None
        and pending.state == "PENDING"
        and recovery_status == "committed"
        and recovered is not None
        and recovered.state == "COMMITTED"
        and replay_status == "replayed"
    )
    return {
        "probe": "sqlite_pending_restart_v1",
        "prepare_status": prepare_status,
        "state_before_restart": pending.state if pending is not None else None,
        "recovery_status": recovery_status,
        "state_after_restart": recovered.state if recovered is not None else None,
        "post_recovery_replay_status": replay_status,
        "context_issued_by_probe": False,
        "passed": passed,
    }


def _route_b_reference(
    evidence: RouteBFixedAuthorizationCircuitEvidence,
) -> tuple[bool, bool]:
    """重算 B1 和 B2 reference，并与 fixed route 最终输出比较。"""
    policy = evidence.policy_evidence
    policy_shadow = build_fixed_policy_shadow_evaluator_v1().evaluate(
        policy.compiled_facts.fact_set,
        policy.signature_evidence,
    )
    relation_reference = ReferenceAuthorizationRelationsV1().evaluate(
        evidence.compiled_raw_input.raw_input
    )
    relation_fixed = evidence.relation_decision
    fixed_predicates = tuple(
        (predicate.relation_name, predicate.output)
        for predicate in relation_fixed.trace.predicates
    )
    reference_predicates = tuple(
        (predicate.relation_name, predicate.output)
        for predicate in relation_reference.predicates
    )
    relation_reason_equivalent = (
        relation_reference.accepted and relation_fixed.accepted
    ) or relation_reference.reason == relation_fixed.reason
    relation_equivalent = (
        relation_reference.accepted is relation_fixed.accepted
        and relation_reference.output == relation_fixed.output
        and reference_predicates == fixed_predicates
        and relation_reason_equivalent
    )
    outside_signature_valid = policy.outside_standard_signature_valid
    reference_accepted = (
        outside_signature_valid
        and policy_shadow.reference_decision.accepted
        and relation_reference.accepted
    )
    equivalent = (
        policy_shadow.equivalent
        and relation_equivalent
        and evidence.accepted is reference_accepted
    )
    return reference_accepted, equivalent


def _status_counts(evidence: tuple[object, ...]) -> dict[str, int]:
    """按稳定 terminal status 汇总 shadow evidence。"""
    counts = {"completed": 0, "error": 0, "timeout": 0, "dropped": 0}
    for item in evidence:
        status = getattr(item, "status", None)
        if status in counts:
            counts[status] += 1
    return counts


def _quadrant_counts(
    cases: tuple[DualRouteFairCaseResultV1, ...],
) -> dict[str, int]:
    """只用 offline_compare 同步观测生成 A/B 四象限，避免重复计数。"""
    counts = {"a0_b0": 0, "a0_b1": 0, "a1_b0": 0, "a1_b1": 0}
    for case in cases:
        if case.mode != "offline_compare" or case.route_a_observed_accept is None:
            continue
        key = (
            f"a{int(case.route_a_observed_accept)}_"
            f"b{int(case.route_b_observed_accept)}"
        )
        counts[key] += 1
    return counts


def _reference_summary(
    cases: tuple[DualRouteFairCaseResultV1, ...],
) -> dict[str, int]:
    """汇总实际被调用的 A/B reference mismatch 和误拒绝。"""
    route_a_cases = [case for case in cases if case.route_a_observed_accept is not None]
    return {
        "route_a_observed_case_count": len(route_a_cases),
        "route_a_mismatch_count": sum(
            case.route_a_reference_equivalent is not True for case in route_a_cases
        ),
        "route_a_false_reject_count": sum(
            case.expected_route_a_accept
            and case.route_a_observed_accept is False
            for case in route_a_cases
        ),
        "route_b_observed_case_count": len(cases),
        "route_b_mismatch_count": sum(
            not case.route_b_reference_equivalent for case in cases
        ),
        "route_b_false_reject_count": sum(
            case.expected_route_b_accept
            and not case.route_b_observed_accept
            for case in cases
        ),
    }


def _authority_summary(
    cases: tuple[DualRouteFairCaseResultV1, ...],
    shadow_load: dict[str, object],
) -> dict[str, object]:
    """统计 Context commit 与受保护 sink 实际副作用。"""
    by_mode = {
        mode: sum(case.committed for case in cases if case.mode == mode)
        for mode in _MODES
    }
    return {
        "core_commit_count": sum(case.committed for case in cases),
        "core_commit_count_by_mode": by_mode,
        "core_protected_sink_effect_count": sum(
            case.protected_sink_effect_count for case in cases
        ),
        "unexpected_core_sink_effect_count": sum(
            case.protected_sink_effect_count != int(case.committed)
            for case in cases
        ),
        "offline_context_count": sum(
            case.committed for case in cases if case.mode == "offline_compare"
        ),
        "shadow_load_commit_count": shadow_load["committed_authority_count"],
        "shadow_load_sink_effect_count": shadow_load["protected_sink_effect_count"],
    }


def _replay_summary(
    cases: tuple[DualRouteFairCaseResultV1, ...],
) -> dict[str, int]:
    """统计成功 commit 后跨 store 重建的 replay 拒绝结果。"""
    probed = [case for case in cases if case.replay_probed]
    return {
        "probe_count": len(probed),
        "rejected_count": sum(case.replay_rejected is True for case in probed),
        "unexpected_context_count": sum(case.replay_rejected is not True for case in probed),
    }


def _latency_summaries(
    cases: tuple[DualRouteFairCaseResultV1, ...],
    shadow_latencies: object,
) -> dict[str, LatencySummaryV1]:
    """分别汇总 Route A、Route B、evaluate、commit 与 late shadow 延迟。"""
    route_a = [
        value
        for case in cases
        for value in (case.route_a_evaluate_seconds, case.route_a_commit_seconds)
        if value is not None
    ]
    route_b = [
        value
        for case in cases
        for value in (case.route_b_evaluate_seconds, case.route_b_commit_seconds)
        if value is not None
    ]
    return {
        "route_a_fixed": _latency_summary(route_a),
        "route_b_standard_plus_fixed": _latency_summary(route_b),
        "coordinator_evaluate": _latency_summary(
            case.evaluate_seconds for case in cases
        ),
        "coordinator_commit": _latency_summary(
            case.commit_seconds for case in cases
        ),
        "shadow_late": _latency_summary(shadow_latencies),
    }


def _latency_summary(values: Iterable[float]) -> LatencySummaryV1:
    """验证样本并按 nearest-rank 计算 p50/p95/p99。"""
    ordered = sorted(float(value) for value in values)
    if any(not math.isfinite(value) or value < 0 for value in ordered):
        raise ValueError("latency samples must be finite and non-negative")
    if not ordered:
        return LatencySummaryV1(0, None, None, None, None, None, None)

    def percentile(fraction: float) -> float:
        """按 nearest-rank 返回一个非插值分位点。"""
        index = max(0, math.ceil(fraction * len(ordered)) - 1)
        return ordered[index]

    return LatencySummaryV1(
        sample_count=len(ordered),
        minimum_seconds=ordered[0],
        maximum_seconds=ordered[-1],
        mean_seconds=statistics.fmean(ordered),
        p50_seconds=percentile(0.50),
        p95_seconds=percentile(0.95),
        p99_seconds=percentile(0.99),
    )


def _workload_manifest(logical_cases: tuple[_LogicalCase, ...]) -> dict[str, object]:
    """记录公平变量、逻辑 case 和不含原文的 workload digest。"""
    case_manifest = [
        {
            "case_id": case.case_id,
            "route_a_expected_accept": case.route_a_accept,
            "route_b_expected_accept": case.route_b_accept,
            "envelope_digest": case.request.route_b_request.envelope.hex_digest(),
        }
        for case in logical_cases
    ]
    encoded = json.dumps(
        case_manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return {
        "workload_id": DUAL_ROUTE_FAIR_WORKLOAD_ID_V1,
        "logical_case_count": len(logical_cases),
        "mode_count": len(_MODES),
        "core_run_count": len(logical_cases) * len(_MODES),
        "workload_digest": hashlib.sha256(encoded).hexdigest(),
        "controlled_variables": [
            "canonical_envelope",
            "route_a_signature",
            "route_b_signature",
            "trusted_time",
            "local_key_registry",
            "route_evaluators",
        ],
        "independent_variable": "locally_configured_dual_route_mode",
        "mode_order": list(_MODES),
        "cases": case_manifest,
    }


def _environment_manifest(backend: dict[str, object]) -> dict[str, object]:
    """记录可复现实验软件身份，并生成不依赖密钥的环境摘要。"""
    manifest = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "cryptography_version": cryptography.__version__,
        "torch_version": _optional_package_version("torch"),
        "backend": dict(backend),
    }
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return {**manifest, "environment_digest": hashlib.sha256(encoded).hexdigest()}


def _optional_package_version(package_name: str) -> str | None:
    """读取可选包版本；未安装时显式记录 null 而不引入运行依赖。"""
    try:
        return metadata.version(package_name)
    except metadata.PackageNotFoundError:
        return None


def _same_inputs_across_modes(
    cases: tuple[DualRouteFairCaseResultV1, ...],
) -> bool:
    """验证每个 case 在四模式下使用同一 envelope digest 和预期象限。"""
    for case_id in {case.case_id for case in cases}:
        selected = [case for case in cases if case.case_id == case_id]
        identities = {
            (
                case.envelope_digest,
                case.expected_route_a_accept,
                case.expected_route_b_accept,
            )
            for case in selected
        }
        if len(selected) != len(_MODES) or len(identities) != 1:
            return False
    return True


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
