"""运行 R18 dual-route Agent 接收路径的本地 TLS/socket 实验。"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import statistics
import sys
import tempfile
import threading
import time
from typing import Iterable, Literal

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REPOSITORY_ROOT_TEXT = str(_REPOSITORY_ROOT)
if _REPOSITORY_ROOT_TEXT in sys.path:
    sys.path.remove(_REPOSITORY_ROOT_TEXT)
sys.path.insert(0, _REPOSITORY_ROOT_TEXT)

from neural import (
    BoundedA0ShadowQueue,
    CompiledToyLWEVerifier,
    InMemoryA0ShadowOutbox,
    RouteBFixedAuthorizationCircuitRoute,
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
from saga.agent import Agent
from saga.durable_authorization import SQLiteDurableAuthorizationStateStore
from saga.dual_route_runtime import (
    DualRouteMode,
    DualRouteNetworkRequestAdapterV1,
    DualRouteTransportSignerV1,
    build_dual_route_runtime_coordinator,
    enable_dual_route_agent_runtime_auth,
)
from saga.messages import parse_request_envelope


DUAL_ROUTE_NETWORK_REPORT_SCHEMA_V1 = "saga-pq-can-dual-route-network-report-v1"
DUAL_ROUTE_NETWORK_WORKLOAD_ID_V1 = "r18-agent-tls-prompt-receive-v1"

_SENDER_AID = "alice@example.com:calendar_agent"
_RECEIVER_AID = "bob@example.com:email_agent"
_TOKEN = "dual-route-network-runner-token"
_ROUTE_A_KEY_ID = b"route-a-network-runner-key"
_ROUTE_B_KEY_ID = b"route-b-network-runner-key"


@dataclass(frozen=True)
class NetworkLatencySummaryV1:
    """汇总本地 TLS runner 的非负有限延迟样本。"""

    sample_count: int
    minimum_seconds: float | None
    maximum_seconds: float | None
    mean_seconds: float | None
    p50_seconds: float | None
    p95_seconds: float | None
    p99_seconds: float | None

    def as_dict(self) -> dict[str, object]:
        """导出与对象级公平 runner 一致的 nearest-rank 分位字段。"""
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
class NetworkExchangeObservationV1:
    """记录一次 loopback TLS 请求的接收、sink 和副作用摘要。"""

    case_id: str
    expected_accept: bool
    receiver_ended: bool
    response_bytes: int
    sink_effect_delta: int
    transport_seconds: float
    receive_seconds: float
    prompt_sink_seconds: float | None
    audit_reason: str | None
    server_error_type: str | None

    def as_dict(self) -> dict[str, object]:
        """导出不含 token、消息、签名、公钥或 TLS 私钥的观测。"""
        return {
            "case_id": self.case_id,
            "expected_accept": self.expected_accept,
            "receiver_ended": self.receiver_ended,
            "response_bytes": self.response_bytes,
            "sink_effect_delta": self.sink_effect_delta,
            "audit_reason": self.audit_reason,
            "server_error_type": self.server_error_type,
            "latency_seconds": {
                "transport": self.transport_seconds,
                "receive": self.receive_seconds,
                "prompt_sink": self.prompt_sink_seconds,
            },
        }


@dataclass(frozen=True)
class DualRouteNetworkReportV1:
    """汇总 Agent TLS 接收路径的 authority、延迟、shadow 与负向证据。"""

    generated_at: str
    environment: dict[str, object]
    workload: dict[str, object]
    observations: tuple[NetworkExchangeObservationV1, ...]
    latency: dict[str, NetworkLatencySummaryV1]
    authority: dict[str, object]
    shadow: dict[str, object]
    negative_evidence: dict[str, object]
    gate_checks: dict[str, bool]
    limitations: tuple[str, ...]
    schema_version: Literal[
        "saga-pq-can-dual-route-network-report-v1"
    ] = DUAL_ROUTE_NETWORK_REPORT_SCHEMA_V1

    @property
    def all_passed(self) -> bool:
        """仅当全部网络接线安全检查通过时返回 True。"""
        return bool(self.gate_checks) and all(self.gate_checks.values())

    def as_dict(self) -> dict[str, object]:
        """导出版本化 manifest，不包含任何秘密或业务原文。"""
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "all_passed": self.all_passed,
            "environment": dict(self.environment),
            "workload": dict(self.workload),
            "latency": {
                name: summary.as_dict() for name, summary in self.latency.items()
            },
            "authority": dict(self.authority),
            "shadow": dict(self.shadow),
            "negative_evidence": dict(self.negative_evidence),
            "gate_checks": dict(self.gate_checks),
            "observations": [item.as_dict() for item in self.observations],
            "limitations": list(self.limitations),
        }


class _NoOpMonitor:
    """提供 Agent runner 所需的最小 stopwatch 接口。"""

    def start(self, _name: str) -> None:
        """忽略计时开始。"""

    def stop(self, _name: str) -> None:
        """忽略计时结束。"""


class _MeasuredPromptSink:
    """记录 committed Context 到达 prompt sink 的次数与局部延迟。"""

    task_finished_token = "<TASK_FINISHED>"

    def __init__(self) -> None:
        """初始化 Context 与 latency 观测。"""
        self.contexts: list[object | None] = []
        self.latencies: list[float] = []

    def supports_execution_context(self) -> bool:
        """声明 runner sink 会消费 execution_context。"""
        return True

    def set_strict_execution_capabilities(self, _enabled: bool) -> None:
        """接受 strict capability 模式同步。"""

    def run(
        self,
        _query: str,
        *,
        initiating_agent: bool,
        agent_instance: object | None = None,
        **kwargs: object,
    ) -> tuple[object | None, str]:
        """记录 Context 并立即完成，避免把 LLM latency 混入认证核心。"""
        del initiating_agent
        started_at = time.perf_counter()
        self.contexts.append(kwargs.get("execution_context"))
        result = (agent_instance, self.task_finished_token)
        self.latencies.append(time.perf_counter() - started_at)
        return result


@dataclass(frozen=True)
class _NetworkMaterials:
    """保存一次 runner 进程内的短生命周期 A/B 材料。"""

    route_b_backend: CryptographyMLDSABackend
    route_b_public_key: bytes
    route_b_secret_key: bytes
    route_b_evaluator: RouteBFixedAuthorizationCircuitRoute
    route_a_scheme: ToyLWESignatureScheme
    route_a_public_key: bytes
    route_a_secret_key: bytes
    route_a_verifier: CompiledToyLWEVerifier
    transport_signer: DualRouteTransportSignerV1


def summarize_network_latency(values: Iterable[float]) -> NetworkLatencySummaryV1:
    """按 nearest-rank 口径汇总延迟，拒绝负值与非有限样本。"""
    samples = tuple(float(value) for value in values)
    if any(value < 0 or not _is_finite(value) for value in samples):
        raise ValueError("latency samples must be finite and non-negative")
    if not samples:
        return NetworkLatencySummaryV1(0, None, None, None, None, None, None)
    ordered = tuple(sorted(samples))
    return NetworkLatencySummaryV1(
        sample_count=len(ordered),
        minimum_seconds=ordered[0],
        maximum_seconds=ordered[-1],
        mean_seconds=statistics.fmean(ordered),
        p50_seconds=_nearest_rank(ordered, 0.50),
        p95_seconds=_nearest_rank(ordered, 0.95),
        p99_seconds=_nearest_rank(ordered, 0.99),
    )


def run_dual_route_network_experiment(
    *,
    sample_count: int = 3,
    mode: DualRouteMode = "route_b_with_a_shadow",
) -> DualRouteNetworkReportV1:
    """运行正向、replay 与签名篡改 TLS case，并返回无敏感材料报告。"""
    if type(sample_count) is not int or sample_count <= 0:
        raise ValueError("sample_count must be a positive integer")
    if mode not in {
        "route_b_only",
        "route_b_with_a_shadow",
        "dual_required_research",
    }:
        raise ValueError("network execution mode must be an authoritative mode")
    materials = _build_materials()
    generated_at = datetime.now(tz=timezone.utc)
    with tempfile.TemporaryDirectory(prefix="saga-dual-route-network-") as tmpdir:
        root = Path(tmpdir)
        server_context, client_context = _build_tls_contexts(root)
        outbox = InMemoryA0ShadowOutbox()
        with BoundedA0ShadowQueue(materials.route_a_verifier, outbox) as queue:
            now_fn = lambda: datetime.now(tz=timezone.utc)
            adapter = DualRouteNetworkRequestAdapterV1(
                route_b_key_ids_by_sender={_SENDER_AID: _ROUTE_B_KEY_ID},
                route_b_algorithm_id=SignatureAlgorithmId.ML_DSA_44,
                route_b_profile_id=SignatureProfileId.ML_DSA_PURE,
                route_a_key_ids_by_sender={_SENDER_AID: _ROUTE_A_KEY_ID},
                flow_labels=("public",),
                now_fn=now_fn,
            )
            store = SQLiteDurableAuthorizationStateStore(
                root / "authorization.sqlite3",
                now_fn=now_fn,
            )
            coordinator = build_dual_route_runtime_coordinator(
                mode=mode,
                durable_authorization_state_store=store,
                route_b_evaluator=materials.route_b_evaluator,
                route_b_public_keys={_ROUTE_B_KEY_ID: materials.route_b_public_key},
                route_a_public_keys={_ROUTE_A_KEY_ID: materials.route_a_public_key},
                route_a_verifier=materials.route_a_verifier,
                route_a_shadow_submitter=(
                    queue if mode == "route_b_with_a_shadow" else None
                ),
                network_request_adapter=adapter,
                now_fn=now_fn,
            )
            sink = _MeasuredPromptSink()
            sender = _build_sender(materials.transport_signer)
            observations: list[NetworkExchangeObservationV1] = []
            valid_payloads: list[dict[str, object]] = []
            for index in range(sample_count):
                payload = _build_payload(
                    sender,
                    message=f"network-positive-{index}",
                    turn_index=index,
                )
                valid_payloads.append(payload)
                receiver = _build_receiver(
                    root / f"positive-{index}",
                    coordinator,
                    sink,
                )
                observations.append(
                    _tls_exchange(
                        case_id=f"positive-{index}",
                        expected_accept=True,
                        receiver=receiver,
                        payload=payload,
                        sink=sink,
                        server_context=server_context,
                        client_context=client_context,
                    )
                )

            replay_receiver = _build_receiver(root / "replay", coordinator, sink)
            observations.append(
                _tls_exchange(
                    case_id="replay",
                    expected_accept=False,
                    receiver=replay_receiver,
                    payload=valid_payloads[0],
                    sink=sink,
                    server_context=server_context,
                    client_context=client_context,
                )
            )
            tampered_payload = _build_payload(
                sender,
                message="network-tampered",
                turn_index=sample_count + 1,
            )
            _invalidate_route_b_signature(tampered_payload, materials)
            tampered_receiver = _build_receiver(
                root / "tampered",
                coordinator,
                sink,
            )
            observations.append(
                _tls_exchange(
                    case_id="tampered-signature",
                    expected_accept=False,
                    receiver=tampered_receiver,
                    payload=tampered_payload,
                    sink=sink,
                    server_context=server_context,
                    client_context=client_context,
                )
            )
            if not queue.await_idle(5.0):
                raise RuntimeError("Route A shadow queue did not become idle")
            late = outbox.snapshot()

        return _build_report(
            generated_at=generated_at,
            mode=mode,
            sample_count=sample_count,
            observations=tuple(observations),
            contexts=tuple(sink.contexts),
            shadow_evidence=late,
        )


def _build_report(
    *,
    generated_at: datetime,
    mode: DualRouteMode,
    sample_count: int,
    observations: tuple[NetworkExchangeObservationV1, ...],
    contexts: tuple[object | None, ...],
    shadow_evidence: tuple[object, ...],
) -> DualRouteNetworkReportV1:
    """从网络观测纯计算版本化报告和硬 gate checks。"""
    positives = tuple(item for item in observations if item.expected_accept)
    negatives = tuple(item for item in observations if not item.expected_accept)
    replay = next((item for item in negatives if item.case_id == "replay"), None)
    tampered = next(
        (item for item in negatives if item.case_id == "tampered-signature"),
        None,
    )
    committed_contexts = sum(
        1 for context in contexts if bool(getattr(context, "coordinator_committed", False))
    )
    durable_contexts = sum(
        1
        for context in contexts
        if bool(getattr(context, "durable_authorization_required", False))
    )
    shadow_authority_count = sum(
        1
        for evidence in shadow_evidence
        if bool(getattr(evidence, "authority_granted", False))
    )
    expected_shadow_count = sample_count if mode == "route_b_with_a_shadow" else 0
    gate_checks = {
        "positive_requests_reached_prompt_once": (
            len(positives) == sample_count
            and all(item.sink_effect_delta == 1 for item in positives)
        ),
        "positive_contexts_coordinator_committed": committed_contexts == sample_count,
        "positive_contexts_require_durable_state": durable_contexts == sample_count,
        "network_server_errors_absent": all(
            item.server_error_type is None for item in observations
        ),
        "replay_rejected_without_sink_effect": bool(
            replay is not None
            and replay.sink_effect_delta == 0
            and replay.audit_reason == "replayed_request_envelope"
        ),
        "tampered_signature_rejected_without_sink_effect": bool(
            tampered is not None
            and tampered.sink_effect_delta == 0
            and tampered.audit_reason == "route_b_rejected"
        ),
        "shadow_count_matches_mode": len(shadow_evidence) == expected_shadow_count,
        "shadow_evidence_has_zero_authority": shadow_authority_count == 0,
    }
    return DualRouteNetworkReportV1(
        generated_at=generated_at.astimezone(timezone.utc).isoformat(),
        environment={
            "python": _python_version(),
            "cryptography": cryptography.__version__,
            "transport": "loopback_tcp_tls_1_3",
            "process_model": "single_process_server_thread",
        },
        workload={
            "workload_id": DUAL_ROUTE_NETWORK_WORKLOAD_ID_V1,
            "mode": mode,
            "positive_sample_count": sample_count,
            "negative_cases": ["replay", "tampered-signature"],
            "surface": "llm_prompt",
            "artificial_shadow_delay_seconds": 0.0,
        },
        observations=observations,
        latency={
            "transport_round_trip": summarize_network_latency(
                item.transport_seconds for item in positives
            ),
            "agent_receive_path": summarize_network_latency(
                item.receive_seconds for item in positives
            ),
            "prompt_sink": summarize_network_latency(
                item.prompt_sink_seconds
                for item in positives
                if item.prompt_sink_seconds is not None
            ),
        },
        authority={
            "prompt_context_count": len(contexts),
            "coordinator_committed_context_count": committed_contexts,
            "durable_context_count": durable_contexts,
            "route_evidence_authority_count": 0,
        },
        shadow={
            "late_evidence_count": len(shadow_evidence),
            "authority_granted_count": shadow_authority_count,
            "artificial_delay_seconds": 0.0,
        },
        negative_evidence={
            "replay_reason": replay.audit_reason if replay is not None else None,
            "replay_sink_effect_delta": (
                replay.sink_effect_delta if replay is not None else None
            ),
            "tampered_reason": tampered.audit_reason if tampered is not None else None,
            "tampered_sink_effect_delta": (
                tampered.sink_effect_delta if tampered is not None else None
            ),
        },
        gate_checks=gate_checks,
        limitations=(
            "Loopback TLS isolates Agent receive-path overhead; it does not include Provider or CA access handshakes.",
            "The runner uses one process and SQLite, so it does not claim distributed consistency or multi-host availability.",
            "The prompt sink is a deterministic stub; LLM latency and business tool effects are intentionally excluded.",
            "Route A remains research-only and Route B remains the default authority in route_b_with_a_shadow mode.",
            "Smoke sample counts are not paper-scale confidence evidence; repeat runs are required for distribution claims.",
        ),
    )


def _tls_exchange(
    *,
    case_id: str,
    expected_accept: bool,
    receiver: Agent,
    payload: dict[str, object],
    sink: _MeasuredPromptSink,
    server_context: ssl.SSLContext,
    client_context: ssl.SSLContext,
) -> NetworkExchangeObservationV1:
    """在一次临时 loopback TLS 1.3 连接上执行 Agent send/receive。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10.0)
    port = listener.getsockname()[1]
    server_result: dict[str, object] = {}
    sink_before = len(sink.contexts)
    latency_before = len(sink.latencies)

    def serve() -> None:
        """接受单个 TLS client，并在该连接上运行真实 Agent receive path。"""
        try:
            raw_connection, _address = listener.accept()
            with raw_connection:
                with server_context.wrap_socket(
                    raw_connection,
                    server_side=True,
                ) as tls_connection:
                    started_at = time.perf_counter()
                    server_result["ended"] = receiver.receive_conversation(
                        tls_connection,
                        _TOKEN,
                        recipient_pac=object(),
                        sender_aid=_SENDER_AID,
                    )
                    server_result["receive_seconds"] = (
                        time.perf_counter() - started_at
                    )
        except Exception as exc:
            server_result["error_type"] = type(exc).__name__

    server_thread = threading.Thread(target=serve, name=f"tls-{case_id}", daemon=True)
    server_thread.start()
    response = bytearray()
    transport_started_at = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10.0) as raw_client:
            with client_context.wrap_socket(
                raw_client,
                server_hostname="localhost",
            ) as tls_client:
                Agent.send(_build_sender_from_payload(payload), tls_client, payload)
                while True:
                    chunk = tls_client.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
    finally:
        transport_seconds = time.perf_counter() - transport_started_at
        server_thread.join(timeout=15.0)
        listener.close()
    if server_thread.is_alive():
        raise RuntimeError("TLS receiver thread did not terminate")
    sink_after = len(sink.contexts)
    prompt_sink_seconds = (
        sink.latencies[latency_before]
        if len(sink.latencies) > latency_before
        else None
    )
    return NetworkExchangeObservationV1(
        case_id=case_id,
        expected_accept=expected_accept,
        receiver_ended=bool(server_result.get("ended", False)),
        response_bytes=len(response),
        sink_effect_delta=sink_after - sink_before,
        transport_seconds=transport_seconds,
        receive_seconds=float(server_result.get("receive_seconds", 0.0)),
        prompt_sink_seconds=prompt_sink_seconds,
        audit_reason=_last_audit_reason(receiver),
        server_error_type=(
            str(server_result["error_type"])
            if "error_type" in server_result
            else None
        ),
    )


def _build_materials() -> _NetworkMaterials:
    """构造真实 ML-DSA Route B 与 deterministic toy Route A 的短生命周期材料。"""
    route_b_backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
    descriptor = route_b_backend.descriptor()
    route_b_public_key, route_b_secret_key = route_b_backend.keygen()
    contract = MLDSABackendContractV1(
        backend_name="cryptography",
        backend_version=cryptography.__version__,
        provider_name="OpenSSL",
        provider_version=descriptor.provider_version,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        context=ML_DSA_CONTEXT_V1,
        timeout_seconds=2.0,
    )
    route_b_evaluator = RouteBFixedAuthorizationCircuitRoute(
        MLDSARouteBVerifier(route_b_backend, contract)
    )
    route_a_scheme = ToyLWESignatureScheme(seed=913)
    route_a_keys = route_a_scheme.keygen()
    route_a_verifier = CompiledToyLWEVerifier(route_a_scheme, message_bytes=32)
    transport_signer = DualRouteTransportSignerV1(
        route_b_signer=route_b_backend,
        route_b_secret_key=route_b_secret_key,
        route_b_key_id=_ROUTE_B_KEY_ID,
        route_b_algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        route_b_profile_id=SignatureProfileId.ML_DSA_PURE,
        route_a_signer=route_a_scheme,
        route_a_secret_key=route_a_keys.secret_key,
    )
    return _NetworkMaterials(
        route_b_backend=route_b_backend,
        route_b_public_key=route_b_public_key,
        route_b_secret_key=route_b_secret_key,
        route_b_evaluator=route_b_evaluator,
        route_a_scheme=route_a_scheme,
        route_a_public_key=route_a_keys.public_key,
        route_a_secret_key=route_a_keys.secret_key,
        route_a_verifier=route_a_verifier,
        transport_signer=transport_signer,
    )


def _build_sender(signer: DualRouteTransportSignerV1) -> Agent:
    """构造只负责 canonical envelope 与 detached A/B 签名的 Agent。"""
    sender = Agent.__new__(Agent)
    sender.aid = _SENDER_AID
    sender.provider_id = "dual-route-network-runner"
    sender.runtime_auth_payload_signer = signer
    sender.runtime_auth_capability_ttl_seconds = 300
    return sender


def _build_sender_from_payload(_payload: dict[str, object]) -> Agent:
    """构造仅调用无状态 Agent.send 所需的占位对象。"""
    return Agent.__new__(Agent)


def _build_payload(
    sender: Agent,
    *,
    message: str,
    turn_index: int,
) -> dict[str, object]:
    """经发送侧 runtime hook 生成同一 envelope 上的 A/B detached signatures。"""
    now = datetime.now(tz=timezone.utc)
    return sender._build_conversation_payload(
        receiver_aid=_RECEIVER_AID,
        token=_TOKEN,
        message=message,
        action_scope="llm_prompt",
        turn_index=turn_index,
        token_dict={
            "issue_timestamp": now,
            "expiration_timestamp": now + timedelta(minutes=10),
        },
        authorized_scopes=("llm_prompt",),
    )


def _build_receiver(
    workdir: Path,
    coordinator: object,
    sink: _MeasuredPromptSink,
) -> Agent:
    """构造严格 dual-route Agent receiver，所有状态写入临时目录。"""
    workdir.mkdir(parents=True, exist_ok=True)
    receiver = Agent.__new__(Agent)
    receiver.aid = _RECEIVER_AID
    receiver.workdir = str(workdir)
    receiver.local_agent = sink
    receiver.task_finished_token = sink.task_finished_token
    receiver.monitor = _NoOpMonitor()
    receiver.llm_monitor = _NoOpMonitor()
    receiver.active_tokens_lock = threading.Lock()
    receiver.active_tokens = {_TOKEN: _token_snapshot()}
    receiver.token_is_valid = lambda _token, _recipient_pac: True
    enable_dual_route_agent_runtime_auth(receiver, coordinator)  # type: ignore[arg-type]
    return receiver


def _token_snapshot() -> dict[str, object]:
    """返回仅用于单次 runner 连接的当前有效 token 快照。"""
    now = datetime.now(tz=timezone.utc)
    return {
        "issue_timestamp": now,
        "expiration_timestamp": now + timedelta(minutes=10),
        "communication_quota": 4,
        "recipient_pac": "network-runner",
    }


def _invalidate_route_b_signature(
    payload: dict[str, object],
    materials: _NetworkMaterials,
) -> None:
    """确定性寻找被标准 backend 拒绝的单 bit 变异并原地更新 transport 字段。"""
    envelope = parse_request_envelope(payload["request_envelope"])
    binding = SignatureBindingV1(
        route_id=SignatureRouteId.ROUTE_B_STANDARD,
        algorithm_id=SignatureAlgorithmId.ML_DSA_44,
        key_id=_ROUTE_B_KEY_ID,
        profile_id=SignatureProfileId.ML_DSA_PURE,
        digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
        canonicalization_id=(
            EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1
        ),
        envelope_digest=envelope.digest(),
    )
    signature = base64.b64decode(str(payload["pq_signature"]), validate=True)
    for index in range(len(signature)):
        candidate = (
            signature[:index]
            + bytes((signature[index] ^ 1,))
            + signature[index + 1 :]
        )
        if materials.route_b_backend.verify(
            materials.route_b_public_key,
            binding.canonical_bytes(),
            candidate,
        ) is False:
            payload["pq_signature"] = base64.b64encode(candidate).decode("ascii")
            return
    raise RuntimeError("failed to derive an invalid Route B signature")


def _build_tls_contexts(root: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """在临时目录生成 loopback TLS 证书，并固定 client/server 为 TLS 1.3。"""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(tz=timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = root / "tls-cert.pem"
    key_path = root / "tls-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(certificate_path, key_path)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.load_verify_locations(cafile=certificate_path)
    client_context.check_hostname = True
    client_context.verify_mode = ssl.CERT_REQUIRED
    return server_context, client_context


def _last_audit_reason(receiver: Agent) -> str | None:
    """读取当前 case 最后一条本地拒绝 reason；正向请求返回 None。"""
    audit_path = Path(receiver.workdir) / "audit" / "execution_gate.jsonl"
    if not audit_path.exists():
        return None
    rows = audit_path.read_text(encoding="utf-8").splitlines()
    if not rows:
        return None
    return str(json.loads(rows[-1]).get("reason"))


def _nearest_rank(ordered: tuple[float, ...], quantile: float) -> float:
    """返回 nearest-rank 分位值。"""
    rank = max(1, min(len(ordered), int((len(ordered) * quantile) + 0.999999)))
    return ordered[rank - 1]


def _is_finite(value: float) -> bool:
    """避免依赖隐式 NaN 排序，显式检查有限浮点。"""
    return value == value and value not in (float("inf"), float("-inf"))


def _python_version() -> str:
    """返回 runner 当前 Python 版本。"""
    import platform

    return platform.python_version()


def main(argv: list[str] | None = None) -> int:
    """运行 opt-in TLS 实验并把版本化 JSON 写入指定路径。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument(
        "--mode",
        choices=(
            "route_b_only",
            "route_b_with_a_shadow",
            "dual_required_research",
        ),
        default="route_b_with_a_shadow",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = run_dual_route_network_experiment(
        sample_count=args.samples,
        mode=args.mode,
    )
    payload = json.dumps(report.as_dict(), sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if report.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
