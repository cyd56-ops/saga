"""Agent socket-path integration tests for the R18 dual-route Coordinator."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest

import cryptography

from neural import (
    BoundedA0ShadowQueue,
    CompiledToyLWEVerifier,
    InMemoryA0ShadowOutbox,
    RouteBFixedAuthorizationCircuitRoute,
)
from pq import (
    CryptographyMLDSABackend,
    ML_DSA_CONTEXT_V1,
    MLDSABackendContractV1,
    MLDSARouteBVerifier,
    SignatureAlgorithmId,
    SignatureProfileId,
    ToyLWESignatureScheme,
)
from saga.agent import Agent
from saga.durable_authorization import SQLiteDurableAuthorizationStateStore
from saga.dual_route_runtime import (
    DualRouteNetworkRequestAdapterV1,
    DualRouteTransportSignerV1,
    build_dual_route_runtime_coordinator,
    enable_dual_route_agent_runtime_auth,
)


class _NoOpMonitor:
    """提供 Agent socket 测试所需的最小计时接口。"""

    def start(self, _name: str) -> None:
        """忽略计时开始。"""

    def stop(self, _name: str) -> None:
        """忽略计时结束。"""


class _FramedDuplexBuffer:
    """在受限 CI 中复现 socket 的 sendall/recv 顺序与分帧语义。"""

    def __init__(self) -> None:
        """初始化单会话有序字节缓冲区。"""
        self._buffer = bytearray()

    def sendall(self, data: bytes) -> None:
        """追加一个 Agent 长度前缀帧。"""
        self._buffer.extend(data)

    def recv(self, size: int) -> bytes:
        """按 socket.recv 约定消费至多 size 字节。"""
        chunk = bytes(self._buffer[:size])
        del self._buffer[:size]
        return chunk


class _PromptSink:
    """记录实际到达 prompt sink 的 committed Context。"""

    task_finished_token = "<TASK_FINISHED>"

    def __init__(self) -> None:
        """初始化调用次数和 Context 观测。"""
        self.run_calls = 0
        self.contexts: list[object | None] = []

    def supports_execution_context(self) -> bool:
        """声明该测试 sink 会执行 Context 授权检查。"""
        return True

    def set_strict_execution_capabilities(self, _enabled: bool) -> None:
        """接受外层 strict capability 模式同步。"""

    def run(
        self,
        _query: str,
        *,
        initiating_agent: bool,
        agent_instance: object | None = None,
        **kwargs: object,
    ) -> tuple[object | None, str]:
        """只记录 Context，不产生工具、memory 或 delegation 副作用。"""
        del initiating_agent
        self.run_calls += 1
        self.contexts.append(kwargs.get("execution_context"))
        return agent_instance, self.task_finished_token


class DualRouteAgentNetworkTests(unittest.TestCase):
    """验证真实 socket framing 到 durable commit 和 prompt sink 的强制路径。"""

    @classmethod
    def setUpClass(cls) -> None:
        """创建进程内短生命周期 A/B 测试密钥与固定 verifier。"""
        cls.sender_aid = "alice@example.com:calendar_agent"
        cls.receiver_aid = "bob@example.com:email_agent"
        cls.token = "dual-route-network-token"
        cls.route_b_key_id = b"route-b-network-key"
        cls.route_a_key_id = b"route-a-network-key"
        cls.route_b_backend = CryptographyMLDSABackend(
            SignatureAlgorithmId.ML_DSA_44
        )
        descriptor = cls.route_b_backend.descriptor()
        cls.route_b_public_key, cls.route_b_secret_key = (
            cls.route_b_backend.keygen()
        )
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
        cls.route_b = RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(cls.route_b_backend, contract)
        )
        cls.route_a_scheme = ToyLWESignatureScheme(seed=912)
        cls.route_a_keys = cls.route_a_scheme.keygen()
        cls.route_a_verifier = CompiledToyLWEVerifier(
            cls.route_a_scheme,
            message_bytes=32,
        )
        cls.transport_signer = DualRouteTransportSignerV1(
            route_b_signer=cls.route_b_backend,
            route_b_secret_key=cls.route_b_secret_key,
            route_b_key_id=cls.route_b_key_id,
            route_b_algorithm_id=SignatureAlgorithmId.ML_DSA_44,
            route_b_profile_id=SignatureProfileId.ML_DSA_PURE,
            route_a_signer=cls.route_a_scheme,
            route_a_secret_key=cls.route_a_keys.secret_key,
        )

    def _sender(self) -> Agent:
        """构造只负责 canonical envelope 与 detached A/B 签名的发送端。"""
        sender = Agent.__new__(Agent)
        sender.aid = self.sender_aid
        sender.provider_id = "provider-network-test"
        sender.runtime_auth_payload_signer = self.transport_signer
        sender.runtime_auth_capability_ttl_seconds = 300
        return sender

    def _receiver(
        self,
        *,
        workdir: Path,
        coordinator: object,
        sink: _PromptSink,
    ) -> Agent:
        """构造使用真实 Agent receive 方法、socket framing 和 strict gate 的接收端。"""
        receiver = Agent.__new__(Agent)
        receiver.aid = self.receiver_aid
        receiver.workdir = str(workdir)
        receiver.local_agent = sink
        receiver.task_finished_token = sink.task_finished_token
        receiver.monitor = _NoOpMonitor()
        receiver.llm_monitor = _NoOpMonitor()
        receiver.active_tokens_lock = threading.Lock()
        receiver.active_tokens = {self.token: self._token_snapshot()}
        receiver.token_is_valid = lambda _token, _recipient_pac: True
        enable_dual_route_agent_runtime_auth(receiver, coordinator)  # type: ignore[arg-type]
        return receiver

    @staticmethod
    def _token_snapshot() -> dict[str, object]:
        """返回当前有效、足够完成一次收发的 token 快照。"""
        now = datetime.now(tz=timezone.utc)
        return {
            "issue_timestamp": now,
            "expiration_timestamp": now + timedelta(minutes=10),
            "communication_quota": 4,
            "recipient_pac": "network-test",
        }

    def _payload(self, *, message: str, turn_index: int) -> dict[str, object]:
        """通过 Agent 发送侧 hook 构造真实 transport payload。"""
        return self._sender()._build_conversation_payload(
            receiver_aid=self.receiver_aid,
            token=self.token,
            message=message,
            action_scope="llm_prompt",
            turn_index=turn_index,
            token_dict=self._token_snapshot(),
            authorized_scopes=("llm_prompt",),
        )

    def _exchange(self, receiver: Agent, payload: dict[str, object]) -> bool:
        """用真实长度前缀 socket 帧向 Agent.receive_conversation 发送一条请求。"""
        transport = _FramedDuplexBuffer()
        Agent.send(self._sender(), transport, payload)
        return receiver.receive_conversation(
            transport,
            self.token,
            recipient_pac=object(),
            sender_aid=self.sender_aid,
        )

    def test_socket_receive_uses_only_durable_dual_route_context(self) -> None:
        """默认 B+A-shadow 网络请求仅在 durable commit 后到达 prompt sink。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outbox = InMemoryA0ShadowOutbox()
            with BoundedA0ShadowQueue(self.route_a_verifier, outbox) as queue:
                now_fn = lambda: datetime.now(tz=timezone.utc)
                adapter = DualRouteNetworkRequestAdapterV1(
                    route_b_key_ids_by_sender={
                        self.sender_aid: self.route_b_key_id
                    },
                    route_b_algorithm_id=SignatureAlgorithmId.ML_DSA_44,
                    route_b_profile_id=SignatureProfileId.ML_DSA_PURE,
                    route_a_key_ids_by_sender={
                        self.sender_aid: self.route_a_key_id
                    },
                    now_fn=now_fn,
                )
                store = SQLiteDurableAuthorizationStateStore(
                    root / "authorization.sqlite3",
                    now_fn=now_fn,
                )
                coordinator = build_dual_route_runtime_coordinator(
                    mode="route_b_with_a_shadow",
                    durable_authorization_state_store=store,
                    route_b_evaluator=self.route_b,
                    route_b_public_keys={
                        self.route_b_key_id: self.route_b_public_key
                    },
                    route_a_public_keys={
                        self.route_a_key_id: self.route_a_keys.public_key
                    },
                    route_a_verifier=self.route_a_verifier,
                    route_a_shadow_submitter=queue,
                    network_request_adapter=adapter,
                    now_fn=now_fn,
                )
                sink = _PromptSink()
                first_receiver = self._receiver(
                    workdir=root / "first",
                    coordinator=coordinator,
                    sink=sink,
                )
                payload = self._payload(message="network authorized", turn_index=0)

                self.assertTrue(self._exchange(first_receiver, payload))
                self.assertEqual(sink.run_calls, 1)
                self.assertEqual(len(sink.contexts), 1)
                context = sink.contexts[0]
                self.assertIsNotNone(context)
                self.assertTrue(context.coordinator_committed)  # type: ignore[union-attr]
                self.assertTrue(context.durable_authorization_required)  # type: ignore[union-attr]
                self.assertTrue(queue.await_idle(2.0))
                self.assertEqual(len(outbox.snapshot()), 1)
                self.assertFalse(outbox.snapshot()[0].authority_granted)

                replay_receiver = self._receiver(
                    workdir=root / "replay",
                    coordinator=coordinator,
                    sink=sink,
                )
                self.assertTrue(self._exchange(replay_receiver, payload))
                self.assertEqual(sink.run_calls, 1)
                replay_audit = Path(replay_receiver.workdir) / "audit" / "execution_gate.jsonl"
                rows = [
                    json.loads(line)
                    for line in replay_audit.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(rows[-1]["reason"], "replayed_request_envelope")

                tampered = self._payload(message="network tampered", turn_index=1)
                signature = base64.b64decode(
                    str(tampered["pq_signature"]),
                    validate=True,
                )
                tampered["pq_signature"] = base64.b64encode(
                    bytes((signature[0] ^ 1,)) + signature[1:]
                ).decode("ascii")
                tampered_receiver = self._receiver(
                    workdir=root / "tampered",
                    coordinator=coordinator,
                    sink=sink,
                )
                self.assertTrue(self._exchange(tampered_receiver, tampered))
                self.assertEqual(sink.run_calls, 1)
                tampered_audit = (
                    Path(tampered_receiver.workdir)
                    / "audit"
                    / "execution_gate.jsonl"
                )
                tampered_rows = [
                    json.loads(line)
                    for line in tampered_audit.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(tampered_rows[-1]["reason"], "route_b_rejected")


if __name__ == "__main__":
    unittest.main()
