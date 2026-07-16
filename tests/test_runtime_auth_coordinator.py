"""Tests for the shared runtime-auth Coordinator commit boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import threading
import unittest

from neural import CAN, CompiledToyLWEVerifier
from pq import ToyLWESignatureScheme
from saga.agent import Agent
from saga.execution_gate import (
    CompositeEvidence,
    ExecutionGateRequest,
    InMemoryRevocationStore,
    RuntimeAuthCommitResult,
    SignedRequestExecutionGate,
)
from saga.messages import RequestEnvelope, build_request_envelope


class _UnavailableReplayStore:
    """模拟 Coordinator commit 阶段不可写的 replay backend。"""

    def load_consumed_request_ids(self) -> set[str]:
        """初始化时返回空 replay 状态。"""
        return set()

    def reserve_request(self, request_id: str, envelope: RequestEnvelope) -> str:
        """模拟持久化失败，Coordinator 必须 fail-closed。"""
        raise OSError("replay backend unavailable")


class RuntimeAuthCoordinatorTests(unittest.TestCase):
    """验证 evaluate/commit 分离、唯一 Context 入口与兼容边界。"""

    def setUp(self) -> None:
        """构造固定 toy verifier、可信公钥和测试时间。"""
        self.scheme = ToyLWESignatureScheme(seed=101)
        self.key_pair = self.scheme.keygen()
        self.now = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
        self.sender_aid = "alice@example.com:calendar_agent"
        self.receiver_aid = "bob@example.com:email_agent"

    def _build_gate(
        self,
        *,
        coordinator_mode: str = "strict",
        replay_state_store: object | None = None,
        revocation_store: InMemoryRevocationStore | None = None,
    ) -> SignedRequestExecutionGate:
        """构造 strict 或显式 compatibility gate。"""
        return SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {self.sender_aid: self.key_pair.public_key},
            now_fn=lambda: self.now,
            replay_state_store=replay_state_store,
            revocation_store=revocation_store,
            coordinator_mode=coordinator_mode,  # type: ignore[arg-type]
        )

    def _build_request(
        self,
        *,
        capability_id: str = "cap-coordinator",
        parameters: dict[str, object] | None = None,
    ) -> ExecutionGateRequest:
        """构造带固定 capability id 的合法签名请求。"""
        envelope = build_request_envelope(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token="enc-token",
            session_id="session-coordinator",
            turn_id="turn-coordinator",
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello coordinator",
            capability_id=capability_id,
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        return ExecutionGateRequest(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token="enc-token",
            message="hello coordinator",
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=signature,
            parameters=parameters,
        )

    def test_evaluate_is_repeatable_and_commit_creates_only_committed_context(self) -> None:
        """evaluate 不消费 replay；首次 commit 才产生标记后的 Context。"""
        gate = self._build_gate()
        coordinator = gate.runtime_auth_coordinator
        request = self._build_request()

        first_evidence = coordinator.evaluate(request)
        second_evidence = coordinator.evaluate(request)

        self.assertTrue(first_evidence.accepted)
        self.assertEqual(first_evidence, second_evidence)
        self.assertIsNone(first_evidence.decision.local_execution_context)

        result = coordinator.commit(first_evidence)

        self.assertTrue(result.committed)
        self.assertIsNotNone(result.context)
        assert result.context is not None
        self.assertTrue(result.context.coordinator_committed)
        self.assertIs(result.decision.local_execution_context, result.context)

    def test_second_commit_of_same_evidence_is_replay_rejected(self) -> None:
        """同一 evidence 只能成功 commit 一次。"""
        coordinator = self._build_gate().runtime_auth_coordinator
        evidence = coordinator.evaluate(self._build_request())

        first = coordinator.commit(evidence)
        second = coordinator.commit(evidence)

        self.assertTrue(first.committed)
        self.assertFalse(second.committed)
        self.assertEqual(second.reason, "replayed_request_envelope")
        self.assertIsNone(second.context)

    def test_concurrent_commit_allows_exactly_one_context(self) -> None:
        """并发提交同一 evidence 时只有一个调用能得到 Context。"""
        coordinator = self._build_gate().runtime_auth_coordinator
        evidence = coordinator.evaluate(self._build_request())
        barrier = threading.Barrier(8)

        def commit_once(_index: int) -> RuntimeAuthCommitResult:
            """同步发起 commit，放大 replay reserve 竞争窗口。"""
            barrier.wait()
            return coordinator.commit(evidence)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(commit_once, range(8)))

        self.assertEqual(sum(result.committed for result in results), 1)
        self.assertEqual(
            sum(result.reason == "replayed_request_envelope" for result in results),
            7,
        )
        self.assertEqual(sum(result.context is not None for result in results), 1)

    def test_commit_rejects_request_mutated_after_evaluate(self) -> None:
        """evaluate 后可变 runtime parameters 漂移时不得提交旧 evidence。"""
        parameters: dict[str, object] = {"priority": 1}
        gate = self._build_gate()
        coordinator = gate.runtime_auth_coordinator
        evidence = coordinator.evaluate(self._build_request(parameters=parameters))

        parameters["priority"] = 2
        result = coordinator.commit(evidence)

        self.assertFalse(result.committed)
        self.assertEqual(result.reason, "runtime_auth_evidence_changed")
        self.assertIsNone(result.context)

    def test_commit_rechecks_revocation_after_evaluate(self) -> None:
        """evaluate 与 commit 之间发生撤销时必须拒绝且不 reserve replay。"""
        revocations = InMemoryRevocationStore()
        gate = self._build_gate(revocation_store=revocations)
        coordinator = gate.runtime_auth_coordinator
        request = self._build_request(capability_id="cap-revoke-between-phases")
        evidence = coordinator.evaluate(request)

        revocations.revoke_capability_id("cap-revoke-between-phases")
        result = coordinator.commit(evidence)

        self.assertFalse(result.committed)
        self.assertEqual(result.reason, "capability_revoked")
        self.assertIsNone(result.context)

    def test_commit_fails_closed_when_replay_store_is_unavailable(self) -> None:
        """Replay reserve 故障时 Coordinator 不得创建 Context。"""
        gate = self._build_gate(replay_state_store=_UnavailableReplayStore())
        coordinator = gate.runtime_auth_coordinator

        result = coordinator.commit(coordinator.evaluate(self._build_request()))

        self.assertFalse(result.committed)
        self.assertEqual(result.reason, "replay_state_persistence_failed")
        self.assertIsNone(result.context)

    def test_commit_rejects_invalid_or_foreign_composite_evidence(self) -> None:
        """畸形、内部不一致或其他 Coordinator 的 evidence 不能被 commit。"""
        gate = self._build_gate()
        coordinator = gate.runtime_auth_coordinator
        evidence = coordinator.evaluate(self._build_request())
        foreign_route = replace(evidence.routes[0], route_id="foreign-route")
        mismatched_decision = replace(evidence.decision, reason="forged")
        cases: tuple[tuple[str, object], ...] = (
            ("empty_routes", replace(evidence, routes=())),
            ("invalid_route_type", replace(evidence, routes=(object(),))),  # type: ignore[arg-type]
            ("foreign_route", replace(evidence, routes=(foreign_route,))),
            ("mismatched_decision", replace(evidence, decision=mismatched_decision)),
            ("invalid_evidence_type", object()),
        )

        for label, candidate in cases:
            with self.subTest(case=label):
                result = coordinator.commit(candidate)  # type: ignore[arg-type]
                self.assertFalse(result.committed)
                self.assertEqual(result.reason, "invalid_composite_evidence")

    def test_noncanonical_runtime_parameters_are_rejected_during_evaluate(self) -> None:
        """无法稳定编码的 runtime parameters 不能形成可提交 evidence。"""
        coordinator = self._build_gate().runtime_auth_coordinator

        evidence = coordinator.evaluate(
            self._build_request(parameters={"opaque": object()})
        )

        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.reason, "runtime_auth_request_not_canonical")
        self.assertFalse(coordinator.commit(evidence).committed)

    def test_strict_mode_blocks_all_legacy_context_creation_helpers(self) -> None:
        """strict gate 的 authorize/consume/direct Context API 都必须 fail-closed。"""
        gate = self._build_gate()
        request = self._build_request()
        decision = gate.evaluate_request(request)

        self.assertFalse(gate.authorize(request))
        self.assertEqual(
            gate.consume_request(request).reason,
            "runtime_auth_coordinator_required",
        )
        self.assertIsNone(gate.build_local_execution_context(request))
        self.assertIsNone(
            gate.build_local_execution_context_from_decision(request, decision)
        )

    def test_compatibility_context_is_marked_and_rejected_by_strict_prompt(self) -> None:
        """兼容 helper 生成的未提交 Context 不能进入 strict prompt sink。"""
        gate = self._build_gate(coordinator_mode="compatibility")
        context = gate.build_local_execution_context(self._build_request())
        assert context is not None
        self.assertFalse(context.coordinator_committed)
        agent = Agent.__new__(Agent)
        agent.enforcement_mode = "strict"
        agent.strict_execution_gate = True

        decision = Agent._evaluate_prompt_surface_request(agent, context)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "uncommitted_local_execution_context")

    def test_evidence_objects_are_frozen(self) -> None:
        """Route/Composite evidence 不能在 evaluate 后被原地改写。"""
        evidence: CompositeEvidence = self._build_gate().runtime_auth_coordinator.evaluate(
            self._build_request()
        )

        with self.assertRaises(FrozenInstanceError):
            evidence.reason = "forged"  # type: ignore[misc]

    def test_unknown_coordinator_mode_is_rejected(self) -> None:
        """未知 coordinator mode 必须在 gate 初始化时 fail-closed。"""
        with self.assertRaisesRegex(ValueError, "coordinator_mode"):
            self._build_gate(coordinator_mode="permissive")


if __name__ == "__main__":
    unittest.main()
