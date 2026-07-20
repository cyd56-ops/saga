"""Tests for the R17 durable authorization state machine and audit outbox."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import threading
import unittest

from neural import CAN, CompiledToyLWEVerifier
from pq import ToyLWESignatureScheme
from saga.durable_authorization import (
    DurableAuthorizationCommitV1,
    SQLiteDurableAuthorizationStateStore,
    dispatch_authorization_outbox,
)
from saga.agent import Agent
from saga.execution_gate import (
    ExecutionGateRequest,
    FileReplayStateStore,
    RuntimeAuthCommitResult,
    SignedRequestExecutionGate,
    build_toy_lwe_execution_gate,
)
from saga.messages import build_request_envelope


class _UnavailableDurableStore:
    """模拟 evaluate 可读但 commit 持久化失败的 durable backend。"""

    def revocation_status(self, _envelope: object) -> str:
        """允许 evaluate 继续到 durable commit。"""
        return "active"

    def commit_authorization(self, _commit: object) -> str:
        """模拟事务数据库在 commit 时不可用。"""
        raise OSError("database unavailable")

    def consume_budget(self, _envelope: object, _action_scope: str) -> str:
        """该测试不会进入 Context 消费。"""
        raise OSError("database unavailable")


class DurableAuthorizationStateTests(unittest.TestCase):
    """验证 R17 状态迁移、唯一 Context、事务撤销/预算与 outbox 恢复。"""

    def setUp(self) -> None:
        """创建确定性 toy 签名材料和固定 UTC 时间。"""
        self.scheme = ToyLWESignatureScheme(seed=701)
        self.key_pair = self.scheme.keygen()
        self.now = datetime(2026, 7, 20, 15, 0, 0, tzinfo=timezone.utc)
        self.sender_aid = "alice@example.com:calendar_agent"
        self.receiver_aid = "bob@example.com:email_agent"

    def _store(self, database_path: Path) -> SQLiteDurableAuthorizationStateStore:
        """构造使用固定时钟的 SQLite durable store。"""
        return SQLiteDurableAuthorizationStateStore(
            database_path,
            now_fn=lambda: self.now,
        )

    def _gate(self, store: object) -> SignedRequestExecutionGate:
        """构造只使用统一 durable store 的 strict gate。"""
        return SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
            {self.sender_aid: self.key_pair.public_key},
            now_fn=lambda: self.now,
            durable_authorization_state_store=store,  # type: ignore[arg-type]
        )

    def _request(
        self,
        *,
        turn_id: str = "turn-durable",
        capability_id: str = "cap-durable",
        execution_budget: dict[str, int] | None = None,
    ) -> ExecutionGateRequest:
        """构造绑定固定请求事实和可选 signed budget 的合法请求。"""
        envelope = build_request_envelope(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token="enc-token",
            session_id="session-durable",
            turn_id=turn_id,
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=4),
            action_scope="llm_prompt",
            message="durable request",
            capability_id=capability_id,
            execution_budget=execution_budget,
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        return ExecutionGateRequest(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token="enc-token",
            message="durable request",
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=signature,
        )

    def _commit_record(
        self,
        gate: SignedRequestExecutionGate,
        request: ExecutionGateRequest,
    ) -> DurableAuthorizationCommitV1:
        """从纯 evaluate evidence 构造与 Coordinator 相同的 durable commit。"""
        coordinator = gate.runtime_auth_coordinator
        evidence = coordinator.evaluate(request)
        route = evidence.routes[0]
        assert evidence.decision.request_envelope is not None
        assert route.request_fingerprint is not None
        return DurableAuthorizationCommitV1(
            request_id=evidence.decision.request_envelope.hex_digest(),
            request_fingerprint=route.request_fingerprint,
            route_id=coordinator.route_id,
            decision_reason=evidence.decision.reason,
            envelope=evidence.decision.request_envelope,
        )

    def test_pending_state_survives_restart_and_same_evidence_resumes_commit(self) -> None:
        """prepare 后崩溃留下的 PENDING 应可由同 fingerprint 安全完成提交。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "authorization.sqlite3"
            first_store = self._store(database_path)
            gate = self._gate(first_store)
            commit = self._commit_record(gate, self._request())

            self.assertEqual(first_store.prepare_authorization(commit), "prepared")
            pending = first_store.authorization_record(commit.request_id)
            assert pending is not None
            self.assertEqual(pending.state, "PENDING")

            restarted_store = self._store(database_path)
            self.assertEqual(
                restarted_store.commit_authorization(commit),
                "committed",
            )
            committed = restarted_store.authorization_record(commit.request_id)
            assert committed is not None
            self.assertEqual(committed.state, "COMMITTED")
            self.assertEqual(
                committed.context_fingerprint,
                commit.context_fingerprint(),
            )
            self.assertEqual(
                restarted_store.load_consumed_request_ids(),
                {commit.request_id},
            )
            self.assertEqual(
                [event.event_type for event in restarted_store.pending_outbox_events()],
                ["authorization_pending", "authorization_committed"],
            )

    def test_pending_can_be_rejected_but_committed_authority_cannot_be_rewritten(self) -> None:
        """显式 abort 只能终结匹配的 PENDING，不能把已提交 authority 改写为拒绝。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            gate = self._gate(store)
            pending = self._commit_record(gate, self._request(turn_id="pending-abort"))
            self.assertEqual(store.prepare_authorization(pending), "prepared")
            self.assertEqual(
                store.reject_pending(
                    pending.request_id,
                    "0" * 64,
                    reason="wrong evidence",
                ),
                "conflict",
            )
            self.assertEqual(
                store.reject_pending(
                    pending.request_id,
                    pending.request_fingerprint,
                    reason="coordinator_aborted",
                ),
                "rejected",
            )
            rejected = store.authorization_record(pending.request_id)
            assert rejected is not None
            self.assertEqual(rejected.state, "REJECTED")
            self.assertEqual(rejected.state_reason, "coordinator_aborted")
            self.assertEqual(store.commit_authorization(pending), "rejected")

            committed = self._commit_record(
                gate,
                self._request(turn_id="committed-no-rewrite"),
            )
            self.assertEqual(store.commit_authorization(committed), "committed")
            self.assertEqual(
                store.reject_pending(
                    committed.request_id,
                    committed.request_fingerprint,
                    reason="late abort",
                ),
                "conflict",
            )
            self.assertEqual(
                store.reject_pending("f" * 64, "e" * 64, reason="missing"),
                "missing",
            )

    def test_coordinator_restart_rejects_committed_replay_without_second_context(self) -> None:
        """COMMITTED 请求在新 gate 进程语义下只能 replay reject，不能重发 Context。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "authorization.sqlite3"
            first_store = self._store(database_path)
            request = self._request()
            first = self._gate(first_store).runtime_auth_coordinator

            committed = first.commit(first.evaluate(request))

            self.assertTrue(committed.committed)
            self.assertIsNotNone(committed.context)
            assert committed.context is not None
            self.assertTrue(committed.context.durable_authorization_required)
            self.assertIsNot(committed.context.capability_state_store, first_store)
            self.assertFalse(
                hasattr(
                    committed.context.capability_state_store,
                    "commit_authorization",
                )
            )

            restarted = self._gate(self._store(database_path)).runtime_auth_coordinator
            replay = restarted.commit(restarted.evaluate(request))
            self.assertFalse(replay.committed)
            self.assertEqual(replay.reason, "replayed_request_envelope")
            self.assertIsNone(replay.context)

    def test_concurrent_durable_commit_returns_exactly_one_context(self) -> None:
        """多个线程竞争同一请求时 SQLite 状态机只能发布一个 committed Context。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            coordinator = self._gate(store).runtime_auth_coordinator
            evidence = coordinator.evaluate(self._request())
            barrier = threading.Barrier(8)

            def commit_once(_index: int) -> RuntimeAuthCommitResult:
                """同步开始 durable commit，放大 PENDING/COMMITTED 竞争窗口。"""
                barrier.wait()
                return coordinator.commit(evidence)

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(commit_once, range(8)))

            self.assertEqual(sum(result.committed for result in results), 1)
            self.assertEqual(sum(result.context is not None for result in results), 1)
            self.assertEqual(
                sum(result.reason == "replayed_request_envelope" for result in results),
                7,
            )

    def test_revocation_between_prepare_and_commit_transitions_to_rejected(self) -> None:
        """PENDING 后出现撤销时 finalize 必须原子转 REJECTED 并写 outbox。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            gate = self._gate(store)
            commit = self._commit_record(
                gate,
                self._request(capability_id="cap-revoke-durable"),
            )

            self.assertEqual(store.prepare_authorization(commit), "prepared")
            store.revoke_capability_id("cap-revoke-durable", reason="operator")
            self.assertEqual(
                store.commit_authorization(commit),
                "capability_revoked",
            )
            rejected = store.authorization_record(commit.request_id)
            assert rejected is not None
            self.assertEqual(rejected.state, "REJECTED")
            self.assertEqual(rejected.state_reason, "capability_revoked")
            self.assertEqual(
                [event.event_type for event in store.pending_outbox_events()],
                [
                    "authorization_pending",
                    "capability_revoked",
                    "authorization_rejected",
                ],
            )

    def test_parent_revocation_has_distinct_status_and_outbox_event(self) -> None:
        """父 capability 撤销应保留级联语义，不能伪装成子 capability 自身撤销。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            parent_digest = "a" * 64
            child = build_request_envelope(
                sender_aid=self.sender_aid,
                receiver_aid=self.receiver_aid,
                token="enc-token",
                session_id="session-durable",
                turn_id="parent-revoked",
                issued_at=self.now - timedelta(minutes=1),
                expires_at=self.now + timedelta(minutes=4),
                action_scope="llm_prompt",
                message="durable request",
                capability_id="cap-child",
                parent_envelope_digest=parent_digest,
                delegation_depth=1,
                timestamp=self.now,
            )

            store.revoke_parent_envelope_digest(parent_digest, reason="parent stopped")

            self.assertEqual(store.revocation_status(child), "parent_capability_revoked")
            event = store.pending_outbox_events()[0]
            self.assertEqual(event.event_type, "parent_capability_revoked")
            self.assertEqual(event.payload()["revocation_type"], "parent_envelope_digest")

    def test_context_consumption_and_budget_update_share_one_database(self) -> None:
        """首次 Context 使用应转 CONSUMED，预算耗尽后拒绝且不扩大计数。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            coordinator = self._gate(store).runtime_auth_coordinator
            request = self._request(
                execution_budget={"total": 1, "llm_prompt": 1},
            )
            result = coordinator.commit(coordinator.evaluate(request))
            assert result.context is not None

            agent = Agent.__new__(Agent)
            agent.enforcement_mode = "strict"
            agent.strict_execution_gate = True
            prompt_decision = Agent._evaluate_prompt_surface_request(
                agent,
                result.context,
            )
            self.assertTrue(prompt_decision.allowed)

            request_id = result.context.request_envelope.hex_digest()
            consumed = store.authorization_record(request_id)
            assert consumed is not None
            self.assertEqual(consumed.state, "CONSUMED")
            self.assertIn(request_id, store.load_consumed_request_ids())
            exhausted = Agent._evaluate_prompt_surface_request(agent, result.context)
            self.assertFalse(exhausted.allowed)
            self.assertEqual(exhausted.reason, "capability_budget_exhausted")
            self.assertEqual(
                [event.event_type for event in store.pending_outbox_events()],
                [
                    "authorization_pending",
                    "authorization_committed",
                    "authorization_consumed",
                ],
            )

    def test_outbox_delivery_failure_remains_pending_then_retries(self) -> None:
        """投递失败不得确认事件；重试成功后 pending 集合应清空。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            coordinator = self._gate(store).runtime_auth_coordinator
            result = coordinator.commit(coordinator.evaluate(self._request()))
            self.assertTrue(result.committed)
            original_ids = tuple(
                event.event_id for event in store.pending_outbox_events()
            )

            def fail_delivery(_event: object) -> None:
                """模拟外部 audit sink 在确认前失败。"""
                raise RuntimeError("sink unavailable")

            with self.assertRaisesRegex(RuntimeError, "sink unavailable"):
                dispatch_authorization_outbox(store, fail_delivery)
            self.assertEqual(
                tuple(event.event_id for event in store.pending_outbox_events()),
                original_ids,
            )

            delivered: list[str] = []
            delivered_count = dispatch_authorization_outbox(
                store,
                lambda event: delivered.append(event.event_id),
            )
            self.assertEqual(delivered_count, len(original_ids))
            self.assertEqual(tuple(delivered), original_ids)
            self.assertEqual(store.pending_outbox_events(), ())
            self.assertEqual(dispatch_authorization_outbox(store, lambda _event: None), 0)

    def test_fingerprint_conflict_and_store_failure_fail_closed(self) -> None:
        """同 request id 的 fingerprint 漂移及数据库故障都不能创建 Context。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            gate = self._gate(store)
            commit = self._commit_record(gate, self._request())
            self.assertEqual(store.prepare_authorization(commit), "prepared")
            conflicting = replace(commit, request_fingerprint="0" * 64)
            self.assertEqual(store.prepare_authorization(conflicting), "conflict")
            foreign_route = replace(commit, route_id="foreign-route")
            self.assertEqual(store.prepare_authorization(foreign_route), "conflict")

        unavailable_coordinator = self._gate(
            _UnavailableDurableStore()
        ).runtime_auth_coordinator
        unavailable = unavailable_coordinator.commit(
            unavailable_coordinator.evaluate(self._request(turn_id="unavailable"))
        )
        self.assertFalse(unavailable.committed)
        self.assertEqual(unavailable.reason, "durable_authorization_state_unavailable")
        self.assertIsNone(unavailable.context)

    def test_durable_profile_cannot_mix_independent_stores_or_compatibility(self) -> None:
        """统一事务 profile 禁止混用独立 replay store 或 compatibility Coordinator。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            durable = self._store(root / "authorization.sqlite3")
            replay = FileReplayStateStore(root / "replay")
            with self.assertRaisesRegex(ValueError, "cannot be mixed"):
                SignedRequestExecutionGate(
                    CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                    {self.sender_aid: self.key_pair.public_key},
                    replay_state_store=replay,
                    durable_authorization_state_store=durable,
                )
            with self.assertRaisesRegex(ValueError, "strict coordinator"):
                SignedRequestExecutionGate(
                    CAN(CompiledToyLWEVerifier(self.scheme, message_bytes=32)),
                    {self.sender_aid: self.key_pair.public_key},
                    durable_authorization_state_store=durable,
                    coordinator_mode="compatibility",
                )

            factory_gate = build_toy_lwe_execution_gate(
                self.scheme,
                {self.sender_aid: self.key_pair.public_key},
                now_fn=lambda: self.now,
                durable_authorization_state_store=durable,
            )
            committed = factory_gate.runtime_auth_coordinator.commit(
                factory_gate.runtime_auth_coordinator.evaluate(
                    self._request(turn_id="factory")
                )
            )
            self.assertTrue(committed.committed)

    def test_persisted_records_and_outbox_exclude_signature_and_message_material(self) -> None:
        """durable 表只保存公开元数据和摘要，不复制签名、token 或 message 原文。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir) / "authorization.sqlite3")
            request = self._request(turn_id="redacted")
            coordinator = self._gate(store).runtime_auth_coordinator
            result = coordinator.commit(coordinator.evaluate(request))
            self.assertTrue(result.committed)
            encoded = "\n".join(
                event.payload_json for event in store.pending_outbox_events()
            )
            payloads = [event.payload() for event in store.pending_outbox_events()]
            self.assertTrue(all(payload["schema_version"] == 1 for payload in payloads))
            self.assertNotIn("durable request", encoded)
            self.assertNotIn("enc-token", encoded)
            self.assertNotIn(self.key_pair.secret_key.hex(), encoded)
            assert isinstance(request.pq_signature, bytes)
            self.assertNotIn(request.pq_signature.hex(), encoded)


if __name__ == "__main__":
    unittest.main()
