"""Tests for R18 four-mode Route A/B runtime integration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest

import cryptography

from neural import (
    A0ShadowSubmission,
    BoundedA0ShadowQueue,
    CompiledToyLWEVerifier,
    InMemoryA0ShadowOutbox,
    RouteBFixedAuthorizationCircuitRoute,
    RouteBShadowRequest,
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
from saga.durable_authorization import SQLiteDurableAuthorizationStateStore
from saga.dual_route_runtime import (
    DualRouteAuthorizationRequestV1,
    DualRouteRuntimeAuthCoordinator,
    RouteAIntegrationEvidenceV1,
    build_dual_route_runtime_coordinator,
)
from saga.execution_gate import ExecutionGateRequest
from saga.messages import build_request_envelope


class _CachedRouteB:
    """在线程测试中重复返回一个已经自校验的真实 Route B evidence。"""

    def __init__(self, evidence: object) -> None:
        self.evidence = evidence

    def evaluate(self, _request: object, _public_key: bytes, _signature: bytes) -> object:
        """返回构造时保存的无状态 evidence。"""
        return self.evidence


class _FaultRouteB:
    """模拟 Route B evaluator 异常。"""

    def evaluate(self, _request: object, _public_key: bytes, _signature: bytes) -> object:
        """抛出不包含在 integration evidence 中的诊断消息。"""
        raise RuntimeError("private backend diagnostic")


class _MismatchedShadowSubmitter:
    """返回错误 job digest，模拟不符合 A0 queue contract 的 submitter。"""

    def submit(self, _job: object) -> A0ShadowSubmission:
        """构造零 authority 但绑定错误 job 的 submission。"""
        return A0ShadowSubmission(True, "shadow_job_queued", "0" * 64)


class DualRouteRuntimeTests(unittest.TestCase):
    """验证四模式公式、唯一 durable authority、shadow 隔离与 trust binding。"""

    @classmethod
    def setUpClass(cls) -> None:
        """创建只驻留内存的真实 ML-DSA 与 deterministic toy Route A 密钥。"""
        cls.now = datetime(2026, 7, 20, 18, 0, tzinfo=timezone.utc)
        cls.sender_aid = "alice@example.com:calendar_agent"
        cls.receiver_aid = "bob@example.com:email_agent"
        cls.token = "dual-route-token"
        cls.message = "authorize dual route"
        cls.route_b_key_id = b"route-b-integration-key"
        cls.route_a_key_id = b"route-a-integration-key"

        cls.mldsa_backend = CryptographyMLDSABackend(SignatureAlgorithmId.ML_DSA_44)
        descriptor = cls.mldsa_backend.descriptor()
        cls.mldsa_contract = MLDSABackendContractV1(
            backend_name="cryptography",
            backend_version=cryptography.__version__,
            provider_name="OpenSSL",
            provider_version=descriptor.provider_version,
            algorithm_id=SignatureAlgorithmId.ML_DSA_44,
            profile_id=SignatureProfileId.ML_DSA_PURE,
            context=ML_DSA_CONTEXT_V1,
            timeout_seconds=1.0,
        )
        cls.route_b_public_key, cls.route_b_secret_key = cls.mldsa_backend.keygen()
        cls.route_b = RouteBFixedAuthorizationCircuitRoute(
            MLDSARouteBVerifier(cls.mldsa_backend, cls.mldsa_contract)
        )

        cls.route_a_scheme = ToyLWESignatureScheme(seed=811)
        cls.route_a_keys = cls.route_a_scheme.keygen()
        cls.route_a_verifier = CompiledToyLWEVerifier(
            cls.route_a_scheme,
            message_bytes=32,
        )

    def _request(
        self,
        *,
        turn_id: str,
        route_b_valid: bool = True,
        route_a_valid: bool = True,
        route_b_key_id: bytes | None = None,
        route_a_key_id: bytes | None = None,
        include_route_a: bool = True,
        parameters: dict[str, object] | None = None,
    ) -> DualRouteAuthorizationRequestV1:
        """构造同一 envelope 上的真实 B 签名与可选 A toy 签名。"""
        envelope = build_request_envelope(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token=self.token,
            session_id="session-dual-route",
            turn_id=turn_id,
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(minutes=4),
            action_scope="llm_prompt",
            message=self.message,
            capability_id=f"cap-{turn_id}",
            timestamp=self.now,
        )
        binding = SignatureBindingV1(
            route_id=SignatureRouteId.ROUTE_B_STANDARD,
            algorithm_id=SignatureAlgorithmId.ML_DSA_44,
            key_id=route_b_key_id or self.route_b_key_id,
            profile_id=SignatureProfileId.ML_DSA_PURE,
            digest_algorithm_id=EnvelopeDigestAlgorithmId.SHA256,
            canonicalization_id=EnvelopeCanonicalizationId.SAGA_REQUEST_ENVELOPE_JSON_V1,
            envelope_digest=envelope.digest(),
        )
        route_b_signature = self.mldsa_backend.sign(
            self.route_b_secret_key,
            binding.canonical_bytes(),
        )
        if not route_b_valid:
            route_b_signature = route_b_signature[:-1] + bytes(
                (route_b_signature[-1] ^ 1,)
            )
        route_b_request = RouteBShadowRequest(
            binding=binding,
            envelope=envelope,
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token_digest=hashlib.sha256(self.token.encode("utf-8")).digest(),
            message_digest=hashlib.sha256(self.message.encode("utf-8")).digest(),
            action_scope="llm_prompt",
            observed_at=self.now,
            parameters=parameters,
            flow_labels=("public",),
        )
        execution_request = ExecutionGateRequest(
            sender_aid=self.sender_aid,
            receiver_aid=self.receiver_aid,
            token=self.token,
            message=self.message,
            action_scope="llm_prompt",
            request_envelope=envelope.canonical_json(),
            pq_signature=route_b_signature,
            parameters=parameters,
        )
        route_a_signature = self.route_a_scheme.sign(
            self.route_a_keys.secret_key,
            envelope.digest(),
        )
        if not route_a_valid:
            route_a_signature = route_a_signature[:-1] + bytes(
                (route_a_signature[-1] ^ 1,)
            )
        return DualRouteAuthorizationRequestV1(
            execution_request=execution_request,
            route_b_request=route_b_request,
            route_a_key_id=(route_a_key_id or self.route_a_key_id) if include_route_a else None,
            route_a_signature=route_a_signature if include_route_a else None,
        )

    def _store(self, root: Path) -> SQLiteDurableAuthorizationStateStore:
        """构造使用临时数据库与固定时间的 R17 store。"""
        return SQLiteDurableAuthorizationStateStore(
            root / "dual-route.sqlite3",
            now_fn=lambda: self.now,
        )

    def _coordinator(
        self,
        root: Path,
        *,
        mode: str,
        route_b: object | None = None,
        shadow_queue: object | None = None,
    ) -> DualRouteRuntimeAuthCoordinator:
        """按指定 mode 构造使用本地 A/B trust registry 的 Coordinator。"""
        return build_dual_route_runtime_coordinator(
            mode=mode,  # type: ignore[arg-type]
            durable_authorization_state_store=self._store(root),
            route_b_evaluator=route_b or self.route_b,  # type: ignore[arg-type]
            route_b_public_keys={self.route_b_key_id: self.route_b_public_key},
            route_a_public_keys={self.route_a_key_id: self.route_a_keys.public_key},
            route_a_verifier=self.route_a_verifier,
            route_a_shadow_submitter=shadow_queue,  # type: ignore[arg-type]
            now_fn=lambda: self.now,
        )

    def test_route_b_only_commits_once_and_uses_durable_context(self) -> None:
        """B-only 只由 B 接受决定，且唯一 Context 必须来自 durable Coordinator。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            coordinator = self._coordinator(root, mode="route_b_only")
            request = self._request(turn_id="b-only", route_a_valid=False)

            evidence = coordinator.evaluate(request)
            first = coordinator.commit(evidence)
            replay = coordinator.commit(evidence)

            self.assertTrue(evidence.formula_accept)
            self.assertEqual(evidence.route_a.status, "not_requested")
            self.assertTrue(first.committed)
            assert first.context is not None
            self.assertTrue(first.context.durable_authorization_required)
            self.assertIs(coordinator.state_gate.runtime_auth_coordinator, coordinator)
            self.assertEqual(coordinator.state_gate.trusted_public_keys, {})
            self.assertFalse(replay.committed)
            self.assertEqual(replay.reason, "replayed_request_envelope")

    def test_route_b_with_a_shadow_commits_before_non_authoritative_submission(self) -> None:
        """默认模式由 B 提交 authority，A late evidence 只作异步观测。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            outbox = InMemoryA0ShadowOutbox()
            with BoundedA0ShadowQueue(self.route_a_verifier, outbox) as queue:
                coordinator = self._coordinator(
                    Path(tmpdir),
                    mode="route_b_with_a_shadow",
                    shadow_queue=queue,
                )
                evidence = coordinator.evaluate(self._request(turn_id="shadow"))
                self.assertEqual(evidence.route_a.status, "planned")
                self.assertEqual(outbox.snapshot(), ())

                result = coordinator.commit(evidence)

                self.assertTrue(result.committed)
                self.assertIsNotNone(result.shadow_submission)
                assert result.shadow_submission is not None
                self.assertFalse(result.shadow_submission.authority_granted)
                self.assertTrue(queue.await_idle(2.0))
                late = outbox.snapshot()
                self.assertEqual(len(late), 1)
                self.assertEqual(late[0].accept_output, 1)
                self.assertFalse(late[0].authority_granted)

    def test_shadow_queue_drop_does_not_roll_back_route_b_authority(self) -> None:
        """A queue 关闭或丢弃只改变 shadow reason，不能降低或扩大 B authority。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            outbox = InMemoryA0ShadowOutbox()
            queue = BoundedA0ShadowQueue(self.route_a_verifier, outbox)
            self.assertTrue(queue.close())
            coordinator = self._coordinator(
                Path(tmpdir),
                mode="route_b_with_a_shadow",
                shadow_queue=queue,
            )

            result = coordinator.commit(
                coordinator.evaluate(self._request(turn_id="shadow-drop"))
            )

            self.assertTrue(result.committed)
            assert result.shadow_submission is not None
            self.assertFalse(result.shadow_submission.queued)
            self.assertEqual(result.shadow_reason, "shadow_queue_closed")
            self.assertFalse(result.shadow_submission.authority_granted)

    def test_dual_required_is_strict_and_never_falls_back_to_one_route(self) -> None:
        """Dual research 只接受 A AND B，任一路失败均不创建 durable 状态。"""
        cases = (
            ("both-valid", True, True, True),
            ("a-invalid", True, False, False),
            ("b-invalid", False, True, False),
            ("both-invalid", False, False, False),
        )
        for label, b_valid, a_valid, expected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                coordinator = self._coordinator(root, mode="dual_required_research")
                request = self._request(
                    turn_id=f"dual-{label}",
                    route_b_valid=b_valid,
                    route_a_valid=a_valid,
                )
                evidence = coordinator.evaluate(request)
                result = coordinator.commit(evidence)

                self.assertIs(evidence.formula_accept, expected)
                self.assertIs(result.committed, expected)
                record = self._store(root).authorization_record(
                    request.route_b_request.envelope.hex_digest()
                )
                self.assertEqual(record is not None, expected)

    def test_offline_compare_records_all_four_quadrants_but_never_commits(self) -> None:
        """offline compare 可观察 A/B 四象限，但 commit 永远不产生 Context 或状态。"""
        quadrants: set[tuple[bool, bool]] = set()
        for b_valid in (False, True):
            for a_valid in (False, True):
                with tempfile.TemporaryDirectory() as tmpdir:
                    root = Path(tmpdir)
                    coordinator = self._coordinator(root, mode="offline_compare")
                    request = self._request(
                        turn_id=f"offline-{int(b_valid)}-{int(a_valid)}",
                        route_b_valid=b_valid,
                        route_a_valid=a_valid,
                    )
                    evidence = coordinator.evaluate(request)
                    result = coordinator.commit(evidence)

                    quadrants.add((evidence.route_b.accepted, evidence.route_a.accepted is True))
                    self.assertFalse(evidence.committable)
                    self.assertIs(
                        evidence.decision.can_accept,
                        evidence.formula_accept,
                    )
                    self.assertFalse(result.committed)
                    self.assertEqual(result.reason, "offline_compare_no_authority")
                    self.assertEqual(result.decision.reason, result.reason)
                    self.assertIsNone(
                        self._store(root).authorization_record(
                            request.route_b_request.envelope.hex_digest()
                        )
                    )
        self.assertEqual(
            quadrants,
            {(False, False), (False, True), (True, False), (True, True)},
        )

    def test_local_key_registries_and_route_errors_fail_closed(self) -> None:
        """未知 A/B key id 与 Route B 异常都不能由请求字段降级绕过。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dual = self._coordinator(root, mode="dual_required_research")
            unknown_b = dual.evaluate(
                self._request(
                    turn_id="unknown-b",
                    route_b_key_id=b"unknown-route-b-key",
                )
            )
            unknown_a = dual.evaluate(
                self._request(
                    turn_id="unknown-a",
                    route_a_key_id=b"unknown-route-a-key",
                )
            )
            fault = self._coordinator(
                root,
                mode="route_b_only",
                route_b=_FaultRouteB(),
            ).evaluate(self._request(turn_id="route-b-error"))

            self.assertEqual(unknown_b.route_b.reason, "route_b_key_untrusted")
            self.assertFalse(unknown_b.committable)
            self.assertEqual(unknown_a.route_a.status, "untrusted_key")
            self.assertFalse(unknown_a.committable)
            self.assertEqual(fault.route_b.reason, "route_b_evaluation_error")
            self.assertEqual(fault.route_b.error_type, "RuntimeError")
            self.assertNotIn("private backend diagnostic", str(fault.as_dict()))

    def test_runtime_parameter_mutation_after_evaluate_is_rejected(self) -> None:
        """evaluate 后嵌套参数漂移必须由 integration fingerprint 检出。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            parameters: dict[str, object] = {"priority": 1}
            request = self._request(
                turn_id="parameter-drift",
                parameters=parameters,
            )
            coordinator = self._coordinator(Path(tmpdir), mode="route_b_only")
            evidence = coordinator.evaluate(request)
            assert isinstance(request.route_b_request.parameters, dict)
            request.route_b_request.parameters["priority"] = 2

            result = coordinator.commit(evidence)

            self.assertFalse(result.committed)
            self.assertEqual(result.reason, "dual_route_evidence_changed")

    def test_noncanonical_parameter_mutation_fails_closed(self) -> None:
        """evaluate 后注入非有限参数时 commit 必须稳定拒绝而非向调用方抛错。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            request = self._request(
                turn_id="noncanonical-parameter-drift",
                parameters={"priority": 1},
            )
            coordinator = self._coordinator(Path(tmpdir), mode="route_b_only")
            evidence = coordinator.evaluate(request)
            assert isinstance(request.route_b_request.parameters, dict)
            request.route_b_request.parameters["priority"] = float("nan")

            result = coordinator.commit(evidence)

            self.assertFalse(result.committed)
            self.assertEqual(result.reason, "dual_route_request_not_canonical")
            self.assertIsNone(result.context)

    def test_concurrent_commit_still_returns_exactly_one_context(self) -> None:
        """integration 并发提交复用 R17 主键事务，最多发布一个 Context。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            request = self._request(turn_id="concurrent")
            first_coordinator = self._coordinator(root, mode="route_b_only")
            real_evidence = first_coordinator.evaluate(request).route_b.evidence
            assert real_evidence is not None
            coordinator = self._coordinator(
                root,
                mode="route_b_only",
                route_b=_CachedRouteB(real_evidence),
            )
            evidence = coordinator.evaluate(request)
            barrier = threading.Barrier(8)

            def commit_once(_index: int) -> object:
                """同步发起 integration durable commit，放大并发窗口。"""
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

    def test_mode_dependency_contracts_reject_ambiguous_wiring(self) -> None:
        """需要 A 的 mode 缺 verifier/queue/key registry 时必须在构造期拒绝。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._store(Path(tmpdir))
            common = {
                "durable_authorization_state_store": store,
                "route_b_evaluator": self.route_b,
                "route_b_public_keys": {self.route_b_key_id: self.route_b_public_key},
                "now_fn": lambda: self.now,
            }
            with self.assertRaisesRegex(ValueError, "shadow mode requires"):
                build_dual_route_runtime_coordinator(
                    mode="route_b_with_a_shadow",
                    **common,
                )
            with self.assertRaisesRegex(ValueError, "dual/offline mode requires"):
                build_dual_route_runtime_coordinator(
                    mode="dual_required_research",
                    route_a_public_keys={self.route_a_key_id: self.route_a_keys.public_key},
                    **common,
                )

    def test_shadow_submission_and_route_a_evidence_are_strictly_bound(self) -> None:
        """畸形 shadow digest 与 error+accept 组合必须拒绝且不能改变 B commit。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = self._coordinator(
                Path(tmpdir),
                mode="route_b_with_a_shadow",
                shadow_queue=_MismatchedShadowSubmitter(),
            )

            result = coordinator.commit(
                coordinator.evaluate(self._request(turn_id="shadow-mismatch"))
            )

            self.assertTrue(result.committed)
            self.assertIsNone(result.shadow_submission)
            self.assertEqual(
                result.shadow_reason,
                "route_a_shadow_submission_mismatch",
            )
        with self.assertRaisesRegex(ValueError, "cannot carry acceptance"):
            RouteAIntegrationEvidenceV1(
                "error",
                "route_a_evaluation_error",
                True,
                "0" * 64,
                "1" * 64,
                "RuntimeError",
            )


if __name__ == "__main__":
    unittest.main()
