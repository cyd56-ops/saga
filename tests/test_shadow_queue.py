"""Tests for the bounded Route A A0 asynchronous shadow queue."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import threading
from typing import cast
import unittest

from neural import (
    A0ShadowEvidence,
    A0ShadowJob,
    BoundedA0ShadowQueue,
    CompiledToyLWEVerifier,
    InMemoryA0ShadowOutbox,
)
from pq import ToyLWESignatureScheme


class _BlockingVerifier:
    """阻塞测试 verifier，用于稳定触发 queue full 和 timeout。"""

    def __init__(self) -> None:
        """初始化 worker 已进入和释放两个同步事件。"""
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """记录调用并阻塞到测试显式释放。"""
        del public_key, message, signature
        self.calls += 1
        self.started.set()
        self.release.wait()
        return 1


class _FaultVerifier:
    """按 message 返回异常、畸形结果或有效结果。"""

    def verify_bytes(self, public_key: bytes, message: bytes, signature: bytes) -> int:
        """覆盖 shadow exception 和 strict output-type 分支。"""
        del public_key, signature
        if message == b"error":
            raise RuntimeError("private shadow diagnostic")
        if message == b"bool":
            return cast(int, True)
        return 1


class _FailingOutbox:
    """模拟 outbox backend 故障，验证失败不影响 worker 终止。"""

    def append(self, evidence: A0ShadowEvidence) -> None:
        """拒绝每次写入且不保存 evidence。"""
        del evidence
        raise OSError("outbox unavailable")


def _job(job_id: str, *, message: bytes = b"message", reference: bool = True) -> A0ShadowJob:
    """构造只含公开材料的固定测试 job。"""
    return A0ShadowJob(
        job_id=job_id,
        public_key=b"P" * 8,
        message=message,
        signature=b"S" * 8,
        reference_accept=reference,
    )


def _evidence(job_id: str) -> A0ShadowEvidence:
    """构造 outbox 容量测试使用的最小合法 evidence。"""
    return A0ShadowEvidence(
        job_id=job_id,
        job_digest=hashlib.sha256(job_id.encode("ascii")).hexdigest(),
        status="completed",
        reason="shadow_accept",
        accept_output=1,
        reference_accept=True,
        agrees_with_reference=True,
        latency_seconds=0.0,
        authority_granted=False,
    )


class BoundedA0ShadowQueueTests(unittest.TestCase):
    """验证非阻塞提交、late evidence、资源上限和无 authority contract。"""

    def test_real_a0_verifier_runs_late_and_matches_reference(self) -> None:
        """真实 compiled toy verifier 应异步产生与 reference 一致的公开 evidence。"""
        scheme = ToyLWESignatureScheme(seed=811)
        key_pair = scheme.keygen()
        message = hashlib.sha256(b"route-a-a0-shadow").digest()
        signature = scheme.sign(key_pair.secret_key, message)
        verifier = CompiledToyLWEVerifier(scheme, message_bytes=len(message))
        outbox = InMemoryA0ShadowOutbox()
        queue = BoundedA0ShadowQueue(verifier, outbox, queue_capacity=2)
        self.addCleanup(queue.close)
        job = A0ShadowJob(
            job_id="valid-a0",
            public_key=key_pair.public_key,
            message=message,
            signature=signature,
            reference_accept=scheme.verify(key_pair.public_key, message, signature),
        )

        submission = queue.submit(job)

        self.assertTrue(submission.queued)
        self.assertFalse(submission.authority_granted)
        self.assertTrue(queue.await_idle(1.0))
        evidence = outbox.snapshot()
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].status, "completed")
        self.assertEqual(evidence[0].accept_output, 1)
        self.assertTrue(evidence[0].agrees_with_reference)
        self.assertFalse(evidence[0].authority_granted)
        self.assertNotIn(key_pair.public_key.hex(), str(evidence[0].as_dict()))
        self.assertNotIn(signature.hex(), str(evidence[0].as_dict()))

    def test_queue_full_drops_immediately_without_stopping_queued_jobs(self) -> None:
        """容量耗尽只丢 shadow job；已入队 job 仍形成 late evidence。"""
        verifier = _BlockingVerifier()
        outbox = InMemoryA0ShadowOutbox(capacity=8)
        queue = BoundedA0ShadowQueue(
            verifier,
            outbox,
            queue_capacity=1,
            job_timeout_seconds=1.0,
        )
        self.addCleanup(verifier.release.set)
        self.addCleanup(queue.close)

        first = queue.submit(_job("first"))
        self.assertTrue(first.queued)
        self.assertTrue(verifier.started.wait(1.0))
        second = queue.submit(_job("second"))
        dropped = queue.submit(_job("third"))

        self.assertTrue(second.queued)
        self.assertFalse(dropped.queued)
        self.assertEqual(dropped.reason, "shadow_queue_full")
        verifier.release.set()
        self.assertTrue(queue.await_idle(1.0))
        stats = queue.stats()
        self.assertEqual(stats.queued_count, 2)
        self.assertEqual(stats.completed_count, 2)
        self.assertEqual(stats.queue_full_drop_count, 1)
        self.assertEqual(stats.pending_count, 0)
        self.assertEqual(
            [item.status for item in outbox.snapshot()].count("dropped"),
            1,
        )

    def test_timeout_quarantines_call_slot_and_later_job_fails_late(self) -> None:
        """超时调用未返回时不启动无限重试线程，后续 job 只报 unavailable。"""
        verifier = _BlockingVerifier()
        outbox = InMemoryA0ShadowOutbox(capacity=8)
        queue = BoundedA0ShadowQueue(
            verifier,
            outbox,
            queue_capacity=2,
            job_timeout_seconds=0.01,
            max_inflight_verifications=1,
        )
        self.addCleanup(verifier.release.set)
        self.addCleanup(queue.close)
        queue.submit(_job("timeout-first"))
        queue.submit(_job("timeout-second"))

        self.assertTrue(queue.await_idle(1.0))
        by_id = {item.job_id: item for item in outbox.snapshot()}
        self.assertEqual(by_id["timeout-first"].status, "timeout")
        self.assertEqual(
            by_id["timeout-first"].reason,
            "shadow_verification_timeout",
        )
        self.assertEqual(by_id["timeout-second"].status, "error")
        self.assertEqual(
            by_id["timeout-second"].reason,
            "shadow_verifier_unavailable",
        )
        self.assertEqual(verifier.calls, 1)
        verifier.release.set()

    def test_exception_and_non_integer_output_become_stable_error_evidence(self) -> None:
        """异常消息不进入 evidence，bool 等非原生整数输出也必须拒绝。"""
        outbox = InMemoryA0ShadowOutbox(capacity=8)
        queue = BoundedA0ShadowQueue(_FaultVerifier(), outbox, queue_capacity=2)
        self.addCleanup(queue.close)
        queue.submit(_job("error", message=b"error"))
        queue.submit(_job("bool", message=b"bool"))

        self.assertTrue(queue.await_idle(1.0))
        by_id = {item.job_id: item for item in outbox.snapshot()}
        self.assertEqual(by_id["error"].reason, "shadow_verification_error")
        self.assertEqual(by_id["error"].error_type, "RuntimeError")
        self.assertNotIn("private", repr(by_id["error"]))
        self.assertEqual(by_id["bool"].reason, "shadow_output_invalid")
        self.assertEqual(by_id["bool"].error_type, "bool")

    def test_outbox_failure_only_updates_shadow_metric(self) -> None:
        """Outbox backend 故障不能传播到提交方或阻止 queue 进入 idle。"""
        queue = BoundedA0ShadowQueue(
            _FaultVerifier(),
            _FailingOutbox(),
            queue_capacity=1,
        )
        self.addCleanup(queue.close)
        submission = queue.submit(_job("outbox-failure"))

        self.assertTrue(submission.queued)
        self.assertTrue(queue.await_idle(1.0))
        stats = queue.stats()
        self.assertEqual(stats.completed_count, 1)
        self.assertEqual(stats.outbox_failure_count, 1)

    def test_outbox_is_bounded_and_shadow_objects_cannot_gain_authority(self) -> None:
        """Outbox 覆盖最旧记录，并拒绝将 submission/evidence 改成 authority。"""
        outbox = InMemoryA0ShadowOutbox(capacity=2)
        outbox.append(_evidence("one"))
        outbox.append(_evidence("two"))
        outbox.append(_evidence("three"))

        self.assertEqual(
            tuple(item.job_id for item in outbox.snapshot()),
            ("two", "three"),
        )
        self.assertEqual(outbox.stats()["dropped_record_count"], 1)
        with self.assertRaises(ValueError):
            replace(_evidence("bad"), authority_granted=cast(object, True))

        queue = BoundedA0ShadowQueue(_FaultVerifier(), outbox, queue_capacity=1)
        self.assertTrue(queue.close())
        self.assertTrue(queue.close())
        dropped = queue.submit(_job("closed"))
        self.assertFalse(dropped.queued)
        self.assertEqual(dropped.reason, "shadow_queue_closed")
        with self.assertRaises(ValueError):
            replace(dropped, authority_granted=cast(object, True))

    def test_drop_evidence_survives_outbox_failure_without_deadlock(self) -> None:
        """关闭后的同步 drop 即使 outbox 故障也必须立即返回。"""
        queue = BoundedA0ShadowQueue(
            _FaultVerifier(),
            _FailingOutbox(),
            queue_capacity=1,
        )
        self.assertTrue(queue.close())

        dropped = queue.submit(_job("closed-outbox-failure"))

        self.assertFalse(dropped.queued)
        self.assertEqual(queue.stats().outbox_failure_count, 1)

    def test_job_contract_rejects_mutable_or_oversized_material(self) -> None:
        """Job 只允许不可变公开 bytes、稳定 ID 和原生 reference bool。"""
        with self.assertRaises(TypeError):
            replace(_job("mutable"), public_key=cast(bytes, bytearray(b"P")))
        with self.assertRaises(TypeError):
            replace(_job("truthy"), reference_accept=cast(bool, 1))
        with self.assertRaises(ValueError):
            replace(_job("oversized"), message=b"M" * ((1 << 20) + 1))
        self.assertNotEqual(_job("one").digest(), _job("two").digest())


if __name__ == "__main__":
    unittest.main()
