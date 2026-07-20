"""路线 A A0 的有界异步 shadow queue 与非授权 evidence outbox。"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import math
from queue import Empty, Full, Queue
import threading
import time
from typing import Literal, Protocol


MAX_A0_SHADOW_MATERIAL_BYTES = 1 << 20

A0ShadowStatus = Literal[
    "completed",
    "error",
    "timeout",
    "dropped",
]


class A0ShadowVerifier(Protocol):
    """定义 A0 shadow worker 所需的公开材料验签接口。"""

    def verify_bytes(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> int:
        """只使用公开材料返回硬 0/1 结果。"""
        ...


@dataclass(frozen=True)
class A0ShadowJob:
    """保存一个不可变 A0 shadow job，不包含签名私钥。"""

    job_id: str
    public_key: bytes
    message: bytes
    signature: bytes
    reference_accept: bool | None = None

    def __post_init__(self) -> None:
        """拒绝空 ID、可变字节、超长材料和非原生 reference 布尔值。"""
        if type(self.job_id) is not str or not self.job_id:
            raise ValueError("job_id must be non-empty text")
        for field_name, value in (
            ("public_key", self.public_key),
            ("message", self.message),
            ("signature", self.signature),
        ):
            if type(value) is not bytes:
                raise TypeError(f"{field_name} must be bytes")
            if len(value) > MAX_A0_SHADOW_MATERIAL_BYTES:
                raise ValueError(f"{field_name} exceeds the shadow material limit")
        if not self.public_key or not self.signature:
            raise ValueError("public_key and signature must be non-empty")
        if self.reference_accept is not None and type(self.reference_accept) is not bool:
            raise TypeError("reference_accept must be a built-in bool or None")

    def digest(self) -> str:
        """对 job ID 和公开材料做长度前缀摘要，供 outbox 关联。"""
        hasher = hashlib.sha256(b"SAGA-PQ-CAN-A0ShadowJobV1\x00")
        for value in (
            self.job_id.encode("utf-8"),
            self.public_key,
            self.message,
            self.signature,
        ):
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
        if self.reference_accept is None:
            hasher.update(b"\xff")
        else:
            hasher.update(b"\x01" if self.reference_accept else b"\x00")
        return hasher.hexdigest()


@dataclass(frozen=True)
class A0ShadowSubmission:
    """记录非阻塞提交结果；该结果永远不能参与执行放行。"""

    queued: bool
    reason: str
    job_digest: str
    authority_granted: Literal[False] = False

    def __post_init__(self) -> None:
        """禁止 submission 被重标记为可执行 authority。"""
        if self.authority_granted is not False:
            raise ValueError("A0 shadow submission cannot grant authority")


@dataclass(frozen=True)
class A0ShadowEvidence:
    """记录 late shadow 结果，不保存 pk/message/signature 原文。"""

    job_id: str
    job_digest: str
    status: A0ShadowStatus
    reason: str
    accept_output: int | None
    reference_accept: bool | None
    agrees_with_reference: bool | None
    latency_seconds: float
    error_type: str | None = None
    authority_granted: Literal[False] = False

    def __post_init__(self) -> None:
        """确保输出、状态、延迟和 authority 使用严格稳定类型。"""
        if self.status not in {"completed", "error", "timeout", "dropped"}:
            raise ValueError("unsupported A0 shadow evidence status")
        if self.accept_output is not None and (
            type(self.accept_output) is not int or self.accept_output not in (0, 1)
        ):
            raise ValueError("accept_output must be a built-in 0/1 integer or None")
        if self.reference_accept is not None and type(self.reference_accept) is not bool:
            raise TypeError("reference_accept must be a built-in bool or None")
        if self.agrees_with_reference is not None and type(
            self.agrees_with_reference
        ) is not bool:
            raise TypeError("agrees_with_reference must be a built-in bool or None")
        if (
            type(self.latency_seconds) not in (int, float)
            or not math.isfinite(float(self.latency_seconds))
            or self.latency_seconds < 0
        ):
            raise ValueError("latency_seconds must be finite and non-negative")
        if self.authority_granted is not False:
            raise ValueError("A0 shadow evidence cannot grant authority")

    def as_dict(self) -> dict[str, object]:
        """导出不含公开材料原文的机器可读 late evidence。"""
        return {
            "job_id": self.job_id,
            "job_digest": self.job_digest,
            "status": self.status,
            "reason": self.reason,
            "accept_output": self.accept_output,
            "reference_accept": self.reference_accept,
            "agrees_with_reference": self.agrees_with_reference,
            "latency_seconds": self.latency_seconds,
            "error_type": self.error_type,
            "authority_granted": self.authority_granted,
        }


class A0ShadowEvidenceOutbox(Protocol):
    """定义 shadow worker 追加 late evidence 的最小接口。"""

    def append(self, evidence: A0ShadowEvidence) -> None:
        """追加一个不授予 authority 的 evidence record。"""
        ...


class InMemoryA0ShadowOutbox:
    """提供线程安全、有界且覆盖最旧记录的研究用内存 outbox。"""

    def __init__(self, capacity: int = 1024) -> None:
        """固定正整数容量并初始化丢弃计数。"""
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("outbox capacity must be a positive built-in integer")
        self.capacity = capacity
        self._records: deque[A0ShadowEvidence] = deque()
        self._dropped_records = 0
        self._lock = threading.RLock()

    def append(self, evidence: A0ShadowEvidence) -> None:
        """追加 evidence；容量满时覆盖最旧记录但不阻塞 shadow worker。"""
        if type(evidence) is not A0ShadowEvidence:
            raise TypeError("evidence must be A0ShadowEvidence")
        with self._lock:
            if len(self._records) >= self.capacity:
                self._records.popleft()
                self._dropped_records += 1
            self._records.append(evidence)

    def snapshot(self) -> tuple[A0ShadowEvidence, ...]:
        """返回当前有序 evidence 快照，不暴露内部可变 deque。"""
        with self._lock:
            return tuple(self._records)

    def stats(self) -> dict[str, int]:
        """返回当前记录数、容量和 outbox 覆盖计数。"""
        with self._lock:
            return {
                "capacity": self.capacity,
                "record_count": len(self._records),
                "dropped_record_count": self._dropped_records,
            }


@dataclass(frozen=True)
class A0ShadowQueueStats:
    """汇总非阻塞队列提交、处理、丢弃和 outbox 故障计数。"""

    queued_count: int
    completed_count: int
    queue_full_drop_count: int
    closed_drop_count: int
    outbox_failure_count: int
    pending_count: int

    def as_dict(self) -> dict[str, int]:
        """导出稳定计数字段，供实验 runner 记录 backlog/drop。"""
        return {
            "queued_count": self.queued_count,
            "completed_count": self.completed_count,
            "queue_full_drop_count": self.queue_full_drop_count,
            "closed_drop_count": self.closed_drop_count,
            "outbox_failure_count": self.outbox_failure_count,
            "pending_count": self.pending_count,
        }


_STOP = object()


class BoundedA0ShadowQueue:
    """异步运行 A0 verifier；资源耗尽只产生 late evidence，不阻塞主路径。"""

    def __init__(
        self,
        verifier: A0ShadowVerifier,
        outbox: A0ShadowEvidenceOutbox,
        *,
        queue_capacity: int = 128,
        job_timeout_seconds: float = 1.0,
        max_inflight_verifications: int = 1,
    ) -> None:
        """固定队列、超时和在途调用上限，并启动单一 daemon worker。"""
        if not callable(getattr(verifier, "verify_bytes", None)):
            raise TypeError("verifier must expose verify_bytes")
        if not callable(getattr(outbox, "append", None)):
            raise TypeError("outbox must expose append")
        if type(queue_capacity) is not int or queue_capacity <= 0:
            raise ValueError("queue_capacity must be a positive built-in integer")
        if (
            type(job_timeout_seconds) not in (int, float)
            or not math.isfinite(float(job_timeout_seconds))
            or job_timeout_seconds <= 0
        ):
            raise ValueError("job_timeout_seconds must be finite and positive")
        if (
            type(max_inflight_verifications) is not int
            or max_inflight_verifications <= 0
        ):
            raise ValueError(
                "max_inflight_verifications must be a positive built-in integer"
            )
        self.verifier = verifier
        self.outbox = outbox
        self.queue_capacity = queue_capacity
        self.job_timeout_seconds = float(job_timeout_seconds)
        self._jobs: Queue[A0ShadowJob | object] = Queue(maxsize=queue_capacity)
        self._call_slots = threading.BoundedSemaphore(max_inflight_verifications)
        # drop 路径持锁隔离 outbox 故障，因此这里必须允许同线程重入。
        self._lock = threading.RLock()
        self._idle_condition = threading.Condition(self._lock)
        self._closed = False
        self._queued_count = 0
        self._completed_count = 0
        self._queue_full_drop_count = 0
        self._closed_drop_count = 0
        self._outbox_failure_count = 0
        self._worker = threading.Thread(
            target=self._run_worker,
            name="saga-route-a-a0-shadow",
            daemon=True,
        )
        self._worker.start()

    def submit(self, job: A0ShadowJob) -> A0ShadowSubmission:
        """非阻塞提交；关闭或队列满时立即返回并记录 dropped evidence。"""
        if type(job) is not A0ShadowJob:
            raise TypeError("job must be A0ShadowJob")
        with self._lock:
            if self._closed:
                self._closed_drop_count += 1
                evidence = self._dropped_evidence(job, "shadow_queue_closed")
                self._append_evidence(evidence)
                return A0ShadowSubmission(False, evidence.reason, job.digest())
            try:
                self._jobs.put_nowait(job)
            except Full:
                self._queue_full_drop_count += 1
                evidence = self._dropped_evidence(job, "shadow_queue_full")
                self._append_evidence(evidence)
                return A0ShadowSubmission(False, evidence.reason, job.digest())
            self._queued_count += 1
            return A0ShadowSubmission(True, "shadow_job_queued", job.digest())

    def await_idle(self, timeout_seconds: float) -> bool:
        """有界等待所有已入队 job 形成 terminal late evidence。"""
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds < 0
        ):
            raise ValueError("timeout_seconds must be finite and non-negative")
        deadline = time.monotonic() + float(timeout_seconds)
        with self._idle_condition:
            while self._completed_count < self._queued_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._idle_condition.wait(timeout=remaining)
            return True

    def stats(self) -> A0ShadowQueueStats:
        """返回 backlog/drop/outbox failure 的一致计数快照。"""
        with self._lock:
            return A0ShadowQueueStats(
                queued_count=self._queued_count,
                completed_count=self._completed_count,
                queue_full_drop_count=self._queue_full_drop_count,
                closed_drop_count=self._closed_drop_count,
                outbox_failure_count=self._outbox_failure_count,
                pending_count=self._queued_count - self._completed_count,
            )

    def close(self, timeout_seconds: float = 2.0) -> bool:
        """停止接收新 job，有界等待 backlog 后终止 worker。"""
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds < 0
        ):
            raise ValueError("timeout_seconds must be finite and non-negative")
        deadline = time.monotonic() + float(timeout_seconds)
        with self._lock:
            self._closed = True
            if not self._worker.is_alive():
                return self._completed_count == self._queued_count
        idle = self.await_idle(max(0.0, deadline - time.monotonic()))
        try:
            self._jobs.put(_STOP, timeout=max(0.0, deadline - time.monotonic()))
        except Full:
            return False
        self._worker.join(timeout=max(0.0, deadline - time.monotonic()))
        return idle and not self._worker.is_alive()

    def __enter__(self) -> BoundedA0ShadowQueue:
        """返回 queue，支持测试和 runner 的有界上下文管理。"""
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        """退出上下文时尝试有界关闭，不向主执行路径传播 shadow 状态。"""
        self.close()

    def _run_worker(self) -> None:
        """顺序消费 bounded queue，并把每个 job 转换成 late evidence。"""
        while True:
            item = self._jobs.get()
            try:
                if item is _STOP:
                    return
                if type(item) is not A0ShadowJob:
                    continue
                evidence = self._evaluate_job(item)
                self._append_evidence(evidence)
                with self._idle_condition:
                    self._completed_count += 1
                    self._idle_condition.notify_all()
            finally:
                self._jobs.task_done()

    def _evaluate_job(self, job: A0ShadowJob) -> A0ShadowEvidence:
        """在有界 daemon call 中执行；超时调用占用 slot 直到自行返回。"""
        started_at = time.perf_counter()
        if not self._call_slots.acquire(blocking=False):
            return self._error_evidence(
                job,
                "shadow_verifier_unavailable",
                started_at,
            )
        outcomes: Queue[tuple[object | None, str | None]] = Queue(maxsize=1)

        def invoke() -> None:
            try:
                result = self.verifier.verify_bytes(
                    job.public_key,
                    job.message,
                    job.signature,
                )
                outcome = (result, None)
            except BaseException as exc:
                outcome = (None, type(exc).__name__)
            finally:
                self._call_slots.release()
            outcomes.put(outcome)

        call = threading.Thread(
            target=invoke,
            name="saga-route-a-a0-shadow-call",
            daemon=True,
        )
        try:
            call.start()
        except Exception as exc:
            self._call_slots.release()
            return self._error_evidence(
                job,
                "shadow_worker_start_failed",
                started_at,
                error_type=type(exc).__name__,
            )
        try:
            result, error_type = outcomes.get(timeout=self.job_timeout_seconds)
        except Empty:
            return A0ShadowEvidence(
                job_id=job.job_id,
                job_digest=job.digest(),
                status="timeout",
                reason="shadow_verification_timeout",
                accept_output=None,
                reference_accept=job.reference_accept,
                agrees_with_reference=None,
                latency_seconds=time.perf_counter() - started_at,
                authority_granted=False,
            )
        if error_type is not None:
            return self._error_evidence(
                job,
                "shadow_verification_error",
                started_at,
                error_type=error_type,
            )
        if type(result) is not int or result not in (0, 1):
            return self._error_evidence(
                job,
                "shadow_output_invalid",
                started_at,
                error_type=type(result).__name__,
            )
        reference_accept = job.reference_accept
        agrees = (
            None
            if reference_accept is None
            else bool(result) is reference_accept
        )
        reason = (
            "shadow_reference_disagreement"
            if agrees is False
            else ("shadow_accept" if result == 1 else "shadow_reject")
        )
        return A0ShadowEvidence(
            job_id=job.job_id,
            job_digest=job.digest(),
            status="completed",
            reason=reason,
            accept_output=result,
            reference_accept=reference_accept,
            agrees_with_reference=agrees,
            latency_seconds=time.perf_counter() - started_at,
            authority_granted=False,
        )

    def _error_evidence(
        self,
        job: A0ShadowJob,
        reason: str,
        started_at: float,
        *,
        error_type: str | None = None,
    ) -> A0ShadowEvidence:
        """构造不复制异常消息或公开材料的 error evidence。"""
        return A0ShadowEvidence(
            job_id=job.job_id,
            job_digest=job.digest(),
            status="error",
            reason=reason,
            accept_output=None,
            reference_accept=job.reference_accept,
            agrees_with_reference=None,
            latency_seconds=time.perf_counter() - started_at,
            error_type=error_type,
            authority_granted=False,
        )

    @staticmethod
    def _dropped_evidence(job: A0ShadowJob, reason: str) -> A0ShadowEvidence:
        """构造 queue full/closed 的即时 dropped evidence。"""
        return A0ShadowEvidence(
            job_id=job.job_id,
            job_digest=job.digest(),
            status="dropped",
            reason=reason,
            accept_output=None,
            reference_accept=job.reference_accept,
            agrees_with_reference=None,
            latency_seconds=0.0,
            authority_granted=False,
        )

    def _append_evidence(self, evidence: A0ShadowEvidence) -> None:
        """隔离 outbox 异常；写入失败只增加 shadow 指标。"""
        try:
            self.outbox.append(evidence)
        except Exception:
            with self._lock:
                self._outbox_failure_count += 1
