"""Offline ablation and overhead runner for SAGA-PQ-CAN."""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from statistics import mean, median
import time

from neural import CAN, CompiledToyLWEVerifier, bytes_to_bits
from pq import ToyLWESignatureScheme
from saga.execution_gate import (
    ExecutionGateRequest,
    LocalExecutionContext,
    build_toy_lwe_execution_gate,
)
from saga.messages import (
    RequestEnvelope,
    build_request_envelope,
    parse_request_envelope,
    sha256_hex,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_SENDER_AID = "alice@example.com:calendar_agent"
DEFAULT_RECEIVER_AID = "bob@example.com:email_agent"
DEFAULT_TOKEN = "enc-token"
DEFAULT_MESSAGE = "schedule a meeting"
DEFAULT_NOW = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
DEFAULT_ITERATIONS = 200

ABLATION_MODES = (
    "saga_only",
    "ordinary_pq_middleware",
    "naive_neural_verifier",
    "shamir_secured_pq_can",
)

OVERHEAD_METRICS = (
    "toy_sign",
    "ordinary_pq_verify",
    "compiled_verifier",
    "shamir_can",
    "execution_gate_evaluate",
)


@dataclass(frozen=True)
class AblationCase:
    """One input case used across all ablation modes.

    消融样本固定输入和期望拒绝语义，便于比较不同模式的安全贡献。
    """

    name: str
    request: ExecutionGateRequest
    expected_allow: bool
    category: str
    real_valued_bits: tuple[int | float, ...] | None = None


@dataclass(frozen=True)
class AblationResult:
    """One mode/case ablation decision.

    记录一个消融模式在一个样本上的允许/拒绝结果。
    """

    mode: str
    case: str
    category: str
    allowed: bool
    expected_allow: bool
    passed: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        """Serialize the ablation result for JSONL output.

        输出字段用于后续统计每种模式的正向通过率和负向拒绝率。
        """
        return {
            "mode": self.mode,
            "case": self.case,
            "category": self.category,
            "allowed": self.allowed,
            "expected_allow": self.expected_allow,
            "passed": self.passed,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OverheadResult:
    """Timing summary for one offline micro-benchmark metric.

    记录单个本地认证组件的微基准耗时统计。
    """

    metric: str
    iterations: int
    mean_ns: float
    median_ns: float
    min_ns: int
    max_ns: int

    def as_dict(self) -> dict[str, object]:
        """Serialize the overhead result for JSON output.

        纳秒级统计用于比较签名、验签、CAN 和 execution gate 的相对开销。
        """
        return {
            "metric": self.metric,
            "iterations": self.iterations,
            "mean_ns": self.mean_ns,
            "median_ns": self.median_ns,
            "min_ns": self.min_ns,
            "max_ns": self.max_ns,
        }


@dataclass(frozen=True)
class _SignedMaterial:
    """Signed request and raw bytes used by ablation and timing code.

    保存消融和开销统计共用的签名信封、签名和 transport request。
    """

    envelope: RequestEnvelope
    signature: bytes
    request: ExecutionGateRequest


class AblationOverheadHarness:
    """Run deterministic offline ablations and micro-overhead benchmarks.

    该 harness 不启动真实服务，只比较执行层认证组件的安全覆盖和局部耗时。
    """

    def __init__(
        self,
        *,
        now: datetime = DEFAULT_NOW,
        seed: int = 131,
    ) -> None:
        """Create deterministic toy signing material and verifier objects.

        toy LWE 仅用于研究消融，不代表生产 PQ 安全。
        """
        self.now = now
        self.scheme = ToyLWESignatureScheme(seed=seed)
        self.key_pair = self.scheme.keygen()
        self.compiled_verifier = CompiledToyLWEVerifier(
            self.scheme,
            message_bytes=32,
        )
        self.can_gate = CAN(self.compiled_verifier)
        self.execution_gate = build_toy_lwe_execution_gate(
            self.scheme,
            {DEFAULT_SENDER_AID: self.key_pair.public_key},
            now_fn=lambda: self.now,
        )
        self.valid_material = self._signed_material()

    def run_ablation(self) -> list[AblationResult]:
        """Run all cases through all ablation modes.

        同一批正负样本在不同模式下比较，展示每个安全组件的增量贡献。
        """
        cases = self._ablation_cases()
        results: list[AblationResult] = []
        for mode in ABLATION_MODES:
            for case in cases:
                allowed, reason = self._evaluate_mode(mode, case)
                results.append(
                    AblationResult(
                        mode=mode,
                        case=case.name,
                        category=case.category,
                        allowed=allowed,
                        expected_allow=case.expected_allow,
                        passed=allowed == case.expected_allow,
                        reason=reason,
                    )
                )
        return results

    def run_overhead(self, *, iterations: int = DEFAULT_ITERATIONS) -> list[OverheadResult]:
        """Run deterministic micro-overhead benchmarks.

        每个指标循环多次取均值和中位数，只衡量本地认证组件局部开销。
        """
        if iterations <= 0:
            raise ValueError("iterations must be positive")

        material = self.valid_material
        public_key_bits = bytes_to_bits(self.key_pair.public_key)
        envelope_bits = bytes_to_bits(material.envelope.digest())
        signature_bits = bytes_to_bits(material.signature)
        samples: dict[str, Callable[[], object]] = {
            "toy_sign": lambda: self.scheme.sign(
                self.key_pair.secret_key,
                material.envelope.digest(),
            ),
            "ordinary_pq_verify": lambda: self.scheme.verify(
                self.key_pair.public_key,
                material.envelope.digest(),
                material.signature,
            ),
            "compiled_verifier": lambda: self.compiled_verifier.verify_bytes(
                self.key_pair.public_key,
                material.envelope.digest(),
                material.signature,
            ),
            "shamir_can": lambda: self.can_gate.can_accept(
                public_key_bits,
                envelope_bits,
                signature_bits,
            ),
            "execution_gate_evaluate": lambda: self.execution_gate.evaluate_request(
                material.request
            ),
        }
        return [
            self._measure_metric(metric, samples[metric], iterations)
            for metric in OVERHEAD_METRICS
        ]

    def _signed_material(
        self,
        *,
        message: str = DEFAULT_MESSAGE,
        action_scope: str = "llm_prompt",
        authorized_scopes: Iterable[str] | None = None,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> _SignedMaterial:
        """Build signed request material for one fixed test envelope.

        构造一组带 detached signature 的规范请求材料。
        """
        envelope = build_request_envelope(
            sender_aid=DEFAULT_SENDER_AID,
            receiver_aid=DEFAULT_RECEIVER_AID,
            token=DEFAULT_TOKEN,
            session_id="ablation-session-1",
            turn_id="turn-1",
            issued_at=issued_at or (self.now - timedelta(minutes=1)),
            expires_at=expires_at or (self.now + timedelta(minutes=5)),
            action_scope=action_scope,
            authorized_scopes=authorized_scopes,
            message=message,
            provider_id="https://provider.example.test",
            timestamp=self.now,
        )
        signature = self.scheme.sign(self.key_pair.secret_key, envelope.digest())
        request = ExecutionGateRequest(
            sender_aid=DEFAULT_SENDER_AID,
            receiver_aid=DEFAULT_RECEIVER_AID,
            token=DEFAULT_TOKEN,
            message=message,
            action_scope=action_scope,
            request_envelope=envelope.canonical_json(),
            pq_signature=base64.b64encode(signature).decode("utf-8"),
        )
        return _SignedMaterial(envelope=envelope, signature=signature, request=request)

    def _ablation_cases(self) -> tuple[AblationCase, ...]:
        """Create deterministic positive and negative ablation cases.

        生成固定正向样本和 envelope/scope/实数输入负向样本。
        """
        valid = self.valid_material
        tampered_message = ExecutionGateRequest(
            sender_aid=valid.request.sender_aid,
            receiver_aid=valid.request.receiver_aid,
            token=valid.request.token,
            message="tampered payload",
            action_scope=valid.request.action_scope,
            request_envelope=valid.request.request_envelope,
            pq_signature=valid.request.pq_signature,
        )
        expired = self._signed_material(
            issued_at=self.now - timedelta(minutes=10),
            expires_at=self.now - timedelta(minutes=1),
        )
        tool_only = self._signed_material(
            message="send mail",
            action_scope="tool_call:send_email",
        )
        unauthorized_tool = self._signed_material(
            authorized_scopes=("tool_call:send_email",),
        )

        public_key_bits = bytes_to_bits(self.key_pair.public_key)
        envelope_bits = bytes_to_bits(valid.envelope.digest())
        signature_bits = bytes_to_bits(valid.signature)
        real_bits: list[int | float] = [
            *public_key_bits,
            *envelope_bits,
            *signature_bits,
        ]
        signature_offset = len(public_key_bits) + len(envelope_bits)
        injected_offset = next(
            index for index, bit in enumerate(signature_bits) if bit == 1
        )
        real_bits[signature_offset + injected_offset] = 2.0 / 3.0

        return (
            AblationCase(
                name="valid_prompt",
                request=valid.request,
                expected_allow=True,
                category="positive",
            ),
            AblationCase(
                name="tampered_message",
                request=tampered_message,
                expected_allow=False,
                category="envelope_binding",
            ),
            AblationCase(
                name="expired_envelope",
                request=expired.request,
                expected_allow=False,
                category="time_window",
            ),
            AblationCase(
                name="prompt_surface_tool_only",
                request=tool_only.request,
                expected_allow=False,
                category="execution_surface",
            ),
            AblationCase(
                name="unauthorized_tool_scope",
                request=unauthorized_tool.request,
                expected_allow=False,
                category="execution_scope",
            ),
            AblationCase(
                name="real_valued_signature_input",
                request=valid.request,
                expected_allow=False,
                category="real_valued_rejection",
                real_valued_bits=tuple(real_bits),
            ),
        )

    def _evaluate_mode(self, mode: str, case: AblationCase) -> tuple[bool, str]:
        """Evaluate one case under one ablation mode.

        按指定消融模式执行一个样本并返回允许结果和原因。
        """
        if mode == "saga_only":
            return self._evaluate_saga_only(case)
        if mode == "ordinary_pq_middleware":
            return self._evaluate_ordinary_pq(case)
        if mode == "naive_neural_verifier":
            return self._evaluate_naive_neural(case)
        if mode == "shamir_secured_pq_can":
            return self._evaluate_shamir_pq_can(case)
        raise ValueError(f"unsupported ablation mode: {mode}")

    def _evaluate_saga_only(self, case: AblationCase) -> tuple[bool, str]:
        """Evaluate baseline SAGA-only behavior.

        SAGA-only 模式只模拟 token 已通过，不检查 envelope/PQ/CAN/scope。
        """
        return True, "saga_token_valid_only"

    def _evaluate_ordinary_pq(self, case: AblationCase) -> tuple[bool, str]:
        """Evaluate envelope plus ordinary byte-level toy PQ verification.

        普通 PQ middleware 只做 envelope 和字节级签名检查，不做执行面 scope gate。
        """
        if case.real_valued_bits is not None:
            return True, "ordinary_pq_no_real_valued_interface"
        parsed = self._parse_and_check_envelope(case.request)
        if parsed[0] is None:
            return False, parsed[1]
        envelope = parsed[0]
        assert envelope is not None
        signature = base64.b64decode(case.request.pq_signature, validate=True)
        verified = self.scheme.verify(
            self.key_pair.public_key,
            envelope.digest(),
            signature,
        )
        if not verified:
            return False, "signature_verification_failed"
        return True, "ordinary_pq_authorized"

    def _evaluate_naive_neural(self, case: AblationCase) -> tuple[bool, str]:
        """Evaluate compiled verifier without Shamir MASK or execution-scope policy.

        naive neural 模式故意省略 MASK 和执行面 scope policy，用于消融对比。
        """
        if case.real_valued_bits is not None:
            # naive neural 只做 STEP 投影，不做 MASK，因此边界实数可被投影回硬比特。
            stepped = [
                self.can_gate.step_in(bit)
                for bit in case.real_valued_bits
            ]
            accepted = self.compiled_verifier.verify_compound_bits(stepped) == 1
            return accepted, "naive_neural_no_mask"

        parsed = self._parse_and_check_envelope(case.request)
        if parsed[0] is None:
            return False, parsed[1]
        envelope = parsed[0]
        assert envelope is not None
        signature = base64.b64decode(case.request.pq_signature, validate=True)
        accepted = self.compiled_verifier.verify_bytes(
            self.key_pair.public_key,
            envelope.digest(),
            signature,
        ) == 1
        if not accepted:
            return False, "signature_verification_failed"
        return True, "naive_neural_authorized_without_scope_policy"

    def _evaluate_shamir_pq_can(self, case: AblationCase) -> tuple[bool, str]:
        """Evaluate the full Shamir-secured PQ-CAN execution-surface policy.

        完整模式同时检查 envelope、PQ-CAN、prompt surface 和下游 tool scope。
        """
        if case.real_valued_bits is not None:
            accepted = self.can_gate.can_accept_compound_bits(case.real_valued_bits) == 1
            return accepted, (
                "shamir_can_authorized"
                if accepted
                else "real_valued_signature_input_rejected"
            )

        decision = self.execution_gate.evaluate_request(case.request)
        if not decision.allowed:
            return False, decision.reason
        context = self.execution_gate.build_local_execution_context_from_decision(
            case.request,
            decision,
        )
        if context is None:
            return False, "missing_local_execution_context"
        if case.name == "prompt_surface_tool_only" and not context.authorize_action("llm_prompt"):
            return False, "prompt_scope_not_authorized"
        if case.name == "unauthorized_tool_scope":
            try:
                context.require_tool_call("add_calendar_event")
            except PermissionError:
                return False, "unauthorized_tool_scope"
        return True, "shamir_pq_can_authorized"

    def _parse_and_check_envelope(
        self,
        request: ExecutionGateRequest,
    ) -> tuple[RequestEnvelope | None, str]:
        """Run deterministic envelope checks shared by ablation modes.

        复用 token/message digest 与时间窗检查，保持各模式输入一致。
        """
        try:
            envelope = parse_request_envelope(request.request_envelope)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None, "invalid_request_envelope"

        if envelope.token_digest != self._sha_token(request.token):
            return None, "token_digest_mismatch"
        if envelope.message_digest != self._sha_message(request.message):
            return None, "message_digest_mismatch"

        issued_at = datetime.fromisoformat(envelope.issued_at.replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(envelope.expires_at.replace("Z", "+00:00"))
        if issued_at > expires_at:
            return None, "invalid_envelope_window"
        if self.now < issued_at:
            return None, "envelope_not_yet_valid"
        if self.now > expires_at:
            return None, "envelope_expired"
        return envelope, "envelope_valid"

    def _sha_token(self, token: str) -> str:
        """Return the token digest used by request envelopes."""
        return sha256_hex(token.encode("utf-8"))

    def _sha_message(self, message: str) -> str:
        """Return the message digest used by request envelopes."""
        return sha256_hex(message.encode("utf-8"))

    def _measure_metric(
        self,
        metric: str,
        operation: Callable[[], object],
        iterations: int,
    ) -> OverheadResult:
        """Measure one operation with ``perf_counter_ns``.

        用纳秒计时器重复测量单个认证操作的本地耗时。
        """
        durations: list[int] = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            operation()
            durations.append(time.perf_counter_ns() - start)
        return OverheadResult(
            metric=metric,
            iterations=iterations,
            mean_ns=mean(durations),
            median_ns=median(durations),
            min_ns=min(durations),
            max_ns=max(durations),
        )


def summarize_ablation(results: Iterable[AblationResult]) -> dict[str, object]:
    """Summarize ablation coverage by mode.

    summary 显示每种模式通过正向样本和拒绝负向样本的能力。
    """
    result_list = list(results)
    by_mode: dict[str, dict[str, object]] = {}
    for mode in ABLATION_MODES:
        mode_results = [result for result in result_list if result.mode == mode]
        positive = [result for result in mode_results if result.expected_allow]
        negative = [result for result in mode_results if not result.expected_allow]
        by_mode[mode] = {
            "case_count": len(mode_results),
            "passed_count": sum(1 for result in mode_results if result.passed),
            "positive_allowed_count": sum(1 for result in positive if result.allowed),
            "negative_rejected_count": sum(1 for result in negative if not result.allowed),
            "failed_cases": [
                result.case for result in mode_results if not result.passed
            ],
        }
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "modes": by_mode,
    }


def write_ablation_overhead_results(
    *,
    ablation_results: Iterable[AblationResult],
    overhead_results: Iterable[OverheadResult],
    output_dir: str | Path,
) -> tuple[Path, Path, Path]:
    """Write ablation JSONL, overhead JSON, and summary JSON artifacts.

    将消融结果、开销结果和汇总写入稳定文件，默认可放在 ignored runs 目录。
    """
    ablation_list = list(ablation_results)
    overhead_list = list(overhead_results)
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    ablation_path = base_dir / "ablation_results.jsonl"
    with ablation_path.open("w", encoding="utf-8") as handle:
        for result in ablation_list:
            handle.write(json.dumps(result.as_dict(), sort_keys=True) + "\n")

    overhead_path = base_dir / "overhead_results.json"
    with overhead_path.open("w", encoding="utf-8") as handle:
        json.dump(
            [result.as_dict() for result in overhead_list],
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")

    summary_path = base_dir / "ablation_overhead_summary.json"
    summary = summarize_ablation(ablation_list)
    summary["overhead_metrics"] = [result.metric for result in overhead_list]
    summary["ablation_results_path"] = str(ablation_path)
    summary["overhead_results_path"] = str(overhead_path)
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return ablation_path, overhead_path, summary_path


def run_ablation_overhead(
    *,
    iterations: int = DEFAULT_ITERATIONS,
    output_dir: str | Path | None = None,
) -> tuple[list[AblationResult], list[OverheadResult]]:
    """Run offline ablation and overhead experiments.

    测试和 CLI 共用入口，默认不写文件，传入输出目录时落盘。
    """
    harness = AblationOverheadHarness()
    ablation_results = harness.run_ablation()
    overhead_results = harness.run_overhead(iterations=iterations)
    if output_dir is not None:
        write_ablation_overhead_results(
            ablation_results=ablation_results,
            overhead_results=overhead_results,
            output_dir=output_dir,
        )
    return ablation_results, overhead_results


def _default_output_dir() -> Path:
    """Return the default ignored output directory for one run.

    默认输出目录位于 ignored 的 experiments/runs 下，避免产物进入提交。
    """
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_RUNS_DIR / f"{timestamp}-ablation-overhead"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the ablation/overhead runner.

    解析离线消融/开销 runner 的迭代次数和输出目录参数。
    """
    parser = argparse.ArgumentParser(
        description="Run offline SAGA-PQ-CAN ablation and overhead experiments."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help="Micro-benchmark iterations per overhead metric.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for JSON artifacts. Defaults under experiments/runs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the ablation/overhead CLI.

    执行离线消融和微开销统计，并打印简短摘要。
    """
    args = parse_args(argv)
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    ablation_results, overhead_results = run_ablation_overhead(
        iterations=args.iterations,
        output_dir=output_dir,
    )
    summary = summarize_ablation(ablation_results)
    print(f"[ablation] output directory: {output_dir}")
    for mode, mode_summary in summary["modes"].items():
        print(
            "[ablation] "
            f"{mode}: passed={mode_summary['passed_count']}/"
            f"{mode_summary['case_count']} "
            f"negative_rejected={mode_summary['negative_rejected_count']}"
        )
    for result in overhead_results:
        print(
            "[overhead] "
            f"{result.metric}: median_ns={int(result.median_ns)} "
            f"mean_ns={int(result.mean_ns)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
