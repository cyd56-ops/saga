"""Offline negative-injection runner for SAGA-PQ-CAN execution gates."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
from typing import Callable, Iterable, Mapping

from neural import bytes_to_bits
from pq import KeyPair, ToyLWESignatureScheme
from saga.agent import Agent
from saga.execution_gate import (
    ExecutionGateDecision,
    ExecutionGateRequest,
    LocalExecutionContext,
    SignedRequestExecutionGate,
    build_toy_lwe_execution_gate,
)
from saga.messages import RequestEnvelope, build_request_envelope, parse_request_envelope


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_SENDER_AID = "alice@example.com:calendar_agent"
DEFAULT_RECEIVER_AID = "bob@example.com:email_agent"
DEFAULT_UNTRUSTED_AID = "mallory@example.com:calendar_agent"
DEFAULT_TOKEN = "enc-token"
DEFAULT_MESSAGE = "schedule a meeting"
DEFAULT_NOW = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)

DEFAULT_SCENARIOS = (
    "tampered_message",
    "tampered_action_scope",
    "tampered_authorized_scope",
    "expired_envelope",
    "replayed_envelope",
    "unauthorized_tool_scope",
    "unauthorized_memory_write",
    "unauthorized_delegation",
    "real_valued_signature_input",
    "untrusted_sender_aid",
    "wrong_trusted_sender_key",
    "agent_runtime_prompt_surface_tool_only",
    "agent_runtime_replayed_envelope",
    "agent_runtime_scope_escalation_tool",
)


@dataclass(frozen=True)
class NegativeInjectionResult:
    """One defensive negative-injection outcome.

    记录一次负向注入是否被按预期拒绝，以及拒绝发生在哪一层。
    """

    scenario: str
    category: str
    passed: bool
    allowed: bool
    expected_reason: str
    observed_reason: str
    side_effect_triggered: bool = False
    details: Mapping[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        """Serialize the result as a JSON-compatible dictionary.

        输出字段保持稳定，便于实验批跑和论文统计脚本读取。
        """
        return {
            "scenario": self.scenario,
            "category": self.category,
            "passed": self.passed,
            "allowed": self.allowed,
            "expected_reason": self.expected_reason,
            "observed_reason": self.observed_reason,
            "side_effect_triggered": self.side_effect_triggered,
            "details": dict(self.details or {}),
        }


@dataclass(frozen=True)
class _SignedFixture:
    """Signed request material shared by runner scenarios."""

    request: ExecutionGateRequest
    envelope: RequestEnvelope
    signature: bytes


class _NoOpMonitor:
    """Minimal monitor used by offline runtime-path scenarios."""

    def start(self, _name: str) -> None:
        """记录离线 runner 中无需真实计时的 start hook。"""

    def stop(self, _name: str) -> None:
        """记录离线 runner 中无需真实计时的 stop hook。"""


class _RuntimeLocalAgent:
    """Local-agent stub that records runtime execution side effects.

    用于验证 Agent runtime 拒绝路径是否阻止 local_agent 副作用。
    """

    task_finished_token = "<TASK_FINISHED>"

    def __init__(self, *, response: str = "continue") -> None:
        """Create a local-agent stub with a fixed response."""
        self.response = response
        self.run_calls = 0
        self.execution_contexts: list[LocalExecutionContext | None] = []
        self.side_effects: list[str] = []
        self.denied_reason = ""

    def run(
        self,
        query: str,
        initiating_agent: bool,
        agent_instance: object | None = None,
        **kwargs: object,
    ) -> tuple[object | None, str]:
        """Record that the prompt surface was reached and return a fixed response.

        如果 gate 正确拒绝，负向场景不应调用这个方法。
        """
        self.run_calls += 1
        self.execution_contexts.append(kwargs.get("execution_context"))
        return agent_instance, self.response


class _ScopeEscalatingLocalAgent(_RuntimeLocalAgent):
    """Local-agent stub that tries to call an unsigned downstream tool scope."""

    def run(
        self,
        query: str,
        initiating_agent: bool,
        agent_instance: object | None = None,
        **kwargs: object,
    ) -> tuple[object | None, str]:
        """Attempt a tool-call scope escalation through the propagated context.

        未签名的工具 scope 必须在真实 runtime 路径中被拒绝，且不记录副作用。
        """
        self.run_calls += 1
        context = kwargs.get("execution_context")
        self.execution_contexts.append(context)
        if not isinstance(context, LocalExecutionContext):
            self.denied_reason = "missing_local_execution_context"
            raise PermissionError("missing_local_execution_context")

        try:
            context.require_tool_call("add_calendar_event")
        except PermissionError:
            self.denied_reason = "unauthorized_tool_scope"
            raise

        self.side_effects.append("add_calendar_event")
        return agent_instance, self.response


class NegativeInjectionHarness:
    """Build deterministic negative injections against the execution gate.

    该 harness 离线构造签名信封和越权动作，不依赖真实网络、模型或私钥外泄。
    """

    def __init__(
        self,
        *,
        now: datetime = DEFAULT_NOW,
        seed: int = 101,
    ) -> None:
        """Create deterministic toy signing material for all scenarios.

        toy LWE 仅用于研究测试 wiring，不代表生产 PQ 签名实现。
        """
        self.now = now
        self.scheme = ToyLWESignatureScheme(seed=seed)
        self.sender_keys = self.scheme.keygen()
        self.alternate_keys = self.scheme.keygen()

    def run(self, scenario_names: Iterable[str] | None = None) -> list[NegativeInjectionResult]:
        """Run selected negative-injection scenarios.

        每个场景都必须 fail-closed；返回值中的 ``passed`` 表示防护生效。
        """
        names = tuple(scenario_names or DEFAULT_SCENARIOS)
        results: list[NegativeInjectionResult] = []
        for name in names:
            results.append(self._run_one(name))
        return results

    def _run_one(self, name: str) -> NegativeInjectionResult:
        """按名称执行单个负向注入场景。"""
        runners: dict[str, Callable[[], NegativeInjectionResult]] = {
            "tampered_message": self._tampered_message,
            "tampered_action_scope": self._tampered_action_scope,
            "tampered_authorized_scope": self._tampered_authorized_scope,
            "expired_envelope": self._expired_envelope,
            "replayed_envelope": self._replayed_envelope,
            "unauthorized_tool_scope": self._unauthorized_tool_scope,
            "unauthorized_memory_write": self._unauthorized_memory_write,
            "unauthorized_delegation": self._unauthorized_delegation,
            "real_valued_signature_input": self._real_valued_signature_input,
            "untrusted_sender_aid": self._untrusted_sender_aid,
            "wrong_trusted_sender_key": self._wrong_trusted_sender_key,
            "agent_runtime_prompt_surface_tool_only": (
                self._agent_runtime_prompt_surface_tool_only
            ),
            "agent_runtime_replayed_envelope": self._agent_runtime_replayed_envelope,
            "agent_runtime_scope_escalation_tool": (
                self._agent_runtime_scope_escalation_tool
            ),
        }
        try:
            runner = runners[name]
        except KeyError as exc:
            raise ValueError(f"unknown negative injection scenario: {name}") from exc
        return runner()

    def _new_gate(
        self,
        trusted_public_keys: Mapping[str, bytes] | None = None,
    ) -> SignedRequestExecutionGate:
        """构造带固定当前时间的 execution gate，避免测试受墙钟影响。"""
        return build_toy_lwe_execution_gate(
            self.scheme,
            trusted_public_keys or {DEFAULT_SENDER_AID: self.sender_keys.public_key},
            now_fn=lambda: self.now,
        )

    def _signed_request(
        self,
        *,
        message: str = DEFAULT_MESSAGE,
        action_scope: str = "llm_prompt",
        authorized_scopes: Iterable[str] | None = None,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
        sender_aid: str = DEFAULT_SENDER_AID,
        receiver_aid: str = DEFAULT_RECEIVER_AID,
        signer_key_pair: KeyPair | None = None,
    ) -> _SignedFixture:
        """构造合法签名请求，具体场景再做最小篡改。"""
        key_pair = signer_key_pair or self.sender_keys
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=DEFAULT_TOKEN,
            session_id="negative-session-1",
            turn_id="turn-1",
            issued_at=issued_at or (self.now - timedelta(minutes=1)),
            expires_at=expires_at or (self.now + timedelta(minutes=5)),
            action_scope=action_scope,
            authorized_scopes=authorized_scopes,
            message=message,
            provider_id="https://provider.example.test",
            timestamp=self.now,
        )
        signature = self.scheme.sign(key_pair.secret_key, envelope.digest())
        return _SignedFixture(
            request=ExecutionGateRequest(
                sender_aid=sender_aid,
                receiver_aid=receiver_aid,
                token=DEFAULT_TOKEN,
                message=message,
                action_scope=action_scope,
                request_envelope=envelope.canonical_json(),
                pq_signature=base64.b64encode(signature).decode("utf-8"),
            ),
            envelope=envelope,
            signature=signature,
        )

    def _decision_result(
        self,
        *,
        scenario: str,
        category: str,
        expected_reason: str,
        decision: ExecutionGateDecision,
        details: Mapping[str, object] | None = None,
    ) -> NegativeInjectionResult:
        """将 gate decision 归一化为负向注入结果。"""
        return NegativeInjectionResult(
            scenario=scenario,
            category=category,
            passed=not decision.allowed and decision.reason == expected_reason,
            allowed=decision.allowed,
            expected_reason=expected_reason,
            observed_reason=decision.reason,
            details=details,
        )

    def _tampered_message(self) -> NegativeInjectionResult:
        """验证传输消息被篡改时会被 message digest 绑定拒绝。"""
        gate = self._new_gate()
        fixture = self._signed_request()
        request = ExecutionGateRequest(
            sender_aid=fixture.request.sender_aid,
            receiver_aid=fixture.request.receiver_aid,
            token=fixture.request.token,
            message="tampered payload",
            action_scope=fixture.request.action_scope,
            request_envelope=fixture.request.request_envelope,
            pq_signature=fixture.request.pq_signature,
        )
        return self._decision_result(
            scenario="tampered_message",
            category="envelope_binding",
            expected_reason="message_digest_mismatch",
            decision=gate.evaluate_request(request),
        )

    def _tampered_action_scope(self) -> NegativeInjectionResult:
        """验证外层 action_scope 被替换时会被签名信封绑定拒绝。"""
        gate = self._new_gate()
        fixture = self._signed_request()
        request = ExecutionGateRequest(
            sender_aid=fixture.request.sender_aid,
            receiver_aid=fixture.request.receiver_aid,
            token=fixture.request.token,
            message=fixture.request.message,
            action_scope="tool_call:send_email",
            request_envelope=fixture.request.request_envelope,
            pq_signature=fixture.request.pq_signature,
        )
        return self._decision_result(
            scenario="tampered_action_scope",
            category="envelope_binding",
            expected_reason="action_scope_mismatch",
            decision=gate.evaluate_request(request),
        )

    def _tampered_authorized_scope(self) -> NegativeInjectionResult:
        """验证签名后的授权 scope 列表不能被扩权篡改。"""
        gate = self._new_gate()
        fixture = self._signed_request(authorized_scopes=("tool_call:send_email",))
        envelope_dict = parse_request_envelope(fixture.request.request_envelope).as_dict()
        envelope_dict["authorized_scopes"] = [
            "llm_prompt",
            "tool_call:add_calendar_event",
        ]
        request = ExecutionGateRequest(
            sender_aid=fixture.request.sender_aid,
            receiver_aid=fixture.request.receiver_aid,
            token=fixture.request.token,
            message=fixture.request.message,
            action_scope=fixture.request.action_scope,
            request_envelope=json.dumps(envelope_dict, sort_keys=True),
            pq_signature=fixture.request.pq_signature,
        )
        return self._decision_result(
            scenario="tampered_authorized_scope",
            category="envelope_binding",
            expected_reason="signature_verification_failed",
            decision=gate.evaluate_request(request),
        )

    def _expired_envelope(self) -> NegativeInjectionResult:
        """验证过期信封即使签名有效也会 fail-closed。"""
        gate = self._new_gate()
        fixture = self._signed_request(
            issued_at=self.now - timedelta(minutes=10),
            expires_at=self.now - timedelta(minutes=1),
        )
        return self._decision_result(
            scenario="expired_envelope",
            category="time_window",
            expected_reason="envelope_expired",
            decision=gate.evaluate_request(fixture.request),
        )

    def _replayed_envelope(self) -> NegativeInjectionResult:
        """验证同一签名信封只能被执行路径消费一次。"""
        gate = self._new_gate()
        fixture = self._signed_request()
        first = gate.consume_request(fixture.request)
        second = gate.consume_request(fixture.request)
        return NegativeInjectionResult(
            scenario="replayed_envelope",
            category="replay",
            passed=first.allowed and not second.allowed and second.reason == "replayed_request_envelope",
            allowed=second.allowed,
            expected_reason="replayed_request_envelope",
            observed_reason=second.reason,
            details={
                "first_allowed": first.allowed,
                "first_reason": first.reason,
            },
        )

    def _valid_context(
        self,
        *,
        authorized_scopes: Iterable[str] | None = None,
    ) -> LocalExecutionContext:
        """构造已验签的本地执行上下文，用于下游执行面越权测试。"""
        gate = self._new_gate()
        fixture = self._signed_request(authorized_scopes=authorized_scopes)
        decision = gate.evaluate_request(fixture.request)
        context = gate.build_local_execution_context_from_decision(
            fixture.request,
            decision,
        )
        if context is None:
            raise RuntimeError(f"valid fixture was unexpectedly rejected: {decision.reason}")
        return context

    def _scope_rejection_result(
        self,
        *,
        scenario: str,
        expected_reason: str,
        action: Callable[[LocalExecutionContext], None],
        authorized_scopes: Iterable[str] | None = None,
    ) -> NegativeInjectionResult:
        """执行一次下游 scope 越权尝试，并确认没有副作用发生。"""
        context = self._valid_context(authorized_scopes=authorized_scopes)
        side_effects: list[str] = []
        exception_text = ""
        try:
            action(context)
            side_effects.append("unauthorized_action")
            observed_reason = "authorized"
        except PermissionError as exc:
            exception_text = str(exc)
            observed_reason = expected_reason

        side_effect_triggered = bool(side_effects)
        return NegativeInjectionResult(
            scenario=scenario,
            category="execution_scope",
            passed=not side_effect_triggered and observed_reason == expected_reason,
            allowed=side_effect_triggered,
            expected_reason=expected_reason,
            observed_reason=observed_reason,
            side_effect_triggered=side_effect_triggered,
            details={"exception": exception_text},
        )

    def _unauthorized_tool_scope(self) -> NegativeInjectionResult:
        """验证已签名工具 scope 只能授权精确工具，不能横向调用其他工具。"""
        return self._scope_rejection_result(
            scenario="unauthorized_tool_scope",
            expected_reason="unauthorized_tool_scope",
            authorized_scopes=("tool_call:send_email",),
            action=lambda context: context.require_tool_call("add_calendar_event"),
        )

    def _unauthorized_memory_write(self) -> NegativeInjectionResult:
        """验证没有 ``memory_write`` scope 时不能写入本地 memory。"""
        return self._scope_rejection_result(
            scenario="unauthorized_memory_write",
            expected_reason="unauthorized_memory_write",
            action=lambda context: context.require_memory_write(),
        )

    def _unauthorized_delegation(self) -> NegativeInjectionResult:
        """验证没有 ``delegation`` scope 时不能发起下游 agent 委托。"""
        return self._scope_rejection_result(
            scenario="unauthorized_delegation",
            expected_reason="unauthorized_delegation",
            action=lambda context: context.require_delegation(),
        )

    def _real_valued_signature_input(self) -> NegativeInjectionResult:
        """验证签名字节对应的实数比特注入会被 Shamir MASK 拒绝。"""
        gate = self._new_gate()
        fixture = self._signed_request()
        public_key_bits = bytes_to_bits(self.sender_keys.public_key)
        envelope_bits = bytes_to_bits(fixture.envelope.digest())
        signature_bits = bytes_to_bits(fixture.signature)
        base_accept = gate.can_gate.can_accept(
            public_key_bits,
            envelope_bits,
            signature_bits,
        )

        injected_bits = [
            *public_key_bits,
            *envelope_bits,
            *signature_bits,
        ]
        injected_index = len(public_key_bits) + len(envelope_bits)
        injected_bits[injected_index] = 0.5
        injected_accept = gate.can_gate.can_accept_compound_bits(injected_bits)

        return NegativeInjectionResult(
            scenario="real_valued_signature_input",
            category="real_valued_rejection",
            passed=base_accept == 1 and injected_accept == 0,
            allowed=injected_accept == 1,
            expected_reason="real_valued_signature_input",
            observed_reason=(
                "real_valued_signature_input"
                if injected_accept == 0
                else "authorized"
            ),
            details={
                "base_accept": base_accept,
                "injected_accept": injected_accept,
                "injected_coordinate": injected_index,
                "injected_value": 0.5,
            },
        )

    def _untrusted_sender_aid(self) -> NegativeInjectionResult:
        """验证未登记可信公钥的发送方身份会在验签前拒绝。"""
        gate = self._new_gate()
        fixture = self._signed_request()
        request = ExecutionGateRequest(
            sender_aid=DEFAULT_UNTRUSTED_AID,
            receiver_aid=fixture.request.receiver_aid,
            token=fixture.request.token,
            message=fixture.request.message,
            action_scope=fixture.request.action_scope,
            request_envelope=fixture.request.request_envelope,
            pq_signature=fixture.request.pq_signature,
        )
        return self._decision_result(
            scenario="untrusted_sender_aid",
            category="trusted_key",
            expected_reason="untrusted_sender_aid",
            decision=gate.evaluate_request(request),
        )

    def _wrong_trusted_sender_key(self) -> NegativeInjectionResult:
        """验证 sender AID 对应错误公钥时签名验签失败。"""
        gate = self._new_gate({DEFAULT_SENDER_AID: self.alternate_keys.public_key})
        fixture = self._signed_request()
        return self._decision_result(
            scenario="wrong_trusted_sender_key",
            category="trusted_key",
            expected_reason="signature_verification_failed",
            decision=gate.evaluate_request(fixture.request),
        )

    def _message_dict_from_fixture(self, fixture: _SignedFixture) -> dict[str, object]:
        """将签名 fixture 转换为 Agent runtime 接收的 transport payload。"""
        return {
            "msg": fixture.request.message,
            "token": fixture.request.token,
            "action_scope": fixture.request.action_scope,
            "request_envelope": fixture.request.request_envelope,
            "pq_signature": fixture.request.pq_signature,
        }

    def _runtime_agent(
        self,
        *,
        gate: SignedRequestExecutionGate,
        local_agent: _RuntimeLocalAgent,
        workdir: str,
        token_quota: int = 1,
    ) -> Agent:
        """构造离线 Agent shell，用真实 receive_conversation 路径消费 payload。"""
        agent = Agent.__new__(Agent)
        agent.execution_gate = gate
        agent.strict_execution_gate = True
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = _NoOpMonitor()
        agent.llm_monitor = _NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            DEFAULT_TOKEN: {
                "issue_timestamp": (self.now - timedelta(minutes=1)).isoformat(),
                "expiration_timestamp": (self.now + timedelta(minutes=5)).isoformat(),
                "communication_quota": token_quota,
                "recipient_pac": "recipient-pac",
            }
        }
        agent.aid = DEFAULT_RECEIVER_AID
        agent.workdir = workdir
        agent.provider_id = "https://provider.example.test"
        agent.token_is_valid = lambda _token, _recipient_pac: True
        return agent

    def _load_last_audit_reason(self, workdir: str) -> str:
        """读取 Agent runtime 写入的最后一条 execution-gate audit reason。"""
        audit_path = Path(workdir) / "audit" / "execution_gate.jsonl"
        if not audit_path.exists():
            return ""
        rows = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not rows:
            return ""
        return str(rows[-1].get("reason", ""))

    def _agent_runtime_prompt_surface_tool_only(self) -> NegativeInjectionResult:
        """验证真实 Agent 路径拒绝 tool-only envelope 进入 LLM prompt。"""
        fixture = self._signed_request(
            message="send mail",
            action_scope="tool_call:send_email",
        )
        message_dict = self._message_dict_from_fixture(fixture)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = _RuntimeLocalAgent()
            agent = self._runtime_agent(
                gate=self._new_gate(),
                local_agent=local_agent,
                workdir=tmpdir,
            )
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended = agent.receive_conversation(
                object(),
                DEFAULT_TOKEN,
                recipient_pac=object(),
                sender_aid=DEFAULT_SENDER_AID,
            )
            observed_reason = self._load_last_audit_reason(tmpdir)

        return NegativeInjectionResult(
            scenario="agent_runtime_prompt_surface_tool_only",
            category="agent_runtime",
            passed=(
                ended
                and local_agent.run_calls == 0
                and observed_reason == "prompt_scope_not_authorized"
            ),
            allowed=local_agent.run_calls > 0,
            expected_reason="prompt_scope_not_authorized",
            observed_reason=observed_reason or "missing_audit_reason",
            side_effect_triggered=local_agent.run_calls > 0,
            details={"local_agent_run_calls": local_agent.run_calls},
        )

    def _agent_runtime_replayed_envelope(self) -> NegativeInjectionResult:
        """验证真实 Agent 执行路径中重复 envelope 不会第二次进入 local agent。"""
        fixture = self._signed_request()
        message_dict = self._message_dict_from_fixture(fixture)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = _RuntimeLocalAgent(response="continue")
            agent = self._runtime_agent(
                gate=self._new_gate(),
                local_agent=local_agent,
                workdir=tmpdir,
                token_quota=2,
            )
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended = agent.receive_conversation(
                object(),
                DEFAULT_TOKEN,
                recipient_pac=object(),
                sender_aid=DEFAULT_SENDER_AID,
            )
            observed_reason = self._load_last_audit_reason(tmpdir)

        return NegativeInjectionResult(
            scenario="agent_runtime_replayed_envelope",
            category="agent_runtime",
            passed=(
                ended
                and local_agent.run_calls == 1
                and observed_reason == "replayed_request_envelope"
            ),
            allowed=local_agent.run_calls > 1,
            expected_reason="replayed_request_envelope",
            observed_reason=observed_reason or "missing_audit_reason",
            side_effect_triggered=local_agent.run_calls > 1,
            details={"local_agent_run_calls": local_agent.run_calls},
        )

    def _agent_runtime_scope_escalation_tool(self) -> NegativeInjectionResult:
        """验证真实 Agent 路径中未签名工具 scope escalation 会被拒绝。"""
        fixture = self._signed_request(
            authorized_scopes=("tool_call:send_email",),
        )
        message_dict = self._message_dict_from_fixture(fixture)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = _ScopeEscalatingLocalAgent()
            agent = self._runtime_agent(
                gate=self._new_gate(),
                local_agent=local_agent,
                workdir=tmpdir,
            )
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended = agent.receive_conversation(
                object(),
                DEFAULT_TOKEN,
                recipient_pac=object(),
                sender_aid=DEFAULT_SENDER_AID,
            )

        return NegativeInjectionResult(
            scenario="agent_runtime_scope_escalation_tool",
            category="agent_runtime",
            passed=(
                ended
                and local_agent.run_calls == 1
                and not local_agent.side_effects
                and local_agent.denied_reason == "unauthorized_tool_scope"
            ),
            allowed=bool(local_agent.side_effects),
            expected_reason="unauthorized_tool_scope",
            observed_reason=local_agent.denied_reason or "authorized",
            side_effect_triggered=bool(local_agent.side_effects),
            details={
                "local_agent_run_calls": local_agent.run_calls,
                "side_effects": list(local_agent.side_effects),
            },
        )


def available_scenarios() -> tuple[str, ...]:
    """Return supported scenario names.

    供 CLI choices 和测试断言复用，避免覆盖清单漂移。
    """
    return DEFAULT_SCENARIOS


def build_summary(results: Iterable[NegativeInjectionResult]) -> dict[str, object]:
    """Build an aggregate summary for a negative-injection run.

    summary 用于快速判断整轮负向注入是否全部 fail-closed。
    """
    result_list = list(results)
    passed_count = sum(1 for result in result_list if result.passed)
    failed = [result.scenario for result in result_list if not result.passed]
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "scenario_count": len(result_list),
        "passed_count": passed_count,
        "failed_count": len(result_list) - passed_count,
        "all_passed": not failed,
        "failed_scenarios": failed,
        "scenarios": [result.scenario for result in result_list],
    }


def write_negative_injection_results(
    results: Iterable[NegativeInjectionResult],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write JSONL results and an aggregate summary.

    结果默认写入 ignored 的 ``experiments/runs``，避免实验产物进入提交。
    """
    result_list = list(results)
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    results_path = base_dir / "negative_injections.jsonl"
    with results_path.open("w", encoding="utf-8") as handle:
        for result in result_list:
            handle.write(json.dumps(result.as_dict(), sort_keys=True) + "\n")

    summary_path = base_dir / "negative_injections_summary.json"
    summary = build_summary(result_list)
    summary["results_path"] = str(results_path)
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return results_path, summary_path


def run_negative_injections(
    scenario_names: Iterable[str] | None = None,
    *,
    output_dir: str | Path | None = None,
) -> list[NegativeInjectionResult]:
    """Run deterministic negative injections and optionally write artifacts.

    这是测试和 CLI 共用入口；不启动 Provider、MongoDB 或模型后端。
    """
    harness = NegativeInjectionHarness()
    results = harness.run(scenario_names)
    if output_dir is not None:
        write_negative_injection_results(results, output_dir)
    return results


def _selected_scenarios(values: Iterable[str] | None) -> tuple[str, ...]:
    """规范化 CLI 传入的场景列表。"""
    requested = tuple(values or ("all",))
    if "all" in requested:
        return DEFAULT_SCENARIOS

    seen: set[str] = set()
    selected: list[str] = []
    for value in requested:
        if value not in seen:
            seen.add(value)
            selected.append(value)
    return tuple(selected)


def _default_output_dir() -> Path:
    """返回本轮负向注入的默认输出目录。"""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_RUNS_DIR / f"{timestamp}-negative-injections"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the negative-injection runner.

    CLI 支持选择单个场景或一次运行全部场景。
    """
    parser = argparse.ArgumentParser(
        description=(
            "Run offline SAGA-PQ-CAN negative injections against the deterministic "
            "execution gate."
        )
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=[*DEFAULT_SCENARIOS, "all"],
        help="Scenario to run. Repeat for multiple scenarios, or use all.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for JSONL results and summary. Defaults under experiments/runs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the negative-injection CLI.

    若任一负向场景未按预期拒绝，则返回非零状态码。
    """
    args = parse_args(argv)
    selected = _selected_scenarios(args.scenario)
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()

    results = run_negative_injections(selected, output_dir=output_dir)
    summary = build_summary(results)
    print(f"[negative] output directory: {output_dir}")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            "[negative] "
            f"{status} {result.scenario}: expected={result.expected_reason} "
            f"observed={result.observed_reason}"
        )
    print(
        "[negative] "
        f"passed={summary['passed_count']}/{summary['scenario_count']} "
        f"all_passed={summary['all_passed']}"
    )
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
