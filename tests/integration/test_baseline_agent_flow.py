"""Lightweight baseline integration tests for the current Agent token flow."""

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from neural import CAN, CompiledToyLWEVerifier
from pq import ToyLWESignatureScheme
import saga.common.crypto as sc
from saga.agent import Agent
from saga.execution_gate import (
    ExecutionAuthorizationError,
    ExecutionGateDecision,
    ExecutionGateRequest,
    SignedRequestExecutionGate,
)
from saga.local_agent import LocalAgent
from saga.messages import build_request_envelope, parse_request_envelope

from tests.security.test_token_validation import (
    _build_minimal_agent,
    _token_dict,
)


class BaselineAgentFlowTests(unittest.TestCase):
    """Exercise a minimal multi-method token lifecycle without network services."""

    class _NoOpMonitor:
        """Minimal monitor stub for direct Agent method tests."""

        def start(self, _name: str) -> None:
            """No-op start hook."""

        def stop(self, _name: str) -> None:
            """No-op stop hook."""

    class _TrackingLocalAgent:
        """Minimal local agent that records whether it was executed."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            return None, self.task_finished_token

    class _FinishImmediatelyLocalAgent:
        """Local agent stub that finishes in a single receiving-side turn."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            return None, self.task_finished_token

    class _StructuredResponseLocalAgent:
        """Local agent stub that returns a structured final answer."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0

        def supports_execution_context(self) -> bool:
            """声明测试替身会接受并遵守 execution_context 约束。"""
            return True

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            return None, {"status": "ready", "items": ["receipt"]}

    class _FailingLocalAgent:
        """Local agent stub that raises during execution."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            raise RuntimeError("model call did not return")

    class _ContextTrackingLocalAgent:
        """Local agent stub that records the propagated execution context."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0
            self.execution_contexts: list[object | None] = []

        def supports_execution_context(self) -> bool:
            """声明测试替身会接收 execution_context 并按其授权运行。"""
            return True

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            self.execution_contexts.append(kwargs.get("execution_context"))
            return None, self.task_finished_token

    class _ContextIgnoringLocalAgent(LocalAgent):
        """Local agent stub that ignores execution context and records side effects."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.run_calls = 0
            self.side_effects: list[str] = []

        def supports_execution_context(self) -> bool:
            """声明该替身不支持 execution_context，用于 U5 fail-closed 测试。"""
            return False

        def run(self, query: str, initiating_agent: bool, agent_instance=None, **kwargs):
            self.run_calls += 1
            self.side_effects.append(query)
            return None, self.task_finished_token

    class _DenyAllGate:
        """Execution gate stub that always rejects."""

        def __init__(self) -> None:
            self.requests: list[ExecutionGateRequest] = []

        def authorize(self, request: ExecutionGateRequest) -> bool:
            self.requests.append(request)
            return False

        def evaluate_request(self, request: ExecutionGateRequest):
            self.requests.append(request)
            return type(
                "Decision",
                (),
                {"allowed": False, "reason": "rejected_by_test_gate"},
            )()

    class _AllowLegacyGate:
        """Legacy gate stub that authorizes without building execution context."""

        def __init__(self) -> None:
            self.requests: list[ExecutionGateRequest] = []

        def authorize(self, request: ExecutionGateRequest) -> bool:
            self.requests.append(request)
            return True

    class _SingleMessageConn:
        """Connection placeholder; data flow is stubbed through Agent.recv."""

        pass

    class _DelegationAwareLocalAgent:
        """Local agent stub that can receive a runtime delegation handler."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.delegation_handler = None

        def set_delegation_handler(self, handler) -> None:
            self.delegation_handler = handler

    class _StrictCapabilityAwareLocalAgent:
        """Local agent stub that records strict capability mode updates."""

        task_finished_token = "<TASK_FINISHED>"

        def __init__(self) -> None:
            self.strict_values: list[bool] = []

        def set_strict_execution_capabilities(self, enabled: bool) -> None:
            """Record whether capability facades should require execution context."""
            self.strict_values.append(enabled)

    def test_store_retrieve_and_invalidate_received_token(self) -> None:
        """A received token should be stored, reused, then invalidated when exhausted."""
        agent = _build_minimal_agent()
        aid = "alice@example.com:calendar_agent"
        token = "enc-token"
        token_dict = _token_dict(
            expires_in_seconds=60,
            communication_quota=1,
            recipient_pac="unused-in-received-path",
        )

        agent.store_received_token(aid, token, token_dict)
        self.assertTrue(agent.received_token_is_valid(token))
        self.assertEqual(agent.retrieve_valid_token(aid), token)

        agent.received_tokens[token]["communication_quota"] = 0
        self.assertFalse(agent.received_token_is_valid(token))
        self.assertIsNone(agent.retrieve_valid_token(aid))
        self.assertNotIn(token, agent.received_tokens)
        self.assertNotIn(aid, agent.aid_to_token)

    def test_lookup_explicitly_raises_until_provider_support_exists(self) -> None:
        """The deprecated lookup path should stay unavailable in the baseline flow."""
        agent = Agent.__new__(Agent)
        with self.assertRaises(NotImplementedError):
            agent.lookup("alice@example.com:calendar_agent")

    def test_execution_gate_can_block_local_agent_run(self) -> None:
        """A configured execution gate should stop messages before local execution."""
        agent = Agent.__new__(Agent)
        token = "enc-token"
        local_agent = self._TrackingLocalAgent()
        gate = self._DenyAllGate()

        agent.execution_gate = gate
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac="recipient-pac",
            )
        }
        agent.aid = "bob@example.com:email_agent"
        agent.token_is_valid = lambda _token, _recipient_pac: True
        agent.recv = lambda _conn: {"msg": "hello", "token": token}
        agent.send = lambda _conn, _payload: None

        ended_from_receiver = agent.receive_conversation(
            self._SingleMessageConn(),
            token,
            recipient_pac=object(),
            sender_aid="alice@example.com:calendar_agent",
        )

        self.assertTrue(ended_from_receiver)
        self.assertEqual(local_agent.run_calls, 0)
        self.assertEqual(len(gate.requests), 1)
        self.assertEqual(gate.requests[0].action_scope, "llm_prompt")

    def test_execution_gate_rejection_logs_stable_audit_reason(self) -> None:
        """Receiver-side gate rejections should emit the local audit reason."""
        token = "enc-token"
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._TrackingLocalAgent()
            gate = self._DenyAllGate()

            agent.execution_gate = gate
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = "bob@example.com:email_agent"
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: {"msg": "hello", "token": token}
            agent.send = lambda _conn, _payload: None

            with mock.patch("saga.agent.logger.error") as error_log, mock.patch(
                "saga.agent.logger.log"
            ) as structured_log:
                ended_from_receiver = agent.receive_conversation(
                    self._SingleMessageConn(),
                    token,
                    recipient_pac=object(),
                    sender_aid="alice@example.com:calendar_agent",
                )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            error_log.assert_called_once()
            self.assertIn("rejected_by_test_gate", error_log.call_args.args[0])
            audit_messages = [
                call.args[1]
                for call in structured_log.call_args_list
                if len(call.args) == 2 and call.args[0] == "AUDIT"
            ]
            self.assertEqual(len(audit_messages), 1)
            audit_record = json.loads(audit_messages[0])
            self.assertEqual(audit_record["reason"], "rejected_by_test_gate")
            self.assertEqual(audit_record["sender_aid"], "alice@example.com:calendar_agent")
            self.assertEqual(audit_record["receiver_aid"], "bob@example.com:email_agent")

            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = audit_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(rows), 1)
            persisted_record = json.loads(rows[0])
            self.assertEqual(persisted_record["reason"], "rejected_by_test_gate")
            self.assertEqual(
                persisted_record["token_digest"],
                audit_record["token_digest"],
            )
            self.assertIn("recorded_at", persisted_record)

    def test_strict_execution_gate_rejects_missing_gate_before_local_agent(self) -> None:
        """Strict runtime-auth mode must fail closed when no gate is installed."""
        token = "enc-token"
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._TrackingLocalAgent()

            agent.execution_gate = None
            agent.strict_execution_gate = True
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = "bob@example.com:email_agent"
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: {"msg": "hello", "token": token}
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid="alice@example.com:calendar_agent",
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "missing_execution_gate")

    def test_strict_execution_gate_rejects_missing_local_execution_context(self) -> None:
        """Strict runtime-auth mode must reject legacy gates without context support."""
        token = "enc-token"
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._TrackingLocalAgent()
            gate = self._AllowLegacyGate()

            agent.execution_gate = gate
            agent.strict_execution_gate = True
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = "bob@example.com:email_agent"
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: {"msg": "hello", "token": token}
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid="alice@example.com:calendar_agent",
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            self.assertEqual(len(gate.requests), 1)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "missing_local_execution_context")

    def test_initiate_conversation_attaches_signed_envelope_when_configured(self) -> None:
        """Outgoing transport messages should carry the signed request envelope."""
        agent = Agent.__new__(Agent)
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        local_agent = self._TrackingLocalAgent()
        scheme = ToyLWESignatureScheme(seed=31)
        key_pair = scheme.keygen()
        sent_payloads: list[dict] = []

        agent.aid = "alice@example.com:calendar_agent"
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.received_tokens_lock = threading.Lock()
        agent.received_tokens = {
            token: {
                "issue_timestamp": datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
                "expiration_timestamp": datetime(2026, 5, 8, 13, 0, 0, tzinfo=timezone.utc).isoformat(),
                "communication_quota": 1,
                "recipient_pac": "recipient-pac",
            }
        }
        agent.aid_to_token = {receiver_aid: token}
        agent.pq_signature_scheme = scheme
        agent.pq_secret_key = key_pair.secret_key
        agent.provider_id = "https://provider.example.test"
        agent.received_token_is_valid = lambda _token: True
        agent.send = lambda _conn, payload: sent_payloads.append(payload)
        agent.recv = lambda _conn: {"msg": local_agent.task_finished_token, "token": token}

        ended_from_receiver = agent.initiate_conversation(
            None,
            token,
            receiver_aid,
            "hello",
        )

        self.assertFalse(ended_from_receiver)
        self.assertEqual(len(sent_payloads), 1)
        self.assertEqual(sent_payloads[0]["action_scope"], "llm_prompt")
        self.assertIn("request_envelope", sent_payloads[0])
        self.assertIn("pq_signature", sent_payloads[0])

        envelope = parse_request_envelope(sent_payloads[0]["request_envelope"])
        signature = base64.b64decode(sent_payloads[0]["pq_signature"])
        self.assertEqual(envelope.sender_aid, agent.aid)
        self.assertEqual(envelope.receiver_aid, receiver_aid)
        self.assertTrue(scheme.verify(key_pair.public_key, envelope.digest(), signature))

    def _signed_response_payload(
        self,
        *,
        scheme: ToyLWESignatureScheme,
        key_pair,
        sender_aid: str,
        receiver_aid: str,
        token: str,
        message: str,
        now: datetime,
    ) -> dict:
        """Build a signed response payload for initiating-side gate tests."""
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message=message,
            timestamp=now,
        )
        return {
            "msg": message,
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

    def _signed_prompt_payload(
        self,
        *,
        scheme: ToyLWESignatureScheme,
        key_pair,
        sender_aid: str,
        receiver_aid: str,
        token: str,
        message: str,
        now: datetime,
    ) -> dict:
        """构造带有效签名的 prompt payload，用于入口 fail-closed 测试。"""
        return self._signed_response_payload(
            scheme=scheme,
            key_pair=key_pair,
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            message=message,
            now=now,
        )

    def _build_initiating_agent_for_response_gate(
        self,
        *,
        gate: SignedRequestExecutionGate | None,
        local_agent,
        token: str,
        receiver_aid: str,
        response_payload: dict,
        workdir: str | None = None,
    ) -> tuple[Agent, list[dict]]:
        """构造最小 initiating-side agent，用于验证响应进入本地执行前的 gate。"""
        agent = Agent.__new__(Agent)
        sent_payloads: list[dict] = []
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)

        agent.aid = "alice@example.com:calendar_agent"
        agent.execution_gate = gate
        agent.strict_execution_gate = True
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.received_tokens_lock = threading.Lock()
        agent.received_tokens = {
            token: {
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(hours=1)).isoformat(),
                "communication_quota": 2,
                "recipient_pac": "recipient-pac",
            }
        }
        agent.aid_to_token = {receiver_aid: token}
        agent.provider_id = "https://provider.example.test"
        agent.pq_signature_scheme = None
        agent.pq_secret_key = None
        if workdir is not None:
            agent.workdir = workdir
        agent.received_token_is_valid = lambda _token: True
        agent.send = lambda _conn, payload: sent_payloads.append(payload)
        agent.recv = lambda _conn: response_payload
        return agent, sent_payloads

    def test_initiating_side_strict_mode_rejects_missing_gate_before_local_agent(self) -> None:
        """Strict initiating-side response processing must reject a missing execution gate."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        response_payload = {
            "msg": "response without gate",
            "token": token,
            "action_scope": "llm_prompt",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextTrackingLocalAgent()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=None,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "missing_execution_gate")

    def test_initiating_side_strict_mode_rejects_legacy_gate_without_context(self) -> None:
        """Strict initiating-side response processing must reject legacy gates without context support."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        response_payload = {
            "msg": "legacy response",
            "token": token,
            "action_scope": "llm_prompt",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextTrackingLocalAgent()
            gate = self._AllowLegacyGate()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=gate,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            self.assertEqual(len(gate.requests), 1)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "missing_local_execution_context")

    def test_initiating_side_accepts_valid_signed_response_and_runs_local_agent(self) -> None:
        """A valid signed response should pass the initiating-side inbound gate."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=61)
        receiver_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {receiver_aid: receiver_keys.public_key},
            now_fn=lambda: now,
        )
        response_payload = self._signed_response_payload(
            scheme=scheme,
            key_pair=receiver_keys,
            sender_aid=receiver_aid,
            receiver_aid="alice@example.com:calendar_agent",
            token=token,
            message="please revise the proposal",
            now=now,
        )
        local_agent = self._ContextTrackingLocalAgent()
        agent, sent_payloads = self._build_initiating_agent_for_response_gate(
            gate=gate,
            local_agent=local_agent,
            token=token,
            receiver_aid=receiver_aid,
            response_payload=response_payload,
        )

        ended_from_initiator = agent.initiate_conversation(
            self._SingleMessageConn(),
            token,
            receiver_aid,
            "hello",
        )

        self.assertTrue(ended_from_initiator)
        self.assertEqual(local_agent.run_calls, 1)
        self.assertGreaterEqual(len(sent_payloads), 2)
        assert local_agent.execution_contexts[0] is not None
        self.assertTrue(local_agent.execution_contexts[0].authorize_action("llm_prompt"))

    def test_initiating_side_rejects_context_ignoring_local_agent_before_run(self) -> None:
        """Strict response processing must reject LocalAgent implementations that ignore context."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=66)
        receiver_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {receiver_aid: receiver_keys.public_key},
            now_fn=lambda: now,
        )
        response_payload = self._signed_response_payload(
            scheme=scheme,
            key_pair=receiver_keys,
            sender_aid=receiver_aid,
            receiver_aid="alice@example.com:calendar_agent",
            token=token,
            message="please process this",
            now=now,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextIgnoringLocalAgent()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=gate,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            self.assertEqual(local_agent.side_effects, [])
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                rows[-1]["reason"],
                "local_agent_execution_context_unsupported",
            )
            self.assertEqual(
                rows[-1]["authorization_formula"],
                {
                    "saga_token_valid": True,
                    "request_envelope_valid": True,
                    "pq_signature_valid": True,
                    "can_accept": True,
                    "execution_scope_allowed": True,
                    "internal_policy_accept": False,
                },
            )

    def test_initiating_side_rejects_missing_response_signature(self) -> None:
        """Strict initiating-side response gate should reject unsigned responses."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=62)
        receiver_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {receiver_aid: receiver_keys.public_key},
            now_fn=lambda: now,
        )
        response_payload = {"msg": "unsigned", "token": token, "action_scope": "llm_prompt"}

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextTrackingLocalAgent()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=gate,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "missing_request_envelope")

    def test_initiating_side_rejects_tampered_response_message(self) -> None:
        """Changing response text after signing must fail before local execution."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=63)
        receiver_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {receiver_aid: receiver_keys.public_key},
            now_fn=lambda: now,
        )
        response_payload = self._signed_response_payload(
            scheme=scheme,
            key_pair=receiver_keys,
            sender_aid=receiver_aid,
            receiver_aid="alice@example.com:calendar_agent",
            token=token,
            message="original response",
            now=now,
        )
        response_payload["msg"] = "tampered response"

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextTrackingLocalAgent()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=gate,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "message_digest_mismatch")

    def test_initiating_side_rejects_untrusted_response_key(self) -> None:
        """A signed response from an untrusted key must not enter local execution."""
        token = "enc-token"
        receiver_aid = "bob@example.com:email_agent"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=64)
        receiver_keys = scheme.keygen()
        trusted_other_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {receiver_aid: trusted_other_keys.public_key},
            now_fn=lambda: now,
        )
        response_payload = self._signed_response_payload(
            scheme=scheme,
            key_pair=receiver_keys,
            sender_aid=receiver_aid,
            receiver_aid="alice@example.com:calendar_agent",
            token=token,
            message="wrong key",
            now=now,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            local_agent = self._ContextTrackingLocalAgent()
            agent, _sent_payloads = self._build_initiating_agent_for_response_gate(
                gate=gate,
                local_agent=local_agent,
                token=token,
                receiver_aid=receiver_aid,
                response_payload=response_payload,
                workdir=tmpdir,
            )

            ended_from_receiver = agent.initiate_conversation(
                self._SingleMessageConn(),
                token,
                receiver_aid,
                "hello",
            )

            self.assertFalse(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "signature_verification_failed")

    def test_execution_gate_accepts_valid_signed_message_and_runs_local_agent(self) -> None:
        """A valid signed request should enter local execution once and then finish."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=37)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=now,
        )
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

        agent = Agent.__new__(Agent)
        local_agent = self._FinishImmediatelyLocalAgent()
        sent_payloads: list[dict] = []
        agent.execution_gate = gate
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac="recipient-pac",
            )
        }
        agent.aid = receiver_aid
        agent.token_is_valid = lambda _token, _recipient_pac: True
        agent.recv = lambda _conn: message_dict
        agent.send = lambda _conn, payload: sent_payloads.append(payload)

        ended_from_receiver = agent.receive_conversation(
            self._SingleMessageConn(),
            token,
            recipient_pac=object(),
            sender_aid=sender_aid,
        )

        self.assertTrue(ended_from_receiver)
        self.assertEqual(local_agent.run_calls, 1)
        self.assertEqual(sent_payloads[0]["msg"], local_agent.task_finished_token)

    def test_receive_conversation_passes_local_execution_context_to_local_agent(self) -> None:
        """A prompt request with signed tool scope should propagate execution context."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=41)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:send_email"],
            message="hello",
            timestamp=now,
        )
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

        agent = Agent.__new__(Agent)
        local_agent = self._ContextTrackingLocalAgent()
        agent.execution_gate = gate
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac="recipient-pac",
            )
        }
        agent.aid = receiver_aid
        agent.token_is_valid = lambda _token, _recipient_pac: True
        agent.recv = lambda _conn: message_dict
        agent.send = lambda _conn, _payload: None

        ended_from_receiver = agent.receive_conversation(
            self._SingleMessageConn(),
            token,
            recipient_pac=object(),
            sender_aid=sender_aid,
        )

        self.assertTrue(ended_from_receiver)
        self.assertEqual(local_agent.run_calls, 1)
        self.assertEqual(len(local_agent.execution_contexts), 1)
        assert local_agent.execution_contexts[0] is not None
        self.assertTrue(local_agent.execution_contexts[0].authorize_action("tool_call:send_email"))
        self.assertFalse(
            local_agent.execution_contexts[0].authorize_action("tool_call:add_calendar_event")
        )

    def test_receive_conversation_rejects_context_ignoring_local_agent_before_run(self) -> None:
        """Strict request processing must fail closed if LocalAgent ignores context."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=67)
        sender_keys = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: sender_keys.public_key},
            now_fn=lambda: now,
        )
        message_dict = self._signed_prompt_payload(
            scheme=scheme,
            key_pair=sender_keys,
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            message="hello",
            now=now,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._ContextIgnoringLocalAgent()
            agent.execution_gate = gate
            agent.strict_execution_gate = True
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = receiver_aid
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid=sender_aid,
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            self.assertEqual(local_agent.side_effects, [])
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                rows[-1]["reason"],
                "local_agent_execution_context_unsupported",
            )
            self.assertEqual(
                rows[-1]["authorization_formula"],
                {
                    "saga_token_valid": True,
                    "request_envelope_valid": True,
                    "pq_signature_valid": True,
                    "can_accept": True,
                    "execution_scope_allowed": True,
                    "internal_policy_accept": False,
                },
            )

    def test_receive_conversation_rejects_tool_only_scope_before_prompt(self) -> None:
        """A tool-only envelope must not enter the LLM prompt surface."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=42)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="tool_call:send_email",
            message="send mail",
            timestamp=now,
        )
        message_dict = {
            "msg": "send mail",
            "token": token,
            "action_scope": "tool_call:send_email",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._ContextTrackingLocalAgent()
            agent.execution_gate = gate
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = receiver_aid
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid=sender_aid,
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "prompt_scope_not_authorized")
            self.assertEqual(rows[-1]["signed_action_scope"], "tool_call:send_email")
            self.assertEqual(
                rows[-1]["authorization_formula"],
                {
                    "saga_token_valid": True,
                    "request_envelope_valid": True,
                    "pq_signature_valid": True,
                    "can_accept": True,
                    "execution_scope_allowed": False,
                    "internal_policy_accept": False,
                },
            )

    def test_receive_conversation_audit_records_full_authorization_formula_on_signature_reject(self) -> None:
        """真实接收路径拒绝时应记录最终授权公式各项，便于 F3/F7 对齐。"""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=46)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=now,
        )
        tampered_signature = bytearray(scheme.sign(key_pair.secret_key, envelope.digest()))
        tampered_signature[0] ^= 1
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(bytes(tampered_signature)).decode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._ContextTrackingLocalAgent()
            agent.execution_gate = gate
            agent.strict_execution_gate = True
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = receiver_aid
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid=sender_aid,
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 0)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "signature_verification_failed")
            self.assertEqual(
                rows[-1]["authorization_formula"],
                {
                    "saga_token_valid": True,
                    "request_envelope_valid": True,
                    "pq_signature_valid": False,
                    "can_accept": False,
                    "execution_scope_allowed": True,
                    "internal_policy_accept": None,
                },
            )

    def test_receive_conversation_rejects_replayed_signed_envelope(self) -> None:
        """Reusing the exact same signed envelope must not execute twice."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=44)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            message="hello",
            timestamp=now,
        )
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._StructuredResponseLocalAgent()
            agent.execution_gate = gate
            agent.strict_execution_gate = True
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=2,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = receiver_aid
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: message_dict
            agent.send = lambda _conn, _payload: None

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid=sender_aid,
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 1)
            audit_path = Path(tmpdir) / "audit" / "execution_gate.jsonl"
            rows = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[-1]["reason"], "replayed_request_envelope")

    def test_receive_conversation_passes_explicit_tool_authorizations_to_local_agent(self) -> None:
        """A prompt request can carry signed tool scopes for downstream execution."""
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:calendar_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=43)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:get_free_time_slots", "tool_call:add_calendar_event"],
            message="hello",
            timestamp=now,
        )
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }

        agent = Agent.__new__(Agent)
        local_agent = self._ContextTrackingLocalAgent()
        agent.execution_gate = gate
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac="recipient-pac",
            )
        }
        agent.aid = receiver_aid
        agent.token_is_valid = lambda _token, _recipient_pac: True
        agent.recv = lambda _conn: message_dict
        agent.send = lambda _conn, _payload: None

        ended_from_receiver = agent.receive_conversation(
            self._SingleMessageConn(),
            token,
            recipient_pac=object(),
            sender_aid=sender_aid,
        )

        self.assertTrue(ended_from_receiver)
        self.assertEqual(local_agent.run_calls, 1)
        assert local_agent.execution_contexts[0] is not None
        self.assertTrue(local_agent.execution_contexts[0].authorize_action("llm_prompt"))
        self.assertTrue(local_agent.execution_contexts[0].authorize_tool_call("get_free_time_slots"))
        self.assertTrue(local_agent.execution_contexts[0].authorize_tool_call("add_calendar_event"))
        self.assertFalse(local_agent.execution_contexts[0].authorize_action("memory_write"))
        self.assertFalse(local_agent.execution_contexts[0].authorize_action("delegation"))

    def test_receive_conversation_serializes_structured_local_agent_response(self) -> None:
        """Structured model responses should be converted to signed transport text."""
        sender_aid = "alice@example.com:email_agent"
        receiver_aid = "bob@example.com:email_agent"
        token = "enc-token"
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        scheme = ToyLWESignatureScheme(seed=45)
        key_pair = scheme.keygen()
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: key_pair.public_key},
            now_fn=lambda: now,
        )
        envelope = build_request_envelope(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id="session-1",
            turn_id="turn-1",
            issued_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["tool_call:check_inbox"],
            message="hello",
            timestamp=now,
        )
        message_dict = {
            "msg": "hello",
            "token": token,
            "action_scope": "llm_prompt",
            "request_envelope": envelope.canonical_json(),
            "pq_signature": base64.b64encode(
                scheme.sign(key_pair.secret_key, envelope.digest())
            ).decode("utf-8"),
        }
        sent_payloads: list[dict] = []

        agent = Agent.__new__(Agent)
        local_agent = self._StructuredResponseLocalAgent()
        agent.execution_gate = gate
        agent.pq_signature_scheme = scheme
        agent.pq_secret_key = key_pair.secret_key
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac="recipient-pac",
            )
        }
        agent.aid = receiver_aid
        agent.provider_id = "https://provider.example.test"
        agent.token_is_valid = lambda _token, _recipient_pac: True
        agent.recv = lambda _conn: message_dict if not sent_payloads else {"msg": local_agent.task_finished_token, "token": token}
        agent.send = lambda _conn, payload: sent_payloads.append(payload)
        agent._conversation_authorized_scopes = lambda action_scope: (action_scope, "tool_call:check_inbox")

        ended_from_receiver = agent.receive_conversation(
            self._SingleMessageConn(),
            token,
            recipient_pac=object(),
            sender_aid=sender_aid,
        )

        self.assertFalse(ended_from_receiver)
        self.assertEqual(local_agent.run_calls, 1)
        self.assertEqual(sent_payloads[0]["msg"], '{"items": ["receipt"], "status": "ready"}')
        self.assertIn("request_envelope", sent_payloads[0])
        self.assertIn("pq_signature", sent_payloads[0])

    def test_receive_conversation_records_failed_local_agent_run(self) -> None:
        """A local-agent failure should be recorded instead of disappearing silently."""
        token = "enc-token"
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = Agent.__new__(Agent)
            local_agent = self._FailingLocalAgent()
            sent_payloads: list[dict] = []

            agent.execution_gate = None
            agent.local_agent = local_agent
            agent.task_finished_token = local_agent.task_finished_token
            agent.monitor = self._NoOpMonitor()
            agent.llm_monitor = self._NoOpMonitor()
            agent.active_tokens_lock = threading.Lock()
            agent.active_tokens = {
                token: _token_dict(
                    expires_in_seconds=60,
                    communication_quota=1,
                    recipient_pac="recipient-pac",
                )
            }
            agent.aid = "bob@example.com:calendar_agent"
            agent.workdir = tmpdir
            agent.token_is_valid = lambda _token, _recipient_pac: True
            agent.recv = lambda _conn: {"msg": "hello", "token": token}
            agent.send = lambda _conn, payload: sent_payloads.append(payload)

            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=object(),
                sender_aid="alice@example.com:calendar_agent",
            )

            self.assertTrue(ended_from_receiver)
            self.assertEqual(local_agent.run_calls, 1)
            self.assertEqual(sent_payloads, [])

            diagnostics_path = Path(tmpdir) / "diagnostics" / "local_agent_runs.jsonl"
            rows = [
                json.loads(line)
                for line in diagnostics_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([row["run_status"] for row in rows], ["started", "failed"])
            self.assertIn("RuntimeError: model call did not return", rows[-1]["error"])

    def test_concurrent_receive_conversation_consumes_active_token_quota_once(self) -> None:
        """并发 receiving-side 会话共用 quota=1 时只能有一个进入 local_agent.run。"""
        token = "enc-token"
        _recipient_private_key, recipient_public_key = sc.generate_x25519_keypair()
        recipient_pac_b64 = base64.b64encode(
            recipient_public_key.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw,
            )
        ).decode("utf-8")
        agent = Agent.__new__(Agent)
        local_agent = self._TrackingLocalAgent()
        barrier = threading.Barrier(3)
        results: list[bool] = []
        results_lock = threading.Lock()

        agent.execution_gate = None
        agent.local_agent = local_agent
        agent.task_finished_token = local_agent.task_finished_token
        agent.monitor = self._NoOpMonitor()
        agent.llm_monitor = self._NoOpMonitor()
        agent.active_tokens_lock = threading.Lock()
        agent.active_tokens = {
            token: _token_dict(
                expires_in_seconds=60,
                communication_quota=1,
                recipient_pac=recipient_pac_b64,
            )
        }
        agent.aid = "bob@example.com:calendar_agent"
        agent.recv = lambda _conn: {"msg": "hello", "token": token}
        agent.send = lambda _conn, _payload: None

        def receive_once() -> None:
            barrier.wait()
            ended_from_receiver = agent.receive_conversation(
                self._SingleMessageConn(),
                token,
                recipient_pac=recipient_public_key,
                sender_aid="alice@example.com:calendar_agent",
            )
            with results_lock:
                results.append(ended_from_receiver)

        threads = [threading.Thread(target=receive_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual(local_agent.run_calls, 1)
        self.assertNotIn(token, agent.active_tokens)
        self.assertEqual(len(results), 2)

    def test_bind_local_agent_runtime_hooks_installs_delegation_handler(self) -> None:
        """Agents should expose their real connect path through the wrapper delegation interface."""
        agent = Agent.__new__(Agent)
        local_agent = self._DelegationAwareLocalAgent()
        delegated_calls: list[tuple[str, str]] = []

        agent.local_agent = local_agent
        agent.connect = lambda target_aid, message: delegated_calls.append((target_aid, message))

        Agent._bind_local_agent_runtime_hooks(agent)
        self.assertIsNotNone(local_agent.delegation_handler)

        assert local_agent.delegation_handler is not None
        local_agent.delegation_handler("alice@example.com:calendar_agent", "hello")
        self.assertEqual(
            delegated_calls,
            [("alice@example.com:calendar_agent", "hello")],
        )

    def test_strict_execution_gate_syncs_local_agent_capability_mode(self) -> None:
        """Strict Agent mode should propagate to local capability facades."""
        agent = Agent.__new__(Agent)
        local_agent = self._StrictCapabilityAwareLocalAgent()

        agent.local_agent = local_agent
        agent.strict_execution_gate = True

        Agent._sync_local_agent_execution_capability_mode(agent)

        self.assertEqual(local_agent.strict_values, [True])

    def test_strict_local_agent_context_support_helper_rejects_default_custom_agent(self) -> None:
        """U5 helper should reject LocalAgent subclasses that do not opt into context support."""
        agent = Agent.__new__(Agent)
        agent.strict_execution_gate = True
        agent.local_agent = self._ContextIgnoringLocalAgent()
        base_decision = ExecutionGateDecision(
            True,
            "prompt_scope_authorized",
            protocol_allow=True,
            request_envelope_valid=True,
            pq_signature_valid=True,
            can_accept=True,
            execution_scope_allowed=True,
            internal_policy_accept=True,
        )

        decision = Agent._evaluate_local_agent_context_support(
            agent,
            base_decision,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "local_agent_execution_context_unsupported")
        self.assertFalse(decision.internal_policy_accept)
        self.assertTrue(decision.request_envelope_valid)
        self.assertTrue(decision.pq_signature_valid)
        self.assertTrue(decision.can_accept)
        self.assertTrue(decision.execution_scope_allowed)

    def test_conversation_authorized_scopes_treat_requested_scopes_as_proposals(self) -> None:
        """Requested scopes must not expand beyond local tool policy."""
        agent = Agent.__new__(Agent)
        agent.local_agent = type(
            "LocalAgentWithTools",
            (),
            {
                "tool_collections": (
                    type("Tool", (), {"name": "send_email"})(),
                )
            },
        )()

        scopes = Agent._conversation_authorized_scopes(
            agent,
            "llm_prompt",
            requested_scopes=(
                "tool_call:send_email",
                "tool_call:add_calendar_event",
                "memory_write",
                "delegation",
            ),
        )

        self.assertEqual(
            scopes,
            ("llm_prompt", "memory_read", "memory_write", "tool_call:send_email"),
        )

        decision = Agent._conversation_policy_decision(
            agent,
            "llm_prompt",
            requested_scopes=(
                "tool_call:send_email",
                "tool_call:add_calendar_event",
                "memory_write",
                "delegation",
            ),
        )

        self.assertEqual(decision.reason, "scope_escalation")
        self.assertEqual(
            decision.rejected_scopes,
            ("delegation", "tool_call:add_calendar_event"),
        )

    def test_conversation_policy_rejects_entry_scope_outside_local_policy(self) -> None:
        """入口 action 本身不在本地 policy 中时不能进入可签名授权集合。"""
        agent = Agent.__new__(Agent)
        agent.local_agent = type(
            "LocalAgentWithTools",
            (),
            {
                "tool_collections": (
                    type("Tool", (), {"name": "send_email"})(),
                )
            },
        )()

        decision = Agent._conversation_policy_decision(agent, "delegation")

        self.assertEqual(decision.reason, "policy_reject")
        self.assertEqual(
            decision.allowed_scopes,
            ("memory_read", "memory_write", "tool_call:send_email"),
        )
        self.assertEqual(decision.rejected_scopes, ("delegation",))
        with self.assertRaises(ExecutionAuthorizationError) as raised:
            Agent._conversation_authorized_scopes(agent, "delegation")
        self.assertEqual(raised.exception.reason, "policy_reject")

    def test_tool_entry_scope_does_not_implicitly_grant_prompt_surface(self) -> None:
        """工具入口信封不应默认携带 prompt scope。"""
        agent = Agent.__new__(Agent)
        agent.local_agent = type(
            "LocalAgentWithTools",
            (),
            {
                "tool_collections": (
                    type("Tool", (), {"name": "send_email"})(),
                )
            },
        )()

        scopes = Agent._conversation_authorized_scopes(agent, "tool_call:send_email")

        self.assertEqual(
            scopes,
            ("memory_read", "memory_write", "tool_call:send_email"),
        )
        self.assertNotIn("llm_prompt", scopes)

    def test_requested_scope_escalation_does_not_expand_signed_envelope(self) -> None:
        """确认 requested scopes 越权时不会扩大签名信封中的授权面。"""
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        token = "enc-token"
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        scheme = ToyLWESignatureScheme(seed=72)
        sender_keys = scheme.keygen()

        sender = Agent.__new__(Agent)
        sender.aid = sender_aid
        sender.provider_id = "https://provider.example.test"
        sender.pq_signature_scheme = scheme
        sender.pq_secret_key = sender_keys.secret_key
        sender.local_agent = type(
            "LocalAgentWithTools",
            (),
            {
                "tool_collections": (
                    type("Tool", (), {"name": "send_email"})(),
                )
            },
        )()

        policy_decision = Agent._conversation_policy_decision(
            sender,
            "llm_prompt",
            requested_scopes=(
                "tool_call:send_email",
                "tool_call:add_calendar_event",
                "delegation",
            ),
        )
        payload = sender._build_conversation_payload(
            receiver_aid=receiver_aid,
            token=token,
            message="please send this",
            action_scope="llm_prompt",
            turn_index=0,
            token_dict={
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
            authorized_scopes=policy_decision.allowed_scopes,
        )
        envelope = parse_request_envelope(payload["request_envelope"])

        self.assertEqual(policy_decision.reason, "scope_escalation")
        self.assertEqual(
            policy_decision.rejected_scopes,
            ("delegation", "tool_call:add_calendar_event"),
        )
        self.assertEqual(
            envelope.authorized_scopes,
            ("llm_prompt", "memory_read", "memory_write", "tool_call:send_email"),
        )
        self.assertNotIn("tool_call:add_calendar_event", envelope.authorized_scopes)
        self.assertNotIn("delegation", envelope.authorized_scopes)

        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: sender_keys.public_key},
            now_fn=lambda: now,
        )
        request = ExecutionGateRequest(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            message="please send this",
            action_scope="llm_prompt",
            request_envelope=payload["request_envelope"],
            pq_signature=payload["pq_signature"],
        )
        context = gate.build_local_execution_context(request)

        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(context.authorize_tool_call("send_email"))
        self.assertFalse(context.authorize_tool_call("add_calendar_event"))
        self.assertFalse(context.authorize_action("delegation"))

    def test_conversation_payload_binds_parent_capability_for_delegation_child(self) -> None:
        """Agent payload builder 应把委托父 capability 关系写入签名信封。"""
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        token = "enc-token"
        sender_aid = "alice@example.com:calendar_agent"
        receiver_aid = "bob@example.com:email_agent"
        scheme = ToyLWESignatureScheme(seed=73)
        sender_keys = scheme.keygen()
        parent = build_request_envelope(
            sender_aid="root@example.com:calendar_agent",
            receiver_aid=sender_aid,
            token="parent-token",
            session_id="session-parent",
            turn_id="turn-parent",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            action_scope="llm_prompt",
            authorized_scopes=["delegation", "tool_call:send_email"],
            message="parent",
            capability_id="cap-parent",
        )
        sender = Agent.__new__(Agent)
        sender.aid = sender_aid
        sender.provider_id = "https://provider.example.test"
        sender.pq_signature_scheme = scheme
        sender.pq_secret_key = sender_keys.secret_key

        payload = sender._build_conversation_payload(
            receiver_aid=receiver_aid,
            token=token,
            message="delegated child",
            action_scope="tool_call:send_email",
            turn_index=1,
            token_dict={
                "issue_timestamp": now.isoformat(),
                "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
            parent_envelope=parent,
        )
        envelope = parse_request_envelope(payload["request_envelope"])

        self.assertEqual(envelope.parent_envelope_digest, parent.hex_digest())
        self.assertEqual(envelope.parent_authorized_scopes, parent.authorized_scopes)
        self.assertEqual(envelope.delegation_depth, 1)
        gate = SignedRequestExecutionGate(
            CAN(CompiledToyLWEVerifier(scheme, message_bytes=32)),
            {sender_aid: sender_keys.public_key},
            now_fn=lambda: now,
            parent_capability_store={parent.hex_digest(): parent.authorized_scopes},
        )
        request = ExecutionGateRequest(
            sender_aid=sender_aid,
            receiver_aid=receiver_aid,
            token=token,
            message="delegated child",
            action_scope="tool_call:send_email",
            request_envelope=payload["request_envelope"],
            pq_signature=payload["pq_signature"],
        )

        self.assertTrue(gate.evaluate_request(request).allowed)


if __name__ == "__main__":
    unittest.main()
