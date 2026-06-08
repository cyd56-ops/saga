"""Integration tests for experiment entrypoints that consume PQ-CAN sample configs."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest import mock

import experiments.create_blogpost as create_blogpost
import experiments.expense_report as expense_report
import experiments.schedule_meeting as schedule_meeting
from saga.agent import Agent, enable_toy_lwe_runtime_auth_from_config
from saga.config import UserConfig, get_index_of_agent
from saga.execution_gate import ExecutionGateRequest


REPO_ROOT = Path(__file__).resolve().parents[2]
EMMA_CONFIG_PATH = str(REPO_ROOT / "user_configs" / "emma_pqcan.yaml")
RAJ_CONFIG_PATH = str(REPO_ROOT / "user_configs" / "raj_pqcan.yaml")


class _RecordingAgent:
    """Minimal agent double that records experiment entrypoint behavior."""

    instances: list["_RecordingAgent"] = []

    def __init__(self, workdir: str, material: dict, local_agent) -> None:
        self.workdir = workdir
        self.material = material
        self.local_agent = local_agent
        self.aid = material["aid"]
        self.provider_id = "https://provider.example.test"
        self.execution_gate = None
        self.pq_signature_scheme = None
        self.pq_public_key = None
        self.pq_secret_key = None
        self.connect_calls: list[tuple[str, str]] = []
        self.listen_calls = 0
        type(self).instances.append(self)

    def connect(self, r_aid: str, message: str) -> None:
        """Record the outbound peer AID and task message."""
        self.connect_calls.append((r_aid, message))

    def listen(self) -> None:
        """Record that the agent entered listen mode."""
        self.listen_calls += 1


class ExperimentRuntimeAuthEntrypointTests(unittest.TestCase):
    """Verify experiment entrypoints enable runtime auth from the sample YAML configs."""

    ENTRYPOINT_SPECS = (
        (
            schedule_meeting,
            "MeetingScheduleTest",
            "calendar_agent",
            "schedule_meeting.py",
        ),
        (
            expense_report,
            "ExpenseReportTest",
            "email_agent",
            "expense_report.py",
        ),
        (
            create_blogpost,
            "BlogPostTest",
            "writing_agent",
            "create_blogpost.py",
        ),
    )

    def setUp(self) -> None:
        """Reset the recording agent registry before each test."""
        _RecordingAgent.instances.clear()

    def _load_agent_config(self, config_path: str, agent_name: str):
        """Load a single agent config from a user config file."""
        config = UserConfig.load(config_path, drop_extra_fields=True)
        agent_index = get_index_of_agent(config, agent_name)
        assert agent_index is not None
        return config, config.agents[agent_index]

    def _make_runtime_agent(self, aid: str):
        """Create a minimal object compatible with runtime-auth helper wiring."""
        agent = Agent.__new__(Agent)
        agent.aid = aid
        agent.provider_id = "https://provider.example.test"
        agent.execution_gate = None
        agent.pq_signature_scheme = None
        agent.pq_public_key = None
        agent.pq_secret_key = None
        return agent

    def _assert_signed_request_round_trip(
        self,
        sender_agent,
        receiver_runtime_auth_config,
        receiver_aid: str,
    ) -> None:
        """Verify the sender can produce a request accepted by the configured receiver gate."""
        now = datetime(2026, 5, 11, 12, 0, 0, tzinfo=timezone.utc)
        receiver_agent = self._make_runtime_agent(receiver_aid)
        enable_toy_lwe_runtime_auth_from_config(
            receiver_agent,
            receiver_runtime_auth_config,
            now_fn=lambda: now,
        )

        token_dict = {
            "issue_timestamp": now.isoformat(),
            "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
        }
        payload = Agent._build_conversation_payload(
            sender_agent,
            receiver_aid=receiver_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            turn_index=0,
            token_dict=token_dict,
        )
        request = ExecutionGateRequest(
            sender_aid=sender_agent.aid,
            receiver_aid=receiver_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=payload["request_envelope"],
            pq_signature=payload["pq_signature"],
        )

        assert receiver_agent.execution_gate is not None
        self.assertTrue(receiver_agent.execution_gate.authorize(request))

    def _build_signed_request(
        self,
        sender_agent,
        receiver_aid: str,
    ) -> ExecutionGateRequest:
        """Build a deterministic signed request using the sender runtime-auth state."""
        now = datetime(2026, 5, 11, 12, 0, 0, tzinfo=timezone.utc)
        token_dict = {
            "issue_timestamp": now.isoformat(),
            "expiration_timestamp": (now + timedelta(minutes=5)).isoformat(),
        }
        payload = Agent._build_conversation_payload(
            sender_agent,
            receiver_aid=receiver_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            turn_index=0,
            token_dict=token_dict,
        )
        return ExecutionGateRequest(
            sender_aid=sender_agent.aid,
            receiver_aid=receiver_aid,
            token="enc-token",
            message="hello",
            action_scope="llm_prompt",
            request_envelope=payload.get("request_envelope"),
            pq_signature=payload.get("pq_signature"),
        )

    def test_query_mode_loads_sample_runtime_auth_and_targets_matching_peer(self) -> None:
        """Each experiment query path should wire runtime auth and connect to the matching peer AID."""
        for module, test_class_name, agent_name, label in self.ENTRYPOINT_SPECS:
            with self.subTest(entrypoint=label):
                sender_config, _ = self._load_agent_config(EMMA_CONFIG_PATH, agent_name)
                receiver_config, receiver_agent_config = self._load_agent_config(
                    RAJ_CONFIG_PATH,
                    agent_name,
                )
                sender_aid = f"{sender_config.email}:{agent_name}"
                receiver_aid = f"{receiver_config.email}:{agent_name}"

                with mock.patch.object(module, "Agent", new=_RecordingAgent), mock.patch.object(
                    module,
                    "get_agent",
                    return_value=object(),
                ), mock.patch.object(
                    module,
                    "get_agent_material",
                    return_value={"aid": sender_aid},
                ), mock.patch.object(
                    module,
                    "load_execution_gate_audit_records",
                    return_value=[{"allowed": False, "reason": "signature_verification_failed"}],
                ), mock.patch.object(
                    module,
                    "collect_query_execution_stats",
                    return_value=(
                        [{"allowed": False, "reason": "signature_verification_failed"}],
                        {
                            "task_latency_seconds": 1.25,
                            "model_call_count": 2,
                            "api_cost_available": False,
                            "api_cost_usd": None,
                            "audit_record_count": 1,
                            "audit_logging_overhead_record_count": 1,
                        },
                    ),
                ), mock.patch.object(
                    module,
                    "append_experiment_result_record",
                ) as append_result_mock, mock.patch.object(
                    getattr(module, test_class_name),
                    "success",
                    return_value=True,
                ):
                    module.main("query", EMMA_CONFIG_PATH, RAJ_CONFIG_PATH)

                self.assertEqual(len(_RecordingAgent.instances), 1)
                sender_agent = _RecordingAgent.instances.pop()
                self.assertEqual(sender_agent.aid, sender_aid)
                self.assertIsNotNone(sender_agent.execution_gate)
                self.assertIsNotNone(sender_agent.pq_signature_scheme)
                self.assertIsNotNone(sender_agent.pq_public_key)
                self.assertIsNotNone(sender_agent.pq_secret_key)
                self.assertEqual(len(sender_agent.connect_calls), 1)
                self.assertEqual(sender_agent.connect_calls[0][0], receiver_aid)
                self._assert_signed_request_round_trip(
                    sender_agent,
                    receiver_agent_config.toy_runtime_auth,
                    receiver_aid,
                )
                append_result_mock.assert_called_once()
                result_record = append_result_mock.call_args.args[1]
                self.assertEqual(result_record["task_name"], label.replace(".py", ""))
                self.assertEqual(result_record["mode"], "query")
                self.assertEqual(result_record["agent_aid"], sender_aid)
                self.assertEqual(result_record["peer_aid"], receiver_aid)
                self.assertTrue(result_record["runtime_auth_enabled"])
                self.assertTrue(result_record["success"])
                self.assertEqual(result_record["audit_reject_count"], 1)
                self.assertEqual(result_record["task_latency_seconds"], 1.25)
                self.assertEqual(result_record["model_call_count"], 2)
                self.assertFalse(result_record["api_cost_available"])
                self.assertIsNone(result_record["api_cost_usd"])
                self.assertEqual(result_record["audit_logging_overhead_record_count"], 1)

    def test_query_mode_rejects_missing_signature_material(self) -> None:
        """Receiver gates should fail closed when a query-path request omits PQ signature fields."""
        for module, test_class_name, agent_name, label in self.ENTRYPOINT_SPECS:
            with self.subTest(entrypoint=label):
                sender_config, _ = self._load_agent_config(EMMA_CONFIG_PATH, agent_name)
                receiver_config, receiver_agent_config = self._load_agent_config(
                    RAJ_CONFIG_PATH,
                    agent_name,
                )
                sender_aid = f"{sender_config.email}:{agent_name}"
                receiver_aid = f"{receiver_config.email}:{agent_name}"

                with mock.patch.object(module, "Agent", new=_RecordingAgent), mock.patch.object(
                    module,
                    "get_agent",
                    return_value=object(),
                ), mock.patch.object(
                    module,
                    "get_agent_material",
                    return_value={"aid": sender_aid},
                ), mock.patch.object(
                    module,
                    "load_execution_gate_audit_records",
                    return_value=[],
                ), mock.patch.object(
                    module,
                    "collect_query_execution_stats",
                    return_value=([], {"task_latency_seconds": 1.0, "model_call_count": 1}),
                ), mock.patch.object(
                    module,
                    "append_experiment_result_record",
                ), mock.patch.object(
                    getattr(module, test_class_name),
                    "success",
                    return_value=True,
                ):
                    module.main("query", EMMA_CONFIG_PATH, RAJ_CONFIG_PATH)

                sender_agent = _RecordingAgent.instances.pop()
                receiver_agent = self._make_runtime_agent(receiver_aid)
                enable_toy_lwe_runtime_auth_from_config(receiver_agent, receiver_agent_config.toy_runtime_auth)

                request = self._build_signed_request(sender_agent, receiver_aid)
                request = ExecutionGateRequest(
                    sender_aid=request.sender_aid,
                    receiver_aid=request.receiver_aid,
                    token=request.token,
                    message=request.message,
                    action_scope=request.action_scope,
                    request_envelope=None,
                    pq_signature=None,
                )

                assert receiver_agent.execution_gate is not None
                self.assertFalse(receiver_agent.execution_gate.authorize(request))

    def test_query_mode_rejects_trusted_key_mismatch(self) -> None:
        """Receiver gates should reject when sample config trust is replaced with a wrong key."""
        for module, test_class_name, agent_name, label in self.ENTRYPOINT_SPECS:
            with self.subTest(entrypoint=label):
                sender_config, _ = self._load_agent_config(EMMA_CONFIG_PATH, agent_name)
                receiver_config, receiver_agent_config = self._load_agent_config(
                    RAJ_CONFIG_PATH,
                    agent_name,
                )
                sender_aid = f"{sender_config.email}:{agent_name}"
                receiver_aid = f"{receiver_config.email}:{agent_name}"

                with mock.patch.object(module, "Agent", new=_RecordingAgent), mock.patch.object(
                    module,
                    "get_agent",
                    return_value=object(),
                ), mock.patch.object(
                    module,
                    "get_agent_material",
                    return_value={"aid": sender_aid},
                ), mock.patch.object(
                    module,
                    "load_execution_gate_audit_records",
                    return_value=[],
                ), mock.patch.object(
                    module,
                    "collect_query_execution_stats",
                    return_value=([], {"task_latency_seconds": 1.0, "model_call_count": 1}),
                ), mock.patch.object(
                    module,
                    "append_experiment_result_record",
                ), mock.patch.object(
                    getattr(module, test_class_name),
                    "success",
                    return_value=True,
                ):
                    module.main("query", EMMA_CONFIG_PATH, RAJ_CONFIG_PATH)

                sender_agent = _RecordingAgent.instances.pop()
                mismatched_runtime_auth = replace(
                    receiver_agent_config.toy_runtime_auth,
                    trusted_public_keys={sender_aid: "AAAAAAAAAAAAAAAAAAAAAA=="},
                )
                receiver_agent = self._make_runtime_agent(receiver_aid)
                enable_toy_lwe_runtime_auth_from_config(receiver_agent, mismatched_runtime_auth)
                request = self._build_signed_request(sender_agent, receiver_aid)

                assert receiver_agent.execution_gate is not None
                self.assertFalse(receiver_agent.execution_gate.authorize(request))

    def test_listen_mode_loads_sample_runtime_auth_before_entering_loop(self) -> None:
        """Each experiment listen path should attach runtime auth before entering listen mode."""
        for module, _test_class_name, agent_name, label in self.ENTRYPOINT_SPECS:
            with self.subTest(entrypoint=label):
                sender_config, _ = self._load_agent_config(EMMA_CONFIG_PATH, agent_name)
                sender_aid = f"{sender_config.email}:{agent_name}"

                with mock.patch.object(module, "Agent", new=_RecordingAgent), mock.patch.object(
                    module,
                    "get_agent",
                    return_value=object(),
                ), mock.patch.object(
                    module,
                    "get_agent_material",
                    return_value={"aid": sender_aid},
                ), mock.patch.object(
                    module,
                    "load_execution_gate_audit_records",
                    return_value=[],
                ), mock.patch.object(
                    module,
                    "append_experiment_result_record",
                ) as append_result_mock:
                    module.main("listen", EMMA_CONFIG_PATH)

                self.assertEqual(len(_RecordingAgent.instances), 1)
                sender_agent = _RecordingAgent.instances.pop()
                self.assertEqual(sender_agent.aid, sender_aid)
                self.assertIsNotNone(sender_agent.execution_gate)
                self.assertIsNotNone(sender_agent.pq_signature_scheme)
                self.assertEqual(sender_agent.listen_calls, 1)
                self.assertEqual(sender_agent.connect_calls, [])
                append_result_mock.assert_called_once()
                result_record = append_result_mock.call_args.args[1]
                self.assertEqual(result_record["task_name"], label.replace(".py", ""))
                self.assertEqual(result_record["mode"], "listen")
                self.assertEqual(result_record["agent_aid"], sender_aid)
                self.assertIsNone(result_record["peer_aid"])
                self.assertIsNone(result_record["success"])


if __name__ == "__main__":
    unittest.main()
