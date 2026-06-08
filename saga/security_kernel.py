"""Security runtime kernel inventory for SAGA-PQ-CAN."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


KernelEntryStatus = Literal["covered", "compat_excluded", "planned_hardening"]


@dataclass(frozen=True)
class SecurityKernelEntry:
    """记录一个执行入口在安全内核中的边界、证据和剩余风险。"""

    entry_id: str
    surface: str
    in_security_kernel: bool
    status: KernelEntryStatus
    code_paths: tuple[str, ...]
    gate_mechanism: str
    evidence_tests: tuple[str, ...]
    residual_risk: str


@dataclass(frozen=True)
class ProtectedSinkAudit:
    """记录一个受保护副作用点及其必须满足的 gate 谓词。"""

    sink_id: str
    surface: str
    side_effect: str
    allowed_call_path: tuple[str, ...]
    required_predicate: str
    evidence_tests: tuple[str, ...]
    residual_risk: str
    static_drift_checks: tuple[str, ...]


@dataclass(frozen=True)
class NoSideEffectOracle:
    """记录一个 protected sink 被拒绝时如何证明没有触发副作用。"""

    oracle_id: str
    sink_id: str
    rejected_condition: str
    expected_observation: str
    evidence_tests: tuple[str, ...]
    evidence_artifacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class MutationEvidence:
    """记录一个 gate 关键检查被移除时应失败的测试证据。"""

    mutation_id: str
    sink_ids: tuple[str, ...]
    mutated_control: str
    expected_test_failures: tuple[str, ...]
    protected_property: str
    notes: str = ""


@dataclass(frozen=True)
class ModelRefinementMapping:
    """记录 P5 抽象模型项到 Python 实现和证据测试的细化对应关系。"""

    mapping_id: str
    model_term: str
    abstract_predicate: str
    python_symbols: tuple[str, ...]
    evidence_tests: tuple[str, ...]
    tcb_assumptions: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    residual_risk: str
    linked_sink_ids: tuple[str, ...] = ()


EXECUTE_SURFACE_CLAIM = (
    "Execute(surface) => N_verify=1 AND scope_ok AND replay_ok "
    "AND delegation_ok AND policy_ok"
)
"""严格 runtime-auth kernel 中 protected sink 的论文级安全命题。"""


SECURITY_KERNEL_ENTRIES: tuple[SecurityKernelEntry, ...] = (
    SecurityKernelEntry(
        entry_id="receiving_prompt_request",
        surface="llm_prompt",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "saga.agent.Agent.receive_conversation",
            "saga.agent.Agent._evaluate_execution_request",
            "saga.agent.Agent._evaluate_prompt_surface_request",
            "saga.agent.Agent._run_local_agent_with_diagnostics",
        ),
        gate_mechanism=(
            "SAGA active-token consume, signed request envelope consume, "
            "PQ/CAN verification, and LocalExecutionContext llm_prompt check"
        ),
        evidence_tests=(
            "tests/integration/test_baseline_agent_flow.py",
            "tests/test_negative_injection_runner.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Only the strict runtime-auth path is claimed; compatibility mode without "
            "an execution gate is explicitly excluded."
        ),
    ),
    SecurityKernelEntry(
        entry_id="initiating_response_prompt",
        surface="response_side_llm_prompt",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "saga.agent.Agent.initiate_conversation",
            "saga.agent.Agent._evaluate_execution_request",
            "saga.agent.Agent._evaluate_prompt_surface_request",
            "saga.agent.Agent._run_local_agent_with_diagnostics",
        ),
        gate_mechanism=(
            "Inbound peer response must verify a response envelope, consume replay "
            "state, and authorize llm_prompt before initiating-side local execution"
        ),
        evidence_tests=("tests/integration/test_baseline_agent_flow.py",),
        residual_risk=(
            "The claim covers signed response processing in Agent.initiate_conversation, "
            "not arbitrary local-agent calls made outside the SAGA Agent wrapper."
        ),
    ),
    SecurityKernelEntry(
        entry_id="wrapped_tool_call",
        surface="tool_call:<tool_name>",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "agent_backend.base.AgentWrapper._collect_tools_for_use",
            "agent_backend.base.AgentWrapper._wrap_tool_with_execution_gate",
            "agent_backend.base.AgentWrapper._gated_tool_resource",
            "saga.execution_gate.GatedExecutionResource",
            "saga.execution_gate.ExecutionCapabilityFacade.call_any_action",
            "saga.execution_gate.LocalExecutionContext.require_action",
        ),
        gate_mechanism=(
            "Configured business tools are wrapped so each forward call requires "
            "the matching signed tool_call:<tool_name> scope; backend resources are "
            "also exposed through a gated facade before direct method access"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/integration/test_baseline_agent_flow.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Only backend clients exposed through AgentWrapper._gated_tool_resource are "
            "claimed; custom code that stores raw backend clients outside this facade is excluded."
        ),
    ),
    SecurityKernelEntry(
        entry_id="agent_memory_read",
        surface="memory_read",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "agent_backend.base.AgentWrapper._read_agent_memory_steps",
            "saga.execution_gate.ExecutionCapabilityFacade.read_memory_steps",
            "saga.execution_gate.LocalExecutionContext.require_memory_read",
        ),
        gate_mechanism=(
            "Memory reads through the wrapper helper and capability facade require signed "
            "memory_read scope"
        ),
        evidence_tests=("tests/test_agent_wrapper_gate.py", "tests/test_execution_gate.py"),
        residual_risk=(
            "Direct access to a downstream library memory object is covered only when callers "
            "use the AgentWrapper capability facade; raw object mutation outside the facade is excluded."
        ),
    ),
    SecurityKernelEntry(
        entry_id="agent_memory_write",
        surface="memory_write",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "agent_backend.base.AgentWrapper._append_agent_memory_step",
            "saga.execution_gate.ExecutionCapabilityFacade.append_memory_step",
            "saga.execution_gate.LocalExecutionContext.require_memory_write",
        ),
        gate_mechanism=(
            "Memory writes through the wrapper helper and capability facade require signed "
            "memory_write scope"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/test_execution_gate.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Raw downstream memory-list mutation outside the capability facade is excluded "
            "from the strict runtime-kernel claim."
        ),
    ),
    SecurityKernelEntry(
        entry_id="delegation_interface",
        surface="delegation",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "agent_backend.base.AgentWrapper.delegate_to_agent",
            "saga.execution_gate.ExecutionCapabilityFacade.delegate",
            "agent_backend.base.AgentWrapper._require_delegation_permission",
            "saga.agent.Agent._delegate_to_agent",
        ),
        gate_mechanism=(
            "Delegation through the first-class wrapper API and capability facade requires "
            "signed delegation scope"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/test_execution_gate.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Only the explicit delegation helper/facade is in scope; ad hoc calls to "
            "Agent.connect outside the capability path are not claimed as delegated execution."
        ),
    ),
    SecurityKernelEntry(
        entry_id="missing_execution_gate_strict_mode",
        surface="legacy_fallback:no_execution_gate",
        in_security_kernel=False,
        status="compat_excluded",
        code_paths=("saga.agent.Agent._evaluate_execution_request",),
        gate_mechanism=(
            "Strict mode rejects with missing_execution_gate; non-strict compatibility "
            "mode can still return no_execution_gate and is excluded on receiving "
            "and initiating response paths"
        ),
        evidence_tests=(
            "tests/integration/test_baseline_agent_flow.py",
            "tests/test_agent_runtime_auth.py",
        ),
        residual_risk=(
            "Non-strict compatibility mode exists for baseline reproduction and must "
            "not be used as evidence for PQ-CAN security claims."
        ),
    ),
    SecurityKernelEntry(
        entry_id="missing_local_execution_context_strict_mode",
        surface="legacy_fallback:legacy_prompt_without_execution_context",
        in_security_kernel=False,
        status="compat_excluded",
        code_paths=("saga.agent.Agent._evaluate_prompt_surface_request",),
        gate_mechanism=(
            "Strict mode rejects with missing_local_execution_context; non-strict "
            "compatibility mode can still allow legacy_prompt_without_execution_context "
            "on receiving and initiating response paths"
        ),
        evidence_tests=("tests/integration/test_baseline_agent_flow.py",),
        residual_risk=(
            "Prompt execution without LocalExecutionContext is excluded from the "
            "security runtime kernel."
        ),
    ),
    SecurityKernelEntry(
        entry_id="custom_local_agent_context_ignored",
        surface="custom_local_agent",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "saga.local_agent.LocalAgent.supports_execution_context",
            "saga.agent.Agent._evaluate_local_agent_context_support",
            "saga.agent.Agent._run_local_agent_with_diagnostics",
        ),
        gate_mechanism=(
            "Strict mode requires the local agent to declare supports_execution_context() "
            "before local_agent.run(); context-ignoring custom LocalAgent implementations "
            "reject as local_agent_execution_context_unsupported"
        ),
        evidence_tests=(
            "tests/integration/test_baseline_agent_flow.py",
            "tests/test_agent_wrapper_gate.py",
        ),
        residual_risk=(
            "The fail-closed claim applies to strict runtime-auth paths. Non-strict "
            "compatibility mode still permits local agents without this declaration and "
            "is excluded from PQ-CAN security claims."
        ),
    ),
    SecurityKernelEntry(
        entry_id="persistent_replay_state",
        surface="request_envelope_replay",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "saga.agent.enable_toy_lwe_runtime_auth",
            "saga.agent.enable_toy_lwe_runtime_auth_from_config",
            "saga.execution_gate.SignedRequestExecutionGate.consume_request",
            "saga.execution_gate.FileReplayStateStore",
            "saga.execution_gate.SQLiteReplayStateStore",
            "saga.execution_gate.RedisReplayStateStore",
        ),
        gate_mechanism=(
            "Strict runtime-auth helper requires persistent replay state through "
            "the agent workdir marker store or an injected ReplayStateStore; "
            "consume_request reserves request ids under a per-gate lock and "
            "rejects duplicate envelopes as replayed_request_envelope"
        ),
        evidence_tests=(
            "tests/test_agent_runtime_auth.py",
            "tests/test_execution_gate.py",
            "tests/test_execution_gate_factory.py",
        ),
        residual_risk=(
            "File markers are local/dev/test evidence only. Multi-host production "
            "claims require an externally managed strongly consistent store such "
            "as Redis/PostgreSQL with equivalent atomic reserve semantics."
        ),
    ),
    SecurityKernelEntry(
        entry_id="signed_intent_capability_envelope",
        surface="intent_capability_envelope",
        in_security_kernel=True,
        status="covered",
        code_paths=(
            "saga.messages.RequestEnvelope",
            "saga.messages.build_request_envelope",
            "saga.execution_gate.SignedRequestExecutionGate._evaluate_delegation_capability",
            "saga.agent.Agent._build_conversation_payload",
        ),
        gate_mechanism=(
            "Signed envelopes include capability_id, parent_envelope_digest, "
            "parent_authorized_scopes, delegation_depth, and max_delegation_depth; "
            "delegated child capabilities require a known parent digest and cannot "
            "expand parent scopes"
        ),
        evidence_tests=(
            "tests/test_encoding.py",
            "tests/test_execution_gate.py",
            "tests/integration/test_baseline_agent_flow.py",
        ),
        residual_risk=(
            "This phase proves the signed capability envelope and gate contract. "
            "Full automatic delegation-chain storage across live multi-agent "
            "sessions remains future wiring and must use the same parent digest "
            "fact source."
        ),
    ),
    SecurityKernelEntry(
        entry_id="attack_model_and_experiment_clones",
        surface="legacy_reproduction_paths",
        in_security_kernel=False,
        status="compat_excluded",
        code_paths=("saga/attack_models/", "experiments/"),
        gate_mechanism=(
            "These paths are evidence harnesses or historical reproductions unless "
            "they explicitly opt into runtime auth"
        ),
        evidence_tests=("tests/test_security_kernel.py",),
        residual_risk=(
            "Do not generalize PQ-CAN security claims to copied attack-model Agent "
            "implementations or experiment stubs that bypass the active Agent runtime."
        ),
    ),
)


PROTECTED_SINK_AUDITS: tuple[ProtectedSinkAudit, ...] = (
    ProtectedSinkAudit(
        sink_id="prompt_local_agent_run",
        surface="llm_prompt",
        side_effect=(
            "local_agent.run() may issue model calls, update agent memory, and "
            "drive follow-on tool or delegation behavior"
        ),
        allowed_call_path=(
            "saga.agent.Agent.receive_conversation",
            "saga.agent.Agent.initiate_conversation",
            "saga.agent.Agent._evaluate_execution_request(consume=True)",
            "saga.execution_gate.SignedRequestExecutionGate.consume_request",
            "saga.agent.Agent._build_local_execution_context",
            "saga.agent.Agent._evaluate_prompt_surface_request",
            "saga.agent.Agent._evaluate_local_agent_context_support",
            "saga.agent.Agent._run_local_agent_with_diagnostics",
            "saga.local_agent.LocalAgent.run",
        ),
        required_predicate=(
            "N_verify=1, signed authorized_scopes allow llm_prompt, replay reserve "
            "succeeds, delegated child envelope is parent-bound when present, and "
            "the local agent declares execution-context support in strict mode"
        ),
        evidence_tests=(
            "tests/integration/test_baseline_agent_flow.py",
            "tests/test_agent_runtime_auth.py",
            "tests/test_negative_injection_runner.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Only prompt execution through the active Agent wrapper is claimed; "
            "legacy attack-model copies and compatibility local-agent calls outside "
            "strict runtime auth are excluded."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_local_agent_run_call_sites_remain_prompt_gated",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="smolagents_tool_forward",
        surface="tool_call:<tool_name>",
        side_effect="Configured smolagents tool forward(...) executes business logic.",
        allowed_call_path=(
            "agent_backend.base.AgentWrapper._collect_tools_for_use",
            "agent_backend.base.AgentWrapper._wrap_tool_with_execution_gate",
            "saga.execution_gate.ExecutionCapabilityFacade.require_action",
            "saga.execution_gate.LocalExecutionContext.require_action",
            "tool.forward",
        ),
        required_predicate=(
            "A gate-accepted LocalExecutionContext exists and its signed "
            "authorized_scopes include the concrete tool_call:<tool_name> scope"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Only configured tools collected by AgentWrapper are covered. Tools "
            "created and called outside this wrapper are not in the strict kernel."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_business_tool_backends_remain_gated_resources",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="business_backend_method",
        surface="tool_backend_method",
        side_effect=(
            "Email, calendar, and document backend methods can send mail, create "
            "calendar events, create documents, or read private task data."
        ),
        allowed_call_path=(
            "agent_backend.base.AgentWrapper._gated_tool_resource",
            "saga.execution_gate.GatedExecutionResource.__getattr__",
            "saga.execution_gate.ExecutionCapabilityFacade.call_any_action",
            "saga.execution_gate.LocalExecutionContext.require_action",
            "agent_backend.tools.*",
        ),
        required_predicate=(
            "The backend object is reachable only through GatedExecutionResource, "
            "and each protected method maps to a signed tool capability scope"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/integration/test_baseline_agent_flow.py",
        ),
        residual_risk=(
            "Raw backend clients stored outside AgentWrapper._gated_tool_resource "
            "remain outside the current security claim."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_business_tool_backends_remain_gated_resources",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="memory_read_facade",
        surface="memory_read",
        side_effect="Local agent memory contents are exposed to the runtime caller.",
        allowed_call_path=(
            "agent_backend.base.AgentWrapper._read_agent_memory_steps",
            "saga.execution_gate.ExecutionCapabilityFacade.read_memory_steps",
            "saga.execution_gate.LocalExecutionContext.require_memory_read",
        ),
        required_predicate=(
            "A gate-accepted LocalExecutionContext exists and its signed scopes "
            "authorize memory_read"
        ),
        evidence_tests=("tests/test_agent_wrapper_gate.py", "tests/test_execution_gate.py"),
        residual_risk=(
            "Diagnostic memory summaries are observational evidence, not an "
            "authorization grant. Raw downstream memory-object access outside the "
            "facade is excluded."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_raw_memory_mutation_remains_inside_capability_facade",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="memory_write_facade",
        surface="memory_write",
        side_effect="Local agent memory is mutated by appending a new step.",
        allowed_call_path=(
            "agent_backend.base.AgentWrapper._append_agent_memory_step",
            "saga.execution_gate.ExecutionCapabilityFacade.append_memory_step",
            "saga.execution_gate.LocalExecutionContext.require_memory_write",
        ),
        required_predicate=(
            "A gate-accepted LocalExecutionContext exists and its signed scopes "
            "authorize memory_write before the append happens"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/test_execution_gate.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Raw memory list mutation outside ExecutionCapabilityFacade remains "
            "outside the strict kernel claim."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_raw_memory_mutation_remains_inside_capability_facade",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="delegation_handler",
        surface="delegation",
        side_effect="A task is delegated to another SAGA agent through Agent.connect().",
        allowed_call_path=(
            "agent_backend.base.AgentWrapper.delegate_to_agent",
            "saga.execution_gate.ExecutionCapabilityFacade.delegate",
            "saga.execution_gate.LocalExecutionContext.require_delegation",
            "saga.agent.Agent._delegate_to_agent",
            "saga.agent.Agent.connect",
        ),
        required_predicate=(
            "A gate-accepted LocalExecutionContext exists, signed scopes authorize "
            "delegation, and delegated child envelopes must satisfy parent digest, "
            "scope attenuation, and depth checks"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py",
            "tests/test_execution_gate.py",
            "tests/test_real_negative_runner.py",
        ),
        residual_risk=(
            "Ad hoc Agent.connect calls in experiment scripts are reproduction "
            "drivers, not protected delegated execution in the strict kernel."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_direct_delegation_connect_calls_remain_excluded_or_gated",
        ),
    ),
    ProtectedSinkAudit(
        sink_id="replay_reserve_consume",
        surface="request_envelope_replay",
        side_effect=(
            "The request envelope digest is consumed in replay state, allowing at "
            "most one execution attempt for that signed capability."
        ),
        allowed_call_path=(
            "saga.agent.Agent._evaluate_execution_request(consume=True)",
            "saga.execution_gate.SignedRequestExecutionGate.consume_request",
            "saga.execution_gate.SignedRequestExecutionGate.evaluate_request",
            "saga.execution_gate.ReplayStateStore.reserve_request",
        ),
        required_predicate=(
            "The envelope is context-bound, N_verify=1, execution scope is allowed, "
            "delegation checks pass when applicable, and replay reservation returns reserved"
        ),
        evidence_tests=(
            "tests/test_execution_gate.py",
            "tests/test_execution_gate_factory.py",
            "tests/test_agent_runtime_auth.py",
        ),
        residual_risk=(
            "File marker replay state is local/dev evidence. Distributed production "
            "claims require an injected strongly consistent backend."
        ),
        static_drift_checks=(
            "tests/test_security_kernel.py::test_replay_consume_and_reserve_calls_remain_gate_mediated",
        ),
    ),
)


NO_SIDE_EFFECT_ORACLES: tuple[NoSideEffectOracle, ...] = (
    NoSideEffectOracle(
        oracle_id="prompt_reject_keeps_local_agent_run_count_zero",
        sink_id="prompt_local_agent_run",
        rejected_condition=(
            "missing execution gate, missing LocalExecutionContext, tool-only "
            "prompt scope, replayed envelope, or context-ignoring LocalAgent"
        ),
        expected_observation=(
            "local_agent.run is not called; run_calls/local_agent_run_count stays 0 "
            "and side_effects remains empty"
        ),
        evidence_tests=(
            "tests/integration/test_baseline_agent_flow.py::test_execution_gate_can_block_local_agent_run",
            "tests/integration/test_baseline_agent_flow.py::test_receive_conversation_rejects_tool_only_scope_before_prompt",
            "tests/integration/test_baseline_agent_flow.py::test_receive_conversation_rejects_replayed_signed_envelope",
            "tests/test_negative_injection_runner.py::test_runner_covers_real_agent_runtime_negative_paths",
            "tests/test_real_negative_runner.py::test_scope_probe_query_uses_local_denied_reason_and_protected_side_effects",
        ),
        evidence_artifacts=(
            "experiments/negative_injection_runner.py",
            "experiments/real_negative_runner.py",
        ),
    ),
    NoSideEffectOracle(
        oracle_id="tool_forward_rejects_before_original_forward",
        sink_id="smolagents_tool_forward",
        rejected_condition="signed scopes do not include the concrete tool_call:<tool_name>",
        expected_observation=(
            "wrapped tool raises tool_not_authorized before original forward executes"
        ),
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py::test_tool_call_is_rejected_when_scope_mismatches",
            "tests/test_agent_wrapper_gate.py::test_tool_call_rejection_exposes_stable_reason",
            "tests/test_negative_injection_runner.py::test_runner_records_execution_surface_rejections_without_side_effects",
        ),
    ),
    NoSideEffectOracle(
        oracle_id="backend_method_rejects_before_raw_client_call",
        sink_id="business_backend_method",
        rejected_condition="raw business backend method is reached without a matching tool scope",
        expected_observation="backend.calls stays empty and protected action is not recorded",
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py::test_direct_tool_backend_proxy_rejects_without_scope",
            "tests/test_agent_wrapper_gate.py::test_direct_tool_backend_proxy_rejects_missing_context_in_strict_mode",
            "tests/test_real_negative_runner.py::test_scope_probe_query_uses_local_denied_reason_and_protected_side_effects",
        ),
        evidence_artifacts=("experiments/real_negative_runner.py",),
    ),
    NoSideEffectOracle(
        oracle_id="memory_read_requires_scope_before_snapshot",
        sink_id="memory_read_facade",
        rejected_condition="memory_read is missing from the signed authorized scopes",
        expected_observation=(
            "read_memory_steps raises unauthorized_memory_read before returning a memory snapshot"
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_local_execution_context_exposes_memory_and_delegation_helpers",
            "tests/test_agent_wrapper_gate.py::test_memory_read_helper_requires_matching_scope",
            "tests/test_agent_wrapper_gate.py::test_memory_read_helper_rejects_without_scope",
        ),
    ),
    NoSideEffectOracle(
        oracle_id="memory_write_rejects_before_append",
        sink_id="memory_write_facade",
        rejected_condition="memory_write is missing from the signed authorized scopes",
        expected_observation="memory.steps stays unchanged and no protected memory record is written",
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py::test_memory_write_helper_rejects_without_scope",
            "tests/test_agent_wrapper_gate.py::test_direct_memory_facade_write_rejects_without_scope",
            "tests/test_negative_injection_runner.py::test_runner_records_execution_surface_rejections_without_side_effects",
            "tests/test_real_negative_runner.py::test_scope_probe_query_uses_local_denied_reason_and_protected_side_effects",
        ),
        evidence_artifacts=("experiments/real_negative_runner.py",),
    ),
    NoSideEffectOracle(
        oracle_id="delegation_rejects_before_handler",
        sink_id="delegation_handler",
        rejected_condition="delegation is missing from the signed authorized scopes",
        expected_observation="delegated calls list stays empty and Agent.connect is not invoked",
        evidence_tests=(
            "tests/test_agent_wrapper_gate.py::test_delegation_helper_rejects_without_scope",
            "tests/test_agent_wrapper_gate.py::test_direct_delegation_facade_rejects_without_scope",
            "tests/test_negative_injection_runner.py::test_runner_records_execution_surface_rejections_without_side_effects",
            "tests/test_real_negative_runner.py::test_scope_probe_query_uses_local_denied_reason_and_protected_side_effects",
        ),
        evidence_artifacts=("experiments/real_negative_runner.py",),
    ),
    NoSideEffectOracle(
        oracle_id="replay_rejects_second_execution_attempt",
        sink_id="replay_reserve_consume",
        rejected_condition="the signed envelope digest has already been consumed",
        expected_observation=(
            "first request may authorize, second request returns replayed_request_envelope "
            "and does not enter local execution"
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_consume_request_rejects_replayed_envelope",
            "tests/test_execution_gate.py::test_consume_request_allows_only_one_concurrent_consumer",
            "tests/test_agent_runtime_auth.py::test_config_default_workdir_replay_store_survives_restart",
            "tests/test_negative_injection_runner.py::test_runner_covers_real_agent_runtime_negative_paths",
        ),
    ),
)


MUTATION_EVIDENCE: tuple[MutationEvidence, ...] = (
    MutationEvidence(
        mutation_id="skip_prompt_surface_authorization",
        sink_ids=("prompt_local_agent_run",),
        mutated_control="bypass Agent._evaluate_prompt_surface_request before local_agent.run",
        expected_test_failures=(
            "tests/integration/test_baseline_agent_flow.py::BaselineAgentFlowTests::test_receive_conversation_rejects_tool_only_scope_before_prompt",
            "tests/test_negative_injection_runner.py::NegativeInjectionRunnerTests::test_runner_covers_real_agent_runtime_negative_paths",
        ),
        protected_property="scope_ok",
        notes="A tool-only signed envelope would incorrectly reach the prompt sink.",
    ),
    MutationEvidence(
        mutation_id="disable_local_execution_context_require_action",
        sink_ids=(
            "smolagents_tool_forward",
            "business_backend_method",
            "memory_read_facade",
            "memory_write_facade",
            "delegation_handler",
        ),
        mutated_control="make LocalExecutionContext.require_action a no-op",
        expected_test_failures=(
            "tests/test_agent_wrapper_gate.py::AgentWrapperExecutionGateTests::test_tool_call_is_rejected_when_scope_mismatches",
            "tests/test_agent_wrapper_gate.py::AgentWrapperExecutionGateTests::test_direct_tool_backend_proxy_rejects_without_scope",
            "tests/test_agent_wrapper_gate.py::AgentWrapperExecutionGateTests::test_memory_write_helper_rejects_without_scope",
            "tests/test_agent_wrapper_gate.py::AgentWrapperExecutionGateTests::test_direct_delegation_facade_rejects_without_scope",
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_local_execution_context_exposes_memory_and_delegation_helpers",
        ),
        protected_property="scope_ok",
        notes="Tool, backend, memory, and delegation sinks would execute without signed scopes.",
    ),
    MutationEvidence(
        mutation_id="skip_replay_reserve",
        sink_ids=("replay_reserve_consume", "prompt_local_agent_run"),
        mutated_control="skip ReplayStateStore.reserve_request inside consume_request",
        expected_test_failures=(
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_consume_request_rejects_replayed_envelope",
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_consume_request_allows_only_one_concurrent_consumer",
            "tests/test_agent_runtime_auth.py::AgentRuntimeAuthTests::test_config_default_workdir_replay_store_survives_restart",
        ),
        protected_property="replay_ok",
        notes="Duplicate signed envelopes would be able to reach execution more than once.",
    ),
    MutationEvidence(
        mutation_id="relax_action_scope_matching",
        sink_ids=(
            "prompt_local_agent_run",
            "smolagents_tool_forward",
            "business_backend_method",
            "memory_read_facade",
            "memory_write_facade",
            "delegation_handler",
        ),
        mutated_control="make action_scopes_allow accept unqualified or unrelated scopes",
        expected_test_failures=(
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_build_local_execution_context_does_not_treat_prompt_as_tool_scope",
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_build_local_execution_context_restricts_to_exact_qualified_tool_scope",
            "tests/integration/test_baseline_agent_flow.py::BaselineAgentFlowTests::test_tool_entry_scope_does_not_implicitly_grant_prompt_surface",
        ),
        protected_property="scope_ok",
        notes="A broad tool or prompt scope could incorrectly authorize narrower protected sinks.",
    ),
    MutationEvidence(
        mutation_id="bypass_gated_execution_resource",
        sink_ids=("business_backend_method",),
        mutated_control="store raw Local*Tool backend clients instead of GatedExecutionResource",
        expected_test_failures=(
            "tests/test_security_kernel.py::SecurityKernelInventoryTests::test_business_tool_backends_remain_gated_resources",
            "tests/test_agent_wrapper_gate.py::AgentWrapperExecutionGateTests::test_direct_tool_backend_proxy_rejects_without_scope",
        ),
        protected_property="policy_ok",
        notes="Business backend methods could run without capability facade checks.",
    ),
    MutationEvidence(
        mutation_id="bypass_shamir_mask_real_valued_rejection",
        sink_ids=(
            "prompt_local_agent_run",
            "smolagents_tool_forward",
            "business_backend_method",
            "memory_read_facade",
            "memory_write_facade",
            "delegation_handler",
            "replay_reserve_consume",
        ),
        mutated_control="make CAN accept unsafe real-valued coordinates when MASK fires",
        expected_test_failures=(
            "tests/test_can.py::CANTests::test_can_rejects_unsafe_real_valued_signature",
            "tests/test_can.py::CANTests::test_can_rejects_boundary_real_valued_signature",
            "tests/security/test_real_valued_rejection.py",
        ),
        protected_property="N_verify",
        notes=(
            "A real-valued neural input could bypass the hard binary interface before "
            "the signed intent gate reaches protected sinks."
        ),
    ),
    MutationEvidence(
        mutation_id="bypass_delegation_parent_digest_check",
        sink_ids=("delegation_handler",),
        mutated_control=(
            "trust child-declared parent scopes when the parent envelope digest is "
            "missing from the local parent capability fact source"
        ),
        expected_test_failures=(
            "tests/test_execution_gate.py::SignedRequestExecutionGateTests::test_authorize_rejects_delegated_child_without_known_parent_digest",
        ),
        protected_property="delegation_ok",
        notes=(
            "A forged delegated child capability could self-assert parent scopes "
            "instead of binding to a known accepted parent envelope digest."
        ),
    ),
    MutationEvidence(
        mutation_id="bypass_policy_compiler_scope_filter",
        sink_ids=tuple(sink.sink_id for sink in PROTECTED_SINK_AUDITS),
        mutated_control=(
            "sign all LLM/requested scopes as allowed scopes without intersecting "
            "them with local policy"
        ),
        expected_test_failures=(
            "tests/test_intent.py::IntentCompilerTests::test_compiler_keeps_only_policy_allowed_scopes",
            "tests/test_intent.py::IntentCompilerTests::test_missing_entry_scope_is_policy_reject",
            "tests/integration/test_baseline_agent_flow.py::BaselineAgentFlowTests::test_requested_scope_escalation_does_not_expand_signed_envelope",
            "tests/integration/test_baseline_agent_flow.py::BaselineAgentFlowTests::test_conversation_policy_rejects_entry_scope_outside_local_policy",
        ),
        protected_property="policy_ok",
        notes=(
            "LLM/requested scopes could become signed authorized scopes and entry "
            "actions outside local policy could proceed to envelope construction."
        ),
    ),
)


MODEL_REFINEMENT_MAPPINGS: tuple[ModelRefinementMapping, ...] = (
    ModelRefinementMapping(
        mapping_id="n_verify_to_signed_can_gate",
        model_term="N_verify",
        abstract_predicate=(
            "The sender public key, canonical signed intent envelope digest, and "
            "detached signature produce a hard accept bit."
        ),
        python_symbols=(
            "saga.execution_gate.SignedRequestExecutionGate.evaluate_request",
            "saga.execution_gate.bytes_to_bits",
            "neural.can.CAN.can_accept",
            "neural.compiled_lwe_dnn.CompiledToyLWEVerifier.verify_compound_bits",
            "neural.fixed_circuit.assert_fixed_circuit",
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_authorize_accepts_valid_signed_request",
            "tests/test_execution_gate.py::test_authorize_rejects_tampered_signature_under_compiled_verifier",
            "tests/test_can.py::test_can_rejects_unsafe_real_valued_signature",
            "tests/test_compiled_lwe_dnn.py::test_can_with_compiled_verifier_has_no_trainable_state",
            "tests/security/test_real_valued_rejection.py",
        ),
        tcb_assumptions=(
            "trusted_public_keys maps the claimed sender AID to the correct public key",
            "ToyLWESignatureScheme is research-only wiring evidence, not production PQ security",
            "SHA-256 challenge derivation remains deterministic preprocessing, not a neural hash claim",
        ),
        excluded_paths=(
            "mldsa_external without an injected vetted backend",
            "legacy ExecutionGate.authorize adapters that do not expose structured decisions",
            "non-strict compatibility mode without runtime-auth wiring",
        ),
        residual_risk=(
            "The refinement proves the fixed verifier wiring and hard gate semantics for the "
            "prototype; production unforgeability still depends on a vetted external ML-DSA backend."
        ),
        linked_sink_ids=tuple(sink.sink_id for sink in PROTECTED_SINK_AUDITS),
    ),
    ModelRefinementMapping(
        mapping_id="scope_ok_to_authorized_scope_checks",
        model_term="scope_ok",
        abstract_predicate=(
            "The signed authorized_scopes set permits the concrete execution surface "
            "and cannot be widened by prompt output or entry-scope defaults."
        ),
        python_symbols=(
            "saga.messages.action_scopes_allow",
            "saga.execution_gate.SignedRequestExecutionGate.evaluate_request",
            "saga.execution_gate.LocalExecutionContext.require_action",
            "saga.execution_gate.ExecutionCapabilityFacade.require_action",
            "saga.agent.Agent._evaluate_prompt_surface_request",
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_build_local_execution_context_does_not_treat_prompt_as_tool_scope",
            "tests/test_execution_gate.py::test_build_local_execution_context_restricts_to_exact_qualified_tool_scope",
            "tests/integration/test_baseline_agent_flow.py::test_receive_conversation_rejects_tool_only_scope_before_prompt",
            "tests/test_agent_wrapper_gate.py::test_tool_call_is_rejected_when_scope_mismatches",
            "tests/test_agent_wrapper_gate.py::test_memory_write_helper_rejects_without_scope",
        ),
        tcb_assumptions=(
            "RequestEnvelope canonical encoding is deterministic",
            "LocalExecutionContext is built only from an allowed gate decision",
            "business tools, memory helpers, and delegation helpers use the capability facade",
        ),
        excluded_paths=(
            "raw backend clients stored outside AgentWrapper._gated_tool_resource",
            "raw downstream memory-object access outside ExecutionCapabilityFacade",
            "tools created and called outside AgentWrapper collection",
        ),
        residual_risk=(
            "Scope refinement is claimed for strict runtime-auth protected sinks and "
            "does not cover arbitrary local Python code that bypasses the facade."
        ),
        linked_sink_ids=(
            "prompt_local_agent_run",
            "smolagents_tool_forward",
            "business_backend_method",
            "memory_read_facade",
            "memory_write_facade",
            "delegation_handler",
        ),
    ),
    ModelRefinementMapping(
        mapping_id="replay_ok_to_atomic_reserve",
        model_term="replay_ok",
        abstract_predicate=(
            "A signed envelope digest is reserved exactly once before protected execution."
        ),
        python_symbols=(
            "saga.execution_gate.SignedRequestExecutionGate.consume_request",
            "saga.execution_gate.ReplayStateStore.reserve_request",
            "saga.execution_gate.FileReplayStateStore.reserve_request",
            "saga.execution_gate.SQLiteReplayStateStore.reserve_request",
            "saga.execution_gate.RedisReplayStateStore.reserve_request",
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_consume_request_rejects_replayed_envelope",
            "tests/test_execution_gate.py::test_consume_request_allows_only_one_concurrent_consumer",
            "tests/test_execution_gate.py::test_sqlite_replay_store_reserves_request_id_atomically",
            "tests/test_execution_gate.py::test_redis_replay_store_uses_set_nx_for_atomic_reservation",
            "tests/test_agent_runtime_auth.py::test_config_default_workdir_replay_store_survives_restart",
        ),
        tcb_assumptions=(
            "execution paths use consume_request rather than pure evaluate_request",
            "injected replay stores implement reserve_request atomically",
            "external Redis or SQL deployment provides the consistency promised by its adapter",
        ),
        excluded_paths=(
            "diagnostic evaluate_request calls that intentionally do not consume replay state",
            "distributed production deployments without a strongly consistent replay backend",
        ),
        residual_risk=(
            "File-marker replay state is local/dev evidence; multi-host claims require "
            "an externally managed atomic backend."
        ),
        linked_sink_ids=("replay_reserve_consume", "prompt_local_agent_run"),
    ),
    ModelRefinementMapping(
        mapping_id="delegation_ok_to_parent_bound_capabilities",
        model_term="delegation_ok",
        abstract_predicate=(
            "Delegated child capabilities bind a known parent digest, match parent scopes, "
            "attenuate child scopes, and respect depth bounds."
        ),
        python_symbols=(
            "saga.messages.RequestEnvelope",
            "saga.messages.action_scopes_are_attenuated",
            "saga.execution_gate.SignedRequestExecutionGate._evaluate_delegation_capability",
            "saga.execution_gate.ExecutionCapabilityFacade.delegate",
            "saga.agent.Agent._delegate_to_agent",
        ),
        evidence_tests=(
            "tests/test_execution_gate.py::test_authorize_accepts_delegated_child_capability_when_attenuated",
            "tests/test_execution_gate.py::test_authorize_rejects_delegated_child_without_known_parent_digest",
            "tests/test_execution_gate.py::test_authorize_rejects_delegated_child_scope_escalation",
            "tests/test_execution_gate.py::test_authorize_rejects_delegation_depth_exceeded",
            "tests/integration/test_baseline_agent_flow.py::test_conversation_payload_binds_parent_capability_for_delegation_child",
        ),
        tcb_assumptions=(
            "parent_capability_store is populated from trusted accepted parent capabilities",
            "delegation entry points use ExecutionCapabilityFacade.delegate before Agent.connect",
        ),
        excluded_paths=(
            "ad hoc Agent.connect calls in experiment drivers",
            "future delegation-chain storage not wired through the parent capability fact source",
        ),
        residual_risk=(
            "The first-stage refinement covers parent digest and attenuation checks; "
            "full live multi-hop delegation storage remains future wiring."
        ),
        linked_sink_ids=("delegation_handler",),
    ),
    ModelRefinementMapping(
        mapping_id="policy_ok_to_local_intent_compiler",
        model_term="policy_ok",
        abstract_predicate=(
            "Local policy compiles requested scopes into signed authorized scopes and "
            "rejects entry actions or requested scopes outside policy."
        ),
        python_symbols=(
            "saga.intent.IntentCompiler.compile",
            "saga.agent.Agent._conversation_policy_decision",
            "saga.agent.Agent._conversation_authorized_scopes",
            "saga.execution_gate.ExecutionGateDecision.formula_terms",
            "saga.execution_gate.build_execution_gate_audit_record",
        ),
        evidence_tests=(
            "tests/test_intent.py::test_compiler_keeps_only_policy_allowed_scopes",
            "tests/test_intent.py::test_missing_entry_scope_is_policy_reject",
            "tests/integration/test_baseline_agent_flow.py::test_conversation_policy_rejects_entry_scope_outside_local_policy",
            "tests/integration/test_baseline_agent_flow.py::test_requested_scope_escalation_does_not_expand_signed_envelope",
            "tests/integration/test_baseline_agent_flow.py::test_receive_conversation_audit_records_full_authorization_formula_on_signature_reject",
        ),
        tcb_assumptions=(
            "local policy scope construction reflects the configured business tools and runtime surfaces",
            "LLM requested scopes are proposals and are not trusted authorization proof",
            "audit formula terms are diagnostics and not an authorization bypass",
        ),
        excluded_paths=(
            "manual payload construction outside Agent._build_conversation_payload",
            "non-strict compatibility paths used only for baseline reproduction",
        ),
        residual_risk=(
            "Policy refinement covers the local prototype policy compiler, not a full "
            "organization-wide policy language."
        ),
        linked_sink_ids=tuple(sink.sink_id for sink in PROTECTED_SINK_AUDITS),
    ),
    ModelRefinementMapping(
        mapping_id="execute_surface_to_protected_sinks",
        model_term="Execute(surface)",
        abstract_predicate=(
            "A protected sink may execute only after the strict runtime-auth predicates "
            "hold for that surface."
        ),
        python_symbols=(
            "saga.agent.Agent._evaluate_execution_request",
            "saga.agent.Agent._evaluate_prompt_surface_request",
            "saga.agent.Agent._run_local_agent_with_diagnostics",
            "agent_backend.base.AgentWrapper._wrap_tool_with_execution_gate",
            "agent_backend.base.AgentWrapper._gated_tool_resource",
            "saga.execution_gate.ExecutionCapabilityFacade",
        ),
        evidence_tests=(
            "tests/test_security_kernel.py::test_local_agent_run_call_sites_remain_prompt_gated",
            "tests/test_security_kernel.py::test_raw_memory_mutation_remains_inside_capability_facade",
            "tests/test_security_kernel.py::test_business_tool_backends_remain_gated_resources",
            "tests/test_security_kernel.py::test_direct_delegation_connect_calls_remain_excluded_or_gated",
            "tests/test_security_kernel.py::test_replay_consume_and_reserve_calls_remain_gate_mediated",
        ),
        tcb_assumptions=(
            "protected sink inventory remains synchronized with active strict runtime-auth code",
            "static drift tests are run before claiming the kernel boundary",
        ),
        excluded_paths=(
            "legacy attack-model copies",
            "experiment harnesses unless they explicitly opt into runtime auth",
            "custom code that calls local agents or raw resources outside the active Agent wrapper",
        ),
        residual_risk=(
            "This is a sink-centric kernel claim, not a statement that every Python "
            "callable in the repository is impossible to invoke directly."
        ),
        linked_sink_ids=tuple(sink.sink_id for sink in PROTECTED_SINK_AUDITS),
    ),
)


def security_kernel_entries() -> tuple[SecurityKernelEntry, ...]:
    """返回当前 security runtime kernel 的不可变执行入口清单。"""
    return SECURITY_KERNEL_ENTRIES


def protected_sink_audits() -> tuple[ProtectedSinkAudit, ...]:
    """返回 strict runtime-auth kernel 的受保护副作用点审计清单。"""
    return PROTECTED_SINK_AUDITS


def protected_sink_surfaces() -> tuple[str, ...]:
    """返回当前 sink-centric 安全声明覆盖的执行面名称。"""
    return tuple(sink.surface for sink in PROTECTED_SINK_AUDITS)


def no_side_effect_oracles() -> tuple[NoSideEffectOracle, ...]:
    """返回 protected sink 的无副作用拒绝证据清单。"""
    return NO_SIDE_EFFECT_ORACLES


def mutation_evidence() -> tuple[MutationEvidence, ...]:
    """返回关键 gate 控制点的 mutation 证据清单。"""
    return MUTATION_EVIDENCE


def model_refinement_mappings() -> tuple[ModelRefinementMapping, ...]:
    """返回 P5 抽象模型到 Python 实现与测试证据的 P6 对照表。"""
    return MODEL_REFINEMENT_MAPPINGS


def entries_for_status(status: KernelEntryStatus) -> tuple[SecurityKernelEntry, ...]:
    """按覆盖状态筛选执行入口，便于文档和测试复用。"""
    return tuple(entry for entry in SECURITY_KERNEL_ENTRIES if entry.status == status)


def covered_surfaces() -> tuple[str, ...]:
    """返回已纳入安全声明的执行面名称。"""
    return tuple(
        entry.surface for entry in SECURITY_KERNEL_ENTRIES if entry.in_security_kernel
    )


def excluded_entries() -> tuple[SecurityKernelEntry, ...]:
    """返回不属于当前 PQ-CAN 安全声明的兼容或待加固入口。"""
    return tuple(entry for entry in SECURITY_KERNEL_ENTRIES if not entry.in_security_kernel)
