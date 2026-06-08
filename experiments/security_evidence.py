"""Security-property evidence map for SAGA-PQ-CAN experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


SECURITY_PROPERTY_ORDER = (
    "unforgeability",
    "context_binding",
    "scope_non_escalation",
    "replay_resistance",
    "side_effect_free_rejection",
)


@dataclass(frozen=True)
class SecurityPropertyClaim:
    """描述论文级安全性质及其代码边界。"""

    property_id: str
    title: str
    statement: str
    enforcement_terms: tuple[str, ...]
    assumptions: tuple[str, ...]
    limitations: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """序列化性质陈述，便于文档和实验脚本复用。"""
        return {
            "property_id": self.property_id,
            "title": self.title,
            "statement": self.statement,
            "enforcement_terms": list(self.enforcement_terms),
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class EvidenceMapping:
    """把一个测试或实验样本映射到安全性质。"""

    source: str
    name: str
    properties: tuple[str, ...]
    expected_reason: str
    evidence_kind: str
    side_effect_expectation: str
    notes: str = ""

    def as_dict(self) -> dict[str, object]:
        """序列化证据映射，保持字段稳定用于论文表格。"""
        return {
            "source": self.source,
            "name": self.name,
            "properties": list(self.properties),
            "expected_reason": self.expected_reason,
            "evidence_kind": self.evidence_kind,
            "side_effect_expectation": self.side_effect_expectation,
            "notes": self.notes,
        }


PROPERTY_CLAIMS: tuple[SecurityPropertyClaim, ...] = (
    SecurityPropertyClaim(
        property_id="unforgeability",
        title="Unforgeability of Execution Capabilities",
        statement=(
            "An execution request is accepted only when the sender AID resolves to a "
            "trusted public key and the detached post-quantum signature verifies over "
            "the canonical signed intent capability envelope digest."
        ),
        enforcement_terms=(
            "request_envelope_valid",
            "pq_signature_valid",
            "can_accept",
        ),
        assumptions=(
            "Trusted public keys are provisioned by the SAGA registration path.",
            "The production-facing ML-DSA path must wrap a vetted external backend.",
            "Toy LWE evidence is research wiring evidence, not a production PQ claim.",
        ),
        limitations=(
            "This property does not claim confidentiality or full post-quantum transport security.",
            "Compatibility paths outside strict runtime auth are excluded.",
        ),
    ),
    SecurityPropertyClaim(
        property_id="context_binding",
        title="Context Binding",
        statement=(
            "A valid signature is bound to sender, receiver, token digest, message "
            "digest, action scope, time window, session, turn, provider, and signed "
            "capability metadata; moving it to another context must be rejected."
        ),
        enforcement_terms=(
            "saga_token_valid",
            "request_envelope_valid",
            "pq_signature_valid",
            "can_accept",
        ),
        assumptions=(
            "Request envelopes are encoded with deterministic canonical JSON.",
            "The receiver compares transport fields with the signed envelope before execution.",
        ),
        limitations=(
            "The claim covers fields represented in the signed request envelope.",
        ),
    ),
    SecurityPropertyClaim(
        property_id="scope_non_escalation",
        title="Scope Non-Escalation",
        statement=(
            "A request cannot gain execution authority beyond the signed "
            "authorized_scopes compiled from local policy, and delegated child "
            "capabilities must attenuate rather than expand parent scope."
        ),
        enforcement_terms=(
            "request_envelope_valid",
            "execution_scope_allowed",
            "internal_policy_accept",
        ),
        assumptions=(
            "LLM-requested scopes are proposals and are not trusted authorization proofs.",
            "Strict runtime surfaces consume LocalExecutionContext or gated facades.",
        ),
        limitations=(
            "Raw backend use outside the checked strict runtime kernel is outside the claim.",
        ),
    ),
    SecurityPropertyClaim(
        property_id="replay_resistance",
        title="Replay Resistance",
        statement=(
            "The execution path consumes each signed envelope digest at most once; "
            "duplicate consumption, restart replay, write-failure, and concurrent "
            "reservation races fail closed."
        ),
        enforcement_terms=(
            "request_envelope_valid",
            "pq_signature_valid",
            "can_accept",
            "internal_policy_accept",
        ),
        assumptions=(
            "A replay store with atomic reserve semantics is configured for strict runtime auth.",
            "File and SQLite stores are local research backends; deployment needs a consistent shared backend.",
        ),
        limitations=(
            "The property is scoped to request-envelope digest consumption, not network-level packet replay.",
        ),
    ),
    SecurityPropertyClaim(
        property_id="side_effect_free_rejection",
        title="Side-Effect-Free Rejection",
        statement=(
            "Rejected prompt, tool, memory, and delegation requests must return, drop, "
            "or audit before triggering the protected local action."
        ),
        enforcement_terms=(
            "execution_scope_allowed",
            "internal_policy_accept",
        ),
        assumptions=(
            "Protected actions are reached only through the strict execution kernel.",
            "Tests use side-effect counters or protected-action files as the oracle.",
        ),
        limitations=(
            "The property does not cover unrelated application code that bypasses the kernel.",
        ),
    ),
)


NEGATIVE_INJECTION_EVIDENCE: tuple[EvidenceMapping, ...] = (
    EvidenceMapping(
        source="offline_negative_injection",
        name="tampered_message",
        properties=("context_binding", "unforgeability"),
        expected_reason="message_digest_mismatch",
        evidence_kind="deterministic_offline_gate",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="tampered_action_scope",
        properties=("context_binding", "scope_non_escalation"),
        expected_reason="action_scope_mismatch",
        evidence_kind="deterministic_offline_gate",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="tampered_authorized_scope",
        properties=("unforgeability", "scope_non_escalation"),
        expected_reason="signature_verification_failed",
        evidence_kind="deterministic_offline_gate",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="expired_envelope",
        properties=("context_binding",),
        expected_reason="envelope_expired",
        evidence_kind="deterministic_offline_gate",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="replayed_envelope",
        properties=("replay_resistance", "side_effect_free_rejection"),
        expected_reason="replayed_request_envelope",
        evidence_kind="deterministic_offline_gate",
        side_effect_expectation="first_allowed_second_rejected",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="unauthorized_tool_scope",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_tool_scope",
        evidence_kind="local_execution_context",
        side_effect_expectation="protected_tool_not_called",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="unauthorized_memory_write",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_memory_write",
        evidence_kind="local_execution_context",
        side_effect_expectation="memory_not_written",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="unauthorized_delegation",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_delegation",
        evidence_kind="local_execution_context",
        side_effect_expectation="delegation_not_started",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="real_valued_signature_input",
        properties=("unforgeability",),
        expected_reason="real_valued_signature_input",
        evidence_kind="shamir_mask_gate",
        side_effect_expectation="no_accepting_real_valued_gate",
        notes="Covers the Shamir STEP/RECT/MASK hard 0/1 interface.",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="untrusted_sender_aid",
        properties=("unforgeability", "context_binding"),
        expected_reason="untrusted_sender_aid",
        evidence_kind="trusted_key_map",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="wrong_trusted_sender_key",
        properties=("unforgeability",),
        expected_reason="signature_verification_failed",
        evidence_kind="trusted_key_map",
        side_effect_expectation="no_local_execution",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="agent_runtime_prompt_surface_tool_only",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="prompt_scope_not_authorized",
        evidence_kind="agent_runtime_path",
        side_effect_expectation="local_agent_run_count_zero",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="agent_runtime_replayed_envelope",
        properties=("replay_resistance", "side_effect_free_rejection"),
        expected_reason="replayed_request_envelope",
        evidence_kind="agent_runtime_path",
        side_effect_expectation="second_local_run_not_called",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="agent_runtime_scope_escalation_tool",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_tool_scope",
        evidence_kind="agent_runtime_path",
        side_effect_expectation="protected_tool_not_called",
    ),
    EvidenceMapping(
        source="offline_negative_injection",
        name="agent_runtime_context_ignoring_local_agent",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="local_agent_execution_context_unsupported",
        evidence_kind="agent_runtime_path",
        side_effect_expectation="local_agent_run_count_zero",
    ),
)


REAL_NEGATIVE_EVIDENCE: tuple[EvidenceMapping, ...] = (
    EvidenceMapping(
        source="real_negative_runner",
        name="missing_request_envelope",
        properties=("unforgeability", "context_binding", "side_effect_free_rejection"),
        expected_reason="missing_request_envelope",
        evidence_kind="provider_token_tls_socket_listener",
        side_effect_expectation="local_agent_run_count_zero",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="tampered_message",
        properties=("context_binding", "unforgeability", "side_effect_free_rejection"),
        expected_reason="message_digest_mismatch",
        evidence_kind="provider_token_tls_socket_listener",
        side_effect_expectation="local_agent_run_count_zero",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="prompt_surface_tool_only",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="prompt_scope_not_authorized",
        evidence_kind="provider_token_tls_socket_listener",
        side_effect_expectation="local_agent_run_count_zero",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="replayed_envelope",
        properties=("replay_resistance", "side_effect_free_rejection"),
        expected_reason="replayed_request_envelope",
        evidence_kind="provider_token_tls_socket_listener",
        side_effect_expectation="second_local_run_not_called",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="wrong_trusted_sender_key",
        properties=("unforgeability", "side_effect_free_rejection"),
        expected_reason="signature_verification_failed",
        evidence_kind="provider_token_tls_socket_listener",
        side_effect_expectation="local_agent_run_count_zero",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="unauthorized_tool_scope",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_tool_scope",
        evidence_kind="provider_token_tls_socket_listener_scope_probe",
        side_effect_expectation="prompt_runs_once_protected_tool_not_called",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="unauthorized_memory_write",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_memory_write",
        evidence_kind="provider_token_tls_socket_listener_scope_probe",
        side_effect_expectation="prompt_runs_once_memory_not_written",
    ),
    EvidenceMapping(
        source="real_negative_runner",
        name="unauthorized_delegation",
        properties=("scope_non_escalation", "side_effect_free_rejection"),
        expected_reason="unauthorized_delegation",
        evidence_kind="provider_token_tls_socket_listener_scope_probe",
        side_effect_expectation="prompt_runs_once_delegation_not_started",
    ),
)


ABLATION_EVIDENCE: tuple[EvidenceMapping, ...] = (
    EvidenceMapping(
        source="ablation_overhead_runner",
        name="saga_only",
        properties=("context_binding", "scope_non_escalation", "replay_resistance"),
        expected_reason="negative_rejected_count=0",
        evidence_kind="offline_ablation_mode",
        side_effect_expectation="baseline_admission_only",
        notes="Shows protocol admission alone does not enforce signed envelope or execution-scope properties.",
    ),
    EvidenceMapping(
        source="ablation_overhead_runner",
        name="ordinary_pq_middleware",
        properties=("unforgeability", "context_binding"),
        expected_reason="negative_rejected_count=2",
        evidence_kind="offline_ablation_mode",
        side_effect_expectation="rejects_signature_and_envelope_cases_only",
        notes="Shows byte-level PQ verification does not by itself enforce prompt/tool scope or Shamir real-valued rejection.",
    ),
    EvidenceMapping(
        source="ablation_overhead_runner",
        name="naive_neural_verifier",
        properties=("unforgeability", "context_binding"),
        expected_reason="negative_rejected_count=2",
        evidence_kind="offline_ablation_mode",
        side_effect_expectation="rejects_signature_and_envelope_cases_only",
        notes="Shows compiled verification without Shamir MASK remains vulnerable at the real-valued input interface.",
    ),
    EvidenceMapping(
        source="ablation_overhead_runner",
        name="shamir_secured_pq_can",
        properties=(
            "unforgeability",
            "context_binding",
            "scope_non_escalation",
            "side_effect_free_rejection",
        ),
        expected_reason="negative_rejected_count=5",
        evidence_kind="offline_ablation_mode",
        side_effect_expectation="rejects_all_current_offline_negative_cases",
        notes="Shows the full stack adds execution-scope policy and Shamir real-valued rejection.",
    ),
)


def property_claims() -> tuple[SecurityPropertyClaim, ...]:
    """返回 U9 的论文级安全性质陈述。"""
    return PROPERTY_CLAIMS


def evidence_mappings() -> tuple[EvidenceMapping, ...]:
    """返回 U10 的负向 runner、真实 runner 与消融证据映射。"""
    return (
        *NEGATIVE_INJECTION_EVIDENCE,
        *REAL_NEGATIVE_EVIDENCE,
        *ABLATION_EVIDENCE,
    )


def mappings_by_property() -> dict[str, tuple[EvidenceMapping, ...]]:
    """按安全性质聚合所有证据映射。"""
    grouped: dict[str, list[EvidenceMapping]] = {
        property_id: [] for property_id in SECURITY_PROPERTY_ORDER
    }
    for mapping in evidence_mappings():
        for property_id in mapping.properties:
            grouped.setdefault(property_id, []).append(mapping)
    return {
        property_id: tuple(grouped.get(property_id, ()))
        for property_id in SECURITY_PROPERTY_ORDER
    }


def mappings_by_source(source: str) -> tuple[EvidenceMapping, ...]:
    """按实验或测试来源筛选证据映射。"""
    return tuple(
        mapping for mapping in evidence_mappings() if mapping.source == source
    )


def summarize_property_evidence(
    mappings: Iterable[EvidenceMapping] | None = None,
) -> dict[str, object]:
    """生成按安全性质统计的证据摘要。"""
    selected = tuple(mappings or evidence_mappings())
    by_property: dict[str, dict[str, object]] = {}
    for property_id in SECURITY_PROPERTY_ORDER:
        property_mappings = [
            mapping for mapping in selected if property_id in mapping.properties
        ]
        by_property[property_id] = {
            "evidence_count": len(property_mappings),
            "sources": sorted({mapping.source for mapping in property_mappings}),
            "names": [mapping.name for mapping in property_mappings],
        }
    return {
        "property_order": list(SECURITY_PROPERTY_ORDER),
        "properties": by_property,
        "evidence_count": len(selected),
    }


def validate_evidence_properties(
    mappings: Iterable[EvidenceMapping] | None = None,
) -> tuple[str, ...]:
    """检查证据映射是否只引用已声明的安全性质。"""
    valid_properties = {claim.property_id for claim in PROPERTY_CLAIMS}
    errors: list[str] = []
    for mapping in tuple(mappings or evidence_mappings()):
        for property_id in mapping.properties:
            if property_id not in valid_properties:
                errors.append(f"{mapping.source}:{mapping.name}:{property_id}")
    return tuple(errors)


def source_reason_map(source: str) -> dict[str, str]:
    """返回指定来源中样本名到预期拒绝原因的映射。"""
    return {
        mapping.name: mapping.expected_reason
        for mapping in mappings_by_source(source)
    }


def ablation_expected_negative_rejections() -> dict[str, int]:
    """返回各消融模式的期望负向拒绝数量。"""
    prefix = "negative_rejected_count="
    expected: dict[str, int] = {}
    for mapping in ABLATION_EVIDENCE:
        if not mapping.expected_reason.startswith(prefix):
            continue
        expected[mapping.name] = int(mapping.expected_reason.removeprefix(prefix))
    return expected


def as_serializable_report() -> dict[str, object]:
    """生成可 JSON 序列化的 U9/U10 性质与证据报告。"""
    return {
        "claims": [claim.as_dict() for claim in property_claims()],
        "evidence": [mapping.as_dict() for mapping in evidence_mappings()],
        "summary": summarize_property_evidence(),
    }
