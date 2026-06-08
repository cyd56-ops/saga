## Run-Level Summary
| mode | runtime_auth_enabled | task_count | succeeded_count | failed_count | task_latency_seconds_total | task_latency_seconds_mean | model_call_count | llm_elapsed_seconds_total | audit_record_count | audit_reject_count | audit_logging_overhead_record_count | logging_stats_collection_latency_seconds_total | api_cost_available | api_cost_usd_total | token_usage_available | total_tokens |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | False | 3 | 3 | 0 | 183.258211 | 61.08607 | 15 | 253.35787 | 0 | 0 | 0 | 0.009615 | False |  | False |  |
| pq_can | True | 3 | 3 | 0 | 224.460688 | 74.820229 | 22 | 321.030396 | 0 | 0 | 0 | 0.008673 | False |  | False |  |

## Task-Level Summary
| mode | task_name | success | runtime_auth_enabled | task_latency_seconds | model_call_count | local_model_call_count | peer_model_call_count | llm_elapsed_seconds_total | audit_record_count | audit_reject_count | peer_audit_reject_count | audit_logging_overhead_record_count | api_cost_available | api_cost_usd | token_usage_available | total_tokens | oracle_reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | schedule_meeting | True | False | 44.419665 | 6 | 2 | 4 | 70.114717 | 0 | 0 | 0 | 0 | False |  | False |  | meeting_scheduled |
| baseline | expense_report | True | False | 99.166138 | 7 | 2 | 5 | 143.647905 | 0 | 0 | 0 | 0 | False |  | False |  |  |
| baseline | create_blogpost | True | False | 39.672408 | 2 | 0 | 2 | 39.595248 | 0 | 0 | 0 | 0 | False |  | False |  |  |
| pq_can | schedule_meeting | True | True | 48.207244 | 7 | 2 | 5 | 74.865621 | 0 | 0 | 0 | 0 | False |  | False |  | meeting_scheduled |
| pq_can | expense_report | True | True | 132.220902 | 12 | 5 | 7 | 202.231406 | 0 | 0 | 0 | 0 | False |  | False |  |  |
| pq_can | create_blogpost | True | True | 44.032542 | 3 | 0 | 3 | 43.933368 | 0 | 0 | 0 | 0 | False |  | False |  |  |

## Security Properties
| property_id | title | enforcement_terms | assumptions | limitations |
| --- | --- | --- | --- | --- |
| unforgeability | Unforgeability of Execution Capabilities | request_envelope_valid, pq_signature_valid, can_accept | Trusted public keys are provisioned by the SAGA registration path.; The production-facing ML-DSA path must wrap a vetted external backend.; Toy LWE evidence is research wiring evidence, not a production PQ claim. | This property does not claim confidentiality or full post-quantum transport security.; Compatibility paths outside strict runtime auth are excluded. |
| context_binding | Context Binding | saga_token_valid, request_envelope_valid, pq_signature_valid, can_accept | Request envelopes are encoded with deterministic canonical JSON.; The receiver compares transport fields with the signed envelope before execution. | The claim covers fields represented in the signed request envelope. |
| scope_non_escalation | Scope Non-Escalation | request_envelope_valid, execution_scope_allowed, internal_policy_accept | LLM-requested scopes are proposals and are not trusted authorization proofs.; Strict runtime surfaces consume LocalExecutionContext or gated facades. | Raw backend use outside the checked strict runtime kernel is outside the claim. |
| replay_resistance | Replay Resistance | request_envelope_valid, pq_signature_valid, can_accept, internal_policy_accept | A replay store with atomic reserve semantics is configured for strict runtime auth.; File and SQLite stores are local research backends; deployment needs a consistent shared backend. | The property is scoped to request-envelope digest consumption, not network-level packet replay. |
| side_effect_free_rejection | Side-Effect-Free Rejection | execution_scope_allowed, internal_policy_accept | Protected actions are reached only through the strict execution kernel.; Tests use side-effect counters or protected-action files as the oracle. | The property does not cover unrelated application code that bypasses the kernel. |

## Security Evidence
| source | name | properties | expected_reason | evidence_kind | side_effect_expectation |
| --- | --- | --- | --- | --- | --- |
| offline_negative_injection | tampered_message | context_binding, unforgeability | message_digest_mismatch | deterministic_offline_gate | no_local_execution |
| offline_negative_injection | tampered_action_scope | context_binding, scope_non_escalation | action_scope_mismatch | deterministic_offline_gate | no_local_execution |
| offline_negative_injection | tampered_authorized_scope | unforgeability, scope_non_escalation | signature_verification_failed | deterministic_offline_gate | no_local_execution |
| offline_negative_injection | expired_envelope | context_binding | envelope_expired | deterministic_offline_gate | no_local_execution |
| offline_negative_injection | replayed_envelope | replay_resistance, side_effect_free_rejection | replayed_request_envelope | deterministic_offline_gate | first_allowed_second_rejected |
| offline_negative_injection | unauthorized_tool_scope | scope_non_escalation, side_effect_free_rejection | unauthorized_tool_scope | local_execution_context | protected_tool_not_called |
| offline_negative_injection | unauthorized_memory_write | scope_non_escalation, side_effect_free_rejection | unauthorized_memory_write | local_execution_context | memory_not_written |
| offline_negative_injection | unauthorized_delegation | scope_non_escalation, side_effect_free_rejection | unauthorized_delegation | local_execution_context | delegation_not_started |
| offline_negative_injection | real_valued_signature_input | unforgeability | real_valued_signature_input | shamir_mask_gate | no_accepting_real_valued_gate |
| offline_negative_injection | untrusted_sender_aid | unforgeability, context_binding | untrusted_sender_aid | trusted_key_map | no_local_execution |
| offline_negative_injection | wrong_trusted_sender_key | unforgeability | signature_verification_failed | trusted_key_map | no_local_execution |
| offline_negative_injection | agent_runtime_prompt_surface_tool_only | scope_non_escalation, side_effect_free_rejection | prompt_scope_not_authorized | agent_runtime_path | local_agent_run_count_zero |
| offline_negative_injection | agent_runtime_replayed_envelope | replay_resistance, side_effect_free_rejection | replayed_request_envelope | agent_runtime_path | second_local_run_not_called |
| offline_negative_injection | agent_runtime_scope_escalation_tool | scope_non_escalation, side_effect_free_rejection | unauthorized_tool_scope | agent_runtime_path | protected_tool_not_called |
| offline_negative_injection | agent_runtime_context_ignoring_local_agent | scope_non_escalation, side_effect_free_rejection | local_agent_execution_context_unsupported | agent_runtime_path | local_agent_run_count_zero |
| real_negative_runner | missing_request_envelope | unforgeability, context_binding, side_effect_free_rejection | missing_request_envelope | provider_token_tls_socket_listener | local_agent_run_count_zero |
| real_negative_runner | tampered_message | context_binding, unforgeability, side_effect_free_rejection | message_digest_mismatch | provider_token_tls_socket_listener | local_agent_run_count_zero |
| real_negative_runner | prompt_surface_tool_only | scope_non_escalation, side_effect_free_rejection | prompt_scope_not_authorized | provider_token_tls_socket_listener | local_agent_run_count_zero |
| real_negative_runner | replayed_envelope | replay_resistance, side_effect_free_rejection | replayed_request_envelope | provider_token_tls_socket_listener | second_local_run_not_called |
| real_negative_runner | wrong_trusted_sender_key | unforgeability, side_effect_free_rejection | signature_verification_failed | provider_token_tls_socket_listener | local_agent_run_count_zero |
| real_negative_runner | unauthorized_tool_scope | scope_non_escalation, side_effect_free_rejection | unauthorized_tool_scope | provider_token_tls_socket_listener_scope_probe | prompt_runs_once_protected_tool_not_called |
| real_negative_runner | unauthorized_memory_write | scope_non_escalation, side_effect_free_rejection | unauthorized_memory_write | provider_token_tls_socket_listener_scope_probe | prompt_runs_once_memory_not_written |
| real_negative_runner | unauthorized_delegation | scope_non_escalation, side_effect_free_rejection | unauthorized_delegation | provider_token_tls_socket_listener_scope_probe | prompt_runs_once_delegation_not_started |
| ablation_overhead_runner | saga_only | context_binding, scope_non_escalation, replay_resistance | negative_rejected_count=0 | offline_ablation_mode | baseline_admission_only |
| ablation_overhead_runner | ordinary_pq_middleware | unforgeability, context_binding | negative_rejected_count=2 | offline_ablation_mode | rejects_signature_and_envelope_cases_only |
| ablation_overhead_runner | naive_neural_verifier | unforgeability, context_binding | negative_rejected_count=2 | offline_ablation_mode | rejects_signature_and_envelope_cases_only |
| ablation_overhead_runner | shamir_secured_pq_can | unforgeability, context_binding, scope_non_escalation, side_effect_free_rejection | negative_rejected_count=5 | offline_ablation_mode | rejects_all_current_offline_negative_cases |
