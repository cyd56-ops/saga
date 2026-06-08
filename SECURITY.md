# SAGA-PQ-CAN Security Notes

This repository is a research prototype for defensive authentication middleware
in agentic systems. It is not a production security product.

## Security Boundary

SAGA remains the protocol-layer admission mechanism:

- Provider registry and contact policy
- one-time key and access-token issuance
- token expiry, quota, and peer binding
- TLS transport for direct agent communication

The active code path is intentionally split into two kernels:

- SAGA protocol kernel: `saga/agent.py`, `saga/provider/provider.py`,
  `saga/user/user.py`, `saga/common/*`, `saga/ca/CA.py`, `saga/config.py`,
  and `saga/local_agent.py`. This layer owns identity, registration, token,
  contact-policy, and transport semantics.
- PQ-CAN extension kernel: `saga/messages.py`, `saga/intent.py`,
  `saga/execution_gate.py`, `pq/`, and `neural/`. This layer owns canonical
  request envelopes, detached post-quantum signature checks, fixed neural
  verification gates, and execution-surface authorization.

The focused regression surface for the two kernels lives under `tests/`,
`tests/security/`, and `tests/integration/`.

PQ-CAN is an optional receiving-agent runtime gate. Its intended boundary is
the execution surface inside the receiving agent:

- `llm_prompt`
- `memory_read`
- `memory_write`
- `tool_call`
- `tool_call:<tool_name>`
- `delegation`

Experiment, paper-reproduction, and demonstration code is not part of the
mandatory runtime security boundary for the PQ-CAN prototype. In particular,
`experiments/`, `proofs/`, `saga/attack_models/`, and most of `agent_backend/`
are evidence, harness, or demo layers unless a specific test or experiment
explicitly opts into them. These directories must not be treated as required
authorization bypass paths for the active runtime gate.

The effective authorization rule is:

```text
allow = saga_token_valid
    AND request_envelope_valid
    AND pq_signature_valid
    AND can_accept
    AND execution_scope_allowed
    AND internal_policy_accept
```

## Invariants

- The neural verifier must not contain signing private keys.
- The verifier receives public key bits, canonical envelope digest bits, and
  detached signature bits only.
- Authentication decisions are hard `0` or `1`; there is no soft score or
  partial authorization.
- DNN/CNN/CAN verifier objects are treated as compiled deterministic circuits,
  not trained classifiers. Fixed circuit audits must reject trainable
  parameters, optimizer state, or explicit training-update entrypoints.
- Real-valued verifier inputs must fail closed through the Shamir
  `STEP_1_3`, `RECT_1_3`, and `MASK` protection path.
- Missing, malformed, expired, mismatched, or untrusted request material must
  reject/drop/audit before local execution.
- Consumed request envelopes are replay-protected by envelope digest. When
  runtime auth is enabled through the standard helper, replay markers are
  persisted under the agent workdir so a fresh gate instance still rejects the
  same envelope with `replayed_request_envelope`. If replay state cannot be
  written, the execution path fails closed with
  `replay_state_persistence_failed`.
- Runtime auth can instead point multiple local workdirs at one shared
  `replay_state_dir`, or inject a `ReplayStateStore` backend with atomic
  `reserve_request` semantics. The checked-in store is a defensive file-marker
  prototype for local/shared-filesystem experiments; full multi-host
  consistency still requires an external strongly consistent backend.
- SAGA one-time-key signatures are bound to the receiving agent identity. The
  signed payload is a domain-separated canonical object containing `aid` and
  the raw OTK bytes; raw OTK-only signatures and cross-AID signatures must fail
  closed at Provider registration/refresh and initiating-side OTK verification.
- Execution-gate decisions expose the six authorization formula terms in
  `authorization_formula`: `saga_token_valid`, `request_envelope_valid`,
  `pq_signature_valid`, `can_accept`, `execution_scope_allowed`, and
  `internal_policy_accept`.
- Agent-LLM output may request scopes or explain intent, but it is not a trusted
  authorization proof. Runtime gates make the final decision.
- LLM/requested scopes are compiled by local policy. Rejected proposals use
  stable local reasons: `policy_reject` when the entry action itself is not
  allowed and `scope_escalation` when extra requested scopes exceed policy.
- Rejected requested scopes must not appear in the signed request envelope's
  `authorized_scopes`; downstream `LocalExecutionContext` checks can only grant
  scopes that survived local policy compilation and signature verification.
- Entry actions outside local policy fail closed before envelope construction.
  Tool-entry envelopes do not implicitly grant `llm_prompt`; prompt entry is a
  separate execution surface checked before `local_agent.run()`.
- Tool permission failures after prompt entry are local execution-surface
  failures, not PQ-CAN signature-gate rejects. Wrapped tool calls expose
  `tool_not_authorized`; lower-level unsigned surfaces expose
  `unauthorized_tool_scope`, `unauthorized_memory_read`,
  `unauthorized_memory_write`, or `unauthorized_delegation`.
- `CodeAgent` must not auto-inject unwrapped `smolagents` base tools. Runtime
  business tools are the explicit config tools wrapped by the local execution
  gate; the intrinsic code executor is treated as part of prompt execution, not
  as an extra authorization grant.

## Cryptography Status

`ToyLWESignatureScheme` is non-production research code used for deterministic
tests and wiring experiments. It does not provide real post-quantum security.

Runtime-auth configuration distinguishes the current research modes from the
future production-facing adapter path:

- `toy_compiled_research` uses toy LWE signing with the compiled fixed verifier
  and Shamir CAN. This is the default for legacy `verifier_flavor: compiled`
  configs and remains non-production.
- `toy_wrapper` uses toy LWE signing with the wrapper verifier for comparison
  tests. This is also non-production.
- `mldsa_external` is reserved for explicit wiring to a vetted external ML-DSA
  backend. The current config-driven helper fails closed for this mode, rather
  than falling back to toy signing or silently accepting missing backend state.

`MLDSAAdapter` is the production-facing integration point. It must wrap a vetted
external ML-DSA implementation. This repository must not implement production
ML-DSA from scratch.

The current compiled toy verifier has a deliberately narrow boundary:

- fixed circuit: public matrix projections over the decoded signature and
  challenge vectors;
- deterministic preprocessing: byte decoding and domain-separated SHA-256
  challenge derivation;
- deterministic hard gates: modular subtraction, coordinate equality, and
  all-coordinate acceptance aggregation.

The SHA-256 challenge derivation is not implemented as a neural hash circuit.
Future work may move more arithmetic gadgets into fixed modules, but the current
security claims and tests must describe the preprocessing boundary explicitly.

Current PQ-CAN request signing protects request authentication only. Unless a
separate post-quantum key exchange or PQ TLS story is added, this repository
does not claim full post-quantum security for the complete communication stack.

## Generated Material

Do not commit private keys, generated credentials, local databases, model
checkpoints, experiment runs, or agent workdir audit/diagnostic outputs.
Generated test keys should live in test-created temporary directories.

Ignored runtime paths include:

- `experiments/results/`
- `experiments/runs/`
- `saga/user/*/audit/`
- `saga/user/*/diagnostics/`

## Security Testing Scope

Security tests in this repository are defensive. They verify fail-closed
behavior for invalid signatures, real-valued verifier inputs, context mismatch,
scope mismatch, stale envelopes, missing signature material, and unauthorized
execution surfaces.

Current negative coverage should include:

- `missing_request_envelope`
- `missing_pq_signature`
- `invalid_request_envelope`
- `untrusted_sender_aid`
- `sender_aid_mismatch`
- `receiver_aid_mismatch`
- `token_digest_mismatch`
- `message_digest_mismatch`
- `action_scope_mismatch`
- `envelope_not_yet_valid`
- `envelope_expired`
- `signature_verification_failed`
- unauthorized `tool_call:<tool_name>`
- unauthorized `memory_write`
- unauthorized `delegation`
- policy-rejected entry actions and scope-escalation proposals
- wrapped tool calls rejected as `tool_not_authorized`
- real-valued signature/verifier input rejection
- raw OTK-only signatures and cross-AID OTK signature replay rejection

The offline runner `experiments/negative_injection_runner.py` provides a
deterministic batch entrypoint for the PQ-CAN-specific negative cases:

```bash
.venv/bin/python experiments/negative_injection_runner.py
```

It writes `negative_injections.jsonl` and
`negative_injections_summary.json` under an ignored `experiments/runs/`
directory by default. The runner is defensive only: it mutates signed request
material and execution scopes to verify fail-closed behavior, and it does not
implement exploit payload generation.

`experiments/real_negative_runner.py` provides an opt-in real-service negative
entrypoint. It starts or reuses local MongoDB, the CA file server, and Provider,
launches a real receiving `Agent.listen()` socket listener, then sends a
negative runtime-auth payload through the normal Provider/token/TLS/socket path:

```bash
.venv/bin/python experiments/real_negative_runner.py run --scenario all
```

The current real-service scenarios are `missing_request_envelope`,
`tampered_message`, `prompt_surface_tool_only`, `replayed_envelope`,
`wrong_trusted_sender_key`, `unauthorized_tool_scope`,
`unauthorized_memory_write`, and `unauthorized_delegation`. The query side
overrides only the post-handshake conversation payload, so the protocol
admission path remains real while the run does not call the model backend.
Results are written under ignored `experiments/runs/` paths. The runner is
defensive only. For envelope/signature/prompt/replay failures, it checks the
expected execution-gate audit reason and verifies that the recording local
agent is not invoked. For tool/memory/delegation scope probes, it allows one
signed prompt run, then verifies that `LocalExecutionContext` rejects the
unsigned downstream action and that no protected side-effect record is written.

`experiments/ablation_overhead_runner.py` provides an offline ablation and
micro-overhead entrypoint:

```bash
.venv/bin/python experiments/ablation_overhead_runner.py
```

It compares `SAGA only`, ordinary byte-level PQ middleware, naive neural
verification without Shamir MASK, and Shamir-secured PQ-CAN on deterministic
positive/negative cases. It also records local timing metrics for toy signing,
ordinary verification, compiled verification, Shamir CAN, and execution-gate
evaluation.

Real experiment runs through `experiments/batch_run.py` now aggregate
end-to-end task statistics into `end_to_end_stats_summary.json` under the run
directory. Task result JSONL rows include task latency, local/peer model-call
attempt counts, LLM elapsed time from runtime diagnostics, execution-gate audit
record counts, and logging-stat collection latency. API cost and token usage
are reported only when the underlying model diagnostics expose explicit
cost/usage fields; otherwise the records mark them unavailable instead of
estimating prices.

`experiments/paper_tables.py` converts those batch summaries into stable
run-level and task-level paper-table rows:

```bash
.venv/bin/python experiments/paper_tables.py --format markdown
```

The default inputs are the `2026-05-27` baseline and PQ-CAN three-task runs.
The table columns preserve wall-clock task latency, model-call counts, LLM
elapsed time, execution-gate audit counts, logging-stat collection latency, and
explicit cost/token availability flags. Tool permission text or model parsing
retries are not counted as PQ-CAN execution-gate rejects unless they appear as
execution-gate audit records.

`experiments/end_to_end_validation.py` validates saved run artifacts without
starting services or using the model backend. It is the current F6 acceptance
check for end-to-end evidence:

- positive baseline summaries must have runtime auth disabled, all tasks
  successful, and zero execution-gate reject counts;
- positive PQ-CAN summaries must have runtime auth enabled, all tasks
  successful, and zero execution-gate reject counts;
- real-service negative summaries must report all scenarios passed;
- real-service negative JSONL rows must match expected audit reasons and must
  show `side_effect_triggered=false` and `local_agent_run_count=0`.
