# Strict Runtime-Auth Evidence Summary

This file is the paper-facing index for the SAGA-PQ-CAN strict runtime-auth
proof-hardening evidence. It summarizes what is claimed, which artifacts support
the claim, and which paths remain outside the claim.

## Core Claim

```text
Execute(surface) => N_verify=1 AND scope_ok AND replay_ok AND delegation_ok AND policy_ok
```

The claim is sink-centric. It covers the strict runtime-auth security kernel
protected sinks listed in `saga/security_kernel.py`; it does not claim that all
Python code in this repository is impossible to call directly.

## Covered Boundary

Covered paths:

- receiving-side prompt execution through `Agent.receive_conversation`
- initiating-side signed response prompt execution through `Agent.initiate_conversation`
- wrapped business tool calls
- gated business backend methods
- memory read/write through the capability facade
- first-class delegation through the capability facade
- request-envelope replay consume/reserve

Excluded or limited paths:

- legacy compatibility paths without strict runtime auth
- `experiments/` harnesses unless they explicitly opt into runtime auth
- `saga/attack_models/` historical copies
- arbitrary raw backend or memory object use outside the gated facade
- toy LWE production security claims
- full post-quantum transport security without a separate PQ key exchange story

## Proof Artifact Matrix

| Artifact | Role | Claim Contribution | Boundary |
| --- | --- | --- | --- |
| `proofs/strict_runtime_auth_model.py` | Python state exploration | Exhaustively checks the five abstract Boolean predicates for each protected surface. | Abstract model only, not whole-repo execution. |
| `proofs/tla/StrictRuntimeAuth.tla` | TLA+ guarded transition spec | Records `CanExecute(surface)`, `ExecuteSurfaceClaim`, and `ScopeCheckRequired`. | Full cfg is inventory-aligned but too large for default full TLC. |
| `proofs/tla/StrictRuntimeAuthSmoke.cfg` | Single-surface TLC smoke | Checks the invariant for one representative surface. | Bounded smoke model. |
| `proofs/tla/StrictRuntimeAuthPairSmoke.cfg` | Two-surface TLC smoke | Checks coexistence of two protected surfaces under the same invariant. | Bounded smoke model. |
| `proofs/tla/StrictRuntimeAuthLayered.tla` | Symmetry-reduced layered TLA+ model | Folds protected surfaces into prompt/tool/memory/delegation/replay layers and checks the same execute guard. | Layer abstraction, not full cfg exhaustive check. |
| `experiments/tlc_strict_runtime_auth_check.py` | Opt-in TLC runner | Generates per-surface cfgs, runs pair smoke, and runs the layered model. | TLC is not vendored or run by default. |
| `experiments/mutation_evidence_runner.py` | Non-destructive mutation runner | Confirms critical removed checks are detected by tests. | Mutates temporary workspace copies only. |
| `saga/security_kernel.py` | Kernel inventory and refinement table | Maps protected sinks, no-side-effect oracles, mutation targets, and model terms to Python symbols and tests. | Source of truth for strict-kernel boundary. |
| `experiments/security_evidence.py` | U9/U10 property map | Maps negative runners, real-service runners, and ablation modes to paper-level security properties. | Evidence map, not a verifier implementation. |

## TLC Model-Checking Summary

Latest local TLC run used `/tmp/tla2tools.jar` and wrote generated cfg/state
artifacts under `/tmp`; those generated artifacts are not committed.

| TLC Target | Generated States | Distinct States | Depth | Status |
| --- | ---: | ---: | ---: | --- |
| each per-surface generated cfg | 65 | 33 | 2 | checked |
| `StrictRuntimeAuthPairSmoke.cfg` | 3202 | 1089 | 3 | checked |
| `StrictRuntimeAuthLayered.cfg` | 325 | 165 | 2 | checked |
| `StrictRuntimeAuth.cfg` full inventory | at least 16777216 initial states in 60s | not completed | n/a | inventory artifact only |

The full inventory cfg expands five free Boolean predicate maps across all
protected surfaces. The checked evidence is therefore per-surface decomposition,
bounded pair smoke, and the layered symmetry-reduced model.

Do not cite the full cfg as a completed TLC run.

## Protected Sink Coverage

| Sink ID | Surface |
| --- | --- |
| `prompt_local_agent_run` | `llm_prompt` |
| `smolagents_tool_forward` | `tool_call:<tool_name>` |
| `business_backend_method` | `tool_backend_method` |
| `memory_read_facade` | `memory_read` |
| `memory_write_facade` | `memory_write` |
| `delegation_handler` | `delegation` |
| `replay_reserve_consume` | `request_envelope_replay` |

Each sink must have a no-side-effect oracle in `saga/security_kernel.py`. The
oracle contract is that unauthorized, tampered, replayed, or scope-escalated
requests reject before the protected prompt, tool, memory, delegation, or replay
side effect occurs.

## Mutation Evidence

| Mutation ID | Protected Term |
| --- | --- |
| `skip_prompt_surface_authorization` | `scope_ok` |
| `disable_local_execution_context_require_action` | `scope_ok` |
| `skip_replay_reserve` | `replay_ok` |
| `relax_action_scope_matching` | `scope_ok` |
| `bypass_gated_execution_resource` | `policy_ok` |
| `bypass_shamir_mask_real_valued_rejection` | `N_verify` |
| `bypass_delegation_parent_digest_check` | `delegation_ok` |
| `bypass_policy_compiler_scope_filter` | `policy_ok` |

The mutation runner treats only pytest test failures as valid detection
evidence. Pytest collection errors, usage errors, or environment failures are
not counted as successful mutation detection.

## Model Refinement Mapping

| Mapping ID | Model Term |
| --- | --- |
| `n_verify_to_signed_can_gate` | `N_verify` |
| `scope_ok_to_authorized_scope_checks` | `scope_ok` |
| `replay_ok_to_atomic_reserve` | `replay_ok` |
| `delegation_ok_to_parent_bound_capabilities` | `delegation_ok` |
| `policy_ok_to_local_intent_compiler` | `policy_ok` |
| `execute_surface_to_protected_sinks` | `Execute(surface)` |

The refinement table maps abstract model terms to Python symbols, evidence
tests, trusted-computing-base assumptions, excluded paths, residual risks, and
linked protected sinks. This keeps the formal model tied to implementation
evidence without claiming whole-repository non-bypassability.

## Paper-Level Security Properties

| Property ID | Property |
| --- | --- |
| `unforgeability` | Unforgeability of Execution Capabilities |
| `context_binding` | Context Binding |
| `scope_non_escalation` | Scope Non-Escalation |
| `replay_resistance` | Replay Resistance |
| `side_effect_free_rejection` | Side-Effect-Free Rejection |

These properties are mapped to offline negative injection evidence, opt-in
real-service negative evidence, and ablation evidence in
`experiments/security_evidence.py`.

## Non-Production Cryptography Boundary

The current toy LWE code and compiled toy verifier are research wiring evidence
only. They help validate deterministic signed-envelope gating, fixed neural
verification semantics, Shamir real-valued rejection, and protected sink
authorization. They do not provide production post-quantum security.
Production claims require a vetted external ML-DSA backend through the adapter path.
