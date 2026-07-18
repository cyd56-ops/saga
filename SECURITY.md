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

The strict runtime-auth security kernel is now recorded as a testable inventory
in `saga/security_kernel.py`. It lists each execution entry and each protected
sink, the protected surface, the code paths that mediate it, evidence tests,
and residual risk. The final paper-facing claim is sink-centric and intentionally
narrower than "all Python code in the repository is impossible to bypass":

```text
Execute(surface) => N_verify=1 AND scope_ok AND replay_ok AND delegation_ok AND policy_ok
```

The protected sinks are local prompt execution, wrapped tool `forward(...)`
calls, gated business backend methods, memory read/write facades, the
first-class delegation handler, and replay consume/reserve. The same inventory
also records sink-level no-side-effect oracles and first-stage mutation
evidence targets, so the claim is tied to tests that should fail if prompt
authorization, scope checks, replay reserve, gated backend mediation, or the
Shamir MASK real-valued rejection path are removed.
`experiments/mutation_evidence_runner.py` turns those targets into a
non-destructive executable check: it copies the repository to a temporary
workspace, applies each mutation to the copy, and treats only pytest test
failures as valid mutation detection evidence. The repository also includes a
first-stage lightweight model in `proofs/strict_runtime_auth_model.py`, a TLA+
specification in `proofs/tla/StrictRuntimeAuth.tla`, and a Python refinement
table in `saga/security_kernel.py`. The paper-facing index for these artifacts
is `proofs/strict_runtime_auth_evidence.md`, which records the core claim,
covered and excluded paths, TLC state counts, protected sinks, mutation
evidence, refinement mappings, U9/U10 properties, and the toy-cryptography
boundary. The Python model exhaustively explores the abstract `N_verify`,
`scope_ok`, `replay_ok`, `delegation_ok`, and `policy_ok` terms; the TLA+
artifact records the same guarded `Execute(surface)` transition and invariant
in a model-checker-friendly form. The checked-in
`StrictRuntimeAuthSmoke.cfg` bounds TLC to one representative protected surface
so the invariant can be model-checked locally; `StrictRuntimeAuthPairSmoke.cfg`
uses two protected surfaces as a bounded coexistence / non-interference smoke
model. `StrictRuntimeAuthLayered.tla` / `StrictRuntimeAuthLayered.cfg` is the
symmetry-reduced layered model: it folds the full surface inventory into
prompt, tool, memory, delegation, and replay layers, checks the same guarded
execute invariant over a selected layer representative, and separately checks
that the layer partition covers every protected surface. The latest local TLC
run completed this layered model with `325 states generated` and `165 distinct
states found`. `experiments/tlc_strict_runtime_auth_check.py` is the opt-in TLC
decomposition runner: it reads the full inventory cfg, generates one-surface
cfgs in an explicit output directory, runs TLC per surface, runs the layered
model by default, and writes a JSON summary. The full `StrictRuntimeAuth.cfg`
remains the inventory-aligned model and is expected to be much larger because
it expands five free Boolean predicate maps across all protected surfaces. The
refinement table maps those terms back to Python functions, evidence tests,
trusted-computing-base assumptions, excluded paths, and residual risks. TLC
itself is not vendored or run by default. The inventory is intentionally
conservative:

- Covered entries include receiving-side prompt execution, initiating-side
  response prompt execution, wrapped business tool calls, wrapper-mediated
  memory reads/writes, and the first-class delegation helper.
- Compatibility fallbacks such as `no_execution_gate` and
  `legacy_prompt_without_execution_context` are excluded from PQ-CAN security
  claims. In strict mode a missing gate fails as `missing_execution_gate`, a
  gate without the shared Coordinator fails as `missing_runtime_auth_coordinator`,
  a missing committed Context fails as `missing_local_execution_context`, and a
  compatibility-created Context fails as `uncommitted_local_execution_context`.
  These checks occur before either receiving-side or response-side prompt
  execution can call `local_agent.run()`.
- Custom `LocalAgent` implementations in strict runtime-auth mode must declare
  `supports_execution_context() == True` before `local_agent.run()` is called.
  Context-ignoring implementations fail closed with
  `local_agent_execution_context_unsupported` even when the signed prompt
  envelope is otherwise valid. Non-strict compatibility mode remains excluded
  from PQ-CAN security claims.
- Historical attack-model copies and experiment harnesses are not part of the
  active runtime kernel unless they explicitly opt into runtime auth. They may
  retain legacy helper code used for reproduction or adversary scenarios; those
  copies are not evidence of an allowed bypass in the strict runtime-auth
  protected-sink claim.

### Runtime Auth Coordinator

Strict runtime auth separates evaluation from state commit:

- `RuntimeAuthCoordinator.evaluate(request)` returns immutable `RouteEvidence`
  and `CompositeEvidence`. It may read verification, policy, time-window, and
  revocation facts, but it does not reserve replay state or create a
  `LocalExecutionContext`.
- `RuntimeAuthCoordinator.commit(evidence)` re-evaluates the request, rechecks
  current revocation and time-window facts, compares a fingerprint covering the
  envelope, signature, transport bindings, and runtime parameters, atomically
  reserves replay state, and only then creates a Coordinator-marked Context.
- A repeated or concurrent commit can create at most one Context. Replay-store
  failure, changed evidence, non-canonical runtime parameters, invalid composite
  evidence, or Context construction failure is fail-closed.

`SignedRequestExecutionGate` defaults to strict Coordinator mode. In this mode,
legacy `authorize(...)`, `consume_request(...)`, direct
`build_local_execution_context(...)`, and direct Context-from-decision helpers
cannot grant executable authority. Explicit `compatibility` mode retains those
APIs only for historical tests, diagnostics, and declared non-strict paths; its
Contexts are marked uncommitted and are rejected by strict prompt enforcement.
The private commit/context primitives are implementation details inside the
security runtime kernel, not supported public authorization entry points.

This first Coordinator closes the supported in-process bypass but is not yet a
cross-backend transaction. With file-marker replay state, a crash after replay
reserve but before Context delivery can permanently reject a legitimate retry.
Atomic persistence of replay, revocation version, decision/capability state, and
audit outbox remains R17 work and is required before stronger crash-consistency
or multi-host availability claims.

Experiment, paper-reproduction, and demonstration code is not part of the
mandatory runtime security boundary for the PQ-CAN prototype. In particular,
`experiments/`, `proofs/`, `saga/attack_models/`, and most of `agent_backend/`
are evidence, harness, or demo layers unless a specific test or experiment
explicitly opts into them. These directories must not be treated as required
authorization bypass paths for the active runtime gate. Main-code hygiene fixes
apply to the SAGA/PQ-CAN kernels above; historical copied attack-model files are
documented as excluded paths rather than silently folded into the strict-kernel
claim.

The effective authorization rule is:

```text
allow = saga_token_valid
    AND request_envelope_valid
    AND pq_signature_valid
    AND can_accept
    AND execution_scope_allowed
    AND internal_policy_accept
```

## Paper-Facing Security Properties

The current U9/U10 claim surface is intentionally scoped to the strict runtime
kernel above. It does not cover legacy compatibility paths, raw backend use
outside gated facades, or production post-quantum security for toy LWE code.
Runtime-auth configuration now exposes an explicit `enforcement_mode`.
`strict` is the security default. `permissive` may continue execution only
while recording `would_reject` audit rows with a `downgrade_reason`; `disabled`
is reserved for offline ablations and is outside the strict-kernel claim.

The paper-level properties are:

- **Unforgeability of execution capabilities**: a request is accepted only when
  the sender AID maps to a trusted public key and the detached post-quantum
  signature verifies over the canonical signed intent capability envelope
  digest. Toy LWE tests are wiring evidence only; production claims require a
  vetted ML-DSA backend.
- **Context binding**: a signature is bound to sender, receiver, token digest,
  message digest, action scope, time window, session, turn, provider, and
  capability metadata. Moving signed material to another context must reject.
- **Scope non-escalation**: a request cannot gain authority beyond signed
  `authorized_scopes` compiled from local policy; delegated child capabilities
  must attenuate rather than expand parent scope.
- **Replay resistance**: each signed envelope digest can be consumed at most
  once on the execution path. Duplicate consumption, restart replay,
  write-failure, and concurrent reservation races fail closed.
- **Side-effect-free rejection**: rejected prompt, tool, memory, and delegation
  requests must return, drop, or audit before triggering the protected local
  action.

`experiments/security_evidence.py` is the machine-readable U9/U10 evidence map.
It records the property statements, the negative-runner scenario mappings, the
real-service negative-runner mappings, and the ablation-mode expectations used
by the tests and paper tables.

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
  same envelope with `replayed_request_envelope`. The helper fails closed at
  setup if neither an agent workdir nor an explicit `ReplayStateStore` is
  available; it must not silently fall back to memory-only replay state. If
  replay state cannot be written during request consumption, the execution path
  fails closed with `replay_state_persistence_failed`. Concurrent consumption
  of the same envelope is serialized at the gate layer, and atomic store
  backends must reserve the request id exactly once.
- Runtime auth can instead point multiple local workdirs at one explicit
  `replay_store.backend: file_marker` directory, or inject a
  `ReplayStateStore` backend with atomic `reserve_request` semantics. The
  checked-in file-marker store is a defensive prototype for local/dev/test
  shared-filesystem experiments; full multi-host consistency still requires an
  external strongly consistent backend. `SQLiteReplayStateStore` provides a
  checked-in SQL-style adapter for local research and tests; it relies on a
  primary-key insert as the atomic reservation step and does not claim
  deployment-grade distributed consistency. `RedisReplayStateStore` wraps an
  injected Redis client and relies on `SET ... NX` as the atomic reservation
  step. Redis service selection, authentication, network policy, and retention
  are deployment concerns and must be configured outside this repository. The
  legacy `replay_state_dir` setting remains accepted only as compatibility
  syntax for the same file-marker backend.
- SAGA one-time-key signatures are bound to the receiving agent identity. The
  signed payload is a domain-separated canonical object containing `aid` and
  the raw OTK bytes; raw OTK-only signatures and cross-AID signatures must fail
  closed at Provider registration/refresh and initiating-side OTK verification.
- Execution-gate decisions expose the six authorization formula terms in
  `authorization_formula`: `saga_token_valid`, `request_envelope_valid`,
  `pq_signature_valid`, `can_accept`, `execution_scope_allowed`, and
  `internal_policy_accept`.
- Execution-gate audit records are appended to
  `<agent workdir>/audit/execution_gate.jsonl` as a local hash chain. Each new
  chained record carries `seq`, `prev_hash`, and `entry_hash`, where
  `entry_hash` is computed over a stable canonical JSON representation of the
  record without the `entry_hash` field itself. Existing plain JSONL rows are
  accepted as a legacy prefix and are anchored by the first chained append. This
  local chain detects middle-of-chain deletion or modification after a chained
  tail exists; it does not by itself prevent truncation of the most recent
  records. Detecting tail truncation requires storing the latest `entry_hash`
  in an external append-only anchor or checkpoint.
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
- Signed request envelopes are treated as signed intent capabilities. The
  canonical payload includes `capability_id`, `parent_envelope_digest`,
  `parent_authorized_scopes`, `parent_scope_constraints`,
  `delegation_depth`, `max_delegation_depth`, and optional
  `execution_budget`. A delegated child capability must bind a known parent
  envelope digest, the parent scopes and parameter constraints must match the
  local parent-capability fact source, every child `authorized_scope` must be
  attenuated from the parent scope set, and every parent parameter constraint
  that applies to the child capability must be preserved or narrowed. Deleting
  a parent constraint, relaxing a predicate, or moving a narrow parent
  constraint to a wider child scope fails closed before local execution.
- `execution_budget` is a signed JSON object whose keys are `total` or action
  scopes such as `tool_call:send_email`; values are non-negative integer use
  limits. `LocalExecutionContext.require_action(...)` consumes matching budgets
  before protected tool, memory, and delegation side effects. A
  `CapabilityStateStore` backend must atomically debit the global `total`
  budget and all matching per-scope budgets. The checked-in
  `SQLiteCapabilityStateStore` is the first local SQL-style contract proof. It
  uses SQLite transactions and a compound key of `capability_id`,
  `envelope_digest`, and budget scope; it does not claim distributed
  consistency. File-marker replay stores are not budget backends. Missing,
  unavailable, conflicting, or exhausted budget state fails closed before the
  protected action runs.
- Runtime-auth signed capabilities default to a short TTL of 300 seconds,
  capped by the SAGA token expiry. This changes only the capability envelope
  lifetime; it does not extend or weaken token validation. Config may lower or
  raise `capability_ttl_seconds`, but the value must be a positive integer.
- Revocation is checked after request envelope binding, time-window validation,
  execution-scope validation, PQ/CAN signature verification, and before
  `LocalExecutionContext` construction. A `RevocationStore` can revoke a single
  signed capability by `capability_id` or cascade-revoke delegated children by
  `parent_envelope_digest`. The checked-in `SQLiteRevocationStore` is a local
  SQL-style contract proof and does not claim distributed consistency.
  Configured revocation-store lookup failure fails closed as
  `revocation_store_unavailable`; revoked entries fail closed as
  `capability_revoked` or `parent_capability_revoked`.
- The first online invariant monitor sits at `ExecutionCapabilityFacade` and
  the protected sink wrappers. It records whether a sink action was authorized
  or violated, binds the event to the public capability id and envelope digest
  when a `LocalExecutionContext` is present, and logs only parameter key names,
  not parameter values. Missing strict context, unauthorized scopes, budget
  exhaustion, budget-store failures, and monitor backend failures all fail
  closed before the protected sink runs. `JSONLExecutionInvariantMonitor` is a
  local audit adapter, not a distributed monitor.
- The first IFC slice is an explicit signed egress contract, not full automatic
  language-level taint tracking. `flow_policy` is part of the canonical signed
  envelope and defines which labels may flow to selected egress scopes. Runtime
  transforms join labels monotonically; a label not allowed by the egress policy
  can leave only when the same signed capability also carries
  `declassify:<label>`. `ExecutionCapabilityFacade.call_egress(...)` checks the
  normal action scope, the flow policy, and required declassification before the
  protected egress operation runs. Missing declassification fails closed as
  `ifc_declassify_scope_required`; tampering with `flow_policy` invalidates the
  detached signature.
- Tool permission failures after prompt entry are local execution-surface
  failures, not PQ-CAN signature-gate rejects. Wrapped tool calls expose
  `tool_not_authorized`; capability-facade failures expose
  `unauthorized_tool_scope`, `unauthorized_memory_read`,
  `unauthorized_memory_write`, or `unauthorized_delegation`.
- `CodeAgent` must not auto-inject unwrapped `smolagents` base tools. Runtime
  business tools are the explicit config tools wrapped by the local execution
  gate; the intrinsic code executor is treated as part of prompt execution, not
  as an extra authorization grant.
- Agent-wrapper tool backends, memory helpers, and delegation callbacks must be
  exposed through `ExecutionCapabilityFacade` / `GatedExecutionResource` in the
  strict runtime kernel. Direct use of raw backend clients or raw downstream
  memory objects outside that facade remains outside the current security claim.
- Strict runtime-auth paths require the local-agent implementation to opt into
  execution-context enforcement via `supports_execution_context()`. The checked
  in `AgentWrapper` does this because its tool, memory, and delegation surfaces
  are mediated by the propagated `LocalExecutionContext`.

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

The generic adapter accepts a verification result only when the backend returns
the built-in `bool` value `True`. It does not coerce strings, integers, arrays,
or other truthy objects. `verify_with_evidence(...)` records a stable,
fail-closed reason for an unavailable or malformed backend, a backend exception,
an invalid backend result type, or an ordinary invalid signature. Diagnostic
exception messages are not copied into this evidence. This strict adapter
contract does not itself constitute a vetted ML-DSA backend integration.

### Signature Binding V1

Dual-route signatures use `SignatureBindingV1` as the complete message supplied
to a signature profile. Its canonical binary representation is an ordered,
length-prefixed TLV structure with a fixed magic, version, and field count. It
binds the route, algorithm, opaque key ID, signature profile, envelope digest
algorithm, envelope canonicalization version, and envelope digest. Signature
bytes are not part of the envelope digest or this binding message.

V1 fixes the envelope side to SHA-256 over SAGA request-envelope canonical JSON
V1. Key IDs are non-empty opaque byte strings of at most 64 bytes. The decoder
rejects unknown versions, fields, routes, algorithms, profiles, digest or
canonicalization identifiers; duplicate or out-of-order fields; non-canonical
field widths; truncated or trailing data; and oversized material.

Route A currently accepts only the explicitly non-production toy LWE research
relation and its direct profile. Route B accepts only ML-DSA-44, ML-DSA-65, or
ML-DSA-87 with either the pure ML-DSA profile or an explicit HashML-DSA profile
for SHA-256, SHA-512, SHAKE128, or SHAKE256. The ML-DSA application context is
fixed as `SAGA-PQ-CAN-SignatureBindingV1`.

For the pure profile, the vetted backend receives the canonical binding bytes
directly through its pure ML-DSA interface. For a HashML-DSA profile, the vetted
backend must apply the profile's standard pre-hash to those same binding bytes.
Callers must not manually pre-hash the binding and then label that operation as
HashML-DSA. The explicit Route B shim and cryptography/OpenSSL backend live on
the independent Route B branch; integration must still preserve the selected
profile, parameter set, context, backend version, and fail-closed behavior.

The current compiled toy verifier has a deliberately narrow boundary:

- fixed circuit: public matrix projections over the decoded signature and
  challenge vectors;
- deterministic preprocessing: byte decoding and domain-separated SHA-256
  challenge derivation;
- deterministic hard gates: modular subtraction, coordinate equality, and
  all-coordinate acceptance aggregation.

The SHA-256 challenge derivation is not implemented as a neural hash circuit.
The A0 verifier therefore remains a partially compiled research shadow rather
than a complete neural signature verifier.

Route A A0 shadow execution uses an explicitly non-authoritative boundary:

- shadow jobs contain immutable public key, message, and signature bytes only;
- the queue and in-memory evidence outbox are bounded;
- queue-full, closed, timeout, verifier-error, invalid-output, and reference
  disagreement states produce late evidence with `authority_granted=False`;
- evidence contains a domain-separated job digest and stable error type, not
  the public material or exception message;
- a timed-out verifier call keeps its bounded call slot until it returns, so a
  stuck verifier cannot cause unbounded retry-thread creation;
- outbox failure changes only shadow metrics and cannot authorize execution.

The Route A A0.5 toolchain is also research-only. `FixedEquality`,
`FixedRangeNormCheck`, and `FixedBooleanAggregator` use fixed Linear/ReLU
modules over declared bounded integer domains. Dense and tiny negacyclic
projectors compile through the same `FixedProjectorCore`; numeric manifests
reject configurations whose worst-case output exceeds the exact IEEE-754
integer range used by this prototype. Input guards reject bool, non-integral
values, NaN, Inf, wrong widths, and declared-bound violations before those
fixed modules run.

The A0.5 gate runner may report preliminary passes for AG1 and AG4-AG8, but it
always leaves AG2 and AG3 open. It does not contain an end-to-end A1 verifier,
and `FixedModReduce` explicitly uses ordinary Python `%` as a deterministic
hard gate. Consequently, the current report is migration and toolchain
evidence, not proof of a complete fixed-circuit verifier and not production
post-quantum authentication.

Route A A1 adds `FullReLUToyLWEVerifier` and a complete claimed toy arithmetic
core after preprocessing. The core uses the shared dense projector, fixed
subtraction, `FixedBoundedModulo`, fixed equality, range/L1 checks, and fixed
Boolean aggregation. `FixedBoundedModulo` expands a finite integer domain into
a construction-time fixed number of ReLU thresholds; it rejects configurations
above 65,536 thresholds rather than allocating unbounded circuit state.

The A1 boundary is deliberately narrower than the byte-level verifier API:

- strict byte decoding, bit packing, and domain-separated SHA-256 challenge
  derivation are deterministic preprocessing, not claimed neural circuits;
- software guards enforce exact widths, built-in numeric types, finite
  `[0,1]` CAN inputs, binary bit vectors, and bounded integer vectors;
- the claimed arithmetic evaluator list is statically audited for Python `%`,
  ordinary `==/!=`, data-dependent `if/while/match`, and calls to a reference
  `verify()` method;
- numeric manifests bound every compiled projection/modulo intermediate below
  the exact IEEE-754 integer limit used by the fixed Linear implementation;
- the A1 object contains public toy parameters only and no signing private key.

The current A1 gate report passes AG1-AG8 with 20,736 exhaustive tiny relation
cases, 32 deterministic default-parameter differential cases, 1,025 bounded
modulo cases, two projector backends, and six deletion witnesses. This is a
testable closure of the declared toy arithmetic core, not a proof of toy scheme
security, a neural SHA-256 implementation, or production post-quantum security.
The A1 verifier is not wired as execution authority; Route B and the shared
Coordinator remain the production-facing enforcement direction.

Route A A2 adds a research-only module-lattice relation and fixed
negacyclic-convolution verifier. Its security boundary is deliberately narrow:

- `ToyModuleLatticeSignatureScheme` defines `A(z-c) mod q = t` only as an
  independent reference oracle. The response exposes secret-related linear
  information, so the construction is not unforgeable and must never be used
  for real authentication.
- The signing secret is returned to the caller by test-only `keygen()` and is
  consumed only by `sign()`. `FixedModuleLatticeVerifier` stores public matrix,
  parameters, public inputs, and fixed modules; it does not store private key
  bytes.
- Each public module-matrix polynomial is expanded at construction time into a
  `TinyNegacyclicProjector`. Runtime ring arithmetic reuses the same
  `FixedProjectorCore` as A0.5, followed by fixed module sum, subtraction,
  bounded modulo, equality, coordinate/L1 checks, exact one-hot challenge
  weight, and hard Boolean aggregation.
- The claimed A2 evaluators inherit the A1 source audit and add module
  projection/relation symbols. Python `%`, ordinary `==/!=`, data-dependent
  branch nodes, and calls to a reference `verify()` are forbidden in that
  claimed runtime core.
- uint16 public-target parsing, int16 response parsing, bit packing, SHA-256
  one-hot challenge derivation, and negacyclic matrix expansion are explicit
  preprocessing or construction-time steps outside the claimed circuit.
- Software guards reject wrong rank/degree/length, bool, non-binary real bits,
  NaN, Inf, coefficients outside the compiled domain, response norm overflow,
  and challenges whose L1 weight is not exactly one. Rejection produces no
  execution authority.

The A2 gate report has zero mismatches over 2,025 exhaustive tiny ring cases
and 64 seeded rank-2 cases, detects six deletion witnesses, and records fixed
state, numeric bounds, structural complexity, latency, and Python peak memory.
This evidence establishes only the first fixed-ring relation checkpoint. It is
not a Module-SIS security proof, CNN/NTT implementation, neural SHA-256,
neuralized ML-DSA, or production post-quantum authentication. Route B and the
shared Coordinator remain the production-facing enforcement direction.

`CAN` now applies a finite `[0,1]` software guard before Shamir MASK. Values
inside the interval but outside the binary set still reach MASK and reject;
bool, NaN, Inf, and values below zero or above one reject before fixed layers.

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
- direct tool backend / memory facade / delegation facade bypass attempts
- custom `LocalAgent` implementations that ignore `execution_context`
- replay after receiver restart, replay-store write failure, and concurrent
  duplicate-envelope consumption
- policy-rejected entry actions and scope-escalation proposals
- delegated child capabilities with missing/unknown parent digest, mismatched
  parent scopes, scope expansion, or delegation-depth overflow
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

`experiments/mutation_evidence_runner.py` provides a non-destructive mutation
evidence entrypoint for the strict runtime-auth kernel:

```bash
.venv/bin/python experiments/mutation_evidence_runner.py --mutation all
```

It covers the current P4 mutation targets: bypassing prompt-surface
authorization, disabling `LocalExecutionContext.require_action`, skipping
replay reserve, relaxing action-scope matching, bypassing gated backend
resources, accepting unsafe real-valued CAN inputs when the Shamir MASK fires,
trusting delegated child-declared parent scopes without a known parent envelope
digest, and signing requested scopes without the local policy compiler scope
filter. Results are written under ignored `experiments/runs/` paths by default.
The runner is defensive only: mutations are applied to temporary workspace
copies, never to the active working tree, and pytest collection or environment
errors are not counted as successful detection.

`experiments/proof_hardening_check.py` provides an opt-in acceptance wrapper for
the proof-hardening evidence:

```bash
.venv/bin/python experiments/proof_hardening_check.py
```

It runs the focused proof tests, runs the mutation evidence runner, and then
validates the mutation artifacts with the same strict artifact validator used by
`experiments/end_to_end_validation.py`. This command is intentionally optional
because the mutation run copies workspaces and invokes pytest once per mutation.
Use `--skip-mutations` for a fast proof-test-only check.

The same check is also available as a manual-only GitHub Actions workflow:
`.github/workflows/proof-hardening.yml`. It is triggered with
`workflow_dispatch`, uploads the proof-hardening summary as an artifact, and is
not part of the default push or pull-request path.

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

For U10, the current ablation interpretation is:

- `saga_only`: protocol admission only; it does not reject the current signed
  envelope or execution-scope negative cases.
- `ordinary_pq_middleware`: rejects envelope/signature failures, but not
  prompt/tool scope misuse or Shamir real-valued input misuse.
- `naive_neural_verifier`: matches byte-level verifier behavior on binary
  signed material, but omits Shamir MASK and execution-scope policy.
- `shamir_secured_pq_can`: rejects the current offline negative set covering
  envelope binding, time window, prompt/tool scope, and real-valued signature
  input.

`tests/test_security_evidence.py` locks this mapping against the actual
negative runner, real-service runner, and ablation runner constants.

Real experiment runs through `experiments/batch_run.py` now aggregate
end-to-end task statistics into `end_to_end_stats_summary.json` under the run
directory. Task result JSONL rows include task latency, local/peer model-call
attempt counts, LLM elapsed time from runtime diagnostics, execution-gate audit
record counts, and logging-stat collection latency. API cost and token usage
are reported only when the underlying model diagnostics expose explicit
cost/usage fields; otherwise the records mark them unavailable instead of
estimating prices.

`experiments/real_ablation_runner.py` is the opt-in bridge from saved or live
real task batches to an ablation-style summary:

```bash
.venv/bin/python experiments/real_ablation_runner.py summarize
```

The current real Agent runtime is wired for `saga_only` and
`shamir_secured_pq_can` end-to-end batches. `ordinary_pq_middleware` and
`naive_neural_verifier` remain offline-only modes in this prototype; the runner
marks them as `offline_only_not_live_wired` instead of fabricating real-service
results. The `preflight` subcommand can check the selected live-mode configs
without starting local services; `--model-probe` is explicit opt-in because it
uses the configured model endpoint:

```bash
.venv/bin/python experiments/real_ablation_runner.py preflight \
  --mode saga_only \
  --mode shamir_secured_pq_can \
  --model-probe \
  --output-dir experiments/runs/<run-id>-real-ablation-preflight
```

The `run` subcommand is explicit opt-in because it starts local services and
model-backed tasks.

`experiments/paper_tables.py` converts those batch summaries into stable
run-level and task-level paper-table rows:

```bash
.venv/bin/python experiments/paper_tables.py --format markdown
```

To archive both the machine-readable and reviewable forms, provide an output
directory:

```bash
.venv/bin/python experiments/paper_tables.py \
  --format markdown \
  --output-dir experiments/tables/20260527-positive-baseline-pqcan
```

The default inputs are the `2026-05-27` baseline and PQ-CAN three-task runs.
The table columns preserve wall-clock task latency, model-call counts, LLM
elapsed time, execution-gate audit counts, logging-stat collection latency, and
explicit cost/token availability flags. Tool permission text or model parsing
retries are not counted as PQ-CAN execution-gate rejects unless they appear as
execution-gate audit records. The same helper now also emits U9/U10 security
property and evidence rows from `experiments/security_evidence.py`, so paper
tables can cite the same mapping enforced by tests.

`experiments/end_to_end_validation.py` validates saved run artifacts without
starting services or using the model backend. It is the current F6 acceptance
check for end-to-end evidence:

- positive baseline summaries must have runtime auth disabled, a non-empty task
  list, all tasks successful, and zero execution-gate reject counts;
- positive PQ-CAN summaries must have runtime auth enabled, a non-empty task
  list, all tasks successful, and zero execution-gate reject counts;
- real-service negative summaries must contain a non-empty scenario list and
  report all scenarios passed;
- real-service negative JSONL rows must match expected audit reasons and must
  show `side_effect_triggered=false`. Signature/prompt/replay gate rejects must
  keep `local_agent_run_count=0`; tool/memory/delegation scope-probe rows must
  enter the prompt stub exactly once and still trigger no protected side effect.
- real-service negative `expected_reason` values must match the U10 evidence
  map, so an artifact cannot silently change the reason contract without
  updating `experiments/security_evidence.py` and its tests.
