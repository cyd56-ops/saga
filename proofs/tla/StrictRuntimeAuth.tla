---- MODULE StrictRuntimeAuth ----
EXTENDS TLC

\* Strict runtime-auth kernel abstraction for SAGA-PQ-CAN.
\* 该规格只覆盖 security kernel 清单中的 protected sinks，不覆盖 legacy 路径。

CONSTANTS Surfaces

ASSUME Surfaces /= {}

VARIABLES
    n_verify,
    scope_ok,
    replay_ok,
    delegation_ok,
    policy_ok,
    executed

Bool == BOOLEAN

Init ==
    /\ n_verify \in [Surfaces -> Bool]
    /\ scope_ok \in [Surfaces -> Bool]
    /\ replay_ok \in [Surfaces -> Bool]
    /\ delegation_ok \in [Surfaces -> Bool]
    /\ policy_ok \in [Surfaces -> Bool]
    /\ executed = [surface \in Surfaces |-> FALSE]

CanExecute(surface) ==
    /\ n_verify[surface]
    /\ scope_ok[surface]
    /\ replay_ok[surface]
    /\ delegation_ok[surface]
    /\ policy_ok[surface]

Execute(surface) ==
    /\ CanExecute(surface)
    /\ executed' = [executed EXCEPT ![surface] = TRUE]
    /\ UNCHANGED <<n_verify, scope_ok, replay_ok, delegation_ok, policy_ok>>

Reject(surface) ==
    /\ ~CanExecute(surface)
    /\ UNCHANGED <<n_verify, scope_ok, replay_ok, delegation_ok, policy_ok, executed>>

Next ==
    \E surface \in Surfaces:
        \/ Execute(surface)
        \/ Reject(surface)

Spec == Init /\ [][Next]_<<n_verify, scope_ok, replay_ok, delegation_ok, policy_ok, executed>>

ExecuteSurfaceClaim ==
    \A surface \in Surfaces:
        executed[surface] =>
            /\ n_verify[surface]
            /\ scope_ok[surface]
            /\ replay_ok[surface]
            /\ delegation_ok[surface]
            /\ policy_ok[surface]

\* Mutation oracle: removing scope_ok from CanExecute would violate this invariant.
ScopeCheckRequired ==
    \A surface \in Surfaces:
        executed[surface] => scope_ok[surface]

====
