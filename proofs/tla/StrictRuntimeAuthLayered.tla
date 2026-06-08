---- MODULE StrictRuntimeAuthLayered ----
EXTENDS TLC

\* Symmetry-reduced layered abstraction for the strict runtime-auth kernel.
\* 该规格把多个 protected sinks 折叠为少量 layer representative，避免全 surface 自由布尔映射状态爆炸。

CONSTANTS
    Surfaces,
    PromptLayer,
    ToolLayer,
    MemoryLayer,
    DelegationLayer,
    ReplayLayer,
    PromptLayerSurfaces,
    ToolLayerSurfaces,
    MemoryLayerSurfaces,
    DelegationLayerSurfaces,
    ReplayLayerSurfaces

Layers == {PromptLayer, ToolLayer, MemoryLayer, DelegationLayer, ReplayLayer}

DistinctLayers ==
    /\ PromptLayer # ToolLayer
    /\ PromptLayer # MemoryLayer
    /\ PromptLayer # DelegationLayer
    /\ PromptLayer # ReplayLayer
    /\ ToolLayer # MemoryLayer
    /\ ToolLayer # DelegationLayer
    /\ ToolLayer # ReplayLayer
    /\ MemoryLayer # DelegationLayer
    /\ MemoryLayer # ReplayLayer
    /\ DelegationLayer # ReplayLayer

LayerSurfaces(layer_id) ==
    CASE layer_id = PromptLayer -> PromptLayerSurfaces
      [] layer_id = ToolLayer -> ToolLayerSurfaces
      [] layer_id = MemoryLayer -> MemoryLayerSurfaces
      [] layer_id = DelegationLayer -> DelegationLayerSurfaces
      [] layer_id = ReplayLayer -> ReplayLayerSurfaces

LayerSurfaceUnion ==
    PromptLayerSurfaces
        \cup ToolLayerSurfaces
        \cup MemoryLayerSurfaces
        \cup DelegationLayerSurfaces
        \cup ReplayLayerSurfaces

LayerPartition ==
    /\ Layers /= {}
    /\ DistinctLayers
    /\ \A layer_id \in Layers:
        /\ LayerSurfaces(layer_id) /= {}
        /\ LayerSurfaces(layer_id) \subseteq Surfaces
    /\ LayerSurfaceUnion = Surfaces
    /\ \A left \in Layers:
        \A right \in Layers:
            left # right => LayerSurfaces(left) \cap LayerSurfaces(right) = {}

ASSUME Surfaces /= {}
ASSUME LayerPartition

VARIABLES
    layer,
    n_verify,
    scope_ok,
    replay_ok,
    delegation_ok,
    policy_ok,
    executed

Vars == <<layer, n_verify, scope_ok, replay_ok, delegation_ok, policy_ok, executed>>

Bool == BOOLEAN

Init ==
    /\ layer \in Layers
    /\ n_verify \in Bool
    /\ scope_ok \in Bool
    /\ replay_ok \in Bool
    /\ delegation_ok \in Bool
    /\ policy_ok \in Bool
    /\ executed = FALSE

CanExecute ==
    /\ n_verify
    /\ scope_ok
    /\ replay_ok
    /\ delegation_ok
    /\ policy_ok

Execute ==
    /\ CanExecute
    /\ executed' = TRUE
    /\ UNCHANGED <<layer, n_verify, scope_ok, replay_ok, delegation_ok, policy_ok>>

Reject ==
    /\ ~CanExecute
    /\ UNCHANGED Vars

Next ==
    \/ Execute
    \/ Reject

Spec == Init /\ [][Next]_Vars

LayerExecuteClaim ==
    executed =>
        /\ n_verify
        /\ scope_ok
        /\ replay_ok
        /\ delegation_ok
        /\ policy_ok

LayerCoverageClaim ==
    /\ layer \in Layers
    /\ LayerSurfaceUnion = Surfaces
    /\ \A layer_id \in Layers:
        /\ LayerSurfaces(layer_id) /= {}
        /\ LayerSurfaces(layer_id) \subseteq Surfaces

====
