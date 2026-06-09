"""Delegation and replay refinement model for the strict runtime-auth kernel."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Literal

from saga.security_kernel import EXECUTE_SURFACE_CLAIM


Decision = Literal["execute", "reject"]
ReplayReserveStatus = Literal["reserved", "replayed", "failed"]


DELEGATION_REPLAY_CLAIM = (
    "DelegateExecute => N_verify=1 AND scope_ok AND policy_ok AND "
    "parent_digest_present AND parent_digest_known AND "
    "parent_authorized_scopes_present AND parent_authorized_scopes_match AND "
    "child_scopes_attenuated AND delegation_depth_ok AND replay_reserved_once"
)
"""委托与 replay 子模型中的细化执行必要条件。"""


@dataclass(frozen=True)
class DelegationReplayState:
    """表示委托 capability 进入受保护副作用点前的细化状态。"""

    n_verify: bool
    scope_ok: bool
    policy_ok: bool
    parent_digest_present: bool
    parent_digest_known: bool
    parent_authorized_scopes_present: bool
    parent_authorized_scopes_match: bool
    child_scopes_attenuated: bool
    delegation_depth_positive: bool
    delegation_depth_within_limit: bool
    replay_already_seen: bool
    replay_reserve_status: ReplayReserveStatus

    def delegation_ok(self) -> bool:
        """汇总委托父摘要、scope 衰减和深度边界是否全部满足。"""
        return (
            self.parent_digest_present
            and self.parent_digest_known
            and self.parent_authorized_scopes_present
            and self.parent_authorized_scopes_match
            and self.child_scopes_attenuated
            and self.delegation_depth_positive
            and self.delegation_depth_within_limit
        )

    def replay_ok(self) -> bool:
        """判断 replay reserve 是否允许该信封第一次进入执行路径。"""
        return (not self.replay_already_seen) and self.replay_reserve_status == "reserved"

    def required_terms(self) -> dict[str, bool]:
        """导出与主模型五项谓词对应的汇总布尔条件。"""
        return {
            "N_verify": self.n_verify,
            "scope_ok": self.scope_ok,
            "replay_ok": self.replay_ok(),
            "delegation_ok": self.delegation_ok(),
            "policy_ok": self.policy_ok,
        }

    def detailed_required_terms(self) -> dict[str, bool]:
        """导出委托和 replay 子模型的细粒度必要条件。"""
        return {
            "N_verify": self.n_verify,
            "scope_ok": self.scope_ok,
            "policy_ok": self.policy_ok,
            "parent_digest_present": self.parent_digest_present,
            "parent_digest_known": self.parent_digest_known,
            "parent_authorized_scopes_present": self.parent_authorized_scopes_present,
            "parent_authorized_scopes_match": self.parent_authorized_scopes_match,
            "child_scopes_attenuated": self.child_scopes_attenuated,
            "delegation_depth_positive": self.delegation_depth_positive,
            "delegation_depth_within_limit": self.delegation_depth_within_limit,
            "replay_not_previously_seen": not self.replay_already_seen,
            "replay_reserved_once": self.replay_reserve_status == "reserved",
        }


@dataclass(frozen=True)
class DelegationReplayTransition:
    """记录委托与 replay 子模型中的一次执行或拒绝转移。"""

    state: DelegationReplayState
    decision: Decision
    reason: str
    side_effect_triggered: bool

    def violates_delegation_replay_claim(self) -> bool:
        """检查触发委托副作用的转移是否缺少任一细化必要条件。"""
        return self.side_effect_triggered and not all(
            self.state.detailed_required_terms().values()
        )

    def violates_execute_surface_claim(self) -> bool:
        """检查触发委托副作用的转移是否违反主 Execute(surface) 命题。"""
        return self.side_effect_triggered and not all(
            self.state.required_terms().values()
        )


@dataclass(frozen=True)
class DelegationReplayModelReport:
    """保存 delegation/replay 细化模型的一次穷举检查报告。"""

    claim: str
    parent_claim: str
    explored_state_count: int
    execute_transition_count: int
    reject_transition_count: int
    violations: tuple[DelegationReplayTransition, ...]
    linked_sink_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """当不存在违反细化命题的执行转移时返回 True。"""
        return not self.violations

    def as_dict(self) -> dict[str, object]:
        """生成可序列化报告，便于 proof summary 和测试复用。"""
        return {
            "claim": self.claim,
            "parent_claim": self.parent_claim,
            "explored_state_count": self.explored_state_count,
            "execute_transition_count": self.execute_transition_count,
            "reject_transition_count": self.reject_transition_count,
            "passed": self.passed,
            "linked_sink_ids": list(self.linked_sink_ids),
            "violations": [
                {
                    "decision": transition.decision,
                    "reason": transition.reason,
                    "side_effect_triggered": transition.side_effect_triggered,
                    "required_terms": transition.state.required_terms(),
                    "detailed_required_terms": transition.state.detailed_required_terms(),
                }
                for transition in self.violations
            ],
        }


def transition(state: DelegationReplayState) -> DelegationReplayTransition:
    """执行 delegation/replay 子模型的正常 fail-closed 转移。"""
    return _transition_with_options(
        state,
        check_parent_fact_source=True,
        check_replay_reserve=True,
    )


def enumerate_states() -> tuple[DelegationReplayState, ...]:
    """穷举委托父绑定、scope 衰减、深度和 replay reserve 的所有组合。"""
    states: list[DelegationReplayState] = []
    for (
        n_verify,
        scope_ok,
        policy_ok,
        parent_digest_present,
        parent_digest_known,
        parent_authorized_scopes_present,
        parent_authorized_scopes_match,
        child_scopes_attenuated,
        delegation_depth_positive,
        delegation_depth_within_limit,
        replay_already_seen,
    ) in product((False, True), repeat=11):
        for replay_reserve_status in ("reserved", "replayed", "failed"):
            states.append(
                DelegationReplayState(
                    n_verify=n_verify,
                    scope_ok=scope_ok,
                    policy_ok=policy_ok,
                    parent_digest_present=parent_digest_present,
                    parent_digest_known=parent_digest_known,
                    parent_authorized_scopes_present=parent_authorized_scopes_present,
                    parent_authorized_scopes_match=parent_authorized_scopes_match,
                    child_scopes_attenuated=child_scopes_attenuated,
                    delegation_depth_positive=delegation_depth_positive,
                    delegation_depth_within_limit=delegation_depth_within_limit,
                    replay_already_seen=replay_already_seen,
                    replay_reserve_status=replay_reserve_status,
                )
            )
    return tuple(states)


def check_delegation_replay_claim() -> DelegationReplayModelReport:
    """穷举 delegation/replay 状态并验证细化执行必要条件。"""
    states = enumerate_states()
    transitions = tuple(transition(state) for state in states)
    violations = tuple(
        candidate
        for candidate in transitions
        if candidate.violates_delegation_replay_claim()
        or candidate.violates_execute_surface_claim()
    )
    return DelegationReplayModelReport(
        claim=DELEGATION_REPLAY_CLAIM,
        parent_claim=EXECUTE_SURFACE_CLAIM,
        explored_state_count=len(states),
        execute_transition_count=sum(
            1 for candidate in transitions if candidate.decision == "execute"
        ),
        reject_transition_count=sum(
            1 for candidate in transitions if candidate.decision == "reject"
        ),
        violations=violations,
        linked_sink_ids=("delegation_handler", "replay_reserve_consume"),
    )


def mutated_transition_without_parent_fact_source(
    state: DelegationReplayState,
) -> DelegationReplayTransition:
    """模拟跳过父 capability 事实源检查后的错误委托转移。"""
    return _transition_with_options(
        state,
        check_parent_fact_source=False,
        check_replay_reserve=True,
    )


def mutated_transition_without_replay_reserve(
    state: DelegationReplayState,
) -> DelegationReplayTransition:
    """模拟跳过 replay reserve 检查后的错误委托转移。"""
    return _transition_with_options(
        state,
        check_parent_fact_source=True,
        check_replay_reserve=False,
    )


def _transition_with_options(
    state: DelegationReplayState,
    *,
    check_parent_fact_source: bool,
    check_replay_reserve: bool,
) -> DelegationReplayTransition:
    # 该顺序刻画受保护副作用触发前必须经过的 fail-closed 决策链。
    if not state.n_verify:
        return _reject(state, "n_verify_reject")
    if not state.scope_ok:
        return _reject(state, "scope_reject")
    if not state.policy_ok:
        return _reject(state, "policy_reject")
    if not state.parent_digest_present:
        return _reject(state, "missing_parent_envelope_digest")
    if check_parent_fact_source and not state.parent_digest_known:
        return _reject(state, "unknown_parent_envelope_digest")
    if not state.parent_authorized_scopes_present:
        return _reject(state, "missing_parent_authorized_scopes")
    if check_parent_fact_source and not state.parent_authorized_scopes_match:
        return _reject(state, "parent_authorized_scopes_mismatch")
    if not state.delegation_depth_positive:
        return _reject(state, "invalid_delegation_depth")
    if not state.delegation_depth_within_limit:
        return _reject(state, "delegation_depth_exceeded")
    if not state.child_scopes_attenuated:
        return _reject(state, "delegation_scope_escalation")
    if check_replay_reserve:
        if state.replay_already_seen:
            return _reject(state, "replayed_request_envelope")
        if state.replay_reserve_status == "failed":
            return _reject(state, "replay_state_persistence_failed")
        if state.replay_reserve_status == "replayed":
            return _reject(state, "replayed_request_envelope")
    return DelegationReplayTransition(
        state=state,
        decision="execute",
        reason="authorized",
        side_effect_triggered=True,
    )


def _reject(
    state: DelegationReplayState,
    reason: str,
) -> DelegationReplayTransition:
    # 拒绝转移不触发任何受保护副作用。
    return DelegationReplayTransition(
        state=state,
        decision="reject",
        reason=reason,
        side_effect_triggered=False,
    )
