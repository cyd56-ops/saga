"""Lightweight state exploration model for the strict runtime-auth kernel."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Literal

from saga.security_kernel import EXECUTE_SURFACE_CLAIM, protected_sink_audits


Decision = Literal["execute", "reject"]


@dataclass(frozen=True)
class RuntimeAuthState:
    """表示一个 protected sink 执行前的抽象授权状态。"""

    surface: str
    n_verify: bool
    scope_ok: bool
    replay_ok: bool
    delegation_ok: bool
    policy_ok: bool

    def required_terms(self) -> dict[str, bool]:
        """导出论文命题中的五个必要授权谓词。"""
        return {
            "N_verify": self.n_verify,
            "scope_ok": self.scope_ok,
            "replay_ok": self.replay_ok,
            "delegation_ok": self.delegation_ok,
            "policy_ok": self.policy_ok,
        }


@dataclass(frozen=True)
class RuntimeAuthTransition:
    """记录模型中一次从授权状态到执行或拒绝的抽象转移。"""

    state: RuntimeAuthState
    decision: Decision
    reason: str

    def violates_execute_claim(self) -> bool:
        """检查执行转移是否违反 strict kernel 的必要条件命题。"""
        return self.decision == "execute" and not all(self.state.required_terms().values())


@dataclass(frozen=True)
class ModelCheckReport:
    """保存一次 exhaustive state exploration 的检查结果。"""

    claim: str
    explored_state_count: int
    execute_transition_count: int
    reject_transition_count: int
    violations: tuple[RuntimeAuthTransition, ...]
    surfaces: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """当不存在违反执行必要条件的转移时返回 True。"""
        return not self.violations

    def as_dict(self) -> dict[str, object]:
        """生成可序列化报告，便于测试、文档和论文附录复用。"""
        return {
            "claim": self.claim,
            "explored_state_count": self.explored_state_count,
            "execute_transition_count": self.execute_transition_count,
            "reject_transition_count": self.reject_transition_count,
            "passed": self.passed,
            "surfaces": list(self.surfaces),
            "violations": [
                {
                    "surface": transition.state.surface,
                    "decision": transition.decision,
                    "reason": transition.reason,
                    "required_terms": transition.state.required_terms(),
                }
                for transition in self.violations
            ],
        }


def protected_model_surfaces() -> tuple[str, ...]:
    """返回模型覆盖的 protected sink surface 集合。"""
    return tuple(sorted({sink.surface for sink in protected_sink_audits()}))


def transition(state: RuntimeAuthState) -> RuntimeAuthTransition:
    """执行 strict runtime-auth kernel 的抽象 allow/reject 转移。"""
    if not state.n_verify:
        return RuntimeAuthTransition(state, "reject", "n_verify_reject")
    if not state.scope_ok:
        return RuntimeAuthTransition(state, "reject", "scope_reject")
    if not state.replay_ok:
        return RuntimeAuthTransition(state, "reject", "replay_reject")
    if not state.delegation_ok:
        return RuntimeAuthTransition(state, "reject", "delegation_reject")
    if not state.policy_ok:
        return RuntimeAuthTransition(state, "reject", "policy_reject")
    return RuntimeAuthTransition(state, "execute", "authorized")


def enumerate_states(
    surfaces: tuple[str, ...] | None = None,
) -> tuple[RuntimeAuthState, ...]:
    """枚举 protected surfaces 与五个授权谓词的所有布尔组合。"""
    selected_surfaces = surfaces or protected_model_surfaces()
    states: list[RuntimeAuthState] = []
    for surface in selected_surfaces:
        for n_verify, scope_ok, replay_ok, delegation_ok, policy_ok in product(
            (False, True),
            repeat=5,
        ):
            states.append(
                RuntimeAuthState(
                    surface=surface,
                    n_verify=n_verify,
                    scope_ok=scope_ok,
                    replay_ok=replay_ok,
                    delegation_ok=delegation_ok,
                    policy_ok=policy_ok,
                )
            )
    return tuple(states)


def check_execute_surface_claim(
    surfaces: tuple[str, ...] | None = None,
) -> ModelCheckReport:
    """穷举模型状态并验证 Execute(surface) 必要条件命题。"""
    states = enumerate_states(surfaces)
    transitions = tuple(transition(state) for state in states)
    violations = tuple(
        candidate for candidate in transitions if candidate.violates_execute_claim()
    )
    return ModelCheckReport(
        claim=EXECUTE_SURFACE_CLAIM,
        explored_state_count=len(states),
        execute_transition_count=sum(
            1 for candidate in transitions if candidate.decision == "execute"
        ),
        reject_transition_count=sum(
            1 for candidate in transitions if candidate.decision == "reject"
        ),
        violations=violations,
        surfaces=surfaces or protected_model_surfaces(),
    )


def mutated_transition_without_scope_check(
    state: RuntimeAuthState,
) -> RuntimeAuthTransition:
    """模拟删除 scope_ok 检查后的错误转移，用于证明测试能发现反例。"""
    if not state.n_verify:
        return RuntimeAuthTransition(state, "reject", "n_verify_reject")
    if not state.replay_ok:
        return RuntimeAuthTransition(state, "reject", "replay_reject")
    if not state.delegation_ok:
        return RuntimeAuthTransition(state, "reject", "delegation_reject")
    if not state.policy_ok:
        return RuntimeAuthTransition(state, "reject", "policy_reject")
    return RuntimeAuthTransition(state, "execute", "authorized")
