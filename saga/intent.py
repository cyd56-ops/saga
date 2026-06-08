"""Policy-aware intent objects for SAGA-PQ-CAN execution scopes."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from saga.messages import action_scopes_allow, parse_action_scope


@dataclass(frozen=True)
class AgentIntent:
    """LLM 或本地 runtime 提出的执行 scope 请求。"""

    action_scope: str
    requested_scopes: tuple[str, ...] = ()
    justification: str = ""

    def __post_init__(self) -> None:
        """规范化并校验 intent 中的 scope 字段。"""
        parse_action_scope(self.action_scope)
        normalized = []
        for scope in self.requested_scopes:
            parse_action_scope(scope)
            normalized.append(scope)
        object.__setattr__(self, "requested_scopes", tuple(sorted(set(normalized))))


@dataclass(frozen=True)
class PolicyDecision:
    """本地 policy 对 intent scope proposal 的裁定结果。"""

    allowed_scopes: tuple[str, ...]
    rejected_scopes: tuple[str, ...]
    reason: str


class IntentCompiler:
    """Compile untrusted requested scopes into signed authorized scopes.

    LLM/requested scopes 只是 proposal；最终签名 scope 只能来自本地 policy 允许集合。
    """

    def __init__(self, policy_scopes: Iterable[str]) -> None:
        """保存本地 policy 允许的 scope 集合。"""
        normalized = []
        for scope in policy_scopes:
            parse_action_scope(scope)
            normalized.append(scope)
        self.policy_scopes = tuple(sorted(set(normalized)))

    def compile(self, intent: AgentIntent) -> PolicyDecision:
        """将 intent 编译为最终可签名的授权 scope 集合。"""
        requested = (intent.action_scope, *intent.requested_scopes)
        allowed = {
            requested_scope
            for requested_scope in requested
            if self._policy_allows(requested_scope)
        }
        rejected = sorted(set(requested) - allowed)
        reason = self._decision_reason(intent.action_scope, rejected)
        return PolicyDecision(
            allowed_scopes=tuple(sorted(allowed)),
            rejected_scopes=tuple(rejected),
            reason=reason,
        )

    def _policy_allows(self, requested_scope: str) -> bool:
        """判断 requested scope 是否被本地 policy 允许。"""
        return action_scopes_allow(self.policy_scopes, requested_scope)

    def _decision_reason(
        self,
        action_scope: str,
        rejected_scopes: list[str],
    ) -> str:
        """根据被拒绝 scope 生成稳定 policy 审计原因。"""
        if not rejected_scopes:
            return "authorized"
        if action_scope in rejected_scopes:
            return "policy_reject"
        return "scope_escalation"
