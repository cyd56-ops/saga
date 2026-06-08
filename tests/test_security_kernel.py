"""Tests for the SAGA-PQ-CAN security runtime kernel inventory."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import unittest

from saga.security_kernel import (
    EXECUTE_SURFACE_CLAIM,
    covered_surfaces,
    entries_for_status,
    excluded_entries,
    model_refinement_mappings,
    mutation_evidence,
    no_side_effect_oracles,
    protected_sink_audits,
    protected_sink_surfaces,
    security_kernel_entries,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class _CallSite:
    """记录静态 drift 检查发现的 Python 调用位置。"""

    path: str
    function: str
    expression: str
    lineno: int


class _CallSiteCollector(ast.NodeVisitor):
    """遍历 AST 并按谓词收集调用点，同时保留所在函数名。"""

    def __init__(self, path: Path, predicate) -> None:
        """保存待扫描文件和调用谓词。"""
        self.path = path
        self.predicate = predicate
        self.function_stack: list[str] = []
        self.call_sites: list[_CallSite] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """进入普通函数作用域，便于后续定位调用点。"""
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """进入异步函数作用域，保持和普通函数相同的记录语义。"""
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        """在调用表达式满足谓词时记录源码位置。"""
        if self.predicate(node):
            self.call_sites.append(
                _CallSite(
                    path=str(self.path.relative_to(REPO_ROOT)),
                    function=self.function_stack[-1] if self.function_stack else "<module>",
                    expression=ast.unparse(node.func),
                    lineno=node.lineno,
                )
            )
        self.generic_visit(node)


def _project_python_files() -> tuple[Path, ...]:
    """返回 strict kernel drift 检查需要扫描的项目 Python 文件。"""
    roots = (REPO_ROOT / "saga", REPO_ROOT / "agent_backend")
    files: list[Path] = []
    for root in roots:
        for path in root.rglob("*.py"):
            relative = path.relative_to(REPO_ROOT)
            if "__pycache__" in relative.parts:
                continue
            if relative.parts[:2] == ("saga", "attack_models"):
                continue
            files.append(path)
    return tuple(sorted(files))


def _call_sites(predicate) -> tuple[_CallSite, ...]:
    """按给定 AST 谓词收集项目源码中的调用点。"""
    call_sites: list[_CallSite] = []
    for path in _project_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        collector = _CallSiteCollector(path, predicate)
        collector.visit(tree)
        call_sites.extend(collector.call_sites)
    return tuple(call_sites)


def _is_attribute_call(node: ast.Call, attribute_name: str) -> bool:
    """判断调用目标是否是指定属性名。"""
    return isinstance(node.func, ast.Attribute) and node.func.attr == attribute_name


def _call_site_locations(call_sites: tuple[_CallSite, ...]) -> set[tuple[str, str]]:
    """把调用点压缩为文件和函数集合，降低行号变动导致的噪声。"""
    return {(site.path, site.function) for site in call_sites}


def _is_wrapped_by_gated_resource(node: ast.AST) -> bool:
    """检查 backend 构造是否被包在 _gated_tool_resource 调用中。"""
    parent = getattr(node, "_parent", None)
    while parent is not None:
        if (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Attribute)
            and parent.func.attr == "_gated_tool_resource"
        ):
            return True
        parent = getattr(parent, "_parent", None)
    return False


def _parsed_tree_with_parents(path: Path) -> ast.AST:
    """解析源码并给子节点补父节点指针，供包裹关系检查使用。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "_parent", parent)
    return tree


class SecurityKernelInventoryTests(unittest.TestCase):
    """Validate the documented execution-surface security boundary."""

    def test_inventory_entry_ids_are_unique(self) -> None:
        """安全内核清单中的入口标识必须唯一，避免证据映射歧义。"""
        entry_ids = [entry.entry_id for entry in security_kernel_entries()]

        self.assertEqual(len(entry_ids), len(set(entry_ids)))

    def test_inventory_covers_required_execution_surfaces(self) -> None:
        """U1 要求 prompt、tool、memory、delegation 与 response-side execution 都有清单项。"""
        self.assertGreaterEqual(
            set(covered_surfaces()),
            {
                "llm_prompt",
                "response_side_llm_prompt",
                "tool_call:<tool_name>",
                "memory_read",
                "memory_write",
                "delegation",
                "request_envelope_replay",
                "intent_capability_envelope",
            },
        )

    def test_protected_sink_audit_covers_required_surfaces(self) -> None:
        """P0 要求 protected sink 审计覆盖 prompt、tool、backend、memory、delegation 和 replay。"""
        self.assertIn("Execute(surface) =>", EXECUTE_SURFACE_CLAIM)
        self.assertIn("N_verify=1", EXECUTE_SURFACE_CLAIM)
        self.assertIn("scope_ok", EXECUTE_SURFACE_CLAIM)
        self.assertIn("replay_ok", EXECUTE_SURFACE_CLAIM)
        self.assertIn("delegation_ok", EXECUTE_SURFACE_CLAIM)
        self.assertIn("policy_ok", EXECUTE_SURFACE_CLAIM)

        self.assertGreaterEqual(
            set(protected_sink_surfaces()),
            {
                "llm_prompt",
                "tool_call:<tool_name>",
                "tool_backend_method",
                "memory_read",
                "memory_write",
                "delegation",
                "request_envelope_replay",
            },
        )

    def test_protected_sink_audits_have_predicates_and_evidence(self) -> None:
        """每个 protected sink 都必须记录调用路径、授权谓词、测试和 drift 检查。"""
        sink_ids = [sink.sink_id for sink in protected_sink_audits()]

        self.assertEqual(len(sink_ids), len(set(sink_ids)))
        for sink in protected_sink_audits():
            self.assertTrue(sink.side_effect)
            self.assertTrue(sink.allowed_call_path)
            self.assertTrue(sink.required_predicate)
            self.assertTrue(sink.evidence_tests)
            self.assertTrue(sink.residual_risk)
            self.assertTrue(sink.static_drift_checks)

    def test_each_protected_sink_has_no_side_effect_oracle(self) -> None:
        """P3 要求每个 protected sink 都有无副作用拒绝 oracle。"""
        sink_ids = {sink.sink_id for sink in protected_sink_audits()}
        oracle_sink_ids = {oracle.sink_id for oracle in no_side_effect_oracles()}

        self.assertGreaterEqual(oracle_sink_ids, sink_ids)
        for oracle in no_side_effect_oracles():
            self.assertIn(oracle.sink_id, sink_ids)
            self.assertTrue(oracle.rejected_condition)
            self.assertTrue(oracle.expected_observation)
            self.assertTrue(oracle.evidence_tests)
            self.assertTrue(
                any("side_effect" in test or "reject" in test for test in oracle.evidence_tests),
                oracle.oracle_id,
            )

    def test_mutation_evidence_covers_required_controls(self) -> None:
        """P4 mutation evidence 应覆盖 prompt、scope、replay、backend、MASK、委托父绑定和 policy。"""
        sink_ids = {sink.sink_id for sink in protected_sink_audits()}
        evidence_by_id = {evidence.mutation_id: evidence for evidence in mutation_evidence()}

        self.assertGreaterEqual(
            set(evidence_by_id),
            {
                "skip_prompt_surface_authorization",
                "disable_local_execution_context_require_action",
                "skip_replay_reserve",
                "relax_action_scope_matching",
                "bypass_gated_execution_resource",
                "bypass_shamir_mask_real_valued_rejection",
                "bypass_delegation_parent_digest_check",
                "bypass_policy_compiler_scope_filter",
            },
        )
        for evidence in mutation_evidence():
            self.assertTrue(evidence.sink_ids)
            self.assertTrue(set(evidence.sink_ids) <= sink_ids)
            self.assertTrue(evidence.mutated_control)
            self.assertTrue(evidence.expected_test_failures)
            self.assertIn(evidence.protected_property, EXECUTE_SURFACE_CLAIM)

    def test_model_refinement_covers_execute_claim_terms(self) -> None:
        """P6 refinement 表必须覆盖 P5 模型中的执行必要条件和 Execute 转移。"""
        mappings_by_term = {
            mapping.model_term: mapping for mapping in model_refinement_mappings()
        }

        self.assertGreaterEqual(
            set(mappings_by_term),
            {
                "Execute(surface)",
                "N_verify",
                "scope_ok",
                "replay_ok",
                "delegation_ok",
                "policy_ok",
            },
        )
        for term in {"N_verify", "scope_ok", "replay_ok", "delegation_ok", "policy_ok"}:
            self.assertIn(term, EXECUTE_SURFACE_CLAIM)

    def test_model_refinement_entries_have_python_evidence_and_boundaries(self) -> None:
        """每条 refinement 对照都要绑定 Python 符号、测试证据、TCB 假设和排除路径。"""
        mapping_ids = [mapping.mapping_id for mapping in model_refinement_mappings()]
        sink_ids = {sink.sink_id for sink in protected_sink_audits()}
        linked_sink_ids = {
            sink_id
            for mapping in model_refinement_mappings()
            for sink_id in mapping.linked_sink_ids
        }

        self.assertEqual(len(mapping_ids), len(set(mapping_ids)))
        self.assertGreaterEqual(linked_sink_ids, sink_ids)
        for mapping in model_refinement_mappings():
            self.assertTrue(mapping.abstract_predicate)
            self.assertTrue(mapping.python_symbols)
            self.assertTrue(mapping.evidence_tests)
            self.assertTrue(mapping.tcb_assumptions)
            self.assertTrue(mapping.excluded_paths)
            self.assertTrue(mapping.residual_risk)
            self.assertTrue(set(mapping.linked_sink_ids) <= sink_ids)
            self.assertTrue(
                all(
                    symbol.startswith(("saga.", "neural.", "agent_backend."))
                    for symbol in mapping.python_symbols
                ),
                mapping.mapping_id,
            )

    def test_covered_entries_have_evidence_and_risk_statements(self) -> None:
        """每个已覆盖入口都要记录代码路径、证据测试和剩余风险。"""
        covered = entries_for_status("covered")

        self.assertGreaterEqual(len(covered), 6)
        for entry in covered:
            self.assertTrue(entry.in_security_kernel)
            self.assertTrue(entry.code_paths)
            self.assertTrue(entry.evidence_tests)
            self.assertTrue(entry.gate_mechanism)
            self.assertTrue(entry.residual_risk)

    def test_compatibility_and_reproduction_paths_are_excluded(self) -> None:
        """legacy fallback 和复现实验路径必须显式排除在安全 claim 外。"""
        excluded_by_id = {entry.entry_id: entry for entry in excluded_entries()}

        for entry_id in {
            "missing_execution_gate_strict_mode",
            "missing_local_execution_context_strict_mode",
            "attack_model_and_experiment_clones",
        }:
            self.assertIn(entry_id, excluded_by_id)
            self.assertFalse(excluded_by_id[entry_id].in_security_kernel)

    def test_custom_local_agent_context_ignored_is_strict_covered(self) -> None:
        """U5 自定义 LocalAgent 忽略 context 的路径应在 strict 模式下 fail-closed。"""
        covered_by_id = {entry.entry_id: entry for entry in entries_for_status("covered")}

        entry = covered_by_id["custom_local_agent_context_ignored"]
        self.assertTrue(entry.in_security_kernel)
        self.assertIn("supports_execution_context", "\n".join(entry.code_paths))
        self.assertIn("local_agent_execution_context_unsupported", entry.gate_mechanism)
        self.assertIn("strict", entry.residual_risk)

    def test_compatibility_fallbacks_name_stable_reject_reasons(self) -> None:
        """严格模式兼容入口应记录 fail-closed 的稳定 reason。"""
        inventory_text = "\n".join(
            entry.gate_mechanism for entry in security_kernel_entries()
        )

        self.assertIn("missing_execution_gate", inventory_text)
        self.assertIn("missing_local_execution_context", inventory_text)
        self.assertIn("local_agent_execution_context_unsupported", inventory_text)
        self.assertIn("replayed_request_envelope", inventory_text)
        self.assertIn("parent_envelope_digest", inventory_text)
        self.assertIn("no_execution_gate", inventory_text)
        self.assertIn("legacy_prompt_without_execution_context", inventory_text)

    def test_persistent_replay_state_is_strict_covered(self) -> None:
        """U6/U7 replay 状态硬化应纳入 strict runtime-auth 安全声明。"""
        covered_by_id = {entry.entry_id: entry for entry in entries_for_status("covered")}

        entry = covered_by_id["persistent_replay_state"]
        self.assertTrue(entry.in_security_kernel)
        self.assertIn("enable_toy_lwe_runtime_auth", "\n".join(entry.code_paths))
        self.assertIn("consume_request", "\n".join(entry.code_paths))
        self.assertIn("persistent replay state", entry.gate_mechanism)
        self.assertIn("atomic reserve semantics", entry.residual_risk)

    def test_signed_intent_capability_envelope_is_strict_covered(self) -> None:
        """U8 signed intent capability envelope 应记录父摘要和 scope 衰减证据。"""
        covered_by_id = {entry.entry_id: entry for entry in entries_for_status("covered")}

        entry = covered_by_id["signed_intent_capability_envelope"]
        self.assertTrue(entry.in_security_kernel)
        self.assertIn("RequestEnvelope", "\n".join(entry.code_paths))
        self.assertIn("parent_envelope_digest", entry.gate_mechanism)
        self.assertIn("cannot expand parent scopes", entry.gate_mechanism)
        self.assertIn("delegation-chain storage", entry.residual_risk)

    def test_strict_fallback_entries_cover_initiating_response_path(self) -> None:
        """U2 的 strict fallback 证据必须同时覆盖 initiating-side response 路径。"""
        fallback_entries = {
            entry.entry_id: entry for entry in excluded_entries()
        }

        for entry_id in {
            "missing_execution_gate_strict_mode",
            "missing_local_execution_context_strict_mode",
        }:
            self.assertIn("initiating", fallback_entries[entry_id].gate_mechanism)

    def test_local_agent_run_call_sites_remain_prompt_gated(self) -> None:
        """新增 local_agent.run 调用必须继续经过 prompt gate 统一入口。"""
        call_sites = _call_sites(
            lambda node: _is_attribute_call(node, "run")
            and "local_agent" in ast.unparse(node.func.value)
        )

        self.assertEqual(
            _call_site_locations(call_sites),
            {("saga/agent.py", "_run_local_agent_with_diagnostics")},
            msg=f"Unexpected local_agent.run call sites: {call_sites!r}",
        )

    def test_raw_memory_mutation_remains_inside_capability_facade(self) -> None:
        """raw memory steps append 只能出现在 capability facade 的 memory_write 路径。"""
        def is_steps_append(node: ast.Call) -> bool:
            """识别 ``memory.steps.append`` 与 ``getattr(memory, 'steps').append``。"""
            if not _is_attribute_call(node, "append"):
                return False
            receiver = ast.unparse(node.func.value)
            return receiver.endswith(".steps") or (
                receiver.startswith("getattr(") and "steps" in receiver
            )

        call_sites = _call_sites(is_steps_append)

        self.assertEqual(
            _call_site_locations(call_sites),
            {("saga/execution_gate.py", "append_memory_step")},
            msg=f"Unexpected raw memory append call sites: {call_sites!r}",
        )

    def test_business_tool_backends_remain_gated_resources(self) -> None:
        """业务 backend 构造必须嵌在 _gated_tool_resource 中，防止原始客户端外泄。"""
        backend_classes = {
            "LocalEmailClientTool",
            "LocalCalendarTool",
            "LocalDocumentsTool",
        }
        direct_backend_calls: list[_CallSite] = []
        for path in _project_python_files():
            tree = _parsed_tree_with_parents(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func_name = ast.unparse(node.func)
                if func_name not in backend_classes:
                    continue
                if _is_wrapped_by_gated_resource(node):
                    continue
                direct_backend_calls.append(
                    _CallSite(
                        path=str(path.relative_to(REPO_ROOT)),
                        function="<unknown>",
                        expression=func_name,
                        lineno=node.lineno,
                    )
                )

        self.assertEqual(
            direct_backend_calls,
            [],
            msg=f"Ungated business backend construction found: {direct_backend_calls!r}",
        )

    def test_direct_delegation_connect_calls_remain_excluded_or_gated(self) -> None:
        """strict kernel 内 Agent.connect 委托调用只能来自已授权 delegation handler。"""
        def is_agent_connect(node: ast.Call) -> bool:
            """识别非 SQLite 的 ``*.connect(...)`` 调用。"""
            if not _is_attribute_call(node, "connect"):
                return False
            expression = ast.unparse(node.func)
            return expression != "sqlite3.connect"

        call_sites = _call_sites(is_agent_connect)

        self.assertEqual(
            _call_site_locations(call_sites),
            {("saga/agent.py", "_delegate_to_agent")},
            msg=f"Unexpected Agent.connect call sites: {call_sites!r}",
        )

    def test_replay_consume_and_reserve_calls_remain_gate_mediated(self) -> None:
        """replay consume / reserve 调用必须保持在 signed gate 消费路径内。"""
        call_sites = _call_sites(
            lambda node: _is_attribute_call(node, "consume_request")
            or _is_attribute_call(node, "reserve_request")
        )

        self.assertEqual(
            _call_site_locations(call_sites),
            {
                ("saga/agent.py", "_evaluate_execution_request"),
                ("saga/execution_gate.py", "consume_request"),
            },
            msg=f"Unexpected replay consume/reserve call sites: {call_sites!r}",
        )


if __name__ == "__main__":
    unittest.main()
