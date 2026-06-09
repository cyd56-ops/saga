"""Tests for the TLA+ strict runtime-auth proof artifact."""

from __future__ import annotations

import re
from pathlib import Path
import unittest

from saga.security_kernel import (
    EXECUTE_SURFACE_CLAIM,
    layer_refinement_mappings,
    protected_sink_surfaces,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
TLA_SPEC = REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuth.tla"
TLA_CONFIG = REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuth.cfg"
TLA_SMOKE_CONFIG = REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuthSmoke.cfg"
TLA_PAIR_SMOKE_CONFIG = (
    REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuthPairSmoke.cfg"
)
TLA_LAYERED_SPEC = REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuthLayered.tla"
TLA_LAYERED_CONFIG = REPO_ROOT / "proofs" / "tla" / "StrictRuntimeAuthLayered.cfg"


class TLAStrictRuntimeAuthTests(unittest.TestCase):
    """验证 TLA+ 规格与 Python strict runtime-auth 模型保持同一安全命题。"""

    def test_tla_artifacts_exist(self) -> None:
        """TLA+ 规格和 TLC 配置必须作为 proof artifact 纳入仓库。"""
        self.assertTrue(TLA_SPEC.is_file())
        self.assertTrue(TLA_CONFIG.is_file())
        self.assertTrue(TLA_SMOKE_CONFIG.is_file())
        self.assertTrue(TLA_PAIR_SMOKE_CONFIG.is_file())
        self.assertTrue(TLA_LAYERED_SPEC.is_file())
        self.assertTrue(TLA_LAYERED_CONFIG.is_file())

    def test_tla_surfaces_match_python_protected_sink_inventory(self) -> None:
        """TLC 配置中的 surface 常量必须和 Python protected sink 清单一致。"""
        config_text = TLA_CONFIG.read_text(encoding="utf-8")
        configured_surfaces = set(_extract_tla_surface_constants(config_text))
        expected_surfaces = {
            _surface_to_tla_model_value(surface) for surface in protected_sink_surfaces()
        }

        self.assertEqual(configured_surfaces, expected_surfaces)

    def test_tla_invariant_names_all_execute_claim_terms(self) -> None:
        """TLA+ invariant 必须显式包含 Execute claim 的五个必要谓词。"""
        spec_text = TLA_SPEC.read_text(encoding="utf-8")

        self.assertIn("ExecuteSurfaceClaim", spec_text)
        self.assertIn("Execute(surface)", spec_text)
        for term in {
            "n_verify",
            "scope_ok",
            "replay_ok",
            "delegation_ok",
            "policy_ok",
        }:
            self.assertIn(term, spec_text)
            self.assertIn(term.replace("n_verify", "N_verify"), EXECUTE_SURFACE_CLAIM)

    def test_tla_transition_keeps_execute_guarded_by_can_execute(self) -> None:
        """Execute 转移必须经 CanExecute guard，避免规格漂移成无条件执行。"""
        spec_text = TLA_SPEC.read_text(encoding="utf-8")
        execute_block = _extract_definition_block(spec_text, "Execute")

        self.assertIn("CanExecute(surface)", execute_block)
        self.assertIn("executed'", execute_block)
        self.assertIn("Reject(surface)", spec_text)

    def test_tla_smoke_config_is_bounded_subset_for_tlc(self) -> None:
        """TLC smoke 配置只取代表性 surface，避免全量布尔映射状态爆炸。"""
        full_surfaces = set(
            _extract_tla_surface_constants(TLA_CONFIG.read_text(encoding="utf-8"))
        )
        smoke_text = TLA_SMOKE_CONFIG.read_text(encoding="utf-8")
        smoke_surfaces = set(_extract_tla_surface_constants(smoke_text))

        self.assertEqual(smoke_surfaces, {"llm_prompt"})
        self.assertLess(len(smoke_surfaces), len(full_surfaces))
        self.assertTrue(smoke_surfaces.issubset(full_surfaces))
        self.assertIn("ExecuteSurfaceClaim", smoke_text)
        self.assertIn("ScopeCheckRequired", smoke_text)

    def test_tla_pair_smoke_config_covers_multiple_surfaces(self) -> None:
        """双 surface smoke 配置验证多个执行面并存时仍保持同一 invariant。"""
        full_surfaces = set(
            _extract_tla_surface_constants(TLA_CONFIG.read_text(encoding="utf-8"))
        )
        single_surfaces = set(
            _extract_tla_surface_constants(
                TLA_SMOKE_CONFIG.read_text(encoding="utf-8")
            )
        )
        pair_text = TLA_PAIR_SMOKE_CONFIG.read_text(encoding="utf-8")
        pair_surfaces = set(_extract_tla_surface_constants(pair_text))

        self.assertEqual(pair_surfaces, {"llm_prompt", "memory_write"})
        self.assertGreater(len(pair_surfaces), len(single_surfaces))
        self.assertLess(len(pair_surfaces), len(full_surfaces))
        self.assertTrue(pair_surfaces.issubset(full_surfaces))
        self.assertIn("ExecuteSurfaceClaim", pair_text)
        self.assertIn("ScopeCheckRequired", pair_text)

    def test_layered_tla_config_partitions_full_surface_inventory(self) -> None:
        """layered cfg 必须把 full surface 清单分区覆盖，不能遗漏或重叠。"""
        full_surfaces = set(
            _extract_tla_surface_constants(TLA_CONFIG.read_text(encoding="utf-8"))
        )
        layered_text = TLA_LAYERED_CONFIG.read_text(encoding="utf-8")
        layered_surfaces = set(_extract_tla_surface_constants(layered_text))
        layer_surfaces = {
            "prompt_layer": set(
                _extract_tla_constant_set(layered_text, "PromptLayerSurfaces")
            ),
            "tool_layer": set(
                _extract_tla_constant_set(layered_text, "ToolLayerSurfaces")
            ),
            "memory_layer": set(
                _extract_tla_constant_set(layered_text, "MemoryLayerSurfaces")
            ),
            "delegation_layer": set(
                _extract_tla_constant_set(layered_text, "DelegationLayerSurfaces")
            ),
            "replay_layer": set(
                _extract_tla_constant_set(layered_text, "ReplayLayerSurfaces")
            ),
        }

        self.assertEqual(layered_surfaces, full_surfaces)
        self.assertEqual(
            set(layer_surfaces),
            {
                "prompt_layer",
                "tool_layer",
                "memory_layer",
                "delegation_layer",
                "replay_layer",
            },
        )
        self.assertEqual(
            layer_surfaces["tool_layer"],
            {"tool_call_placeholder", "tool_backend_method"},
        )
        self.assertEqual(layer_surfaces["memory_layer"], {"memory_read", "memory_write"})

        seen: set[str] = set()
        for layer, surfaces in layer_surfaces.items():
            with self.subTest(layer=layer):
                self.assertTrue(surfaces)
                self.assertTrue(surfaces.issubset(full_surfaces))
                self.assertFalse(seen.intersection(surfaces))
                seen.update(surfaces)

        self.assertEqual(seen, full_surfaces)

    def test_layered_tla_config_matches_python_layer_refinement(self) -> None:
        """TLA+ layer cfg 必须和 Python layer refinement 对照表一致。"""
        layered_text = TLA_LAYERED_CONFIG.read_text(encoding="utf-8")
        configured_layer_values = {
            mapping.layer_id: _extract_tla_constant_value(
                layered_text, mapping.tla_layer_constant
            )
            for mapping in layer_refinement_mappings()
        }
        configured_layer_surfaces = {
            mapping.layer_id: set(
                _extract_tla_constant_set(layered_text, mapping.tla_surfaces_constant)
            )
            for mapping in layer_refinement_mappings()
        }

        self.assertEqual(
            configured_layer_values,
            {mapping.layer_id: mapping.layer_id for mapping in layer_refinement_mappings()},
        )
        self.assertEqual(
            configured_layer_surfaces,
            {
                mapping.layer_id: set(mapping.tla_surface_values)
                for mapping in layer_refinement_mappings()
            },
        )

    def test_layered_tla_spec_preserves_execute_claim_terms(self) -> None:
        """layered TLA+ 规格必须保留同一 Execute 必要条件命题。"""
        spec_text = TLA_LAYERED_SPEC.read_text(encoding="utf-8")

        self.assertIn("LayerPartition", spec_text)
        self.assertIn("DistinctLayers", spec_text)
        self.assertIn("LayerExecuteClaim", spec_text)
        self.assertIn("LayerCoverageClaim", spec_text)
        self.assertIn("layer \\in Layers", spec_text)
        self.assertIn("CanExecute", spec_text)
        for term in {
            "n_verify",
            "scope_ok",
            "replay_ok",
            "delegation_ok",
            "policy_ok",
        }:
            self.assertIn(term, spec_text)


def _surface_to_tla_model_value(surface: str) -> str:
    """将 Python surface 名称转换为 TLC 配置中的 model value 名称。"""
    if surface == "tool_call:<tool_name>":
        return "tool_call_placeholder"
    return surface


def _extract_tla_surface_constants(config_text: str) -> tuple[str, ...]:
    """从 TLC cfg 的 Surfaces 集合中提取 model value 名称。"""
    return _extract_tla_constant_set(config_text, "Surfaces")


def _extract_tla_constant_set(config_text: str, constant_name: str) -> tuple[str, ...]:
    """从 TLC cfg 中提取一个 model-value 集合常量。"""
    match = re.search(
        rf"(?m)^\s*{re.escape(constant_name)}\s*=\s*\{{(?P<body>.*?)\}}",
        config_text,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"{constant_name} constant set not found")
    return tuple(
        value.strip()
        for value in match.group("body").split(",")
        if value.strip()
    )


def _extract_tla_constant_value(config_text: str, constant_name: str) -> str:
    """从 TLC cfg 中提取一个单值 model-value 常量。"""
    match = re.search(
        rf"(?m)^\s*{re.escape(constant_name)}\s*=\s*(?P<value>[A-Za-z0-9_]+)\s*$",
        config_text,
    )
    if match is None:
        raise AssertionError(f"{constant_name} constant value not found")
    return match.group("value")


def _extract_definition_block(spec_text: str, definition_name: str) -> str:
    """提取一个简单 TLA+ 定义块，供测试检查关键 guard。"""
    pattern = rf"(?m)^{definition_name}\(surface\)\s*==(?P<body>.*?)(?:\n\n[A-Za-z_]+|\n====)"
    match = re.search(pattern, spec_text, re.DOTALL)
    if match is None:
        raise AssertionError(f"{definition_name} definition not found")
    return match.group("body")


if __name__ == "__main__":
    unittest.main()
