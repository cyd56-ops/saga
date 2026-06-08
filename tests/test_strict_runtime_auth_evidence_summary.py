"""Tests for the strict runtime-auth proof evidence summary."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from experiments.security_evidence import property_claims
from saga.security_kernel import (
    EXECUTE_SURFACE_CLAIM,
    model_refinement_mappings,
    mutation_evidence,
    no_side_effect_oracles,
    protected_sink_audits,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY_PATH = REPO_ROOT / "proofs" / "strict_runtime_auth_evidence.md"


class StrictRuntimeAuthEvidenceSummaryTests(unittest.TestCase):
    """验证 proof evidence summary 与安全内核事实来源保持一致。"""

    def test_summary_exists_and_names_core_claim(self) -> None:
        """证据摘要必须存在，并显式写出 strict runtime-auth 核心命题。"""
        text = SUMMARY_PATH.read_text(encoding="utf-8")

        self.assertIn(EXECUTE_SURFACE_CLAIM, text)
        self.assertIn("sink-centric", text)
        self.assertIn("strict runtime-auth security kernel", text)

    def test_summary_lists_all_protected_sinks(self) -> None:
        """每个 protected sink 都必须在证据摘要中有一行 sink coverage。"""
        rows = _markdown_table_rows(
            SUMMARY_PATH.read_text(encoding="utf-8"),
            "Protected Sink Coverage",
        )
        sink_rows = {
            cells[0].strip("`"): cells[1].strip("`")
            for cells in rows
        }

        self.assertEqual(
            sink_rows,
            {sink.sink_id: sink.surface for sink in protected_sink_audits()},
        )
        self.assertGreaterEqual(
            {oracle.sink_id for oracle in no_side_effect_oracles()},
            set(sink_rows),
        )

    def test_summary_lists_all_mutation_evidence(self) -> None:
        """每个 mutation evidence ID 和受保护谓词都必须写入摘要表。"""
        rows = _markdown_table_rows(
            SUMMARY_PATH.read_text(encoding="utf-8"),
            "Mutation Evidence",
        )
        mutation_rows = {
            cells[0].strip("`"): cells[1].strip("`")
            for cells in rows
        }

        self.assertEqual(
            mutation_rows,
            {
                evidence.mutation_id: evidence.protected_property
                for evidence in mutation_evidence()
            },
        )

    def test_summary_lists_all_model_refinement_terms(self) -> None:
        """P6 refinement mapping 不能只在代码里存在，摘要也必须列出。"""
        rows = _markdown_table_rows(
            SUMMARY_PATH.read_text(encoding="utf-8"),
            "Model Refinement Mapping",
        )
        mapping_rows = {
            cells[0].strip("`"): cells[1].strip("`")
            for cells in rows
        }

        self.assertEqual(
            mapping_rows,
            {
                mapping.mapping_id: mapping.model_term
                for mapping in model_refinement_mappings()
            },
        )

    def test_summary_lists_all_paper_level_properties(self) -> None:
        """U9/U10 论文级性质必须出现在 proof evidence summary 中。"""
        rows = _markdown_table_rows(
            SUMMARY_PATH.read_text(encoding="utf-8"),
            "Paper-Level Security Properties",
        )
        property_rows = {
            cells[0].strip("`"): cells[1]
            for cells in rows
        }

        self.assertEqual(
            property_rows,
            {claim.property_id: claim.title for claim in property_claims()},
        )

    def test_tlc_summary_keeps_state_counts_and_full_cfg_boundary(self) -> None:
        """TLC 状态规模和 full cfg 未完成边界必须稳定记录。"""
        text = SUMMARY_PATH.read_text(encoding="utf-8")
        rows = _markdown_table_rows(text, "TLC Model-Checking Summary")
        rows_by_target = {cells[0].strip("`"): cells for cells in rows}

        self.assertEqual(
            rows_by_target["each per-surface generated cfg"][1:4],
            ("65", "33", "2"),
        )
        self.assertEqual(
            rows_by_target["StrictRuntimeAuthPairSmoke.cfg"][1:4],
            ("3202", "1089", "3"),
        )
        self.assertEqual(
            rows_by_target["StrictRuntimeAuthLayered.cfg"][1:4],
            ("325", "165", "2"),
        )
        self.assertIn("Do not cite the full cfg as a completed TLC run", text)
        self.assertIn("16777216 initial states", text)

    def test_summary_records_non_production_crypto_boundary(self) -> None:
        """摘要必须明确 toy LWE 不是生产后量子安全证据。"""
        text = SUMMARY_PATH.read_text(encoding="utf-8")

        self.assertIn("toy LWE", text)
        self.assertIn("research wiring evidence", text)
        self.assertIn("Production claims require a vetted external ML-DSA backend", text)


def _markdown_table_rows(markdown_text: str, heading: str) -> tuple[tuple[str, ...], ...]:
    """提取指定二级标题后第一个 Markdown 表格的数据行。"""
    section_match = re.search(
        rf"(?ms)^## {re.escape(heading)}\n(?P<section>.*?)(?:\n## |\Z)",
        markdown_text,
    )
    if section_match is None:
        raise AssertionError(f"section {heading!r} not found")
    lines = [
        line.strip()
        for line in section_match.group("section").splitlines()
        if line.strip().startswith("|")
    ]
    if len(lines) < 2:
        raise AssertionError(f"table for section {heading!r} not found")
    data_lines = [
        line
        for line in lines[2:]
        if not set(line.replace("|", "").strip()) <= {"-", ":"}
    ]
    return tuple(
        tuple(cell.strip() for cell in line.strip("|").split("|"))
        for line in data_lines
    )


if __name__ == "__main__":
    unittest.main()
