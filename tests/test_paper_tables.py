"""Tests for paper-table extraction from end-to-end summaries."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from experiments.paper_tables import (
    DEFAULT_BASELINE_SUMMARY_PATH,
    DEFAULT_PQ_CAN_SUMMARY_PATH,
    LAYER_REFINEMENT_COLUMNS,
    MODEL_REFINEMENT_COLUMNS,
    PROOF_ARTIFACT_COLUMNS,
    PROOF_CLAIM_COLUMNS,
    PROOF_MUTATION_COLUMNS,
    PROTECTED_SINK_COLUMNS,
    TASK_LEVEL_COLUMNS,
    RUN_LEVEL_COLUMNS,
    SECURITY_EVIDENCE_COLUMNS,
    SECURITY_PROPERTY_COLUMNS,
    build_paper_tables,
    format_paper_tables_markdown,
    format_markdown_table,
    load_end_to_end_summary,
    main,
    write_paper_table_archive,
)
from experiments.security_evidence import SECURITY_PROPERTY_ORDER
from saga.security_kernel import (
    EXECUTE_SURFACE_CLAIM,
    layer_refinement_mappings,
    model_refinement_mappings,
    mutation_evidence as kernel_mutation_evidence,
    protected_sink_audits,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PROOF_APPENDIX_ARCHIVE_DIR = (
    REPO_ROOT / "experiments" / "tables" / "20260609-proof-hardening-appendix"
)


def _summary(
    *,
    runtime_auth_enabled: bool,
    task_latency: float,
    model_call_count: int,
    llm_elapsed: float,
    peer_audit_reject_count: int = 0,
) -> dict[str, object]:
    """构造最小端到端 summary fixture，避免测试依赖 ignored 运行产物。"""
    return {
        "task_count": 1,
        "succeeded_count": 1,
        "failed_count": 0,
        "task_latency_seconds_total": task_latency,
        "task_latency_seconds_mean": task_latency,
        "model_call_count": model_call_count,
        "audit_record_count": peer_audit_reject_count,
        "audit_logging_overhead_record_count": peer_audit_reject_count,
        "logging_stats_collection_latency_seconds_total": 0.001234567,
        "api_cost_available": False,
        "api_cost_usd_total": None,
        "token_usage_available": False,
        "total_tokens": None,
        "tasks": [
            {
                "task_name": "schedule_meeting",
                "success": True,
                "runtime_auth_enabled": runtime_auth_enabled,
                "task_latency_seconds": task_latency,
                "model_call_count": model_call_count,
                "local_model_call_count": 1,
                "peer_model_call_count": model_call_count - 1,
                "llm_elapsed_seconds_total": llm_elapsed,
                "audit_record_count": peer_audit_reject_count,
                "audit_reject_count": 0,
                "peer_audit_reject_count": peer_audit_reject_count,
                "audit_logging_overhead_record_count": peer_audit_reject_count,
                "api_cost_available": False,
                "api_cost_usd": None,
                "token_usage_available": False,
                "total_tokens": None,
                "oracle_reason": "meeting_scheduled",
            }
        ],
    }


def _proof_summary() -> dict[str, object]:
    """构造最小 proof-hardening summary fixture。"""
    return {
        "passed": True,
        "finding_count": 0,
        "mutation_validation": {"passed": True},
        "proof_tests": {
            "stdout_tail": (
                "................................... [100%]\n"
                "85 passed, 37 subtests passed in 0.80s\n"
            )
        },
    }


def _mutation_summary() -> dict[str, object]:
    """构造最小 mutation evidence summary fixture。"""
    return {
        "mutation_count": 8,
        "detected_count": 8,
        "all_detected": True,
        "undetected_count": 0,
        "recorded_at": "2026-06-09T07:35:29.610329+00:00",
    }


class PaperTablesTests(unittest.TestCase):
    """Verify paper-table rows use stable experiment fields and conservative cost semantics."""

    def test_build_paper_tables_emits_run_and_task_rows(self) -> None:
        """Run-level and task-level rows should expose stable columns."""
        tables = build_paper_tables(
            {
                "baseline": _summary(
                    runtime_auth_enabled=False,
                    task_latency=10.1234567,
                    model_call_count=2,
                    llm_elapsed=8.5,
                ),
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                ),
            }
        )

        self.assertEqual(tables["run_level_columns"], list(RUN_LEVEL_COLUMNS))
        self.assertEqual(tables["task_level_columns"], list(TASK_LEVEL_COLUMNS))
        self.assertEqual(
            tables["security_property_columns"],
            list(SECURITY_PROPERTY_COLUMNS),
        )
        self.assertEqual(
            tables["security_evidence_columns"],
            list(SECURITY_EVIDENCE_COLUMNS),
        )
        self.assertEqual(tables["proof_claim_columns"], list(PROOF_CLAIM_COLUMNS))
        self.assertEqual(
            tables["protected_sink_columns"],
            list(PROTECTED_SINK_COLUMNS),
        )
        self.assertEqual(
            tables["proof_mutation_columns"],
            list(PROOF_MUTATION_COLUMNS),
        )
        self.assertEqual(
            tables["model_refinement_columns"],
            list(MODEL_REFINEMENT_COLUMNS),
        )
        self.assertEqual(
            tables["layer_refinement_columns"],
            list(LAYER_REFINEMENT_COLUMNS),
        )
        self.assertEqual(
            tables["proof_artifact_columns"],
            list(PROOF_ARTIFACT_COLUMNS),
        )
        self.assertEqual(len(tables["run_level_rows"]), 2)
        self.assertEqual(len(tables["task_level_rows"]), 2)

        baseline_row = tables["run_level_rows"][0]
        pq_can_task = tables["task_level_rows"][1]
        self.assertEqual(baseline_row["mode"], "baseline")
        self.assertFalse(baseline_row["runtime_auth_enabled"])
        self.assertEqual(baseline_row["task_latency_seconds_total"], 10.123457)
        self.assertEqual(baseline_row["llm_elapsed_seconds_total"], 8.5)
        self.assertFalse(baseline_row["api_cost_available"])
        self.assertIsNone(baseline_row["api_cost_usd_total"])
        self.assertEqual(pq_can_task["mode"], "pq_can")
        self.assertTrue(pq_can_task["runtime_auth_enabled"])
        self.assertEqual(pq_can_task["oracle_reason"], "meeting_scheduled")

    def test_security_evidence_tables_expose_u9_u10_rows(self) -> None:
        """Paper tables should include U9 properties and U10 evidence mappings.

        论文表格输出必须包含安全性质与证据映射，避免 U9/U10 只停留在文档。
        """
        tables = build_paper_tables(
            {
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                )
            }
        )

        property_ids = {
            row["property_id"]
            for row in tables["security_property_rows"]
        }
        evidence_names = {
            row["name"]
            for row in tables["security_evidence_rows"]
        }

        self.assertEqual(property_ids, set(SECURITY_PROPERTY_ORDER))
        self.assertIn("tampered_message", evidence_names)
        self.assertIn("missing_request_envelope", evidence_names)
        self.assertIn("shamir_secured_pq_can", evidence_names)

    def test_proof_appendix_tables_expose_security_kernel_rows(self) -> None:
        """Proof appendix 表必须把 security-kernel 事实源转成论文表格。"""
        tables = build_paper_tables(
            {
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                )
            }
        )

        self.assertEqual(
            tables["proof_claim_rows"][0]["claim"],
            EXECUTE_SURFACE_CLAIM,
        )
        self.assertEqual(
            {row["sink_id"] for row in tables["protected_sink_rows"]},
            {sink.sink_id for sink in protected_sink_audits()},
        )
        self.assertEqual(
            {row["mutation_id"] for row in tables["proof_mutation_rows"]},
            {evidence.mutation_id for evidence in kernel_mutation_evidence()},
        )
        self.assertEqual(
            {row["mapping_id"] for row in tables["model_refinement_rows"]},
            {mapping.mapping_id for mapping in model_refinement_mappings()},
        )
        self.assertEqual(
            {row["layer_id"] for row in tables["layer_refinement_rows"]},
            {mapping.layer_id for mapping in layer_refinement_mappings()},
        )
        mutation_rows = {
            row["mutation_id"]: row
            for row in tables["proof_mutation_rows"]
        }
        self.assertEqual(
            mutation_rows["bypass_delegation_parent_digest_check"][
                "protected_property"
            ],
            "delegation_ok",
        )

    def test_optional_proof_artifact_summary_row(self) -> None:
        """Artifact summary 参数应生成可引用的 GitHub proof-hardening 行。"""
        tables = build_paper_tables(
            {
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                )
            },
            proof_artifact_summary=_proof_summary(),
            mutation_evidence_summary=_mutation_summary(),
            proof_artifact_name="proof-hardening-27191142461.zip",
            proof_artifact_sha256="f659a94e",
        )

        row = tables["proof_artifact_rows"][0]
        self.assertEqual(row["artifact_name"], "proof-hardening-27191142461.zip")
        self.assertEqual(row["artifact_sha256"], "f659a94e")
        self.assertTrue(row["passed"])
        self.assertEqual(row["proof_tests_summary"], "85 passed, 37 subtests passed")
        self.assertTrue(row["mutation_validation_passed"])
        self.assertEqual(row["mutation_count"], 8)
        self.assertEqual(row["detected_count"], 8)
        self.assertTrue(row["all_detected"])
        self.assertEqual(row["undetected_count"], 0)

    def test_audit_counts_track_execution_gate_records_only(self) -> None:
        """Audit fields should preserve execution-gate counts without inventing tool failures."""
        tables = build_paper_tables(
            {
                "pq_can": _summary(
                    runtime_auth_enabled=True,
                    task_latency=12.0,
                    model_call_count=3,
                    llm_elapsed=9.75,
                    peer_audit_reject_count=2,
                )
            }
        )

        row = tables["run_level_rows"][0]
        task_row = tables["task_level_rows"][0]
        self.assertEqual(row["audit_record_count"], 2)
        self.assertEqual(row["audit_reject_count"], 0)
        self.assertEqual(task_row["peer_audit_reject_count"], 2)

    def test_load_end_to_end_summary_reads_json_object(self) -> None:
        """Summary loader should reject non-object JSON and return objects unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_path = Path(tmpdir) / "summary.json"
            summary_path.write_text(json.dumps({"task_count": 0}), encoding="utf-8")

            self.assertEqual(load_end_to_end_summary(summary_path), {"task_count": 0})

            summary_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                load_end_to_end_summary(summary_path)

    def test_format_markdown_table_outputs_stable_cells(self) -> None:
        """Markdown output should keep column order and render None as an empty cell."""
        markdown = format_markdown_table(
            [{"mode": "baseline", "api_cost_usd_total": None, "value": 1.230000}],
            ("mode", "api_cost_usd_total", "value"),
        )

        self.assertEqual(
            markdown.splitlines(),
            [
                "| mode | api_cost_usd_total | value |",
                "| --- | --- | --- |",
                "| baseline |  | 1.23 |",
            ],
        )

    def test_format_paper_tables_markdown_outputs_all_sections(self) -> None:
        """Full Markdown formatter should render all paper-table sections."""
        tables = build_paper_tables(
            {
                "baseline": _summary(
                    runtime_auth_enabled=False,
                    task_latency=10.0,
                    model_call_count=2,
                    llm_elapsed=8.5,
                )
            }
        )

        markdown = format_paper_tables_markdown(tables)

        self.assertIn("## Run-Level Summary", markdown)
        self.assertIn("## Task-Level Summary", markdown)
        self.assertIn("## Security Properties", markdown)
        self.assertIn("## Security Evidence", markdown)
        self.assertIn("## Proof Claim", markdown)
        self.assertIn("## Protected Sinks", markdown)
        self.assertIn("## Proof Mutation Evidence", markdown)
        self.assertIn("## Model Refinement Mapping", markdown)
        self.assertIn("## Layer Refinement Mapping", markdown)
        self.assertIn("## Proof Artifact Summary", markdown)
        self.assertTrue(markdown.endswith("\n"))

    def test_write_paper_table_archive_writes_json_and_markdown(self) -> None:
        """Archive writer should persist both machine-readable and reviewable outputs."""
        tables = build_paper_tables(
            {
                "baseline": _summary(
                    runtime_auth_enabled=False,
                    task_latency=10.0,
                    model_call_count=2,
                    llm_elapsed=8.5,
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = write_paper_table_archive(tables, tmpdir)

            self.assertEqual(paths["json"], Path(tmpdir) / "paper_tables.json")
            self.assertEqual(paths["markdown"], Path(tmpdir) / "paper_tables.md")
            self.assertEqual(
                json.loads(paths["json"].read_text(encoding="utf-8")),
                tables,
            )
            self.assertIn(
                "## Run-Level Summary",
                paths["markdown"].read_text(encoding="utf-8"),
            )

    def test_cli_output_dir_archives_without_suppressing_stdout(self) -> None:
        """CLI archive mode should write files while keeping the selected stdout format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "baseline.json"
            pq_can_path = Path(tmpdir) / "pq_can.json"
            archive_dir = Path(tmpdir) / "archive"
            baseline_path.write_text(
                json.dumps(
                    _summary(
                        runtime_auth_enabled=False,
                        task_latency=10.0,
                        model_call_count=2,
                        llm_elapsed=8.5,
                    )
                ),
                encoding="utf-8",
            )
            pq_can_path.write_text(
                json.dumps(
                    _summary(
                        runtime_auth_enabled=True,
                        task_latency=12.0,
                        model_call_count=3,
                        llm_elapsed=9.75,
                    )
                ),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "--baseline-summary",
                    str(baseline_path),
                    "--pq-can-summary",
                    str(pq_can_path),
                    "--format",
                    "markdown",
                    "--output-dir",
                    str(archive_dir),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue((archive_dir / "paper_tables.json").exists())
            self.assertTrue((archive_dir / "paper_tables.md").exists())

    def test_cli_accepts_optional_proof_artifact_summaries(self) -> None:
        """CLI 应把 proof-hardening artifact summary 写入归档 JSON。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline_path = root / "baseline.json"
            pq_can_path = root / "pq_can.json"
            proof_path = root / "proof_hardening_check_summary.json"
            mutation_path = root / "mutation_evidence_summary.json"
            archive_dir = root / "archive"
            baseline_path.write_text(
                json.dumps(
                    _summary(
                        runtime_auth_enabled=False,
                        task_latency=10.0,
                        model_call_count=2,
                        llm_elapsed=8.5,
                    )
                ),
                encoding="utf-8",
            )
            pq_can_path.write_text(
                json.dumps(
                    _summary(
                        runtime_auth_enabled=True,
                        task_latency=12.0,
                        model_call_count=3,
                        llm_elapsed=9.75,
                    )
                ),
                encoding="utf-8",
            )
            proof_path.write_text(json.dumps(_proof_summary()), encoding="utf-8")
            mutation_path.write_text(json.dumps(_mutation_summary()), encoding="utf-8")

            exit_code = main(
                [
                    "--baseline-summary",
                    str(baseline_path),
                    "--pq-can-summary",
                    str(pq_can_path),
                    "--format",
                    "json",
                    "--output-dir",
                    str(archive_dir),
                    "--proof-hardening-summary",
                    str(proof_path),
                    "--mutation-evidence-summary",
                    str(mutation_path),
                    "--proof-artifact-name",
                    "proof-hardening-27191142461.zip",
                    "--proof-artifact-sha256",
                    "f659a94e",
                ]
            )

            archived = json.loads(
                (archive_dir / "paper_tables.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                archived["proof_artifact_rows"][0]["proof_tests_summary"],
                "85 passed, 37 subtests passed",
            )

    def test_checked_in_proof_appendix_manifest_matches_archive(self) -> None:
        """checked-in manifest 必须与 appendix 表格中的 artifact summary 一致。"""
        manifest = json.loads(
            (PROOF_APPENDIX_ARCHIVE_DIR / "artifact_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        archive = json.loads(
            (PROOF_APPENDIX_ARCHIVE_DIR / "paper_tables.json").read_text(
                encoding="utf-8"
            )
        )

        artifact_row = archive["proof_artifact_rows"][0]
        self.assertEqual(artifact_row["artifact_name"], manifest["artifact_name"])
        self.assertEqual(artifact_row["artifact_sha256"], manifest["artifact_sha256"])
        self.assertEqual(
            artifact_row["proof_tests_summary"],
            manifest["proof_tests_summary"],
        )
        self.assertEqual(artifact_row["mutation_count"], manifest["mutation_count"])
        self.assertEqual(artifact_row["detected_count"], manifest["detected_count"])
        self.assertEqual(
            artifact_row["undetected_count"],
            manifest["undetected_count"],
        )
        for output_path in manifest["generated_outputs"]:
            self.assertTrue((REPO_ROOT / output_path).exists())

    def test_default_summary_paths_can_build_current_20260527_tables(self) -> None:
        """Checked local run summaries should remain readable when present in the workspace."""
        if not DEFAULT_BASELINE_SUMMARY_PATH.exists() or not DEFAULT_PQ_CAN_SUMMARY_PATH.exists():
            self.skipTest("local ignored end-to-end summaries are not present")

        tables = build_paper_tables(
            {
                "baseline": load_end_to_end_summary(DEFAULT_BASELINE_SUMMARY_PATH),
                "pq_can": load_end_to_end_summary(DEFAULT_PQ_CAN_SUMMARY_PATH),
            }
        )

        rows_by_mode = {
            str(row["mode"]): row
            for row in tables["run_level_rows"]
        }
        self.assertEqual(rows_by_mode["baseline"]["succeeded_count"], 3)
        self.assertEqual(rows_by_mode["pq_can"]["succeeded_count"], 3)
        self.assertEqual(rows_by_mode["baseline"]["audit_record_count"], 0)
        self.assertEqual(rows_by_mode["pq_can"]["audit_record_count"], 0)


if __name__ == "__main__":
    unittest.main()
