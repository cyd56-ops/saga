"""Tests for the Route B PolicyCompiler BG7/BG8 evidence runner."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from experiments.route_b_policy_compiler_runner import (
    POLICY_COMPILER_GATE_REPORT_VERSION_V1,
    build_policy_compiler_gate_report,
    main,
)


class RouteBPolicyCompilerRunnerTests(unittest.TestCase):
    """验证双 profile portability、manifest 边界和 CLI JSON contract。"""

    def test_report_passes_bg7_and_bg8_for_two_distinct_profiles(self) -> None:
        """两个 profile 应复用编译结构并分别通过差分与覆盖门槛。"""
        report = build_policy_compiler_gate_report(
            seed=401,
            differential_cases_per_profile=16,
            latency_iterations=8,
        )
        payload = report.as_dict()

        self.assertEqual(
            report.report_version,
            POLICY_COMPILER_GATE_REPORT_VERSION_V1,
        )
        self.assertTrue(report.all_passed)
        self.assertTrue(report.bg7_passed)
        self.assertTrue(report.bg8_passed)
        self.assertEqual(payload["profile_count"], 2)
        self.assertEqual(report.shared_layout_schema, "RouteBRawAuthorizationInputV1")
        self.assertEqual(report.shared_reference_class, "ReferenceAuthorizationRelationsV1")
        self.assertEqual(report.shared_circuit_class, "FixedAuthorizationCircuitV1")
        self.assertTrue(report.shared_gadget_classes)
        self.assertEqual(len({item.profile_digest for item in report.profiles}), 2)
        self.assertTrue(all(item.all_equivalent for item in report.profiles))
        self.assertTrue(all(item.coverage_complete for item in report.profiles))
        self.assertTrue(
            all(item.fixed_peak_python_bytes > 0 for item in report.profiles)
        )

    def test_manifest_preserves_security_and_measurement_boundaries(self) -> None:
        """机器清单必须记录无训练/无权限及微基准测量边界。"""
        report = build_policy_compiler_gate_report(
            seed=503,
            differential_cases_per_profile=8,
            latency_iterations=4,
        )
        payload = report.as_dict()
        encoded = json.dumps(payload, sort_keys=True)
        profiles = {item["profile"]["execution_surface_id"]: item for item in payload["profiles"]}

        self.assertEqual(set(profiles), {"general_authorization", "memory_access"})
        self.assertEqual(
            profiles["memory_access"]["profile"]["permitted_scope_families"],
            ["memory_read", "memory_write"],
        )
        self.assertTrue(
            all(item["trainable_finding_count"] == 0 for item in payload["profiles"])
        )
        self.assertTrue(
            all(item["authority_granted_count"] == 0 for item in payload["profiles"])
        )
        self.assertIn("tracemalloc_python_allocator_peak", encoded)
        self.assertIn("not Agent end-to-end latency", encoded)
        self.assertIn("not a second signature scheme", encoded)
        self.assertNotIn("private_key", encoded.lower())
        self.assertNotIn("secret_key", encoded.lower())

    def test_cli_writes_the_same_manifest_emitted_on_stdout(self) -> None:
        """CLI 应把同一份通过的 manifest 写入临时路径并返回零。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "route-b-policy-compiler.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--seed",
                        "607",
                        "--differential-cases",
                        "8",
                        "--latency-iterations",
                        "4",
                        "--output",
                        str(output_path),
                    ]
                )

            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout_payload, file_payload)
            self.assertTrue(file_payload["all_passed"])

    def test_report_rejects_boolean_or_empty_measurement_parameters(self) -> None:
        """固定种子、差分样本数和延迟次数必须是明确的内建整数。"""
        with self.assertRaises(TypeError):
            build_policy_compiler_gate_report(
                seed=True,
                differential_cases_per_profile=1,
                latency_iterations=1,
            )
        for field_name in (
            "differential_cases_per_profile",
            "latency_iterations",
        ):
            for value in (True, 0, -1):
                with self.subTest(field_name=field_name, value=value):
                    arguments = {
                        "seed": 1,
                        "differential_cases_per_profile": 1,
                        "latency_iterations": 1,
                    }
                    arguments[field_name] = value
                    with self.assertRaises(ValueError):
                        build_policy_compiler_gate_report(**arguments)


if __name__ == "__main__":
    unittest.main()
