"""Optional proof-hardening acceptance entrypoint for SAGA-PQ-CAN."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from collections.abc import Iterable, Sequence

# 直接按脚本路径运行时，先把仓库根目录加入导入路径。
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from experiments import end_to_end_validation, mutation_evidence_runner
from saga.security_kernel import mutation_evidence


DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_PROOF_TESTS = (
    "tests/test_security_kernel.py",
    "tests/test_mutation_evidence_runner.py",
    "tests/test_end_to_end_validation.py",
    "tests/test_strict_runtime_auth_model.py",
    "tests/test_strict_runtime_auth_evidence_summary.py",
    "tests/test_tla_strict_runtime_auth.py",
    "tests/test_tlc_strict_runtime_auth_check.py",
)
DEFAULT_PROOF_TIMEOUT_SECONDS = 180.0
DEFAULT_MUTATION_TIMEOUT_SECONDS = 180.0


@dataclass(frozen=True)
class ProofCheckFinding:
    """记录 proof-hardening 验收中发现的单个问题。"""

    artifact: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        """转换为稳定 JSON 字段。"""
        return {
            "artifact": self.artifact,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CommandResult:
    """记录 proof-hardening 检查中执行的外部命令结果。"""

    name: str
    command: tuple[str, ...]
    returncode: int | None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        """转换为可写入验收报告的稳定 JSON 字段。"""
        return {
            "name": self.name,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "error": self.error,
        }


@dataclass(frozen=True)
class ProofHardeningCheckReport:
    """汇总 proof tests、mutation evidence 和 artifact validation 的验收结果。"""

    passed: bool
    output_dir: str
    proof_tests: CommandResult | None
    mutation_validation: end_to_end_validation.ArtifactValidationReport | None
    findings: tuple[ProofCheckFinding, ...]

    def as_dict(self) -> dict[str, object]:
        """转换为可机器读取的 proof-hardening 验收报告。"""
        payload: dict[str, object] = {
            "passed": self.passed,
            "finding_count": len(self.findings),
            "findings": [finding.as_dict() for finding in self.findings],
            "output_dir": self.output_dir,
        }
        if self.proof_tests is not None:
            payload["proof_tests"] = self.proof_tests.as_dict()
        if self.mutation_validation is not None:
            payload["mutation_validation"] = self.mutation_validation.as_dict()
        return payload


def run_proof_hardening_check(
    *,
    output_dir: str | Path | None = None,
    proof_tests: Sequence[str] = DEFAULT_PROOF_TESTS,
    mutation_names: Iterable[str] | None = None,
    required_mutations: Iterable[str] | None = None,
    skip_mutations: bool = False,
    proof_timeout_seconds: float = DEFAULT_PROOF_TIMEOUT_SECONDS,
    mutation_timeout_seconds: float = DEFAULT_MUTATION_TIMEOUT_SECONDS,
    python_executable: str = sys.executable,
) -> ProofHardeningCheckReport:
    """运行 opt-in proof-hardening 验收，并把结果写入输出目录。"""
    base_output_dir = Path(output_dir) if output_dir is not None else _default_output_dir()
    base_output_dir.mkdir(parents=True, exist_ok=True)

    findings: list[ProofCheckFinding] = []
    proof_result = _run_pytest_targets(
        proof_tests,
        timeout_seconds=proof_timeout_seconds,
        python_executable=python_executable,
    )
    if proof_result.returncode != 0:
        findings.append(
            ProofCheckFinding(
                "proof_tests",
                f"proof pytest command returned {proof_result.returncode}",
            )
        )
    if proof_result.error:
        findings.append(ProofCheckFinding("proof_tests", proof_result.error))

    mutation_validation: end_to_end_validation.ArtifactValidationReport | None = None
    if not skip_mutations:
        mutation_output_dir = base_output_dir / "mutation_evidence"
        selected_mutations = tuple(mutation_names or ("all",))
        try:
            mutation_evidence_runner.run_mutation_evidence(
                selected_mutations,
                output_dir=mutation_output_dir,
                timeout_seconds=mutation_timeout_seconds,
                python_executable=python_executable,
            )
            mutation_validation = end_to_end_validation.validate_mutation_evidence_run_dir(
                mutation_output_dir,
                required_mutations=(
                    tuple(required_mutations)
                    if required_mutations is not None
                    else _default_required_mutations(selected_mutations)
                ),
            )
        except Exception as exc:
            findings.append(ProofCheckFinding("mutation_evidence", str(exc)))
        else:
            if not mutation_validation.passed:
                findings.extend(
                    ProofCheckFinding(
                        f"mutation_evidence:{finding.artifact}",
                        finding.reason,
                    )
                    for finding in mutation_validation.findings
                )

    report = ProofHardeningCheckReport(
        passed=not findings,
        output_dir=str(base_output_dir),
        proof_tests=proof_result,
        mutation_validation=mutation_validation,
        findings=tuple(findings),
    )
    write_proof_hardening_report(report, base_output_dir)
    return report


def write_proof_hardening_report(
    report: ProofHardeningCheckReport,
    output_dir: str | Path,
) -> Path:
    """写出 proof-hardening 验收 summary JSON。"""
    output_path = Path(output_dir) / "proof_hardening_check_summary.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report.as_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 proof-hardening 验收 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description="Run optional proof-hardening checks for SAGA-PQ-CAN."
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for proof-hardening summary and mutation artifacts.",
    )
    parser.add_argument(
        "--proof-test",
        action="append",
        help="Pytest file/nodeid for proof checks. Repeat to override defaults.",
    )
    parser.add_argument(
        "--mutation",
        action="append",
        choices=[*mutation_evidence_runner.available_mutations(), "all"],
        help="Mutation to run. Repeat for a subset; default is all.",
    )
    parser.add_argument(
        "--required-mutation",
        action="append",
        help="Mutation id required during artifact validation.",
    )
    parser.add_argument(
        "--skip-mutations",
        action="store_true",
        help="Run only proof pytest targets; skip mutation evidence.",
    )
    parser.add_argument(
        "--proof-timeout-seconds",
        type=float,
        default=DEFAULT_PROOF_TIMEOUT_SECONDS,
        help="Timeout for the proof pytest command.",
    )
    parser.add_argument(
        "--mutation-timeout-seconds",
        type=float,
        default=DEFAULT_MUTATION_TIMEOUT_SECONDS,
        help="Per-mutation pytest timeout.",
    )
    parser.add_argument(
        "--python-executable",
        default=sys.executable,
        help="Python executable used for pytest subprocesses.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """运行 proof-hardening 验收 CLI；任一检查失败则返回非零。"""
    args = parse_args(argv)
    report = run_proof_hardening_check(
        output_dir=args.output_dir,
        proof_tests=tuple(args.proof_test) if args.proof_test else DEFAULT_PROOF_TESTS,
        mutation_names=args.mutation,
        required_mutations=args.required_mutation,
        skip_mutations=args.skip_mutations,
        proof_timeout_seconds=args.proof_timeout_seconds,
        mutation_timeout_seconds=args.mutation_timeout_seconds,
        python_executable=args.python_executable,
    )
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.passed else 1


def _run_pytest_targets(
    proof_tests: Sequence[str],
    *,
    timeout_seconds: float,
    python_executable: str,
) -> CommandResult:
    """运行 proof-hardening targeted pytest 集合。"""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    command = (python_executable, "-m", "pytest", "-q", *tuple(proof_tests))
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            name="proof_tests",
            command=command,
            returncode=None,
            stdout_tail=_tail(exc.stdout),
            stderr_tail=_tail(exc.stderr),
            error=f"proof pytest command timed out after {timeout_seconds} seconds",
        )
    return CommandResult(
        name="proof_tests",
        command=command,
        returncode=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
    )


def _default_required_mutations(selected_mutations: Sequence[str]) -> tuple[str, ...] | None:
    """根据 CLI mutation 选择推导 artifact validation 的默认 required 集合。"""
    if not selected_mutations or "all" in selected_mutations:
        return None
    return tuple(dict.fromkeys(selected_mutations))


def _default_output_dir() -> Path:
    """返回 proof-hardening check 默认输出目录。"""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_RUNS_DIR / f"{timestamp}-proof-hardening-check"


def _tail(value: str | bytes | None, *, max_chars: int = 4000) -> str:
    """截取命令输出尾部，避免 JSON summary 过大。"""
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text[-max_chars:]


if __name__ == "__main__":
    raise SystemExit(main())
