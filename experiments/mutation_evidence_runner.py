"""Executable mutation-evidence runner for the strict runtime-auth kernel."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence

from saga.security_kernel import mutation_evidence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_TIMEOUT_SECONDS = 180.0


@dataclass(frozen=True)
class MutationPatch:
    """描述一个只作用于临时副本的源码替换 mutation。"""

    relative_path: str
    needle: str
    replacement: str
    expected_occurrences: int = 1


@dataclass(frozen=True)
class MutationSpec:
    """绑定 mutation 清单、源码替换和预期失败测试。"""

    mutation_id: str
    description: str
    patches: tuple[MutationPatch, ...]
    expected_test_failures: tuple[str, ...]

    def pytest_command(self, python_executable: str = sys.executable) -> tuple[str, ...]:
        """生成用于检测该 mutation 的 pytest 命令。"""
        return (
            python_executable,
            "-m",
            "pytest",
            "-q",
            *self.expected_test_failures,
        )


@dataclass(frozen=True)
class MutationRunResult:
    """记录一次 mutation 检测运行结果。"""

    mutation_id: str
    mutation_detected: bool
    returncode: int | None
    command: tuple[str, ...]
    workspace: str | None
    applied: bool
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str = ""
    dry_run: bool = False

    def as_dict(self) -> dict[str, object]:
        """转换为稳定 JSON 字段，便于论文证据和 CI artifact 读取。"""
        return {
            "mutation_id": self.mutation_id,
            "mutation_detected": self.mutation_detected,
            "returncode": self.returncode,
            "command": list(self.command),
            "workspace": self.workspace,
            "applied": self.applied,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "error": self.error,
            "dry_run": self.dry_run,
        }


def mutation_specs() -> tuple[MutationSpec, ...]:
    """返回当前 P4 mutation evidence 的可执行 mutation 定义。"""
    evidence_by_id = {evidence.mutation_id: evidence for evidence in mutation_evidence()}
    return (
        MutationSpec(
            mutation_id="skip_prompt_surface_authorization",
            description="Bypass llm_prompt authorization before local_agent.run.",
            patches=(
                MutationPatch(
                    relative_path="saga/agent.py",
                    needle=(
                        '        if execution_context.authorize_action("llm_prompt"):\n'
                        "            return ExecutionGateDecision(\n"
                        "                True,\n"
                        '                "prompt_scope_authorized",\n'
                    ),
                    replacement=(
                        "        if True:\n"
                        "            return ExecutionGateDecision(\n"
                        "                True,\n"
                        '                "prompt_scope_authorized_mutation",\n'
                    ),
                ),
            ),
            expected_test_failures=evidence_by_id[
                "skip_prompt_surface_authorization"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="disable_local_execution_context_require_action",
            description="Make LocalExecutionContext.require_action a no-op.",
            patches=(
                MutationPatch(
                    relative_path="saga/execution_gate.py",
                    needle=(
                        "        if not self.authorize_action(action_scope):\n"
                        "            raise ExecutionAuthorizationError(\n"
                        "                reason_for_unauthorized_scope(action_scope),\n"
                        "                action_scope,\n"
                        "            )\n"
                    ),
                    replacement="        return None\n",
                ),
            ),
            expected_test_failures=evidence_by_id[
                "disable_local_execution_context_require_action"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="skip_replay_reserve",
            description="Return from consume_request before replay reserve/consume state.",
            patches=(
                MutationPatch(
                    relative_path="saga/execution_gate.py",
                    needle=(
                        "        assert decision.request_envelope is not None\n"
                        "        request_id = self._request_replay_id(decision.request_envelope)\n"
                    ),
                    replacement=(
                        "        return decision\n\n"
                        "        assert decision.request_envelope is not None\n"
                        "        request_id = self._request_replay_id(decision.request_envelope)\n"
                    ),
                ),
            ),
            expected_test_failures=evidence_by_id["skip_replay_reserve"].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="relax_action_scope_matching",
            description="Make action scope matching accept unrelated granted scopes.",
            patches=(
                MutationPatch(
                    relative_path="saga/messages.py",
                    needle=(
                        "    if granted_base != requested_base:\n"
                        "        return False\n"
                        "    if granted_detail is None:\n"
                        "        return True\n"
                        "    return granted_detail == requested_detail\n"
                    ),
                    replacement=(
                        "    if granted_base != requested_base:\n"
                        "        return True\n"
                        "    return True\n"
                    ),
                ),
            ),
            expected_test_failures=evidence_by_id[
                "relax_action_scope_matching"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="bypass_gated_execution_resource",
            description="Return raw business backend resources instead of GatedExecutionResource.",
            patches=(
                MutationPatch(
                    relative_path="agent_backend/base.py",
                    needle=(
                        "        return GatedExecutionResource(\n"
                        "            resource,\n"
                        "            self._execution_capability_facade(),\n"
                        "            method_scopes,\n"
                        "        )\n"
                    ),
                    replacement="        return resource  # type: ignore[return-value]\n",
                ),
            ),
            expected_test_failures=evidence_by_id[
                "bypass_gated_execution_resource"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="bypass_shamir_mask_real_valued_rejection",
            description="Accept unsafe real-valued CAN inputs when the Shamir MASK fires.",
            patches=(
                MutationPatch(
                    relative_path="neural/can.py",
                    needle=(
                        "        if mask_value > 0.0:\n"
                        "            return 0\n"
                    ),
                    replacement=(
                        "        if mask_value > 0.0:\n"
                        "            return 1\n"
                    ),
                ),
            ),
            expected_test_failures=evidence_by_id[
                "bypass_shamir_mask_real_valued_rejection"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="bypass_delegation_parent_digest_check",
            description=(
                "Trust child-declared parent scopes instead of requiring a known "
                "parent envelope digest."
            ),
            patches=(
                MutationPatch(
                    relative_path="saga/execution_gate.py",
                    needle=(
                        "        parent_scopes = self.parent_capability_store.get(envelope.parent_envelope_digest)\n"
                        "        if parent_scopes is None:\n"
                        "            return ExecutionGateDecision(\n"
                        "                False,\n"
                        '                "unknown_parent_envelope_digest",\n'
                        "                request_envelope_valid=True,\n"
                        "                request_envelope=envelope,\n"
                        "            )\n"
                    ),
                    replacement=(
                        "        parent_scopes = self.parent_capability_store.get(envelope.parent_envelope_digest)\n"
                        "        if parent_scopes is None:\n"
                        "            parent_scopes = envelope.parent_authorized_scopes\n"
                    ),
                ),
            ),
            expected_test_failures=evidence_by_id[
                "bypass_delegation_parent_digest_check"
            ].expected_test_failures,
        ),
        MutationSpec(
            mutation_id="bypass_policy_compiler_scope_filter",
            description=(
                "Sign all requested scopes instead of intersecting them with "
                "local policy."
            ),
            patches=(
                MutationPatch(
                    relative_path="saga/intent.py",
                    needle=(
                        "        allowed = {\n"
                        "            requested_scope\n"
                        "            for requested_scope in requested\n"
                        "            if self._policy_allows(requested_scope)\n"
                        "        }\n"
                    ),
                    replacement="        allowed = set(requested)\n",
                ),
            ),
            expected_test_failures=evidence_by_id[
                "bypass_policy_compiler_scope_filter"
            ].expected_test_failures,
        ),
    )


def available_mutations() -> tuple[str, ...]:
    """返回可执行 mutation id 列表，供 CLI choices 和测试复用。"""
    return tuple(spec.mutation_id for spec in mutation_specs())


def select_mutations(values: Iterable[str] | None) -> tuple[MutationSpec, ...]:
    """规范化 CLI mutation 选择；``all`` 会展开为全部 mutation。"""
    requested = tuple(values or ("all",))
    by_id = {spec.mutation_id: spec for spec in mutation_specs()}
    if "all" in requested:
        return tuple(by_id.values())

    selected: list[MutationSpec] = []
    seen: set[str] = set()
    for value in requested:
        if value in seen:
            continue
        try:
            selected.append(by_id[value])
        except KeyError as exc:
            raise ValueError(f"unknown mutation: {value}") from exc
        seen.add(value)
    return tuple(selected)


def apply_mutation_patches(workspace: Path, spec: MutationSpec) -> None:
    """在临时 workspace 中应用指定 mutation 的精确源码替换。"""
    for patch in spec.patches:
        target = workspace / patch.relative_path
        text = target.read_text(encoding="utf-8")
        count = text.count(patch.needle)
        if count != patch.expected_occurrences:
            raise RuntimeError(
                f"{spec.mutation_id}: expected {patch.expected_occurrences} "
                f"occurrences in {patch.relative_path}, found {count}"
            )
        target.write_text(text.replace(patch.needle, patch.replacement), encoding="utf-8")


def copy_mutation_workspace(source_root: Path, destination_root: Path) -> None:
    """复制当前仓库的非 ignored 文件到临时目录，用于无破坏 mutation。"""
    files = _tracked_or_unignored_files(source_root)
    for relative in files:
        source = source_root / relative
        destination = destination_root / relative
        if not source.is_file():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def run_mutation(
    spec: MutationSpec,
    *,
    source_root: Path = REPO_ROOT,
    output_dir: Path | None = None,
    keep_workspace: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    python_executable: str = sys.executable,
    dry_run: bool = False,
) -> MutationRunResult:
    """复制临时仓库、应用 mutation，并确认对应测试能检测到该变更。"""
    command = spec.pytest_command(python_executable)
    if dry_run:
        return MutationRunResult(
            mutation_id=spec.mutation_id,
            mutation_detected=False,
            returncode=None,
            command=command,
            workspace=None,
            applied=False,
            dry_run=True,
        )

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if keep_workspace:
        if output_dir is None:
            raise ValueError("output_dir is required when keep_workspace=True")
        workspace_path = output_dir / "workspaces" / spec.mutation_id
        if workspace_path.exists():
            shutil.rmtree(workspace_path)
        workspace_path.mkdir(parents=True)
        return _run_mutation_in_workspace(
            spec,
            source_root=source_root,
            workspace=workspace_path,
            command=command,
            timeout_seconds=timeout_seconds,
        )

    with tempfile.TemporaryDirectory(prefix=f"saga-mut-{spec.mutation_id}-") as tmpdir:
        workspace_path = Path(tmpdir) / "repo"
        workspace_path.mkdir()
        return _run_mutation_in_workspace(
            spec,
            source_root=source_root,
            workspace=workspace_path,
            command=command,
            timeout_seconds=timeout_seconds,
        )


def run_mutation_evidence(
    mutation_names: Iterable[str] | None = None,
    *,
    output_dir: str | Path | None = None,
    keep_workspaces: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    source_root: str | Path = REPO_ROOT,
    python_executable: str = sys.executable,
    dry_run: bool = False,
) -> list[MutationRunResult]:
    """运行一组 mutation evidence，并可写出 JSON artifact。"""
    selected = select_mutations(mutation_names)
    base_output_dir = Path(output_dir) if output_dir is not None else _default_output_dir()
    base_output_dir.mkdir(parents=True, exist_ok=True)
    results = [
        run_mutation(
            spec,
            source_root=Path(source_root),
            output_dir=base_output_dir,
            keep_workspace=keep_workspaces,
            timeout_seconds=timeout_seconds,
            python_executable=python_executable,
            dry_run=dry_run,
        )
        for spec in selected
    ]
    write_mutation_results(results, base_output_dir)
    return results


def build_summary(results: Iterable[MutationRunResult]) -> dict[str, object]:
    """汇总 mutation runner 结果，``all_detected`` 表示全部 mutation 被测试发现。"""
    result_list = list(results)
    detected = [result.mutation_id for result in result_list if result.mutation_detected]
    failed = [
        result.mutation_id
        for result in result_list
        if not result.mutation_detected and not result.dry_run
    ]
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "mutation_count": len(result_list),
        "detected_count": len(detected),
        "undetected_count": len(failed),
        "all_detected": len(detected) == len(result_list) and not any(
            result.dry_run for result in result_list
        ),
        "dry_run": all(result.dry_run for result in result_list) if result_list else False,
        "detected_mutations": detected,
        "undetected_mutations": failed,
        "mutations": [result.mutation_id for result in result_list],
    }


def write_mutation_results(
    results: Iterable[MutationRunResult],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """写出 mutation evidence JSONL 和 summary。"""
    result_list = list(results)
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    results_path = base_dir / "mutation_evidence.jsonl"
    with results_path.open("w", encoding="utf-8") as handle:
        for result in result_list:
            handle.write(json.dumps(result.as_dict(), sort_keys=True) + "\n")

    summary_path = base_dir / "mutation_evidence_summary.json"
    summary = build_summary(result_list)
    summary["results_path"] = str(results_path)
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return results_path, summary_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 mutation evidence runner 的 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description=(
            "Run non-destructive mutation evidence checks for the strict "
            "SAGA-PQ-CAN runtime-auth kernel."
        )
    )
    parser.add_argument(
        "--mutation",
        action="append",
        choices=[*available_mutations(), "all"],
        help="Mutation to run. Repeat for multiple mutations, or use all.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for JSONL results and summary. Defaults under experiments/runs.",
    )
    parser.add_argument(
        "--keep-workspaces",
        action="store_true",
        help="Keep mutated temporary workspaces under the output directory.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-mutation pytest timeout.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print and write planned mutation commands without running pytest.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """运行 mutation evidence CLI；未被测试发现的 mutation 会返回非零。"""
    args = parse_args(argv)
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    results = run_mutation_evidence(
        args.mutation,
        output_dir=output_dir,
        keep_workspaces=args.keep_workspaces,
        timeout_seconds=args.timeout_seconds,
        dry_run=args.dry_run,
    )
    summary = build_summary(results)
    print(f"[mutation] output directory: {output_dir}")
    for result in results:
        if result.dry_run:
            status = "PLAN"
        else:
            status = "DETECTED" if result.mutation_detected else "UNDETECTED"
        print(
            "[mutation] "
            f"{status} {result.mutation_id}: returncode={result.returncode} "
            f"cmd={' '.join(result.command)}"
        )
    if summary["dry_run"]:
        return 0
    print(
        "[mutation] "
        f"detected={summary['detected_count']}/{summary['mutation_count']} "
        f"all_detected={summary['all_detected']}"
    )
    return 0 if summary["all_detected"] else 1


def _run_mutation_in_workspace(
    spec: MutationSpec,
    *,
    source_root: Path,
    workspace: Path,
    command: tuple[str, ...],
    timeout_seconds: float,
) -> MutationRunResult:
    """在已创建 workspace 中复制源码、应用 mutation 并执行 pytest。"""
    try:
        copy_mutation_workspace(source_root, workspace)
        apply_mutation_patches(workspace, spec)
    except Exception as exc:
        return MutationRunResult(
            mutation_id=spec.mutation_id,
            mutation_detected=False,
            returncode=None,
            command=command,
            workspace=str(workspace),
            applied=False,
            error=str(exc),
        )

    try:
        completed = subprocess.run(
            command,
            cwd=workspace,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return MutationRunResult(
            mutation_id=spec.mutation_id,
            mutation_detected=False,
            returncode=None,
            command=command,
            workspace=str(workspace),
            applied=True,
            stdout_tail=_tail(exc.stdout or ""),
            stderr_tail=_tail(exc.stderr or ""),
            error=f"pytest timed out after {timeout_seconds} seconds",
        )

    return MutationRunResult(
        mutation_id=spec.mutation_id,
        mutation_detected=completed.returncode == 1,
        returncode=completed.returncode,
        command=command,
        workspace=str(workspace),
        applied=True,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
    )


def _tracked_or_unignored_files(source_root: Path) -> tuple[Path, ...]:
    """读取 git 跟踪文件和未忽略新文件，避免复制实验产物和本地密钥目录。"""
    command = ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    completed = subprocess.run(
        command,
        cwd=source_root,
        text=True,
        capture_output=True,
        check=True,
    )
    return tuple(Path(line) for line in completed.stdout.splitlines() if line.strip())


def _tail(text: str, *, line_count: int = 80) -> str:
    """截取命令输出尾部，避免 artifact 过大。"""
    lines = text.splitlines()
    return "\n".join(lines[-line_count:])


def _default_output_dir() -> Path:
    """返回本轮 mutation evidence 的默认输出目录。"""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_RUNS_DIR / f"{timestamp}-mutation-evidence"


if __name__ == "__main__":
    raise SystemExit(main())
