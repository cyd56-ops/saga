"""Optional TLC checker for the strict runtime-auth TLA+ model."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile
from collections.abc import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
TLA_DIR = REPO_ROOT / "proofs" / "tla"
TLA_SPEC = TLA_DIR / "StrictRuntimeAuth.tla"
TLA_FULL_CONFIG = TLA_DIR / "StrictRuntimeAuth.cfg"
TLA_PAIR_SMOKE_CONFIG = TLA_DIR / "StrictRuntimeAuthPairSmoke.cfg"
TLA_LAYERED_SPEC = TLA_DIR / "StrictRuntimeAuthLayered.tla"
TLA_LAYERED_CONFIG = TLA_DIR / "StrictRuntimeAuthLayered.cfg"
DEFAULT_TLA2TOOLS_JAR = "/tmp/tla2tools.jar"
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_WORKERS = "1"


@dataclass(frozen=True)
class TLCCheckFinding:
    """记录 TLC 分解验收中的单个失败原因。"""

    artifact: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        """转换为稳定 JSON 字段。"""
        return {
            "artifact": self.artifact,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TLCRunResult:
    """记录一次 TLC 命令的执行结果和解析出的状态统计。"""

    name: str
    command: tuple[str, ...]
    spec_path: str
    config_path: str
    metadir: str
    returncode: int | None
    passed: bool
    initial_states: int | None = None
    states_generated: int | None = None
    distinct_states: int | None = None
    depth: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        """转换为可写入 TLC summary 的稳定 JSON 字段。"""
        return {
            "name": self.name,
            "command": list(self.command),
            "spec_path": self.spec_path,
            "config_path": self.config_path,
            "metadir": self.metadir,
            "returncode": self.returncode,
            "passed": self.passed,
            "initial_states": self.initial_states,
            "states_generated": self.states_generated,
            "distinct_states": self.distinct_states,
            "depth": self.depth,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "error": self.error,
        }


@dataclass(frozen=True)
class TLCStrictRuntimeAuthReport:
    """汇总 per-surface、pair smoke 与 layered TLC 的验收结果。"""

    passed: bool
    output_dir: str
    full_config: str
    checked_surfaces: tuple[str, ...]
    include_pair_smoke: bool
    include_layered_model: bool
    results: tuple[TLCRunResult, ...]
    findings: tuple[TLCCheckFinding, ...]

    def as_dict(self) -> dict[str, object]:
        """转换为机器可读的 TLC 验收报告。"""
        return {
            "passed": self.passed,
            "finding_count": len(self.findings),
            "findings": [finding.as_dict() for finding in self.findings],
            "output_dir": self.output_dir,
            "full_config": self.full_config,
            "checked_surfaces": list(self.checked_surfaces),
            "checked_surface_count": len(self.checked_surfaces),
            "include_pair_smoke": self.include_pair_smoke,
            "include_layered_model": self.include_layered_model,
            "results": [result.as_dict() for result in self.results],
        }


def run_tlc_strict_runtime_auth_check(
    *,
    output_dir: str | Path | None = None,
    surface_names: Sequence[str] | None = None,
    include_pair_smoke: bool = True,
    include_layered_model: bool = True,
    tla2tools_jar: str | Path = DEFAULT_TLA2TOOLS_JAR,
    java_executable: str = "java",
    workers: str = DEFAULT_WORKERS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> TLCStrictRuntimeAuthReport:
    """运行 per-surface、pair smoke 和 layered strict runtime-auth TLC 验收。"""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    base_output_dir = Path(output_dir) if output_dir is not None else _default_output_dir()
    cfg_dir = base_output_dir / "cfgs"
    metadir_root = base_output_dir / "states"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    metadir_root.mkdir(parents=True, exist_ok=True)

    full_surfaces = extract_tla_surface_constants(TLA_FULL_CONFIG.read_text(encoding="utf-8"))
    checked_surfaces = _select_surfaces(full_surfaces, surface_names)
    findings: list[TLCCheckFinding] = []
    results: list[TLCRunResult] = []

    for surface in checked_surfaces:
        cfg_path = write_surface_config(surface, cfg_dir)
        result = run_tlc_config(
            name=f"surface:{surface}",
            config_path=cfg_path,
            metadir=metadir_root / f"surface-{surface}",
            spec_path=TLA_SPEC,
            tla2tools_jar=tla2tools_jar,
            java_executable=java_executable,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        results.append(result)
        if not result.passed:
            findings.append(
                TLCCheckFinding(result.name, _failure_reason(result))
            )

    if include_pair_smoke:
        result = run_tlc_config(
            name="pair_smoke",
            config_path=TLA_PAIR_SMOKE_CONFIG,
            metadir=metadir_root / "pair-smoke",
            spec_path=TLA_SPEC,
            tla2tools_jar=tla2tools_jar,
            java_executable=java_executable,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        results.append(result)
        if not result.passed:
            findings.append(TLCCheckFinding(result.name, _failure_reason(result)))

    if include_layered_model:
        result = run_tlc_config(
            name="layered_model",
            config_path=TLA_LAYERED_CONFIG,
            metadir=metadir_root / "layered-model",
            spec_path=TLA_LAYERED_SPEC,
            tla2tools_jar=tla2tools_jar,
            java_executable=java_executable,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        results.append(result)
        if not result.passed:
            findings.append(TLCCheckFinding(result.name, _failure_reason(result)))

    report = TLCStrictRuntimeAuthReport(
        passed=not findings,
        output_dir=str(base_output_dir),
        full_config=str(TLA_FULL_CONFIG),
        checked_surfaces=checked_surfaces,
        include_pair_smoke=include_pair_smoke,
        include_layered_model=include_layered_model,
        results=tuple(results),
        findings=tuple(findings),
    )
    write_tlc_report(report, base_output_dir)
    return report


def run_tlc_config(
    *,
    name: str,
    config_path: str | Path,
    metadir: str | Path,
    tla2tools_jar: str | Path,
    java_executable: str,
    workers: str,
    timeout_seconds: float,
    spec_path: str | Path = TLA_SPEC,
) -> TLCRunResult:
    """运行单个 TLC cfg，并解析成功标记和状态空间统计。"""
    config = Path(config_path)
    spec = Path(spec_path)
    state_dir = Path(metadir)
    state_dir.mkdir(parents=True, exist_ok=True)
    command = (
        java_executable,
        "-XX:+UseParallelGC",
        "-cp",
        str(tla2tools_jar),
        "tlc2.TLC",
        "-workers",
        workers,
        "-config",
        str(config),
        "-metadir",
        str(state_dir),
        spec.name,
    )
    try:
        completed = subprocess.run(
            command,
            cwd=TLA_DIR,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return TLCRunResult(
            name=name,
            command=command,
            spec_path=str(spec),
            config_path=str(config),
            metadir=str(state_dir),
            returncode=None,
            passed=False,
            stdout_tail=_tail(exc.stdout),
            stderr_tail=_tail(exc.stderr),
            error=f"TLC command timed out after {timeout_seconds} seconds",
        )

    stats = parse_tlc_output(completed.stdout)
    passed = completed.returncode == 0 and stats["completed"]
    return TLCRunResult(
        name=name,
        command=command,
        spec_path=str(spec),
        config_path=str(config),
        metadir=str(state_dir),
        returncode=completed.returncode,
        passed=passed,
        initial_states=stats["initial_states"],
        states_generated=stats["states_generated"],
        distinct_states=stats["distinct_states"],
        depth=stats["depth"],
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
        error="" if passed else "TLC did not complete successfully",
    )


def extract_tla_surface_constants(config_text: str) -> tuple[str, ...]:
    """从 TLC cfg 的 Surfaces 集合中提取 model value 名称。"""
    match = re.search(r"Surfaces\s*=\s*\{(?P<body>.*?)\}", config_text, re.DOTALL)
    if match is None:
        raise ValueError("Surfaces constant set not found")
    return tuple(
        value.strip()
        for value in match.group("body").split(",")
        if value.strip()
    )


def write_surface_config(surface: str, output_dir: str | Path) -> Path:
    """为单个 surface 写出临时 TLC cfg。"""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", surface):
        raise ValueError(f"unsafe TLA model value: {surface!r}")
    output_path = Path(output_dir) / f"StrictRuntimeAuth_{surface}.cfg"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "\n".join(
            (
                "CONSTANTS",
                f"    Surfaces = {{{surface}}}",
                "",
                "SPECIFICATION Spec",
                "",
                "INVARIANTS",
                "    ExecuteSurfaceClaim",
                "    ScopeCheckRequired",
                "",
            )
        ),
        encoding="utf-8",
    )
    return output_path


def parse_tlc_output(output_text: str) -> dict[str, int | bool | None]:
    """解析 TLC 输出中的完成标记和状态空间统计。"""
    initial = _first_int(
        r"Finished computing initial states:\s+(\d+)\s+distinct states generated",
        output_text,
    )
    states_match = re.search(
        r"(\d+)\s+states generated,\s+(\d+)\s+distinct states found",
        output_text,
    )
    depth = _first_int(
        r"The depth of the complete state graph search is\s+(\d+)",
        output_text,
    )
    return {
        "completed": "Model checking completed. No error has been found." in output_text,
        "initial_states": initial,
        "states_generated": int(states_match.group(1)) if states_match else None,
        "distinct_states": int(states_match.group(2)) if states_match else None,
        "depth": depth,
    }


def write_tlc_report(report: TLCStrictRuntimeAuthReport, output_dir: str | Path) -> Path:
    """写出 strict runtime-auth TLC 验收 summary JSON。"""
    output_path = Path(output_dir) / "tlc_strict_runtime_auth_summary.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report.as_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """解析 strict runtime-auth TLC 验收 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description="Run decomposed TLC checks for StrictRuntimeAuth.tla."
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for generated cfgs, TLC metadirs, and summary JSON.",
    )
    parser.add_argument(
        "--surface",
        action="append",
        help="TLA surface model value to check. Repeat to run a subset.",
    )
    parser.add_argument(
        "--skip-pair-smoke",
        action="store_true",
        help="Skip checked-in two-surface smoke config.",
    )
    parser.add_argument(
        "--skip-layered-model",
        action="store_true",
        help="Skip checked-in symmetry-reduced layered TLA+ model.",
    )
    parser.add_argument(
        "--tla2tools-jar",
        default=DEFAULT_TLA2TOOLS_JAR,
        help="Path to tla2tools.jar.",
    )
    parser.add_argument(
        "--java-executable",
        default="java",
        help="Java executable used to run TLC.",
    )
    parser.add_argument(
        "--workers",
        default=DEFAULT_WORKERS,
        help="TLC worker count. Default 1 keeps bounded checks predictable.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Timeout for each TLC invocation.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """运行 strict runtime-auth TLC 分解验收 CLI；失败时返回非零。"""
    args = parse_args(argv)
    report = run_tlc_strict_runtime_auth_check(
        output_dir=args.output_dir,
        surface_names=args.surface,
        include_pair_smoke=not args.skip_pair_smoke,
        include_layered_model=not args.skip_layered_model,
        tla2tools_jar=args.tla2tools_jar,
        java_executable=args.java_executable,
        workers=args.workers,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.passed else 1


def _select_surfaces(
    full_surfaces: Sequence[str],
    selected_surfaces: Sequence[str] | None,
) -> tuple[str, ...]:
    """校验并去重用户选择的 surface；未选择时返回 full cfg 全量列表。"""
    if selected_surfaces is None:
        return tuple(full_surfaces)
    full_set = set(full_surfaces)
    selected: list[str] = []
    for surface in selected_surfaces:
        if surface not in full_set:
            raise ValueError(f"surface {surface!r} is not in StrictRuntimeAuth.cfg")
        if surface not in selected:
            selected.append(surface)
    return tuple(selected)


def _failure_reason(result: TLCRunResult) -> str:
    """生成稳定失败原因，供 summary findings 使用。"""
    if result.error:
        return result.error
    return f"TLC command returned {result.returncode}"


def _default_output_dir() -> Path:
    """返回默认 /tmp 输出目录，避免 TLC 运行状态进入仓库。"""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(tempfile.gettempdir()) / f"saga-tlc-strict-runtime-auth-{timestamp}"


def _tail(value: str | bytes | None, *, max_chars: int = 4000) -> str:
    """截取命令输出尾部，避免 summary JSON 过大。"""
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text[-max_chars:]


def _first_int(pattern: str, text: str) -> int | None:
    """从文本中提取第一个整数匹配。"""
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


if __name__ == "__main__":
    raise SystemExit(main())
