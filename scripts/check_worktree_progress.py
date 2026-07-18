#!/usr/bin/env python3
"""检查关联 worktree 的 HEAD 是否已登记到主工作树日志。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from typing import Sequence


REGISTRY_START = "<!-- worktree-progress:start -->"
REGISTRY_END = "<!-- worktree-progress:end -->"
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class WorktreeHead:
    """表示 Git porcelain 输出中的一个 worktree HEAD。"""

    path: Path
    commit: str
    branch: str | None


def parse_worktree_porcelain(output: str) -> tuple[WorktreeHead, ...]:
    """解析 `git worktree list --porcelain` 的稳定记录格式。"""

    worktrees: list[WorktreeHead] = []
    for record in output.strip().split("\n\n"):
        if not record.strip():
            continue
        fields: dict[str, str] = {}
        detached = False
        for line in record.splitlines():
            key, _, value = line.partition(" ")
            if key == "detached":
                detached = True
            else:
                fields[key] = value
        if "worktree" not in fields or "HEAD" not in fields:
            raise ValueError("worktree porcelain record is missing path or HEAD")
        branch = None if detached else fields.get("branch")
        worktrees.append(
            WorktreeHead(
                path=Path(fields["worktree"]),
                commit=fields["HEAD"],
                branch=branch,
            )
        )
    if not worktrees:
        raise ValueError("git reported no worktrees")
    return tuple(worktrees)


def parse_progress_registry(markdown: str) -> dict[str, str]:
    """读取主工作日志中的机器可读 branch-to-HEAD 登记表。"""

    if markdown.count(REGISTRY_START) != 1 or markdown.count(REGISTRY_END) != 1:
        raise ValueError("worktree progress registry markers must appear exactly once")
    payload = markdown.split(REGISTRY_START, 1)[1].split(REGISTRY_END, 1)[0].strip()
    if payload.startswith("```json") and payload.endswith("```"):
        payload = payload[len("```json") : -len("```")].strip()
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("worktree progress registry must be a JSON object")
    registry: dict[str, str] = {}
    for branch, commit in parsed.items():
        if not isinstance(branch, str) or not branch.startswith("refs/heads/"):
            raise ValueError("registry branch keys must use refs/heads/* names")
        if not isinstance(commit, str) or FULL_COMMIT_RE.fullmatch(commit) is None:
            raise ValueError(f"registry commit for {branch!r} must be a full lowercase hash")
        registry[branch] = commit
    return registry


def find_progress_mismatches(
    worktrees: Sequence[WorktreeHead],
    registry: dict[str, str],
) -> tuple[str, ...]:
    """比较非主、非 detached worktree 与主日志登记的精确 HEAD。"""

    findings: list[str] = []
    for worktree in worktrees[1:]:
        if worktree.branch is None:
            continue
        recorded = registry.get(worktree.branch)
        if recorded is None:
            findings.append(
                f"unrecorded worktree: {worktree.branch} at {worktree.commit}"
            )
        elif recorded != worktree.commit:
            findings.append(
                f"stale worktree: {worktree.branch} recorded {recorded}, "
                f"actual {worktree.commit}"
            )
    return tuple(findings)


def check_worktree_progress(repo_root: Path) -> tuple[str, ...]:
    """以 Git 主 worktree 的工作日志为准执行跨 worktree 同步检查。"""

    completed = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    worktrees = parse_worktree_porcelain(completed.stdout)
    primary_worklog = worktrees[0].path / "SAGA_PQ_CAN_WORKLOG.md"
    registry = parse_progress_registry(primary_worklog.read_text(encoding="utf-8"))
    return find_progress_mismatches(worktrees, registry)


def main(argv: Sequence[str] | None = None) -> int:
    """运行命令行检查，并以非零状态阻止带过期主日志的收尾。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="任一关联 worktree 的仓库根目录",
    )
    args = parser.parse_args(argv)
    try:
        findings = check_worktree_progress(args.repo_root.resolve())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"worktree progress check failed: {type(exc).__name__}: {exc}")
        return 2
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}")
        return 1
    print("worktree progress registry matches all linked branch HEADs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
