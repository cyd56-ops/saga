"""Tests for the primary-worktree progress synchronization guard."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from scripts.check_worktree_progress import (
    REGISTRY_END,
    REGISTRY_START,
    WorktreeHead,
    find_progress_mismatches,
    parse_progress_registry,
    parse_worktree_porcelain,
)


ROOT = Path(__file__).resolve().parents[1]


class WorktreeProgressCheckTests(unittest.TestCase):
    """验证 worktree 解析、日志登记与过期检测边界。"""

    def test_parse_worktree_porcelain_preserves_branch_and_detached_state(self) -> None:
        """porcelain 解析必须保留完整 HEAD，并忽略 detached 分支名。"""

        parsed = parse_worktree_porcelain(
            "worktree /repo\n"
            "HEAD 1111111111111111111111111111111111111111\n"
            "branch refs/heads/main\n\n"
            "worktree /repo/route-a\n"
            "HEAD 2222222222222222222222222222222222222222\n"
            "branch refs/heads/research/route-a\n\n"
            "worktree /repo/detached\n"
            "HEAD 3333333333333333333333333333333333333333\n"
            "detached\n"
        )

        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[1].branch, "refs/heads/research/route-a")
        self.assertIsNone(parsed[2].branch)

    def test_parse_progress_registry_requires_full_commit_hashes(self) -> None:
        """登记表必须使用完整 commit，避免短哈希碰撞或含糊记录。"""

        payload = {
            "refs/heads/research/route-a": "2" * 40,
            "refs/heads/research/route-b": "3" * 40,
        }
        markdown = (
            f"{REGISTRY_START}\n```json\n{json.dumps(payload)}\n```\n{REGISTRY_END}"
        )

        self.assertEqual(parse_progress_registry(markdown), payload)
        with self.assertRaises(ValueError):
            parse_progress_registry(
                f'{REGISTRY_START}\n{{"refs/heads/main": "abc1234"}}\n{REGISTRY_END}'
            )

    def test_find_progress_mismatches_detects_missing_and_stale_heads(self) -> None:
        """关联分支未登记或继续前进时必须报告同步失败。"""

        worktrees = (
            WorktreeHead(Path("/repo"), "1" * 40, "refs/heads/main"),
            WorktreeHead(Path("/repo/a"), "2" * 40, "refs/heads/research/a"),
            WorktreeHead(Path("/repo/b"), "3" * 40, "refs/heads/research/b"),
            WorktreeHead(Path("/repo/tmp"), "4" * 40, None),
        )

        findings = find_progress_mismatches(
            worktrees,
            {"refs/heads/research/a": "5" * 40},
        )

        self.assertEqual(len(findings), 2)
        self.assertIn("stale worktree", findings[0])
        self.assertIn("unrecorded worktree", findings[1])

    def test_repository_rules_require_the_progress_guard(self) -> None:
        """仓库规则与主日志收尾动作必须共同要求同步检查。"""

        command = "python scripts/check_worktree_progress.py"
        self.assertIn(command, (ROOT / "AGENTS.md").read_text(encoding="utf-8"))
        self.assertIn(
            command,
            (ROOT / "SAGA_PQ_CAN_WORKLOG.md").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
