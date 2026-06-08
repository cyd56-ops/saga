"""Tests for the optional proof-hardening GitHub Actions workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "proof-hardening.yml"


class ProofHardeningWorkflowTests(unittest.TestCase):
    """验证可选 proof-hardening workflow 的触发边界和核心命令。"""

    def test_workflow_is_manual_only(self) -> None:
        """workflow 必须只通过 workflow_dispatch 手动触发，避免拖慢默认 CI。"""
        text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", text)
        self.assertIsNone(re.search(r"(?m)^\s*(push|pull_request):", text))

    def test_workflow_runs_existing_proof_hardening_entrypoint(self) -> None:
        """workflow 应复用仓库内已有 proof-hardening 验收入口。"""
        text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("python experiments/proof_hardening_check.py", text)
        self.assertIn("--output-dir artifacts/proof-hardening", text)
        self.assertIn("--skip-mutations", text)
        self.assertIn("actions/upload-artifact@v4", text)

    def test_workflow_installs_project_without_secret_inputs(self) -> None:
        """workflow 不应依赖模型密钥、真实服务凭据或自动推送权限。"""
        text = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("python -m pip install -r requirements.txt pytest", text)
        self.assertIn("python -m pip install -e .", text)
        self.assertIn("permissions:\n  contents: read", text)
        for forbidden in ("secrets.", "OPENAI_API_KEY", "MONGODB_URI", "git push"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
