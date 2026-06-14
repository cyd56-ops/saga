"""Tests for agent material loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from saga.agent import get_agent_material


class AgentMaterialTests(unittest.TestCase):
    """覆盖 agent 材料读取 helper 的路径类型兼容性。"""

    def test_get_agent_material_accepts_path_objects(self) -> None:
        """``get_agent_material`` 应同时支持 ``Path`` 和字符串目录。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir)
            material = {"aid": "alice@example.com:calendar_agent"}
            (agent_dir / "agent.json").write_text(
                json.dumps(material),
                encoding="utf-8",
            )

            self.assertEqual(get_agent_material(agent_dir), material)


if __name__ == "__main__":
    unittest.main()
