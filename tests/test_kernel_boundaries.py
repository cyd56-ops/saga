"""测试 SAGA 内核导入边界，防止扩展依赖回流到核心路径。"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import unittest


class KernelBoundaryTests(unittest.TestCase):
    """验证 legacy SAGA 核心导入不会强制加载 PQ-CAN 扩展模块。"""

    def test_agent_import_does_not_eagerly_load_toy_pq_can_modules(self) -> None:
        """导入 saga.agent 时不应急切导入 toy LWE 或 neural CAN。"""
        script = textwrap.dedent(
            """
            import json
            import sys

            import saga.agent

            print(json.dumps({
                "neural": "neural" in sys.modules,
                "pq_toy_lwe": "pq.toy_lwe" in sys.modules,
            }, sort_keys=True))
            """
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.stdout.strip(), '{"neural": false, "pq_toy_lwe": false}')


if __name__ == "__main__":
    unittest.main()
