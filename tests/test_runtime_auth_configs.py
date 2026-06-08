"""Tests for research-only toy runtime-auth user config examples."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from saga.config import ReplayStoreConfig, UserConfig


class RuntimeAuthConfigExamplesTests(unittest.TestCase):
    """Verify the sample PQ-CAN config files parse into runtime-auth settings."""

    def test_emma_pqcan_config_loads_runtime_auth_for_all_agents(self) -> None:
        """Emma's sample config should enable toy runtime auth on all three agents."""
        config = UserConfig.load("user_configs/emma_pqcan.yaml", drop_extra_fields=True)

        self.assertEqual(len(config.agents), 3)
        for agent in config.agents:
            self.assertIsNotNone(agent.toy_runtime_auth)
            assert agent.toy_runtime_auth is not None
            self.assertTrue(agent.toy_runtime_auth.enabled)
            self.assertTrue(agent.toy_runtime_auth.strict_execution_gate)
            self.assertEqual(agent.toy_runtime_auth.verifier_flavor, "compiled")
            self.assertEqual(
                agent.toy_runtime_auth.resolved_mode(),
                "toy_compiled_research",
            )
            self.assertEqual(len(agent.toy_runtime_auth.trusted_public_keys), 1)

    def test_raj_pqcan_config_loads_runtime_auth_for_all_agents(self) -> None:
        """Raj's sample config should mirror the same runtime-auth structure."""
        config = UserConfig.load("user_configs/raj_pqcan.yaml", drop_extra_fields=True)

        self.assertEqual(len(config.agents), 3)
        for agent in config.agents:
            self.assertIsNotNone(agent.toy_runtime_auth)
            assert agent.toy_runtime_auth is not None
            self.assertTrue(agent.toy_runtime_auth.enabled)
            self.assertTrue(agent.toy_runtime_auth.strict_execution_gate)
            self.assertEqual(
                agent.toy_runtime_auth.resolved_mode(),
                "toy_compiled_research",
            )
            self.assertEqual(agent.toy_runtime_auth.message_bytes, 32)
            self.assertEqual(len(agent.toy_runtime_auth.trusted_public_keys), 1)

    def test_runtime_auth_replay_store_block_loads_from_yaml(self) -> None:
        """YAML 中的 replay_store 块应解析为显式 ReplayStoreConfig。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "runtime-auth.yaml"
            config_path.write_text(
                """
name: Test User
email: test@example.com
agents:
  - name: calendar_agent
    description: Calendar agent
    endpoint:
      ip: 127.0.0.1
      port: 7010
      device_name: localhost
    local_agent_config:
      model: gpt-5.2
      tools: []
    toy_runtime_auth:
      enabled: true
      mode: toy_compiled_research
      seed: 47
      verifier_flavor: compiled
      message_bytes: 32
      replay_store:
        backend: file_marker
        state_dir: /tmp/saga-pqcan-test-replay
      trusted_public_keys: {}
""".lstrip(),
                encoding="utf-8",
            )

            config = UserConfig.load(config_path, drop_extra_fields=True)

        runtime_auth = config.agents[0].toy_runtime_auth
        self.assertIsNotNone(runtime_auth)
        assert runtime_auth is not None
        replay_store = runtime_auth.resolved_replay_store()
        self.assertIsInstance(replay_store, ReplayStoreConfig)
        assert replay_store is not None
        self.assertEqual(replay_store.backend, "file_marker")
        self.assertEqual(replay_store.state_dir, "/tmp/saga-pqcan-test-replay")


if __name__ == "__main__":
    unittest.main()
