"""Tests for research-only toy runtime-auth user config examples."""

from __future__ import annotations

import unittest

from saga.config import UserConfig


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


if __name__ == "__main__":
    unittest.main()
