"""Tests for local-agent API endpoint defaults."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from agent_backend.config import (
    DEFAULT_OPENAI_API_BASE,
    LocalAgentConfig,
    api_base_requires_openai_api_key,
)


class AgentBackendConfigTests(unittest.TestCase):
    """Verify OpenAI-compatible endpoint defaults and key handling."""

    def test_openai_server_model_uses_codexi_endpoint_by_default(self) -> None:
        """New OpenAIServerModel configs should default to the Codexi API base."""
        config = LocalAgentConfig(
            model_type="OpenAIServerModel",
            model="gpt-5.2",
            tools=[],
        )

        self.assertEqual(config.api_base, DEFAULT_OPENAI_API_BASE)

    def test_default_codexi_endpoint_requires_openai_api_key(self) -> None:
        """The default OpenAI-compatible endpoint should receive OPENAI_API_KEY."""
        self.assertTrue(api_base_requires_openai_api_key(DEFAULT_OPENAI_API_BASE))
        self.assertTrue(api_base_requires_openai_api_key(f"{DEFAULT_OPENAI_API_BASE}/"))
        self.assertTrue(api_base_requires_openai_api_key("https://api.openai.com/v1"))
        self.assertFalse(api_base_requires_openai_api_key("http://localhost:8000/v1"))

    def test_user_config_examples_use_codexi_endpoint(self) -> None:
        """All checked-in user config examples should use the default API base."""
        for config_path in sorted(Path("user_configs").glob("*.yaml")):
            with self.subTest(config=str(config_path)):
                config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                for agent in config.get("agents", []):
                    local_agent_config = agent.get("local_agent_config", {})
                    self.assertEqual(
                        local_agent_config.get("api_base"),
                        DEFAULT_OPENAI_API_BASE,
                    )


if __name__ == "__main__":
    unittest.main()
