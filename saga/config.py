"""
    Helper module to read configuration settings for the SAGA application.
"""
import saga
import os
import yaml
from dataclasses import dataclass, field
from typing import Literal, List, Optional
from simple_parsing.helpers import Serializable

from agent_backend.config import LocalAgentConfig


CA_CONFIG = None
PROVIDER_CONFIG = None
USER_DEFAULT_CONFIG = None
AGENT_DEFAULT_CONFIG = None
MONGO_URI_FOR_TOOLS = None
ROOT_DIR = os.path.dirname(saga.__file__)


def populate_config():
    """
    Read config.yaml file and populate variables here.
    """
    global CA_CONFIG, PROVIDER_CONFIG, USER_DEFAULT_CONFIG, AGENT_DEFAULT_CONFIG, MONGO_URI_FOR_TOOLS
    config_path = os.path.join(os.path.dirname(ROOT_DIR), 'config.yaml')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at {config_path}")

    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    CA_CONFIG = config.get('ca', None)
    PROVIDER_CONFIG = config.get('provider', None)
    USER_DEFAULT_CONFIG = config.get('user', None)
    AGENT_DEFAULT_CONFIG = config.get('agent', None)
    if CA_CONFIG is None:
        raise ValueError("CA configuration not found in config.yaml")
    if PROVIDER_CONFIG is None:
        raise ValueError("Provider configuration not found in config.yaml")
    if USER_DEFAULT_CONFIG is None:
        raise ValueError("User configuration not found in config.yaml")
    if AGENT_DEFAULT_CONFIG is None:
        raise ValueError("Agent configuration not found in config.yaml")

    if CA_CONFIG.get('endpoint', None) is None:
        raise ValueError("CA endpoint not found in config.yaml")
    
    if PROVIDER_CONFIG.get('endpoint', None) is None:
        raise ValueError("Provider endpoint not found in config.yaml")
    

    # This is specific to our agent implementation, so not really required
    MONGO_URI_FOR_TOOLS = config.get('mongo_uri_for_tools', None)


# Auto-load on first import
if not CA_CONFIG:
    populate_config()


### CA ###
CA_WORKDIR = ROOT_DIR+"/ca"
CA_CERT_PATH = ROOT_DIR+'/ca/ca.crt'

### PROVIDER ###
PROVIDER_WORKDIR = ROOT_DIR+"/provider"
PROVIDER_CERT_PATH = ROOT_DIR+'/provider/provider.crt'

### USER ###
USER_WORKDIR = ROOT_DIR+"/user"

### TOKEN SETTINGS ###
Q_MAX = 50


@dataclass
class EndPointConfig(Serializable):
    """
    Configuration to capture the endpoint details for the agent.
    """
    ip: str
    """Endpoint IP of the agent."""
    port: int
    """Endpoint port of the agent."""
    device_name: str
    """Name of the device."""
    def __post_init__(self):
        if self.port <= 0 or self.port > 65535:
            raise ValueError("Port must be between 1 and 65535")


@dataclass
class ToyRuntimeAuthConfig(Serializable):
    """研究用 toy LWE 执行层认证配置。"""

    enabled: bool = False
    """Whether to enable the toy LWE runtime-auth path for this agent."""
    mode: Literal["toy_compiled_research", "toy_wrapper", "mldsa_external"] | None = None
    """Runtime-auth mode; omitted legacy configs are inferred from ``verifier_flavor``."""
    strict_execution_gate: bool = True
    """Whether runtime-auth mode rejects missing gate/context state."""
    seed: int = 0
    """Deterministic seed used to derive the toy LWE key pair."""
    verifier_flavor: str = "compiled"
    """Legacy toy verifier flavor; use ``mode`` for new configs."""
    message_bytes: int = 32
    """Envelope digest length expected by the verifier helper."""
    replay_state_dir: str | None = None
    """Optional shared replay marker directory for multi-workdir experiments."""
    trusted_public_keys: dict[str, str] = field(default_factory=dict)
    """Mapping from trusted peer AIDs to base64-encoded toy public keys."""

    def __post_init__(self) -> None:
        """Validate the minimal research-only runtime-auth settings."""
        valid_modes = {"toy_compiled_research", "toy_wrapper", "mldsa_external"}
        if self.mode is not None and self.mode not in valid_modes:
            raise ValueError(
                "mode must be one of: toy_compiled_research, toy_wrapper, mldsa_external"
            )
        if self.verifier_flavor not in {"compiled", "wrapper"}:
            raise ValueError("verifier_flavor must be 'compiled' or 'wrapper'")
        if self.mode == "toy_compiled_research" and self.verifier_flavor != "compiled":
            raise ValueError("toy_compiled_research mode requires verifier_flavor='compiled'")
        if self.mode == "toy_wrapper" and self.verifier_flavor != "wrapper":
            raise ValueError("toy_wrapper mode requires verifier_flavor='wrapper'")
        if self.message_bytes <= 0:
            raise ValueError("message_bytes must be positive")

    def resolved_mode(self) -> Literal["toy_compiled_research", "toy_wrapper", "mldsa_external"]:
        """返回规范化 runtime-auth mode，兼容旧的 verifier_flavor 配置。"""
        if self.mode is not None:
            return self.mode
        if self.verifier_flavor == "compiled":
            return "toy_compiled_research"
        return "toy_wrapper"

    def toy_verifier_flavor(self) -> Literal["compiled", "wrapper"]:
        """返回 toy mode 对应的 verifier flavor，ML-DSA mode 不允许调用。"""
        resolved_mode = self.resolved_mode()
        if resolved_mode == "toy_compiled_research":
            return "compiled"
        if resolved_mode == "toy_wrapper":
            return "wrapper"
        raise ValueError("mldsa_external mode does not use a toy verifier flavor")


@dataclass
class AgentConfig(Serializable):
    """
    Configuration for an agent.
    This includes the agent's name, description, local agent configuration, endpoint details, and contact rule-book.
    """
    name: str
    """Name of the agent."""
    description: str
    """Description of the agent."""
    local_agent_config: LocalAgentConfig
    """Config to use for the local agent."""
    endpoint: EndPointConfig
    """Endpoint details for where the agent will be hosted."""
    contact_rulebook: Optional[List[str]] = field(default_factory=list)
    """Contact rule-book for this particular agent (who can contact it, etc.)"""
    num_one_time_keys: Optional[int] = 100
    """Number of one-time-keys to generate for this agent. Defaults to 100"""
    toy_runtime_auth: Optional[ToyRuntimeAuthConfig] = None
    """Optional research-only toy LWE runtime-auth config."""


@dataclass
class UserConfig(Serializable):
    """
    Configuration for a user.
    """
    name: str
    """Name of the user."""
    email: str
    """Email ID of the user."""
    agents: List[AgentConfig] = field(default_factory=list)
    """List of agents associated with the user."""


def get_index_of_agent(config: UserConfig, agent_name: str) -> int:
    """
        Helper function to get the index of an agent (out of all agents) that matches a given name.

        Args:
            config (UserConfig): The user configuration containing the agents.
            agent_name (str): The name of the agent to find.
        Returns:
            int: The index of the agent in the list of agents, or None if not found.
    """
    # Find the index of the "writing_agent" out of all config.agents
    agent_index = next((i for i, agent in enumerate(config.agents) if agent.name == agent_name), None)
    return agent_index
