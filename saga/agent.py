"""
    Agent class for the SAGA system.
"""
import threading
import time
import json
import os
import hashlib
import bson.json_util
import socket
import ssl
import base64
import binascii
import requests
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import traceback
from pathlib import Path
from collections.abc import Callable
from cryptography.x509 import Certificate

import saga.config
from saga.common.logger import Logger as logger
from saga.common.overhead import Monitor
from saga.common.contact_policy import check_rulebook, match
from saga.ca.CA import get_SAGA_CA
import saga.common.crypto as sc
from saga.execution_gate import (
    append_execution_gate_audit_record,
    build_execution_gate_audit_record,
    ExecutionAuthorizationError,
    ExecutionGateDecision,
    ExecutionGate,
    ExecutionGateRequest,
    LocalExecutionContext,
    ReplayStateStore,
    build_toy_lwe_execution_gate,
)
from saga.messages import RequestEnvelope, build_request_envelope
from saga.intent import AgentIntent, IntentCompiler, PolicyDecision
from saga.local_agent import LocalAgent, DummyAgent
from saga.runtime_diagnostics import (
    append_local_run_diagnostic_record,
    build_local_run_diagnostic_record,
)

DEBUG = False
NONCE_SIZE_BYTES = 12  # Size of the nonce in bytes
MAX_QUERIES = 100
# 真实 LLM 工具调用可能超过两分钟；该超时只限制 socket 等待，不改变 token/信封有效期。
CONVERSATION_SOCKET_TIMEOUT_SECONDS = 300.0
# TODO: Handle max_queries


def get_agent_material(dir_path: Path) -> dict:
    """
    Reads the agent material from the agent.json file in the given directory.

    Args:
        dir_path (Path): The directory path where the agent.json file is located.
    Returns:
        dict: The material read from the agent.json file.
    """
    # Check if dir exists:
    if not os.path.exists(dir_path):
        os.mkdir(dir_path)

    # Open agent.json
    if dir_path[-1] != '/':
        dir_path += "/"

    material = None
    with open(dir_path+"agent.json", "r") as f:
        material = json.load(f)
    
    return material


def serialize(obj):
    """
    Serializes the object to a JSON string.

    Args:
        obj: The object to serialize. It can be a bytes, list, dict, or any other type.
    """
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, list):
        return [serialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize(value) for key, value in obj.items()}
    else:
        return obj


def deserialize(obj):
    """
    Deserializes the object from a JSON string.

    Args:
        obj: The object to deserialize. It can be a base64 encoded string, list, dict, or any other type.
    """
    if isinstance(obj, str):
        try:
            return base64.b64decode(obj)
        except:
            return obj
    elif isinstance(obj, list):
        return [deserialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: deserialize(value) for key, value in obj.items()}
    else:
        return obj


def _default_replay_state_dir(agent: "Agent") -> Path | None:
    """返回 agent 默认的 replay 状态目录；缺少 workdir 时返回 ``None``。"""
    workdir = getattr(agent, "workdir", None)
    if not workdir:
        return None
    return Path(workdir) / "audit" / "replay"


def _require_default_replay_state_dir(agent: "Agent") -> Path:
    """返回安全模式默认 replay 目录；缺少 workdir 时 fail-closed。"""
    replay_state_dir = _default_replay_state_dir(agent)
    if replay_state_dir is None:
        raise RuntimeError(
            "runtime auth requires persistent replay state; configure an agent "
            "workdir or inject a ReplayStateStore backend"
        )
    return replay_state_dir


def _runtime_auth_replay_state_dir(
    agent: "Agent",
    replay_store_config: saga.config.ReplayStoreConfig | None,
) -> Path:
    """根据显式 replay backend 配置选择 marker 目录；强一致后端必须外部注入。"""
    if replay_store_config is None:
        return _require_default_replay_state_dir(agent)
    if replay_store_config.backend == "agent_workdir_file":
        return _require_default_replay_state_dir(agent)
    if replay_store_config.backend == "file_marker":
        assert replay_store_config.state_dir is not None
        return Path(replay_store_config.state_dir)
    if replay_store_config.backend == "external_strong_consistency":
        raise RuntimeError(
            "external_strong_consistency replay store requires explicit "
            "ReplayStateStore backend wiring; the config-driven path fails closed."
        )
    raise ValueError(f"unsupported replay store backend: {replay_store_config.backend}")


def _sync_execution_capability_mode(agent: "Agent") -> None:
    """把外层 strict runtime-auth 模式同步给支持 capability facade 的本地 agent。"""
    local_agent = getattr(agent, "local_agent", None)
    if hasattr(local_agent, "set_strict_execution_capabilities"):
        local_agent.set_strict_execution_capabilities(
            bool(getattr(agent, "strict_execution_gate", False))
        )


def enable_toy_lwe_runtime_auth(
    agent: "Agent",
    *,
    scheme: "ToyLWESignatureScheme",
    key_pair: "KeyPair",
    trusted_public_keys: dict[str, bytes],
    verifier_flavor: str = "compiled",
    message_bytes: int = 32,
    now_fn: Callable[[], datetime] | None = None,
    replay_state_dir: str | Path | None = None,
    replay_state_store: ReplayStateStore | None = None,
) -> ExecutionGate:
    """Attach research-only toy LWE signing and execution-gate wiring to an agent.

    This helper centralizes the current prototype runtime setup so experiments
    and future real-agent entry points can enable the full toy LWE path with one
    call instead of manually configuring both outbound signing and inbound gate
    verification.

    启用 toy LWE runtime auth 时默认打开严格执行层 gate，缺失 gate/context 会拒绝。
    """
    effective_replay_state_dir = replay_state_dir
    if replay_state_store is None:
        effective_replay_state_dir = replay_state_dir or _require_default_replay_state_dir(agent)

    gate = build_toy_lwe_execution_gate(
        scheme,
        trusted_public_keys,
        verifier_flavor=verifier_flavor,
        message_bytes=message_bytes,
        now_fn=now_fn,
        replay_state_dir=effective_replay_state_dir,
        replay_state_store=replay_state_store,
    )
    agent.pq_signature_scheme = scheme
    agent.pq_public_key = key_pair.public_key
    agent.pq_secret_key = key_pair.secret_key
    agent.execution_gate = gate
    agent.strict_execution_gate = True
    _sync_execution_capability_mode(agent)
    return gate


def enable_toy_lwe_runtime_auth_from_config(
    agent: "Agent",
    runtime_auth_config: saga.config.ToyRuntimeAuthConfig | None,
    *,
    now_fn: Callable[[], datetime] | None = None,
    replay_state_store: ReplayStateStore | None = None,
) -> ExecutionGate | None:
    """从配置块启用 runtime auth，并按 mode 与 replay backend 保持安全边界。"""
    if runtime_auth_config is None or not runtime_auth_config.enabled:
        return None

    mode = runtime_auth_config.resolved_mode()
    if mode == "mldsa_external":
        raise RuntimeError(
            "mldsa_external runtime auth requires explicit vetted backend wiring; "
            "the config-driven path fails closed by default."
        )

    trusted_public_keys: dict[str, bytes] = {}
    for aid, public_key_b64 in runtime_auth_config.trusted_public_keys.items():
        try:
            trusted_public_keys[aid] = base64.b64decode(public_key_b64, validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ValueError(f"invalid base64 trusted public key for {aid}") from exc

    replay_store_config = runtime_auth_config.resolved_replay_store()
    if replay_state_store is not None:
        if replay_store_config is None or replay_store_config.backend != "external_strong_consistency":
            raise ValueError(
                "explicit ReplayStateStore injection requires "
                "replay_store.backend='external_strong_consistency'"
            )
        replay_state_dir = None
    else:
        replay_state_dir = _runtime_auth_replay_state_dir(agent, replay_store_config)

    # toy LWE 只在显式启用 research runtime auth 时加载，避免 SAGA 核心路径强依赖 PQ-CAN。
    from pq.toy_lwe import ToyLWESignatureScheme

    scheme = ToyLWESignatureScheme(seed=runtime_auth_config.seed)
    key_pair = scheme.keygen()
    gate = enable_toy_lwe_runtime_auth(
        agent,
        scheme=scheme,
        key_pair=key_pair,
        trusted_public_keys=trusted_public_keys,
        verifier_flavor=runtime_auth_config.toy_verifier_flavor(),
        message_bytes=runtime_auth_config.message_bytes,
        now_fn=now_fn,
        replay_state_dir=replay_state_dir,
        replay_state_store=replay_state_store,
    )
    if agent.strict_execution_gate != runtime_auth_config.strict_execution_gate:
        agent.strict_execution_gate = runtime_auth_config.strict_execution_gate
        _sync_execution_capability_mode(agent)
    return gate


class Agent:
    """
        Main agent wrapper class for the SAGA system.
        This class is responsible for managing the agent's lifecycle, handling communication with other agents,
        and managing the agent's access control and security features.
    """
    def __init__(
        self,
        workdir: str,
        material: dict,
        local_agent: LocalAgent = None,
        execution_gate: ExecutionGate | None = None,
        strict_execution_gate: bool = False,
    ):
        """
        Initializes the Agent object with the given work directory and material.

        Args:
            workdir (str): The working directory for the agent.
            material (dict): The material for the agent, which contains the agent's credentials and other information.
            local_agent (LocalAgent): An optional local agent object that will be used to run tasks. If not provided, a DummyAgent will be used.
            execution_gate (ExecutionGate | None): Optional execution-layer gate.
            strict_execution_gate (bool): Reject execution when gate/context state is missing.

        严格执行层 gate 模式用于 PQ-CAN 安全路径，缺少 gate 或上下文时默认拒绝。
        """

        self.workdir = workdir
        if self.workdir[-1] != '/':
            self.workdir += '/'

        # library-agnostic agent object
        self.local_agent = local_agent
        if local_agent is None:
            logger.warn("No local agent provided. Using dummy agent.")
            self.local_agent = DummyAgent()
        
        # Check if local_agent is a child of LocalAgent:
        if not isinstance(self.local_agent, LocalAgent):
            raise Exception("Please provide a valid LocalAgent instance or a child of it.")

        self._bind_local_agent_runtime_hooks()
        self.task_finished_token = self.local_agent.task_finished_token
        self.execution_gate = execution_gate
        self.strict_execution_gate = strict_execution_gate
        self._sync_local_agent_execution_capability_mode()
        self.pq_signature_scheme = None
        self.pq_public_key = None
        self.pq_secret_key = None
        self.provider_id = saga.config.PROVIDER_CONFIG.get("endpoint", "")

        self.aid = material.get("aid")
        self.device = material.get("device")
        self.IP = material.get("IP")
        self.port = material.get("port")
        self.active = material.get("active", True)

        # TLS signing keys for the Agent:
        self.sk_a = sc.bytesToPrivateEd25519Key(
            base64.b64decode(material.get("secret_signing_key"))
        )

        # Load the agent's certificates
        self.cert = sc.bytesToX509Certificate(
            base64.b64decode(material.get("agent_cert"))
        )

        self.pk_a = self.cert.public_key()

        # Save the key and certificate:
        sc.save_ed25519_keys(self.workdir+"agent", self.sk_a, self.pk_a)
        sc.save_x509_certificate(self.workdir+"agent", self.cert)

        # Agent Access Control Key Pair:
        self.pac = sc.bytesToPublicX25519Key(
            base64.b64decode(material.get("pac"))
        )
        self.sac = sc.bytesToPrivateX25519Key(
            base64.b64decode(material.get("sac"))
        )
        

        # One-Time Keys:
        self.sotks = [sc.bytesToPrivateX25519Key(
            base64.b64decode(sotk)
        ) for sotk in material.get("sotks")]
        self.otks = [sc.bytesToPublicX25519Key(
            base64.b64decode(otk)
        ) for otk in material.get("otks")]

        # Join the One-time keys:
        self.otks_lock = threading.Lock()
        self.otks_dict = {}
        for i in range(len(self.otks)):
            self.otks_dict[self.otks[i].public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )] = self.sotks[i] 

        # Agent Contact Policy Rulebook:
        self.contact_rulebook = material.get("contact_rulebook", [])
        if not check_rulebook(self.contact_rulebook):
            logger.error("Contact rulebook is not valid. Exiting...")
            raise Exception("Contact rulebook is not valid. Exiting...")

        # Init token storing dicts:
        self.active_tokens = {} # Active tokens that were given to initiating agents from the agent.
        self.active_tokens_lock = threading.Lock()
        self.aid_to_token = {} # dict that maps the aid of a receiving agent to the token that was given from them.
        self.received_tokens = {} # Tokens that were received from the receiving agents.
        self.received_tokens_lock = threading.Lock()

        # Previously contacted agents:
        self.previously_contacted_agents = {}

        # Provider Identity
        # Setup the SAGA CA:
        self.CA = get_SAGA_CA()
        # Download provider certificate
        provider_cert = self.get_provider_cert()
        # Verify the provider certificate:
        self.CA.verify(provider_cert) # if the verification fails an exception will be raised.
        self.PK_Prov = provider_cert.public_key()

        # Get the stamp issued by the provider (allegedly):
        agent_sig_bytes = material.get("agent_sig")
        self.stamp = material.get("stamp")
        self.card = {
            "aid": self.aid,
            "device": self.device,
            "IP": self.IP,
            "port": self.port,
            "agent_cert": base64.b64decode(material.get("agent_cert")),
            "pac":  base64.b64decode(material.get("pac")),
            "agent_sig": base64.b64decode(agent_sig_bytes),
        }
        # Verify the stamp:
        try:
            self.PK_Prov.verify(
                base64.b64decode(self.stamp),
                str(self.card).encode("utf-8")
            )
        except:
            logger.error("ERROR: PROVIDER STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
            raise Exception("ERROR: PROVIDER STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
        
        # Serialize the card:
        self.card['agent_cert'] = base64.b64encode(
            self.card['agent_cert']
        ).decode("utf-8")
        self.card['pac'] = base64.b64encode(
            self.card['pac']
        ).decode("utf-8")
        self.card['agent_sig'] = base64.b64encode(
            self.card['agent_sig']
        ).decode("utf-8")

        self.crt_u = sc.bytesToX509Certificate(
            base64.b64decode(material.get("crt_u"))
        )
        # Verify usr certificate:
        self.CA.verify(self.crt_u)

        self.monitor = Monitor()
        self.llm_monitor = Monitor(time.time)

    def _bind_local_agent_runtime_hooks(self) -> None:
        """Install optional runtime callbacks into the local agent wrapper."""
        if hasattr(self.local_agent, "set_delegation_handler"):
            self.local_agent.set_delegation_handler(self._delegate_to_agent)

    def _sync_local_agent_execution_capability_mode(self) -> None:
        """把外层 strict runtime-auth 模式同步给本地 capability facade。"""
        _sync_execution_capability_mode(self)


    @staticmethod
    def _local_agent_memory_step_count(agent_instance: object | None) -> int:
        """Return the current memory step count for a local agent instance."""
        if agent_instance is None:
            return 0

        memory = getattr(agent_instance, "memory", None)
        steps = getattr(memory, "steps", None)
        if steps is None:
            return 0
        try:
            return len(steps)
        except TypeError:
            return 0

    def _record_local_run_diagnostic(
        self,
        *,
        peer_aid: str | None,
        conversation_side: str,
        turn_index: int,
        query: str,
        response: object,
        llm_elapsed_seconds: float | None,
        agent_instance: object | None,
        step_start_index: int,
        run_status: str = "completed",
        error: str | None = None,
    ) -> None:
        """Persist one structured local runtime diagnostic record."""
        record = build_local_run_diagnostic_record(
            agent_aid=self.aid,
            peer_aid=peer_aid,
            conversation_side=conversation_side,
            turn_index=turn_index,
            query=query,
            response=response,
            llm_elapsed_seconds=llm_elapsed_seconds,
            agent_instance=agent_instance,
            step_start_index=step_start_index,
        )
        record["run_status"] = run_status
        if error is not None:
            record["error"] = error
        append_local_run_diagnostic_record(getattr(self, "workdir", None), record)
        logger.log(
            "DIAG",
            json.dumps(
                {
                    "run_status": run_status,
                    "side": conversation_side,
                    "turn": turn_index,
                    "peer_aid": peer_aid,
                    "tool_call_count": record["tool_call_count"],
                    "tool_call_names": record["tool_call_names"],
                    "error_step_count": record["error_step_count"],
                    "response_is_task_finished": record["response_is_task_finished"],
                    "error": error,
                },
                sort_keys=True,
            ),
        )

    def _llm_elapsed_seconds(self, run_id: str) -> float | None:
        """Return elapsed LLM timing data when the configured monitor exposes it."""
        if not hasattr(self.llm_monitor, "elapsed"):
            return None
        if hasattr(self.llm_monitor, "has_run") and not self.llm_monitor.has_run(run_id):
            return None
        return self.llm_monitor.elapsed(run_id)

    def _run_local_agent_with_diagnostics(
        self,
        *,
        query: str,
        initiating_agent: bool,
        agent_instance: object | None,
        peer_aid: str | None,
        conversation_side: str,
        turn_index: int,
        run_id: str,
        local_agent_kwargs: dict | None = None,
    ):
        """Run the local agent and persist start/completion/failure diagnostics."""
        local_agent_kwargs = local_agent_kwargs or {}
        step_start_index = self._local_agent_memory_step_count(agent_instance)
        self._record_local_run_diagnostic(
            peer_aid=peer_aid,
            conversation_side=conversation_side,
            turn_index=turn_index,
            query=query,
            response="",
            llm_elapsed_seconds=None,
            agent_instance=agent_instance,
            step_start_index=step_start_index,
            run_status="started",
        )
        self.llm_monitor.start(run_id)
        try:
            next_agent_instance, response = self.local_agent.run(
                query,
                initiating_agent=initiating_agent,
                agent_instance=agent_instance,
                **local_agent_kwargs,
            )
            response = self._normalize_local_agent_response(response)
        except Exception as exc:
            self.llm_monitor.stop(run_id)
            error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            self._record_local_run_diagnostic(
                peer_aid=peer_aid,
                conversation_side=conversation_side,
                turn_index=turn_index,
                query=query,
                response="",
                llm_elapsed_seconds=self._llm_elapsed_seconds(run_id),
                agent_instance=agent_instance,
                step_start_index=step_start_index,
                run_status="failed",
                error=error,
            )
            raise
        self.llm_monitor.stop(run_id)
        self._record_local_run_diagnostic(
            peer_aid=peer_aid,
            conversation_side=conversation_side,
            turn_index=turn_index,
            query=query,
            response=response,
            llm_elapsed_seconds=self._llm_elapsed_seconds(run_id),
            agent_instance=next_agent_instance,
            step_start_index=step_start_index,
            run_status="completed",
        )
        return next_agent_instance, response

    def _normalize_local_agent_response(self, response) -> str:
        """Normalize local-agent output into transport-safe text.

        模型可能返回 dict/list 等结构化 final_answer；签名信封和 socket 传输统一使用字符串。
        """
        if isinstance(response, str):
            return response
        if isinstance(response, bytes):
            return response.decode("utf-8", errors="replace")
        return json.dumps(serialize(response), sort_keys=True, ensure_ascii=True)

    def _delegate_to_agent(self, target_aid: str, message: str, **kwargs) -> None:
        """Delegate a task to another SAGA agent through the outer runtime."""
        self.connect(target_aid, message)

    def _consume_local_otk(self, otk_bytes: bytes):
        """原子消费本地一次性私钥，防止并发握手重复使用同一个 OTK。"""
        with self.otks_lock:
            sotk = self.otks_dict.get(otk_bytes)
            if sotk is None:
                return None
            del self.otks_dict[otk_bytes]
            return sotk

    def get_provider_cert(self) -> Certificate:
        """
        This is a 'smarter' way to get the provider's certificate. This function uses the requests library
        to get the certificate of the server.
        
        Returns:
            cert (Certificate): The provider's certificate as a cryptography.x509.Certificate object.
        """
        provider_url = saga.config.PROVIDER_CONFIG['endpoint']
        response = requests.get(provider_url+"/certificate", verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        ))
        cert_bytes = base64.b64decode(response.json().get('certificate'))
        cert = sc.bytesToX509Certificate(cert_bytes)
        
        return cert

    def lookup(self, t_aid: str) -> dict:
        """
        Compatibility shim for a provider endpoint that is not implemented.
        Use access() for the active protocol flow.
        """
        raise NotImplementedError(
            "Provider /lookup is not implemented in this codebase. Use access() instead."
        )
        
    def access(self, t_aid):
        """向 provider 请求目标 agent 的访问材料并解析扩展 JSON 响应。"""
        response = requests.post(f"{saga.config.PROVIDER_CONFIG['endpoint']}/access", json={'i_aid':self.aid, 't_aid': t_aid}, verify=saga.config.CA_CERT_PATH, cert=(
            self.workdir+"agent.crt", self.workdir+"agent.key"
        )) 
        if response.status_code == 200:
            data = response.json()
            # Convert extended-json dict to python dict:
            data = bson.json_util.loads(json.dumps(data))
            return data
        elif response.status_code == 403:
            logger.log("ACCESS", f"Access denied to {t_aid}.")
            print(response.json())
            return None

    def generate_token(self, recipient_pac, sdhk) -> bytes:
        """
        Encode a token based on the shared diffie-hellman key.
        The token contains the following information:
        - Nonce: A random nonce for the token.
        - Issue Timestamp: The timestamp when the token was issued.
        - Expiration Timestamp: The timestamp when the token expires (1 hour from issue).
        - Communication Quota: The maximum number of communications allowed with this token.
        - Recipient PAC: The public access control key of the recipient agent.

        Args:
            recipient_pac: The public access control key of the recipient agent.
            sdhk: The shared Diffie-Hellman key used to encrypt the token.

        """
        # Generate a random nonce
        # TODO: Allow control of nonce length at some point
        nonce = os.urandom(NONCE_SIZE_BYTES)

        # Issue and expiration timestamps
        # TODO: Make sure we use UTC throughout the entire implementation
        issue_timestamp = datetime.now(tz=timezone.utc)
        # TODO: Allow control over the expiration-time over user's config
        expiration_timestamp = issue_timestamp + timedelta(hours=1)

        # Communication quota
        communication_quota = saga.config.Q_MAX  # Example quota

        # Token dictionary
        token_dict = {
            "nonce": nonce,
            "issue_timestamp": issue_timestamp,
            "expiration_timestamp": expiration_timestamp,
            "communication_quota": communication_quota,
            "recipient_pac": recipient_pac
        }

        # Encrypt the token using the shared DH key (SDHK)
        encrypted_token = sc.encrypt_token(token_dict, sdhk)
        
        return encrypted_token

    def token_is_valid(self, token: str, recipient_pac) -> bool:
        """
        Checks if a token that was presented by an initiating agent is valid.
        - If it was not generated by self, it is invalid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.

        Args:
            token (str): The token to check.
            recipient_pac: The public access control key of the recipient agent.
        """
        with self.active_tokens_lock:
            if token not in self.active_tokens.keys():
                logger.error("Token provided by initiating not found in given tokens.")
                return False
            # Check if the token is still valid:
            token_dict = self.active_tokens[token]
            return self._active_token_is_valid_unlocked(token_dict, recipient_pac)

    def _parse_token_expiration(self, expiration_date: object) -> datetime:
        """解析 token 过期时间，并把 naive timestamp 视为 UTC。"""
        if isinstance(expiration_date, datetime):
            expiration_timestamp = expiration_date
        elif isinstance(expiration_date, str):
            expiration_timestamp = datetime.fromisoformat(expiration_date)
        else:
            raise ValueError("token expiration timestamp is missing or invalid")
        if expiration_timestamp.tzinfo is None:
            expiration_timestamp = expiration_timestamp.replace(tzinfo=timezone.utc)
        return expiration_timestamp

    def _active_token_is_valid_unlocked(self, token_dict: dict, recipient_pac) -> bool:
        """在持有 active token 锁时检查 token 是否仍可被发起方消费。"""
        try:
            expiration_timestamp = self._parse_token_expiration(
                token_dict.get("expiration_timestamp")
            )
        except ValueError:
            logger.error("Token expiration timestamp is invalid.")
            return False
        if datetime.now(tz=timezone.utc) > expiration_timestamp:
            logger.error("Token expired.")
            return False

        remaining_quota = int(token_dict.get("communication_quota", 0) or 0)
        if remaining_quota <= 0:
            logger.error("Token's max quota has been exceeded.")
            return False

        token_recipient_pac = token_dict.get("recipient_pac")
        try:
            recipient_pac_to_bytes = base64.b64encode(
                recipient_pac.public_bytes(
                    encoding=sc.serialization.Encoding.Raw,
                    format=sc.serialization.PublicFormat.Raw
                )
            ).decode('utf-8')
        except AttributeError:
            logger.error("Recipient PAC cannot be serialized for token validation.")
            return False

        if token_recipient_pac != recipient_pac_to_bytes:
            logger.error("Token's recipient PAC does not match the one that the token was originally issued to.")
            return False

        return True

    def _decrement_token_quota_unlocked(self, token_dict: dict) -> None:
        """在调用方持锁时原子扣减 token quota，避免并发重复消费。"""
        remaining_quota = int(token_dict.get("communication_quota", 0) or 0)
        token_dict["communication_quota"] = max(0, remaining_quota - 1)
        logger.log('ACCESS', f'Remaining token quota: {token_dict["communication_quota"]}')

    def _consume_active_token(self, token: str | None, recipient_pac) -> dict | None:
        """锁内完成 active token 校验和 quota 扣减，成功时返回消费前快照。"""
        with self.active_tokens_lock:
            if token not in self.active_tokens.keys():
                logger.error("Token provided by initiating not found in given tokens.")
                return None
            token_dict = self.active_tokens[token]
            # 兼容直接单元测试中的实例级 monkeypatch；正常运行走锁内 helper。
            token_validator = self.__dict__.get("token_is_valid")
            if token_validator is not None:
                valid = bool(token_validator(token, recipient_pac))
            else:
                valid = self._active_token_is_valid_unlocked(token_dict, recipient_pac)
            if not valid:
                return None
            token_snapshot = dict(token_dict)
            self._decrement_token_quota_unlocked(token_dict)
            return token_snapshot

    def _received_token_is_valid_unlocked(self, token_dict: dict) -> bool:
        """
        Validates a received token while the caller manages locking.
        """
        try:
            expiration_timestamp = self._parse_token_expiration(
                token_dict.get("expiration_timestamp")
            )
        except ValueError:
            logger.log("ACCESS", "Token expiration timestamp is invalid.")
            return False
        if datetime.now(tz=timezone.utc) > expiration_timestamp:
            logger.log("ACCESS", "Token expired.")
            return False

        remaining_quota = int(token_dict.get("communication_quota", 0) or 0)
        if remaining_quota <= 0:
            logger.log("ACCESS", "Token's max quota has been exceeded.")
            return False

        return True

    def _consume_received_token(self, token: str) -> dict | None:
        """锁内完成 received token 校验和 quota 扣减，成功时返回消费前快照。"""
        with self.received_tokens_lock:
            if token not in self.received_tokens.keys():
                logger.log("ACCESS", "Token provided by receiving agent not found in given tokens.")
                return None
            token_dict = self.received_tokens[token]
            # 兼容直接单元测试中的实例级 monkeypatch；正常运行走锁内 helper。
            token_validator = self.__dict__.get("received_token_is_valid")
            if token_validator is not None:
                valid = bool(token_validator(token))
            else:
                valid = self._received_token_is_valid_unlocked(token_dict)
            if not valid:
                return None
            token_snapshot = dict(token_dict)
            self._decrement_token_quota_unlocked(token_dict)
            return token_snapshot

    def _active_token_snapshot(self, token: str) -> dict | None:
        """读取 active token 快照；token 已被并发失效时返回 ``None``。"""
        with self.active_tokens_lock:
            token_dict = self.active_tokens.get(token)
            if token_dict is None:
                return None
            return dict(token_dict)

    def _invalidate_active_token(self, token: str) -> None:
        """幂等失效 active token，避免并发删除触发 KeyError。"""
        with self.active_tokens_lock:
            self.active_tokens.pop(token, None)

    def _invalidate_received_token(self, token: str, r_aid: str) -> None:
        """幂等失效 received token 和对应 AID 映射。"""
        with self.received_tokens_lock:
            self.received_tokens.pop(token, None)
            if self.aid_to_token.get(r_aid) == token:
                self.aid_to_token.pop(r_aid, None)

    def received_token_is_valid(self, token: str) -> bool:
        """
        Makes sure that the token that was received from the receiving agent is valid.
        - If it is expired, it is invalid.
        - If the communication quota is reached, it is invalid.

        Args:
            token (str): The token to check.
        """
        with self.received_tokens_lock:
            if token not in self.received_tokens.keys():
                logger.log("ACCESS", "Token provided by receiving agent not found in given tokens.")
                return False
            
            token_dict = self.received_tokens[token]
            return self._received_token_is_valid_unlocked(token_dict)

    def store_received_token(self, r_aid, token_str, token_dict):
        """
        Stores the token that was received from the receiving agent.

        Args:
            r_aid: The AID of the receiving agent.
            token_str: The string representation of the token.
            token_dict: The dictionary representation of the token.
        """
        with self.received_tokens_lock:
            self.received_tokens[token_str] = token_dict
            self.aid_to_token[r_aid] = token_str

    def retrieve_valid_token(self, r_aid):
        """
        Retrieves a valid token for the receiving agent.
        This function checks if the token is valid and if it is, returns it.
        If the token is not valid, it removes it from the received tokens and the aid_to_token dict.
        """
        with self.received_tokens_lock:
            token = self.aid_to_token.get(r_aid, None)
            if token is None:
                return None

            token_dict = self.received_tokens.get(token)
            if token_dict is None:
                del self.aid_to_token[r_aid]
                return None

            if not self._received_token_is_valid_unlocked(token_dict):
                del self.received_tokens[token]
                del self.aid_to_token[r_aid]
                return None

            return token

    def _authorize_execution_request(
        self,
        *,
        sender_aid: str | None,
        token: str,
        message_dict: dict,
    ) -> bool:
        """Authorize a received request before it enters the local execution path."""
        return self._evaluate_execution_request(
            sender_aid=sender_aid,
            token=token,
            message_dict=message_dict,
        ).allowed

    def _evaluate_execution_request(
        self,
        *,
        sender_aid: str | None,
        token: str,
        message_dict: dict,
        consume: bool = False,
        protocol_allow: bool | None = None,
    ) -> ExecutionGateDecision:
        """Evaluate or consume a received request and keep a stable audit reason."""
        execution_gate = getattr(self, "execution_gate", None)
        if execution_gate is None:
            if getattr(self, "strict_execution_gate", False):
                return ExecutionGateDecision(
                    False,
                    "missing_execution_gate",
                    protocol_allow=protocol_allow,
                )
            return ExecutionGateDecision(
                True,
                "no_execution_gate",
                protocol_allow=protocol_allow,
                internal_policy_accept=True,
            )

        request = self._build_execution_gate_request(
            sender_aid=sender_aid,
            token=token,
            message_dict=message_dict,
        )
        if consume and hasattr(execution_gate, "consume_request"):
            return self._attach_protocol_allow(
                execution_gate.consume_request(request),
                protocol_allow=protocol_allow,
            )
        if hasattr(execution_gate, "evaluate_request"):
            return self._attach_protocol_allow(
                execution_gate.evaluate_request(request),
                protocol_allow=protocol_allow,
            )
        if execution_gate.authorize(request):
            return ExecutionGateDecision(
                True,
                "authorized_by_legacy_gate",
                protocol_allow=protocol_allow,
                execution_scope_allowed=True,
                internal_policy_accept=True,
            )
        return ExecutionGateDecision(
            False,
            "rejected_by_legacy_gate",
            protocol_allow=protocol_allow,
        )

    def _attach_protocol_allow(
        self,
        decision: ExecutionGateDecision,
        *,
        protocol_allow: bool | None,
    ) -> ExecutionGateDecision:
        """把协议层 token 结果合入 gate decision，兼容旧测试 gate 返回对象。"""
        if hasattr(decision, "with_formula_values"):
            return decision.with_formula_values(protocol_allow=protocol_allow)
        return ExecutionGateDecision(
            bool(getattr(decision, "allowed")),
            str(getattr(decision, "reason", "legacy_gate_decision")),
            protocol_allow=protocol_allow,
        )

    def _build_local_execution_context(
        self,
        *,
        sender_aid: str | None,
        token: str,
        message_dict: dict,
        decision: ExecutionGateDecision | None = None,
    ) -> LocalExecutionContext | None:
        """Build a local execution context for downstream tool/memory gating."""
        execution_gate = getattr(self, "execution_gate", None)
        if execution_gate is None or not hasattr(execution_gate, "build_local_execution_context"):
            return None

        request = self._build_execution_gate_request(
            sender_aid=sender_aid,
            token=token,
            message_dict=message_dict,
        )
        if decision is not None and hasattr(execution_gate, "build_local_execution_context_from_decision"):
            return execution_gate.build_local_execution_context_from_decision(
                request,
                decision,
            )
        return execution_gate.build_local_execution_context(request)

    def _build_execution_gate_request(
        self,
        *,
        sender_aid: str | None,
        token: str,
        message_dict: dict,
    ) -> ExecutionGateRequest:
        """构造执行层 gate 使用的规范请求对象。"""
        return ExecutionGateRequest(
            sender_aid=sender_aid,
            receiver_aid=self.aid,
            token=token,
            message=str(message_dict.get("msg", self.task_finished_token)),
            action_scope=str(message_dict.get("action_scope", "llm_prompt")),
            request_envelope=message_dict.get("request_envelope"),
            pq_signature=message_dict.get("pq_signature"),
        )

    def _evaluate_prompt_surface_request(
        self,
        execution_context: LocalExecutionContext | None,
        base_decision: ExecutionGateDecision | None = None,
    ) -> ExecutionGateDecision:
        """在进入 local_agent.run() 前检查 prompt surface 是否被签名授权。"""
        protocol_allow = base_decision.protocol_allow if base_decision is not None else None
        request_envelope_valid = (
            base_decision.request_envelope_valid if base_decision is not None else False
        )
        pq_signature_valid = (
            base_decision.pq_signature_valid if base_decision is not None else False
        )
        can_accept = base_decision.can_accept if base_decision is not None else False
        if execution_context is None:
            if getattr(self, "strict_execution_gate", False):
                return ExecutionGateDecision(
                    False,
                    "missing_local_execution_context",
                    protocol_allow=protocol_allow,
                    request_envelope_valid=request_envelope_valid,
                    pq_signature_valid=pq_signature_valid,
                    can_accept=can_accept,
                    execution_scope_allowed=False,
                    internal_policy_accept=False,
                )
            return ExecutionGateDecision(
                True,
                "legacy_prompt_without_execution_context",
                protocol_allow=protocol_allow,
                request_envelope_valid=request_envelope_valid,
                pq_signature_valid=pq_signature_valid,
                can_accept=can_accept,
                execution_scope_allowed=True,
                internal_policy_accept=True,
            )
        if execution_context.authorize_action("llm_prompt"):
            return ExecutionGateDecision(
                True,
                "prompt_scope_authorized",
                protocol_allow=protocol_allow,
                request_envelope_valid=request_envelope_valid,
                pq_signature_valid=pq_signature_valid,
                can_accept=can_accept,
                execution_scope_allowed=True,
                internal_policy_accept=True,
                request_envelope=execution_context.request_envelope,
                pq_signature=execution_context.pq_signature,
            )
        return ExecutionGateDecision(
            False,
            "prompt_scope_not_authorized",
            protocol_allow=protocol_allow,
            request_envelope_valid=request_envelope_valid,
            pq_signature_valid=pq_signature_valid,
            can_accept=can_accept,
            execution_scope_allowed=False,
            internal_policy_accept=False,
            request_envelope=execution_context.request_envelope,
            pq_signature=execution_context.pq_signature,
        )

    def _local_agent_supports_execution_context(self) -> bool:
        """检查本地 agent 是否声明会用 execution_context 保护受限资源。"""
        support_checker = getattr(
            getattr(self, "local_agent", None),
            "supports_execution_context",
            None,
        )
        if not callable(support_checker):
            return False
        try:
            return bool(support_checker())
        except Exception:
            return False

    def _evaluate_local_agent_context_support(
        self,
        base_decision: ExecutionGateDecision,
    ) -> ExecutionGateDecision:
        """严格模式下要求本地 agent 显式支持 execution_context，否则拒绝执行。"""
        if not getattr(self, "strict_execution_gate", False):
            return base_decision
        if self._local_agent_supports_execution_context():
            return base_decision
        return replace(
            base_decision,
            allowed=False,
            reason="local_agent_execution_context_unsupported",
            internal_policy_accept=False,
        )

    def _record_execution_gate_rejection(
        self,
        *,
        request: ExecutionGateRequest,
        decision: ExecutionGateDecision,
        log_message: str,
    ) -> None:
        """记录执行层 gate 拒绝审计，并保留稳定本地 reason。"""
        audit_record = build_execution_gate_audit_record(request, decision)
        logger.log("AUDIT", json.dumps(audit_record, sort_keys=True))
        append_execution_gate_audit_record(getattr(self, "workdir", None), audit_record)
        logger.error(f"{log_message} Reason: {decision.reason}. Ending conversation...")

    def _build_conversation_payload(
        self,
        *,
        receiver_aid: str | None,
        token: str,
        message: str,
        action_scope: str,
        turn_index: int,
        token_dict: dict | None,
        authorized_scopes: list[str] | tuple[str, ...] | None = None,
        parent_envelope: RequestEnvelope | None = None,
        parent_envelope_digest: str = "",
        parent_authorized_scopes: list[str] | tuple[str, ...] | None = None,
        delegation_depth: int = 0,
    ) -> dict:
        """Build a transport payload and attach a signed request envelope when configured.

        入口动作、额外授权 scope 和可选父 capability 一起进入签名信封。
        """
        payload = {
            "msg": message,
            "token": token,
            "action_scope": action_scope,
        }

        signature_scheme = getattr(self, "pq_signature_scheme", None)
        secret_key = getattr(self, "pq_secret_key", None)
        if receiver_aid is None or signature_scheme is None or secret_key is None:
            return payload

        # 签名覆盖规范化信封摘要，消息和 token 只以哈希形式进入信封。
        now = datetime.now(tz=timezone.utc)
        issued_at = now
        expires_at = now + timedelta(hours=1)
        if token_dict is not None:
            issued_at = token_dict.get("issue_timestamp", issued_at)
            expires_at = token_dict.get("expiration_timestamp", expires_at)

        envelope = build_request_envelope(
            sender_aid=self.aid,
            receiver_aid=receiver_aid,
            token=token,
            session_id=f"session-{hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]}",
            turn_id=f"turn-{turn_index}",
            issued_at=issued_at,
            expires_at=expires_at,
            action_scope=action_scope,
            authorized_scopes=authorized_scopes,
            message=message,
            provider_id=getattr(self, "provider_id", ""),
            timestamp=now,
            parent_envelope=parent_envelope,
            parent_envelope_digest=parent_envelope_digest,
            parent_authorized_scopes=parent_authorized_scopes,
            delegation_depth=delegation_depth,
        )
        signature = signature_scheme.sign(secret_key, envelope.digest())
        payload["request_envelope"] = envelope.canonical_json()
        payload["pq_signature"] = base64.b64encode(signature).decode("utf-8")
        return payload

    def _conversation_authorized_scopes(
        self,
        action_scope: str,
        requested_scopes: list[str] | tuple[str, ...] | None = None,
    ) -> tuple[str, ...]:
        """Return policy-compiled signed scopes for a conversation turn.

        requested scopes 只作为 proposal；最终签名 scopes 来自本地 policy 交集。
        """
        decision = self._conversation_policy_decision(
            action_scope,
            requested_scopes=requested_scopes,
        )
        if decision.reason == "policy_reject":
            raise ExecutionAuthorizationError("policy_reject", action_scope)
        return decision.allowed_scopes

    def _conversation_policy_decision(
        self,
        action_scope: str,
        requested_scopes: list[str] | tuple[str, ...] | None = None,
    ) -> PolicyDecision:
        """编译会话 intent 并返回带稳定 reason 的本地 policy 裁定。"""
        # 本地 CodeAgent 初始化和每轮响应处理会读写 memory，签名 scope 必须显式覆盖这些运行时动作。
        runtime_required_scopes = {"memory_read", "memory_write"}
        policy_scopes = set(runtime_required_scopes)
        local_agent = getattr(self, "local_agent", None)
        for tool_obj in getattr(local_agent, "tool_collections", ()) or ():
            tool_name = getattr(tool_obj, "name", None)
            if tool_name:
                policy_scopes.add(f"tool_call:{tool_name}")
        policy_scopes.add("llm_prompt")

        requested_scope_set = set(requested_scopes or ()) | runtime_required_scopes
        # 非 prompt 入口不默认携带 ``llm_prompt``，否则工具入口可被误解释为 prompt 授权。
        default_scope_pool = policy_scopes - {action_scope}
        if action_scope != "llm_prompt":
            default_scope_pool.discard("llm_prompt")
        default_requested_scopes = tuple(sorted(default_scope_pool))
        intent = AgentIntent(
            action_scope=action_scope,
            requested_scopes=tuple(sorted(requested_scope_set))
            if requested_scopes is not None
            else default_requested_scopes,
        )
        return IntentCompiler(policy_scopes).compile(intent)

    def send(self, conn, payload: dict):
        """
        Sends a JSON payload over the given connection.

        Args:
            conn: The connection to send the data over.
            payload (dict): The JSON payload to send. It should be a dictionary.
        """
        data = json.dumps(payload).encode('utf-8')
        conn.sendall(len(data).to_bytes(4, 'big') + data)

    def recv(self, conn) -> dict:
        """
        Receives a JSON payload from the given connection.

        Args:
            conn: The connection to receive the data from.
        
        Returns:
            response (dict): The JSON payload received from the connection.
            If the reception fails, it returns None.
        """
        try:
            length_bytes = conn.recv(4)
            length = int.from_bytes(length_bytes, 'big')

            buffer = b''
            while len(buffer) < length:
                buffer += conn.recv(length - len(buffer))

            response = json.loads(buffer.decode('utf-8'))
            return response
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None

    def initiate_conversation(self, conn, token: str, r_aid: str, init_msg: str) -> bool:
        """
        This function initiates a conversation with the receiving agent.
        It sends the initial message to the receiving agent and waits for a response.
        Returns true if the conversation ended from the initiating side.

        Args:
            conn: The connection to the receiving agent.
            token (str): The token that was received from the receiving agent.
            r_aid (str): The AID of the receiving agent.
            init_msg (str): The initial message to send to the receiving agent.
        """
        agent_instance = None

        text = init_msg
        i = 0
        while True:
            # Check if the received token that you are using is valid:
            token_dict = self._consume_received_token(token)
            if token_dict is None:
                logger.error("Token is invalid. Ending conversation...")
                self.monitor.stop("agent:communication_conv_init")
                return True

            msg = self._build_conversation_payload(
                receiver_aid=r_aid,
                token=token,
                message=text,
                action_scope="llm_prompt",
                turn_index=i,
                token_dict=token_dict,
                authorized_scopes=self._conversation_authorized_scopes("llm_prompt"),
            )

            # Send message:
            self.monitor.stop("agent:communication_conv_init")
            self.send(conn, msg)
            self.monitor.start("agent:communication_conv_init")
            logger.log("AGENT", f"Sent: \'{msg['msg']}\'")

            if msg['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                # Invalidate the token:
                self._invalidate_received_token(token, r_aid)
                logger.log("ACCESS", "Token invalidated from the initiating side.")
                self.monitor.stop("agent:communication_conv_init")
                return True
            # Receive response:
            self.monitor.stop("agent:communication_conv_init")
            response = self.recv(conn)
            self.monitor.start("agent:communication_conv_init")
            if not response:
                logger.warn("Failed to parse incoming socket message; connection may have closed abruptly during reception.")
                self.monitor.stop("agent:communication_conv_init")
                return False

            response_decision = self._evaluate_execution_request(
                sender_aid=r_aid,
                token=token,
                message_dict=response,
                consume=True,
                protocol_allow=True,
            )
            if not response_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=r_aid,
                    token=token,
                    message_dict=response,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=response_decision,
                    log_message="Execution gate rejected inbound response.",
                )
                self.monitor.stop("agent:communication_conv_init")
                return False

            response_execution_context = self._build_local_execution_context(
                sender_aid=r_aid,
                token=token,
                message_dict=response,
                decision=response_decision,
            )
            response_prompt_decision = self._evaluate_prompt_surface_request(
                response_execution_context,
                base_decision=response_decision,
            )
            if not response_prompt_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=r_aid,
                    token=token,
                    message_dict=response,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=response_prompt_decision,
                    log_message="Execution gate rejected inbound response prompt surface.",
                )
                self.monitor.stop("agent:communication_conv_init")
                return False

            response_local_agent_decision = self._evaluate_local_agent_context_support(
                response_prompt_decision
            )
            if not response_local_agent_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=r_aid,
                    token=token,
                    message_dict=response,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=response_local_agent_decision,
                    log_message="Execution gate rejected inbound response local agent.",
                )
                self.monitor.stop("agent:communication_conv_init")
                return False

            # Process response:
            received_message = str(response.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")
            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                # Invalidate the token:
                self._invalidate_received_token(token, r_aid)
                logger.log("ACCESS", "Token invalidated from the receiving side.")
                self.monitor.stop("agent:communication_conv_init")
                return False
            
            # Process message:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                self.monitor.stop("agent:communication_conv_init")
                return True
            self.monitor.stop("agent:communication_conv_init")
            try:
                agent_instance, text = self._run_local_agent_with_diagnostics(
                    query=received_message,
                    initiating_agent=True,
                    agent_instance=agent_instance,
                    peer_aid=r_aid,
                    conversation_side="initiating",
                    turn_index=i,
                    run_id="agent:llm_backend_init",
                    local_agent_kwargs={"execution_context": response_execution_context},
                )
            except Exception as exc:
                logger.error(f"Local agent run failed on initiating side: {exc}")
                self.monitor.start("agent:communication_conv_init")
                self.monitor.stop("agent:communication_conv_init")
                return False
            self.monitor.start("agent:communication_conv_init")
            i += 1 # increment queries counter

    def receive_conversation(
        self,
        conn,
        token: str,
        recipient_pac,
        sender_aid: str | None = None,
    ) -> bool:
        """
        This function receives a conversation from the initiating agent.
        It waits for a message from the initiating agent and processes it.
        Returns true if the conversation ended from the receiving side.

        Args:
            conn: The connection to the initiating agent.
            token: The token that was received from the initiating agent.
            recipient_pac: The public access control key of the recipient agent.
        """
        agent_instance = None
        i = 0
        while True: 
            
            # Receive message from the initiating side:
            self.monitor.stop("agent:communication_conv_recv")
            message_dict = self.recv(conn)
            self.monitor.start("agent:communication_conv_recv")
            if not message_dict:
                logger.warn("Failed to parse incoming socket message; connection may have closed abruptly during reception.")
                self.monitor.stop("agent:communication_conv_recv")
                return False
            

            # Extract token from the message:
            token = message_dict.get("token", None)
            
            # Check if the token of the message is valid
            token_dict = self._consume_active_token(token, recipient_pac)
            if token_dict is None:
                logger.error("Token is invalid. Ending conversation...")
                self.monitor.stop("agent:communication_conv_recv")
                return True
            
            # Process message:
            received_message = str(message_dict.get("msg", self.local_agent.task_finished_token))
            logger.log("AGENT", f"Received: \'{received_message}\'")

            if received_message == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from initiating side.")
                # Invalidate the token:
                self._invalidate_active_token(token)
                logger.log("ACCESS", "Token invalidated from the initiating side.")
                self.monitor.stop("agent:communication_conv_recv")
                return False

            # Check if too many queries have been sent to your llm resources:
            if i > MAX_QUERIES:
                logger.warn("Maximum allowed number of queries in the conversation is reached. Ending conversation...")
                self.monitor.stop("agent:communication_conv_recv")
                return True

            execution_decision = self._evaluate_execution_request(
                sender_aid=sender_aid,
                token=token,
                message_dict=message_dict,
                consume=True,
                protocol_allow=True,
            )
            if not execution_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=sender_aid,
                    token=token,
                    message_dict=message_dict,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=execution_decision,
                    log_message="Execution gate rejected incoming request.",
                )
                self.monitor.stop("agent:communication_conv_recv")
                return True

            execution_context = self._build_local_execution_context(
                sender_aid=sender_aid,
                token=token,
                message_dict=message_dict,
                decision=execution_decision,
            )
            prompt_decision = self._evaluate_prompt_surface_request(
                execution_context,
                base_decision=execution_decision,
            )
            if not prompt_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=sender_aid,
                    token=token,
                    message_dict=message_dict,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=prompt_decision,
                    log_message="Execution gate rejected prompt surface request.",
                )
                self.monitor.stop("agent:communication_conv_recv")
                return True

            local_agent_decision = self._evaluate_local_agent_context_support(prompt_decision)
            if not local_agent_decision.allowed:
                request = self._build_execution_gate_request(
                    sender_aid=sender_aid,
                    token=token,
                    message_dict=message_dict,
                )
                self._record_execution_gate_rejection(
                    request=request,
                    decision=local_agent_decision,
                    log_message="Execution gate rejected local agent implementation.",
                )
                self.monitor.stop("agent:communication_conv_recv")
                return True

            # Get agent response:
            self.monitor.stop("agent:communication_conv_recv")
            try:
                agent_instance, response = self._run_local_agent_with_diagnostics(
                    query=received_message,
                    initiating_agent=False,
                    agent_instance=agent_instance,
                    peer_aid=sender_aid,
                    conversation_side="receiving",
                    turn_index=i,
                    run_id="agent:llm_backend_recv",
                    local_agent_kwargs={"execution_context": execution_context},
                )
            except Exception as exc:
                logger.error(f"Local agent run failed on receiving side: {exc}")
                self.monitor.start("agent:communication_conv_recv")
                self.monitor.stop("agent:communication_conv_recv")
                return True
            self.monitor.start("agent:communication_conv_recv")
            i+=1 # increase query counter
            
            # Prepare response:
            response_token_dict = self._active_token_snapshot(token)
            if response_token_dict is None:
                logger.error("Token was invalidated before response signing. Ending conversation...")
                self.monitor.stop("agent:communication_conv_recv")
                return True
            response_dict = self._build_conversation_payload(
                receiver_aid=sender_aid,
                token=token,
                message=response,
                action_scope="llm_prompt",
                turn_index=i,
                token_dict=response_token_dict,
                authorized_scopes=self._conversation_authorized_scopes("llm_prompt"),
            )
            # Send response:
            self.monitor.stop("agent:communication_conv_recv")
            self.send(conn, response_dict)
            self.monitor.start("agent:communication_conv_recv")
            logger.log("AGENT", f"Sent: \'{response_dict['msg']}\'")

            if response_dict['msg'] == self.task_finished_token:
                logger.log("AGENT", "Task deemed complete from receiving side.")
                # Invalidate the token:
                self._invalidate_active_token(token)
                logger.log("ACCESS", "Token invalidated from the receiving side.")
                self.monitor.stop("agent:communication_conv_recv")
                return True

    def connect(self, r_aid, message: str):
        """
        Connects to the receiving agent and initiates a conversation with it.
        This function performs the following steps:
        1. Initializes the communication protocol with the receiving agent.
        2. Verifies the receiving agent's identity and device information.
        3. Creates a secure connection to the receiving agent.
        4. Initiates a conversation with the receiving agent.

        Args:
            r_aid: The AID of the receiving agent.
            message: The initial message to send to the receiving agent.
        """
        if not self.active:
            logger.error(f"Agent {self.aid} is deactivated and cannot initiate new sessions.")
            return
        # Start measuring algo overhead:
        self.monitor.start("agent:communication_proto_init")

        # Get everything you need to reach the receiving agent from the provider:

        # Check if you have a token:
        logger.log("ACCESS", f"Checking if a token exists for {r_aid}.")
        token = self.retrieve_valid_token(r_aid)
        if token is not None:
            # Fetch agent information from memory:
            logger.log("ACCESS", f"Found token for {r_aid}. Will use it.")
            r_agent_material = self.previously_contacted_agents.get(r_aid, None)
        else:
            # Fetch agent information from the provider:
            logger.log("ACCESS", f"No valid token found for {r_aid}.")
            logger.log("ACCESS", f"Requesting access to {r_aid} via the Provider.")
            self.monitor.stop("agent:communication_proto_init")
            r_agent_material = self.access(r_aid)
            self.monitor.start("agent:communication_proto_init")

        if r_agent_material is None:
            logger.log("ACCESS", f"Access to {r_aid} denied.")
            return

        # ========================================================================
        # Perform verification checks for integrity purposes before connecting to 
        # the receiving agent.
        # ========================================================================    

        # Verify user certificate:
        r_agent_user_cert_bytes = r_agent_material.get("crt_u", None)
        r_agent_user_cert = sc.bytesToX509Certificate(r_agent_user_cert_bytes)

        logger.log("CRYPTO", f"Verifying {r_aid}'s user certificate.")
        try:
            self.CA.verify(r_agent_user_cert)
        except:
            logger.error(f"ERROR: {r_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")
            raise Exception(f"ERROR: {r_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")

        # Retrieve user identity key: 
        pk_u = r_agent_user_cert.public_key()
    
        # Verify the agent's identity:
        r_aid = r_agent_material.get("aid", None)
        r_agent_cert_bytes = r_agent_material.get("agent_cert", None)
        r_agent_cert = sc.bytesToX509Certificate(
            r_agent_cert_bytes 
        )
        if r_agent_cert is None:
            logger.error("No valid certificate found.")
            raise Exception("No valid certificate found.")
        r_agent_pk = r_agent_cert.public_key()
        r_agent_pk_bytes = r_agent_pk.public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw
        )        

        # Verify the target agent's device information:
        r_device = r_agent_material.get("device")
        r_ip = r_agent_material.get("IP")
        r_port = r_agent_material.get("port")

        dev_network_info = {
            "aid": r_aid, 
            "device": r_device, 
            "IP": r_ip, 
            "port": r_port
        }

        r_agent_pac_bytes = r_agent_material.get("pac", None)

        crypto_info = {
            "pk_a": r_agent_pk_bytes,
            "pac": r_agent_pac_bytes,
            "pk_prov": self.PK_Prov.public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            )
        }

        block = {}
        block.update(dev_network_info)
        block.update(crypto_info)
        r_agent_sig_bytes = r_agent_material.get("agent_sig")
        logger.log("CRYPTO", f"Verifying {r_aid}'s signature.")
        try:
            pk_u.verify(
                r_agent_sig_bytes,
                str(block).encode("utf-8")
            )
        except:
            logger.error(f"ERROR: {r_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")
            return

        # ========================================================================
        # If no signature verification fails, that means that the receiving agent's 
        # information is legitimate. The initiating agent can request a connection 
        # to the receiving agent.
        # ========================================================================
        
        # Save/Update agent material in memory now that it is verified:
        self.previously_contacted_agents[r_aid] = r_agent_material

        # Stop measuring algo overhead:
        self.monitor.stop("agent:communication_proto_init")

        # Create SSL context for the client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")
        # Load the CA certificate for verification:    
        context.load_verify_locations(saga.config.CA_CERT_PATH)


        try:
            # Create and connect the socket
            with socket.create_connection(
                (r_ip, r_port),
                timeout=CONVERSATION_SOCKET_TIMEOUT_SECONDS,
            ) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with context.wrap_socket(sock, server_hostname=r_aid) as conn:
                    conn.settimeout(CONVERSATION_SOCKET_TIMEOUT_SECONDS)
                    logger.log("NETWORK", f"Connected to {r_ip}:{r_port} with verified certificate.")

                    # Start measuring algo overhead:
                    self.monitor.start("agent:communication_proto_init")

                    # Prepare the request:
                    request_dict = {}
                    # Attach the agent's information card and the stamp from the Provider.
                    request_dict['crt_u'] = base64.b64encode(
                        self.crt_u.public_bytes(sc.serialization.Encoding.PEM)
                    ).decode("utf-8")
                    
                    request_dict['card'] = self.card                    
                    request_dict['stamp'] = self.stamp

                    # If there is no active token for contacting r_aid:
                    if token is None:
                        # If no token is found, the initiating agent must 
                        # receive a new one from the receiving agent.
                        logger.log("ACCESS", f"Requesting new token from {r_aid}.")
                        # Use of the receiving agent's one-time keys:
                        r_otk = r_agent_material.get("one_time_keys", None)[0]
                        r_otk_sig_bytes = r_agent_material.get("one_time_key_sigs", None)[0]
                        
                        # Verify the one-time key:
                        if not sc.verify_otk_signature(pk_u, r_aid, r_otk, r_otk_sig_bytes):
                            logger.error(f"ERROR: {r_aid} ONE TIME KEY VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {r_aid} ONE TIME KEY VERIFICATION FAILED. UNSAFE CONNECTION.")

                        # Prepare JSON message
                        request_dict['otk'] = base64.b64encode(r_otk).decode("utf-8")
                    else:
                        # If a token is found, the initiating agent can send 
                        # it to the receiving agent.                        
                        request_dict['token'] = token
                    # Stop the stopwatch
                    self.monitor.stop("agent:communication_proto_init")

                    # Send JSON request
                    self.send(conn, request_dict)

                    # Receive response
                    response_dict = self.recv(conn)

                    # Restart the stopwatch:
                    self.monitor.start("agent:communication_proto_init")
                    
                    if token is None and response_dict:
                        # If no valid token was found, the expected response is a token.
                        
                        self.monitor.start("agent:token_init")
                        # Diffie hellman calculations:
                        r_otk = sc.bytesToPublicX25519Key(r_otk)
                        DH = self.sac.exchange(r_otk)

                        shared_secrets = [DH]
                        concat_secret = b''.join(shared_secrets)

                        SDHK = sc.HKDF(
                            algorithm=sc.hashes.SHA256(),
                            length=32,  # Generate a 256-bit key
                            salt=None,  # Optional: Provide a salt for added security
                            info=b"access-control-shdk-exchange",
                        ).derive(concat_secret)

                        logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")

                        # Receive the new token:
                        # The new token that is generated will be received as a string.
                        # This string is an encoding, i.e. an encryption of the token's
                        # metadata.
                        new_enc_token_str = response_dict.get("token", None)
                        logger.log("ACCESS", f"Received token: {new_enc_token_str}")

                        # Decrypt the token:
                        token_dict = sc.decrypt_token(new_enc_token_str, SDHK)
                        # Store the token:
                        self.store_received_token(r_aid, new_enc_token_str, token_dict)
                        self.monitor.stop("agent:token_init")
                        logger.log("OVERHEAD", f"agent:token_init: {self.monitor.elapsed('agent:token_init')}")
                        # Stop the stopwatch:
                        self.monitor.stop("agent:communication_proto_init")
                        logger.log("OVERHEAD", f"agent:communication_proto_init: {self.monitor.elapsed('agent:communication_proto_init')}")

                        # Start the conversation:
                        self.initiate_conversation(conn, new_enc_token_str, r_aid, message)
                        logger.log("OVERHEAD", f"agent:communication_conv_init: {self.monitor.elapsed('agent:communication_conv_init')}")
                        llm_elapsed = self._llm_elapsed_seconds("agent:llm_backend_init")
                        if llm_elapsed is not None:
                            logger.log("OVERHEAD", f"agent:llm_backend_init: {llm_elapsed}")
                    else:
                        logger.log("ACCESS", f"Valid token found. Will start conversation.")
                        # If a valid token was found, the expected response is a message.
                        if response_dict:
                            if response_dict["token"] is not None:
                                # Stop the stopwatch:
                                self.monitor.stop("agent:communication_proto_init")
                                logger.log("OVERHEAD", f"agent:communication_proto_init: {self.monitor.elapsed('agent:communication_proto_init')}")
                                self.initiate_conversation(conn, token, r_aid, message)
                                logger.log("OVERHEAD", f"agent:communication_conv_init: {self.monitor.elapsed('agent:communication_conv_init')}")
                                llm_elapsed = self._llm_elapsed_seconds("agent:llm_backend_init")
                                if llm_elapsed is not None:
                                    logger.log("OVERHEAD", f"agent:llm_backend_init: {llm_elapsed}")
                            else:
                                logger.error("Token rejected from receiving side.")
                                
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def handle_i_agent_connection(self, conn, fromaddr):
        """
        Handles an incoming TLS connection from an initiating agent.

        This function performs the following steps:
        1. Receives the initial message from the initiating agent.
        2. Verifies the initiating agent's identity and device information.
        3. Checks access control rules to ensure the initiating agent is allowed to contact this agent.
        4. Verifies the initiating agent's user certificate and PAC.
        5. If all checks pass, it initiates a conversation with the initiating agent.

        Args:
            conn: The connection object for the incoming connection.
            fromaddr: The address of the initiating agent.
        """
        try:
            logger.log("NETWORK", f"Incoming connection from {fromaddr}.")

            # Receive data
            received_msg = self.recv(conn)
            if received_msg:
                    # Start the stopwatch:
                    self.monitor.start("agent:communication_proto_recv")
                    try:

                        # Extract i_aid from card:
                        i_card = received_msg.get("card", None)
                        #i_card = self.deserialize(i_card)
                        i_aid = i_card.get("aid", None)

                        # Check that the agent 

                        if i_aid is None:
                            logger.error("No agent ID found in the initial message from the initiating side.")
                            raise Exception("No agent ID provided.")
                        
                        if match(self.contact_rulebook, i_aid) < 0:
                            # The initiating agent is not allowed to contact the receiving agent.
                            logger.log("ACCESS", f"Access control failed: {i_aid} is not allowed to contact this agent.")
                            raise Exception(f"Access control failed: {i_aid} is not allowed to contact this agent.")
                        
                        # Fill in the agent certificate and agent IP from the connection:
                        # - this handles mismatch checks too
                        i_card['IP'] = fromaddr[0]
                        i_card['agent_cert'] = sc.der_to_pem(conn.getpeercert(binary_form=True))
                        # Convert to byte format for signature verification:
                        i_card['pac'] = base64.b64decode(i_card['pac'])
                        i_card['agent_sig'] = base64.b64decode(i_card['agent_sig'])
                
                        
                        logger.log("CRYPTO", f"Verifying {i_aid}'s stamp from the Provider.")
                        i_stamp = received_msg.get("stamp", None)
                        try:
                            self.PK_Prov.verify(
                                base64.b64decode(i_stamp),
                                str(i_card).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} STAMP VERIFICATION FAILED. UNSAFE CONNECTION.")
                        
                        # Check data integrity:
                        i_agent_material = i_card

                        # Perform verification checks:                                
                        if i_agent_material is None:
                            logger.error(f"{i_aid} not found.")
                            raise Exception(f"{i_aid} not found.")
                    
                        # Verify user certificate:
                        i_agent_user_cert_bytes = base64.b64decode(received_msg.get("crt_u", None))
                        i_agent_user_cert = sc.bytesToX509Certificate(i_agent_user_cert_bytes)

                        logger.log("CRYPTO", f"Verifying {i_aid}'s user certificate.")
                        try:
                            self.CA.verify(i_agent_user_cert)
                        except:
                            logger.error(f"ERROR: {i_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} USER CERTIFICATE VERIFICATION FAILED. UNSAFE CONNECTION.")

                        # Retrieve user identity key: 
                        pk_u = i_agent_user_cert.public_key()
                    
                        # Verify the agent's identity:
                        i_agent_cert = sc.bytesToX509Certificate(sc.der_to_pem(conn.getpeercert(binary_form=True)))
                        if i_agent_cert is None:
                            logger.error("No valid certificate found.")
                            raise Exception("No valid certificate found.")
                        
                        i_agent_pk = i_agent_cert.public_key()
                        i_agent_pk_bytes = i_agent_pk.public_bytes(
                            encoding=sc.serialization.Encoding.Raw,
                            format=sc.serialization.PublicFormat.Raw
                        )
                    
                        i_device = i_agent_material.get("device")
                        # Use the connections's IP to verify the device information.
                        i_ip = fromaddr[0]
                        i_port = i_agent_material.get("port")
                        dev_network_info = {
                            "aid": i_aid, 
                            "device": i_device, 
                            "IP": i_ip, 
                            "port": i_port
                        }

                        i_agent_pac_bytes = i_agent_material.get("pac", None)
                        i_pac = sc.bytesToPublicX25519Key(i_agent_pac_bytes)
                        crypto_info = {
                            "pk_a": i_agent_pk_bytes,
                            "pac": i_agent_pac_bytes,
                            "pk_prov": self.PK_Prov.public_bytes(
                                encoding=sc.serialization.Encoding.Raw,
                                format=sc.serialization.PublicFormat.Raw
                            )
                        }


                        block = {}
                        block.update(dev_network_info)
                        block.update(crypto_info)
                        i_agent_sig_bytes = i_agent_material.get("agent_sig")
                        logger.log("CRYPTO", f"Verifying {i_aid}'s signature.")
                        try:
                            pk_u.verify(
                                i_agent_sig_bytes,
                                str(block).encode("utf-8")
                            )
                        except:
                            logger.error(f"ERROR: {i_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")
                            raise Exception(f"ERROR: {i_aid} SIGNATURE VERIFICATION FAILED. MATERIAL INTEGRITY PERHAPS COMPROMISED. UNSAFE CONNECTION.")

                        # ========================================================================
                        # If no signature verification fails, that means that the receiving agent's 
                        # information is legitimate. The initiating agent can request a connection 
                        # to the receiving agent.
                        # ========================================================================

                        # ============================ ACCESS CONTROL ============================

                        # Check if the initiating agent has a token:
                        i_token = received_msg.get("token", None)
                        if i_token is None:
                            self.monitor.start("agent:token_recv")
                            # The initiating agent does not have a token. 
                            logger.log("ACCESS", f"No valid received token found. For {i_aid}. Generating new one.")
                            
                            # The agent must have a otk:
                            i_otk_json = received_msg.get("otk", None)
                            if i_otk_json is None:
                                logger.error("Acces control failed: no one-time key provided from initiating agent.")
                                raise Exception("Acces control failed: no one-time key provided from initiating agent.")
                            i_otk_bytes = base64.b64decode(i_otk_json)

                            sotk = self._consume_local_otk(i_otk_bytes)
                            if sotk is None:
                                logger.error("Access control failed: unknown one-time key.")
                                raise Exception("Access control failed: unknown one-time key.")

                            # Diffie hellman calculations:
                            DH = sotk.exchange(i_pac)
                            
                            shared_secrets = [DH]
                            concat_secret = b''.join(shared_secrets)

                            SDHK = sc.HKDF(
                                algorithm=sc.hashes.SHA256(),
                                length=32,  # Generate a 256-bit key
                                salt=None,  # Optional: Provide a salt for added security
                                info=b"access-control-shdk-exchange",
                            ).derive(concat_secret)

                            logger.log("ACCESS", f"Derived SDHK: {SDHK.hex()}")
                            
                            # Generate the token:
                            enc_token_bytes = self.generate_token(i_pac, SDHK)
                            enc_token_str = base64.b64encode(enc_token_bytes).decode('utf-8') 
                            token_response = {"token": enc_token_str}
                            logger.log("ACCESS", f"Generated token: {enc_token_str}")

                            ser_token_response = json.dumps(token_response).encode('utf-8')
                            
                            # Store the token:
                            with self.active_tokens_lock:
                                self.active_tokens[enc_token_str] = sc.decrypt_token(enc_token_str, SDHK)

                            self.monitor.stop("agent:token_recv")
                            logger.log("OVERHEAD", f"agent:token_recv: {self.monitor.elapsed('agent:token_recv')}")
                            # Stop the stopwatch
                            self.monitor.stop("agent:communication_proto_recv")
                            logger.log("OVERHEAD", f"agent:communication_proto_recv: {self.monitor.elapsed('agent:communication_proto_recv')}")

                            self.send(conn, token_response)

                            # Start the conversation:
                            logger.log("AGENT", f"Starting conversation with {i_aid}.")
                            self.receive_conversation(conn, enc_token_str, i_pac, sender_aid=i_aid)
                            logger.log("OVERHEAD", f"agent:communication_conv_recv: {self.monitor.elapsed('agent:communication_conv_recv')}")
                            llm_elapsed = self._llm_elapsed_seconds("agent:llm_backend_recv")
                            if llm_elapsed is not None:
                                logger.log("OVERHEAD", f"agent:llm_backend_recv: {llm_elapsed}")
                        else:
                            # Check the token and see if it is in the active tokens:
                            if self.token_is_valid(i_token, i_pac):
                                # Stop the stopwatch
                                self.monitor.stop("agent:communication_proto_recv")
                                logger.log("OVERHEAD", f"agent:communication_proto_recv: {self.monitor.elapsed('agent:communication_proto_recv')}")

                                # If the token is valid, start the conversation:
                                logger.log("ACCESS", f"Valid token found. Will accept conversation.")
                                self.send(conn, {"token": i_token})
                                self.receive_conversation(conn, i_token, i_pac, sender_aid=i_aid)
                                logger.log("OVERHEAD", f"agent:communication_conv_recv: {self.monitor.elapsed('agent:communication_conv_recv')}")
                                llm_elapsed = self._llm_elapsed_seconds("agent:llm_backend_recv")
                                if llm_elapsed is not None:
                                    logger.log("OVERHEAD", f"agent:llm_backend_recv: {llm_elapsed}")
                            else:
                                logger.error("Token is invalid. Ending connection.")

                    except json.JSONDecodeError:
                        print("Received invalid JSON format.")


                    except Exception as e:
                        print(f"Error: {e}")
                        traceback.print_exc()
        finally:
            try:
                logger.log("NETWORK", "Attempting to close connection.")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                logger.log("NETWORK", "Connection succesfully closed.")
            except:
                logger.log("NETWORK", "Connection already closed by other party.")

    def listen(self):
        """
        Listens for incoming TLS connections, handles Ctrl+C gracefully,
        and ensures proper socket closure on shutdown.
        """
        if not self.active:
            logger.error(f"Agent {self.aid} is deactivated and cannot listen for new sessions.")
            return

        # Create SSL context for the server
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  # TLS 1.3 only
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(saga.config.CA_CERT_PATH)
        # Load the self-signed certificate and private key
        context.load_cert_chain(certfile=self.workdir + "agent.crt", keyfile=self.workdir + "agent.key")

        # Create and bind the socket
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((self.IP, int(self.port)))
        bindsocket.listen(5)

        logger.log("NETWORK", f"Listening on {self.IP}:{self.port}... (Press Ctrl+C to stop)")

        try:
            while True:
                try:
                    # Incoming connection:
                    newsocket, fromaddr = bindsocket.accept()
                    # TLS takes over and tries to
                    conn = context.wrap_socket(newsocket, server_side=True)
                    conn.settimeout(CONVERSATION_SOCKET_TIMEOUT_SECONDS)
                    logger.log("NETWORK", f"Connection from {fromaddr}")
                    # Spawn a new thread to handle the incoming connection:
                    i_agent_thread = threading.Thread(target=self.handle_i_agent_connection, args=(conn, fromaddr))
                    i_agent_thread.daemon = True  # Daemon mode: Exits when main thread ends
                    i_agent_thread.start()

                except KeyboardInterrupt:
                    print("\nReceived Ctrl+C, shutting down server gracefully...")
                    break

                except ssl.SSLError as e:
                    logger.error(f"SSL Error: {e}")
        finally:
            bindsocket.close()
            print("Server socket closed. Exiting.")
