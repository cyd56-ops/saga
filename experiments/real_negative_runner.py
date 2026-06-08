"""Opt-in real-service negative runner for SAGA-PQ-CAN runtime gates."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from types import MethodType
from typing import Iterable, Literal

from saga.agent import Agent, enable_toy_lwe_runtime_auth_from_config, get_agent_material
from saga.config import ROOT_DIR, ReplayStoreConfig, ToyRuntimeAuthConfig, UserConfig, get_index_of_agent
from saga.execution_gate import RedisReplayStateStore, ReplayStateStore, SQLiteReplayStateStore
from saga.local_agent import LocalAgent

try:  # pragma: no cover - exercised by script-style execution
    from experiments import batch_run
    from experiments.result_logging import (
        filter_records_since,
        load_execution_gate_audit_records,
    )
except ImportError:  # pragma: no cover - supports `python experiments/real_negative_runner.py`
    import batch_run  # type: ignore
    from result_logging import (  # type: ignore
        filter_records_since,
        load_execution_gate_audit_records,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_INITIATOR_CONFIG = REPO_ROOT / "user_configs" / "emma_pqcan.yaml"
DEFAULT_RECEIVER_CONFIG = REPO_ROOT / "user_configs" / "raj_pqcan.yaml"
DEFAULT_AGENT_NAME = "calendar_agent"
DEFAULT_MESSAGE = "real negative runtime auth probe"
DEFAULT_TOOL_ONLY_SCOPE = "tool_call:add_calendar_event"
DEFAULT_SCENARIOS = (
    "missing_request_envelope",
    "tampered_message",
    "prompt_surface_tool_only",
    "replayed_envelope",
    "wrong_trusted_sender_key",
    "unauthorized_tool_scope",
    "unauthorized_memory_write",
    "unauthorized_delegation",
)
EXPECTED_REASONS = {
    "missing_request_envelope": "missing_request_envelope",
    "tampered_message": "message_digest_mismatch",
    "prompt_surface_tool_only": "prompt_scope_not_authorized",
    "replayed_envelope": "replayed_request_envelope",
    "wrong_trusted_sender_key": "signature_verification_failed",
    "unauthorized_tool_scope": "unauthorized_tool_scope",
    "unauthorized_memory_write": "unauthorized_memory_write",
    "unauthorized_delegation": "unauthorized_delegation",
}
SCOPE_PROBE_SCENARIOS = (
    "unauthorized_tool_scope",
    "unauthorized_memory_write",
    "unauthorized_delegation",
)
REPLAY_STORE_BACKENDS = ("agent_config", "sqlite", "redis")


@dataclass(frozen=True)
class RealNegativeResult:
    """真实服务负向样本的一条结果记录。"""

    scenario: str
    passed: bool
    expected_reason: str
    observed_reason: str
    side_effect_triggered: bool
    local_agent_run_count: int
    details: Mapping[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        """序列化为稳定 JSON 字典，供实验结果落盘。"""
        return {
            "scenario": self.scenario,
            "category": "real_service_runtime",
            "passed": self.passed,
            "expected_reason": self.expected_reason,
            "observed_reason": self.observed_reason,
            "side_effect_triggered": self.side_effect_triggered,
            "local_agent_run_count": self.local_agent_run_count,
            "details": dict(self.details or {}),
        }


@dataclass(frozen=True)
class RealNegativeRunConfig:
    """真实服务负向 runner 的解析后配置。"""

    repo_root: Path
    python_executable: str
    scenarios: tuple[str, ...]
    initiator_config: Path
    receiver_config: Path
    agent_name: str
    run_dir: Path
    ca_static_dir: Path
    mongo_dbpath: Path
    mongo_binary: Path | None
    provider_db_uri: str
    startup_timeout_seconds: float
    listener_startup_timeout_seconds: float
    query_timeout_seconds: float
    audit_timeout_seconds: float
    skip_db_preflight: bool
    replay_store_backend: Literal["agent_config", "sqlite", "redis"] = "agent_config"
    replay_store_sqlite_path: Path | None = None
    replay_store_redis_url: str | None = None
    replay_store_key_prefix: str = "saga:pqcan:replay:"
    replay_store_ttl_seconds: int | None = None


class _RecordingLocalAgent(LocalAgent):
    """记录真实 listener 中是否触发 local_agent.run()。"""

    task_finished_token = "<TASK_FINISHED>"

    def __init__(
        self,
        side_effect_path: str | Path,
        *,
        scope_probe: str | None = None,
        protected_side_effect_path: str | Path | None = None,
    ) -> None:
        """保存本地运行记录路径；scope_probe 场景另行记录受保护动作副作用。"""
        self.side_effect_path = Path(side_effect_path)
        self.scope_probe = scope_probe
        self.protected_side_effect_path = (
            Path(protected_side_effect_path)
            if protected_side_effect_path is not None
            else _protected_side_effect_path(self.side_effect_path)
        )

    def supports_execution_context(self) -> bool:
        """声明真实服务负向探针会使用 execution_context 检查下游能力。"""
        return True

    def run(
        self,
        query: str,
        initiating_agent: bool,
        agent_instance: LocalAgent | None = None,
        **kwargs: object,
    ) -> tuple[LocalAgent | None, str]:
        """记录一次本地执行；scope_probe 场景会尝试未授权下游动作。"""
        record = {
            "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
            "query": query,
            "initiating_agent": initiating_agent,
            "has_execution_context": kwargs.get("execution_context") is not None,
            "scope_probe": self.scope_probe,
        }
        if self.scope_probe is None:
            self._append_jsonl(self.side_effect_path, record)
            return agent_instance, self.task_finished_token

        context = kwargs.get("execution_context")
        try:
            self._run_scope_probe(context)
        except PermissionError as exc:
            record["denied_reason"] = getattr(exc, "reason", str(exc).split(":", 1)[0])
            self._append_jsonl(self.side_effect_path, record)
            raise

        record["denied_reason"] = "authorized"
        self._append_jsonl(self.side_effect_path, record)
        self._append_jsonl(
            self.protected_side_effect_path,
            {
                "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
                "scope_probe": self.scope_probe,
                "query": query,
            },
        )
        return agent_instance, self.task_finished_token

    def _run_scope_probe(self, context: object) -> None:
        """根据场景尝试一个未签名的下游执行面动作。"""
        if context is None:
            raise PermissionError("missing_local_execution_context")
        if self.scope_probe == "unauthorized_tool_scope":
            context.require_tool_call("add_calendar_event")
            return
        if self.scope_probe == "unauthorized_memory_write":
            context.require_memory_write()
            return
        if self.scope_probe == "unauthorized_delegation":
            context.require_delegation()
            return
        raise ValueError(f"unsupported scope probe: {self.scope_probe}")

    def _append_jsonl(self, path: Path, record: Mapping[str, object]) -> None:
        """追加一条 JSONL 记录；测试探针使用独立文件区分真实副作用。"""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def available_scenarios() -> tuple[str, ...]:
    """返回当前真实服务负向 runner 支持的场景名。"""
    return DEFAULT_SCENARIOS


def build_summary(results: Iterable[RealNegativeResult]) -> dict[str, object]:
    """汇总真实服务负向样本结果，判断整轮是否全部 fail-closed。"""
    result_list = list(results)
    failed = [result.scenario for result in result_list if not result.passed]
    return {
        "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        "scenario_count": len(result_list),
        "passed_count": len(result_list) - len(failed),
        "failed_count": len(failed),
        "all_passed": not failed,
        "failed_scenarios": failed,
        "scenarios": [result.scenario for result in result_list],
    }


def write_real_negative_results(
    results: Iterable[RealNegativeResult],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """将真实服务负向样本 JSONL 与 summary 写入 ignored run 目录。"""
    result_list = list(results)
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    results_path = base_dir / "real_negative_results.jsonl"
    with results_path.open("w", encoding="utf-8") as handle:
        for result in result_list:
            handle.write(json.dumps(result.as_dict(), sort_keys=True) + "\n")

    summary_path = base_dir / "real_negative_summary.json"
    summary = build_summary(result_list)
    summary["results_path"] = str(results_path)
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return results_path, summary_path


def build_negative_payload(
    agent: Agent,
    *,
    scenario: str,
    receiver_aid: str,
    token: str,
    message: str,
    turn_index: int,
    token_dict: Mapping[str, object],
) -> dict[str, object]:
    """构造真实 socket 会发送的负向 conversation payload。"""
    if scenario == "missing_request_envelope":
        return {
            "msg": message,
            "token": token,
            "action_scope": "llm_prompt",
        }
    if scenario == "tampered_message":
        payload = agent._build_conversation_payload(
            receiver_aid=receiver_aid,
            token=token,
            message=message,
            action_scope="llm_prompt",
            turn_index=turn_index,
            token_dict=dict(token_dict),
            authorized_scopes=agent._conversation_authorized_scopes("llm_prompt"),
        )
        payload["msg"] = f"{message} [tampered after signing]"
        return payload
    if scenario in {"prompt_surface_tool_only", "replayed_envelope"}:
        # 使用已签名的工具入口 scope，确保拒绝发生在 prompt surface 或 replay gate。
        return agent._build_conversation_payload(
            receiver_aid=receiver_aid,
            token=token,
            message=message,
            action_scope=DEFAULT_TOOL_ONLY_SCOPE,
            turn_index=turn_index,
            token_dict=dict(token_dict),
            # 该负向样本要验证 receiver 侧 prompt surface gate；不能让 initiating 侧本地 policy 提前拒绝。
            authorized_scopes=(DEFAULT_TOOL_ONLY_SCOPE,),
        )
    if scenario in {"wrong_trusted_sender_key", *SCOPE_PROBE_SCENARIOS}:
        authorized_scopes = agent._conversation_authorized_scopes("llm_prompt")
        if scenario == "unauthorized_tool_scope":
            authorized_scopes = ("llm_prompt", "memory_read", "tool_call:send_email")
        elif scenario == "unauthorized_memory_write":
            authorized_scopes = ("llm_prompt", "memory_read")
        elif scenario == "unauthorized_delegation":
            authorized_scopes = ("llm_prompt", "memory_read")
        return agent._build_conversation_payload(
            receiver_aid=receiver_aid,
            token=token,
            message=message,
            action_scope="llm_prompt",
            turn_index=turn_index,
            token_dict=dict(token_dict),
            authorized_scopes=authorized_scopes,
        )
    raise ValueError(f"unsupported real negative scenario: {scenario}")


def run_listener(
    *,
    receiver_config: str | Path,
    agent_name: str,
    side_effect_path: str | Path,
    wrong_trusted_sender_aid: str | None = None,
    scope_probe: str | None = None,
    replay_store_backend: str = "agent_config",
    replay_store_sqlite_path: str | Path | None = None,
    replay_store_redis_url: str | None = None,
    replay_store_key_prefix: str = "saga:pqcan:replay:",
    replay_store_ttl_seconds: int | None = None,
) -> None:
    """启动真实 receiving Agent listener，但本地 agent 只记录副作用。"""
    agent = _build_agent_from_config(
        config_path=receiver_config,
        agent_name=agent_name,
        side_effect_path=side_effect_path,
        scope_probe=scope_probe,
        replay_state_store=_build_replay_state_store(
            replay_store_backend,
            sqlite_path=replay_store_sqlite_path,
            redis_url=replay_store_redis_url,
            key_prefix=replay_store_key_prefix,
            ttl_seconds=replay_store_ttl_seconds,
        ),
    )
    if wrong_trusted_sender_aid is not None:
        _install_wrong_trusted_sender_key(agent, sender_aid=wrong_trusted_sender_aid)
    agent.listen()


def run_query(
    *,
    scenario: str,
    initiator_config: str | Path,
    receiver_config: str | Path,
    agent_name: str,
    run_dir: str | Path,
    side_effect_path: str | Path,
    audit_timeout_seconds: float = 10.0,
) -> RealNegativeResult:
    """通过真实 Provider/token/TLS/socket 路径发送一个负向 payload。"""
    if scenario not in EXPECTED_REASONS:
        raise ValueError(f"unsupported real negative scenario: {scenario}")

    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    side_effect = Path(side_effect_path)
    side_effect.parent.mkdir(parents=True, exist_ok=True)
    if side_effect.exists():
        side_effect.unlink()

    started_at = datetime.now(tz=timezone.utc)
    receiver_aid = _agent_aid(receiver_config, agent_name)
    receiver_workdir = _agent_workdir_from_config_path(receiver_config, agent_name)
    agent = _build_agent_from_config(
        config_path=initiator_config,
        agent_name=agent_name,
        side_effect_path=run_path / "initiator_local_agent_runs.jsonl",
    )
    _install_negative_initiate_conversation(agent, scenario=scenario)

    for _ in range(_connect_attempts_for_scenario(scenario)):
        agent.connect(receiver_aid, DEFAULT_MESSAGE)
    if scenario in SCOPE_PROBE_SCENARIOS:
        observed_reason = _wait_for_local_denied_reason(
            side_effect,
            timeout_seconds=audit_timeout_seconds,
        )
    else:
        observed_reason = _wait_for_observed_reason(
            receiver_workdir,
            started_at=started_at,
            timeout_seconds=audit_timeout_seconds,
        )
    local_agent_run_count = _count_jsonl_rows(side_effect)
    protected_side_effect_count = _count_jsonl_rows(_protected_side_effect_path(side_effect))
    expected_reason = EXPECTED_REASONS[scenario]
    if scenario in SCOPE_PROBE_SCENARIOS:
        observed_reason = _last_local_denied_reason(side_effect) or observed_reason
        passed = (
            observed_reason == expected_reason
            and local_agent_run_count == 1
            and protected_side_effect_count == 0
        )
        side_effect_triggered = protected_side_effect_count > 0
    else:
        passed = observed_reason == expected_reason and local_agent_run_count == 0
        side_effect_triggered = local_agent_run_count > 0
    result = RealNegativeResult(
        scenario=scenario,
        passed=passed,
        expected_reason=expected_reason,
        observed_reason=observed_reason,
        side_effect_triggered=side_effect_triggered,
        local_agent_run_count=local_agent_run_count,
        details={
            "receiver_aid": receiver_aid,
            "receiver_workdir": receiver_workdir,
            "side_effect_path": str(side_effect),
            "protected_side_effect_count": protected_side_effect_count,
        },
    )
    result_path = run_path / "real_negative_result.json"
    result_path.write_text(
        json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def run_real_negative_services(config: RealNegativeRunConfig) -> list[RealNegativeResult]:
    """启动本地 CA/Provider/socket listener 并运行 opt-in 真实负向样本。"""
    config.run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "started_at": datetime.now(tz=timezone.utc).isoformat(),
        "scenarios": list(config.scenarios),
        "initiator_config": str(config.initiator_config),
        "receiver_config": str(config.receiver_config),
        "agent_name": config.agent_name,
        "run_dir": str(config.run_dir),
        "replay_store_backend": config.replay_store_backend,
        "replay_store_sqlite_path": (
            str(config.replay_store_sqlite_path)
            if config.replay_store_sqlite_path is not None
            else None
        ),
        "replay_store_redis_url_configured": config.replay_store_redis_url is not None,
        "replay_store_key_prefix": config.replay_store_key_prefix,
        "replay_store_ttl_seconds": config.replay_store_ttl_seconds,
    }
    (config.run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    ports = batch_run._load_service_ports(config.repo_root)
    batch_config = _batch_config_from_real_config(config)
    managed = []
    results: list[RealNegativeResult] = []
    try:
        managed.extend(batch_run._start_local_services(batch_config, ports))
        batch_run._require_preflight_ok(
            batch_config,
            label="real_negative_trust_chain_preflight",
            check_db_sync=not config.skip_db_preflight,
            check_model_backends=False,
        )
        for scenario in config.scenarios:
            results.append(_run_real_negative_scenario(config, scenario))
        write_real_negative_results(results, config.run_dir)
        return results
    finally:
        for process in reversed(managed):
            batch_run._stop_process(process)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析真实服务负向 runner 的 CLI 参数。"""
    parser = argparse.ArgumentParser(
        description="Run opt-in real-service SAGA-PQ-CAN negative samples."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    run_parser = subparsers.add_parser("run", help="Run services, listener, and query samples.")
    _add_common_run_args(run_parser)

    listen_parser = subparsers.add_parser("listen", help="Internal receiver listener entrypoint.")
    listen_parser.add_argument("--receiver-config", required=True)
    listen_parser.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    listen_parser.add_argument("--side-effect-path", required=True)
    listen_parser.add_argument("--wrong-trusted-sender-aid")
    listen_parser.add_argument("--scope-probe", choices=SCOPE_PROBE_SCENARIOS)
    _add_replay_store_args(listen_parser)

    query_parser = subparsers.add_parser("query", help="Internal negative query entrypoint.")
    query_parser.add_argument("--scenario", choices=DEFAULT_SCENARIOS, required=True)
    query_parser.add_argument("--initiator-config", required=True)
    query_parser.add_argument("--receiver-config", required=True)
    query_parser.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    query_parser.add_argument("--run-dir", required=True)
    query_parser.add_argument("--side-effect-path", required=True)
    query_parser.add_argument("--audit-timeout", type=float, default=10.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """运行真实服务负向 CLI；run 模式下若任一场景失败则返回非零。"""
    args = parse_args(argv)
    if args.mode == "listen":
        run_listener(
            receiver_config=args.receiver_config,
            agent_name=args.agent_name,
            side_effect_path=args.side_effect_path,
            wrong_trusted_sender_aid=args.wrong_trusted_sender_aid,
            scope_probe=args.scope_probe,
            replay_store_backend=args.replay_store_backend,
            replay_store_sqlite_path=args.replay_store_sqlite_path,
            replay_store_redis_url=args.replay_store_redis_url,
            replay_store_key_prefix=args.replay_store_key_prefix,
            replay_store_ttl_seconds=args.replay_store_ttl_seconds,
        )
        return 0
    if args.mode == "query":
        result = run_query(
            scenario=args.scenario,
            initiator_config=args.initiator_config,
            receiver_config=args.receiver_config,
            agent_name=args.agent_name,
            run_dir=args.run_dir,
            side_effect_path=args.side_effect_path,
            audit_timeout_seconds=args.audit_timeout,
        )
        print(json.dumps(result.as_dict(), sort_keys=True))
        return 0

    config = _config_from_run_args(args)
    print(f"[real-negative] run directory: {config.run_dir}")
    results = run_real_negative_services(config)
    summary = build_summary(results)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            "[real-negative] "
            f"{status} {result.scenario}: expected={result.expected_reason} "
            f"observed={result.observed_reason} local_runs={result.local_agent_run_count}"
        )
    print(
        "[real-negative] "
        f"passed={summary['passed_count']}/{summary['scenario_count']} "
        f"all_passed={summary['all_passed']}"
    )
    return 0 if summary["all_passed"] else 1


def _build_agent_from_config(
    *,
    config_path: str | Path,
    agent_name: str,
    side_effect_path: str | Path,
    scope_probe: str | None = None,
    replay_state_store: ReplayStateStore | None = None,
) -> Agent:
    """从 user config 和本地注册材料构造真实 Agent，并启用 PQ-CAN runtime auth。"""
    config = UserConfig.load(str(config_path), drop_extra_fields=True)
    agent_index = get_index_of_agent(config, agent_name)
    if agent_index is None:
        raise ValueError(f"{config_path} does not define agent {agent_name}")
    credentials_endpoint = _agent_workdir(config, config.agents[agent_index].name)
    material = get_agent_material(credentials_endpoint)
    agent = Agent(
        workdir=credentials_endpoint,
        material=material,
        local_agent=_RecordingLocalAgent(side_effect_path, scope_probe=scope_probe),
    )
    runtime_auth_config = config.agents[agent_index].toy_runtime_auth
    if replay_state_store is not None:
        runtime_auth_config = _runtime_auth_config_for_injected_replay_store(runtime_auth_config)
    enable_toy_lwe_runtime_auth_from_config(
        agent,
        runtime_auth_config,
        replay_state_store=replay_state_store,
    )
    return agent


def _install_negative_initiate_conversation(agent: Agent, *, scenario: str) -> None:
    """覆盖 initiating-side conversation，仅发送负向 payload 而不调用模型。"""
    replay_payload: dict[str, object] | None = None

    def _negative_initiate(
        self: Agent,
        conn,
        token: str,
        r_aid: str,
        init_msg: str,
    ) -> bool:
        """使用真实 token/TLS 连接发送一个预设负向 conversation payload。"""
        with self.received_tokens_lock:
            token_dict = dict(self.received_tokens[token])
        nonlocal replay_payload
        if scenario == "replayed_envelope" and replay_payload is not None:
            payload = dict(replay_payload)
        else:
            payload = build_negative_payload(
                self,
                scenario=scenario,
                receiver_aid=r_aid,
                token=token,
                message=init_msg,
                turn_index=0,
                token_dict=token_dict,
            )
            if scenario == "replayed_envelope":
                replay_payload = dict(payload)
        self.send(conn, payload)
        try:
            self.recv(conn)
        except Exception:
            pass
        return False

    agent.initiate_conversation = MethodType(_negative_initiate, agent)


def _install_wrong_trusted_sender_key(agent: Agent, *, sender_aid: str) -> None:
    """将指定 sender 的可信公钥替换为错误公钥，用于真实验签失败样本。"""
    gate = getattr(agent, "execution_gate", None)
    wrong_public_key = getattr(agent, "pq_public_key", None)
    trusted_public_keys = getattr(gate, "trusted_public_keys", None)
    if gate is None or trusted_public_keys is None or wrong_public_key is None:
        raise RuntimeError("receiver runtime auth is not configured for wrong-key scenario")
    trusted_public_keys[sender_aid] = wrong_public_key


def _connect_attempts_for_scenario(scenario: str) -> int:
    """返回单个场景需要建立的真实会话次数。"""
    return 2 if scenario == "replayed_envelope" else 1


def _agent_workdir(config: UserConfig, agent_name: str) -> str:
    """返回指定 agent 的本地 workdir 路径。"""
    return str(Path(ROOT_DIR) / "user" / f"{config.email}:{agent_name}") + "/"


def _agent_workdir_from_config_path(config_path: str | Path, agent_name: str) -> str:
    """从 user config 路径读取指定 agent 的本地 workdir。"""
    return _agent_workdir(
        UserConfig.load(str(config_path), drop_extra_fields=True),
        agent_name,
    )


def _agent_aid(config_path: str | Path, agent_name: str) -> str:
    """从 user config 推导指定 agent 的 AID。"""
    config = UserConfig.load(str(config_path), drop_extra_fields=True)
    agent_index = get_index_of_agent(config, agent_name)
    if agent_index is None:
        raise ValueError(f"{config_path} does not define agent {agent_name}")
    return f"{config.email}:{config.agents[agent_index].name}"


def _wait_for_observed_reason(
    receiver_workdir: str | Path,
    *,
    started_at: datetime,
    timeout_seconds: float,
) -> str:
    """轮询 receiver execution-gate audit，返回本次窗口最后一个拒绝 reason。"""
    deadline = time.monotonic() + timeout_seconds
    last_reason = ""
    while time.monotonic() <= deadline:
        records = filter_records_since(
            load_execution_gate_audit_records(receiver_workdir),
            started_at=started_at,
        )
        denied = [record for record in records if record.get("allowed") is False]
        if denied:
            last_reason = str(denied[-1].get("reason", ""))
            return last_reason
        time.sleep(0.2)
    return last_reason or "missing_audit_reason"


def _count_jsonl_rows(path: str | Path) -> int:
    """统计 side-effect JSONL 行数；文件不存在表示没有触发本地执行。"""
    row_path = Path(path)
    if not row_path.exists():
        return 0
    return sum(1 for line in row_path.read_text(encoding="utf-8").splitlines() if line.strip())


def _protected_side_effect_path(path: str | Path) -> Path:
    """返回受保护动作副作用文件路径，用于和 prompt 运行记录分开统计。"""
    row_path = Path(path)
    return row_path.with_name(f"{row_path.stem}_protected_actions{row_path.suffix}")


def _last_local_denied_reason(path: str | Path) -> str:
    """读取 scope-probe local agent 记录中的最后一个拒绝原因。"""
    row_path = Path(path)
    if not row_path.exists():
        return ""
    reason = ""
    for line in row_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        reason = str(payload.get("denied_reason", reason))
    return reason


def _wait_for_local_denied_reason(
    path: str | Path,
    *,
    timeout_seconds: float,
) -> str:
    """轮询本地 scope-probe 记录，等待未授权执行面拒绝原因。"""
    deadline = time.monotonic() + timeout_seconds
    last_reason = ""
    while time.monotonic() <= deadline:
        last_reason = _last_local_denied_reason(path)
        if last_reason:
            return last_reason
        time.sleep(0.2)
    return last_reason or "missing_local_denied_reason"


def _run_real_negative_scenario(
    config: RealNegativeRunConfig,
    scenario: str,
) -> RealNegativeResult:
    """为单个场景启动 receiver listener，再运行真实 query 注入。"""
    task = batch_run.TaskSpec(
        name="real_negative",
        script=Path(__file__).resolve(),
        receiver_agent_name=config.agent_name,
    )
    host, port = batch_run._receiver_endpoint(config.receiver_config, task)
    if batch_run._port_is_open(host, port):
        raise RuntimeError(
            f"{scenario} receiver port {host}:{port} is already in use before listener start"
        )

    scenario_dir = config.run_dir / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)
    side_effect_path = scenario_dir / "receiver_local_agent_runs.jsonl"
    wrong_trusted_sender_aid = (
        _agent_aid(config.initiator_config, config.agent_name)
        if scenario == "wrong_trusted_sender_key"
        else None
    )
    listener = batch_run._start_process(
        name=f"real_negative_{scenario}_listen",
        command=_listen_command(
            config,
            side_effect_path=side_effect_path,
            wrong_trusted_sender_aid=wrong_trusted_sender_aid,
            scope_probe=scenario if scenario in SCOPE_PROBE_SCENARIOS else None,
        ),
        cwd=config.repo_root,
        run_dir=config.run_dir,
        interrupt_first=True,
    )
    try:
        batch_run._wait_for_port(
            name=f"{scenario} listener",
            host=host,
            port=port,
            timeout_seconds=config.listener_startup_timeout_seconds,
            process=listener.process,
        )
        batch_run._run_blocking(
            name=f"real_negative_{scenario}_query",
            command=_query_command(
                config,
                scenario=scenario,
                scenario_dir=scenario_dir,
                side_effect_path=side_effect_path,
            ),
            cwd=config.repo_root,
            run_dir=config.run_dir,
            timeout_seconds=config.query_timeout_seconds,
        )
    finally:
        batch_run._stop_process(listener)

    result_path = scenario_dir / "real_negative_result.json"
    return _load_result(result_path)


def _listen_command(
    config: RealNegativeRunConfig,
    *,
    side_effect_path: Path,
    wrong_trusted_sender_aid: str | None = None,
    scope_probe: str | None = None,
) -> list[str]:
    """构造真实 receiver listener 子进程命令。"""
    command = [
        config.python_executable,
        str(Path(__file__).resolve()),
        "listen",
        "--receiver-config",
        str(config.receiver_config),
        "--agent-name",
        config.agent_name,
        "--side-effect-path",
        str(side_effect_path),
    ]
    if config.replay_store_backend != "agent_config":
        command.extend(["--replay-store-backend", config.replay_store_backend])
    if config.replay_store_sqlite_path is not None:
        command.extend(["--replay-store-sqlite-path", str(config.replay_store_sqlite_path)])
    if config.replay_store_redis_url is not None:
        command.extend(["--replay-store-redis-url", config.replay_store_redis_url])
    if config.replay_store_backend == "redis":
        command.extend(["--replay-store-key-prefix", config.replay_store_key_prefix])
    if config.replay_store_ttl_seconds is not None:
        command.extend(["--replay-store-ttl-seconds", str(config.replay_store_ttl_seconds)])
    if wrong_trusted_sender_aid is not None:
        command.extend(
            [
                "--wrong-trusted-sender-aid",
                wrong_trusted_sender_aid,
            ]
        )
    if scope_probe is not None:
        command.extend(
            [
                "--scope-probe",
                scope_probe,
            ]
        )
    return command


def _query_command(
    config: RealNegativeRunConfig,
    *,
    scenario: str,
    scenario_dir: Path,
    side_effect_path: Path,
) -> list[str]:
    """构造真实 negative query 子进程命令。"""
    return [
        config.python_executable,
        str(Path(__file__).resolve()),
        "query",
        "--scenario",
        scenario,
        "--initiator-config",
        str(config.initiator_config),
        "--receiver-config",
        str(config.receiver_config),
        "--agent-name",
        config.agent_name,
        "--run-dir",
        str(scenario_dir),
        "--side-effect-path",
        str(side_effect_path),
        "--audit-timeout",
        str(config.audit_timeout_seconds),
    ]


def _load_result(path: str | Path) -> RealNegativeResult:
    """从 query 子进程写出的 JSON 结果恢复 dataclass。"""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return RealNegativeResult(
        scenario=str(payload["scenario"]),
        passed=bool(payload["passed"]),
        expected_reason=str(payload["expected_reason"]),
        observed_reason=str(payload["observed_reason"]),
        side_effect_triggered=bool(payload["side_effect_triggered"]),
        local_agent_run_count=int(payload["local_agent_run_count"]),
        details=payload.get("details") if isinstance(payload.get("details"), Mapping) else None,
    )


def _selected_scenarios(values: Iterable[str] | None) -> tuple[str, ...]:
    """规范化 CLI 场景列表，保持顺序且去重。"""
    requested = tuple(values or ("all",))
    if "all" in requested:
        return DEFAULT_SCENARIOS
    seen: set[str] = set()
    selected: list[str] = []
    for value in requested:
        if value not in seen:
            seen.add(value)
            selected.append(value)
    return tuple(selected)


def _add_common_run_args(parser: argparse.ArgumentParser) -> None:
    """给 run 子命令添加本地服务与场景参数。"""
    parser.add_argument(
        "--scenario",
        action="append",
        choices=[*DEFAULT_SCENARIOS, "all"],
        help="Scenario to run. Repeat for multiple scenarios, or use all.",
    )
    parser.add_argument("--initiator-config", default=str(DEFAULT_INITIATOR_CONFIG))
    parser.add_argument("--receiver-config", default=str(DEFAULT_RECEIVER_CONFIG))
    parser.add_argument("--agent-name", default=DEFAULT_AGENT_NAME)
    parser.add_argument("--run-dir")
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--mongo-binary")
    parser.add_argument("--mongo-dbpath", default=str(batch_run.DEFAULT_MONGO_DBPATH))
    parser.add_argument("--provider-db-uri", default=batch_run.DEFAULT_PROVIDER_DB_URI)
    parser.add_argument("--ca-static-dir", default=str(batch_run.DEFAULT_CA_STATIC_DIR))
    parser.add_argument("--startup-timeout", type=float, default=45.0)
    parser.add_argument("--listener-startup-timeout", type=float, default=30.0)
    parser.add_argument("--query-timeout", type=float, default=120.0)
    parser.add_argument("--audit-timeout", type=float, default=10.0)
    parser.add_argument(
        "--skip-db-preflight",
        action="store_true",
        help="Skip Provider DB sync checks in the post-start trust-chain preflight.",
    )
    _add_replay_store_args(parser)


def _add_replay_store_args(parser: argparse.ArgumentParser) -> None:
    """给真实负向 runner 添加显式 replay store 注入参数。"""
    parser.add_argument(
        "--replay-store-backend",
        choices=REPLAY_STORE_BACKENDS,
        default="agent_config",
        help="Replay store source for receiver listeners.",
    )
    parser.add_argument(
        "--replay-store-sqlite-path",
        help="SQLite database path for --replay-store-backend sqlite.",
    )
    parser.add_argument(
        "--replay-store-redis-url",
        help="Redis URL for --replay-store-backend redis; requires redis-py.",
    )
    parser.add_argument(
        "--replay-store-key-prefix",
        default="saga:pqcan:replay:",
        help="Redis key prefix for replay markers.",
    )
    parser.add_argument(
        "--replay-store-ttl-seconds",
        type=int,
        help="Optional Redis replay marker TTL in seconds.",
    )


def _config_from_run_args(args: argparse.Namespace) -> RealNegativeRunConfig:
    """从 run 子命令参数构造 runner 配置。"""
    scenarios = _selected_scenarios(args.scenario)
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = (
        batch_run._resolve_repo_path(args.run_dir)
        if args.run_dir
        else DEFAULT_RUNS_DIR / f"{timestamp}-real-negative-{'-'.join(scenarios)}"
    )
    mongo_binary = (
        Path(args.mongo_binary).expanduser()
        if args.mongo_binary
        else batch_run._find_repo_mongod(REPO_ROOT)
    )
    replay_store_backend = args.replay_store_backend
    replay_store_sqlite_path = _sqlite_replay_path_from_args(
        replay_store_backend,
        args.replay_store_sqlite_path,
        run_dir=run_dir,
    )
    replay_store_redis_url = _redis_url_from_args(
        replay_store_backend,
        args.replay_store_redis_url,
    )
    if args.replay_store_ttl_seconds is not None and args.replay_store_ttl_seconds <= 0:
        raise ValueError("replay store ttl must be positive")
    return RealNegativeRunConfig(
        repo_root=REPO_ROOT,
        python_executable=args.python_executable,
        scenarios=scenarios,
        initiator_config=batch_run._resolve_repo_path(args.initiator_config),
        receiver_config=batch_run._resolve_repo_path(args.receiver_config),
        agent_name=args.agent_name,
        run_dir=run_dir,
        ca_static_dir=batch_run._resolve_repo_path(args.ca_static_dir),
        mongo_dbpath=batch_run._resolve_repo_path(args.mongo_dbpath),
        mongo_binary=mongo_binary,
        provider_db_uri=args.provider_db_uri,
        startup_timeout_seconds=args.startup_timeout,
        listener_startup_timeout_seconds=args.listener_startup_timeout,
        query_timeout_seconds=args.query_timeout,
        audit_timeout_seconds=args.audit_timeout,
        skip_db_preflight=args.skip_db_preflight,
        replay_store_backend=replay_store_backend,
        replay_store_sqlite_path=replay_store_sqlite_path,
        replay_store_redis_url=replay_store_redis_url,
        replay_store_key_prefix=args.replay_store_key_prefix,
        replay_store_ttl_seconds=args.replay_store_ttl_seconds,
    )


def _sqlite_replay_path_from_args(
    replay_store_backend: str,
    sqlite_path: str | None,
    *,
    run_dir: Path,
) -> Path | None:
    """根据 run 参数解析 SQLite replay DB 路径；run 模式默认写入 run 目录。"""
    if replay_store_backend != "sqlite":
        if sqlite_path is not None:
            raise ValueError("sqlite replay path is only valid for sqlite replay backend")
        return None
    if sqlite_path is None:
        return run_dir / "replay_state.sqlite3"
    return batch_run._resolve_repo_path(sqlite_path)


def _redis_url_from_args(replay_store_backend: str, redis_url: str | None) -> str | None:
    """校验 Redis replay backend URL，避免配置面含混。"""
    if replay_store_backend != "redis":
        if redis_url is not None:
            raise ValueError("redis replay URL is only valid for redis replay backend")
        return None
    if not redis_url:
        raise ValueError("redis replay backend requires --replay-store-redis-url")
    return redis_url


def _build_replay_state_store(
    replay_store_backend: str,
    *,
    sqlite_path: str | Path | None,
    redis_url: str | None,
    key_prefix: str,
    ttl_seconds: int | None,
) -> ReplayStateStore | None:
    """按 runner 显式参数构造 replay store；默认继续使用 agent 配置。"""
    if replay_store_backend == "agent_config":
        return None
    if replay_store_backend == "sqlite":
        if sqlite_path is None:
            raise ValueError("sqlite replay backend requires a database path")
        return SQLiteReplayStateStore(sqlite_path)
    if replay_store_backend == "redis":
        if redis_url is None:
            raise ValueError("redis replay backend requires a Redis URL")
        return RedisReplayStateStore(
            _redis_client_from_url(redis_url),
            key_prefix=key_prefix,
            ttl_seconds=ttl_seconds,
        )
    raise ValueError(f"unsupported replay store backend: {replay_store_backend}")


def _redis_client_from_url(redis_url: str) -> object:
    """动态加载 redis-py client；未安装时保持 opt-in runner fail-fast。"""
    try:
        import redis  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("redis replay backend requires the optional redis package") from exc
    return redis.from_url(redis_url)


def _runtime_auth_config_for_injected_replay_store(
    runtime_auth_config: ToyRuntimeAuthConfig | None,
) -> ToyRuntimeAuthConfig | None:
    """显式 runner backend 注入时，将 runtime auth 配置规范化为强一致 backend。"""
    if runtime_auth_config is None:
        return None
    return replace(
        runtime_auth_config,
        replay_store=ReplayStoreConfig(backend="external_strong_consistency"),
        replay_state_dir=None,
    )


def _batch_config_from_real_config(config: RealNegativeRunConfig) -> batch_run.BatchRunConfig:
    """转换为 batch runner 配置以复用本地服务启动和 preflight 逻辑。"""
    task = batch_run.TaskSpec(
        name="real_negative",
        script=Path(__file__).resolve(),
        receiver_agent_name=config.agent_name,
    )
    return batch_run.BatchRunConfig(
        repo_root=config.repo_root,
        python_executable=config.python_executable,
        tasks=(task,),
        initiator_config=config.initiator_config,
        receiver_config=config.receiver_config,
        seed_user_config_dir=batch_run.DEFAULT_USER_CONFIG_DIR,
        ca_static_dir=config.ca_static_dir,
        run_dir=config.run_dir,
        mongo_dbpath=config.mongo_dbpath,
        mongo_binary=config.mongo_binary,
        provider_db_uri=config.provider_db_uri,
        probe_required_successes=1,
        probe_max_attempts=0,
        probe_interval_seconds=0.0,
        model_probe_timeout_seconds=0.0,
        startup_timeout_seconds=config.startup_timeout_seconds,
        listener_startup_timeout_seconds=config.listener_startup_timeout_seconds,
        query_timeout_seconds=config.query_timeout_seconds,
        skip_model_probe=True,
        skip_db_preflight=config.skip_db_preflight,
        skip_seed=True,
        allow_task_failure=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
