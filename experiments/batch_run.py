"""Single-entry batch runner for local SAGA experiment reruns."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import IO
from urllib.parse import urlparse

import yaml

try:  # pragma: no cover - exercised by script-style execution
    from experiments import preflight
    from experiments.seed_tool_data import main as seed_tool_data
except ImportError:  # pragma: no cover - supports `python experiments/batch_run.py`
    import preflight  # type: ignore
    from seed_tool_data import main as seed_tool_data  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_DIR = REPO_ROOT / "experiments" / "runs"
DEFAULT_MONGO_DBPATH = REPO_ROOT / ".mongodata"
DEFAULT_CA_STATIC_DIR = REPO_ROOT / ".ca_static"
DEFAULT_USER_CONFIG_DIR = REPO_ROOT / "user_configs"
DEFAULT_INITIATOR_CONFIG = REPO_ROOT / "user_configs" / "emma.yaml"
DEFAULT_RECEIVER_CONFIG = REPO_ROOT / "user_configs" / "raj.yaml"
DEFAULT_PROVIDER_DB_URI = "mongodb://localhost:27017/saga"


@dataclass(frozen=True)
class TaskSpec:
    """Static metadata needed to run one experiment entrypoint."""

    name: str
    script: Path
    receiver_agent_name: str


TASK_SPECS: dict[str, TaskSpec] = {
    "schedule_meeting": TaskSpec(
        name="schedule_meeting",
        script=REPO_ROOT / "experiments" / "schedule_meeting.py",
        receiver_agent_name="calendar_agent",
    ),
    "expense_report": TaskSpec(
        name="expense_report",
        script=REPO_ROOT / "experiments" / "expense_report.py",
        receiver_agent_name="email_agent",
    ),
    "create_blogpost": TaskSpec(
        name="create_blogpost",
        script=REPO_ROOT / "experiments" / "create_blogpost.py",
        receiver_agent_name="writing_agent",
    ),
}


@dataclass(frozen=True)
class BatchRunConfig:
    """Resolved configuration for one local batch run."""

    repo_root: Path
    python_executable: str
    tasks: tuple[TaskSpec, ...]
    initiator_config: Path
    receiver_config: Path
    seed_user_config_dir: Path
    ca_static_dir: Path
    run_dir: Path
    mongo_dbpath: Path
    mongo_binary: Path | None
    provider_db_uri: str
    probe_required_successes: int
    probe_max_attempts: int
    probe_interval_seconds: float
    model_probe_timeout_seconds: float
    startup_timeout_seconds: float
    listener_startup_timeout_seconds: float
    query_timeout_seconds: float
    skip_model_probe: bool
    skip_db_preflight: bool
    skip_seed: bool
    allow_task_failure: bool


@dataclass(frozen=True)
class ServicePorts:
    """Local service ports parsed from config.yaml."""

    ca_host: str
    ca_port: int
    provider_host: str
    provider_port: int


@dataclass
class _ManagedProcess:
    name: str
    process: subprocess.Popen
    log_path: Path
    log_handle: IO[bytes]
    interrupt_first: bool = False


def _resolve_repo_path(path: str | Path, *, repo_root: Path = REPO_ROOT) -> Path:
    raw_path = Path(path).expanduser()
    if raw_path.is_absolute():
        return raw_path
    return (repo_root / raw_path).resolve()


def _parse_host_port(endpoint: str, *, default_port: int) -> tuple[str, int]:
    parsed = urlparse(endpoint)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or default_port
    return host, port


def _load_service_ports(repo_root: Path) -> ServicePorts:
    config_path = repo_root / "config.yaml"
    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    ca_host, ca_port = _parse_host_port(config["ca"]["endpoint"], default_port=80)
    provider_host, provider_port = _parse_host_port(
        config["provider"]["endpoint"],
        default_port=443,
    )
    return ServicePorts(
        ca_host=ca_host,
        ca_port=ca_port,
        provider_host=provider_host,
        provider_port=provider_port,
    )


def _selected_tasks(task_names: list[str] | None) -> tuple[TaskSpec, ...]:
    names = task_names or ["schedule_meeting"]
    if "all" in names:
        return tuple(TASK_SPECS[name] for name in TASK_SPECS)

    seen: set[str] = set()
    tasks: list[TaskSpec] = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        tasks.append(TASK_SPECS[name])
    return tuple(tasks)


def _find_repo_mongod(repo_root: Path) -> Path | None:
    env_mongod = os.getenv("MONGOD")
    if env_mongod:
        return Path(env_mongod).expanduser()

    system_mongod = shutil.which("mongod")
    if system_mongod:
        return Path(system_mongod)

    candidates = sorted((repo_root / ".mongodb").glob("**/bin/mongod"))
    return candidates[0] if candidates else None


def _mongo_command(config: BatchRunConfig) -> list[str]:
    if config.mongo_binary is None:
        raise RuntimeError(
            "mongod binary not found. Set MONGOD or place a MongoDB build under .mongodb/."
        )
    return [
        str(config.mongo_binary),
        "--dbpath",
        str(config.mongo_dbpath),
        "--bind_ip",
        "127.0.0.1",
        "--port",
        "27017",
        "--quiet",
    ]


def _ca_command(config: BatchRunConfig, ports: ServicePorts) -> list[str]:
    return [
        config.python_executable,
        "-m",
        "http.server",
        str(ports.ca_port),
        "--bind",
        ports.ca_host,
    ]


def _provider_command(config: BatchRunConfig) -> list[str]:
    return [config.python_executable, "provider.py"]


def _task_command(
    config: BatchRunConfig,
    task: TaskSpec,
    mode: str,
) -> list[str]:
    command = [
        config.python_executable,
        str(task.script),
        mode,
        str(config.receiver_config if mode == "listen" else config.initiator_config),
    ]
    if mode == "query":
        command.append(str(config.receiver_config))
    return command


def _port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _wait_for_port(
    *,
    name: str,
    host: str,
    port: int,
    timeout_seconds: float,
    process: subprocess.Popen | None = None,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{name} exited before opening {host}:{port}")
        if _port_is_open(host, port):
            return
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for {name} on {host}:{port}")


def _start_process(
    *,
    name: str,
    command: list[str],
    cwd: Path,
    run_dir: Path,
    interrupt_first: bool = False,
) -> _ManagedProcess:
    log_path = run_dir / f"{name}.log"
    log_handle = log_path.open("ab")
    log_handle.write(f"$ {shlex.join(command)}\n".encode("utf-8"))
    log_handle.flush()
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    print(f"[batch] started {name} pid={process.pid} log={log_path}")
    return _ManagedProcess(
        name=name,
        process=process,
        log_path=log_path,
        log_handle=log_handle,
        interrupt_first=interrupt_first,
    )


def _signal_process_group(process: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return


def _stop_process(managed: _ManagedProcess, *, timeout_seconds: float = 10.0) -> None:
    process = managed.process
    try:
        if process.poll() is None:
            first_signal = signal.SIGINT if managed.interrupt_first else signal.SIGTERM
            _signal_process_group(process, first_signal)
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                _signal_process_group(process, signal.SIGKILL)
                process.wait(timeout=timeout_seconds)
    finally:
        managed.log_handle.close()
        print(f"[batch] stopped {managed.name} log={managed.log_path}")


def _run_blocking(
    *,
    name: str,
    command: list[str],
    cwd: Path,
    run_dir: Path,
    timeout_seconds: float,
) -> None:
    log_path = run_dir / f"{name}.log"
    with log_path.open("ab") as log_handle:
        log_handle.write(f"$ {shlex.join(command)}\n".encode("utf-8"))
        log_handle.flush()
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        print(f"[batch] running {name} pid={process.pid} log={log_path}")
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _signal_process_group(process, signal.SIGKILL)
            process.wait()
            raise TimeoutError(f"{name} timed out after {timeout_seconds} seconds") from exc

    if returncode != 0:
        tail = _tail_text(log_path)
        raise RuntimeError(f"{name} failed with exit code {returncode}\n{tail}")


def _tail_text(path: Path, *, lines: int = 40) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def _results_path(config: BatchRunConfig, task: TaskSpec) -> Path:
    return config.repo_root / "experiments" / "results" / f"{task.name}.jsonl"


def _query_records(results_path: Path) -> list[dict]:
    if not results_path.exists():
        return []

    records: list[dict] = []
    with results_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("mode") == "query":
                records.append(record)
    return records


def _assert_new_query_succeeded(
    config: BatchRunConfig,
    task: TaskSpec,
    *,
    previous_query_count: int,
) -> None:
    if config.allow_task_failure:
        return

    results_path = _results_path(config, task)
    new_records = _query_records(results_path)[previous_query_count:]
    if not new_records:
        raise RuntimeError(f"{task.name} did not write a new query result to {results_path}")
    record = new_records[-1]
    if record.get("success") is not True:
        raise RuntimeError(
            f"{task.name} query did not succeed; latest result success={record.get('success')}"
        )


def _latest_new_query_record(
    config: BatchRunConfig,
    task: TaskSpec,
    *,
    previous_query_count: int,
) -> dict | None:
    """Return the latest query result written by the current task run."""
    new_records = _query_records(_results_path(config, task))[previous_query_count:]
    if not new_records:
        return None
    return new_records[-1]


def _write_end_to_end_stats_summary(
    config: BatchRunConfig,
    records: list[dict],
) -> Path:
    """Write a run-level end-to-end stats summary for real task batches."""
    task_records = [record for record in records if record is not None]
    task_count = len(task_records)
    succeeded_count = sum(1 for record in task_records if record.get("success") is True)
    task_latency_total = sum(
        float(record.get("task_latency_seconds", 0.0) or 0.0)
        for record in task_records
    )
    model_call_count = sum(
        int(record.get("model_call_count", 0) or 0)
        for record in task_records
    )
    audit_record_count = sum(
        int(record.get("audit_record_count", 0) or 0)
        for record in task_records
    )
    logging_stats_collection_latency_total = sum(
        float(record.get("logging_stats_collection_latency_seconds", 0.0) or 0.0)
        for record in task_records
    )
    api_cost_values = [
        float(record["api_cost_usd"])
        for record in task_records
        if isinstance(record.get("api_cost_usd"), (int, float))
    ]
    token_values = [
        int(record["total_tokens"])
        for record in task_records
        if isinstance(record.get("total_tokens"), int)
    ]
    summary = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(config.run_dir),
        "task_count": task_count,
        "succeeded_count": succeeded_count,
        "failed_count": task_count - succeeded_count,
        "task_latency_seconds_total": task_latency_total,
        "task_latency_seconds_mean": task_latency_total / task_count if task_count else 0.0,
        "model_call_count": model_call_count,
        "audit_record_count": audit_record_count,
        "audit_logging_overhead_record_count": audit_record_count,
        "logging_stats_collection_latency_seconds_total": (
            logging_stats_collection_latency_total
        ),
        "api_cost_available": len(api_cost_values) == task_count and task_count > 0,
        "api_cost_usd_total": sum(api_cost_values) if api_cost_values else None,
        "token_usage_available": len(token_values) == task_count and task_count > 0,
        "total_tokens": sum(token_values) if token_values else None,
        "tasks": task_records,
    }
    summary_path = config.run_dir / "end_to_end_stats_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary_path


def _receiver_endpoint(receiver_config: Path, task: TaskSpec) -> tuple[str, int]:
    with receiver_config.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    for agent in config.get("agents", []):
        if agent.get("name") == task.receiver_agent_name:
            endpoint = agent["endpoint"]
            return endpoint["ip"], int(endpoint["port"])

    raise ValueError(f"{receiver_config} does not define {task.receiver_agent_name}")


def _results_to_json(results: list[preflight.CheckResult]) -> str:
    payload = {
        "ok": all(result.ok for result in results),
        "results": [
            {
                "name": result.name,
                "ok": result.ok,
                "summary": result.summary,
                "details": list(result.details),
            }
            for result in results
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _write_preflight_results(path: Path, results: list[preflight.CheckResult]) -> None:
    path.write_text(_results_to_json(results) + "\n", encoding="utf-8")


def _run_preflight_once(
    config: BatchRunConfig,
    *,
    check_db_sync: bool,
    check_model_backends: bool,
) -> list[preflight.CheckResult]:
    return preflight.run_preflight_checks(
        config_paths=[config.initiator_config, config.receiver_config],
        ca_static_dir=config.ca_static_dir,
        ca_workdir=config.repo_root / "saga" / "ca",
        provider_cert_path=config.repo_root / "saga" / "provider" / "provider.crt",
        mongo_uri=config.provider_db_uri,
        check_db_sync=check_db_sync,
        check_model_backends=check_model_backends,
        model_probe_timeout_seconds=config.model_probe_timeout_seconds,
    )


def _require_preflight_ok(
    config: BatchRunConfig,
    *,
    label: str,
    check_db_sync: bool,
    check_model_backends: bool,
) -> None:
    results = _run_preflight_once(
        config,
        check_db_sync=check_db_sync,
        check_model_backends=check_model_backends,
    )
    result_path = config.run_dir / f"{label}.json"
    _write_preflight_results(result_path, results)
    if not all(result.ok for result in results):
        raise RuntimeError(f"{label} failed; details written to {result_path}")
    print(f"[batch] {label} passed")


def _wait_for_stable_model_backend(config: BatchRunConfig) -> None:
    if config.skip_model_probe:
        print("[batch] skipping model probe by request")
        return

    consecutive_successes = 0
    attempt = 0
    while True:
        attempt += 1
        results = _run_preflight_once(
            config,
            check_db_sync=False,
            check_model_backends=True,
        )
        result_path = config.run_dir / f"model_probe_{attempt:03d}.json"
        _write_preflight_results(result_path, results)
        non_model_failures = [
            result
            for result in results
            if not result.ok and not result.name.startswith("model_probe:")
        ]
        if non_model_failures:
            raise RuntimeError(
                "non-model preflight checks failed before model probing; "
                f"details written to {result_path}"
            )

        ok = all(result.ok for result in results)
        if ok:
            consecutive_successes += 1
            print(
                "[batch] model probe passed "
                f"({consecutive_successes}/{config.probe_required_successes})"
            )
            if consecutive_successes >= config.probe_required_successes:
                return
        else:
            consecutive_successes = 0
            print(f"[batch] model probe failed; details written to {result_path}")

        if config.probe_max_attempts > 0 and attempt >= config.probe_max_attempts:
            raise RuntimeError(
                "model probe did not reach stability "
                f"after {config.probe_max_attempts} attempts"
            )
        time.sleep(config.probe_interval_seconds)


def _seed_tools(config: BatchRunConfig) -> None:
    if config.skip_seed:
        print("[batch] skipping seed step by request")
        return

    log_path = config.run_dir / "seed_tool_data.log"
    with log_path.open("w", encoding="utf-8") as log_handle, redirect_stdout(log_handle):
        seed_tool_data(str(config.seed_user_config_dir))
    print(f"[batch] seeded tool data log={log_path}")


def _start_local_services(config: BatchRunConfig, ports: ServicePorts) -> list[_ManagedProcess]:
    managed: list[_ManagedProcess] = []

    if _port_is_open("127.0.0.1", 27017):
        print("[batch] MongoDB port 27017 is already open; using existing service")
    else:
        config.mongo_dbpath.mkdir(parents=True, exist_ok=True)
        mongo = _start_process(
            name="mongod",
            command=_mongo_command(config),
            cwd=config.repo_root,
            run_dir=config.run_dir,
        )
        managed.append(mongo)
        _wait_for_port(
            name="MongoDB",
            host="127.0.0.1",
            port=27017,
            timeout_seconds=config.startup_timeout_seconds,
            process=mongo.process,
        )

    if _port_is_open(ports.ca_host, ports.ca_port):
        print(f"[batch] CA file server port {ports.ca_port} is already open; using existing service")
    else:
        ca_server = _start_process(
            name="ca_http",
            command=_ca_command(config, ports),
            cwd=config.ca_static_dir,
            run_dir=config.run_dir,
        )
        managed.append(ca_server)
        _wait_for_port(
            name="CA file server",
            host=ports.ca_host,
            port=ports.ca_port,
            timeout_seconds=config.startup_timeout_seconds,
            process=ca_server.process,
        )

    if _port_is_open(ports.provider_host, ports.provider_port):
        print(
            f"[batch] Provider port {ports.provider_port} is already open; using existing service"
        )
    else:
        provider = _start_process(
            name="provider",
            command=_provider_command(config),
            cwd=config.repo_root / "saga" / "provider",
            run_dir=config.run_dir,
        )
        managed.append(provider)
        _wait_for_port(
            name="Provider",
            host=ports.provider_host,
            port=ports.provider_port,
            timeout_seconds=config.startup_timeout_seconds,
            process=provider.process,
        )

    return managed


def _run_task(config: BatchRunConfig, task: TaskSpec) -> dict | None:
    host, port = _receiver_endpoint(config.receiver_config, task)
    if _port_is_open(host, port):
        raise RuntimeError(
            f"{task.name} receiver port {host}:{port} is already in use before listener start"
        )

    listener = _start_process(
        name=f"{task.name}_listen",
        command=_task_command(config, task, "listen"),
        cwd=config.repo_root,
        run_dir=config.run_dir,
        interrupt_first=True,
    )
    try:
        _wait_for_port(
            name=f"{task.name} listener",
            host=host,
            port=port,
            timeout_seconds=config.listener_startup_timeout_seconds,
            process=listener.process,
        )
        previous_query_count = len(_query_records(_results_path(config, task)))
        _run_blocking(
            name=f"{task.name}_query",
            command=_task_command(config, task, "query"),
            cwd=config.repo_root,
            run_dir=config.run_dir,
            timeout_seconds=config.query_timeout_seconds,
        )
        _assert_new_query_succeeded(
            config,
            task,
            previous_query_count=previous_query_count,
        )
        latest_record = _latest_new_query_record(
            config,
            task,
            previous_query_count=previous_query_count,
        )
        print(f"[batch] task {task.name} completed")
        return latest_record
    finally:
        _stop_process(listener)


def run_batch(config: BatchRunConfig) -> None:
    """Run model probes, local services, seed data, and selected experiments."""
    config.run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tasks": [task.name for task in config.tasks],
        "initiator_config": str(config.initiator_config),
        "receiver_config": str(config.receiver_config),
        "run_dir": str(config.run_dir),
    }
    (config.run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    managed: list[_ManagedProcess] = []
    ports = _load_service_ports(config.repo_root)
    try:
        _wait_for_stable_model_backend(config)
        managed.extend(_start_local_services(config, ports))
        _require_preflight_ok(
            config,
            label="trust_chain_preflight",
            check_db_sync=not config.skip_db_preflight,
            check_model_backends=False,
        )
        _seed_tools(config)
        end_to_end_records: list[dict] = []
        for task in config.tasks:
            task_record = _run_task(config, task)
            if task_record is not None:
                end_to_end_records.append(task_record)
        summary_path = _write_end_to_end_stats_summary(config, end_to_end_records)
        print(f"[batch] end-to-end stats summary: {summary_path}")
    finally:
        for process in reversed(managed):
            _stop_process(process)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the batch runner."""
    parser = argparse.ArgumentParser(
        description=(
            "Probe model readiness until stable, then start local SAGA services, "
            "seed tools, and run experiment listen/query pairs."
        )
    )
    parser.add_argument(
        "--task",
        action="append",
        choices=[*TASK_SPECS.keys(), "all"],
        help="Experiment task to run. Repeat for multiple tasks, or use 'all'.",
    )
    parser.add_argument(
        "--initiator-config",
        default=str(DEFAULT_INITIATOR_CONFIG),
        help="Initiating user config YAML.",
    )
    parser.add_argument(
        "--receiver-config",
        default=str(DEFAULT_RECEIVER_CONFIG),
        help="Receiving user config YAML.",
    )
    parser.add_argument(
        "--seed-user-config-dir",
        default=str(DEFAULT_USER_CONFIG_DIR),
        help="Directory of user configs consumed by seed_tool_data.",
    )
    parser.add_argument(
        "--ca-static-dir",
        default=str(DEFAULT_CA_STATIC_DIR),
        help="Directory served by the local CA static file server.",
    )
    parser.add_argument(
        "--run-dir",
        help="Directory for logs and probe/preflight JSON. Defaults to experiments/runs/<timestamp>.",
    )
    parser.add_argument(
        "--python",
        dest="python_executable",
        default=sys.executable,
        help="Python executable used for subprocess entrypoints.",
    )
    parser.add_argument(
        "--mongo-binary",
        help="Path to mongod. Defaults to MONGOD, PATH, then repo-local .mongodb.",
    )
    parser.add_argument(
        "--mongo-dbpath",
        default=str(DEFAULT_MONGO_DBPATH),
        help="MongoDB dbpath used when the runner starts mongod.",
    )
    parser.add_argument(
        "--provider-db-uri",
        default=DEFAULT_PROVIDER_DB_URI,
        help="Provider Mongo URI used by the trust-chain preflight.",
    )
    parser.add_argument(
        "--probe-required-successes",
        type=int,
        default=2,
        help="Consecutive successful model probes required before services start.",
    )
    parser.add_argument(
        "--probe-max-attempts",
        type=int,
        default=0,
        help="Maximum model probe attempts. Use 0 to wait indefinitely.",
    )
    parser.add_argument(
        "--probe-interval",
        type=float,
        default=30.0,
        help="Seconds to wait between model probe attempts.",
    )
    parser.add_argument(
        "--model-probe-timeout",
        type=float,
        default=20.0,
        help="Per-endpoint timeout for each model probe request.",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=45.0,
        help="Seconds to wait for MongoDB, CA, and Provider ports.",
    )
    parser.add_argument(
        "--listener-startup-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for each receiver listener port.",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=1800.0,
        help="Seconds to allow each query-side experiment process.",
    )
    parser.add_argument(
        "--skip-model-probe",
        action="store_true",
        help="Skip model readiness probes. Intended only for local debugging.",
    )
    parser.add_argument(
        "--skip-db-preflight",
        action="store_true",
        help="Skip Provider DB sync checks in the post-start trust-chain preflight.",
    )
    parser.add_argument(
        "--skip-seed",
        action="store_true",
        help="Do not refresh tool seed data before running tasks.",
    )
    parser.add_argument(
        "--allow-task-failure",
        action="store_true",
        help="Return success even when the latest query result has success=false.",
    )
    return parser.parse_args(argv)


def _config_from_args(args: argparse.Namespace) -> BatchRunConfig:
    if args.probe_required_successes <= 0:
        raise ValueError("--probe-required-successes must be positive")
    if args.probe_max_attempts < 0:
        raise ValueError("--probe-max-attempts must be non-negative")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = (
        _resolve_repo_path(args.run_dir)
        if args.run_dir
        else DEFAULT_RUNS_DIR / f"{timestamp}-{'-'.join(task.name for task in _selected_tasks(args.task))}"
    )
    mongo_binary = Path(args.mongo_binary).expanduser() if args.mongo_binary else _find_repo_mongod(REPO_ROOT)

    return BatchRunConfig(
        repo_root=REPO_ROOT,
        python_executable=args.python_executable,
        tasks=_selected_tasks(args.task),
        initiator_config=_resolve_repo_path(args.initiator_config),
        receiver_config=_resolve_repo_path(args.receiver_config),
        seed_user_config_dir=_resolve_repo_path(args.seed_user_config_dir),
        ca_static_dir=_resolve_repo_path(args.ca_static_dir),
        run_dir=run_dir,
        mongo_dbpath=_resolve_repo_path(args.mongo_dbpath),
        mongo_binary=mongo_binary,
        provider_db_uri=args.provider_db_uri,
        probe_required_successes=args.probe_required_successes,
        probe_max_attempts=args.probe_max_attempts,
        probe_interval_seconds=args.probe_interval,
        model_probe_timeout_seconds=args.model_probe_timeout,
        startup_timeout_seconds=args.startup_timeout,
        listener_startup_timeout_seconds=args.listener_startup_timeout,
        query_timeout_seconds=args.query_timeout,
        skip_model_probe=args.skip_model_probe,
        skip_db_preflight=args.skip_db_preflight,
        skip_seed=args.skip_seed,
        allow_task_failure=args.allow_task_failure,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the batch runner CLI."""
    args = parse_args(argv)
    config = _config_from_args(args)
    print(f"[batch] run directory: {config.run_dir}")
    run_batch(config)
    print("[batch] completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
