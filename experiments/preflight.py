"""Read-only preflight checks for real experiment trust-chain consistency."""

from __future__ import annotations

import argparse
import base64
from collections.abc import Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection

from agent_backend.config import api_base_requires_openai_api_key
import saga.common.crypto as sc
from saga.config import PROVIDER_WORKDIR, ROOT_DIR, USER_WORKDIR, UserConfig


DEFAULT_CA_STATIC_DIR = Path(ROOT_DIR).parent / ".ca_static"
DEFAULT_CA_WORKDIR = Path(ROOT_DIR) / "ca"
DEFAULT_PROVIDER_CERT_PATH = Path(PROVIDER_WORKDIR) / "provider.crt"
DEFAULT_PROVIDER_DB_URI = "mongodb://localhost:27017/saga"
DEFAULT_MODEL_PROBE_PROMPT = "Reply with exactly: ok"


@dataclass(frozen=True)
class CheckResult:
    """One structured preflight check result."""

    name: str
    ok: bool
    summary: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class ManagedIdentity:
    """One user or agent identity that should match the current CA and DB."""

    config_path: Path
    email: str
    agent_name: str | None = None

    @property
    def aid(self) -> str | None:
        """Return the full agent AID when this identity is agent-scoped."""
        if self.agent_name is None:
            return None
        return f"{self.email}:{self.agent_name}"


@dataclass(frozen=True)
class ModelEndpoint:
    """One unique model backend endpoint referenced by experiment configs."""

    model_type: str
    model: str
    api_base: str | None

    @property
    def label(self) -> str:
        """Return a stable human-readable endpoint label."""
        return f"{self.model_type}:{self.model}@{self.api_base or '<default>'}"


def _load_cert(path: Path):
    """Load one PEM X.509 certificate from disk."""
    return sc.load_x509_certificate(str(path))


def _load_cert_bytes(cert_bytes: bytes):
    """Load one PEM X.509 certificate from raw bytes."""
    return sc.bytesToX509Certificate(cert_bytes)


def _cert_bytes(path: Path) -> bytes:
    """Read raw certificate bytes from disk."""
    return path.read_bytes()


def _cert_public_key_b64(path: Path) -> str:
    """Return a stable base64-encoded public key fingerprint input."""
    cert = _load_cert(path)
    return base64.b64encode(
        cert.public_key().public_bytes(
            encoding=sc.serialization.Encoding.Raw,
            format=sc.serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _check_cert_signed_by_ca(name: str, cert_path: Path, ca_cert_path: Path) -> CheckResult:
    """Verify that one certificate is signed by the current CA."""
    try:
        cert = _load_cert(cert_path)
    except FileNotFoundError:
        return CheckResult(name, False, f"missing certificate: {cert_path}")

    try:
        ca_cert = _load_cert(ca_cert_path)
    except FileNotFoundError:
        return CheckResult(name, False, f"missing CA certificate: {ca_cert_path}")

    try:
        sc.verify_x509_certificate(cert, ca_cert)
    except Exception as exc:  # pragma: no cover - cryptography error text is environment-specific
        return CheckResult(
            name,
            False,
            f"certificate is not signed by current CA: {cert_path}",
            (str(exc),),
        )

    return CheckResult(name, True, f"certificate matches current CA: {cert_path}")


def _check_cert_bytes_signed_by_ca(name: str, cert_bytes: bytes, ca_cert_path: Path, source_label: str) -> CheckResult:
    """Verify that one in-memory certificate is signed by the current CA."""
    try:
        cert = _load_cert_bytes(cert_bytes)
    except Exception as exc:  # pragma: no cover - parser error text is environment-specific
        return CheckResult(name, False, f"invalid certificate bytes from {source_label}", (str(exc),))

    try:
        ca_cert = _load_cert(ca_cert_path)
    except FileNotFoundError:
        return CheckResult(name, False, f"missing CA certificate: {ca_cert_path}")

    try:
        sc.verify_x509_certificate(cert, ca_cert)
    except Exception as exc:  # pragma: no cover - cryptography error text is environment-specific
        return CheckResult(
            name,
            False,
            f"certificate is not signed by current CA: {source_label}",
            (str(exc),),
        )

    return CheckResult(name, True, f"certificate matches current CA: {source_label}")


def _check_ca_static_layout(ca_static_dir: Path, ca_workdir: Path) -> list[CheckResult]:
    """Verify that CA service source and CA download target stay separate and aligned."""
    results: list[CheckResult] = []
    static_cert = ca_static_dir / "ca.crt"
    static_key = ca_static_dir / "ca.key"
    static_pub = ca_static_dir / "ca.pub"
    work_cert = ca_workdir / "ca.crt"

    if ca_static_dir.resolve() == ca_workdir.resolve():
        results.append(
            CheckResult(
                "ca_layout",
                False,
                "CA static service directory must not be the same as saga/ca",
            )
        )
        return results

    missing = [str(path) for path in (static_cert, static_key, static_pub, work_cert) if not path.exists()]
    if missing:
        results.append(
            CheckResult(
                "ca_files",
                False,
                "missing CA material required for preflight",
                tuple(missing),
            )
        )
        return results

    static_pubkey = _cert_public_key_b64(static_cert)
    work_pubkey = _cert_public_key_b64(work_cert)
    if static_pubkey != work_pubkey:
        results.append(
            CheckResult(
                "ca_sync",
                False,
                "CA static source and saga/ca target do not expose the same public key",
            )
        )
    else:
        results.append(
            CheckResult(
                "ca_sync",
                True,
                "CA static source and saga/ca target expose the same public key",
            )
        )

    return results


def _load_managed_identities(config_paths: Sequence[Path]) -> list[ManagedIdentity]:
    """Collect all users and agents referenced by one or more user configs."""
    identities: list[ManagedIdentity] = []
    for config_path in config_paths:
        config = UserConfig.load(str(config_path), drop_extra_fields=True)
        identities.append(ManagedIdentity(config_path=config_path, email=config.email))
        for agent in config.agents:
            identities.append(
                ManagedIdentity(
                    config_path=config_path,
                    email=config.email,
                    agent_name=agent.name,
                )
            )
    return identities


def _load_model_endpoints(config_paths: Sequence[Path]) -> list[ModelEndpoint]:
    """Collect unique model endpoints referenced by one or more user configs."""
    endpoints: dict[tuple[str, str, str | None], ModelEndpoint] = {}
    for config_path in config_paths:
        config = UserConfig.load(str(config_path), drop_extra_fields=True)
        for agent in config.agents:
            local_config = agent.local_agent_config
            endpoint = ModelEndpoint(
                model_type=local_config.model_type or "",
                model=local_config.model,
                api_base=local_config.api_base,
            )
            endpoints[(endpoint.model_type, endpoint.model, endpoint.api_base)] = endpoint
    return list(endpoints.values())


def _probe_openai_server_model(
    endpoint: ModelEndpoint,
    *,
    timeout_seconds: float,
) -> CheckResult:
    """Probe an OpenAI-compatible chat-completions endpoint with one tiny request."""
    if api_base_requires_openai_api_key(endpoint.api_base) and not os.getenv("OPENAI_API_KEY"):
        return CheckResult(
            f"model_probe:{endpoint.label}",
            False,
            "OPENAI_API_KEY is not set for OpenAI-compatible model probe",
        )

    try:
        from openai import OpenAI
    except ImportError as exc:
        return CheckResult(
            f"model_probe:{endpoint.label}",
            False,
            "openai package is required for OpenAIServerModel preflight probes",
            (str(exc),),
        )

    try:
        client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY", "") if api_base_requires_openai_api_key(endpoint.api_base) else "",
            base_url=endpoint.api_base,
            timeout=timeout_seconds,
            max_retries=0,
        )
        response = client.chat.completions.create(
            model=endpoint.model,
            messages=[{"role": "user", "content": DEFAULT_MODEL_PROBE_PROMPT}],
            max_tokens=4,
            temperature=0,
        )
    except Exception as exc:  # pragma: no cover - live API failures vary by provider
        return CheckResult(
            f"model_probe:{endpoint.label}",
            False,
            "model endpoint probe failed before running a full experiment",
            (f"{type(exc).__module__}.{type(exc).__name__}: {exc}",),
        )

    content = response.choices[0].message.content if response.choices else None
    if content is None:
        return CheckResult(
            f"model_probe:{endpoint.label}",
            False,
            "model endpoint returned no assistant content",
        )

    return CheckResult(
        f"model_probe:{endpoint.label}",
        True,
        "model endpoint returned a chat-completions response",
    )


def _check_model_backends(
    config_paths: Sequence[Path],
    *,
    timeout_seconds: float,
) -> list[CheckResult]:
    """Optionally verify model backend readiness before real experiments."""
    results: list[CheckResult] = []
    for endpoint in _load_model_endpoints(config_paths):
        if endpoint.model_type == "OpenAIServerModel":
            results.append(_probe_openai_server_model(endpoint, timeout_seconds=timeout_seconds))
        else:
            results.append(
                CheckResult(
                    f"model_probe:{endpoint.label}",
                    True,
                    "model type does not require a network preflight probe",
                )
            )
    return results


def _local_agent_cert_bytes(aid: str) -> tuple[bytes | None, str]:
    """Load one local agent certificate from agent.crt or embedded agent.json state."""
    agent_dir = Path(USER_WORKDIR) / aid
    cert_path = agent_dir / "agent.crt"
    if cert_path.exists():
        return cert_path.read_bytes(), str(cert_path)

    manifest_path = agent_dir / "agent.json"
    if not manifest_path.exists():
        return None, str(cert_path)

    try:
        material = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, str(manifest_path)

    agent_cert_b64 = material.get("agent_cert")
    if not isinstance(agent_cert_b64, str):
        return None, str(manifest_path)

    try:
        return base64.b64decode(agent_cert_b64), str(manifest_path)
    except Exception:
        return None, str(manifest_path)


def _check_local_identity_certs(
    identities: Sequence[ManagedIdentity],
    ca_cert_path: Path,
) -> list[CheckResult]:
    """Verify all local user and agent certs referenced by the provided configs."""
    results: list[CheckResult] = []
    for identity in identities:
        if identity.agent_name is None:
            user_cert_path = Path(USER_WORKDIR) / "keys" / f"{identity.email}.crt"
            results.append(
                _check_cert_signed_by_ca(
                    f"user_cert:{identity.email}",
                    user_cert_path,
                    ca_cert_path,
                )
            )
            continue

        local_agent_cert_bytes, source_label = _local_agent_cert_bytes(identity.aid)
        if local_agent_cert_bytes is None:
            results.append(
                CheckResult(
                    f"agent_cert:{identity.aid}",
                    False,
                    f"missing certificate: {source_label}",
                )
            )
        else:
            results.append(
                _check_cert_bytes_signed_by_ca(
                    f"agent_cert:{identity.aid}",
                    local_agent_cert_bytes,
                    ca_cert_path,
                    source_label,
                )
            )
    return results


def _connect_provider_db(mongo_uri: str) -> tuple[MongoClient, Any]:
    """Return a Mongo client plus the configured provider database handle."""
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
    client.admin.command("ping")
    database_name = mongo_uri.rsplit("/", 1)[-1] or "saga"
    return client, client.get_database(database_name)


def _check_db_sync(
    identities: Sequence[ManagedIdentity],
    users_collection: Collection,
    agents_collection: Collection,
) -> list[CheckResult]:
    """Compare local cert material against Provider DB registration state."""
    results: list[CheckResult] = []

    seen_users: set[str] = set()
    for identity in identities:
        if identity.email not in seen_users:
            seen_users.add(identity.email)
            user_cert_path = Path(USER_WORKDIR) / "keys" / f"{identity.email}.crt"
            local_user_cert = _cert_bytes(user_cert_path) if user_cert_path.exists() else None
            user_doc = users_collection.find_one({"uid": identity.email})
            if user_doc is None:
                results.append(
                    CheckResult(
                        f"db_user:{identity.email}",
                        False,
                        "Provider DB is missing expected user registration",
                    )
                )
            elif local_user_cert is None:
                results.append(
                    CheckResult(
                        f"db_user:{identity.email}",
                        False,
                        "local user certificate is missing",
                    )
                )
            elif user_doc.get("crt_u") != local_user_cert:
                results.append(
                    CheckResult(
                        f"db_user:{identity.email}",
                        False,
                        "Provider DB user certificate does not match local certificate",
                    )
                )
            else:
                results.append(
                    CheckResult(
                        f"db_user:{identity.email}",
                        True,
                        "Provider DB user certificate matches local certificate",
                    )
                )

        if identity.aid is None:
            continue

        local_agent_cert, _source_label = _local_agent_cert_bytes(identity.aid)
        agent_doc = agents_collection.find_one({"aid": identity.aid})
        if agent_doc is None:
            results.append(
                CheckResult(
                    f"db_agent:{identity.aid}",
                    False,
                    "Provider DB is missing expected agent registration",
                )
            )
        elif local_agent_cert is None:
            results.append(
                CheckResult(
                    f"db_agent:{identity.aid}",
                    False,
                    "local agent certificate is missing",
                )
            )
        elif agent_doc.get("agent_cert") != local_agent_cert:
            results.append(
                CheckResult(
                    f"db_agent:{identity.aid}",
                    False,
                    "Provider DB agent certificate does not match local certificate",
                )
            )
        else:
            results.append(
                CheckResult(
                    f"db_agent:{identity.aid}",
                    True,
                    "Provider DB agent certificate matches local certificate",
                )
            )

    return results


def run_preflight_checks(
    *,
    config_paths: Sequence[Path],
    ca_static_dir: Path = DEFAULT_CA_STATIC_DIR,
    ca_workdir: Path = DEFAULT_CA_WORKDIR,
    provider_cert_path: Path = DEFAULT_PROVIDER_CERT_PATH,
    mongo_uri: str = DEFAULT_PROVIDER_DB_URI,
    check_db_sync: bool = True,
    check_model_backends: bool = False,
    model_probe_timeout_seconds: float = 20.0,
) -> list[CheckResult]:
    """Run the full read-only trust-chain and registration preflight."""
    results: list[CheckResult] = []
    results.extend(_check_ca_static_layout(ca_static_dir, ca_workdir))

    ca_cert_path = ca_static_dir / "ca.crt"
    results.append(
        _check_cert_signed_by_ca(
            "provider_cert",
            provider_cert_path,
            ca_cert_path,
        )
    )

    identities = _load_managed_identities(config_paths)
    results.extend(_check_local_identity_certs(identities, ca_cert_path))

    if check_db_sync:
        try:
            client, database = _connect_provider_db(mongo_uri)
        except Exception as exc:
            results.append(
                CheckResult(
                    "db_connectivity",
                    False,
                    f"unable to connect to Provider DB via {mongo_uri}",
                    (str(exc),),
                )
            )
        else:
            try:
                results.extend(
                    _check_db_sync(
                        identities,
                        users_collection=database.users,
                        agents_collection=database.agents,
                    )
                )
            finally:
                client.close()

    if check_model_backends:
        results.extend(
            _check_model_backends(
                config_paths,
                timeout_seconds=model_probe_timeout_seconds,
            )
        )

    return results


def build_repair_plan(
    results: Sequence[CheckResult],
    *,
    config_paths: Sequence[Path],
) -> list[str]:
    """Convert failed checks into a read-only repair plan."""
    failures = [result for result in results if not result.ok]
    if not failures:
        return ["No repair actions suggested. Preflight passed."]

    suggestions: list[str] = [
        "Do not regenerate the CA during an ordinary rerun.",
        "Do not restore .bak/.selfsigned certs back into active paths.",
        "Serve CA files only from .ca_static, never from saga/ca.",
    ]

    names = {result.name for result in failures}
    if "ca_sync" in names or "ca_files" in names or "ca_layout" in names:
        suggestions.append(
            "Fix CA material first: ensure .ca_static/ca.* exists, saga/ca/ca.crt matches it, and the static file server uses .ca_static."
        )
    if "provider_cert" in names:
        suggestions.append(
            "Regenerate only the Provider TLS material from the current CA by moving aside saga/provider/provider.crt|key|pub and restarting Provider."
        )
    if any(name.startswith("user_cert:") or name.startswith("agent_cert:") for name in names):
        suggestions.append(
            "Move aside stale local user/agent cert directories before any re-registration; do not overwrite them in place."
        )
    if any(name.startswith("db_user:") or name.startswith("db_agent:") for name in names):
        config_labels = ", ".join(str(path) for path in config_paths)
        suggestions.append(
            "If local certs were replaced, delete only the affected user/agent registration rows from the local Provider DB, then re-run register + register-agents for: "
            + config_labels
        )
    if "db_connectivity" in names:
        suggestions.append(
            "Start local MongoDB before trusting any DB-sync result. File-side CA checks can still be used without MongoDB."
        )
    if any(name.startswith("model_probe:") for name in names):
        suggestions.append(
            "Fix the model backend before running a full experiment: verify OPENAI_API_KEY, api_base, model id, quota, and provider availability."
        )

    return suggestions


def _results_to_json(results: Sequence[CheckResult], repair_plan: Sequence[str] | None = None) -> str:
    """Serialize preflight results to JSON."""
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
    if repair_plan is not None:
        payload["repair_plan"] = list(repair_plan)
    return json.dumps(payload, indent=2, sort_keys=True)


def _print_human_report(results: Sequence[CheckResult], repair_plan: Sequence[str] | None = None) -> None:
    """Print a concise human-readable preflight report."""
    print("SAGA Experiment Preflight")
    print("=" * 26)
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] {result.name}: {result.summary}")
        for detail in result.details:
            print(f"  - {detail}")

    if repair_plan is not None:
        print("\nRepair Plan")
        print("-" * 11)
        for step in repair_plan:
            print(f"- {step}")

    print(f"\nOverall: {'PASS' if all(result.ok for result in results) else 'FAIL'}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the read-only preflight."""
    parser = argparse.ArgumentParser(description="Read-only trust-chain preflight for real SAGA experiments.")
    parser.add_argument(
        "--user-config",
        action="append",
        dest="user_configs",
        required=True,
        help="User config YAML to validate against local certs and Provider DB registrations.",
    )
    parser.add_argument(
        "--mongo-uri",
        default=DEFAULT_PROVIDER_DB_URI,
        help="Provider MongoDB URI used for user/agent registration state checks.",
    )
    parser.add_argument(
        "--skip-db-sync",
        action="store_true",
        help="Skip Provider DB registration-state checks and only verify file-side trust-chain state.",
    )
    parser.add_argument(
        "--model-probe",
        action="store_true",
        help="Also send a tiny request to configured model backends. This may use network and API quota.",
    )
    parser.add_argument(
        "--model-probe-timeout",
        type=float,
        default=20.0,
        help="Timeout in seconds for each optional model backend probe.",
    )
    parser.add_argument(
        "--ca-static-dir",
        default=str(DEFAULT_CA_STATIC_DIR),
        help="Directory that serves CA files over HTTP; must stay separate from saga/ca.",
    )
    parser.add_argument(
        "--ca-workdir",
        default=str(DEFAULT_CA_WORKDIR),
        help="Local saga/ca workdir where downloaded CA files live.",
    )
    parser.add_argument(
        "--provider-cert",
        default=str(DEFAULT_PROVIDER_CERT_PATH),
        help="Provider TLS certificate path to verify against the current CA.",
    )
    parser.add_argument(
        "--repair-plan",
        action="store_true",
        help="Print a read-only repair plan alongside the check results.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human report.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the preflight CLI."""
    args = parse_args(argv)
    config_paths = [Path(path).resolve() for path in args.user_configs]
    results = run_preflight_checks(
        config_paths=config_paths,
        ca_static_dir=Path(args.ca_static_dir).resolve(),
        ca_workdir=Path(args.ca_workdir).resolve(),
        provider_cert_path=Path(args.provider_cert).resolve(),
        mongo_uri=args.mongo_uri,
        check_db_sync=not args.skip_db_sync,
        check_model_backends=args.model_probe,
        model_probe_timeout_seconds=args.model_probe_timeout,
    )
    repair_plan = build_repair_plan(results, config_paths=config_paths) if args.repair_plan else None

    if args.json:
        print(_results_to_json(results, repair_plan))
    else:
        _print_human_report(results, repair_plan)

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
