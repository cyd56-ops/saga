"""Tests for the read-only experiment preflight checks."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import saga.common.crypto as sc

from experiments import preflight


CA_CONFIG = {
    "COUNTRY_NAME": "XX",
    "STATE_OR_PROVINCE_NAME": "Anonymous",
    "LOCALITY_NAME": "Anonymous",
    "ORG_NAME": "ca",
    "COMMON_NAME": "127.0.0.1",
    "IP": "127.0.0.1",
}


def _write_text(path: Path, content: str) -> None:
    """Write UTF-8 text to a file path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _issue_cert(common_name: str, ca_private_key, ca_certificate):
    """Issue one Ed25519-backed cert from the provided CA."""
    secret_key, public_key = sc.generate_ed25519_keypair()
    cert = sc.generate_x509_certificate(
        {
            "COUNTRY_NAME": "XX",
            "STATE_OR_PROVINCE_NAME": "Anonymous",
            "LOCALITY_NAME": "Anonymous",
            "ORG_NAME": "test",
            "COMMON_NAME": common_name,
            "IP": "127.0.0.1",
        },
        public_key=public_key,
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate,
    )
    return secret_key, public_key, cert


@dataclass
class _FakeCollection:
    """Simple in-memory collection stub for `find_one` lookups."""

    docs: list[dict]

    def find_one(self, query: dict):
        """Return the first document whose query keys all match exactly."""
        for doc in self.docs:
            if all(doc.get(key) == value for key, value in query.items()):
                return doc
        return None


class PreflightTests(unittest.TestCase):
    """Verify the read-only trust-chain preflight behavior."""

    def _build_minimal_config(self, path: Path, email: str, agent_name: str) -> None:
        """Write one minimal user config that `UserConfig.load` accepts."""
        _write_text(
            path,
            textwrap.dedent(
                f"""
                name: Example User
                email: {email}
                passwd: "secret"
                agents:
                  - name: "{agent_name}"
                    description: "test agent"
                    endpoint:
                      ip: 127.0.0.1
                      port: 7000
                      device_name: localhost
                    contact_rulebook: []
                    num_one_time_keys: 10
                    local_agent_config:
                      model_type: "OpenAIServerModel"
                      base_agent_type: "CodeAgent"
                      api_base: "https://api.openai.com/v1"
                      model: "gpt-5.2"
                      additional_authorized_imports: []
                      tools: [self]
                      specific_agent_instruction: ""
                """
            ).strip()
            + "\n",
        )

    def test_run_preflight_checks_passes_when_local_and_db_state_match(self) -> None:
        """The preflight should pass when CA, certs, and DB registrations are aligned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ca_static_dir = root / ".ca_static"
            ca_workdir = root / "saga" / "ca"
            provider_dir = root / "saga" / "provider"
            user_workdir = root / "saga" / "user"
            config_path = root / "user_configs" / "emma.yaml"

            ca_static_dir.mkdir(parents=True, exist_ok=True)
            ca_workdir.mkdir(parents=True, exist_ok=True)
            provider_dir.mkdir(parents=True, exist_ok=True)
            user_workdir.mkdir(parents=True, exist_ok=True)
            (user_workdir / "keys").mkdir(parents=True, exist_ok=True)

            ca_private_key, ca_public_key, ca_certificate = sc.generate_ca(CA_CONFIG)
            sc.save_ca(str(ca_static_dir), "ca", ca_private_key, ca_public_key, ca_certificate)
            sc.save_ca(str(ca_workdir), "ca", ca_private_key, ca_public_key, ca_certificate)

            _, _, provider_cert = _issue_cert("provider", ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(provider_dir / "provider"), provider_cert)

            email = "emma@example.com"
            agent_name = "calendar_agent"
            _, _, user_cert = _issue_cert(email, ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(user_workdir / "keys" / email), user_cert)

            agent_dir = user_workdir / f"{email}:{agent_name}"
            agent_dir.mkdir(parents=True, exist_ok=True)
            _, _, agent_cert = _issue_cert(f"{email}:{agent_name}", ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(agent_dir / "agent"), agent_cert)

            self._build_minimal_config(config_path, email, agent_name)

            fake_db = type(
                "FakeDatabase",
                (),
                {
                    "users": _FakeCollection(
                        [{"uid": email, "crt_u": (user_workdir / "keys" / f"{email}.crt").read_bytes()}]
                    ),
                    "agents": _FakeCollection(
                        [
                            {
                                "aid": f"{email}:{agent_name}",
                                "agent_cert": (agent_dir / "agent.crt").read_bytes(),
                            }
                        ]
                    ),
                },
            )()
            fake_client = type("FakeClient", (), {"close": lambda self: None})()

            with mock.patch.object(preflight, "USER_WORKDIR", str(user_workdir)), mock.patch.object(
                preflight,
                "_connect_provider_db",
                return_value=(fake_client, fake_db),
            ):
                results = preflight.run_preflight_checks(
                    config_paths=[config_path],
                    ca_static_dir=ca_static_dir,
                    ca_workdir=ca_workdir,
                    provider_cert_path=provider_dir / "provider.crt",
                    check_db_sync=True,
                )

        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(preflight.build_repair_plan(results, config_paths=[config_path]), ["No repair actions suggested. Preflight passed."])

    def test_run_preflight_checks_fails_when_db_cert_state_is_out_of_sync(self) -> None:
        """The preflight should fail when Provider DB registrations reference stale cert bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ca_static_dir = root / ".ca_static"
            ca_workdir = root / "saga" / "ca"
            provider_dir = root / "saga" / "provider"
            user_workdir = root / "saga" / "user"
            config_path = root / "user_configs" / "raj.yaml"

            ca_static_dir.mkdir(parents=True, exist_ok=True)
            ca_workdir.mkdir(parents=True, exist_ok=True)
            provider_dir.mkdir(parents=True, exist_ok=True)
            user_workdir.mkdir(parents=True, exist_ok=True)
            (user_workdir / "keys").mkdir(parents=True, exist_ok=True)

            ca_private_key, ca_public_key, ca_certificate = sc.generate_ca(CA_CONFIG)
            sc.save_ca(str(ca_static_dir), "ca", ca_private_key, ca_public_key, ca_certificate)
            sc.save_ca(str(ca_workdir), "ca", ca_private_key, ca_public_key, ca_certificate)

            _, _, provider_cert = _issue_cert("provider", ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(provider_dir / "provider"), provider_cert)

            email = "raj@example.com"
            agent_name = "calendar_agent"
            _, _, user_cert = _issue_cert(email, ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(user_workdir / "keys" / email), user_cert)

            agent_dir = user_workdir / f"{email}:{agent_name}"
            agent_dir.mkdir(parents=True, exist_ok=True)
            _, _, agent_cert = _issue_cert(f"{email}:{agent_name}", ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(agent_dir / "agent"), agent_cert)
            self._build_minimal_config(config_path, email, agent_name)

            stale_user_bytes = b"stale-user-cert"
            stale_agent_bytes = b"stale-agent-cert"
            fake_db = type(
                "FakeDatabase",
                (),
                {
                    "users": _FakeCollection([{"uid": email, "crt_u": stale_user_bytes}]),
                    "agents": _FakeCollection(
                        [{"aid": f"{email}:{agent_name}", "agent_cert": stale_agent_bytes}]
                    ),
                },
            )()
            fake_client = type("FakeClient", (), {"close": lambda self: None})()

            with mock.patch.object(preflight, "USER_WORKDIR", str(user_workdir)), mock.patch.object(
                preflight,
                "_connect_provider_db",
                return_value=(fake_client, fake_db),
            ):
                results = preflight.run_preflight_checks(
                    config_paths=[config_path],
                    ca_static_dir=ca_static_dir,
                    ca_workdir=ca_workdir,
                    provider_cert_path=provider_dir / "provider.crt",
                    check_db_sync=True,
                )
                repair_plan = preflight.build_repair_plan(results, config_paths=[config_path])

        self.assertFalse(all(result.ok for result in results))
        self.assertTrue(any(result.name == f"db_user:{email}" and not result.ok for result in results))
        self.assertTrue(any(result.name == f"db_agent:{email}:{agent_name}" and not result.ok for result in results))
        self.assertTrue(any("delete only the affected user/agent registration rows" in step for step in repair_plan))

    def test_ca_layout_fails_when_static_and_workdir_public_material_diverge(self) -> None:
        """The preflight should reject a CA static source that no longer matches saga/ca."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            static_dir = root / ".ca_static"
            workdir = root / "saga" / "ca"
            static_dir.mkdir(parents=True, exist_ok=True)
            workdir.mkdir(parents=True, exist_ok=True)

            ca_private_key_a, ca_public_key_a, ca_certificate_a = sc.generate_ca(CA_CONFIG)
            ca_private_key_b, ca_public_key_b, ca_certificate_b = sc.generate_ca(CA_CONFIG)
            sc.save_ca(str(static_dir), "ca", ca_private_key_a, ca_public_key_a, ca_certificate_a)
            sc.save_ca(str(workdir), "ca", ca_private_key_b, ca_public_key_b, ca_certificate_b)

            results = preflight._check_ca_static_layout(static_dir, workdir)

        self.assertTrue(any(result.name == "ca_sync" and not result.ok for result in results))

    def test_agent_cert_may_be_loaded_from_agent_manifest_when_agent_crt_is_absent(self) -> None:
        """Real preflight should accept agent certs embedded only inside `agent.json`."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ca_static_dir = root / ".ca_static"
            ca_workdir = root / "saga" / "ca"
            provider_dir = root / "saga" / "provider"
            user_workdir = root / "saga" / "user"
            config_path = root / "user_configs" / "emma.yaml"

            ca_static_dir.mkdir(parents=True, exist_ok=True)
            ca_workdir.mkdir(parents=True, exist_ok=True)
            provider_dir.mkdir(parents=True, exist_ok=True)
            user_workdir.mkdir(parents=True, exist_ok=True)
            (user_workdir / "keys").mkdir(parents=True, exist_ok=True)

            ca_private_key, ca_public_key, ca_certificate = sc.generate_ca(CA_CONFIG)
            sc.save_ca(str(ca_static_dir), "ca", ca_private_key, ca_public_key, ca_certificate)
            sc.save_ca(str(ca_workdir), "ca", ca_private_key, ca_public_key, ca_certificate)

            _, _, provider_cert = _issue_cert("provider", ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(provider_dir / "provider"), provider_cert)

            email = "emma@example.com"
            agent_name = "email_agent"
            _, _, user_cert = _issue_cert(email, ca_private_key, ca_certificate)
            sc.save_x509_certificate(str(user_workdir / "keys" / email), user_cert)
            _, _, agent_cert = _issue_cert(f"{email}:{agent_name}", ca_private_key, ca_certificate)
            agent_dir = user_workdir / f"{email}:{agent_name}"
            agent_dir.mkdir(parents=True, exist_ok=True)
            _write_text(
                agent_dir / "agent.json",
                textwrap.dedent(
                    f"""
                    {{
                      "aid": "{email}:{agent_name}",
                      "agent_cert": "{base64.b64encode(agent_cert.public_bytes(sc.serialization.Encoding.PEM)).decode('ascii')}"
                    }}
                    """
                ).strip()
                + "\n",
            )
            self._build_minimal_config(config_path, email, agent_name)

            fake_db = type(
                "FakeDatabase",
                (),
                {
                    "users": _FakeCollection(
                        [{"uid": email, "crt_u": (user_workdir / "keys" / f"{email}.crt").read_bytes()}]
                    ),
                    "agents": _FakeCollection(
                        [
                            {
                                "aid": f"{email}:{agent_name}",
                                "agent_cert": agent_cert.public_bytes(sc.serialization.Encoding.PEM),
                            }
                        ]
                    ),
                },
            )()
            fake_client = type("FakeClient", (), {"close": lambda self: None})()

            with mock.patch.object(preflight, "USER_WORKDIR", str(user_workdir)), mock.patch.object(
                preflight,
                "_connect_provider_db",
                return_value=(fake_client, fake_db),
            ):
                results = preflight.run_preflight_checks(
                    config_paths=[config_path],
                    ca_static_dir=ca_static_dir,
                    ca_workdir=ca_workdir,
                    provider_cert_path=provider_dir / "provider.crt",
                    check_db_sync=True,
                )

        self.assertTrue(all(result.ok for result in results))

    def test_model_probe_fails_closed_when_openai_key_is_missing(self) -> None:
        """Optional model probes should fail before experiments when a required key is absent."""
        endpoint = preflight.ModelEndpoint(
            model_type="OpenAIServerModel",
            model="gpt-5.2",
            api_base="https://api.openai.com/v1",
        )

        with mock.patch.dict("os.environ", {}, clear=True):
            result = preflight._probe_openai_server_model(endpoint, timeout_seconds=0.01)

        self.assertFalse(result.ok)
        self.assertIn("OPENAI_API_KEY", result.summary)

    def test_model_probe_skips_non_network_model_types(self) -> None:
        """Optional model checks should not call network APIs for local model types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "user_configs" / "local.yaml"
            _write_text(
                config_path,
                textwrap.dedent(
                    """
                    name: Local User
                    email: local@example.com
                    passwd: "secret"
                    agents:
                      - name: "calendar_agent"
                        description: "test agent"
                        endpoint:
                          ip: 127.0.0.1
                          port: 7000
                          device_name: localhost
                        contact_rulebook: []
                        num_one_time_keys: 10
                        local_agent_config:
                          model_type: "TransformersModel"
                          base_agent_type: "CodeAgent"
                          model: "tiny-local-model"
                          additional_authorized_imports: []
                          tools: [self]
                          specific_agent_instruction: ""
                    """
                ).strip()
                + "\n",
            )

            results = preflight._check_model_backends([config_path], timeout_seconds=0.01)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)
        self.assertIn("does not require", results[0].summary)

    def test_cli_preflight_does_not_probe_models_by_default(self) -> None:
        """The default preflight should remain a file/DB check unless explicitly requested."""
        with mock.patch.object(preflight, "run_preflight_checks", return_value=[]) as run_checks:
            exit_code = preflight.main(["--user-config", "user_configs/emma.yaml", "--skip-db-sync"])

        self.assertEqual(exit_code, 0)
        self.assertFalse(run_checks.call_args.kwargs["check_model_backends"])

    def test_cli_preflight_enables_model_probe_when_requested(self) -> None:
        """The model probe should be opt-in from the CLI."""
        with mock.patch.object(preflight, "run_preflight_checks", return_value=[]) as run_checks:
            exit_code = preflight.main(
                [
                    "--user-config",
                    "user_configs/emma.yaml",
                    "--skip-db-sync",
                    "--model-probe",
                    "--model-probe-timeout",
                    "3",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(run_checks.call_args.kwargs["check_model_backends"])
        self.assertEqual(run_checks.call_args.kwargs["model_probe_timeout_seconds"], 3)


if __name__ == "__main__":
    unittest.main()
