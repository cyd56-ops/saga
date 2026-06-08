"""测试一次性密钥签名是否绑定到 agent 身份。"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import threading
import unittest

from flask import Flask

import saga.common.crypto as sc
from saga.agent import Agent
from saga.provider.provider import Provider


_CA_CONFIG = {
    "COUNTRY_NAME": "XX",
    "STATE_OR_PROVINCE_NAME": "Anonymous",
    "LOCALITY_NAME": "Anonymous",
    "ORG_NAME": "test-ca",
    "COMMON_NAME": "127.0.0.1",
    "IP": "127.0.0.1",
}


class _NoOpMonitor:
    """为 Provider 路由测试提供最小 monitor 桩。"""

    def start(self, _name: str) -> None:
        """空实现的启动钩子。"""

    def stop(self, _name: str) -> None:
        """空实现的停止钩子。"""

    def elapsed(self, _name: str) -> float:
        """返回确定性的耗时值。"""
        return 0.0


class _NoOpCA:
    """证书验签桩，测试只关注 OTK 签名语义。"""

    def verify(self, _certificate) -> None:
        """接受可解析的测试证书，不依赖外部 CA 状态。"""


class _FakeCollection:
    """为 Provider 注册路由提供一个小型内存集合桩。"""

    def __init__(self, docs: list[dict] | None = None) -> None:
        self.docs = list(docs or [])
        self.updates: list[tuple[dict, dict]] = []

    def find_one(self, query: dict):
        """仅在顶层字段完全匹配时返回文档。"""
        for doc in self.docs:
            if all(key in doc and doc[key] == value for key, value in query.items()):
                return doc
        return None

    def insert_one(self, document: dict) -> object:
        """保存插入文档的副本，供断言使用。"""
        self.docs.append(document)
        return object()

    def update_one(self, query: dict, update: dict) -> object:
        """记录 token 消费路径触发的更新调用。"""
        self.updates.append((query, update))
        return object()


def _issue_cert(common_name: str, public_key, ca_private_key, ca_certificate):
    """为路由测试签发一个可解析的 Ed25519 证书。"""
    return sc.generate_x509_certificate(
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


def _raw_public_key(public_key) -> bytes:
    """按 SAGA manifest 所用格式序列化原始公钥。"""
    return public_key.public_bytes(
        encoding=sc.serialization.Encoding.Raw,
        format=sc.serialization.PublicFormat.Raw,
    )


class OTKSignatureBindingTests(unittest.TestCase):
    """验证 OTK 签名不能跨 agent 身份复用。"""

    def test_otk_signature_payload_binds_agent_identity(self) -> None:
        """同一个 OTK 签名只能在对应 AID 上验签通过。"""
        signing_secret, signing_public = sc.generate_ed25519_keypair()
        _, public_otk = sc.generate_x25519_keypair()
        otk_bytes = _raw_public_key(public_otk)

        signature = sc.sign_otk(signing_secret, "alice@example.com:calendar_agent", otk_bytes)

        self.assertTrue(
            sc.verify_otk_signature(
                signing_public,
                "alice@example.com:calendar_agent",
                otk_bytes,
                signature,
            )
        )
        self.assertFalse(
            sc.verify_otk_signature(
                signing_public,
                "alice@example.com:email_agent",
                otk_bytes,
                signature,
            )
        )

    def test_provider_register_agent_accepts_aid_bound_otk_signature(self) -> None:
        """Provider 注册应接受绑定 AID 的 OTK 签名。"""
        client, provider = self._build_provider_client(
            lambda signing_secret, aid, otk: sc.sign_otk(signing_secret, aid, otk)
        )

        response = client.post("/register_agent", json=provider.request_body)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(provider.agents_collection.docs), 1)

    def test_provider_register_agent_rejects_legacy_otk_only_signature(self) -> None:
        """只签 raw OTK bytes 的旧签名必须 fail closed。"""
        client, provider = self._build_provider_client(
            lambda signing_secret, _aid, otk: signing_secret.sign(otk)
        )

        response = client.post("/register_agent", json=provider.request_body)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["message"], "Invalid one-time key signature")
        self.assertEqual(provider.agents_collection.docs, [])

    def test_provider_register_agent_rejects_cross_aid_otk_signature(self) -> None:
        """来自其他 agent 身份的 OTK 签名不能通过验签。"""
        client, provider = self._build_provider_client(
            lambda signing_secret, _aid, otk: sc.sign_otk(
                signing_secret,
                "alice@example.com:email_agent",
                otk,
            )
        )

        response = client.post("/register_agent", json=provider.request_body)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["message"], "Invalid one-time key signature")
        self.assertEqual(provider.agents_collection.docs, [])

    def test_local_otk_consume_allows_only_one_concurrent_consumer(self) -> None:
        """接收方必须原子消费本地 OTK，确保并发下最多只用一次。"""
        private_otk, public_otk = sc.generate_x25519_keypair()
        otk_bytes = _raw_public_key(public_otk)
        agent = Agent.__new__(Agent)
        agent.otks_lock = threading.Lock()
        agent.otks_dict = {otk_bytes: private_otk}
        barrier = threading.Barrier(3)
        results: list[bool] = []
        results_lock = threading.Lock()

        def consume_once() -> None:
            barrier.wait()
            consumed = agent._consume_local_otk(otk_bytes)
            with results_lock:
                results.append(consumed is not None)

        threads = [threading.Thread(target=consume_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)
        self.assertEqual(agent.otks_dict, {})

    def _build_provider_client(self, otk_signer):
        """围绕 Provider 的真实 register 路由构造 Flask 测试客户端。"""
        uid = "alice@example.com"
        aid = f"{uid}:calendar_agent"
        ca_private_key, _, ca_certificate = sc.generate_ca(_CA_CONFIG)
        provider_secret, provider_public = sc.generate_ed25519_keypair()
        user_secret, user_public = sc.generate_ed25519_keypair()
        agent_secret, agent_public = sc.generate_ed25519_keypair()
        _, pac = sc.generate_x25519_keypair()
        _, public_otk = sc.generate_x25519_keypair()

        user_cert = _issue_cert(uid, user_public, ca_private_key, ca_certificate)
        agent_cert = _issue_cert(aid, agent_public, ca_private_key, ca_certificate)
        pac_bytes = _raw_public_key(pac)
        otk_bytes = _raw_public_key(public_otk)
        provider_public_bytes = _raw_public_key(provider_public)
        dev_network_info = {
            "aid": aid,
            "device": "localhost",
            "IP": "127.0.0.1",
            "port": 12345,
        }
        crypto_info = {
            "pk_a": _raw_public_key(agent_public),
            "pac": pac_bytes,
            "pk_prov": provider_public_bytes,
        }
        signed_block = {}
        signed_block.update(dev_network_info)
        signed_block.update(crypto_info)
        application = {
            **dev_network_info,
            "agent_cert": base64.b64encode(
                agent_cert.public_bytes(sc.serialization.Encoding.PEM)
            ).decode("utf-8"),
            "pac": base64.b64encode(pac_bytes).decode("utf-8"),
            "otks": [base64.b64encode(otk_bytes).decode("utf-8")],
            "contact_rulebook": [],
            "agent_sig": base64.b64encode(
                user_secret.sign(str(signed_block).encode("utf-8"))
            ).decode("utf-8"),
            "otk_sigs": [
                base64.b64encode(otk_signer(user_secret, aid, otk_bytes)).decode("utf-8")
            ],
        }
        provider = Provider.__new__(Provider)
        provider.app = Flask(__name__)
        provider.monitor = _NoOpMonitor()
        provider.CA = _NoOpCA()
        provider.SK_Prov = provider_secret
        provider.PK_Prov = provider_public
        provider.users_collection = _FakeCollection(
            [
                {
                    "uid": uid,
                    "crt_u": user_cert.public_bytes(sc.serialization.Encoding.PEM),
                    "auth_tokens": [
                        {
                            "token": "provider-jwt",
                            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
                        }
                    ],
                }
            ]
        )
        provider.agents_collection = _FakeCollection()
        provider.request_body = {
            "uid": uid,
            "jwt": "provider-jwt",
            "application": application,
        }
        Provider._register_routes(provider)
        return provider.app.test_client(), provider


if __name__ == "__main__":
    unittest.main()
