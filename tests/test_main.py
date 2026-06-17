from pathlib import Path
from unittest.mock import patch, MagicMock

import dns.exception
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.txtbase
import pytest
from fastapi.testclient import TestClient
from git import Repo

from app.config import AppConfig, AuthConfig, RepoConfig, VaultConfig, WebhookConfig
from app.main import app, config as global_config, vault_handler as global_vault


def _make_txt_rdata(value: str):
    return dns.rdtypes.txtbase.TXTBase(
        dns.rdataclass.IN, dns.rdatatype.TXT, [value.encode()],
    )


@pytest.fixture(autouse=True)
def _setup_config(tmp_path: Path, bare_git_repo: Path):
    global_config = AppConfig(
        auth=AuthConfig(api_keys=["test-key"]),
        webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
        repo=RepoConfig(
            url=str(bare_git_repo),
            branch="main",
            zone_path="zones",
            zone_file_suffix=".zone",
        ),
    )
    import app.main as m
    m.config = global_config
    yield
    m.config = None


@pytest.fixture
def client():
    return TestClient(app)


class TestHealth:
    def test_health_returns_ok(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestAcmeAuth:
    def test_auth_with_valid_key(self, client: TestClient, tmp_path: Path):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["domain"] == "_acme-challenge.example.com"

    def test_auth_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_auth_without_auth_header(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post("/acme/auth", json=payload)
        assert resp.status_code == 401

    def test_auth_creates_txt_in_zone_file(
        self, client: TestClient, tmp_path: Path, bare_git_repo: Path
    ):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "txt123",
        }
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200

        clone_dir = tmp_path / "verify-clone"
        verify_repo = Repo.clone_from(str(bare_git_repo), str(clone_dir))
        zone_content = (clone_dir / "zones" / "example.com.zone").read_text()
        assert "txt123" in zone_content


class TestAcmeCleanup:
    def test_cleanup_after_auth(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        auth_payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "cleanme",
        }
        client.post(
            "/acme/auth",
            json=auth_payload,
            headers={"Authorization": "Bearer test-key"},
        )

        cleanup_payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=cleanup_payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_cleanup_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_cleanup_idempotent(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"


class TestAcmeWaitForPropagation:
    def test_propagation_with_valid_key(self, client: TestClient):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("abc123")]
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
            "timeout": 10,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "propagated"
        assert len(data["matched"]) == 2  # default NS: 8.8.8.8, 1.1.1.1

    def test_propagation_timeout(self, client: TestClient):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
            "nameservers": ["8.8.8.8"],
            "timeout": 1,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.DNSException):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "timeout"
        assert data["pending"] == ["8.8.8.8"]

    def test_propagation_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post(
            "/acme/wait-for-propagation",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_propagation_without_auth_header(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post("/acme/wait-for-propagation", json=payload)
        assert resp.status_code == 401

    def test_propagation_custom_nameservers(self, client: TestClient):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("val")]
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "val",
            "nameservers": ["4.4.4.4", "8.8.4.4"],
            "timeout": 10,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        assert resp.json()["matched"] == ["4.4.4.4", "8.8.4.4"]


class TestAcmeDeploy:
    def test_deploy_skipped_when_vault_disabled(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert-data",
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        # No vault config in fixture => skipped
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"
        assert "Vault not configured" in resp.json()["detail"]

    def test_deploy_with_invalid_key(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_deploy_without_auth_header(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post("/acme/deploy", json=payload)
        assert resp.status_code == 401

    def test_deploy_with_vault_enabled(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m
        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        m.vault_handler = MagicMock()
        m.vault_handler.store_cert.return_value = "secret/certs/example.com"

        payload = {
            "domain": "example.com",
            "cert_pem": "cert-data",
            "chain_pem": "chain-data",
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["vault_path"] == "secret/certs/example.com"
        m.vault_handler.store_cert.assert_called_once_with(
            domain="example.com",
            cert_pem="cert-data",
            chain_pem="chain-data",
            fullchain_pem="fullchain-data",
            privkey_pem="key-data",
        )

    def test_deploy_vault_error_returns_502(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m
        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        mock_handler = MagicMock()
        mock_handler.store_cert.side_effect = Exception("Vault connection refused")
        m.vault_handler = mock_handler

        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Vault operation failed" in resp.json()["detail"]
