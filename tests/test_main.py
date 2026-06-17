from pathlib import Path
from unittest.mock import patch, MagicMock

import dns.exception
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.txtbase
import pytest
from fastapi.testclient import TestClient
from git import Repo

from app.config import AppConfig, AuthConfig, RepoConfig, WebhookConfig
from app.main import app, config as global_config


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
