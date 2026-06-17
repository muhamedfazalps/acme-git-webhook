import yaml
import pytest
from pydantic import ValidationError

from app.config import (
    load_config,
    AppConfig,
    AuthConfig,
    WebhookConfig,
    RepoConfig,
    VaultConfig,
)


class TestAuthConfig:
    def test_valid(self):
        cfg = AuthConfig(api_keys=["key1", "key2"])
        assert cfg.api_keys == ["key1", "key2"]

    def test_empty_keys(self):
        cfg = AuthConfig(api_keys=[])
        assert cfg.api_keys == []


class TestWebhookConfig:
    def test_defaults(self):
        cfg = WebhookConfig()
        assert cfg.bind == "0.0.0.0:8000"
        assert cfg.work_dir == "/data/acme-git-webhook"
        assert cfg.ssh_key is None

    def test_custom(self):
        cfg = WebhookConfig(bind="127.0.0.1:9000", work_dir="/tmp/test", ssh_key="/key")
        assert cfg.bind == "127.0.0.1:9000"
        assert cfg.ssh_key == "/key"


class TestRepoConfig:
    def test_defaults(self):
        cfg = RepoConfig(url="git@github.com:org/dns-zones.git")
        assert cfg.branch == "main"
        assert cfg.zone_path == "."
        assert cfg.zone_file_suffix == ".zone"

    def test_custom(self):
        cfg = RepoConfig(
            url="git@example.com:repo.git",
            branch="develop",
            zone_path="bind/zones",
            zone_file_suffix=".db",
        )
        assert cfg.zone_path == "bind/zones"
        assert cfg.zone_file_suffix == ".db"


class TestAppConfig:
    def test_valid(self):
        cfg = AppConfig(
            auth=AuthConfig(api_keys=["k"]),
            webhook=WebhookConfig(),
            repo=RepoConfig(url="git@github.com:org/dns-zones.git"),
        )
        assert cfg.auth.api_keys == ["k"]

    def test_missing_field(self):
        with pytest.raises(ValidationError):
            AppConfig(auth=AuthConfig(api_keys=["k"]), webhook=WebhookConfig())


class TestLoadConfig:
    def test_load_valid(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump({
                "auth": {"api_keys": ["sk-test"]},
                "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                "repo": {"url": "git@github.com:org/dns-zones.git"},
            })
        )
        cfg = load_config(str(path))
        assert cfg.auth.api_keys == ["sk-test"]
        assert cfg.repo.url == "git@github.com:org/dns-zones.git"

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("auth: {bad_yaml: ")
        with pytest.raises(yaml.YAMLError):
            load_config(str(path))

    def test_missing_required_field(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump({"auth": {"api_keys": ["k"]}}))
        with pytest.raises(ValidationError):
            load_config(str(path))

    def test_with_vault_section(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump({
                "auth": {"api_keys": ["sk-test"]},
                "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                "repo": {"url": "git@github.com:org/dns-zones.git"},
                "vault": {
                    "addr": "https://vault.example.com:8200",
                    "role_id": "role-abc",
                    "secret_id_path": "/run/secrets/vault_secret_id",
                },
            })
        )
        cfg = load_config(str(path))
        assert cfg.vault is not None
        assert cfg.vault.addr == "https://vault.example.com:8200"
        assert cfg.vault.role_id == "role-abc"
        assert cfg.vault.kv_mount == "secret"

    def test_without_vault_section(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump({
                "auth": {"api_keys": ["sk-test"]},
                "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                "repo": {"url": "git@github.com:org/dns-zones.git"},
            })
        )
        cfg = load_config(str(path))
        assert cfg.vault is None


class TestVaultConfig:
    def test_valid(self):
        cfg = VaultConfig(
            addr="https://vault.example.com:8200",
            role_id="role-abc",
            secret_id_path="/secrets/vault_secret_id",
        )
        assert cfg.addr == "https://vault.example.com:8200"
        assert cfg.role_id == "role-abc"
        assert cfg.kv_mount == "secret"
        assert cfg.certs_path == "certs"
        assert cfg.verify is True
        assert cfg.skip is False

    def test_custom_values(self):
        cfg = VaultConfig(
            addr="http://127.0.0.1:8200",
            role_id="role-xyz",
            secret_id_path="/tmp/secret",
            kv_mount="kv-v2",
            certs_path="pki/certs",
            verify=False,
            skip=True,
        )
        assert cfg.kv_mount == "kv-v2"
        assert cfg.certs_path == "pki/certs"
        assert cfg.verify is False
        assert cfg.skip is True

    def test_missing_required(self):
        with pytest.raises(ValidationError):
            VaultConfig(addr="https://vault.example.com:8200")

    def test_skip_defaults_to_false(self):
        cfg = VaultConfig(
            addr="https://vault.example.com:8200",
            role_id="role-abc",
            secret_id_path="/secrets/id",
        )
        assert cfg.skip is False
