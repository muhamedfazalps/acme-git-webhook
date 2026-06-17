import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class AuthConfig(BaseModel):
    api_keys: list[str]


class WebhookConfig(BaseModel):
    bind: str = "0.0.0.0:8000"
    work_dir: str = "/data/acme-git-webhook"
    ssh_key: str | None = None


class RepoConfig(BaseModel):
    url: str
    branch: str = "main"
    zone_path: str = "."
    zone_file_suffix: str = ".zone"


class AppConfig(BaseModel):
    auth: AuthConfig
    webhook: WebhookConfig
    repo: RepoConfig


def load_config(path: str | None = None) -> AppConfig:
    if path is None:
        path = os.getenv("CONFIG_PATH", "config.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)
    return AppConfig.model_validate(data)
