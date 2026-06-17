import os
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fasteners import InterProcessLock

from app.auth import verify_api_key
from app.config import AppConfig, load_config
from app.git_handler import clone_or_pull, commit_and_push
from app.models import AcmeRequest
from app.zone_handler import add_txt_record, remove_txt_record

config: AppConfig | None = None
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global config
    config_path = os.getenv("CONFIG_PATH", "config.yaml")
    config = load_config(config_path)
    yield


app = FastAPI(title="acme-git-webhook", lifespan=lifespan)


def _get_config() -> AppConfig:
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Config not loaded",
        )
    return config


def _auth_dep(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    cfg = _get_config()
    return verify_api_key(credentials, valid_keys=cfg.auth.api_keys)


def _repo_dir() -> Path:
    return Path(_get_config().webhook.work_dir).resolve()


def _lock_path() -> Path:
    work_dir = _repo_dir()
    return work_dir / "repo.lock"


def _zone_name(domain: str) -> str:
    return domain.removeprefix("_acme-challenge.").removeprefix("*.")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/acme/auth")
def acme_auth(
    req: AcmeRequest,
    _token: str = Depends(_auth_dep),
):
    cfg = _get_config()
    work_dir = _repo_dir()
    repo_root = work_dir / "zone-repo"
    lock_path = _lock_path()

    work_dir.mkdir(parents=True, exist_ok=True)

    lock = InterProcessLock(str(lock_path))
    acquired = lock.acquire(blocking=True)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Another operation is in progress, try again",
        )
    try:
        clone_or_pull(work_dir, cfg.repo.url, cfg.repo.branch)
        add_txt_record(
            repo_root,
            req.domain,
            req.validation,
            cfg.repo.zone_path,
            cfg.repo.zone_file_suffix,
        )
        commit_and_push(work_dir, f"ACME: add challenge for {req.domain}")
    finally:
        lock.release()

    return {
        "status": "ok",
        "domain": req.domain,
        "zone_file": f"{_zone_name(req.domain)}{cfg.repo.zone_file_suffix}",
    }


@app.post("/acme/cleanup")
def acme_cleanup(
    req: AcmeRequest,
    _token: str = Depends(_auth_dep),
):
    cfg = _get_config()
    work_dir = _repo_dir()
    repo_root = work_dir / "zone-repo"
    lock_path = _lock_path()

    work_dir.mkdir(parents=True, exist_ok=True)

    lock = InterProcessLock(str(lock_path))
    acquired = lock.acquire(blocking=True)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Another operation is in progress, try again",
        )
    try:
        clone_or_pull(work_dir, cfg.repo.url, cfg.repo.branch)
        removed = remove_txt_record(
            repo_root,
            req.domain,
            cfg.repo.zone_path,
            cfg.repo.zone_file_suffix,
        )
        if removed:
            commit_and_push(work_dir, f"ACME: remove challenge for {req.domain}")
            return {
                "status": "ok",
                "domain": req.domain,
                "zone_file": Path(removed).name,
            }
        else:
            return {
                "status": "skipped",
                "domain": req.domain,
                "detail": "No TXT record found to remove",
            }
    finally:
        lock.release()
