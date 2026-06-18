from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import httpx
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import MonitorConfig
from app.vault_handler import VaultHandler

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 15.0


class CertMonitor:
    def __init__(
        self,
        config: MonitorConfig | None,
        vault_handler: VaultHandler | None,
    ) -> None:
        self.config = config
        self._vault = vault_handler
        self._scheduler: BackgroundScheduler | None = None
        self._sent_warnings: dict[str, set[int]] = {}
        self._latest_status: list[dict] = []

    def _load_certs_from_vault(self) -> list[dict]:
        if self._vault is None:
            return []
        try:
            self._vault._ensure_authenticated()
            client = self._vault._client
            mount = self._vault.config.kv_mount
            path = self._vault.config.certs_path
            domains = client.secrets.kv.v2.list_secrets(
                mount_point=mount, path=path
            )
        except Exception:
            logger.warning("CertMonitor: no certificates found in Vault", exc_info=True)
            return []

        certs = []
        for domain_key in domains.get("data", {}).get("keys", []):
            domain = domain_key.rstrip("/")
            try:
                secret = client.secrets.kv.v2.read_secret_version(
                    mount_point=mount, path=f"{path}/{domain}"
                )
                data = secret.get("data", {}).get("data", {})
                metadata_raw = data.get("metadata", "{}")
                metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw
                expiry_str = metadata.get("expiry")
                if expiry_str and expiry_str != "unknown":
                    expiry = datetime.fromisoformat(expiry_str)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                else:
                    expiry = None
                    days_left = None
                certs.append({
                    "domain": domain,
                    "expiry": expiry.isoformat() if expiry else None,
                    "days_left": days_left,
                    "stored_at": metadata.get("stored_at"),
                })
            except Exception:
                logger.warning("CertMonitor: failed to read cert for %s", domain, exc_info=True)
        return certs

    def _send_webhook_alert(self, domain: str, days_left: int) -> None:
        url = self.config.alert_webhook_url
        if not url:
            return
        try:
            payload = {
                "text": (
                    f"Certificate expiration warning: {domain}\n"
                    f"Days left: {days_left}\n"
                    f"Severity: {'CRITICAL' if days_left <= 7 else 'WARNING' if days_left <= 30 else 'INFO'}"
                ),
                "domain": domain,
                "days_left": days_left,
            }
            httpx.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
        except Exception:
            logger.warning("CertMonitor: failed to send webhook alert for %s", domain, exc_info=True)

    def _check_day_threshold(self, domain: str, days_left: int) -> None:
        if self.config is None:
            return
        for threshold in self.config.warn_days:
            if days_left <= threshold:
                sent = self._sent_warnings.setdefault(domain, set())
                if threshold not in sent:
                    logger.warning(
                        "CertMonitor: %s expires in %d days (threshold: %d)",
                        domain,
                        days_left,
                        threshold,
                    )
                    self._send_webhook_alert(domain, days_left)
                    sent.add(threshold)

    def run_check(self) -> list[dict]:
        certs = self._load_certs_from_vault()
        for cert in certs:
            days = cert.get("days_left")
            if days is not None and self.config is not None:
                self._check_day_threshold(cert["domain"], days)
        self._latest_status = certs
        logger.info("CertMonitor: checked %d certificates", len(certs))
        return certs

    def get_status(self) -> list[dict]:
        return self._latest_status

    def start(self) -> None:
        if self.config is None:
            logger.info("CertMonitor: monitoring disabled (no config)")
            return
        self._scheduler = BackgroundScheduler()
        self._scheduler.add_job(
            self.run_check,
            "interval",
            hours=self.config.check_interval_hours,
            id="cert_monitor_check",
        )
        self._scheduler.start()
        self.run_check()
        logger.info(
            "CertMonitor: started (interval=%dh)",
            self.config.check_interval_hours,
        )

    def stop(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
