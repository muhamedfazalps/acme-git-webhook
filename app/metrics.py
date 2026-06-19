"""Prometheus metrics instrumentation for acme-git-webhook."""

from prometheus_client import Counter, make_asgi_app

# ── Application-level counters ──────────────────────────────────────

cert_auth_total = Counter(
    "acme_cert_auth_total",
    "Total number of ACME auth (challenge-add) operations",
)

cert_cleanup_total = Counter(
    "acme_cert_cleanup_total",
    "Total number of ACME cleanup (challenge-remove) operations",
)

cert_deploy_total = Counter(
    "acme_cert_deploy_total",
    "Total number of ACME deploy operations",
    labelnames=["target"],
)

cert_renew_total = Counter(
    "acme_cert_renew_total",
    "Total number of manual certificate renewals",
)

webhook_requests_total = Counter(
    "acme_webhook_requests_total",
    "Total number of HTTP requests by endpoint",
    labelnames=["endpoint", "method", "status"],
)


def create_metrics_app():
    """Return an ASGI app exposing Prometheus metrics at ``/metrics``."""
    return make_asgi_app()
