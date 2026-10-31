"""Runtime configuration from environment variables (12-factor style)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def secret(name: str) -> str | None:
    """Read a secret from <NAME>_FILE (mounted Kubernetes secret) or, failing that, <NAME>."""
    path = os.getenv(f"{name}_FILE")
    if path and os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip() or None
    return os.getenv(name)


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    investigator: str = field(default_factory=lambda: os.getenv("SRE_AGENT_INVESTIGATOR", "rules"))
    read_only: bool = field(default_factory=lambda: _bool("SRE_AGENT_READ_ONLY", True))
    allowed_namespaces: list[str] = field(
        default_factory=lambda: os.getenv("SRE_AGENT_NAMESPACES", "*").split(",")
    )
    prometheus_url: str = field(
        default_factory=lambda: os.getenv(
            "PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc:9090"
        )
    )
    loki_url: str | None = field(
        default_factory=lambda: os.getenv("LOKI_URL", "http://loki-gateway.observability.svc")
    )
    service_label: str = field(default_factory=lambda: os.getenv("SERVICE_LABEL", "app"))
    audit_path: str = field(default_factory=lambda: os.getenv("SRE_AGENT_AUDIT_PATH", "audit/audit.jsonl"))
    webhook_token: str | None = field(default_factory=lambda: secret("WEBHOOK_TOKEN"))
    slack_webhook_url: str | None = field(default_factory=lambda: secret("SLACK_WEBHOOK_URL"))
    max_concurrent: int = field(default_factory=lambda: int(os.getenv("SRE_AGENT_MAX_CONCURRENT", "2")))
    dedupe_minutes: int = field(default_factory=lambda: int(os.getenv("SRE_AGENT_DEDUPE_MINUTES", "15")))
