"""Data model shared by tools, investigators, guardrails and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_time(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


class RootCause(StrEnum):
    """Root-cause categories the agent can conclude. Kept small on purpose:
    a fixed vocabulary makes findings comparable and evaluations scoreable."""

    BAD_DEPLOY = "bad_deploy"
    OOM_KILL = "oom_kill"
    CONFIG_ERROR = "config_error"
    IMAGE_PULL = "image_pull"
    DEPENDENCY_FAILURE = "dependency_failure"
    DNS_FAILURE = "dns_failure"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    RESOURCE_SATURATION = "resource_saturation"
    NODE_FAILURE = "node_failure"
    POISON_MESSAGE = "poison_message"
    UNKNOWN = "unknown"


@dataclass
class Alert:
    name: str
    service: str
    namespace: str = "default"
    severity: str = "page"
    summary: str = ""
    starts_at: datetime = field(default_factory=utcnow)
    labels: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Alert:
        return cls(
            name=d["name"],
            service=d["service"],
            namespace=d.get("namespace", "default"),
            severity=d.get("severity", "page"),
            summary=d.get("summary", ""),
            starts_at=parse_time(d.get("starts_at")) or utcnow(),
            labels=d.get("labels", {}),
        )

    @classmethod
    def from_alertmanager(cls, a: dict[str, Any]) -> Alert:
        """Build from one alert in an Alertmanager webhook payload."""
        labels = a.get("labels", {})
        return cls(
            name=labels.get("alertname", "unknown"),
            service=labels.get("service") or labels.get("app") or labels.get("job", "unknown"),
            namespace=labels.get("namespace", "default"),
            severity=labels.get("severity", "page"),
            summary=a.get("annotations", {}).get("summary", ""),
            starts_at=parse_time(a.get("startsAt")) or utcnow(),
            labels=labels,
        )


@dataclass
class Evidence:
    """One tool result, numbered so findings can cite it (E1, E2, ...)."""

    id: str
    tool: str
    args: dict[str, Any]
    summary: str
    data: Any
    redactions: int = 0
    injection_flagged: bool = False


@dataclass
class Finding:
    root_cause: RootCause
    service: str
    summary: str
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    alternatives: list[tuple[str, float]] = field(default_factory=list)


@dataclass
class ProposedAction:
    tool: str
    args: dict[str, Any]
    reason: str


@dataclass
class ActionOutcome:
    action: ProposedAction
    status: str  # executed | blocked | denied | failed
    detail: str = ""


@dataclass
class Investigation:
    alert: Alert
    finding: Finding | None = None
    evidence: list[Evidence] = field(default_factory=list)
    actions: list[ActionOutcome] = field(default_factory=list)
    blocked_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    steps: int = 0
    investigator: str = ""
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.finding:
            d["finding"]["root_cause"] = self.finding.root_cause.value
        return d
