"""Deterministic investigator: a fixed evidence-gathering playbook plus scored
hypotheses. No LLM, no network beyond the telemetry backends.

It exists for three reasons:
  * a baseline the LLM investigator must beat in the evaluation harness
  * a fallback when the LLM is unavailable or not allowed (air-gapped, cost)
  * a readable statement of what "good triage" looks like

Taxonomy rule: platform failure signatures (OOM, config, image pull, node,
DNS, TLS) are more specific than "bad deploy" and win when present, because
they point at the fix. `bad_deploy` means a new version misbehaves at runtime
without one of those signatures.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sre_agent.models import Evidence, Finding, Investigation, RootCause, parse_time
from sre_agent.tools.base import ToolRegistry

DEPENDENCY_RX = re.compile(
    r"connection (refused|reset)|timed? ?out|timeout|ECONNREFUSED|EndpointConnectionError|"
    r"could not connect|upstream|503 service unavailable|pool (exhausted|timeout)|too many connections|"
    r"throttl",
    re.IGNORECASE,
)
DNS_RX = re.compile(
    r"no such host|NXDOMAIN|name resolution|Name or service not known|"
    r"could not resolve",
    re.IGNORECASE,
)
TLS_RX = re.compile(r"x509|certificate (has )?expired|certificate verify failed|tls handshake", re.IGNORECASE)
CONFIG_RX = re.compile(
    r"(secret|configmap)s? \"?[\w.-]+\"? not found|couldn't find key|"
    r"CreateContainerConfigError|invalid configuration",
    re.IGNORECASE,
)
POISON_RX = re.compile(
    r"(parse|decode|deserializ|validation|schema|invalid (payload|message)|"
    r"malformed)",
    re.IGNORECASE,
)
NODE_REASONS = {
    "NodeNotReady",
    "NodeHasDiskPressure",
    "NodeHasMemoryPressure",
    "Evicted",
    "TaintManagerEviction",
    "NodeShutdown",
    "Rebooted",
}


@dataclass
class Hypothesis:
    cause: RootCause
    score: float = 0.0
    evidence: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    def add(self, points: float, ev: Evidence | None, note: str) -> None:
        self.score += points
        if ev:
            self.evidence.add(ev.id)
        self.notes.append(note)


def _points(ev: Evidence | None) -> list[tuple[datetime, float]]:
    if not ev or not isinstance(ev.data, dict):
        return []
    return [(parse_time(t), float(v)) for t, v in ev.data.get("points", [])]


def _onset(points: list[tuple[datetime, float]], floor: float, factor: float) -> datetime | None:
    """First time a series rises above max(floor, factor x early baseline)."""
    if len(points) < 3:
        return None
    early = [v for _, v in points[: max(2, len(points) // 3)]]
    threshold = max(floor, factor * statistics.median(early))
    return next((t for t, v in points if v > threshold), None)


def _share(entries: list[dict[str, Any]], rx: re.Pattern[str]) -> float:
    if not entries:
        return 0.0
    total = sum(e["count"] for e in entries)
    return sum(e["count"] for e in entries if rx.search(e["msg"])) / max(total, 1)


class RuleBasedInvestigator:
    name = "rule-based"

    def investigate(self, inv: Investigation, tools: ToolRegistry) -> None:
        a = inv.alert
        ns, svc = a.namespace, a.service

        # 1. Gather: what changed, what the golden signals say, what the platform reports
        deps = tools.call("recent_deployments", {"namespace": ns, "minutes": 120}, inv)
        err = tools.call("query_metric", {"signal": "error_rate", "namespace": ns, "service": svc}, inv)
        lat = tools.call("query_metric", {"signal": "p95_latency", "namespace": ns, "service": svc}, inv)
        pods = tools.call("get_pods", {"namespace": ns, "service": svc}, inv)
        events = tools.call("get_events", {"namespace": ns, "minutes": 60}, inv)
        logs = tools.call(
            "search_logs", {"namespace": ns, "service": svc, "level": "error", "minutes": 60}, inv
        )
        cpu = tools.call("query_metric", {"signal": "cpu_throttling", "namespace": ns, "service": svc}, inv)
        mem = tools.call(
            "query_metric", {"signal": "memory_utilization", "namespace": ns, "service": svc}, inv
        )
        queue_related = re.search(r"queue|backlog|worker|dlq|consumer", f"{a.name} {svc}", re.I)
        dlq = (
            tools.call("query_metric", {"signal": "dlq_depth", "namespace": ns, "service": svc}, inv)
            if queue_related
            else None
        )

        h = {c: Hypothesis(c) for c in RootCause if c is not RootCause.UNKNOWN}
        err_pts, lat_pts = _points(err), _points(lat)
        onset = _onset(err_pts, floor=0.02, factor=5) or _onset(lat_pts, floor=0.3, factor=2) or a.starts_at

        # 2. Platform failure signatures from pods and events (scoped to this service)
        pod_list = pods.data if isinstance(pods.data, list) else []
        svc_events = [
            e
            for e in (events.data if isinstance(events.data, list) else [])
            if svc in e.get("object", "") or svc in e.get("message", "")
        ]
        reasons = {e.get("reason", "") for e in svc_events}
        messages = " ".join(e.get("message", "") for e in svc_events)

        if (
            any(p.get("last_termination_reason") == "OOMKilled" for p in pod_list)
            or "OOMKilling" in reasons
            or "OOMKilled" in messages
        ):
            h[RootCause.OOM_KILL].add(0.85, pods, "containers terminated with OOMKilled")
            if mem and any(v >= 0.9 for _, v in _points(mem)):
                h[RootCause.OOM_KILL].add(0.1, mem, "memory at >=90% of limit")
        if CONFIG_RX.search(messages) or any(
            p.get("waiting_reason") == "CreateContainerConfigError" for p in pod_list
        ):
            h[RootCause.CONFIG_ERROR].add(
                0.9, events, "container config error (missing secret/configmap/key)"
            )
        if reasons & {"ErrImagePull", "ImagePullBackOff"} or any(
            p.get("waiting_reason") in ("ErrImagePull", "ImagePullBackOff") for p in pod_list
        ):
            h[RootCause.IMAGE_PULL].add(0.9, events, "image cannot be pulled")
        all_events = events.data if isinstance(events.data, list) else []
        bad_nodes = {
            e["object"].split("/", 1)[1]
            for e in all_events
            if e.get("reason") in NODE_REASONS and e.get("object", "").startswith("Node/")
        }
        svc_nodes = {p.get("node") for p in pod_list if p.get("node")}
        if bad_nodes & svc_nodes or reasons & {"Evicted", "TaintManagerEviction"}:
            h[RootCause.NODE_FAILURE].add(0.8, events, "node not ready / pod eviction affecting this service")

        # 3. Log signatures (share of error lines, so a little noise does not dominate)
        top = logs.data.get("top_messages", []) if isinstance(logs.data, dict) else []
        n_err = logs.data.get("count", 0) if isinstance(logs.data, dict) else 0
        if n_err >= 5:
            dns, tls, dep = _share(top, DNS_RX), _share(top, TLS_RX), _share(top, DEPENDENCY_RX)
            if dns >= 0.3:
                h[RootCause.DNS_FAILURE].add(
                    0.85 * min(1, dns / 0.6), logs, f"{dns:.0%} of errors are DNS failures"
                )
            if tls >= 0.3:
                h[RootCause.CERTIFICATE_EXPIRY].add(
                    0.85 * min(1, tls / 0.6), logs, f"{tls:.0%} of errors are TLS/certificate failures"
                )
            if dep >= 0.5 and dns < 0.3 and tls < 0.3:
                h[RootCause.DEPENDENCY_FAILURE].add(
                    0.7 * min(1, dep / 0.8), logs, f"{dep:.0%} of errors are dependency timeouts/refusals"
                )

        # 4. Change correlation: a deploy of THIS service shortly before onset
        dep_list = deps.data if isinstance(deps.data, list) else []
        suspects = [
            d
            for d in dep_list
            if d.get("service") == svc
            and onset - timedelta(minutes=30) <= parse_time(d["at"]) <= onset + timedelta(minutes=1)
        ]
        if suspects:
            d = suspects[-1]
            at = parse_time(d["at"])
            h[RootCause.BAD_DEPLOY].add(0.55, deps, f"{svc} deployed {d.get('version')} shortly before onset")
            before = [v for t, v in err_pts if t < at] or [v for t, v in lat_pts if t < at]
            after = [v for t, v in err_pts if t >= at] or [v for t, v in lat_pts if t >= at]
            if before and after and max(after) > 3 * max(statistics.median(before), 0.005):
                h[RootCause.BAD_DEPLOY].add(
                    0.3, err if err_pts else lat, "signal degraded only after the deploy"
                )
            versions = [
                s.get("version") for s in (logs.data.get("sample", []) if isinstance(logs.data, dict) else [])
            ]
            if versions and versions.count(d.get("version")) / len(versions) >= 0.8:
                h[RootCause.BAD_DEPLOY].add(0.1, logs, "errors come from the new version")
            # A platform signature or dependency explanation outranks a coincident deploy
            if any(
                h[c].score >= 0.7 for c in (RootCause.CONFIG_ERROR, RootCause.IMAGE_PULL, RootCause.OOM_KILL)
            ):
                h[RootCause.BAD_DEPLOY].score -= 0.3

        # 5. Saturation and queue health
        cpu_pts = _points(cpu)
        if cpu_pts and max(v for _, v in cpu_pts) >= 0.5:
            h[RootCause.RESOURCE_SATURATION].add(0.55, cpu, "heavy CPU throttling")
            if lat_pts and (not err_pts or max(v for _, v in err_pts) < 0.05):
                h[RootCause.RESOURCE_SATURATION].add(0.2, lat, "latency up while errors stay low")
        dlq_pts = _points(dlq)
        if dlq_pts and dlq_pts[-1][1] > dlq_pts[0][1]:
            h[RootCause.POISON_MESSAGE].add(0.4, dlq, "dead-letter queue is growing")
            if top and top[0]["count"] / max(n_err, 1) >= 0.7 and POISON_RX.search(top[0]["msg"]):
                h[RootCause.POISON_MESSAGE].add(0.45, logs, "one repeated payload/parse error dominates")

        ranked = sorted(h.values(), key=lambda x: x.score, reverse=True)
        best = ranked[0]
        if best.score < 0.4:
            inv.finding = Finding(
                RootCause.UNKNOWN,
                svc,
                "No hypothesis is supported strongly enough; escalate to a human with the evidence gathered.",
                round(best.score, 2),
                sorted({deps.id, err.id, logs.id}),
            )
            return
        inv.finding = Finding(
            root_cause=best.cause,
            service=svc,
            summary="; ".join(best.notes),
            confidence=round(min(best.score, 0.99), 2),
            evidence_ids=sorted(best.evidence),
            alternatives=[(x.cause.value, round(x.score, 2)) for x in ranked[1:3] if x.score > 0],
        )
