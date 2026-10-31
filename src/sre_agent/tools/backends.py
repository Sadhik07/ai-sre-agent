"""Telemetry backends behind the tools.

`FixtureBackend` replays a recorded incident (used by the evaluation harness,
the demo and tests). `LiveBackend` talks to Prometheus, Loki and the
Kubernetes API. Both satisfy the same `Backend` protocol, so investigators
cannot tell them apart.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any, Protocol

import httpx
import yaml

from sre_agent.models import Alert

SIGNALS: dict[str, dict[str, str]] = yaml.safe_load(
    resources.files("sre_agent").joinpath("signals.yaml").read_text()
)
LEVELS = ["debug", "info", "warning", "error", "critical"]


class Backend(Protocol):
    def deployments(self, namespace: str, service: str | None, minutes: int) -> list[dict[str, Any]]: ...
    def metric(self, signal: str, namespace: str, service: str, minutes: int) -> dict[str, Any]: ...
    def logs(
        self, namespace: str, service: str, query: str, level: str, minutes: int, limit: int
    ) -> list[dict[str, Any]]: ...
    def events(self, namespace: str, minutes: int) -> list[dict[str, Any]]: ...
    def pods(self, namespace: str, service: str) -> list[dict[str, Any]]: ...
    def rollback(self, namespace: str, service: str) -> dict[str, Any]: ...
    def restart(self, namespace: str, service: str) -> dict[str, Any]: ...
    def scale(self, namespace: str, service: str, replicas: int) -> dict[str, Any]: ...


def expand_series(spec: list[list[float]] | dict[str, float]) -> list[tuple[float, float]]:
    """Fixture metric series: an explicit [[minute, value], ...] list, or a step
    shorthand {baseline, after, change_at, from, to, step} for a level shift."""
    if isinstance(spec, list):
        return [(float(m), float(v)) for m, v in spec]
    start, end, step = spec.get("from", -60), spec.get("to", 5), spec.get("step", 2.5)
    out, m = [], float(start)
    while m <= end:
        out.append((m, spec["after"] if m >= spec["change_at"] else spec["baseline"]))
        m += step
    return out


def _level_ok(entry_level: str, minimum: str) -> bool:
    try:
        return LEVELS.index(entry_level.lower()) >= LEVELS.index(minimum.lower())
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Fixture backend (recorded incidents)
# ---------------------------------------------------------------------------
class FixtureBackend:
    """Serves a scenario's telemetry. Times in the fixture are minute offsets
    relative to the alert start, which keeps scenarios short to write."""

    def __init__(self, scenario: dict[str, Any], alert: Alert) -> None:
        self.t = scenario.get("telemetry", {})
        self.t0 = alert.starts_at
        self.now = self.t0 + timedelta(minutes=scenario.get("now_offset_min", 5))
        self.actions: list[dict[str, Any]] = []

    def _at(self, offset_min: float) -> datetime:
        return self.t0 + timedelta(minutes=offset_min)

    def _recent(self, offset_min: float, minutes: int) -> bool:
        return self.now - timedelta(minutes=minutes) <= self._at(offset_min) <= self.now

    def deployments(self, namespace, service, minutes):
        out = []
        for d in self.t.get("deployments", []):
            if service and d["service"] != service:
                continue
            if self._recent(d["at_min"], minutes):
                out.append(
                    {**{k: v for k, v in d.items() if k != "at_min"}, "at": self._at(d["at_min"]).isoformat()}
                )
        return out

    def metric(self, signal, namespace, service, minutes):
        if signal not in SIGNALS:
            raise ValueError(f"unknown signal '{signal}'; choose from {sorted(SIGNALS)}")
        series = expand_series(self.t.get("metrics", {}).get(signal, {}).get(service, []))
        points = [[self._at(m).isoformat(), v] for m, v in series if self._recent(m, minutes)]
        return {"signal": signal, "service": service, "unit": SIGNALS[signal]["unit"], "points": points}

    def logs(self, namespace, service, query, level, minutes, limit):
        rx = re.compile(query, re.IGNORECASE) if query else None
        out = []
        for e in self.t.get("logs", []):
            if e["service"] != service or not self._recent(e["at_min"], minutes):
                continue
            if not _level_ok(e.get("level", "info"), level) or (rx and not rx.search(e["msg"])):
                continue
            for _ in range(e.get("repeat", 1)):
                out.append(
                    {
                        "ts": self._at(e["at_min"]).isoformat(),
                        "level": e.get("level", "info"),
                        "msg": e["msg"],
                        **({"version": e["version"]} if "version" in e else {}),
                    }
                )
        return out[:limit] if limit else out

    def events(self, namespace, minutes):
        return [
            {**{k: v for k, v in e.items() if k != "at_min"}, "ts": self._at(e["at_min"]).isoformat()}
            for e in self.t.get("events", [])
            if self._recent(e["at_min"], minutes)
        ]

    def pods(self, namespace, service):
        return [p for p in self.t.get("pods", []) if p.get("service") == service]

    def _act(self, kind, **kw):
        self.actions.append({"action": kind, **kw})
        return {"status": "ok", "simulated": True, "action": kind, **kw}

    def rollback(self, namespace, service):
        return self._act("rollback", namespace=namespace, service=service)

    def restart(self, namespace, service):
        return self._act("restart", namespace=namespace, service=service)

    def scale(self, namespace, service, replicas):
        return self._act("scale", namespace=namespace, service=service, replicas=replicas)


# ---------------------------------------------------------------------------
# Live backend
# ---------------------------------------------------------------------------
class LiveBackend:
    """Prometheus + Loki over HTTP, Kubernetes via the official client.

    Kubernetes access is optional (`pip install sre-agent[k8s]`); without it,
    the k8s tools return an explanatory error instead of failing the run.
    """

    def __init__(
        self,
        prometheus_url: str,
        loki_url: str | None = None,
        service_label: str = "app",
        http: httpx.Client | None = None,
        kube: Any | None = None,
    ) -> None:
        self.prom = prometheus_url.rstrip("/")
        self.loki = loki_url.rstrip("/") if loki_url else None
        self.service_label = service_label
        self.http = http or httpx.Client(timeout=15)
        self.kube = kube if kube is not None else _load_kube()

    # ---- metrics / logs --------------------------------------------------
    def metric(self, signal, namespace, service, minutes):
        if signal not in SIGNALS:
            raise ValueError(f"unknown signal '{signal}'; choose from {sorted(SIGNALS)}")
        query = SIGNALS[signal]["query"].replace("{service}", service).replace("{namespace}", namespace)
        end = datetime.now(UTC)
        step = max(15, minutes * 60 // 60)
        resp = self.http.get(
            f"{self.prom}/api/v1/query_range",
            params={
                "query": query,
                "start": (end - timedelta(minutes=minutes)).timestamp(),
                "end": end.timestamp(),
                "step": step,
            },
        )
        resp.raise_for_status()
        result = resp.json()["data"]["result"]
        values = result[0]["values"] if result else []
        points = [
            [datetime.fromtimestamp(float(ts), UTC).isoformat(), float(v)]
            for ts, v in values
            if v not in ("NaN", "+Inf", "-Inf")
        ]
        return {"signal": signal, "service": service, "unit": SIGNALS[signal]["unit"], "points": points}

    def logs(self, namespace, service, query, level, minutes, limit):
        if not self.loki:
            raise RuntimeError("no Loki URL configured")
        logql = f'{{namespace="{namespace}", {self.service_label}="{service}"}}'
        if query:
            logql += f' |~ "(?i){query.replace(chr(34), "")}"'
        end = datetime.now(UTC)
        resp = self.http.get(
            f"{self.loki}/loki/api/v1/query_range",
            params={
                "query": logql,
                "start": int((end - timedelta(minutes=minutes)).timestamp() * 1e9),
                "end": int(end.timestamp() * 1e9),
                "limit": max(limit, 1) * 5,
                "direction": "backward",
            },
        )
        resp.raise_for_status()
        out = []
        for stream in resp.json()["data"]["result"]:
            stream_level = stream.get("stream", {}).get("level", "")
            for ts, line in stream["values"]:
                lvl = stream_level or _guess_level(line)
                if _level_ok(lvl or "info", level):
                    out.append(
                        {
                            "ts": datetime.fromtimestamp(int(ts) / 1e9, UTC).isoformat(),
                            "level": lvl or "unknown",
                            "msg": line[:500],
                        }
                    )
        return out[:limit]

    # ---- kubernetes --------------------------------------------------------
    def _need_kube(self):
        if self.kube is None:
            raise RuntimeError("Kubernetes client not available (pip install 'sre-agent[k8s]')")
        return self.kube

    def events(self, namespace, minutes):
        core = self._need_kube()["core"]
        cutoff = datetime.now(UTC) - timedelta(minutes=minutes)
        out = []
        for e in core.list_namespaced_event(namespace).items:
            ts = e.last_timestamp or e.event_time or e.metadata.creation_timestamp
            if ts and ts >= cutoff:
                out.append(
                    {
                        "ts": ts.isoformat(),
                        "type": e.type,
                        "reason": e.reason,
                        "object": f"{e.involved_object.kind}/{e.involved_object.name}",
                        "message": (e.message or "")[:300],
                        "count": e.count or 1,
                    }
                )
        return sorted(out, key=lambda x: x["ts"])

    def pods(self, namespace, service):
        core = self._need_kube()["core"]
        out = []
        for p in core.list_namespaced_pod(namespace, label_selector=f"{self.service_label}={service}").items:
            statuses = p.status.container_statuses or []
            last = next(
                (
                    s.last_state.terminated.reason
                    for s in statuses
                    if s.last_state and s.last_state.terminated
                ),
                None,
            )
            waiting = next((s.state.waiting.reason for s in statuses if s.state and s.state.waiting), None)
            out.append(
                {
                    "name": p.metadata.name,
                    "service": service,
                    "phase": p.status.phase,
                    "ready": all(s.ready for s in statuses) if statuses else False,
                    "restarts": sum(s.restart_count for s in statuses),
                    "last_termination_reason": last,
                    "waiting_reason": waiting,
                    "node": p.spec.node_name,
                    "version": (p.spec.containers[0].image.rsplit(":", 1) + [""])[1],
                }
            )
        return out

    def deployments(self, namespace, service, minutes):
        apps = self._need_kube()["apps"]
        cutoff = datetime.now(UTC) - timedelta(minutes=minutes)
        selector = f"{self.service_label}={service}" if service else None
        rs = apps.list_namespaced_replica_set(namespace, label_selector=selector).items
        rs = sorted(rs, key=lambda r: r.metadata.creation_timestamp)
        out = []
        for prev, cur in zip([None, *rs[:-1]], rs, strict=False):
            created = cur.metadata.creation_timestamp
            if created < cutoff:
                continue
            svc = (cur.metadata.labels or {}).get(self.service_label, service or "unknown")
            image = cur.spec.template.spec.containers[0].image
            prev_image = prev.spec.template.spec.containers[0].image if prev else None
            out.append(
                {
                    "service": svc,
                    "version": image.rsplit(":", 1)[-1],
                    "previous_version": prev_image.rsplit(":", 1)[-1] if prev_image else None,
                    "at": created.isoformat(),
                    "by": "kubernetes",
                }
            )
        return out

    def rollback(self, namespace, service):
        # Argo Rollouts: abort returns traffic to the stable ReplicaSet
        # (same as `kubectl argo rollouts abort`)
        custom = self._need_kube()["custom"]
        custom.patch_namespaced_custom_object_status(
            "argoproj.io", "v1alpha1", namespace, "rollouts", service, {"status": {"abort": True}}
        )
        return {"status": "ok", "action": "rollout_abort", "service": service}

    def restart(self, namespace, service):
        apps = self._need_kube()["apps"]
        now = datetime.now(UTC).isoformat()
        apps.patch_namespaced_deployment(
            service,
            namespace,
            {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": now}}}}},
        )
        return {"status": "ok", "action": "restart", "service": service}

    def scale(self, namespace, service, replicas):
        apps = self._need_kube()["apps"]
        apps.patch_namespaced_deployment_scale(service, namespace, {"spec": {"replicas": replicas}})
        return {"status": "ok", "action": "scale", "service": service, "replicas": replicas}


def _guess_level(line: str) -> str:
    m = re.search(r'"?level"?\s*[:=]\s*"?(\w+)', line, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _load_kube() -> dict[str, Any] | None:
    try:
        from kubernetes import client, config
    except ImportError:
        return None
    try:
        config.load_incluster_config()
    except Exception:  # noqa: BLE001 - fall back to local kubeconfig
        try:
            config.load_kube_config()
        except Exception:  # noqa: BLE001
            return None
    return {"core": client.CoreV1Api(), "apps": client.AppsV1Api(), "custom": client.CustomObjectsApi()}


def summarize_logs(entries: list[dict[str, Any]], top: int = 8, sample: int = 5) -> dict[str, Any]:
    """Collapse log lines into counts of normalised messages (numbers and ids masked),
    plus a few raw lines, newest last."""
    norm = Counter(re.sub(r"\b[0-9a-f]{8,}\b|\d+", "#", e["msg"])[:200] for e in entries)
    return {
        "count": len(entries),
        "top_messages": [{"msg": m, "count": c} for m, c in norm.most_common(top)],
        "sample": entries[-sample:] if sample else [],
    }
