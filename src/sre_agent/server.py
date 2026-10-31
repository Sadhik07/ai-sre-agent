"""HTTP service: receives Alertmanager webhooks and runs investigations.

Alertmanager config (see docs/integration.md):
  receivers:
    - name: sre-agent
      webhook_configs:
        - url: http://sre-agent.sre-agent.svc/webhook/alertmanager
          http_config: { authorization: { credentials_file: /etc/alertmanager/secrets/sre-agent-token } }
          send_resolved: false
"""

from __future__ import annotations

import hmac
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from sre_agent.agent import Agent
from sre_agent.config import Settings
from sre_agent.models import Alert, Investigation
from sre_agent.report import render_markdown

INVESTIGATIONS = Counter("sre_agent_investigations_total", "Investigations run", ["root_cause"])
SKIPPED = Counter("sre_agent_alerts_skipped_total", "Alerts not investigated", ["reason"])
DURATION = Histogram(
    "sre_agent_investigation_seconds", "Investigation wall time", buckets=(1, 5, 15, 30, 60, 120, 300)
)
BLOCKED = Counter("sre_agent_blocked_tool_calls_total", "Tool calls blocked by guardrails", ["tool"])


def create_app(agent_factory: Callable[[], Agent], settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="sre-agent", version="0.1.0")
    pool = ThreadPoolExecutor(max_workers=settings.max_concurrent, thread_name_prefix="investigation")
    store: dict[str, dict[str, Any]] = {}
    recent: dict[tuple[str, str, str], float] = {}
    lock = threading.Lock()

    def check_token(authorization: str | None) -> None:
        if not settings.webhook_token:
            return
        expected = f"Bearer {settings.webhook_token}"
        if not authorization or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid token")

    def is_duplicate(alert: Alert) -> bool:
        key = (alert.name, alert.namespace, alert.service)
        now = time.monotonic()
        with lock:
            last = recent.get(key)
            if last is not None and now - last < settings.dedupe_minutes * 60:
                return True
            recent[key] = now
            return False

    def run(inv_id: str, alert: Alert) -> None:
        start = time.monotonic()
        try:
            inv: Investigation = agent_factory().run(alert)
            report = render_markdown(inv)
            cause = inv.finding.root_cause.value if inv.finding else "none"
            store[inv_id].update(status="done", investigation=inv.to_dict(), report=report)
            INVESTIGATIONS.labels(cause).inc()
            for b in inv.blocked_tool_calls:
                BLOCKED.labels(b["tool"]).inc()
            if settings.slack_webhook_url:
                text = f"*{alert.name}* on `{alert.service}`: root cause `{cause}`\n" + report[:2500]
                httpx.post(settings.slack_webhook_url, json={"text": text}, timeout=10)
        except Exception as exc:  # noqa: BLE001 - record failures, keep serving
            store[inv_id].update(status="failed", error=f"{type(exc).__name__}: {exc}")
        finally:
            DURATION.observe(time.monotonic() - start)

    @app.post("/webhook/alertmanager", status_code=202)
    async def alertmanager(request: Request, authorization: str | None = Header(default=None)):
        check_token(authorization)
        payload = await request.json()
        accepted = []
        for raw in payload.get("alerts", []):
            if raw.get("status") != "firing":
                SKIPPED.labels("not_firing").inc()
                continue
            alert = Alert.from_alertmanager(raw)
            if is_duplicate(alert):
                SKIPPED.labels("duplicate").inc()
                continue
            inv_id = uuid.uuid4().hex[:12]
            store[inv_id] = {"id": inv_id, "status": "running", "alert": alert.name, "service": alert.service}
            pool.submit(run, inv_id, alert)
            accepted.append(inv_id)
        return {"accepted": accepted}

    @app.get("/investigations")
    def list_investigations():
        return [
            {k: v for k, v in i.items() if k in ("id", "status", "alert", "service")} for i in store.values()
        ]

    @app.get("/investigations/{inv_id}")
    def get_investigation(inv_id: str):
        if inv_id not in store:
            raise HTTPException(404, "not found")
        return store[inv_id]

    @app.get("/investigations/{inv_id}/report")
    def get_report(inv_id: str):
        item = store.get(inv_id)
        if not item or "report" not in item:
            raise HTTPException(404, "report not ready")
        return Response(item["report"], media_type="text/markdown")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app
