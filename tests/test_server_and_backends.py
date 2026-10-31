import asyncio
import json
import time

import httpx
from conftest import load
from fastapi.testclient import TestClient

from sre_agent.agent import Agent, AgentConfig
from sre_agent.config import Settings
from sre_agent.investigators.rule_based import RuleBasedInvestigator
from sre_agent.mcp_server import build_server
from sre_agent.server import create_app
from sre_agent.tools.backends import FixtureBackend, LiveBackend


def make_app(tmp_path, token=None):
    scenario, alert = load("01-bad-deploy-api.yaml")
    settings = Settings(webhook_token=token, slack_webhook_url=None, dedupe_minutes=15)

    def factory():
        return Agent(
            FixtureBackend(scenario, alert),
            RuleBasedInvestigator(),
            AgentConfig(audit_path=str(tmp_path / "a.jsonl")),
        )

    return TestClient(create_app(factory, settings))


AM_PAYLOAD = {
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "ApiErrorBudgetFastBurn",
                "service": "api",
                "namespace": "orders",
                "severity": "page",
            },
            "annotations": {"summary": "burning"},
            "startsAt": "2026-06-30T10:00:00Z",
        },
        {"status": "resolved", "labels": {"alertname": "Other"}, "startsAt": "2026-06-30T09:00:00Z"},
    ]
}


def wait_done(client, inv_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        item = client.get(f"/investigations/{inv_id}").json()
        if item["status"] != "running":
            return item
        time.sleep(0.05)
    raise AssertionError("investigation did not finish")


def test_webhook_runs_investigation_and_dedupes(tmp_path):
    client = make_app(tmp_path)
    accepted = client.post("/webhook/alertmanager", json=AM_PAYLOAD).json()["accepted"]
    assert len(accepted) == 1  # resolved alert ignored
    item = wait_done(client, accepted[0])
    assert item["status"] == "done"
    assert item["investigation"]["finding"]["root_cause"] == "bad_deploy"
    assert "# Incident report" in client.get(f"/investigations/{accepted[0]}/report").text
    # Same alert again within the dedupe window is skipped
    assert client.post("/webhook/alertmanager", json=AM_PAYLOAD).json()["accepted"] == []
    assert "sre_agent_investigations_total" in client.get("/metrics").text


def test_webhook_token(tmp_path):
    client = make_app(tmp_path, token="s3cret")
    assert client.post("/webhook/alertmanager", json=AM_PAYLOAD).status_code == 401
    ok = client.post("/webhook/alertmanager", json=AM_PAYLOAD, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 202


def test_live_backend_parses_prometheus_and_loki():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/query_range":
            assert 'service="api"' in request.url.params["query"]
            return httpx.Response(
                200,
                json={
                    "data": {
                        "result": [
                            {"values": [[1751277600, "0.01"], [1751277660, "NaN"], [1751277720, "0.2"]]}
                        ]
                    }
                },
            )
        if request.url.path == "/loki/api/v1/query_range":
            assert request.url.params["query"].startswith('{namespace="orders", app="api"}')
            return httpx.Response(
                200,
                json={
                    "data": {
                        "result": [
                            {"stream": {"level": "error"}, "values": [["1751277600000000000", "boom"]]},
                            {
                                "stream": {},
                                "values": [["1751277601000000000", '{"level":"info","msg":"ok"}']],
                            },
                        ]
                    }
                },
            )
        return httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    b = LiveBackend("http://prom", "http://loki", http=http, kube={})
    m = b.metric("error_rate", "orders", "api", 60)
    assert [v for _, v in m["points"]] == [0.01, 0.2]  # NaN dropped
    logs = b.logs("orders", "api", "", "error", 30, 10)
    assert [entry["msg"] for entry in logs] == ["boom"]  # info line filtered by level


def test_mcp_server_exposes_only_read_only_tools(tmp_path):
    scenario, alert = load("11-prompt-injection.yaml")
    server = build_server(FixtureBackend(scenario, alert), audit_path=str(tmp_path / "m.jsonl"))
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"recent_deployments", "query_metric", "search_logs", "get_events", "get_pods"}
    assert all(t.annotations.read_only_hint for t in tools)

    result = asyncio.run(server.call_tool("search_logs", {"namespace": "orders", "service": "api"}))
    text = json.dumps(result, default=str)
    assert "4111 1111" not in text and "REDACTED" in text and "instruction-like" in text
