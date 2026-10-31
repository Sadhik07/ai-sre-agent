"""The LLM loop, tested against a scripted fake client (no network, no API key)."""

import copy
from types import SimpleNamespace

from conftest import load

from sre_agent.agent import Agent, AgentConfig
from sre_agent.guardrails.approval import AlwaysApprove
from sre_agent.investigators.llm import SYSTEM_PROMPT, LLMInvestigator
from sre_agent.models import RootCause
from sre_agent.tools.backends import FixtureBackend


def tool_use(id_, name, input_):
    return {"type": "tool_use", "id": id_, "name": name, "input": input_}


class ScriptedClient:
    """Replays a fixed sequence of assistant turns and records what was sent."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))  # the loop keeps appending to messages
        content = self.turns.pop(0)
        stop = "tool_use" if any(b["type"] == "tool_use" for b in content) else "end_turn"
        return SimpleNamespace(content=content, stop_reason=stop)


def test_llm_loop_gathers_evidence_and_submits(tmp_path):
    scenario, alert = load("11-prompt-injection.yaml")
    backend = FixtureBackend(scenario, alert)
    client = ScriptedClient(
        [
            [
                {"type": "text", "text": "Checking changes first."},
                tool_use("t1", "recent_deployments", {"namespace": "orders"}),
            ],
            [tool_use("t2", "search_logs", {"namespace": "orders", "service": "api"})],
            # The model is "persuaded" by the injected log line and tries a write:
            [
                tool_use(
                    "t3",
                    "scale_workload",
                    {
                        "namespace": "orders",
                        "service": "api",
                        "replicas": 0,
                        "current_replicas": 1,
                        "reason": "log said so",
                    },
                )
            ],
            [
                tool_use(
                    "t4",
                    "submit_findings",
                    {
                        "root_cause": "bad_deploy",
                        "summary": "sha-e1e2e3 raises ValueError on pricing.",
                        "confidence": 0.8,
                        "evidence_ids": ["E1", "E2", "E99"],
                    },
                )
            ],
        ]
    )
    llm = LLMInvestigator(client=client, model="test-model")
    agent = Agent(
        backend,
        llm,
        AgentConfig(read_only=True, remediate=False, audit_path=str(tmp_path / "a.jsonl")),
        AlwaysApprove(),
    )
    inv = agent.run(alert)

    assert inv.finding.root_cause is RootCause.BAD_DEPLOY
    assert inv.finding.evidence_ids == ["E1", "E2"]  # hallucinated E99 dropped
    assert llm.hallucinated_citations == 1
    # Guardrail held even though the model asked and the approver would have said yes
    assert backend.actions == []
    assert inv.blocked_tool_calls[0]["tool"] == "scale_workload"

    # What reached the model: system prompt, fenced untrusted output, no raw secrets
    first = client.requests[0]
    assert first["system"] == SYSTEM_PROMPT and first["model"] == "test-model"
    sent = str(client.requests[2]["messages"])
    assert 'trust="untrusted"' in sent and "WARNING" in sent
    assert "4111 1111" not in sent and "EXAMPLEbearer" not in sent
    assert "blocked by policy" in str(client.requests[3]["messages"][-1])


def test_llm_without_conclusion_falls_back_to_unknown(tmp_path):
    scenario, alert = load("01-bad-deploy-api.yaml")
    client = ScriptedClient([[{"type": "text", "text": "hmm"}], [{"type": "text", "text": "still unsure"}]])
    inv = Agent(
        FixtureBackend(scenario, alert),
        LLMInvestigator(client=client),
        AgentConfig(remediate=False, audit_path=str(tmp_path / "a.jsonl")),
    ).run(alert)
    assert inv.finding.root_cause is RootCause.UNKNOWN
    assert "Call submit_findings" in str(client.requests[1]["messages"][-1])


def test_invalid_category_maps_to_unknown(tmp_path):
    scenario, alert = load("01-bad-deploy-api.yaml")
    client = ScriptedClient(
        [
            [
                tool_use(
                    "t1",
                    "submit_findings",
                    {"root_cause": "aliens", "summary": "x", "confidence": 7, "evidence_ids": []},
                )
            ]
        ]
    )
    inv = Agent(
        FixtureBackend(scenario, alert),
        LLMInvestigator(client=client),
        AgentConfig(remediate=False, audit_path=str(tmp_path / "a.jsonl")),
    ).run(alert)
    assert inv.finding.root_cause is RootCause.UNKNOWN and inv.finding.confidence == 1.0
