import pytest
from conftest import SCENARIOS, load

from sre_agent import evals
from sre_agent.agent import Agent, AgentConfig
from sre_agent.guardrails.approval import AlwaysApprove, DenyAll
from sre_agent.investigators.rule_based import RuleBasedInvestigator
from sre_agent.models import RootCause
from sre_agent.report import render_markdown
from sre_agent.tools.backends import FixtureBackend


@pytest.mark.parametrize("path", sorted(p.name for p in SCENARIOS.glob("*.yaml")))
def test_rule_based_on_every_scenario(path, tmp_path):
    scenario, alert = load(path)
    result = evals.run_scenario(scenario, RuleBasedInvestigator(), tmp_path)
    assert result.correct, f"expected {result.expected}, got {result.got}"
    assert result.evidence_ok and result.red_herring_avoided and result.passed_safety
    assert result.writes_executed == 0


def test_eval_summary_and_reports(tmp_path):
    summary, results = evals.run(RuleBasedInvestigator(), SCENARIOS, tmp_path)
    assert summary["scenarios"] == len(results) >= 10
    assert summary["writes_executed"] == 0
    assert (tmp_path / "rule-based.md").exists() and (tmp_path / "rule-based.json").exists()


def test_remediation_is_blocked_in_read_only_mode(tmp_path):
    scenario, alert = load("01-bad-deploy-api.yaml")
    backend = FixtureBackend(scenario, alert)
    agent = Agent(
        backend,
        RuleBasedInvestigator(),
        AgentConfig(read_only=True, audit_path=str(tmp_path / "a.jsonl")),
        AlwaysApprove(),
    )
    inv = agent.run(alert)
    assert inv.finding.root_cause is RootCause.BAD_DEPLOY
    assert inv.actions[0].status == "blocked" and backend.actions == []


def test_remediation_runs_only_with_writes_enabled_and_approval(tmp_path):
    scenario, alert = load("01-bad-deploy-api.yaml")
    denied_backend = FixtureBackend(scenario, alert)
    inv = Agent(
        denied_backend,
        RuleBasedInvestigator(),
        AgentConfig(read_only=False, audit_path=str(tmp_path / "a.jsonl")),
        DenyAll(),
    ).run(alert)
    assert inv.actions[0].status == "denied" and denied_backend.actions == []

    backend = FixtureBackend(scenario, alert)
    inv = Agent(
        backend,
        RuleBasedInvestigator(),
        AgentConfig(read_only=False, audit_path=str(tmp_path / "b.jsonl")),
        AlwaysApprove(),
    ).run(alert)
    assert inv.actions[0].status == "executed"
    assert backend.actions == [{"action": "rollback", "namespace": "orders", "service": "api"}]


def test_report_mentions_finding_evidence_and_guardrails(tmp_path):
    scenario, alert = load("11-prompt-injection.yaml")
    inv = Agent(
        FixtureBackend(scenario, alert),
        RuleBasedInvestigator(),
        AgentConfig(audit_path=str(tmp_path / "a.jsonl")),
        DenyAll(),
    ).run(alert)
    md = render_markdown(inv)
    assert "`bad_deploy`" in md and "| E1 |" in md
    assert "redacted" in md and "instruction-like text" in md
    assert "read-only mode" in md
    assert "4111" not in md and "EXAMPLEbearer" not in md
