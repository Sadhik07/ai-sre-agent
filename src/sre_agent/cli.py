"""Command line entry point.

sre-agent investigate --scenario evals/scenarios/01-bad-deploy-api.yaml
sre-agent investigate --alert alert.json --live --investigator llm
sre-agent eval --investigator rules --out evals/results
sre-agent serve --port 8080
sre-agent mcp
sre-agent audit verify audit/audit.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from sre_agent.agent import Agent, AgentConfig
from sre_agent.config import Settings
from sre_agent.guardrails import audit as audit_mod
from sre_agent.guardrails.approval import AlwaysApprove, CliApprover, DenyAll
from sre_agent.models import Alert
from sre_agent.report import render_markdown
from sre_agent.tools.backends import FixtureBackend, LiveBackend


def _investigator(kind: str):
    if kind == "llm":
        from sre_agent.investigators.llm import LLMInvestigator

        return LLMInvestigator()
    from sre_agent.investigators.rule_based import RuleBasedInvestigator

    return RuleBasedInvestigator()


def _live_backend(s: Settings) -> LiveBackend:
    return LiveBackend(s.prometheus_url, s.loki_url, s.service_label)


def cmd_investigate(args: argparse.Namespace) -> int:
    s = Settings()
    if args.scenario:
        scenario = yaml.safe_load(Path(args.scenario).read_text())
        alert = Alert.from_dict(scenario["alert"])
        backend = FixtureBackend(scenario, alert)
    else:
        alert = Alert.from_dict(json.loads(Path(args.alert).read_text()))
        backend = _live_backend(s)
    approver = {"deny": DenyAll(), "cli": CliApprover(), "auto": AlwaysApprove()}[args.approve]
    cfg = AgentConfig(
        read_only=not args.allow_writes, allowed_namespaces=s.allowed_namespaces, audit_path=args.audit
    )
    inv = Agent(backend, _investigator(args.investigator), cfg, approver).run(alert)
    report = render_markdown(inv)
    if args.out:
        Path(args.out).write_text(report)
        print(f"report written to {args.out}")
    else:
        print(report)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from sre_agent import evals

    summary, results = evals.run(_investigator(args.investigator), args.scenarios, args.out)
    print(evals.to_markdown(args.investigator, summary, results))
    return 0 if summary["root_cause_accuracy"] >= args.min_accuracy and summary["writes_executed"] == 0 else 1


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from sre_agent.server import create_app

    s = Settings()

    def factory() -> Agent:
        cfg = AgentConfig(
            read_only=s.read_only, allowed_namespaces=s.allowed_namespaces, audit_path=s.audit_path
        )
        return Agent(_live_backend(s), _investigator(s.investigator), cfg, DenyAll())

    uvicorn.run(create_app(factory, s), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from sre_agent.mcp_server import build_server

    s = Settings()
    backend = LiveBackend(
        args.prometheus_url or s.prometheus_url, args.loki_url or s.loki_url, s.service_label
    )
    build_server(backend, allowed_namespaces=s.allowed_namespaces).run("stdio")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    ok, msg = audit_mod.verify(args.path)
    print(msg)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sre-agent", description="AI SRE incident investigation agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("investigate", help="investigate one alert")
    src = inv.add_mutually_exclusive_group(required=True)
    src.add_argument("--scenario", help="replay a recorded incident (YAML)")
    src.add_argument("--alert", help="alert JSON, investigated against live Prometheus/Loki/Kubernetes")
    inv.add_argument("--investigator", choices=["rules", "llm"], default="rules")
    inv.add_argument(
        "--allow-writes", action="store_true", help="leave read-only mode (writes still need approval)"
    )
    inv.add_argument("--approve", choices=["deny", "cli", "auto"], default="cli")
    inv.add_argument("--audit", default="audit/audit.jsonl")
    inv.add_argument("--out", help="write the Markdown report here")
    inv.set_defaults(func=cmd_investigate)

    ev = sub.add_parser("eval", help="score an investigator on recorded incidents")
    ev.add_argument("--investigator", choices=["rules", "llm"], default="rules")
    ev.add_argument("--scenarios", default="evals/scenarios")
    ev.add_argument("--out", default="evals/results")
    ev.add_argument("--min-accuracy", type=float, default=0.0, help="exit non-zero below this")
    ev.set_defaults(func=cmd_eval)

    sv = sub.add_parser("serve", help="run the Alertmanager webhook service")
    sv.add_argument("--host", default="0.0.0.0")  # noqa: S104 - container entrypoint
    sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(func=cmd_serve)

    mc = sub.add_parser("mcp", help="run the read-only MCP server over stdio")
    mc.add_argument("--prometheus-url")
    mc.add_argument("--loki-url")
    mc.set_defaults(func=cmd_mcp)

    au = sub.add_parser("audit", help="audit log utilities")
    au_sub = au.add_subparsers(dest="audit_cmd", required=True)
    vf = au_sub.add_parser("verify", help="verify the hash chain")
    vf.add_argument("path")
    vf.set_defaults(func=cmd_audit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
