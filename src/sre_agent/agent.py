"""Runs one investigation end to end: gather evidence, conclude, then propose
(and only with policy permission and human approval, execute) a remediation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sre_agent.guardrails.approval import Approver, DenyAll
from sre_agent.guardrails.audit import AuditLog
from sre_agent.guardrails.policy import ActionPolicy
from sre_agent.investigators.base import Investigator
from sre_agent.models import ActionOutcome, Alert, Investigation, ProposedAction, RootCause, utcnow
from sre_agent.tools.backends import Backend
from sre_agent.tools.base import ToolRegistry
from sre_agent.tools.catalog import build_tools

# What a human would usually do first for each root cause. Only some are
# safe to automate; the rest are recommendations in the report.
PLAYBOOK: dict[RootCause, tuple[str | None, str]] = {
    RootCause.BAD_DEPLOY: (
        "rollback_workload",
        "Roll back to the last stable version, then debug the release.",
    ),
    RootCause.RESOURCE_SATURATION: (
        "scale_workload",
        "Add replicas now; then review requests/limits and HPA targets.",
    ),
    RootCause.OOM_KILL: (
        None,
        "Raise the memory limit or fix the leak via a reviewed change; do not hot-patch.",
    ),
    RootCause.CONFIG_ERROR: (
        None,
        "Restore the missing secret/configmap key; the pods recover on their own.",
    ),
    RootCause.IMAGE_PULL: (None, "Check the image tag exists and registry credentials; re-run the pipeline."),
    RootCause.DEPENDENCY_FAILURE: (
        None,
        "Engage the dependency owner; consider failing over or shedding load.",
    ),
    RootCause.DNS_FAILURE: (None, "Check CoreDNS health and the target record; look for recent DNS changes."),
    RootCause.CERTIFICATE_EXPIRY: (None, "Renew/rotate the certificate and check cert-manager or the CA."),
    RootCause.NODE_FAILURE: (None, "Let Karpenter replace the node; cordon it if it flaps."),
    RootCause.POISON_MESSAGE: (None, "Inspect the DLQ message, fix the consumer, then redrive the queue."),
    RootCause.UNKNOWN: (None, "Escalate to the on-call engineer with this evidence."),
}


@dataclass
class AgentConfig:
    read_only: bool = True
    allowed_namespaces: list[str] = field(default_factory=lambda: ["*"])
    audit_path: str = "audit/audit.jsonl"
    remediate: bool = True  # propose (and if permitted, run) the playbook action


class Agent:
    def __init__(
        self,
        backend: Backend,
        investigator: Investigator,
        config: AgentConfig | None = None,
        approver: Approver | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.config = config or AgentConfig()
        self.backend = backend
        self.investigator = investigator
        self.approver = approver or DenyAll()
        Path(self.config.audit_path).parent.mkdir(parents=True, exist_ok=True)
        self.audit = audit or AuditLog(self.config.audit_path)

    def run(self, alert: Alert) -> Investigation:
        policy = ActionPolicy(
            read_only=self.config.read_only, allowed_namespaces=self.config.allowed_namespaces
        )
        tools = ToolRegistry(build_tools(self.backend), policy, self.audit, self.approver)
        inv = Investigation(alert=alert, investigator=self.investigator.name)
        self.audit.record(
            "investigation_started",
            alert=alert.name,
            service=alert.service,
            namespace=alert.namespace,
            investigator=self.investigator.name,
            read_only=self.config.read_only,
        )

        self.investigator.investigate(inv, tools)
        if self.config.remediate and inv.finding:
            self._remediate(inv, tools)

        inv.finished_at = utcnow()
        f = inv.finding
        self.audit.record(
            "investigation_finished",
            alert=alert.name,
            root_cause=f.root_cause.value if f else None,
            confidence=f.confidence if f else None,
            steps=inv.steps,
            blocked_calls=len(inv.blocked_tool_calls),
        )
        return inv

    def _remediate(self, inv: Investigation, tools: ToolRegistry) -> None:
        f = inv.finding
        tool, advice = PLAYBOOK.get(f.root_cause, (None, ""))
        if tool is None:
            return
        args = {"namespace": inv.alert.namespace, "service": inv.alert.service, "reason": advice}
        if tool == "scale_workload":
            current = max(len(self.backend.pods(inv.alert.namespace, inv.alert.service)), 1)
            args.update(current_replicas=current, replicas=current + 2)
        action = ProposedAction(tool, args, advice)
        ev = tools.call(tool, args, inv)
        if isinstance(ev.data, dict) and "error" in ev.data:
            status = "blocked" if "policy" in ev.data["error"] else "denied"
            inv.actions.append(ActionOutcome(action, status, ev.data["error"]))
        else:
            inv.actions.append(ActionOutcome(action, "executed", ev.summary))
