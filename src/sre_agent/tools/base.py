"""Tool registry: the single choke point between an investigator and the world.

Every call goes through `ToolRegistry.call`, which applies, in order:
argument validation, policy, human approval (for writes), execution, secret
redaction, prompt-injection screening, evidence numbering and audit logging.
Investigators (rule-based, LLM, or an MCP client) cannot bypass it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sre_agent.guardrails import injection
from sre_agent.guardrails.approval import Approver, DenyAll
from sre_agent.guardrails.audit import AuditLog
from sre_agent.guardrails.policy import ActionPolicy
from sre_agent.guardrails.redaction import Redactor
from sre_agent.models import Evidence, Investigation

_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    func: Callable[..., Any]
    read_only: bool = True
    summarize: Callable[[Any], str] | None = None

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


class ToolError(Exception):
    pass


def validate_args(tool: Tool, args: dict[str, Any]) -> dict[str, Any]:
    props = tool.input_schema.get("properties", {})
    missing = [k for k in tool.input_schema.get("required", []) if k not in args]
    if missing:
        raise ToolError(f"missing required argument(s): {', '.join(missing)}")
    clean: dict[str, Any] = {}
    for key, value in args.items():
        if key not in props:
            continue  # drop unknown arguments instead of passing them through
        expected = _TYPES.get(props[key].get("type", ""), object)
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise ToolError(f"argument '{key}' must be of type {props[key].get('type')}")
        if "enum" in props[key] and value not in props[key]["enum"]:
            raise ToolError(f"argument '{key}' must be one of {props[key]['enum']}")
        clean[key] = value
    return clean


class ToolRegistry:
    def __init__(
        self,
        tools: list[Tool],
        policy: ActionPolicy,
        audit: AuditLog,
        approver: Approver | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self.tools = {t.name: t for t in tools}
        self.policy = policy
        self.audit = audit
        self.approver = approver or DenyAll()
        self.redactor = redactor or Redactor()

    def schemas(self, include_writes: bool = True) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools.values() if include_writes or t.read_only]

    def call(self, name: str, args: dict[str, Any], inv: Investigation) -> Evidence:
        """Run a tool under guardrails. Never raises: failures come back as evidence
        with an `error` field, so an investigator can reason about them."""
        inv.steps += 1
        tool = self.tools.get(name)
        if tool is None:
            return self._failed(inv, name, args, f"unknown tool '{name}'")
        try:
            args = validate_args(tool, args)
        except ToolError as exc:
            return self._failed(inv, name, args, str(exc))

        decision = self.policy.evaluate(name, args, tool.read_only)
        self.audit.record(
            "policy_decision",
            tool=name,
            args=args,
            allowed=decision.allowed,
            requires_approval=decision.requires_approval,
            reason=decision.reason,
        )
        if not decision.allowed:
            inv.blocked_tool_calls.append({"tool": name, "args": args, "reason": decision.reason})
            return self._failed(inv, name, args, f"blocked by policy: {decision.reason}")
        if decision.requires_approval:
            approved = self.approver.approve(name, args, decision.reason)
            self.audit.record("approval", tool=name, args=args, approved=approved)
            if not approved:
                inv.blocked_tool_calls.append({"tool": name, "args": args, "reason": "not approved"})
                return self._failed(inv, name, args, "not approved by a human operator")

        try:
            raw = tool.func(**args)
        except Exception as exc:  # noqa: BLE001 - surface backend errors as evidence
            return self._failed(inv, name, args, f"{type(exc).__name__}: {exc}")
        if not tool.read_only:
            self.policy.record_write()

        data, redactions = self.redactor.redact(raw)
        flagged = injection.scan(data)
        summary = tool.summarize(data) if tool.summarize else _default_summary(data)
        ev = Evidence(
            id=f"E{len(inv.evidence) + 1}",
            tool=name,
            args=args,
            summary=summary,
            data=data,
            redactions=redactions,
            injection_flagged=bool(flagged),
        )
        inv.evidence.append(ev)
        self.audit.record(
            "tool_call",
            tool=name,
            args=args,
            evidence=ev.id,
            summary=summary,
            redactions=redactions,
            injection_matches=len(flagged),
            write=not tool.read_only,
        )
        return ev

    def _failed(self, inv: Investigation, name: str, args: dict[str, Any], error: str) -> Evidence:
        ev = Evidence(
            id=f"E{len(inv.evidence) + 1}",
            tool=name,
            args=args,
            summary=f"error: {error}",
            data={"error": error},
        )
        inv.evidence.append(ev)
        self.audit.record("tool_error", tool=name, args=args, evidence=ev.id, error=error)
        return ev


def _default_summary(data: Any) -> str:
    if isinstance(data, list):
        return f"{len(data)} item(s)"
    if isinstance(data, dict):
        return ", ".join(f"{k}={v}" for k, v in list(data.items())[:4] if not isinstance(v, (list, dict)))
    return str(data)[:200]
