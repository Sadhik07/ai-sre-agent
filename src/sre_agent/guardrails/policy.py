"""Action policy: decides, in code, whether a tool call may run.

Order of checks:
  1. read-only tools always run (subject to namespace scope)
  2. write tools are blocked outright in read-only mode (the default)
  3. namespace allowlist and per-tool blast-radius limits
  4. a cap on write actions per investigation
  5. anything that passes still needs a human approval
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Decision:
    allowed: bool
    requires_approval: bool
    reason: str


@dataclass
class ActionPolicy:
    read_only: bool = True
    allowed_namespaces: list[str] = field(default_factory=lambda: ["*"])
    max_writes_per_investigation: int = 1
    max_scale_replicas: int = 10
    max_scale_step: int = 3
    writes_done: int = 0

    def _namespace_ok(self, args: dict[str, Any]) -> bool:
        ns = args.get("namespace")
        return ns is None or "*" in self.allowed_namespaces or ns in self.allowed_namespaces

    def evaluate(self, tool: str, args: dict[str, Any], read_only_tool: bool) -> Decision:
        if not self._namespace_ok(args):
            return Decision(False, False, f"namespace '{args.get('namespace')}' is outside the allowlist")
        if read_only_tool:
            return Decision(True, False, "read-only tool")
        if self.read_only:
            return Decision(False, False, "agent is in read-only mode; write actions are disabled")
        if self.writes_done >= self.max_writes_per_investigation:
            return Decision(False, False, "write-action budget for this investigation is used up")
        if tool == "scale_workload":
            target = int(args.get("replicas", 0))
            current = int(args.get("current_replicas", target))
            if target > self.max_scale_replicas:
                return Decision(False, False, f"scale target {target} exceeds max {self.max_scale_replicas}")
            if target < 1:
                return Decision(False, False, "scaling to zero is never automated")
            if abs(target - current) > self.max_scale_step:
                return Decision(False, False, f"scale step larger than {self.max_scale_step}")
        return Decision(True, True, "write action within policy; human approval required")

    def record_write(self) -> None:
        self.writes_done += 1
