"""Human-in-the-loop approval for write actions."""

from __future__ import annotations

import sys
from typing import Any, Protocol


class Approver(Protocol):
    def approve(self, tool: str, args: dict[str, Any], reason: str) -> bool: ...


class DenyAll:
    """Default for unattended runs: never approve a write."""

    def approve(self, tool: str, args: dict[str, Any], reason: str) -> bool:
        return False


class CliApprover:
    """Asks the operator on the terminal. Anything but an explicit 'yes' is a no."""

    def approve(self, tool: str, args: dict[str, Any], reason: str) -> bool:
        if not sys.stdin.isatty():
            return False
        print(f"\nThe agent wants to run: {tool} {args}\nReason: {reason}")
        return input("Type 'yes' to approve: ").strip().lower() == "yes"


class AlwaysApprove:
    """For tests and evaluations only."""

    def approve(self, tool: str, args: dict[str, Any], reason: str) -> bool:
        return True
