from __future__ import annotations

from typing import Protocol

from sre_agent.models import Investigation
from sre_agent.tools.base import ToolRegistry


class Investigator(Protocol):
    name: str

    def investigate(self, inv: Investigation, tools: ToolRegistry) -> None:
        """Gather evidence through `tools` and set `inv.finding`."""
        ...
