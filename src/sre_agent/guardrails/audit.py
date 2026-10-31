"""Append-only, tamper-evident audit log.

Each JSON line carries the SHA-256 of the previous line, so editing or deleting
any past entry breaks the chain, and `sre-agent audit verify` reports where.
Every tool call, policy decision, approval and action is recorded.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from sre_agent.models import utcnow

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last_line = self.path.read_text().strip().splitlines()[-1]
        return json.loads(last_line)["hash"]

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            entry = {"ts": utcnow().isoformat(), "event": event, **fields, "prev": self._last}
            entry["hash"] = _digest(entry)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            self._last = entry["hash"]
            return entry


def verify(path: str | os.PathLike[str]) -> tuple[bool, str]:
    """Check the whole chain. Returns (ok, message)."""
    prev = GENESIS
    p = Path(path)
    if not p.exists():
        return False, f"{p} does not exist"
    for n, line in enumerate(p.read_text().splitlines(), start=1):
        entry = json.loads(line)
        claimed = entry.pop("hash")
        if entry.get("prev") != prev:
            return False, f"line {n}: chain broken (prev hash mismatch)"
        if _digest(entry) != claimed:
            return False, f"line {n}: entry was modified"
        prev = claimed
    return True, "audit chain intact"
