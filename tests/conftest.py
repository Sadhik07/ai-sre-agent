from pathlib import Path

import pytest
import yaml

from sre_agent.guardrails.audit import AuditLog
from sre_agent.models import Alert

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "evals" / "scenarios"


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def load(name: str) -> tuple[dict, Alert]:
    scenario = yaml.safe_load((SCENARIOS / name).read_text())
    return scenario, Alert.from_dict(scenario["alert"])
