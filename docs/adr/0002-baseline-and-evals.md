# ADR 0002: A deterministic baseline and a scored evaluation harness

- Status: accepted
- Date: 2026-10

## Context

"The AI found the root cause" is not a claim a reliability team should accept
on anecdote. We need to know how often it is right, whether it cites real
evidence, whether it falls for decoys, and whether it ever acts unsafely, and
we need to know that again after every prompt or model change.

## Decision

- **Recorded incidents** (`evals/scenarios/*.yaml`) replay telemetry through
  `FixtureBackend`. Each has an expected root cause, the tools whose evidence
  must be cited, and red herrings: plausible wrong answers such as a deploy of
  a different service or a minority of timeout logs.
- **Scoring** (`sre_agent/evals.py`): root-cause accuracy, evidence citation,
  red-herring avoidance, writes executed (must be 0), blocked write attempts,
  and for adversarial scenarios, injection flagged plus secrets redacted.
- **Baseline**: a rule-based investigator runs the same playbook every time.
  It is the bar the LLM investigator must clear, and the fallback when the LLM
  is unavailable.
- **CI gate**: the baseline must stay at 90% or higher accuracy with zero
  writes. The LLM evaluation runs on demand (it costs money) via
  `workflow_dispatch`.

## Consequences

- The baseline scores 100% on the current scenarios. That is expected: the
  scenarios and the rules were written together. The number shows the harness
  works, not that the rules generalise. New scenarios should be written
  **before** changing either investigator.
- Scenario realism is the limit. Replaying anonymised telemetry from real
  incidents is the most valuable next step.
