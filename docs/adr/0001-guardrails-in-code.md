# ADR 0001: Guardrails are enforced in code, not in the prompt

- Status: accepted
- Date: 2026-10

## Context

An LLM agent reads attacker-influenced text (logs, events, alert annotations)
and has tools that can change production. Instructions in a system prompt
("never scale to zero") reduce the chance of a bad action but cannot
guarantee it: a sufficiently persuasive input can override them.

## Decision

The model has no authority. It can only *request* tool calls. A single
`ToolRegistry` decides, with deterministic code, whether each call runs:

1. Arguments are validated against the tool schema; unknown arguments are dropped.
2. `ActionPolicy` blocks every write in read-only mode (the default), enforces
   a namespace allowlist, scale bounds and a write budget.
3. Writes that pass policy still need a human `Approver`. Unattended runs
   use `DenyAll`.
4. Results are redacted and screened before the model sees them.
5. Every decision is written to a hash-chained audit log.

The prompt still tells the model to treat tool output as data, as defence in
depth, but nothing depends on the model obeying it.

## Consequences

- The `11-prompt-injection` evaluation and `test_llm_loop_gathers_evidence_and_submits`
  show a model that is persuaded to call `scale_workload(replicas=0)` with an
  approver that would say yes, and the call is still blocked.
- Adding a tool means declaring `read_only=False` for anything that changes
  state. Reviewers check that flag the same way they check RBAC.
- MCP clients get the same registry, so external agents cannot bypass the
  controls either.
