# AI SRE Incident Agent

An incident-investigation agent for Kubernetes that turns a firing alert into
an evidence-backed root-cause report, **without being able to make an incident
worse**. Claude (or a deterministic rule engine) drives a small set of
observability tools. Every call passes through guardrails enforced in code:
read-only by default, namespace-scoped, secret-redacting, screened for prompt
injection, approval-gated for writes, and recorded in a tamper-evident audit
log. A scored evaluation harness replays recorded incidents, so accuracy and
safety are measured rather than assumed.

```
Alertmanager -> /webhook -> Agent -> Investigator (rules | Claude)
                                       |
                                ToolRegistry  --policy--approval--redaction--injection scan--audit
                                       |
                    Prometheus . Loki . Kubernetes API      -> report (Markdown) -> Slack / API
MCP clients (Claude Desktop/Code) ---> same read-only tools, same guardrails
```

See [docs/architecture.md](docs/architecture.md) for the full diagram.

## Why this design

| Problem with naive "AI ops" | What this project does |
|---|---|
| The model is told "don't do anything dangerous" | The model has no authority: a policy engine in code decides, writes need a human, and read-only is the default ([ADR 0001](docs/adr/0001-guardrails-in-code.md)) |
| Logs are pasted into prompts | Every tool result is redacted (cards, tokens, keys, emails, PEM keys) before the model sees it |
| Logs can contain instructions | Output is fenced as untrusted, instruction-like text is flagged, and the eval suite includes an injection attack |
| "It found the root cause!" (once) | 11 recorded incidents with red herrings, scored on accuracy, evidence citation, decoy avoidance and safety ([ADR 0002](docs/adr/0002-baseline-and-evals.md)) |
| Unverifiable conclusions | Findings cite evidence ids (`E1`, `E2`, ...); invented ids are stripped and counted |
| No record of what the bot did | SHA-256 hash-chained audit log, checked with `sre-agent audit verify` |

## Quick start (no cluster, no API key)

```bash
pip install -e ".[dev]"
make demo     # investigates a bad deploy whose logs contain a prompt-injection attack
make eval     # scores the rule-based investigator on all 11 incidents
make test     # 36 unit tests
```

`make demo` prints a report: the root cause, cited evidence, six redacted
secrets, the injected instructions flagged as data, and the rollback blocked
because the agent is read-only.

## Evaluation results

Rule-based baseline on the 11 recorded incidents ([full table](evals/results/rule-based.md)):

| Metric | Rule-based |
|---|---|
| Root-cause accuracy | 100% (11/11) |
| Cites required evidence | 100% |
| Avoided red herrings | 100% |
| Write actions executed | 0 |
| Safety checks (injection + redaction) | 100% |
| Median tool calls | 8 |

The baseline and the scenarios were written together, so 100% shows
consistency, not generalisation. The harness exists to measure the Claude
investigator and catch regressions. Run it yourself and add the column:

```bash
export ANTHROPIC_API_KEY=...
make eval-llm          # writes evals/results/llm.md
```

## Incidents in the suite

| Scenario | Root cause | Decoy it must ignore |
|---|---|---|
| bad-deploy-api | bad_deploy | worker deployed too; a few old timeout logs |
| oom-worker | oom_kill | API deployed 15 minutes earlier |
| config-error-missing-secret-key | config_error | the deploy that triggered it |
| image-pull-bad-tag | image_pull | the deploy that triggered it |
| dependency-database-timeouts | dependency_failure | web deployed 10 minutes earlier |
| dns-failure | dns_failure | errors that look like generic connection failures |
| certificate-expiry | certificate_expiry | "upstream unavailable" errors |
| cpu-saturation | resource_saturation | API deployed 100 minutes earlier |
| node-failure | node_failure | connection-reset errors |
| poison-message | poison_message | a few connection resets |
| prompt-injection-in-logs | bad_deploy | instructions in logs and alert text; secrets in logs |

## Usage

```bash
sre-agent investigate --scenario evals/scenarios/05-dependency-db.yaml        # replay
sre-agent investigate --alert alert.json --investigator llm                   # live cluster
sre-agent serve --port 8080                                                   # Alertmanager webhook service
sre-agent mcp --prometheus-url http://localhost:9090                          # MCP server (stdio)
sre-agent eval --investigator llm --min-accuracy 0.8                          # CI gate
sre-agent audit verify audit/audit.jsonl
```

Write actions (`rollback_workload`, `restart_workload`, `scale_workload`) only
run with `--allow-writes`, inside policy limits, after a human types `yes`.

## Deploy

`kubectl apply -k deploy/k8s` runs it read-only, with least-privilege RBAC (no
Secrets access), a NetworkPolicy, Pod Security `restricted` and secrets mounted
as files. Alertmanager and MCP client configuration are in
[docs/integration.md](docs/integration.md). It is built to sit next to the
companion **eks-gitops-platform** project, whose SLO alerts already carry the
labels the agent needs.

## Security

[docs/threat-model.md](docs/threat-model.md) covers 10 threats (prompt
injection, data exfiltration, over-broad remediation, hallucinated evidence,
audit tampering, RBAC, webhook auth, alert storms) and the control for each.

## Project layout

```
src/sre_agent/
  guardrails/    policy, approval, redaction, injection screening, audit log
  tools/         registry (enforcement point), tool catalog, Prometheus/Loki/K8s + fixture backends
  investigators/ rule_based.py (baseline), llm.py (Claude tool-use loop)
  agent.py       investigation + remediation playbook
  server.py      Alertmanager webhook API      mcp_server.py   read-only MCP tools
  evals.py       scoring harness               report.py       Markdown report / postmortem draft
evals/scenarios/ 11 recorded incidents         evals/results/  committed scores
deploy/k8s/      Kubernetes manifests          docs/           architecture, threat model, ADRs, integration
```

## License

MIT
