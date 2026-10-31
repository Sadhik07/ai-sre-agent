# Integration

## Run in Kubernetes

```bash
# optional: API key for the LLM investigator and a webhook token
kubectl -n sre-agent create secret generic sre-agent \
  --from-literal=anthropic-api-key="$ANTHROPIC_API_KEY" \
  --from-literal=webhook-token="$(openssl rand -hex 24)"

kubectl apply -k deploy/k8s
```

It starts read-only, scoped to the `orders` namespace, using the rule-based
investigator. Set `SRE_AGENT_INVESTIGATOR=llm` once the key exists.

## Alertmanager

```yaml
route:
  routes:
    - matchers: ['severity=~"page|ticket"']
      receiver: sre-agent
      continue: true   # keep paging humans as well
receivers:
  - name: sre-agent
    webhook_configs:
      - url: http://sre-agent.sre-agent.svc/webhook/alertmanager
        send_resolved: false
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/secrets/sre-agent/webhook-token
```

Alerts need `service` (or `app`) and `namespace` labels. The PrometheusRules
in the companion `eks-gitops-platform` repository already set them.

Reports: `GET /investigations`, `GET /investigations/<id>/report` (Markdown),
or set `SLACK_WEBHOOK_URL` (or `SLACK_WEBHOOK_URL_FILE`) to post a summary.

## MCP clients (Claude Desktop, Claude Code, IDEs)

The read-only tools are available over MCP (stdio), with the same redaction,
scoping and audit logging:

```json
{
  "mcpServers": {
    "sre-agent": {
      "command": "sre-agent",
      "args": ["mcp", "--prometheus-url", "http://localhost:9090", "--loki-url", "http://localhost:3100"],
      "env": { "SRE_AGENT_NAMESPACES": "orders" }
    }
  }
}
```

Port-forward Prometheus and Loki first, for example
`kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090`.

## Adapting the signals

`src/sre_agent/signals.yaml` maps signal names (`error_rate`, `p95_latency`, ...)
to PromQL. Change the queries to match your metric names. The model never sees
or writes PromQL directly.

## Adding a scenario

Copy a file in `evals/scenarios/`. Times are minute offsets from the alert
start, and a metric can be a list of `[minute, value]` pairs or a step
shorthand `{baseline, after, change_at}`. Set `expected.root_cause`,
`required_evidence_tools` and `red_herrings`, then run `make eval`.
