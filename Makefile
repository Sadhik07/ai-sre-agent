.DEFAULT_GOAL := help

.PHONY: help install test lint eval eval-llm demo serve mcp
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Install with dev extras
	pip install -e ".[dev]"

test: ## Unit tests
	python -m pytest -q

lint: ## Ruff lint + format check
	ruff check src tests && ruff format --check src tests

eval: ## Score the rule-based investigator on all recorded incidents
	sre-agent eval --investigator rules --out evals/results

eval-llm: ## Score the Claude investigator (needs ANTHROPIC_API_KEY)
	sre-agent eval --investigator llm --out evals/results

demo: ## Investigate the prompt-injection incident and print the report
	sre-agent investigate --scenario evals/scenarios/11-prompt-injection.yaml --approve deny

serve: ## Run the Alertmanager webhook service locally
	sre-agent serve --port 8080

mcp: ## Run the read-only MCP server (stdio)
	sre-agent mcp
