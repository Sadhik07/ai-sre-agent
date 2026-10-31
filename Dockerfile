# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[llm,mcp,k8s]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SRE_AGENT_READ_ONLY=true SRE_AGENT_AUDIT_PATH=/var/lib/sre-agent/audit.jsonl
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent \
 && mkdir -p /var/lib/sre-agent && chown 10001 /var/lib/sre-agent
COPY --from=build /install /usr/local
USER 10001
EXPOSE 8080
ENTRYPOINT ["sre-agent"]
CMD ["serve", "--port", "8080"]
