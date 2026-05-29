# mcp-audit

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8)
[![CI](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml)
[![mcp-audit MCP server](https://glama.ai/mcp/servers/P4ST4S/mcp-audit/badges/score.svg)](https://glama.ai/mcp/servers/P4ST4S/mcp-audit)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)
![Status](https://img.shields.io/badge/Status-beta-yellow)
[![GitHub Discussions](https://img.shields.io/badge/discussions-join-blue?logo=github)](https://github.com/P4ST4S/mcp-audit/discussions)

A drop-in security and observability proxy for MCP servers. `mcp-audit` sits between an MCP client and any upstream MCP server to produce signed audit trails, redact sensitive payloads, enforce allow/deny policies and per-tool rate limits, and expose a local read-only dashboard.

## Why mcp-audit?

[The MCP 2026 roadmap](https://modelcontextprotocol.io/development/roadmap) calls out enterprise needs around audit trails, gateway patterns, and operational visibility. `mcp-audit` fills that gap as a deployable sidecar or local wrapper: it sits between any MCP client and server, preserves protocol traffic, and records signed audit entries for tool calls, resource reads, prompt requests, and all other JSON-RPC methods.

```text
+-------------+    JSON-RPC / MCP     +-----------+      JSON-RPC / MCP     +-------------+
| MCP client  | <-------------------> | mcp-audit | <---------------------> | MCP server  |
+-------------+                       +-----------+                         +-------------+
                                            |
                                            v
                                JSONL or SQLite audit log
                                            |
                                            v
                                   Read-only dashboard
```

## What This Is / Is Not

`mcp-audit` is not a domain-specific MCP server. It is a transparent security and observability proxy that wraps any MCP server and audits the JSON-RPC traffic passing through it.

Directories may show the tools exposed by the upstream server, not tools implemented by `mcp-audit` itself.

## Supported Transports

- `stdio` for local MCP clients such as Claude Desktop
- `http` for MCP servers exposed over HTTP

HTTP upstreams can use custom CA bundles, TLS server name overrides, and optional mTLS client certificates. Upstream retries are disabled by default and only apply to conservative, idempotent JSON-RPC methods when enabled; `tools/call` is not retried.

## Use Cases

- Audit tool calls made by AI agents in regulated environments
- Detect unexpected or dangerous MCP tool usage
- Keep signed JSONL or SQLite logs for incident review
- Redact sensitive fields before storing requests and responses
- Block disallowed tools and apply per-tool rate limits without modifying the upstream MCP server

## Demo

![mcp-audit demo](demo/mcp-audit-demo.gif)

## Install

Download a prebuilt binary from [GitHub Releases](https://github.com/P4ST4S/mcp-audit/releases):

```bash
curl -L -o mcp-audit.tar.gz \
  https://github.com/P4ST4S/mcp-audit/releases/download/v0.9.0/mcp-audit_v0.9.0_linux_amd64.tar.gz
curl -L -o mcp-audit_checksums.txt \
  https://github.com/P4ST4S/mcp-audit/releases/download/v0.9.0/mcp-audit_v0.9.0_checksums.txt
sha256sum -c mcp-audit_checksums.txt --ignore-missing
tar -xzf mcp-audit.tar.gz
./mcp-audit --version
```

Run with Docker:

```bash
docker run --rm ghcr.io/p4st4s/mcp-audit:v0.9.0 --version
```

Or install with Go:

```bash
go install github.com/P4ST4S/mcp-audit/cmd/mcp-audit@v0.9.0
```

## Quick Start

Run in stdio mode:

```bash
AUDIT_SECRET="$(openssl rand -hex 32)" \
mcp-audit --transport stdio --upstream "npx @modelcontextprotocol/server-filesystem /tmp"
```

Run in HTTP mode:

```bash
mcp-audit --transport http --upstream http://localhost:8080 --port 4422
```

Run with Docker Compose:

```bash
docker compose up --build
```

The dashboard is available at `http://localhost:9090` by default.
Prometheus metrics are available at `http://localhost:9091/metrics` by default.

## Examples

- [Cursor stdio configuration](examples/cursor/README.md)

## Configuration

`mcp-audit` loads `config.yaml` from the current directory by default. CLI flags override config values, and `AUDIT_SECRET` overrides `audit.secret`.

| Key | Default | Description |
| --- | --- | --- |
| `proxy.transport` | `stdio` | Proxy transport: `stdio` or `http`. |
| `proxy.upstream` | required | Stdio command or HTTP upstream URL. |
| `proxy.port` | `4422` | HTTP listen port. |
| `proxy.upstream_timeout_ms` | `30000` | HTTP upstream request timeout in milliseconds. |
| `proxy.tls.ca_file` | empty | Optional CA bundle used to verify an HTTPS upstream MCP server. |
| `proxy.tls.server_name` | empty | Optional TLS server name override for the upstream MCP server. |
| `proxy.tls.insecure_skip_verify` | `false` | Skip upstream TLS certificate verification. Intended only for local testing. |
| `proxy.tls.client_cert_file` | empty | Optional client certificate for upstream mTLS. Must be configured with `proxy.tls.client_key_file`. |
| `proxy.tls.client_key_file` | empty | Optional client key for upstream mTLS. Must be configured with `proxy.tls.client_cert_file`. |
| `proxy.retry.max_retries` | `0` | Maximum conservative retry attempts for safe HTTP upstream requests. Off by default. |
| `proxy.retry.initial_interval_ms` | `200` | Initial upstream retry backoff. |
| `proxy.retry.max_interval_ms` | `2000` | Maximum upstream retry backoff. |
| `proxy.client_id` | `claude-desktop` | Client identifier written to audit entries. |
| `proxy.server_id` | `filesystem` | Server identifier written to audit entries. |
| `audit.storage` | `jsonl` | Storage backend: `jsonl` or `sqlite`. |
| `audit.path` | `./audit.jsonl` | JSONL audit log path. |
| `audit.sqlite_path` | `./audit.db` | SQLite database path. |
| `audit.sign` | `true` | Enable HMAC-SHA256 signatures when a secret is set. |
| `audit.secret` | empty | HMAC secret. Prefer `AUDIT_SECRET`. |
| `audit.async.enabled` | `false` | Enable asynchronous batched audit writes through a bounded ring buffer. |
| `audit.async.queue_size` | `4096` | Maximum queued audit entries before backpressure blocks writers. |
| `audit.async.batch_size` | `128` | Maximum entries written per storage batch. |
| `audit.async.flush_interval_ms` | `1000` | Maximum time before a partial batch is flushed. |
| `middleware.rate_limit.enabled` | `true` | Enable per-client, per-tool token buckets. |
| `middleware.rate_limit.requests_per_minute` | `60` | Allowed requests per minute per `(client_id, tool_name)`. |
| `middleware.redact.enabled` | `true` | Enable JSON key-based PII redaction. |
| `middleware.redact.patterns` | sensitive keys | Case-insensitive key fragments to redact. |
| `policy.enabled` | `false` | Enable synchronous allow/deny policy checks for `tools/call`. |
| `policy.default_action` | `allow` | Fallback action when no policy rule matches: `allow` or `deny`. |
| `policy.rules` | empty | Ordered first-match allow/deny rules for tool calls. |
| `dashboard.enabled` | `true` | Serve the dashboard. |
| `dashboard.port` | `9090` | Dashboard listen port. |
| `metrics.enabled` | `true` | Serve Prometheus metrics on a separate HTTP endpoint. |
| `metrics.port` | `9091` | Metrics listen port. |
| `metrics.path` | `/metrics` | Metrics HTTP path. |
| `metrics.include_go_metrics` | `true` | Include Go runtime metrics. |
| `metrics.include_process_metrics` | `true` | Include process metrics. |
| `metrics.tool_labels` | `true` | Include `tool_name` and `client_id` labels for tool-level metrics. Disable to minimize label cardinality. |
| `otel.enabled` | `false` | Export `tools/call` audit entries as OTLP/HTTP JSON spans. |
| `otel.endpoint` | `http://localhost:4318` | OTLP HTTP endpoint base URL. `/v1/traces` is appended automatically. |
| `otel.service_name` | `mcp-audit` | OpenTelemetry `service.name` resource attribute. |
| `otel.headers` | empty | Additional OTLP HTTP headers, for example `Authorization` or API key headers. |
| `otel.tls.ca_file` | empty | Optional CA bundle used to verify the OTLP endpoint. |
| `otel.tls.server_name` | empty | Optional TLS server name override. |
| `otel.tls.insecure_skip_verify` | `false` | Skip OTLP TLS certificate verification. Intended only for local testing. |
| `otel.retry.max_retries` | `3` | Maximum OTLP retry attempts after a failed export request. |
| `otel.retry.initial_interval_ms` | `200` | Initial OTLP retry backoff. |
| `otel.retry.max_interval_ms` | `2000` | Maximum OTLP retry backoff. |
| `otel.queue_size` | `1024` | Maximum queued audit entries before trace exports are dropped. |
| `otel.batch_size` | `64` | Maximum spans per OTLP export request. |
| `otel.flush_interval_ms` | `1000` | Maximum time before a partial OTLP batch is exported. |
| `otel.timeout_ms` | `5000` | OTLP HTTP request timeout. |

CLI flags:

```text
--transport    stdio | http
--upstream     upstream server command or URL
--port         proxy port for http mode
--upstream-timeout upstream HTTP request timeout in milliseconds
--config       path to config.yaml
--storage      jsonl | sqlite
--no-dashboard disable the web dashboard
--no-metrics   disable Prometheus metrics
--version      print version and exit
--log-level    debug | info | warn | error
```

## Claude Desktop

Configure Claude Desktop to spawn `mcp-audit` instead of the upstream MCP server:

```json
{
  "mcpServers": {
    "filesystem-audited": {
      "command": "mcp-audit",
      "args": [
        "--transport",
        "stdio",
        "--upstream",
        "npx @modelcontextprotocol/server-filesystem /tmp"
      ],
      "env": {
        "AUDIT_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

## Dashboard

The dashboard shows recent entries, filters, expandable request/result JSON, top tools, calls today, and error rate. It refreshes every five seconds.

## Prometheus Metrics

`mcp-audit` exposes Prometheus metrics on a separate endpoint so platform teams can scrape operational data without exposing the dashboard.

```yaml
scrape_configs:
  - job_name: mcp-audit
    static_configs:
      - targets: ["localhost:9091"]
```

Application metrics use the `mcp_audit_` prefix and avoid unbounded labels. Tool-level labels can be disabled with `metrics.tool_labels: false` for stricter cardinality control. Policy decisions are exposed as `mcp_audit_policy_decisions_total{action="allow|deny"}`.

For a ready-made Prometheus + Grafana stack, see [examples/docker-compose-observability](examples/docker-compose-observability/README.md).

## Policy Engine

`mcp-audit` can enforce synchronous allow/deny rules before a `tools/call` reaches the upstream MCP server. Denied calls return a JSON-RPC error and are still written to the audit log.

```yaml
policy:
  enabled: true
  default_action: allow
  rules:
    - action: deny
      client_id: claude-desktop
      server_id: filesystem
      tool_name: delete_file
      reason: "Destructive filesystem operations are blocked"
```

Rules are evaluated in order. Empty fields and `*` match any value, so `default_action: deny` can be used with explicit allow rules for stricter deployments.

## OpenTelemetry

`mcp-audit` can export `tools/call` audit entries as OTLP/HTTP JSON spans to Jaeger, Tempo, Honeycomb, or any OTLP-compatible collector.

```yaml
otel:
  enabled: true
  endpoint: "http://localhost:4318"
  service_name: "mcp-audit"
  headers:
    Authorization: "Bearer your-token"
  timeout_ms: 5000
  retry:
    max_retries: 3
    initial_interval_ms: 200
    max_interval_ms: 2000
```

The exporter uses current OpenTelemetry MCP and GenAI semantic conventions where possible, including `mcp.method.name`, `jsonrpc.request.id`, `gen_ai.operation.name`, `gen_ai.tool.name`, `network.transport`, `network.protocol.name`, `rpc.response.status_code`, and `error.type`. Project-specific attributes are kept link-oriented, such as `mcp_audit.entry_id`, `mcp_audit.direction`, `mcp_audit.client_id`, `mcp_audit.server_id`, `mcp_audit.storage`, and `mcp_audit.signature.present`.

Request params and tool results are not exported to spans by default. The signed JSONL or SQLite audit row remains the evidence artifact; OTLP provides correlation, latency, and operational visibility.

Exporter health is visible through Prometheus metrics under the `mcp_audit_otel_` prefix, including export requests, span outcomes, dropped spans, queue depth, and queue capacity. Temporary OTLP failures are retried with bounded exponential backoff; `Retry-After` is honored for retryable responses up to `otel.retry.max_interval_ms`.

## Audit Entries

Each stored entry includes a ULID, timestamp, direction, transport, JSON-RPC method, tool name when present, redacted params/result, JSON-RPC error when present, duration, client/server identifiers, and an optional HMAC-SHA256 signature.

Example JSONL entry:

```json
{
  "id": "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
  "timestamp": "2026-05-25T12:34:56Z",
  "direction": "client_to_server",
  "transport": "stdio",
  "method": "tools/call",
  "tool_name": "read_file",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/tmp/example.txt",
      "token": "[REDACTED]"
    }
  },
  "duration_ms": 18,
  "client_id": "claude-desktop",
  "server_id": "filesystem",
  "signature": "hmac-sha256:..."
}
```

The signature covers:

```text
id + timestamp + method + tool_name + raw_params
```

## Roadmap

- SIEM-friendly exports
- OTLP compression and trace context propagation

## Contributing

This project is experimental. Keep changes small, run `go build ./...` and `go vet ./...`, and prefer standard library behavior over new dependencies.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR expectations, and project principles. See [CHANGELOG.md](CHANGELOG.md) for release history.

## Community

- [Discussions](https://github.com/P4ST4S/mcp-audit/discussions): questions, ideas, and design conversations
- [Issues](https://github.com/P4ST4S/mcp-audit/issues): bug reports and concrete feature requests
- Security: see [SECURITY.md](SECURITY.md) for the private vulnerability reporting process

## License

Apache-2.0. See [LICENSE](LICENSE).
