# mcp-audit

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8)
[![CI](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml)
[![mcp-audit MCP server](https://glama.ai/mcp/servers/P4ST4S/mcp-audit/badges/score.svg)](https://glama.ai/mcp/servers/P4ST4S/mcp-audit)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)
![Status](https://img.shields.io/badge/Status-experimental-orange)

A drop-in security and observability proxy for MCP servers. `mcp-audit` sits between an MCP client and any upstream MCP server to produce signed audit trails, redact sensitive payloads, enforce per-tool rate limits, and expose a local read-only dashboard.

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

## Use Cases

- Audit tool calls made by AI agents in regulated environments
- Detect unexpected or dangerous MCP tool usage
- Keep signed JSONL or SQLite logs for incident review
- Redact sensitive fields before storing requests and responses
- Apply per-tool rate limits without modifying the upstream MCP server

## Demo

![mcp-audit demo](demo/mcp-audit-demo.gif)

## Quick Start

Install Go, then build from source:

```bash
brew install go
go install github.com/P4ST4S/mcp-audit/cmd/mcp-audit@v0.2.0
```

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

## Configuration

`mcp-audit` loads `config.yaml` from the current directory by default. CLI flags override config values, and `AUDIT_SECRET` overrides `audit.secret`.

| Key | Default | Description |
| --- | --- | --- |
| `proxy.transport` | `stdio` | Proxy transport: `stdio` or `http`. |
| `proxy.upstream` | required | Stdio command or HTTP upstream URL. |
| `proxy.port` | `4422` | HTTP listen port. |
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
| `dashboard.enabled` | `true` | Serve the dashboard. |
| `dashboard.port` | `9090` | Dashboard listen port. |
| `metrics.enabled` | `true` | Serve Prometheus metrics on a separate HTTP endpoint. |
| `metrics.port` | `9091` | Metrics listen port. |
| `metrics.path` | `/metrics` | Metrics HTTP path. |
| `metrics.include_go_metrics` | `true` | Include Go runtime metrics. |
| `metrics.include_process_metrics` | `true` | Include process metrics. |
| `metrics.tool_labels` | `true` | Include `tool_name` and `client_id` labels for tool-level metrics. Disable to minimize label cardinality. |

CLI flags:

```text
--transport    stdio | http
--upstream     upstream server command or URL
--port         proxy port for http mode
--config       path to config.yaml
--storage      jsonl | sqlite
--no-dashboard disable the web dashboard
--no-metrics   disable Prometheus metrics
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

Application metrics use the `mcp_audit_` prefix and avoid unbounded labels. Tool-level labels can be disabled with `metrics.tool_labels: false` for stricter cardinality control.

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

- OpenTelemetry export
- Policy engine for allow/deny rules
- SIEM-friendly exports

## Contributing

This project is experimental. Keep changes small, run `go build ./...` and `go vet ./...`, and prefer standard library behavior over new dependencies.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR expectations, and project principles. See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

Apache-2.0. See [LICENSE](LICENSE).
