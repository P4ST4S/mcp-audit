# mcp-audit

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8)
[![CI](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/P4ST4S/mcp-audit/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)
![Status](https://img.shields.io/badge/Status-experimental-orange)

A transparent Go proxy that intercepts, signs, rate-limits, redacts, and audits MCP JSON-RPC traffic without changing the client or server.

## Why mcp-audit?

The MCP 2026 roadmap calls out enterprise needs around audit trails, gateway patterns, and operational visibility. `mcp-audit` fills that gap as a deployable sidecar or local wrapper: it sits between any MCP client and server, preserves protocol traffic, and records signed audit entries for tool calls, resource reads, prompt requests, and all other JSON-RPC methods.

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
| `middleware.rate_limit.enabled` | `true` | Enable per-client, per-tool token buckets. |
| `middleware.rate_limit.requests_per_minute` | `60` | Allowed requests per minute per `(client_id, tool_name)`. |
| `middleware.redact.enabled` | `true` | Enable JSON key-based PII redaction. |
| `middleware.redact.patterns` | sensitive keys | Case-insensitive key fragments to redact. |
| `dashboard.enabled` | `true` | Serve the dashboard. |
| `dashboard.port` | `9090` | Dashboard listen port. |

CLI flags:

```text
--transport    stdio | http
--upstream     upstream server command or URL
--port         proxy port for http mode
--config       path to config.yaml
--storage      jsonl | sqlite
--no-dashboard disable the web dashboard
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

## Audit Entries

Each stored entry includes a ULID, timestamp, direction, transport, JSON-RPC method, tool name when present, redacted params/result, JSON-RPC error when present, duration, client/server identifiers, and an optional HMAC-SHA256 signature.

The signature covers:

```text
id + timestamp + method + tool_name + raw_params
```

## Contributing

This project is experimental. Keep changes small, run `go build ./...` and `go vet ./...`, and prefer standard library behavior over new dependencies.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR expectations, and project principles.

## License

Apache-2.0. See [LICENSE](LICENSE).
