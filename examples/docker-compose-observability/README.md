# Observability Stack Example

Brings up `mcp-audit`, Prometheus, and Grafana with a single command.

## Services

| Service | Description | URL |
|---|---|---|
| `mcp-audit` | Proxy + dashboard + metrics | `http://localhost:9090` (dashboard), `http://localhost:9091/metrics` |
| `filesystem` | Mock upstream MCP server (filesystem) | internal only |
| `prometheus` | Scrapes `mcp-audit:9091` every 15 s | `http://localhost:9092` |
| `grafana` | Dashboards with Prometheus datasource pre-wired | `http://localhost:3000` |

## Start

```bash
docker compose up --build
```

## What to expect

- **mcp-audit dashboard** at `http://localhost:9090` — recent audit entries, top tools, error rate.
- **Prometheus** at `http://localhost:9092` — query `mcp_audit_*` metrics directly.
- **Grafana** at `http://localhost:3000` — Prometheus datasource is provisioned automatically; create dashboards using `mcp_audit_*` metrics such as:
  - `mcp_audit_entries_total` — total audit entries by method and direction
  - `mcp_audit_tool_calls_total` — tool call count by tool name and client
  - `mcp_audit_errors_total` — error count by method
  - `mcp_audit_async_queue_depth` — async write queue depth

## Notes

- `AUDIT_SECRET` in `docker-compose.yml` should be replaced with a long random value in any non-local environment.
- Grafana anonymous access is enabled for convenience. Remove `GF_AUTH_ANONYMOUS_ENABLED` for production use.
- Audit log is written to `./audit.jsonl` on the host via a bind mount.
