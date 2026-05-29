# Observability Stack Example

Brings up `mcp-audit`, Prometheus, and Grafana with a single command.

## Services

| Service | Description | URL |
|---|---|---|
| `mock-mcp` | Minimal HTTP JSON-RPC server (canned responses) | internal only |
| `mcp-audit` | Proxy + dashboard + metrics | `http://localhost:9090` (dashboard), `http://localhost:9091/metrics` |
| `prometheus` | Scrapes `mcp-audit:9091` every 15 s | `http://localhost:9092` |
| `grafana` | Dashboards with Prometheus datasource pre-wired | `http://localhost:3000` |

## Start

```bash
docker compose up --build
```

```bash
docker compose down   # tear down when done
```

## What to expect

- **mcp-audit dashboard** at `http://localhost:9090` — recent audit entries, top tools, error rate.
- **Prometheus** at `http://localhost:9092` — query `mcp_audit_*` metrics directly.
- **Grafana** at `http://localhost:3000` — Prometheus datasource is provisioned automatically; create dashboards using metrics such as:
  - `mcp_audit_entries_total{status="ok|rpc_error"}` — total audit entries by transport, direction, method, and status
  - `mcp_audit_tool_calls_total{status="ok|rpc_error"}` — tool call count by transport, tool name, and status
  - `mcp_audit_policy_decisions_total{action="allow|deny"}` — policy decisions
  - `mcp_audit_rate_limit_rejections_total` — rate-limited requests by client and tool
  - `mcp_audit_async_queue_depth` — async write queue depth
  - `mcp_audit_storage_writes_total` — storage write count by backend, mode, and status

## Notes

- Point any HTTP MCP client at `http://localhost:4422/mcp` to start generating real audit traffic.
- Replace `AUDIT_SECRET` in `docker-compose.yml` with a long random value: `openssl rand -hex 32`.
- Grafana anonymous access is enabled for convenience. Remove `GF_AUTH_ANONYMOUS_ENABLED` for production use.
- Audit log and database are written to `./audit-data/` on the host via a bind mount.
