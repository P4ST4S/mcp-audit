# Observability Stack Example

Brings up `mcp-audit`, Prometheus, and Grafana with a single command.

This example targets v1.2.1 and builds the repository checkout. Run the commands
below from `examples/docker-compose-observability/`.

## Services

| Service | Description | URL |
|---|---|---|
| `mock-mcp` | Minimal HTTP JSON-RPC server (canned responses) | internal only |
| `mcp-audit` | Proxy + dashboard + metrics | `http://localhost:9090` (dashboard), `http://localhost:9091/metrics` |
| `prometheus` | Scrapes `mcp-audit:9091` every 15 s | `http://localhost:9092` |
| `grafana` | Dashboards with Prometheus datasource pre-wired | `http://localhost:3000` |

## Start

```bash
export MCP_AUDIT_SIGNING_SECRET="$(openssl rand -hex 32)"
docker compose up --build
```

```bash
docker compose down   # tear down when done
```

## What to expect

- **mcp-audit dashboard** at `http://localhost:9090` — recent audit entries, top tools, error rate.
- **Prometheus** at `http://localhost:9092` — query `mcp_audit_*` metrics directly.
- **Grafana** at `http://localhost:3000` — Prometheus datasource is provisioned automatically; create dashboards using metrics such as:
  - `mcp_audit_entries_total` — total audit entries by transport, direction, method, and status
  - `mcp_audit_tool_calls_total` — tool call count by transport, tool name, and status
  - `mcp_audit_policy_decisions_total{action="allow|deny"}` — policy decisions
  - `mcp_audit_rate_limit_rejections_total` — rate-limited requests by client and tool
  - `mcp_audit_async_queue_depth` — async write queue depth
  - `mcp_audit_storage_writes_total` — storage write count by backend, mode, and status

## Notes

- Point any HTTP MCP client at `http://localhost:4422/mcp` to start generating real audit traffic.
- Signing requires `MCP_AUDIT_SIGNING_SECRET` in the environment; Compose refuses
  to start without it. Keep the same secret to verify existing audit records.
- Services are published on host loopback. The dashboard binds to `0.0.0.0`
  inside its container so Docker can route the published port to it.
- Grafana anonymous access is enabled for convenience. Remove `GF_AUTH_ANONYMOUS_ENABLED` for production use.
- Audit output is retained in the `audit-data` Docker volume at `/data`.
  Export the JSONL artifact with
  `docker compose cp mcp-audit:/data/audit.jsonl ./audit.jsonl`.
  `docker compose down` preserves the volume; adding `-v` deletes it.

Since v1.2.1, terminal transport failures are classified by outcome (for example,
`timeout` or `upstream_error`) instead of `ok`. Use `status!="ok"` to select all
failure classes. See the main README for the complete bounded status mapping.
