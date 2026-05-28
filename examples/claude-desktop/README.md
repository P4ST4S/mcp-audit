# Claude Desktop example

This example routes Claude Desktop through `mcp-audit` before it reaches an upstream stdio MCP server.

1. Copy `config.yaml` somewhere stable, then edit `proxy.upstream` for your real server.
2. Generate a secret with `openssl rand -hex 32`.
3. Add this server entry to `~/Library/Application Support/Claude/claude_desktop_config.json`.

```json
{ "mcpServers": { "filesystem-audited": {
  "command": "mcp-audit",
  "args": ["--config", "/absolute/path/to/examples/claude-desktop/config.yaml"],
  "env": { "AUDIT_SECRET": "replace-with-a-long-random-secret" }
}}}
```

Claude Desktop uses stdio MCP, so `proxy.transport` stays `stdio` and `proxy.upstream` is the local server command.
After restarting Claude Desktop, audit rows are written to `audit.path`; the dashboard is available at `http://localhost:9090`.
