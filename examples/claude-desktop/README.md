# Claude Desktop example

This example uses Claude Desktop's `stdio` MCP transport to start `mcp-audit`,
then lets `mcp-audit` launch the real upstream MCP server.

1. Edit `examples/claude-desktop/config.yaml` and set `proxy.upstream`. Replace
   `/path/to/allowed/root` with a real directory if you use the filesystem server.
2. Set `AUDIT_SECRET` to a long random value (see below) before starting Claude
   Desktop.
3. Add this server entry to your Claude Desktop config file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "filesystem-audited": {
      "command": "mcp-audit",
      "args": ["--config", "/absolute/path/to/examples/claude-desktop/config.yaml"],
      "env": {
        "AUDIT_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

Generate `AUDIT_SECRET`:

```bash
openssl rand -hex 32
```

On Windows PowerShell:

```powershell
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

Use the resulting value in the `env` block above.

Restart Claude Desktop. Audit records are written to `./claude-desktop-audit.jsonl`
relative to the working directory where `mcp-audit` starts. Set `dashboard.enabled: true`
in `config.yaml` to expose the read-only dashboard at `http://localhost:9090`.
