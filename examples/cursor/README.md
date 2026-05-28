# Cursor example

This example uses Cursor's `stdio` MCP transport to start `mcp-audit`, then
lets `mcp-audit` launch the real upstream MCP server.

1. Copy `examples/cursor/config.yaml` and edit `proxy.upstream`.
2. Set `AUDIT_SECRET` to a long random value before starting Cursor.
3. Add this to `.cursor/mcp.json` in the Cursor project:

```json
{
  "mcpServers": {
    "filesystem-audited": {
      "type": "stdio",
      "command": "mcp-audit",
      "args": ["--config", "examples/cursor/config.yaml"],
      "env": {
        "AUDIT_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

The example upstream points at the filesystem MCP server. Replace the placeholder
path with a real directory before using it.
