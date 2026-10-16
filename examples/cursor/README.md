# Cursor example

This example uses Cursor's `stdio` MCP transport to start `mcp-audit`, then
lets `mcp-audit` launch the real upstream MCP server.

Use v1.2.0 or newer. On Windows, run this stdio example inside WSL; see
[installation prerequisites](../../INSTALL.md#prerequisites).

1. Edit `examples/cursor/config.yaml` and set `proxy.upstream`.
2. Set `MCP_AUDIT_SIGNING_SECRET` to a long random value before starting Cursor.
3. Add this to `.cursor/mcp.json` in the Cursor project:

```json
{
  "mcpServers": {
    "filesystem-audited": {
      "type": "stdio",
      "command": "mcp-audit",
      "args": ["--config", "examples/cursor/config.yaml"],
      "env": {
        "MCP_AUDIT_SIGNING_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

The example upstream points at the filesystem MCP server. Replace the placeholder
path with a real directory before using it.

If you copy `config.yaml` somewhere else, update the `--config` path in
`.cursor/mcp.json` to match that location.
