# Zed example

This example uses Zed's `stdio` MCP transport to start `mcp-audit`, then lets
`mcp-audit` launch the real upstream MCP server.

## Setup

1. Install `mcp-audit` on your `PATH` ([releases](https://github.com/P4ST4S/mcp-audit/releases)).
2. Edit `examples/zed/config.yaml` and set `proxy.upstream` to your MCP server command.
3. Replace `/path/to/allowed/root` with a real directory if you use the filesystem server.
4. Set `AUDIT_SECRET` to a long random value (see below).

## Zed settings

Open your Zed settings file and add a `context_servers` entry:

| Platform | Settings path |
| --- | --- |
| macOS / Linux | `~/.config/zed/settings.json` |
| Windows | `%APPDATA%\Zed\settings.json` |

```json
{
  "context_servers": {
    "filesystem-audited": {
      "command": "mcp-audit",
      "args": ["--config", "examples/zed/config.yaml"],
      "env": {
        "AUDIT_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

Use a path to `config.yaml` that is correct from the workspace where Zed starts
the context server. If you copy the example elsewhere, update the `--config`
argument accordingly.

## Generate `AUDIT_SECRET`

```bash
export AUDIT_SECRET="$(openssl rand -hex 32)"
```

On Windows PowerShell:

```powershell
$env:AUDIT_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

Use the same value in your Zed `env` block, or export it in the environment that
launches Zed if your setup inherits environment variables.

## Verify

1. Reload Zed or restart the context server from the Agent Panel settings.
2. Confirm the context server indicator is active in Zed's Agent Panel settings.
3. Ask the Zed agent what MCP tools are available from `filesystem-audited`.
4. Optional: set `dashboard.enabled: true` in `config.yaml` and open `http://localhost:9090` to inspect audit entries.

Audit records are written to `./zed-audit.jsonl` relative to the working
directory where `mcp-audit` starts.
