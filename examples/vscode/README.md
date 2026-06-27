# VS Code example

This example uses VS Code's `stdio` MCP transport to start `mcp-audit`, then
lets `mcp-audit` launch the real upstream MCP server.

## Setup

1. Install `mcp-audit` on your `PATH` ([releases](https://github.com/P4ST4S/mcp-audit/releases)).
2. Edit `examples/vscode/config.yaml` and set `proxy.upstream` to your MCP server command.
3. Replace `/path/to/allowed/root` with a real directory if you use the filesystem server.
4. Set `AUDIT_SECRET` to a long random value (see below).

## Workspace-level VS Code config

Create `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "filesystem-audited": {
      "type": "stdio",
      "command": "mcp-audit",
      "args": ["--config", "examples/vscode/config.yaml"],
      "env": {
        "AUDIT_SECRET": "replace-with-a-long-random-secret"
      }
    }
  }
}
```

Use a path to `config.yaml` that is correct from your project root. If you copy
the example elsewhere, update the `--config` argument accordingly.

## User-level VS Code config

Add the same `servers` entry to your user MCP config:

| Platform | Config path |
| --- | --- |
| macOS | `~/Library/Application Support/Code/User/mcp.json` |
| Linux | `~/.config/Code/User/mcp.json` |
| Windows | `%APPDATA%\Code\User\mcp.json` |

## Generate `AUDIT_SECRET`

```bash
export AUDIT_SECRET="$(openssl rand -hex 32)"
```

On Windows PowerShell:

```powershell
$env:AUDIT_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

Use the same value in your VS Code `env` block (or export it in the shell that
launches VS Code if your setup inherits the environment).

## Verify

1. Reload VS Code.
2. Confirm the MCP server appears in VS Code's MCP server list.
3. Optional: set `dashboard.enabled: true` in `config.yaml` and open `http://localhost:9090` to inspect audit entries.

Audit records are written to `./vscode-audit.jsonl` relative to the working
directory where `mcp-audit` starts (usually your project root).
