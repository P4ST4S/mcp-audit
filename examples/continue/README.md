# Continue example

This example uses Continue's `stdio` MCP transport to start `mcp-audit`, then
lets `mcp-audit` launch the real upstream MCP server.

## Transport

**stdio** — Continue spawns `mcp-audit` as a subprocess. `mcp-audit` speaks MCP
on stdin/stdout with Continue and proxies JSON-RPC to the upstream server defined
in `proxy.upstream`.

## Setup

1. Install `mcp-audit` on your `PATH` ([releases](https://github.com/P4ST4S/mcp-audit/releases)).
2. Edit `examples/continue/config.yaml` and set `proxy.upstream` to your MCP server command.
3. Replace `/path/to/allowed/root` with a real directory if you use the filesystem server.
4. Set `AUDIT_SECRET` to a long random value (see below).

## Option A — workspace block (recommended)

Create `.continue/mcpServers/filesystem-audited.yaml` in your project root:

```yaml
name: Filesystem Audited
version: 0.0.1
schema: v1
mcpServers:
  - name: Filesystem Audited
    type: stdio
    command: mcp-audit
    args:
      - --config
      - examples/continue/config.yaml
    env:
      AUDIT_SECRET: replace-with-a-long-random-secret
```

Use a path to `config.yaml` that is correct from your project root. If you copy
the example elsewhere, update the `--config` argument accordingly.

## Option B — global Continue config

Add the same `mcpServers` entry to your user config:

| Platform | Config path |
| --- | --- |
| macOS / Linux | `~/.continue/config.yaml` |
| Windows | `%USERPROFILE%\.continue\config.yaml` |

## Generate `AUDIT_SECRET`

```bash
export AUDIT_SECRET="$(openssl rand -hex 32)"
```

On Windows PowerShell:

```powershell
$env:AUDIT_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

Use the same value in your Continue `env` block (or export it in the shell that
launches Continue if your setup inherits the environment).

## Verify

1. Reload Continue (or restart the extension host).
2. Confirm the MCP server appears in Continue's MCP tools list.
3. Optional: set `dashboard.enabled: true` in `config.yaml` and open `http://localhost:9090` to inspect audit entries.

Audit records are written to `./continue-audit.jsonl` relative to the working
directory where `mcp-audit` starts (usually your project root).
