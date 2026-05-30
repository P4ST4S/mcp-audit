Output demo/mcp-audit-demo.gif

Require echo
Require go
Require jq

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 760
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

# --- Setup ---
Type "rm -f audit.jsonl"
Enter
Sleep 300ms

Type "go build -ldflags='-X main.version=v0.9.0' -o mcp-audit ./cmd/mcp-audit && ./mcp-audit --version"
Enter
Sleep 4s

Type "export AUDIT_SECRET=$(openssl rand -hex 32)"
Enter
Sleep 500ms

# --- Policy denies destructive tool ---
Type "# policy blocks destructive tools before they reach the upstream"
Enter
Sleep 1500ms

Type "cat demo/delete.json | ./mcp-audit --config demo/config.yaml 2>/dev/null | jq ."
Enter
Sleep 4s

# --- Authorized call goes through ---
Type "# authorized call: redacted in audit, never seen by the upstream raw"
Enter
Sleep 1500ms

Type "cat demo/call.json | ./mcp-audit --config demo/config.yaml 2>/dev/null > /dev/null"
Enter
Sleep 3s

# --- Audit log inspection ---
Type `cat audit.jsonl | jq '{method, tool_name, params, error, signature}'`
Enter
Sleep 5s

# --- Tagline ---
Type "# signed · redacted · policy-enforced · transparent"
Enter
Sleep 2500ms
