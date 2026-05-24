Output demo/mcp-audit-demo.gif

Require echo
Require go
Require jq

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "rm -f audit.jsonl"
Enter
Sleep 300ms

Type "go build -o mcp-audit ./cmd/mcp-audit && echo 'build OK'"
Enter
Sleep 5s

Type "export AUDIT_SECRET=$(openssl rand -hex 32)"
Enter
Sleep 500ms

Type "cat demo/list.json | ./mcp-audit --transport stdio --upstream cat --storage jsonl 2>/dev/null"
Enter
Sleep 3s

Type "cat demo/call.json | ./mcp-audit --transport stdio --upstream cat --storage jsonl 2>/dev/null"
Enter
Sleep 3s

Type "cat demo/seed.jsonl >> audit.jsonl"
Enter
Sleep 800ms

Type "cat audit.jsonl | jq '{method,tool_name,duration_ms,signature}'"
Enter
Sleep 4s

Type "# transparent · signed · zero-config"
Enter
Sleep 2s
