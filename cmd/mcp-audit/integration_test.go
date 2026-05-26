package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestStdioProxyWritesAuditEntry(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	input := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}` + "\n")

	cmd := exec.Command("go", "run", ".", "--transport", "stdio", "--upstream", "cat", "--storage", "jsonl", "--no-dashboard", "--no-metrics", "--log-level", "error")
	cmd.Env = append(os.Environ(), "AUDIT_PATH="+auditPath)
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("mcp-audit failed: %v\nstderr:\n%s", err, stderr.String())
	}
	if got := stdout.String(); got != string(input) {
		t.Fatalf("stdout = %q, want %q", got, string(input))
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		t.Fatalf("audit log is empty")
	}

	var found bool
	for _, line := range lines {
		var entry audit.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("decode audit entry: %v\n%s", err, string(raw))
		}
		if entry.Direction != audit.DirectionClientToServer {
			continue
		}
		if entry.Transport != "stdio" {
			t.Fatalf("transport = %q, want stdio", entry.Transport)
		}
		if entry.Method != "tools/call" {
			t.Fatalf("method = %q, want tools/call", entry.Method)
		}
		if entry.ToolName != "echo" {
			t.Fatalf("tool_name = %q, want echo", entry.ToolName)
		}
		if len(entry.Params) == 0 {
			t.Fatal("params were not recorded")
		}
		found = true
	}
	if !found {
		t.Fatalf("client-to-server tools/call entry not found\n%s", string(raw))
	}
}
