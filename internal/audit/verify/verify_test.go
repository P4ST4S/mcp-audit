package verify_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	"github.com/P4ST4S/mcp-audit/internal/audit/storage"
	auditverify "github.com/P4ST4S/mcp-audit/internal/audit/verify"
	_ "modernc.org/sqlite"
)

const testSecret = "a sufficiently long audit verification secret"

func TestVerifyJSONLReportsV2LegacyUnsignedAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entries := []audit.Entry{
		signedV2Entry(t, "v2"),
		legacyEntry("legacy"),
		baseEntry("unsigned"),
		signedV2Entry(t, "tampered"),
	}
	entries[3].Result = json.RawMessage(`{"ok":false}`)

	var lines []string
	for _, entry := range entries {
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		lines = append(lines, string(raw))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}

	result, err := auditverify.VerifyPath(path, auditverify.Config{
		Keys: map[string]string{integrity.DefaultKeyID: testSecret},
	})
	if err != nil {
		t.Fatalf("verify JSONL: %v", err)
	}
	assertResult(t, result, auditverify.Result{
		Verified: 1,
		Invalid:  1,
		Legacy:   1,
		Unsigned: 1,
		Total:    4,
	})
	if result.Clean() {
		t.Fatal("result should not be clean")
	}
	if !strings.Contains(result.FirstError, "entry unsigned: unsigned") {
		t.Fatalf("first error = %q, want unsigned entry", result.FirstError)
	}
}

func TestVerifyJSONLRejectsAmbiguousJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	raw := `{"id":"first","id":"second","timestamp":"2026-08-24T09:10:11Z","direction":"client→server","transport":"stdio","method":"ping","duration_ms":1,"client_id":"client","server_id":"server","signature":""}`
	if err := os.WriteFile(path, []byte(raw+"\n"), 0o600); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}

	result, err := auditverify.VerifyPath(path, auditverify.Config{Format: auditverify.FormatJSONL})
	if err != nil {
		t.Fatalf("verify JSONL: %v", err)
	}
	if result.Invalid != 1 || result.Total != 1 {
		t.Fatalf("result = %+v, want one invalid record", result)
	}
	if !strings.Contains(result.FirstError, "ambiguous JSON") {
		t.Fatalf("first error = %q, want ambiguous JSON", result.FirstError)
	}
}

func TestVerifySQLiteAutoDetectionReadsEveryEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := storage.NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open SQLite store: %v", err)
	}
	entries := []audit.Entry{signedV2Entry(t, "v2"), legacyEntry("legacy")}
	for _, entry := range entries {
		if err := store.Append(entry); err != nil {
			t.Fatalf("append entry: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close SQLite store: %v", err)
	}

	result, err := auditverify.VerifyPath(path, auditverify.Config{
		Keys: map[string]string{integrity.DefaultKeyID: testSecret},
	})
	if err != nil {
		t.Fatalf("verify SQLite: %v", err)
	}
	assertResult(t, result, auditverify.Result{Verified: 1, Legacy: 1, Total: 2})
	if !result.Clean() {
		t.Fatalf("result should be clean: %+v", result)
	}
}

func TestVerifySQLiteSupportsLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(context.Background(), `CREATE TABLE audit_entries (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		direction TEXT NOT NULL,
		transport TEXT NOT NULL,
		method TEXT NOT NULL,
		request_id TEXT,
		tool_name TEXT,
		params TEXT,
		result TEXT,
		error TEXT,
		duration_ms INTEGER NOT NULL,
		client_id TEXT NOT NULL,
		server_id TEXT NOT NULL,
		signature TEXT
	)`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	entry := legacyEntry("legacy")
	_, err = db.ExecContext(context.Background(), `INSERT INTO audit_entries (
		id, timestamp, direction, transport, method, request_id, tool_name, params,
		result, error, duration_ms, client_id, server_id, signature
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.Timestamp.Format(time.RFC3339Nano), entry.Direction, entry.Transport,
		entry.Method, entry.RequestID, entry.ToolName, string(entry.Params), string(entry.Result),
		nil, entry.DurationMs, entry.ClientID, entry.ServerID, entry.Signature,
	)
	if err != nil {
		t.Fatalf("insert legacy entry: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close SQLite: %v", err)
	}

	result, err := auditverify.VerifyPath(path, auditverify.Config{
		Format: auditverify.FormatSQLite,
		Keys:   map[string]string{integrity.DefaultKeyID: testSecret},
	})
	if err != nil {
		t.Fatalf("verify legacy SQLite: %v", err)
	}
	assertResult(t, result, auditverify.Result{Legacy: 1, Total: 1})
}

func TestVerifyPathErrorsForUnsupportedFormatAndMissingFile(t *testing.T) {
	t.Run("unsupported format", func(t *testing.T) {
		_, err := auditverify.VerifyPath("unused", auditverify.Config{Format: "csv"})
		if err == nil || !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("error = %v, want unsupported format", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := auditverify.VerifyPath(filepath.Join(t.TempDir(), "missing.jsonl"), auditverify.Config{})
		if err == nil || !strings.Contains(err.Error(), "open input") {
			t.Fatalf("error = %v, want open input", err)
		}
	})
}

func baseEntry(id string) audit.Entry {
	return audit.Entry{
		ID:               id,
		Timestamp:        time.Date(2026, 8, 24, 9, 10, 11, 123456789, time.UTC),
		AuditOperationID: "019d2f6e-47ad-75ad-b506-b7990d8c11ba",
		Outcome:          audit.OutcomeSuccess,
		Direction:        audit.DirectionClientToServer,
		Transport:        "http",
		Method:           "tools/call",
		RequestID:        "42",
		MCPName:          "read_file",
		ToolName:         "read_file",
		Params:           json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/file"}}`),
		Result:           json.RawMessage(`{"ok":true}`),
		DurationMs:       17,
		ClientID:         "client",
		ServerID:         "server",
		Principal: &audit.Principal{
			Subject:  "alice",
			ClientID: "client",
			Issuer:   "https://issuer.example.com",
		},
		Policy: &audit.PolicyEvidence{Decision: "allow", RuleID: "SEC-001"},
	}
}

func signedV2Entry(t *testing.T, id string) audit.Entry {
	t.Helper()
	entry := baseEntry(id)
	metadata, err := integrity.NewSigner(testSecret, integrity.DefaultKeyID).Sign(audit.IntegrityEntryV2(entry))
	if err != nil {
		t.Fatalf("sign Integrity v2 entry: %v", err)
	}
	entry.Integrity = metadata
	return entry
}

func legacyEntry(id string) audit.Entry {
	entry := baseEntry(id)
	entry.AuditOperationID = ""
	entry.Outcome = ""
	entry.Signature = audit.NewSigner(testSecret).Sign(entry)
	return entry
}

func assertResult(t *testing.T, got, want auditverify.Result) {
	t.Helper()
	got.FirstError = ""
	if got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
}
