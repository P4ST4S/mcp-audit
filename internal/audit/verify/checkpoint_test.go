package verify_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	"github.com/P4ST4S/mcp-audit/internal/audit/storage"
	auditverify "github.com/P4ST4S/mcp-audit/internal/audit/verify"
)

func TestStrictVerificationPreservesLegacyDefault(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		entries                   []audit.Entry
		defaultClean, strictClean bool
	}{
		{"legacy", []audit.Entry{legacyEntry("legacy")}, true, false},
		{"empty", nil, true, false},
		{"v2", []audit.Entry{signedV2Entry(t, "v2")}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeEvidence(t, tc.entries)
			config := auditverify.Config{Keys: map[string]string{integrity.DefaultKeyID: testSecret}}
			result, err := auditverify.VerifyPath(path, config)
			if err != nil || result.Clean() != tc.defaultClean {
				t.Fatalf("default: %+v %v", result, err)
			}
			config.RequireIntegrityV2 = true
			result, err = auditverify.VerifyPath(path, config)
			if err != nil || result.Clean() != tc.strictClean {
				t.Fatalf("strict: %+v %v", result, err)
			}
			if _, err = auditverify.CreateCheckpoint(path, config, integrity.DefaultKeyID); (err == nil) != tc.strictClean {
				t.Fatalf("checkpoint eligibility: %v", err)
			}
		})
	}
}

func TestJSONLCheckpointCanonicalizationIncludesExtraFields(t *testing.T) {
	path := writeEvidence(t, []audit.Entry{signedV2Entry(t, "canonical")})
	config := auditverify.Config{Keys: map[string]string{integrity.DefaultKeyID: testSecret}}
	checkpoint, err := auditverify.CreateCheckpoint(path, config, integrity.DefaultKeyID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// JSONL still requires one object per line; add insignificant spaces only.
	spacedRaw := bytes.ReplaceAll(raw, []byte(`":"`), []byte(`" : "`))
	if err := os.WriteFile(path, spacedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	config.Checkpoint = &checkpoint
	result, err := auditverify.VerifyPath(path, config)
	if err != nil || !result.Clean() {
		t.Fatalf("whitespace: %+v %v", result, err)
	}
	extra := append([]byte(`{"extra":true,`), bytes.TrimSpace(raw)[1:]...)
	if err := os.WriteFile(path, append(extra, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = auditverify.VerifyPath(path, config)
	if err != nil || result.Clean() || result.Verified != 1 {
		t.Fatalf("extra field: %+v %v", result, err)
	}
}

func writeEvidence(t *testing.T, entries []audit.Entry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var raw []byte
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, append(line, '\n')...)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckpointDetectsMissingReorderedAndReplacedEvidence(t *testing.T) {
	entries := []audit.Entry{signedV2Entry(t, "first"), signedV2Entry(t, "second"), signedV2Entry(t, "third")}
	config := auditverify.Config{Keys: map[string]string{integrity.DefaultKeyID: testSecret}}
	checkpoint, err := auditverify.CreateCheckpoint(writeEvidence(t, entries), config, integrity.DefaultKeyID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		entries []audit.Entry
		clean   bool
	}{
		{"unchanged", entries, true},
		{"middle removed", []audit.Entry{entries[0], entries[2]}, false},
		{"tail removed", entries[:2], false},
		{"all removed", nil, false},
		{"reordered", []audit.Entry{entries[1], entries[0], entries[2]}, false},
		{"duplicate", []audit.Entry{entries[0], entries[0], entries[2]}, false},
		{"other valid record", []audit.Entry{entries[0], entries[1], signedV2Entry(t, "replacement")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.Checkpoint = &checkpoint
			result, err := auditverify.VerifyPath(writeEvidence(t, tc.entries), config)
			if err != nil || result.Clean() != tc.clean {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
	for _, mutate := range []func(*auditverify.Checkpoint){
		func(c *auditverify.Checkpoint) { c.Records-- }, func(c *auditverify.Checkpoint) { c.Digest = "00" },
		func(c *auditverify.Checkpoint) { c.KeyID = "unknown" }, func(c *auditverify.Checkpoint) { c.Version++ },
		func(c *auditverify.Checkpoint) { c.Signature = "00" }, func(c *auditverify.Checkpoint) { c.Format = "sqlite" },
	} {
		changed := checkpoint
		mutate(&changed)
		config.Checkpoint = &changed
		result, err := auditverify.VerifyPath(writeEvidence(t, entries), config)
		if err != nil || result.Clean() {
			t.Fatalf("changed checkpoint accepted: %+v %v", changed, err)
		}
	}
}

func TestSQLiteCheckpointUsesCompleteOrderedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := storage.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AppendBatch([]audit.Entry{signedV2Entry(t, "a"), signedV2Entry(t, "b")}); err != nil {
		t.Fatal(err)
	}
	config := auditverify.Config{Keys: map[string]string{integrity.DefaultKeyID: testSecret}}
	checkpoint, err := auditverify.CreateCheckpoint(path, config, integrity.DefaultKeyID)
	if err != nil {
		t.Fatal(err)
	}
	config.Checkpoint = &checkpoint
	result, err := auditverify.VerifyPath(path, config)
	if err != nil || !result.Clean() {
		t.Fatalf("roundtrip: %+v %v", result, err)
	}
	if err := store.Append(signedV2Entry(t, "c")); err != nil {
		t.Fatal(err)
	}
	result, err = auditverify.VerifyPath(path, config)
	if err != nil || result.Clean() {
		t.Fatalf("changed SQLite accepted: %+v %v", result, err)
	}
}
