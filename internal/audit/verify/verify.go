// Package verify validates stored audit evidence without modifying it.
package verify

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
)

const (
	FormatAuto   = "auto"
	FormatJSONL  = "jsonl"
	FormatSQLite = "sqlite"
)

// Result summarizes verification outcomes for one evidence artifact.
type Result struct {
	Verified   int    `json:"verified"`
	Invalid    int    `json:"invalid"`
	Legacy     int    `json:"legacy"`
	Unsigned   int    `json:"unsigned"`
	Total      int    `json:"total"`
	FirstError string `json:"first_error,omitempty"`
}

// Clean reports whether every record was cryptographically verified.
func (r Result) Clean() bool {
	return r.Invalid == 0 && r.Unsigned == 0
}

// Config supplies verification keys and input format.
type Config struct {
	Format Format
	Keys   map[string]string
}

// Format is an evidence storage format.
type Format string

// VerifyPath verifies every record in path.
func VerifyPath(path string, config Config) (Result, error) {
	format := config.Format
	if format == "" || format == FormatAuto {
		detected, err := detectFormat(path)
		if err != nil {
			return Result{}, err
		}
		format = detected
	}
	verifier := newEntryVerifier(config.Keys)
	switch format {
	case FormatJSONL:
		return verifyJSONLPath(path, verifier)
	case FormatSQLite:
		return verifySQLitePath(path, verifier)
	default:
		return Result{}, fmt.Errorf("audit: verify: unsupported format %q", format)
	}
}

type entryVerifier struct {
	v2     *integrity.Verifier
	legacy map[string]*audit.Signer
}

func newEntryVerifier(keys map[string]string) entryVerifier {
	legacy := make(map[string]*audit.Signer, len(keys))
	for keyID, secret := range keys {
		legacy[keyID] = audit.NewSigner(secret)
	}
	return entryVerifier{v2: integrity.NewVerifier(keys), legacy: legacy}
}

func (v entryVerifier) verify(entry audit.Entry) (string, error) {
	if entry.Integrity != nil {
		if err := v.v2.Verify(audit.IntegrityEntryV2(entry), entry.Integrity); err != nil {
			return "invalid", err
		}
		return "verified", nil
	}
	if entry.Signature == "" {
		return "unsigned", nil
	}
	for _, signer := range v.legacy {
		if signer.Verify(entry) {
			return "legacy", nil
		}
	}
	return "invalid", errors.New("legacy signature does not match any configured key")
}

func (r *Result) record(entry audit.Entry, verifier entryVerifier) {
	r.Total++
	status, err := verifier.verify(entry)
	switch status {
	case "verified":
		r.Verified++
	case "legacy":
		r.Legacy++
	case "unsigned":
		r.Unsigned++
		if r.FirstError == "" {
			r.FirstError = entryLabel(entry.ID, r.Total) + ": unsigned"
		}
	default:
		r.Invalid++
		if r.FirstError == "" {
			r.FirstError = entryLabel(entry.ID, r.Total) + ": " + err.Error()
		}
	}
}

func (r *Result) malformed(index int, err error) {
	r.Total++
	r.Invalid++
	if r.FirstError == "" {
		r.FirstError = fmt.Sprintf("record %d: %v", index, err)
	}
}

func entryLabel(id string, index int) string {
	if id != "" {
		return fmt.Sprintf("entry %s", id)
	}
	return fmt.Sprintf("record %d", index)
}

func detectFormat(path string) (Format, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("audit: verify: open input: %w", err)
	}
	defer file.Close()
	header := make([]byte, 16)
	read, err := file.Read(header)
	if err == io.EOF && read == 0 {
		return FormatJSONL, nil
	}
	if err != nil && read == 0 {
		return "", fmt.Errorf("audit: verify: read input header: %w", err)
	}
	if string(header[:read]) == "SQLite format 3\x00" {
		return FormatSQLite, nil
	}
	return FormatJSONL, nil
}
