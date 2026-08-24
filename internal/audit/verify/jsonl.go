package verify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/gowebpki/jcs"
)

const maxJSONLRecordBytes = 32 * 1024 * 1024

func verifyJSONLPath(path string, verifier entryVerifier) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("audit: verify: open JSONL: %w", err)
	}
	defer file.Close()

	var result Result
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxJSONLRecordBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if _, err := jcs.Transform(raw); err != nil {
			result.malformed(lineNumber, fmt.Errorf("invalid or ambiguous JSON: %w", err))
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal(raw, &entry); err != nil {
			result.malformed(lineNumber, fmt.Errorf("decode audit entry: %w", err))
			continue
		}
		result.record(entry, verifier)
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("audit: verify: scan JSONL: %w", err)
	}
	return result, nil
}
