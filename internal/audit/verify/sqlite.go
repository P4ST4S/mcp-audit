package verify

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	_ "modernc.org/sqlite"
)

var sqliteEntryColumns = []string{
	"id", "timestamp", "audit_operation_id", "outcome", "direction", "transport", "method",
	"request_id", "tool_name", "params", "result", "error", "duration_ms", "client_id", "server_id",
	"signature", "integrity",
}

func verifySQLitePath(path string, verifier entryVerifier) (Result, error) {
	if _, err := os.Stat(path); err != nil {
		return Result{}, fmt.Errorf("audit: verify: stat SQLite: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Result{}, fmt.Errorf("audit: verify: open SQLite: %w", err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA query_only = ON`); err != nil {
		return Result{}, fmt.Errorf("audit: verify: enable SQLite query-only mode: %w", err)
	}
	available, err := sqliteColumns(db)
	if err != nil {
		return Result{}, err
	}
	for _, required := range []string{"id", "timestamp", "direction", "transport", "method", "duration_ms", "client_id", "server_id", "signature"} {
		if !available[required] {
			return Result{}, fmt.Errorf("audit: verify: SQLite audit_entries is missing required column %q", required)
		}
	}
	selects := make([]string, len(sqliteEntryColumns))
	for index, column := range sqliteEntryColumns {
		if available[column] {
			selects[index] = column
		} else {
			selects[index] = "NULL AS " + column
		}
	}
	rows, err := db.Query(`SELECT ` + strings.Join(selects, ", ") + ` FROM audit_entries ORDER BY rowid`)
	if err != nil {
		return Result{}, fmt.Errorf("audit: verify: query SQLite: %w", err)
	}
	defer rows.Close()

	var result Result
	rowNumber := 0
	for rows.Next() {
		rowNumber++
		entry, err := scanSQLiteEntry(rows)
		if err != nil {
			result.malformed(rowNumber, err)
			continue
		}
		result.record(entry, verifier)
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("audit: verify: iterate SQLite: %w", err)
	}
	return result, nil
}

func sqliteColumns(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(audit_entries)`)
	if err != nil {
		return nil, fmt.Errorf("audit: verify: inspect SQLite schema: %w", err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("audit: verify: scan SQLite schema: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: verify: iterate SQLite schema: %w", err)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("audit: verify: SQLite table audit_entries does not exist")
	}
	return columns, nil
}

func scanSQLiteEntry(rows *sql.Rows) (audit.Entry, error) {
	values := make([]sql.NullString, len(sqliteEntryColumns))
	destinations := make([]any, len(values))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := rows.Scan(destinations...); err != nil {
		return audit.Entry{}, fmt.Errorf("scan SQLite entry: %w", err)
	}
	value := func(column string) string {
		for index, candidate := range sqliteEntryColumns {
			if candidate == column && values[index].Valid {
				return values[index].String
			}
		}
		return ""
	}
	timestamp, err := time.Parse(time.RFC3339Nano, value("timestamp"))
	if err != nil {
		return audit.Entry{}, fmt.Errorf("parse timestamp: %w", err)
	}
	durationMS, err := strconv.ParseInt(value("duration_ms"), 10, 64)
	if err != nil {
		return audit.Entry{}, fmt.Errorf("parse duration_ms: %w", err)
	}
	entry := audit.Entry{
		ID:               value("id"),
		Timestamp:        timestamp,
		AuditOperationID: value("audit_operation_id"),
		Outcome:          audit.Outcome(value("outcome")),
		Direction:        value("direction"),
		Transport:        value("transport"),
		Method:           value("method"),
		RequestID:        value("request_id"),
		ToolName:         value("tool_name"),
		Params:           json.RawMessage(value("params")),
		Result:           json.RawMessage(value("result")),
		DurationMs:       durationMS,
		ClientID:         value("client_id"),
		ServerID:         value("server_id"),
		Signature:        value("signature"),
	}
	if raw := value("error"); raw != "" && raw != "null" {
		if err := json.Unmarshal([]byte(raw), &entry.Error); err != nil {
			return audit.Entry{}, fmt.Errorf("decode error field: %w", err)
		}
	}
	if raw := value("integrity"); raw != "" && raw != "null" {
		entry.Integrity = &integrity.Metadata{}
		if err := json.Unmarshal([]byte(raw), entry.Integrity); err != nil {
			return audit.Entry{}, fmt.Errorf("decode integrity field: %w", err)
		}
	}
	return entry, nil
}
