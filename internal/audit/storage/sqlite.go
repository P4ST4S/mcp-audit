package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	_ "modernc.org/sqlite"
)

// SQLiteStore persists audit entries in a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

// NewSQLiteStore opens path and initializes the audit schema.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("audit: sqlite: create directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: sqlite: open: %w", err)
	}
	store := &SQLiteStore{db: db}
	if err := store.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS audit_entries (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			audit_operation_id TEXT,
			outcome TEXT,
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
			principal TEXT,
			signature TEXT,
			integrity TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp ON audit_entries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_method ON audit_entries(method)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_tool_name ON audit_entries(tool_name)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_client_id ON audit_entries(client_id)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("audit: sqlite: init: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries ADD COLUMN request_id TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("audit: sqlite: migrate request_id: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries ADD COLUMN principal TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("audit: sqlite: migrate principal: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries ADD COLUMN audit_operation_id TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("audit: sqlite: migrate audit_operation_id: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries ADD COLUMN outcome TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("audit: sqlite: migrate outcome: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries ADD COLUMN integrity TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("audit: sqlite: migrate integrity: %w", err)
	}
	return nil
}

// Append writes entry to SQLite.
func (s *SQLiteStore) Append(entry audit.Entry) error {
	return s.AppendBatch([]audit.Entry{entry})
}

// AppendBatch writes entries to SQLite in a single transaction.
func (s *SQLiteStore) AppendBatch(entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: sqlite: begin batch: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO audit_entries (
		id, timestamp, audit_operation_id, outcome, direction, transport, method, request_id, tool_name, params, result, error,
		duration_ms, client_id, server_id, principal, signature, integrity
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("audit: sqlite: prepare batch: %w", err)
	}
	defer stmt.Close()

	for _, entry := range entries {
		errorJSON, err := json.Marshal(entry.Error)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: sqlite: marshal rpc error: %w", err)
		}
		if entry.Error == nil {
			errorJSON = nil
		}
		principalJSON, err := json.Marshal(entry.Principal)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: sqlite: marshal principal: %w", err)
		}
		if entry.Principal == nil {
			principalJSON = nil
		}
		integrityJSON, err := json.Marshal(entry.Integrity)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: sqlite: marshal integrity: %w", err)
		}
		if entry.Integrity == nil {
			integrityJSON = nil
		}
		_, err = stmt.Exec(
			entry.ID,
			entry.Timestamp.UTC().Format(time.RFC3339Nano),
			entry.AuditOperationID,
			entry.Outcome,
			entry.Direction,
			entry.Transport,
			entry.Method,
			entry.RequestID,
			entry.ToolName,
			string(entry.Params),
			string(entry.Result),
			string(errorJSON),
			entry.DurationMs,
			entry.ClientID,
			entry.ServerID,
			string(principalJSON),
			entry.Signature,
			string(integrityJSON),
		)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: sqlite: insert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: sqlite: commit batch: %w", err)
	}
	return nil
}

// Query returns recent entries matching filter.
func (s *SQLiteStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	rows, err := s.db.Query(`SELECT id, timestamp, audit_operation_id, outcome, direction, transport, method, request_id, tool_name, params, result, error,
		duration_ms, client_id, server_id, principal, signature, integrity
		FROM audit_entries
		ORDER BY timestamp DESC
		LIMIT 10000`)
	if err != nil {
		return nil, fmt.Errorf("audit: sqlite: query: %w", err)
	}
	defer rows.Close()

	var entries []audit.Entry
	for rows.Next() {
		var entry audit.Entry
		var timestamp, operationID, outcome, params, result, rpcErr, principal, integrityJSON sql.NullString
		if err := rows.Scan(
			&entry.ID,
			&timestamp,
			&operationID,
			&outcome,
			&entry.Direction,
			&entry.Transport,
			&entry.Method,
			&entry.RequestID,
			&entry.ToolName,
			&params,
			&result,
			&rpcErr,
			&entry.DurationMs,
			&entry.ClientID,
			&entry.ServerID,
			&principal,
			&entry.Signature,
			&integrityJSON,
		); err != nil {
			return nil, fmt.Errorf("audit: sqlite: scan: %w", err)
		}
		if timestamp.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, timestamp.String)
			if err == nil {
				entry.Timestamp = parsed
			}
		}
		if operationID.Valid {
			entry.AuditOperationID = operationID.String
		}
		if outcome.Valid {
			entry.Outcome = audit.Outcome(outcome.String)
		}
		if params.Valid {
			entry.Params = json.RawMessage(params.String)
		}
		if result.Valid {
			entry.Result = json.RawMessage(result.String)
		}
		if rpcErr.Valid && rpcErr.String != "" && rpcErr.String != "null" {
			var decoded audit.RPCError
			if err := json.Unmarshal([]byte(rpcErr.String), &decoded); err == nil {
				entry.Error = &decoded
			}
		}
		if principal.Valid && principal.String != "" && principal.String != "null" {
			var decoded audit.Principal
			if err := json.Unmarshal([]byte(principal.String), &decoded); err == nil {
				entry.Principal = &decoded
			}
		}
		if integrityJSON.Valid && integrityJSON.String != "" && integrityJSON.String != "null" {
			if err := json.Unmarshal([]byte(integrityJSON.String), &entry.Integrity); err != nil {
				return nil, fmt.Errorf("audit: sqlite: decode integrity: %w", err)
			}
		}
		if audit.MatchFilter(entry, filter) {
			entries = append(entries, entry)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: sqlite: rows: %w", err)
	}
	return audit.LimitNewest(entries, filter.Limit), nil
}

// Stats returns aggregate dashboard statistics.
func (s *SQLiteStore) Stats() (audit.Stats, error) {
	entries, err := s.Query(audit.QueryFilter{Limit: 10000})
	if err != nil {
		return audit.Stats{}, fmt.Errorf("audit: sqlite: stats query: %w", err)
	}
	return audit.BuildStats(entries), nil
}

// Close closes the SQLite database.
func (s *SQLiteStore) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("audit: sqlite: close: %w", err)
	}
	return nil
}
