package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	_ "modernc.org/sqlite"
)

// SQLiteStore persists audit entries in a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
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
			direction TEXT NOT NULL,
			transport TEXT NOT NULL,
			method TEXT NOT NULL,
			tool_name TEXT,
			params TEXT,
			result TEXT,
			error TEXT,
			duration_ms INTEGER NOT NULL,
			client_id TEXT NOT NULL,
			server_id TEXT NOT NULL,
			signature TEXT
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
	return nil
}

// Append writes entry to SQLite.
func (s *SQLiteStore) Append(entry audit.Entry) error {
	errorJSON, err := json.Marshal(entry.Error)
	if err != nil {
		return fmt.Errorf("audit: sqlite: marshal rpc error: %w", err)
	}
	if entry.Error == nil {
		errorJSON = nil
	}
	_, err = s.db.Exec(`INSERT INTO audit_entries (
		id, timestamp, direction, transport, method, tool_name, params, result, error,
		duration_ms, client_id, server_id, signature
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Direction,
		entry.Transport,
		entry.Method,
		entry.ToolName,
		string(entry.Params),
		string(entry.Result),
		string(errorJSON),
		entry.DurationMs,
		entry.ClientID,
		entry.ServerID,
		entry.Signature,
	)
	if err != nil {
		return fmt.Errorf("audit: sqlite: insert: %w", err)
	}
	return nil
}

// Query returns recent entries matching filter.
func (s *SQLiteStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	rows, err := s.db.Query(`SELECT id, timestamp, direction, transport, method, tool_name, params, result, error,
		duration_ms, client_id, server_id, signature
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
		var timestamp, params, result, rpcErr sql.NullString
		if err := rows.Scan(
			&entry.ID,
			&timestamp,
			&entry.Direction,
			&entry.Transport,
			&entry.Method,
			&entry.ToolName,
			&params,
			&result,
			&rpcErr,
			&entry.DurationMs,
			&entry.ClientID,
			&entry.ServerID,
			&entry.Signature,
		); err != nil {
			return nil, fmt.Errorf("audit: sqlite: scan: %w", err)
		}
		if timestamp.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, timestamp.String)
			if err == nil {
				entry.Timestamp = parsed
			}
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
