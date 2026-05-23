package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// DirectionClientToServer names client-to-server audit direction.
const DirectionClientToServer = "client→server"

// DirectionServerToClient names server-to-client audit direction.
const DirectionServerToClient = "server→client"

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Entry is a single audited JSON-RPC exchange or message.
type Entry struct {
	ID         string          `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	Direction  string          `json:"direction"`
	Transport  string          `json:"transport"`
	Method     string          `json:"method"`
	ToolName   string          `json:"tool_name,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      *RPCError       `json:"error,omitempty"`
	DurationMs int64           `json:"duration_ms"`
	ClientID   string          `json:"client_id"`
	ServerID   string          `json:"server_id"`
	Signature  string          `json:"signature"`
}

// Store persists and queries audit entries.
type Store interface {
	Append(entry Entry) error
	Query(filter QueryFilter) ([]Entry, error)
	Stats() (Stats, error)
	Close() error
}

// Redactor redacts sensitive values before entries are stored.
type Redactor interface {
	Redact(raw json.RawMessage) json.RawMessage
}

// Logger records signed audit entries.
type Logger struct {
	store     Store
	signer    *Signer
	redactor  Redactor
	log       *slog.Logger
	transport string
	clientID  string
	serverID  string
}

// LoggerConfig configures a Logger.
type LoggerConfig struct {
	Store     Store
	Signer    *Signer
	Redactor  Redactor
	Log       *slog.Logger
	Transport string
	ClientID  string
	ServerID  string
}

// NewLogger creates an audit logger.
func NewLogger(config LoggerConfig) *Logger {
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	return &Logger{
		store:     config.Store,
		signer:    config.Signer,
		redactor:  config.Redactor,
		log:       logger,
		transport: config.Transport,
		clientID:  config.ClientID,
		serverID:  config.ServerID,
	}
}

// Record records entry after applying redaction and signing.
func (l *Logger) Record(entry Entry) error {
	if entry.ID == "" {
		entry.ID = ulid.Make().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.Transport == "" {
		entry.Transport = l.transport
	}
	if entry.ClientID == "" {
		entry.ClientID = l.clientID
	}
	if entry.ServerID == "" {
		entry.ServerID = l.serverID
	}
	if l.redactor != nil {
		entry.Params = l.redactor.Redact(entry.Params)
		entry.Result = l.redactor.Redact(entry.Result)
		if entry.Error != nil {
			entry.Error.Data = l.redactor.Redact(entry.Error.Data)
		}
	}
	if l.signer != nil {
		entry.Signature = l.signer.Sign(entry)
	}
	if err := l.store.Append(entry); err != nil {
		return fmt.Errorf("audit: logger: append: %w", err)
	}
	l.log.Debug("audit entry recorded", "id", entry.ID, "method", entry.Method, "tool", entry.ToolName)
	return nil
}

// Store returns the logger storage backend.
func (l *Logger) Store() Store {
	return l.store
}

// QueryFilter filters dashboard and API audit queries.
type QueryFilter struct {
	Method   string
	ToolName string
	ClientID string
	From     time.Time
	To       time.Time
	Limit    int
}

// ToolStat is a count for a tool name.
type ToolStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Stats contains dashboard aggregate data.
type Stats struct {
	TotalToday int        `json:"total_today"`
	ErrorRate  float64    `json:"error_rate"`
	TopTools   []ToolStat `json:"top_tools"`
}

// MatchFilter reports whether entry satisfies filter.
func MatchFilter(entry Entry, filter QueryFilter) bool {
	if filter.Method != "" && entry.Method != filter.Method {
		return false
	}
	if filter.ToolName != "" && entry.ToolName != filter.ToolName {
		return false
	}
	if filter.ClientID != "" && entry.ClientID != filter.ClientID {
		return false
	}
	if !filter.From.IsZero() && entry.Timestamp.Before(filter.From) {
		return false
	}
	if !filter.To.IsZero() && entry.Timestamp.After(filter.To) {
		return false
	}
	return true
}

// LimitNewest sorts entries newest first and applies limit.
func LimitNewest(entries []Entry, limit int) []Entry {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	if limit <= 0 {
		limit = 100
	}
	if len(entries) > limit {
		return entries[:limit]
	}
	return entries
}

// BuildStats builds dashboard statistics from entries.
func BuildStats(entries []Entry) Stats {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var today, total, errors int
	toolCounts := make(map[string]int)
	for _, entry := range entries {
		if entry.Direction != DirectionClientToServer {
			continue
		}
		total++
		if entry.Error != nil {
			errors++
		}
		if entry.Timestamp.After(start) {
			today++
		}
		if entry.ToolName != "" {
			toolCounts[entry.ToolName]++
		}
	}
	stats := Stats{TotalToday: today}
	if total > 0 {
		stats.ErrorRate = float64(errors) / float64(total)
	}
	for name, count := range toolCounts {
		stats.TopTools = append(stats.TopTools, ToolStat{Name: name, Count: count})
	}
	sort.Slice(stats.TopTools, func(i, j int) bool {
		if stats.TopTools[i].Count == stats.TopTools[j].Count {
			return strings.Compare(stats.TopTools[i].Name, stats.TopTools[j].Name) < 0
		}
		return stats.TopTools[i].Count > stats.TopTools[j].Count
	})
	if len(stats.TopTools) > 5 {
		stats.TopTools = stats.TopTools[:5]
	}
	return stats
}
