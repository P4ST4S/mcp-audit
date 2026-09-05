package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	"github.com/oklog/ulid/v2"
)

// DirectionClientToServer names client-to-server audit direction.
const DirectionClientToServer = "client→server"

// DirectionServerToClient names server-to-client audit direction.
const DirectionServerToClient = "server→client"

// Outcome is the terminal state of an accepted audit operation.
type Outcome string

const (
	OutcomeSuccess                   Outcome = "success"
	OutcomeDenied                    Outcome = "denied"
	OutcomeRateLimited               Outcome = "rate_limited"
	OutcomeUpstreamError             Outcome = "upstream_error"
	OutcomeTimeout                   Outcome = "timeout"
	OutcomeClientDisconnect          Outcome = "client_disconnect"
	OutcomeMalformedUpstreamResponse Outcome = "malformed_upstream_response"
	OutcomeCancelled                 Outcome = "cancelled"
	OutcomeInternalError             Outcome = "internal_error"
)

// Valid reports whether outcome is a supported terminal state.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeSuccess,
		OutcomeDenied,
		OutcomeRateLimited,
		OutcomeUpstreamError,
		OutcomeTimeout,
		OutcomeClientDisconnect,
		OutcomeMalformedUpstreamResponse,
		OutcomeCancelled,
		OutcomeInternalError:
		return true
	default:
		return false
	}
}

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Principal is the minimal authenticated identity retained as audit evidence.
type Principal struct {
	Subject  string `json:"subject"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
}

// PolicyEvidence identifies the authorization decision applied to an operation.
type PolicyEvidence struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
}

// Entry is a single audited JSON-RPC exchange or message.
type Entry struct {
	ID               string              `json:"id"`
	Timestamp        time.Time           `json:"timestamp"`
	AuditOperationID string              `json:"audit_operation_id,omitempty"`
	Outcome          Outcome             `json:"outcome,omitempty"`
	Direction        string              `json:"direction"`
	Transport        string              `json:"transport"`
	Method           string              `json:"method"`
	RequestID        string              `json:"request_id,omitempty"`
	MCPName          string              `json:"mcp_name,omitempty"`
	ToolName         string              `json:"tool_name,omitempty"`
	Params           json.RawMessage     `json:"params,omitempty"`
	Result           json.RawMessage     `json:"result,omitempty"`
	Error            *RPCError           `json:"error,omitempty"`
	DurationMs       int64               `json:"duration_ms"`
	ClientID         string              `json:"client_id"`
	ServerID         string              `json:"server_id"`
	Principal        *Principal          `json:"principal,omitempty"`
	Policy           *PolicyEvidence     `json:"policy,omitempty"`
	Signature        string              `json:"signature"`
	Integrity        *integrity.Metadata `json:"integrity,omitempty"`
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

// MetricsRecorder records audit metrics.
type MetricsRecorder interface {
	RecordAuditEntry(entry Entry)
}

// TraceExporter exports audit entries to an operational tracing backend.
type TraceExporter interface {
	ExportAuditEntry(entry Entry) error
}

// Logger records signed audit entries.
type Logger struct {
	store           Store
	signer          *Signer
	integritySigner *integrity.Signer
	redactor        Redactor
	traceExporter   TraceExporter
	log             *slog.Logger
	transport       string
	clientID        string
	serverID        string
	metrics         MetricsRecorder
}

// LoggerConfig configures a Logger.
type LoggerConfig struct {
	Store           Store
	Signer          *Signer
	IntegritySigner *integrity.Signer
	Redactor        Redactor
	Log             *slog.Logger
	Transport       string
	ClientID        string
	ServerID        string
	Metrics         MetricsRecorder
	Trace           TraceExporter
}

// NewLogger creates an audit logger.
func NewLogger(config LoggerConfig) *Logger {
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	return &Logger{
		store:           config.Store,
		signer:          config.Signer,
		integritySigner: config.IntegritySigner,
		redactor:        config.Redactor,
		traceExporter:   config.Trace,
		log:             logger,
		transport:       config.Transport,
		clientID:        config.ClientID,
		serverID:        config.ServerID,
		metrics:         config.Metrics,
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
	if l.integritySigner != nil && l.integritySigner.Enabled() {
		metadata, err := l.integritySigner.Sign(IntegrityEntryV2(entry))
		if err != nil {
			return fmt.Errorf("audit: logger: sign integrity v2: %w", err)
		}
		entry.Integrity = metadata
	}
	if err := l.store.Append(entry); err != nil {
		return fmt.Errorf("audit: logger: append: %w", err)
	}
	if l.metrics != nil {
		l.metrics.RecordAuditEntry(entry)
	}
	if l.traceExporter != nil {
		if err := l.traceExporter.ExportAuditEntry(entry); err != nil {
			l.log.Warn("failed to export audit trace", "id", entry.ID, "error", err)
		}
	}
	l.log.Debug("audit entry recorded", "id", entry.ID, "method", entry.Method, "tool", entry.ToolName)
	return nil
}

// IntegrityEntryV2 maps a stored audit entry to the Integrity v2 signed payload.
func IntegrityEntryV2(entry Entry) integrity.EntryV2 {
	var rpcErr *integrity.RPCErrorV2
	if entry.Error != nil {
		rpcErr = &integrity.RPCErrorV2{
			Code:    entry.Error.Code,
			Message: entry.Error.Message,
			Data:    append(json.RawMessage(nil), entry.Error.Data...),
		}
	}
	var principal *integrity.PrincipalV2
	if entry.Principal != nil {
		principal = &integrity.PrincipalV2{
			Subject:  entry.Principal.Subject,
			ClientID: entry.Principal.ClientID,
			Issuer:   entry.Principal.Issuer,
		}
	}
	var policyEvidence *integrity.PolicyV2
	if entry.Policy != nil {
		policyEvidence = &integrity.PolicyV2{
			Decision: entry.Policy.Decision,
			RuleID:   entry.Policy.RuleID,
		}
	}
	return integrity.EntryV2{
		ID:               entry.ID,
		Timestamp:        entry.Timestamp.UTC().Format(time.RFC3339Nano),
		AuditOperationID: entry.AuditOperationID,
		Outcome:          string(entry.Outcome),
		Direction:        entry.Direction,
		Transport:        entry.Transport,
		Method:           entry.Method,
		RequestID:        entry.RequestID,
		MCPName:          entry.MCPName,
		ToolName:         entry.ToolName,
		Params:           append(json.RawMessage(nil), entry.Params...),
		Result:           append(json.RawMessage(nil), entry.Result...),
		Error:            rpcErr,
		DurationMS:       entry.DurationMs,
		ClientID:         entry.ClientID,
		ServerID:         entry.ServerID,
		Principal:        principal,
		Policy:           policyEvidence,
	}
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
