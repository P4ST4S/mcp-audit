package middleware

import (
	"encoding/json"
	"strings"
)

// DefaultRedactPatterns are the default case-insensitive key fragments to redact.
var DefaultRedactPatterns = []string{"password", "token", "secret", "api_key", "bearer", "authorization"}

// Redactor redacts sensitive JSON object values by key pattern.
type Redactor struct {
	enabled  bool
	patterns []string
}

// NewRedactor creates a Redactor.
func NewRedactor(enabled bool, patterns []string) *Redactor {
	if len(patterns) == 0 {
		patterns = DefaultRedactPatterns
	}
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern != "" {
			normalized = append(normalized, pattern)
		}
	}
	return &Redactor{enabled: enabled, patterns: normalized}
}

// Redact returns a redacted copy of raw JSON. Invalid JSON is returned unchanged.
func (r *Redactor) Redact(raw json.RawMessage) json.RawMessage {
	if r == nil || !r.enabled || len(raw) == 0 {
		return raw
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	redacted := r.redactValue(value, "")
	out, err := json.Marshal(redacted)
	if err != nil {
		return raw
	}
	return out
}

func (r *Redactor) redactValue(value any, key string) any {
	if r.sensitive(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = r.redactValue(v, k)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = r.redactValue(v, key)
		}
		return out
	default:
		return value
	}
}

func (r *Redactor) sensitive(key string) bool {
	key = strings.ToLower(key)
	for _, pattern := range r.patterns {
		if strings.Contains(key, pattern) {
			return true
		}
	}
	return false
}
