// Package integrity implements the additive, versioned audit integrity format.
package integrity

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

const maxJCSSafeInteger = int64(1<<53 - 1)

// RPCErrorV2 is the error representation authenticated by Integrity v2.
type RPCErrorV2 struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// PrincipalV2 is the authenticated identity projection protected by Integrity v2.
type PrincipalV2 struct {
	Subject  string `json:"subject"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
}

// PolicyV2 is the policy provenance protected by Integrity v2.
type PolicyV2 struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
}

// EntryV2 is the complete, explicitly ordered input to JCS canonicalization.
// JSON property ordering is ultimately defined by RFC 8785, not field order.
type EntryV2 struct {
	ID               string          `json:"id"`
	Timestamp        string          `json:"timestamp"`
	AuditOperationID string          `json:"audit_operation_id,omitempty"`
	Outcome          string          `json:"outcome,omitempty"`
	Direction        string          `json:"direction"`
	Transport        string          `json:"transport"`
	Method           string          `json:"method"`
	RequestID        string          `json:"request_id,omitempty"`
	MCPName          string          `json:"mcp_name,omitempty"`
	ToolName         string          `json:"tool_name,omitempty"`
	Params           json.RawMessage `json:"params,omitempty"`
	Result           json.RawMessage `json:"result,omitempty"`
	Error            *RPCErrorV2     `json:"error,omitempty"`
	DurationMS       int64           `json:"duration_ms"`
	ClientID         string          `json:"client_id"`
	ServerID         string          `json:"server_id"`
	Principal        *PrincipalV2    `json:"principal,omitempty"`
	Policy           *PolicyV2       `json:"policy,omitempty"`
}

// Canonicalize serializes entry according to RFC 8785 JCS.
func Canonicalize(entry EntryV2) ([]byte, error) {
	if entry.DurationMS < -maxJCSSafeInteger || entry.DurationMS > maxJCSSafeInteger {
		return nil, fmt.Errorf("audit: integrity: duration_ms exceeds the JCS safe integer range")
	}
	if entry.Error != nil {
		code := int64(entry.Error.Code)
		if code < -maxJCSSafeInteger || code > maxJCSSafeInteger {
			return nil, fmt.Errorf("audit: integrity: error code exceeds the JCS safe integer range")
		}
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("audit: integrity: marshal v2 payload: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("audit: integrity: canonicalize v2 payload: %w", err)
	}
	return canonical, nil
}
