package proxy

import (
	"encoding/json"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/policy"
)

const policyDeniedCode = -32030

func policyError(decision policy.Decision) *audit.RPCError {
	data, _ := json.Marshal(struct {
		Action    string `json:"action"`
		Reason    string `json:"reason,omitempty"`
		RuleIndex int    `json:"rule_index"`
	}{
		Action:    decision.Action,
		Reason:    decision.Reason,
		RuleIndex: decision.RuleIndex,
	})
	return &audit.RPCError{
		Code:    policyDeniedCode,
		Message: "policy denied",
		Data:    data,
	}
}
