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
		RuleID    string `json:"rule_id,omitempty"`
	}{
		Action:    decision.Action,
		Reason:    decision.Reason,
		RuleIndex: decision.RuleIndex,
		RuleID:    decision.RuleID,
	})
	return &audit.RPCError{
		Code:    policyDeniedCode,
		Message: "policy denied",
		Data:    data,
	}
}

func auditPolicyEvidence(decision policy.Decision) *audit.PolicyEvidence {
	if !decision.Applied {
		return nil
	}
	return &audit.PolicyEvidence{Decision: decision.Action, RuleID: decision.RuleID}
}

func outcomeForRPCError(rpcErr *audit.RPCError) audit.Outcome {
	if rpcErr != nil {
		return audit.OutcomeUpstreamError
	}
	return audit.OutcomeSuccess
}
