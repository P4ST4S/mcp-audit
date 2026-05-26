package policy

import (
	"fmt"
	"strings"
)

const (
	// ActionAllow permits a matching tool call.
	ActionAllow = "allow"
	// ActionDeny rejects a matching tool call before it reaches the upstream server.
	ActionDeny = "deny"
)

const defaultDenyReason = "blocked by policy"

// Config configures the policy engine.
type Config struct {
	Enabled       bool
	DefaultAction string
	Rules         []Rule
}

// Rule matches tool call context and returns an allow or deny decision.
type Rule struct {
	Action   string `mapstructure:"action"`
	ClientID string `mapstructure:"client_id"`
	ServerID string `mapstructure:"server_id"`
	ToolName string `mapstructure:"tool_name"`
	Reason   string `mapstructure:"reason"`
}

// Request is the context used to evaluate a tool call.
type Request struct {
	ClientID string
	ServerID string
	ToolName string
}

// Decision is the result of a policy evaluation.
type Decision struct {
	Allowed   bool
	Action    string
	Reason    string
	RuleIndex int
}

// Engine evaluates allow/deny rules for tool calls.
type Engine struct {
	enabled       bool
	defaultAction string
	rules         []Rule
}

// NewEngine creates a policy engine from config.
func NewEngine(config Config) (*Engine, error) {
	defaultAction := normalizeAction(config.DefaultAction)
	if defaultAction == "" {
		defaultAction = ActionAllow
	}
	if defaultAction != ActionAllow && defaultAction != ActionDeny {
		return nil, fmt.Errorf("policy: default_action must be allow or deny")
	}
	rules := append([]Rule(nil), config.Rules...)
	for i := range rules {
		rules[i].Action = normalizeAction(rules[i].Action)
		if rules[i].Action != ActionAllow && rules[i].Action != ActionDeny {
			return nil, fmt.Errorf("policy: rules[%d].action must be allow or deny", i)
		}
	}
	return &Engine{
		enabled:       config.Enabled,
		defaultAction: defaultAction,
		rules:         rules,
	}, nil
}

// Evaluate returns the first matching rule decision, or the default action.
func (e *Engine) Evaluate(request Request) Decision {
	if e == nil || !e.enabled {
		return Decision{Allowed: true, Action: ActionAllow, RuleIndex: -1}
	}
	for i, rule := range e.rules {
		if !matches(rule.ClientID, request.ClientID) ||
			!matches(rule.ServerID, request.ServerID) ||
			!matches(rule.ToolName, request.ToolName) {
			continue
		}
		reason := strings.TrimSpace(rule.Reason)
		if reason == "" && rule.Action == ActionDeny {
			reason = defaultDenyReason
		}
		return Decision{
			Allowed:   rule.Action == ActionAllow,
			Action:    rule.Action,
			Reason:    reason,
			RuleIndex: i,
		}
	}
	reason := ""
	if e.defaultAction == ActionDeny {
		reason = "blocked by default policy"
	}
	return Decision{
		Allowed:   e.defaultAction == ActionAllow,
		Action:    e.defaultAction,
		Reason:    reason,
		RuleIndex: -1,
	}
}

func normalizeAction(action string) string {
	return strings.ToLower(strings.TrimSpace(action))
}

func matches(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	return pattern == value
}
