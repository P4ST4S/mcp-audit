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
	// ScopeToolsOnly preserves the legacy tools/call-only policy behavior.
	ScopeToolsOnly = "tools_only"
	// ScopeAllOperations evaluates every client-originated MCP method.
	ScopeAllOperations = "all_operations"
)

const defaultDenyReason = "blocked by policy"

// Config configures the policy engine.
type Config struct {
	Enabled       bool
	DefaultAction string
	Scope         string
	Rules         []Rule
}

// Rule matches principal and MCP operation context and returns a decision.
type Rule struct {
	ID       string `mapstructure:"id"`
	Action   string `mapstructure:"action"`
	Subject  string `mapstructure:"subject"`
	ClientID string `mapstructure:"client_id"`
	Issuer   string `mapstructure:"issuer"`
	Role     string `mapstructure:"role"`
	Scope    string `mapstructure:"scope"`
	ServerID string `mapstructure:"server_id"`
	Method   string `mapstructure:"method"`
	Name     string `mapstructure:"name"`
	ToolName string `mapstructure:"tool_name"`
	Reason   string `mapstructure:"reason"`
}

// Request is the context used to evaluate an MCP operation.
type Request struct {
	Subject  string
	ClientID string
	Issuer   string
	Roles    []string
	Scopes   []string
	ServerID string
	Method   string
	Name     string
	ToolName string
}

// Decision is the result of a policy evaluation.
type Decision struct {
	Applied   bool
	Allowed   bool
	Action    string
	Reason    string
	RuleIndex int
	RuleID    string
}

// Engine evaluates deterministic allow/deny rules for MCP operations.
type Engine struct {
	enabled       bool
	defaultAction string
	scope         string
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
	scope := strings.ToLower(strings.TrimSpace(config.Scope))
	if scope == "" {
		scope = ScopeToolsOnly
	}
	if scope != ScopeToolsOnly && scope != ScopeAllOperations {
		return nil, fmt.Errorf("policy: scope must be tools_only or all_operations")
	}
	rules := append([]Rule(nil), config.Rules...)
	for i := range rules {
		rules[i].ID = strings.TrimSpace(rules[i].ID)
		rules[i].Action = normalizeAction(rules[i].Action)
		if rules[i].Action != ActionAllow && rules[i].Action != ActionDeny {
			return nil, fmt.Errorf("policy: rules[%d].action must be allow or deny", i)
		}
	}
	return &Engine{
		enabled:       config.Enabled,
		defaultAction: defaultAction,
		scope:         scope,
		rules:         rules,
	}, nil
}

// Evaluate returns the first matching rule decision, or the default action.
func (e *Engine) Evaluate(request Request) Decision {
	if e == nil || !e.enabled {
		return Decision{Allowed: true, Action: ActionAllow, RuleIndex: -1}
	}
	method := request.Method
	if method == "" && request.ToolName != "" {
		method = "tools/call"
		request.Method = method
	}
	if e.scope == ScopeToolsOnly && method != "tools/call" {
		return Decision{Allowed: true, Action: ActionAllow, RuleIndex: -1}
	}
	for i, rule := range e.rules {
		if !matches(rule.Subject, request.Subject) ||
			!matches(rule.ClientID, request.ClientID) ||
			!matches(rule.Issuer, request.Issuer) ||
			!matchesAny(rule.Role, request.Roles) ||
			!matchesAny(rule.Scope, request.Scopes) ||
			!matches(rule.ServerID, request.ServerID) ||
			!matches(rule.Method, request.Method) ||
			!matches(rule.Name, request.Name) ||
			!matches(rule.ToolName, request.ToolName) {
			continue
		}
		reason := strings.TrimSpace(rule.Reason)
		if reason == "" && rule.Action == ActionDeny {
			reason = defaultDenyReason
		}
		return Decision{
			Applied:   true,
			Allowed:   rule.Action == ActionAllow,
			Action:    rule.Action,
			Reason:    reason,
			RuleIndex: i,
			RuleID:    rule.ID,
		}
	}
	reason := ""
	if e.defaultAction == ActionDeny {
		reason = "blocked by default policy"
	}
	return Decision{
		Applied:   true,
		Allowed:   e.defaultAction == ActionAllow,
		Action:    e.defaultAction,
		Reason:    reason,
		RuleIndex: -1,
	}
}

func matchesAny(pattern string, values []string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	for _, value := range values {
		if pattern == value {
			return true
		}
	}
	return false
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
