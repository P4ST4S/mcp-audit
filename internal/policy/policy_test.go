package policy

import "testing"

func TestEngineReturnsFirstMatchingRule(t *testing.T) {
	engine, err := NewEngine(Config{
		Enabled:       true,
		DefaultAction: ActionAllow,
		Rules: []Rule{
			{Action: ActionAllow, ClientID: "other", ToolName: "delete_file"},
			{Action: ActionDeny, ClientID: "claude-desktop", ServerID: "filesystem", ToolName: "delete_file", Reason: "destructive tool blocked"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(Request{
		ClientID: "claude-desktop",
		ServerID: "filesystem",
		ToolName: "delete_file",
	})

	if decision.Allowed {
		t.Fatal("decision allowed denied tool call")
	}
	if decision.RuleIndex != 1 {
		t.Fatalf("rule index = %d, want 1", decision.RuleIndex)
	}
	if decision.Reason != "destructive tool blocked" {
		t.Fatalf("reason = %q", decision.Reason)
	}
}

func TestEngineSupportsDefaultDeny(t *testing.T) {
	engine, err := NewEngine(Config{
		Enabled:       true,
		DefaultAction: ActionDeny,
		Rules: []Rule{
			{Action: ActionAllow, ToolName: "read_file"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	allowed := engine.Evaluate(Request{ToolName: "read_file"})
	if !allowed.Allowed {
		t.Fatal("allow rule was not honored")
	}

	denied := engine.Evaluate(Request{ToolName: "delete_file"})
	if denied.Allowed {
		t.Fatal("default deny was not honored")
	}
	if denied.RuleIndex != -1 {
		t.Fatalf("rule index = %d, want -1", denied.RuleIndex)
	}
}

func TestEngineDisabledAllowsRequests(t *testing.T) {
	engine, err := NewEngine(Config{
		Enabled:       false,
		DefaultAction: ActionDeny,
		Rules: []Rule{
			{Action: ActionDeny, ToolName: "delete_file"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(Request{ToolName: "delete_file"})
	if !decision.Allowed {
		t.Fatal("disabled engine denied request")
	}
}
