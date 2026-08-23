package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

const testStaticToken = "0123456789abcdef0123456789abcdef"

func TestNoneAuthenticatorReturnsDefensivePrincipalCopy(t *testing.T) {
	authenticator, err := NewNoneAuthenticator(Principal{Subject: "local", ClientID: "desktop", Roles: []string{"operator"}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	principal, err := authenticator.Authenticate(context.Background(), nil)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	principal.Roles[0] = "mutated"
	again, _ := authenticator.Authenticate(context.Background(), nil)
	if again.Roles[0] != "operator" {
		t.Fatalf("stored principal was mutated: %#v", again)
	}
}

func TestStaticBearerAuthenticator(t *testing.T) {
	authenticator, err := NewStaticBearerAuthenticator(testStaticToken, Principal{Subject: "alice", ClientID: "client-1"})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	cases := []struct {
		name   string
		header []string
		want   error
	}{
		{name: "missing", want: ErrMissingCredentials},
		{name: "invalid scheme", header: []string{"Basic abc"}, want: ErrInvalidCredentials},
		{name: "invalid token", header: []string{"Bearer wrong"}, want: ErrInvalidCredentials},
		{name: "duplicate", header: []string{"Bearer " + testStaticToken, "Bearer " + testStaticToken}, want: ErrInvalidCredentials},
		{name: "valid", header: []string{"Bearer " + testStaticToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "http://proxy.local/mcp", nil)
			for _, value := range tc.header {
				request.Header.Add("Authorization", value)
			}
			principal, err := authenticator.Authenticate(context.Background(), request)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (principal == nil || principal.Subject != "alice") {
				t.Fatalf("principal = %#v", principal)
			}
		})
	}
}

func TestPrincipalContextUsesDefensiveCopies(t *testing.T) {
	original := &Principal{Subject: "alice", ClientID: "client-1", Scopes: []string{"tools:read"}, Claims: map[string]any{"tier": "internal", "nested": map[string]any{"groups": []any{"ops"}}}}
	ctx := WithPrincipal(context.Background(), original)
	original.Scopes[0] = "mutated"
	original.Claims["tier"] = "mutated"
	original.Claims["nested"].(map[string]any)["groups"].([]any)[0] = "mutated"
	principal, ok := PrincipalFromContext(ctx)
	groups := principal.Claims["nested"].(map[string]any)["groups"].([]any)
	if !ok || principal.Scopes[0] != "tools:read" || principal.Claims["tier"] != "internal" || groups[0] != "ops" {
		t.Fatalf("principal = %#v, ok = %t", principal, ok)
	}
}
