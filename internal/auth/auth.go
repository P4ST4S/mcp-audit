package auth

import (
	"context"
	"net/http"
)

const (
	ModeNone         = "none"
	ModeStaticBearer = "static_bearer"
)

// Principal is the authenticated identity used by gateway controls.
type Principal struct {
	Subject  string
	ClientID string
	Issuer   string
	Roles    []string
	Scopes   []string
	Claims   map[string]any
}

// Authenticator derives a trusted principal from an incoming HTTP request.
type Authenticator interface {
	Authenticate(context.Context, *http.Request) (*Principal, error)
}

type principalContextKey struct{}

// WithPrincipal attaches an authenticated principal to a request context.
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, clonePrincipal(principal))
}

// PrincipalFromContext returns a defensive copy of the request principal.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(*Principal)
	if !ok || principal == nil {
		return nil, false
	}
	return clonePrincipal(principal), true
}

func clonePrincipal(principal *Principal) *Principal {
	if principal == nil {
		return nil
	}
	cloned := *principal
	cloned.Roles = append([]string(nil), principal.Roles...)
	cloned.Scopes = append([]string(nil), principal.Scopes...)
	if principal.Claims != nil {
		cloned.Claims = make(map[string]any, len(principal.Claims))
		for key, value := range principal.Claims {
			cloned.Claims[key] = cloneClaimValue(value)
		}
	}
	return &cloned
}

func cloneClaimValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, item := range typed {
			cloned[key] = cloneClaimValue(item)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneClaimValue(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}
