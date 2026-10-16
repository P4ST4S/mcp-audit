package auth

import (
	"context"
	"fmt"
	"net/http"
)

// NoneAuthenticator supplies an explicitly configured local principal.
type NoneAuthenticator struct {
	principal *Principal
}

// NewNoneAuthenticator creates an authenticator for local and legacy modes.
func NewNoneAuthenticator(principal Principal) (*NoneAuthenticator, error) {
	if principal.Subject == "" || principal.ClientID == "" {
		return nil, fmt.Errorf("auth: none: subject and client_id are required")
	}
	return &NoneAuthenticator{principal: clonePrincipal(&principal)}, nil
}

// Authenticate returns the configured local principal without reading headers.
func (a *NoneAuthenticator) Authenticate(context.Context, *http.Request) (*Principal, error) {
	return clonePrincipal(a.principal), nil
}
