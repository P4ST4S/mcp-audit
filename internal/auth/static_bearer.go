package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	// ErrMissingCredentials indicates that no bearer credential was supplied.
	ErrMissingCredentials = errors.New("auth: bearer credentials are required")
	// ErrInvalidCredentials indicates that a supplied bearer credential is invalid.
	ErrInvalidCredentials = errors.New("auth: bearer credentials are invalid")
)

// StaticBearerAuthenticator authenticates a single pre-shared bearer token.
type StaticBearerAuthenticator struct {
	tokenHash [sha256.Size]byte
	principal *Principal
}

// NewStaticBearerAuthenticator creates a constant-time static token authenticator.
func NewStaticBearerAuthenticator(token string, principal Principal) (*StaticBearerAuthenticator, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("auth: static bearer token must be at least 32 bytes")
	}
	if principal.Subject == "" || principal.ClientID == "" {
		return nil, fmt.Errorf("auth: static bearer subject and client_id are required")
	}
	return &StaticBearerAuthenticator{tokenHash: sha256.Sum256([]byte(token)), principal: clonePrincipal(&principal)}, nil
}

// Authenticate validates an RFC 6750-style Authorization header.
func (a *StaticBearerAuthenticator) Authenticate(_ context.Context, request *http.Request) (*Principal, error) {
	token, err := bearerToken(request)
	if err != nil {
		return nil, err
	}
	presentedHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(presentedHash[:], a.tokenHash[:]) != 1 {
		return nil, ErrInvalidCredentials
	}
	return clonePrincipal(a.principal), nil
}

func bearerToken(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) == 0 {
		return "", ErrMissingCredentials
	}
	if len(values) != 1 {
		return "", ErrInvalidCredentials
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", ErrInvalidCredentials
	}
	return token, nil
}
