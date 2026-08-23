package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "mcp-audit"
)

type rotatingJWKS struct {
	mu       sync.RWMutex
	kid      string
	key      *rsa.PrivateKey
	requests int
}

func (j *rotatingJWKS) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.requests++
	publicKey := j.key.PublicKey
	exponent := big.NewInt(int64(publicKey.E)).Bytes()
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": j.kid,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

func (j *rotatingJWKS) rotate(t *testing.T, kid string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	j.mu.Lock()
	j.kid = kid
	j.key = key
	j.mu.Unlock()
	return key
}

func TestJWTAuthenticatorValidatesAndProjectsPrincipal(t *testing.T) {
	state := &rotatingJWKS{}
	key := state.rotate(t, "key-1")
	server := httptest.NewServer(state)
	defer server.Close()
	authenticator := newTestJWTAuthenticator(t, server.URL)
	defer authenticator.Close()

	claims := validJWTClaims(time.Now())
	claims["roles"] = []string{"operator", "auditor", "operator"}
	claims["scope"] = "tools:read tools:call tools:read"
	claims["private"] = "must-not-be-projected"
	token := signJWT(t, key, "key-1", claims)
	principal, err := authenticator.Authenticate(context.Background(), bearerRequest(token))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.Subject != "alice" || principal.ClientID != "client-1" || principal.Issuer != testIssuer {
		t.Fatalf("principal = %#v", principal)
	}
	if len(principal.Roles) != 2 || len(principal.Scopes) != 2 || principal.Claims != nil {
		t.Fatalf("principal projection = %#v", principal)
	}
}

func TestJWTAuthenticatorRejectsInvalidRegisteredClaims(t *testing.T) {
	state := &rotatingJWKS{}
	key := state.rotate(t, "key-1")
	server := httptest.NewServer(state)
	defer server.Close()
	authenticator := newTestJWTAuthenticator(t, server.URL)
	defer authenticator.Close()
	now := time.Now()

	cases := []struct {
		name   string
		mutate func(jwtlib.MapClaims)
	}{
		{name: "wrong issuer", mutate: func(claims jwtlib.MapClaims) { claims["iss"] = "https://evil.example.com" }},
		{name: "wrong audience", mutate: func(claims jwtlib.MapClaims) { claims["aud"] = "other" }},
		{name: "expired", mutate: func(claims jwtlib.MapClaims) { claims["exp"] = now.Add(-time.Minute).Unix() }},
		{name: "not active", mutate: func(claims jwtlib.MapClaims) { claims["nbf"] = now.Add(time.Minute).Unix() }},
		{name: "missing expiry", mutate: func(claims jwtlib.MapClaims) { delete(claims, "exp") }},
		{name: "missing not before", mutate: func(claims jwtlib.MapClaims) { delete(claims, "nbf") }},
		{name: "missing subject", mutate: func(claims jwtlib.MapClaims) { delete(claims, "sub") }},
		{name: "missing client ID", mutate: func(claims jwtlib.MapClaims) { delete(claims, "client_id") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := validJWTClaims(now)
			tc.mutate(claims)
			token := signJWT(t, key, "key-1", claims)
			if _, err := authenticator.Authenticate(context.Background(), bearerRequest(token)); err == nil {
				t.Fatal("expected token validation error")
			}
		})
	}
}

func TestJWTAuthenticatorRejectsWrongSignatureAndAlgorithm(t *testing.T) {
	state := &rotatingJWKS{}
	state.rotate(t, "key-1")
	server := httptest.NewServer(state)
	defer server.Close()
	authenticator := newTestJWTAuthenticator(t, server.URL)
	defer authenticator.Close()

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongSignature := signJWT(t, wrongKey, "key-1", validJWTClaims(time.Now()))
	if _, err := authenticator.Authenticate(context.Background(), bearerRequest(wrongSignature)); err == nil {
		t.Fatal("expected wrong-signature error")
	}
	hsToken := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, validJWTClaims(time.Now()))
	hsToken.Header["kid"] = "key-1"
	rawHS, err := hsToken.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("sign HMAC token: %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), bearerRequest(rawHS)); err == nil {
		t.Fatal("expected disallowed-algorithm error")
	}
}

func TestJWTAuthenticatorRefreshesUnknownKeyID(t *testing.T) {
	state := &rotatingJWKS{}
	key1 := state.rotate(t, "key-1")
	server := httptest.NewServer(state)
	defer server.Close()
	authenticator := newTestJWTAuthenticator(t, server.URL)
	defer authenticator.Close()
	if _, err := authenticator.Authenticate(context.Background(), bearerRequest(signJWT(t, key1, "key-1", validJWTClaims(time.Now())))); err != nil {
		t.Fatalf("authenticate first key: %v", err)
	}

	key2 := state.rotate(t, "key-2")
	if _, err := authenticator.Authenticate(context.Background(), bearerRequest(signJWT(t, key2, "key-2", validJWTClaims(time.Now())))); err != nil {
		t.Fatalf("authenticate rotated key: %v", err)
	}
	state.mu.RLock()
	requests := state.requests
	state.mu.RUnlock()
	if requests < 2 {
		t.Fatalf("JWKS requests = %d, want at least 2", requests)
	}
}

func TestNewJWTAuthenticatorFailsClosedOnInvalidJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":"invalid"}`))
	}))
	defer server.Close()
	if _, err := NewJWTAuthenticator(context.Background(), JWTAuthenticatorConfig{
		Issuer:      testIssuer,
		Audience:    testAudience,
		JWKSURI:     server.URL,
		HTTPTimeout: time.Second,
	}); err == nil {
		t.Fatal("expected invalid JWKS startup error")
	}
}

func newTestJWTAuthenticator(t *testing.T, jwksURI string) *JWTAuthenticator {
	t.Helper()
	authenticator, err := NewJWTAuthenticator(context.Background(), JWTAuthenticatorConfig{
		Issuer:          testIssuer,
		Audience:        testAudience,
		JWKSURI:         jwksURI,
		ClockSkew:       0,
		HTTPTimeout:     2 * time.Second,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("new JWT authenticator: %v", err)
	}
	return authenticator
}

func validJWTClaims(now time.Time) jwtlib.MapClaims {
	return jwtlib.MapClaims{
		"iss":       testIssuer,
		"aud":       testAudience,
		"sub":       "alice",
		"client_id": "client-1",
		"exp":       now.Add(5 * time.Minute).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
	}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwtlib.MapClaims) string {
	t.Helper()
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

func bearerRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://proxy.local/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}
