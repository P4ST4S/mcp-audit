package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// JWTAuthenticatorConfig configures OIDC resource-server token validation.
type JWTAuthenticatorConfig struct {
	Issuer          string
	Audience        string
	JWKSURI         string
	ClientIDClaim   string
	RolesClaim      string
	ScopesClaim     string
	AllowedMethods  []string
	ClockSkew       time.Duration
	HTTPTimeout     time.Duration
	RefreshInterval time.Duration
}

// JWTAuthenticator verifies bearer JWTs against a rotating remote JWKS.
type JWTAuthenticator struct {
	config JWTAuthenticatorConfig
	keys   keyfunc.Keyfunc
	cancel context.CancelFunc
	once   sync.Once
}

// NewJWTAuthenticator initializes the JWKS cache and validates its first key set.
func NewJWTAuthenticator(ctx context.Context, config JWTAuthenticatorConfig) (*JWTAuthenticator, error) {
	if config.Issuer == "" || config.Audience == "" || config.JWKSURI == "" {
		return nil, fmt.Errorf("auth: oidc: issuer, audience, and jwks_uri are required")
	}
	if config.ClientIDClaim == "" {
		config.ClientIDClaim = "client_id"
	}
	if config.RolesClaim == "" {
		config.RolesClaim = "roles"
	}
	if config.ScopesClaim == "" {
		config.ScopesClaim = "scope"
	}
	if len(config.AllowedMethods) == 0 {
		config.AllowedMethods = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
	}
	if config.ClockSkew < 0 {
		return nil, fmt.Errorf("auth: oidc: clock skew must be non-negative")
	}
	if config.HTTPTimeout <= 0 {
		config.HTTPTimeout = 5 * time.Second
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 5 * time.Minute
	}
	if err := preflightJWKS(ctx, config.JWKSURI, config.HTTPTimeout); err != nil {
		return nil, err
	}
	cacheCtx, cancel := context.WithCancel(ctx)
	keys, err := keyfunc.NewDefaultOverrideCtx(cacheCtx, []string{config.JWKSURI}, keyfunc.Override{
		HTTPTimeout:       config.HTTPTimeout,
		RefreshInterval:   config.RefreshInterval,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(time.Second), 1),
		RateLimitWaitMax:  config.HTTPTimeout,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("auth: oidc: initialize JWKS: %w", err)
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, config.HTTPTimeout)
	defer readyCancel()
	for {
		verificationKeys, lookupErr := keys.VerificationKeySet(readyCtx)
		if lookupErr == nil && len(verificationKeys.Keys) > 0 {
			break
		}
		select {
		case <-readyCtx.Done():
			cancel()
			return nil, fmt.Errorf("auth: oidc: JWKS cache did not become ready: %w", readyCtx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	return &JWTAuthenticator{config: config, keys: keys, cancel: cancel}, nil
}

func preflightJWKS(ctx context.Context, uri string, timeout time.Duration) error {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("auth: oidc: create JWKS request: %w", err)
	}
	response, err := (&http.Client{Timeout: timeout}).Do(request)
	if err != nil {
		return fmt.Errorf("auth: oidc: fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("auth: oidc: fetch JWKS: unexpected HTTP status %d", response.StatusCode)
	}
	const maxJWKSBytes = int64(1024 * 1024)
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("auth: oidc: read JWKS: %w", err)
	}
	if int64(len(raw)) > maxJWKSBytes {
		return fmt.Errorf("auth: oidc: JWKS exceeds %d bytes", maxJWKSBytes)
	}
	if _, err := keyfunc.NewJWKSetJSON(raw); err != nil {
		return fmt.Errorf("auth: oidc: validate JWKS: %w", err)
	}
	return nil
}

// Authenticate verifies a JWT and projects only configured identity fields.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, request *http.Request) (*Principal, error) {
	rawToken, err := bearerToken(request)
	if err != nil {
		return nil, err
	}
	claims := jwtlib.MapClaims{}
	token, err := jwtlib.ParseWithClaims(rawToken, claims, a.keys.KeyfuncCtx(ctx),
		jwtlib.WithValidMethods(a.config.AllowedMethods),
		jwtlib.WithIssuer(a.config.Issuer),
		jwtlib.WithAudience(a.config.Audience),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithNotBeforeRequired(),
		jwtlib.WithLeeway(a.config.ClockSkew),
		jwtlib.WithJSONNumber(),
		jwtlib.WithStrictDecoding(),
	)
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("%w: token validation failed", ErrInvalidCredentials)
	}
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return nil, fmt.Errorf("%w: subject claim is required", ErrInvalidCredentials)
	}
	clientID, ok := stringClaim(claims, a.config.ClientIDClaim)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("%w: client ID claim %q is required", ErrInvalidCredentials, a.config.ClientIDClaim)
	}
	roles, err := stringListClaim(claims, a.config.RolesClaim, false)
	if err != nil {
		return nil, fmt.Errorf("%w: roles claim: %v", ErrInvalidCredentials, err)
	}
	scopes, err := stringListClaim(claims, a.config.ScopesClaim, true)
	if err != nil {
		return nil, fmt.Errorf("%w: scopes claim: %v", ErrInvalidCredentials, err)
	}
	return &Principal{
		Subject:  subject,
		ClientID: clientID,
		Issuer:   a.config.Issuer,
		Roles:    roles,
		Scopes:   scopes,
	}, nil
}

// Close stops background JWKS refreshes. It is safe to call more than once.
func (a *JWTAuthenticator) Close() error {
	a.once.Do(a.cancel)
	return nil
}

func stringClaim(claims jwtlib.MapClaims, name string) (string, bool) {
	value, ok := claims[name]
	if !ok {
		return "", false
	}
	stringValue, ok := value.(string)
	return stringValue, ok
}

func stringListClaim(claims jwtlib.MapClaims, name string, splitSpaces bool) ([]string, error) {
	value, ok := claims[name]
	if !ok {
		return nil, nil
	}
	var values []string
	switch typed := value.(type) {
	case string:
		if splitSpaces {
			values = strings.Fields(typed)
		} else if typed != "" {
			values = []string{typed}
		}
	case []any:
		values = make([]string, 0, len(typed))
		for _, item := range typed {
			stringItem, ok := item.(string)
			if !ok || stringItem == "" {
				return nil, fmt.Errorf("must contain only non-empty strings")
			}
			values = append(values, stringItem)
		}
	default:
		return nil, fmt.Errorf("must be a string or string array")
	}
	return deduplicateStrings(values), nil
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
