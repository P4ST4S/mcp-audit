package integrity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	VersionV2       = 2
	AlgorithmHMACV2 = "hmac-sha256"
	DefaultKeyID    = "default"
)

var (
	ErrUnsupportedVersion   = errors.New("audit: integrity: unsupported version")
	ErrUnsupportedAlgorithm = errors.New("audit: integrity: unsupported algorithm")
	ErrUnknownKey           = errors.New("audit: integrity: unknown key ID")
	ErrInvalidSignature     = errors.New("audit: integrity: invalid signature")
)

// Metadata is stored alongside an audit entry without changing legacy signature semantics.
type Metadata struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Signer creates Integrity v2 HMAC-SHA256 metadata.
type Signer struct {
	secret []byte
	keyID  string
}

// NewSigner creates an Integrity v2 signer. Empty secrets disable it.
func NewSigner(secret, keyID string) *Signer {
	if strings.TrimSpace(keyID) == "" {
		keyID = DefaultKeyID
	}
	return &Signer{secret: []byte(secret), keyID: keyID}
}

// Enabled reports whether the signer has a secret.
func (s *Signer) Enabled() bool {
	return s != nil && len(s.secret) > 0
}

// Sign returns Integrity v2 metadata for entry.
func (s *Signer) Sign(entry EntryV2) (*Metadata, error) {
	if !s.Enabled() {
		return nil, nil
	}
	canonical, err := Canonicalize(entry)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write(canonical)
	return &Metadata{
		Version:   VersionV2,
		Algorithm: AlgorithmHMACV2,
		KeyID:     s.keyID,
		Signature: hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

// Verifier verifies Integrity v2 records against a key ID to secret mapping.
type Verifier struct {
	keys map[string][]byte
}

// NewVerifier creates a verifier and defensively copies the key material.
func NewVerifier(keys map[string]string) *Verifier {
	copied := make(map[string][]byte, len(keys))
	for keyID, secret := range keys {
		copied[keyID] = []byte(secret)
	}
	return &Verifier{keys: copied}
}

// Verify authenticates entry using metadata's version, algorithm, and key ID.
func (v *Verifier) Verify(entry EntryV2, metadata *Metadata) error {
	if metadata == nil {
		return ErrInvalidSignature
	}
	if metadata.Version != VersionV2 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, metadata.Version)
	}
	if metadata.Algorithm != AlgorithmHMACV2 {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, metadata.Algorithm)
	}
	if v == nil {
		return fmt.Errorf("%w: %q", ErrUnknownKey, metadata.KeyID)
	}
	secret, ok := v.keys[metadata.KeyID]
	if !ok || len(secret) == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownKey, metadata.KeyID)
	}
	provided, err := hex.DecodeString(metadata.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed encoding", ErrInvalidSignature)
	}
	canonical, err := Canonicalize(entry)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(canonical)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return ErrInvalidSignature
	}
	return nil
}
