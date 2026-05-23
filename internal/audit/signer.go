package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Signer signs audit entries using HMAC-SHA256.
type Signer struct {
	secret []byte
}

// NewSigner returns a signer for secret. Empty secrets disable signing.
func NewSigner(secret string) *Signer {
	return &Signer{secret: []byte(secret)}
}

// Enabled reports whether the signer has a secret.
func (s *Signer) Enabled() bool {
	return s != nil && len(s.secret) > 0
}

// Sign returns the HMAC-SHA256 signature for entry.
func (s *Signer) Sign(entry Entry) string {
	if !s.Enabled() {
		return ""
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(entry.ID))
	mac.Write([]byte(entry.Timestamp.UTC().Format(time.RFC3339Nano)))
	mac.Write([]byte(entry.Method))
	mac.Write([]byte(entry.ToolName))
	mac.Write(entry.Params)
	return hex.EncodeToString(mac.Sum(nil))
}
