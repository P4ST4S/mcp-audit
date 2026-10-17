package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/gowebpki/jcs"
)

const checkpointAlgorithm = "hmac-sha256/sha256"
const checkpointDomain = "mcp-audit/checkpoint/v1\n"

// Checkpoint authenticates an ordered, complete artifact snapshot.
type Checkpoint struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Format    Format `json:"format"`
	Records   uint64 `json:"records"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type orderedDigest struct {
	hash  hash.Hash
	count uint64
}

func newOrderedDigest() *orderedDigest { return &orderedDigest{hash: sha256.New()} }
func (d *orderedDigest) add(canonical []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(canonical)))
	_, _ = d.hash.Write(size[:])
	_, _ = d.hash.Write(canonical)
	d.count++
}

func (c Checkpoint) signature(secret string) (string, error) {
	// Signature is excluded from the payload, not represented as an empty field.
	payload := struct {
		Version   int    `json:"version"`
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		Format    Format `json:"format"`
		Records   uint64 `json:"records"`
		Digest    string `json:"digest"`
	}{c.Version, c.Algorithm, c.KeyID, c.Format, c.Records, c.Digest}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(checkpointDomain))
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (c Checkpoint) verify(format Format, digest *orderedDigest, keys map[string]string) error {
	if c.Version != 1 || c.Algorithm != checkpointAlgorithm || c.Format != format {
		return fmt.Errorf("audit: checkpoint: unsupported format or version")
	}
	secret := keys[c.KeyID]
	if secret == "" {
		return fmt.Errorf("audit: checkpoint: unknown signing key")
	}
	expected, err := c.signature(secret)
	if err != nil {
		return fmt.Errorf("audit: checkpoint: signature payload: %w", err)
	}
	provided, err := hex.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("audit: checkpoint: invalid signature")
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(provided, want) {
		return fmt.Errorf("audit: checkpoint: invalid signature")
	}
	if c.Records != digest.count || c.Digest != hex.EncodeToString(digest.hash.Sum(nil)) {
		return fmt.Errorf("audit: checkpoint: artifact count, order or content does not match")
	}
	return nil
}

// CreateCheckpoint signs one nonempty artifact containing only valid v2 entries.
// Retain the expected checkpoint separately; replacing both inputs defeats freshness.
func CreateCheckpoint(path string, config Config, keyID string) (Checkpoint, error) {
	secret := config.Keys[keyID]
	if secret == "" {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint: signing key is required")
	}
	format := config.Format
	if format == "" || format == FormatAuto {
		var err error
		format, err = detectFormat(path)
		if err != nil {
			return Checkpoint{}, err
		}
	}
	digest := newOrderedDigest()
	config.Format, config.RequireIntegrityV2, config.Checkpoint, config.digest = format, true, nil, digest
	result, err := VerifyPath(path, config)
	if err != nil {
		return Checkpoint{}, err
	}
	if !result.Clean() {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint: source does not satisfy v2 policy: %s", result.FirstError)
	}
	checkpoint := Checkpoint{Version: 1, Algorithm: checkpointAlgorithm, KeyID: keyID, Format: format, Records: digest.count, Digest: hex.EncodeToString(digest.hash.Sum(nil))}
	checkpoint.Signature, err = checkpoint.signature(secret)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint: sign: %w", err)
	}
	return checkpoint, nil
}
