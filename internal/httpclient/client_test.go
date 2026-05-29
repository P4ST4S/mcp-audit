package httpclient

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSetsTimeout(t *testing.T) {
	client, err := New(Config{Timeout: 1500 * time.Millisecond})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client.Timeout != 1500*time.Millisecond {
		t.Fatalf("timeout = %s, want 1.5s", client.Timeout)
	}
}

func TestNewTLSConfigRejectsMissingCAFile(t *testing.T) {
	_, err := NewTLSConfig(TLSConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")})
	if err == nil {
		t.Fatal("expected missing CA file error")
	}
}

func TestNewTLSConfigRejectsInvalidCAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	_, err := NewTLSConfig(TLSConfig{CAFile: path})
	if err == nil {
		t.Fatal("expected invalid CA file error")
	}
}

func TestNewTLSConfigRequiresClientCertAndKeyTogether(t *testing.T) {
	_, err := NewTLSConfig(TLSConfig{ClientCertFile: "client.crt"})
	if err == nil {
		t.Fatal("expected client cert/key pair validation error")
	}
}

func TestNewTLSConfigEnforcesTLS12Minimum(t *testing.T) {
	tlsConfig, err := NewTLSConfig(TLSConfig{ServerName: "upstream.local"})
	if err != nil {
		t.Fatalf("new tls config: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("min version = %d, want TLS 1.2", tlsConfig.MinVersion)
	}
}
