package httpclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
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

// writeSelfSignedCert generates a self-signed cert + key pair for TLS tests and
// writes them to disk. Returns the cert path, key path, and PEM-encoded CA.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "ca.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath, caPath
}

func TestNewTLSConfigLoadsValidCAFile(t *testing.T) {
	_, _, caPath := writeSelfSignedCert(t)
	tlsConfig, err := NewTLSConfig(TLSConfig{CAFile: caPath})
	if err != nil {
		t.Fatalf("new tls config: %v", err)
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs should be populated when CAFile is loaded")
	}
}

func TestNewTLSConfigLoadsValidClientCertAndKey(t *testing.T) {
	certPath, keyPath, _ := writeSelfSignedCert(t)
	tlsConfig, err := NewTLSConfig(TLSConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if err != nil {
		t.Fatalf("new tls config: %v", err)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestNewTLSConfigRejectsInvalidClientCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bogus-cert.pem")
	keyPath := filepath.Join(dir, "bogus-key.pem")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, err := NewTLSConfig(TLSConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if err == nil {
		t.Fatal("expected error when client cert/key are invalid")
	}
}

func TestNewTLSConfigRequiresClientKeyWhenCertProvided(t *testing.T) {
	_, err := NewTLSConfig(TLSConfig{ClientKeyFile: "key.pem"})
	if err == nil {
		t.Fatal("expected error when only ClientKeyFile is provided")
	}
}

func TestNewTLSConfigReturnsNilWhenNoFieldsSet(t *testing.T) {
	tlsConfig, err := NewTLSConfig(TLSConfig{})
	if err != nil {
		t.Fatalf("new tls config: %v", err)
	}
	if tlsConfig != nil {
		t.Fatal("expected nil TLS config when no fields are set")
	}
}

func TestNewTLSConfigSupportsInsecureSkipVerify(t *testing.T) {
	tlsConfig, err := NewTLSConfig(TLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("new tls config: %v", err)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be propagated")
	}
}

func TestNewClientWithTLSAppliesTransport(t *testing.T) {
	_, _, caPath := writeSelfSignedCert(t)
	client, err := New(Config{
		Timeout: time.Second,
		TLS:     TLSConfig{CAFile: caPath},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport should be *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("transport should have TLS config when CAFile is set")
	}
}

func TestNewClientPropagatesTLSConfigError(t *testing.T) {
	_, err := New(Config{
		Timeout: time.Second,
		TLS:     TLSConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")},
	})
	if err == nil {
		t.Fatal("expected error when CA file is missing")
	}
}

func TestNewClientWithoutTLSStillReturnsClient(t *testing.T) {
	// When no TLS settings are provided, the transport should still be set
	// (cloned default) but without an explicit TLSClientConfig override.
	client, err := New(Config{Timeout: time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client.Transport == nil {
		t.Fatal("transport should not be nil")
	}
}
