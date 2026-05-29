package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TLSConfig configures TLS verification and optional client authentication.
type TLSConfig struct {
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
	ClientCertFile     string
	ClientKeyFile      string
}

// Config configures an HTTP client.
type Config struct {
	Timeout time.Duration
	TLS     TLSConfig
}

// New creates an HTTP client with the configured timeout and TLS settings.
func New(config Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig, err := NewTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}, nil
}

// NewTLSConfig creates a TLS config from file-based settings.
func NewTLSConfig(config TLSConfig) (*tls.Config, error) {
	if config.CAFile == "" && config.ServerName == "" && !config.InsecureSkipVerify && config.ClientCertFile == "" && config.ClientKeyFile == "" {
		return nil, nil
	}
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if config.CAFile != "" {
		pemBytes, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("httpclient: read tls ca file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("httpclient: parse tls ca file: no certificates found")
		}
		tlsConfig.RootCAs = roots
	}
	if config.ClientCertFile != "" || config.ClientKeyFile != "" {
		if config.ClientCertFile == "" || config.ClientKeyFile == "" {
			return nil, fmt.Errorf("httpclient: tls client cert and key must be configured together")
		}
		cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("httpclient: load tls client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}
