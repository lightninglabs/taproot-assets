package healthcheck

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// TLSCheckConfig contains the configuration for TLS certificate health checks.
type TLSCheckConfig struct {
	// CertPath is the path to the TLS certificate file.
	CertPath string

	// Interval is the duration between health checks.
	Interval time.Duration

	// Timeout is the maximum duration for a health check.
	Timeout time.Duration

	// Backoff is the duration to wait between retries on failure.
	Backoff time.Duration

	// Attempts is the number of times to retry before failing.
	Attempts int
}

// NewTLSCheck creates a health check observation for TLS certificate expiry.
func NewTLSCheck(cfg *TLSCheckConfig) *Observation {
	return NewObservation(
		"tls",
		func() error {
			return checkCertExpiry(cfg.CertPath)
		},
		cfg.Interval,
		cfg.Timeout,
		cfg.Backoff,
		cfg.Attempts,
	)
}

// checkCertExpiry checks if the TLS certificate at the given path has expired.
func checkCertExpiry(certPath string) error {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("unable to read TLS certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf(
			"TLS certificate expired at %v",
			cert.NotAfter,
		)
	}

	return nil
}
