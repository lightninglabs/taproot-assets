package healthcheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// createTestCert creates a self-signed certificate for testing purposes.
func createTestCert(t *testing.T, notAfter time.Time) string {
	t.Helper()

	// Generate a new ECDSA private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	// Create self-signed certificate.
	certDER, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	require.NoError(t, err)

	// Write certificate to temp file.
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "tls.cert")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0644))

	return certPath
}

// TestCheckCertExpiry_Valid tests that a valid certificate passes the check.
func TestCheckCertExpiry_Valid(t *testing.T) {
	// Create a certificate that expires in 1 year.
	certPath := createTestCert(t, time.Now().Add(365*24*time.Hour))

	err := checkCertExpiry(certPath)
	require.NoError(t, err)
}

// TestCheckCertExpiry_Expired tests that an expired certificate fails.
func TestCheckCertExpiry_Expired(t *testing.T) {
	// Create a certificate that expired 1 hour ago.
	certPath := createTestCert(t, time.Now().Add(-time.Hour))

	err := checkCertExpiry(certPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

// TestCheckCertExpiry_MissingFile tests that a missing file returns an error.
func TestCheckCertExpiry_MissingFile(t *testing.T) {
	err := checkCertExpiry("/nonexistent/path/tls.cert")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to read")
}

// TestNewTLSCheck tests creating a TLS health check observation.
func TestNewTLSCheck(t *testing.T) {
	certPath := createTestCert(t, time.Now().Add(365*24*time.Hour))

	cfg := &TLSCheckConfig{
		CertPath: certPath,
		Interval: time.Minute,
		Timeout:  5 * time.Second,
		Backoff:  time.Minute,
		Attempts: 2,
	}

	obs := NewTLSCheck(cfg)
	require.Equal(t, "tls", obs.Name)
	require.Equal(t, 2, obs.Attempts)

	// The check function should succeed for a valid cert.
	errChan := obs.Check()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("check timed out")
	}
}
