package rfq

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Test certificate data - a valid self-signed certificate for testing
const validTestCertPEM = `-----BEGIN CERTIFICATE-----
MIICmjCCAYICCQCuu1gzY+BBKjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0
ZXN0MB4XDTI1MDgyODEwNDA1NVoXDTI1MDgyOTEwNDA1NVowDzENMAsGA1UEAwwE
dGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTWCm8l3d9nE2QK
TK8HJ36ftO8pK3//nb8Nj/p97FrPFSgzdgL1ZNJs4gP5/ZsU+iE6VeKhalHoSf6/
IMLe3ATTL0rWA1M6z7cw6ll8VS8NQMaMSFWNomncsxyoJAQde++SC5f1RwQJBD/0
gGB4bJIIqUHtT12m23GLX48d6JGEEi5kEQtk91S/QGnHtglzZ8CQOogDBzDhSHu2
jj4mKYDgkXcyAqN7DoDzoEcrpeAaeAwem8k1sFBeTtrqT1ot7Ey5KG+RUyJbdKGt
5adJiwH782NgsSnISQ2X7Sct6Uu0JzHKx9JzyABsA05tf3cNJkLhh1Is9edYI2e9
m0dqedECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAQOCs/7xZVPjabbhdv30mUJMG
lddi2A+R/5IRXW1MKnpemwiv4ZWYQ9PMTmuR7kqaF7AGLkvx+5sp2evUJN4x7vHP
ao6wihbdh+vBkrobE+Y9dE7nbkvMQSNi1sXzDnfZB9LqY9Huun2soUwBQNCMPVMa
Wo7g6udwyA48doEVJMjThFLPcW7xmsy6Ldew682m1kD8/ag+9qihX1IJyiqiEjha
3uT4CT+zEg0RJorEJKbR38fE4Uhx1wZO4zvjEg6qZeW/I4lw+UzSY5xV7lJ1EQvf
BcoNuBHB65RxQM5fpA7hkEFm1bxBoowGX2hx6VCCeBBwREISRfgvkUxZahUXNg==
-----END CERTIFICATE-----`

// Invalid PEM data for testing failure cases
const invalidTestCertPEM = `-----BEGIN CERTIFICATE-----
This is not a valid certificate
-----END CERTIFICATE-----`

// DefaultTLSConfig returns a default TLS configuration for testing.
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		InsecureSkipVerify: true,
	}
}

// TestConfigureTransportCredentials_InsecureSkipVerify tests the function
// when InsecureSkipVerify is true.
func TestConfigureTransportCredentials_InsecureSkipVerify(t *testing.T) {
	config := &TLSConfig{
		InsecureSkipVerify: true,
	}

	creds, err := configureTransportCredentials(config)

	require.NoError(t, err)
	require.NotNil(t, creds)

	// Verify that we got insecure credentials by checking the type
	require.Equal(t, "insecure", creds.Info().SecurityProtocol)
}

// TestConfigureTransportCredentials_ValidCustomCertificates tests the
// function when valid custom certificates are provided.
func TestConfigureTransportCredentials_ValidCustomCertificates(t *testing.T) {
	config := &TLSConfig{
		InsecureSkipVerify: false,
		CustomCertificates: []byte(validTestCertPEM),
	}

	creds, err := configureTransportCredentials(config)

	require.NoError(t, err)
	require.NotNil(t, creds)

	// Verify that we got TLS credentials (not insecure)
	require.Equal(t, "tls", creds.Info().SecurityProtocol)
}

// TestConfigureTransportCredentials_NoCredentialsConfigured tests the
// function when no credentials are configured.
func TestConfigureTransportCredentials_NoCredentialsConfigured(t *testing.T) {
	config := &TLSConfig{
		InsecureSkipVerify: false,
		CustomCertificates: nil,
	}

	creds, err := configureTransportCredentials(config)

	require.NoError(t, err)
	require.NotNil(t, creds)
	require.Equal(t, "tls", creds.Info().SecurityProtocol)
}
