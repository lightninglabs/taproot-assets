package rfq

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// validCertificate is a valid certificate.
const validCertificate = `-----BEGIN CERTIFICATE-----
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

// invalidCertificate is an invalid certificate.
const invalidCertificate = `-----BEGIN CERTIFICATE-----
This is not a valid certificate
-----END CERTIFICATE-----`

// testCaseConfigureTransportCredentials is a test case for the
// configureTransportCredentials function.
type testCaseConfigureTransportCredentials struct {
	name string

	expectInsecure bool

	expectError bool

	tlsConfig *TLSConfig
}

// runConfigureTransportCredentialsTest tests that we get the expected
// security protocol from the provided test case.
func runConfigureTransportCredentialsTest(t *testing.T,
	tc *testCaseConfigureTransportCredentials) {

	creds, err := configureTransportCredentials(tc.tlsConfig)

	// If we expect an error, verify we got one and return.
	if tc.expectError {
		require.Error(t, err)
		require.Nil(t, creds)
		return
	}

	// Otherwise, we should not see an error.
	require.Nil(t, err)
	require.NotNil(t, creds)

	protocol := creds.Info().SecurityProtocol

	if tc.expectInsecure {
		require.Equal(t, "insecure", protocol)
		return
	}

	require.Equal(t, "tls", protocol)
}

// defaultTLSConfig is the default TLS config.
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		InsecureSkipVerify: false,
		TrustSystemRootCAs: true,
	}
}

// TestConfigureTransportCredentials tests the configureTransportCredentials
// function.
func TestConfigureTransportCredentials(t *testing.T) {
	testCases := []*testCaseConfigureTransportCredentials{
		{
			name:           "default configuration",
			expectInsecure: false,
			tlsConfig:      DefaultTLSConfig(),
		},
		{
			name:           "tls disabled",
			expectInsecure: true,
			tlsConfig: &TLSConfig{
				Disabled: true,
			},
		},
		{
			name:           "trust os root CAs",
			expectInsecure: false,
			tlsConfig: &TLSConfig{
				InsecureSkipVerify: false,
				TrustSystemRootCAs: true,
			},
		},
		{
			name:           "no trust os root CAs",
			expectInsecure: false,
			tlsConfig: &TLSConfig{
				InsecureSkipVerify: false,
				TrustSystemRootCAs: false,
			},
		},
		{
			name:           "valid custom certificate",
			expectInsecure: false,
			tlsConfig: &TLSConfig{
				InsecureSkipVerify: false,
				TrustSystemRootCAs: false,
				CustomCertificates: []byte(validCertificate),
			},
		},
		{
			name:           "invalid custom certificate",
			expectInsecure: false,
			expectError:    true,
			tlsConfig: &TLSConfig{
				InsecureSkipVerify: false,
				TrustSystemRootCAs: false,
				CustomCertificates: []byte(invalidCertificate),
			},
		},
	}

	for _, tc := range testCases {
		runConfigureTransportCredentialsTest(t, tc)
	}
}
