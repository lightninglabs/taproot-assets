package rfq

import (
	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSConfig represents TLS configuration options for oracle connections.
type TLSConfig struct {
	// Enabled indicates that we should use TLS.
	Enabled bool

	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool

	// TrustSystemRootCAs indicates whether or not to use the operating
	// system's root certificate authority list.
	TrustSystemRootCAs bool

	// CustomCertificates contains PEM data for additional root CA and
	// self-signed certificates to trust.
	CustomCertificates []byte
}

// configureTransportCredentials configures the TLS transport credentials to
// be used for RPC connections.
func configureTransportCredentials(
	config *TLSConfig) (credentials.TransportCredentials, error) {

	// If TLS is disabled, return insecure credentials.
	if !config.Enabled {
		return insecure.NewCredentials(), nil
	}

	// If we're to skip certificate verification, then return TLS
	// credentials with certificate verification disabled.
	if config.InsecureSkipVerify {
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
		return creds, nil
	}

	// Initialize the certificate pool.
	certPool, err := constructCertPool(config.TrustSystemRootCAs)
	if err != nil {
		return nil, err
	}

	// If we have any custom certificates, add them to the certificate
	// pool.
	certPool.AppendCertsFromPEM(config.CustomCertificates)

	// Return the constructed transport credentials.
	return credentials.NewClientTLSFromCert(certPool, ""), nil
}

// constructCertPool is a helper for constructing an initial certificate pool,
// depending on whether or not we should trust the system root CA list.
func constructCertPool(trustSystem bool) (*x509.CertPool, error) {
	if trustSystem {
		return x509.SystemCertPool()
	}
	return x509.NewCertPool(), nil
}
