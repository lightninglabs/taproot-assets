package rfq

// TLSConfig represents TLS configuration options for oracle connections.
type TLSConfig struct {
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
}

// DefaultTLSConfig returns a default TLS configuration.
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		InsecureSkipVerify: true,
	}
}
