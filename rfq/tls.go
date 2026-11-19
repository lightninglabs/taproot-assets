package rfq

// TLSCliConfig holds TLS-related CLI configuration options shared by all RFQ
// gRPC client connections (price oracle, portfolio pilot).
//
// nolint: lll
type TLSCliConfig struct {
	Disable bool `long:"disable" description:"Disable TLS for RFQ gRPC client communication (price oracle, portfolio pilot)."`

	Insecure bool `long:"insecure" description:"Disable certificate verification for RFQ gRPC client connections. Should only be used for testing."`

	NoSystemCAs bool `long:"nosystemcas" description:"Disable use of the operating system's list of root CA's when verifying RFQ gRPC server certificates."`

	CertPath string `long:"certpath" description:"Path to a PEM-encoded x509 certificate to use when constructing TLS connections for RFQ gRPC clients."`
}
