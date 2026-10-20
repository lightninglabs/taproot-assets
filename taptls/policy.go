// Package taptls builds the transport credentials that tapd uses for
// outbound gRPC connections.
package taptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Mode is the security mode of an outbound connection.
type Mode uint8

const (
	// ModeVerify uses TLS and authenticates the server: its certificate
	// must chain to a trusted root and match the dialed host name.
	ModeVerify Mode = iota

	// ModeSkipVerify uses TLS without authenticating the server.
	ModeSkipVerify

	// ModePlaintext uses no TLS.
	ModePlaintext
)

// String returns the name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeVerify:
		return "verify"

	case ModeSkipVerify:
		return "skip-verify"

	case ModePlaintext:
		return "plaintext"

	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

// Config describes the TLS policy for one class of outbound connections.
// The zero value verifies servers against the system roots.
type Config struct {
	// Mode is the mode used for hosts that have no host-specific
	// setting.
	Mode Mode

	// NoSystemRoots excludes the operating system's root certificates
	// from the trusted roots.
	NoSystemRoots bool

	// Roots holds PEM-encoded certificates that are trusted as roots for
	// all hosts, in addition to the system roots unless NoSystemRoots is
	// set.
	Roots []byte

	// Pins maps a host name or IP address to PEM-encoded certificates
	// that are the only roots trusted for that host.
	Pins map[string][]byte

	// SkipVerifyHosts lists host names or IP addresses whose server
	// certificates are not verified.
	SkipVerifyHosts []string
}

// Policy is a validated TLS policy for one class of outbound connections.
// The zero value verifies servers against the system roots.
type Policy struct {
	// mode is the mode used for hosts that have no host-specific setting.
	mode Mode

	// roots is the pool of roots trusted for all hosts. If nil, the
	// system roots are used.
	roots *x509.CertPool

	// pins maps a normalized host to the only roots trusted for it.
	pins map[string]*x509.CertPool

	// skipHosts is the set of normalized hosts whose server certificates
	// are not verified.
	skipHosts map[string]struct{}
}

// New validates the given config and returns the policy it describes.
func New(cfg Config) (Policy, error) {
	if cfg.Mode > ModePlaintext {
		return Policy{}, fmt.Errorf("unknown mode %v", cfg.Mode)
	}

	hostScoped := len(cfg.Pins) > 0 || len(cfg.SkipVerifyHosts) > 0
	customRoots := cfg.NoSystemRoots || len(cfg.Roots) > 0
	if cfg.Mode != ModeVerify && (hostScoped || customRoots) {
		return Policy{}, fmt.Errorf("trusted roots, pins and "+
			"verification exceptions require mode %v, got %v",
			ModeVerify, cfg.Mode)
	}

	policy := Policy{
		mode: cfg.Mode,
	}

	if customRoots {
		roots := x509.NewCertPool()
		if !cfg.NoSystemRoots {
			var err error
			roots, err = x509.SystemCertPool()
			if err != nil {
				return Policy{}, fmt.Errorf("unable to load "+
					"system roots: %w", err)
			}
		}

		if len(cfg.Roots) > 0 {
			if !roots.AppendCertsFromPEM(cfg.Roots) {
				return Policy{}, fmt.Errorf("no valid " +
					"certificates in trusted roots")
			}
		}

		policy.roots = roots
	}

	if len(cfg.Pins) > 0 {
		policy.pins = make(map[string]*x509.CertPool, len(cfg.Pins))
	}
	for host, pem := range cfg.Pins {
		key, err := normalizeHost(host)
		if err != nil {
			return Policy{}, fmt.Errorf("invalid pinned host %q: "+
				"%w", host, err)
		}

		if _, ok := policy.pins[key]; ok {
			return Policy{}, fmt.Errorf("host %q pinned more "+
				"than once", key)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return Policy{}, fmt.Errorf("no valid certificates "+
				"pinned for host %q", key)
		}

		policy.pins[key] = pool
	}

	if len(cfg.SkipVerifyHosts) > 0 {
		policy.skipHosts = make(
			map[string]struct{}, len(cfg.SkipVerifyHosts),
		)
	}
	for _, host := range cfg.SkipVerifyHosts {
		key, err := normalizeHost(host)
		if err != nil {
			return Policy{}, fmt.Errorf("invalid verification "+
				"exception host %q: %w", host, err)
		}

		if _, ok := policy.pins[key]; ok {
			return Policy{}, fmt.Errorf("host %q is both pinned "+
				"and exempt from verification", key)
		}

		policy.skipHosts[key] = struct{}{}
	}

	return policy, nil
}

// HostScoped reports whether a pin or a verification exception applies to the
// given target, a host or host:port.
func (p Policy) HostScoped(target string) bool {
	host := hostOf(target)

	_, pinned := p.pins[host]
	_, skipped := p.skipHosts[host]

	return pinned || skipped
}

// DialOption returns the transport credentials dial option for a connection
// to the given target, a host or host:port.
func (p Policy) DialOption(target string) grpc.DialOption {
	return grpc.WithTransportCredentials(p.credentials(hostOf(target)))
}

// credentials returns the transport credentials for a connection to the
// given normalized host.
func (p Policy) credentials(host string) credentials.TransportCredentials {
	if p.mode == ModePlaintext {
		return insecure.NewCredentials()
	}

	_, skip := p.skipHosts[host]
	if p.mode == ModeSkipVerify || skip {
		return credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,

			//nolint:gosec
			InsecureSkipVerify: true,
		})
	}

	roots := p.roots
	if pinned, ok := p.pins[host]; ok {
		roots = pinned
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	})
}

// normalizeHost returns the canonical form of a host name or IP address
// given in a config. It rejects empty hosts and hosts with a port.
func normalizeHost(host string) (string, error) {
	canonical := canonicalHost(host)
	if canonical == "" {
		return "", fmt.Errorf("empty host")
	}

	if net.ParseIP(canonical) == nil && strings.Contains(canonical, ":") {
		return "", fmt.Errorf("host must not include a port")
	}

	return canonical, nil
}

// hostOf returns the canonical host of a dial target, a host or host:port.
func hostOf(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	return canonicalHost(host)
}

// canonicalHost returns a host name or IP address without enclosing brackets
// or a trailing dot, with names in lower case and IP addresses in their
// standard form.
func canonicalHost(host string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.TrimSuffix(host, ".")

	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	return strings.ToLower(host)
}
