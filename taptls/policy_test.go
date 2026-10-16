package taptls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/cert"
	"github.com/stretchr/testify/require"
)

// testServer is a local TLS server with a self-signed certificate.
type testServer struct {
	// addr is the address the server listens on.
	addr string

	// certPEM is the server's PEM-encoded certificate.
	certPEM []byte
}

// startTestServer starts a TLS server on a free loopback port that completes
// handshakes and then closes the connection.
func startTestServer(t *testing.T) *testServer {
	t.Helper()

	certPEM, keyPEM, err := cert.GenCertPair(
		"taptls test", nil, nil, false, time.Hour,
	)
	require.NoError(t, err)

	tlsCert, _, err := cert.LoadCertFromBytes(certPEM, keyPEM)
	require.NoError(t, err)

	tlsConf := cert.TLSConfFromCert(tlsCert)
	tlsConf.NextProtos = []string{"h2"}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = lis.Close()
	})

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func() {
				tlsConn, ok := conn.(*tls.Conn)
				if ok {
					_ = tlsConn.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()

	return &testServer{
		addr:    lis.Addr().String(),
		certPEM: certPEM,
	}
}

// handshake connects to the server and runs a client handshake with the
// credentials the policy selects for the given dial target.
func handshake(t *testing.T, p Policy, srv *testServer, target string) error {
	t.Helper()

	conn, err := net.Dial("tcp", srv.addr)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	creds := p.credentials(hostOf(target))
	_, _, err = creds.ClientHandshake(ctx, target, conn)

	return err
}

// TestPolicyVerification tests which servers each policy accepts.
func TestPolicyVerification(t *testing.T) {
	srv := startTestServer(t)
	other := startTestServer(t)

	_, port, err := net.SplitHostPort(srv.addr)
	require.NoError(t, err)

	ipTarget := srv.addr
	nameTarget := net.JoinHostPort("localhost", port)

	pin := func(host string, pem []byte) map[string][]byte {
		return map[string][]byte{host: pem}
	}

	tests := []struct {
		name   string
		cfg    Config
		target string
		accept bool
	}{
		{
			name:   "system roots reject self-signed",
			target: ipTarget,
		},
		{
			name: "pin accepts pinned host",
			cfg: Config{
				Pins: pin("127.0.0.1", srv.certPEM),
			},
			target: ipTarget,
			accept: true,
		},
		{
			name: "pin by name accepts pinned host",
			cfg: Config{
				Pins: pin("LOCALHOST", srv.certPEM),
			},
			target: nameTarget,
			accept: true,
		},
		{
			name: "pin does not apply to other hosts",
			cfg: Config{
				Pins: pin("localhost", srv.certPEM),
			},
			target: ipTarget,
		},
		{
			name: "pin rejects other certificate",
			cfg: Config{
				Pins: pin("127.0.0.1", other.certPEM),
			},
			target: ipTarget,
		},
		{
			name: "pin replaces trusted roots",
			cfg: Config{
				Roots: srv.certPEM,
				Pins:  pin("127.0.0.1", other.certPEM),
			},
			target: ipTarget,
		},
		{
			name: "exception accepts host",
			cfg: Config{
				SkipVerifyHosts: []string{"127.0.0.1"},
			},
			target: ipTarget,
			accept: true,
		},
		{
			name: "exception does not apply to other hosts",
			cfg: Config{
				SkipVerifyHosts: []string{"localhost"},
			},
			target: ipTarget,
		},
		{
			name: "skip-verify mode accepts host",
			cfg: Config{
				Mode: ModeSkipVerify,
			},
			target: ipTarget,
			accept: true,
		},
		{
			name: "trusted roots accept host",
			cfg: Config{
				Roots: srv.certPEM,
			},
			target: ipTarget,
			accept: true,
		},
		{
			name: "trusted roots without system roots accept host",
			cfg: Config{
				NoSystemRoots: true,
				Roots:         srv.certPEM,
			},
			target: ipTarget,
			accept: true,
		},
		{
			name: "no roots reject host",
			cfg: Config{
				NoSystemRoots: true,
			},
			target: ipTarget,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := New(tc.cfg)
			require.NoError(t, err)

			err = handshake(t, policy, srv, tc.target)
			if tc.accept {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, "certificate")
		})
	}
}

// TestPolicyHostScoped tests which targets have a pin or a verification
// exception.
func TestPolicyHostScoped(t *testing.T) {
	srv := startTestServer(t)

	policy, err := New(Config{
		Pins: map[string][]byte{
			"pinned.example.com": srv.certPEM,
		},
		SkipVerifyHosts: []string{"::1"},
	})
	require.NoError(t, err)

	require.True(t, policy.HostScoped("Pinned.example.com:10029"))
	require.True(t, policy.HostScoped("[::1]:443"))
	require.False(t, policy.HostScoped("other.example.com:10029"))

	skipVerify, err := New(Config{Mode: ModeSkipVerify})
	require.NoError(t, err)
	require.False(t, skipVerify.HostScoped("other.example.com:10029"))

	var zero Policy
	require.False(t, zero.HostScoped("other.example.com:10029"))
}

// TestPolicyProtocol tests the security protocol of each mode.
func TestPolicyProtocol(t *testing.T) {
	tests := []struct {
		mode     Mode
		protocol string
	}{
		{mode: ModeVerify, protocol: "tls"},
		{mode: ModeSkipVerify, protocol: "tls"},
		{mode: ModePlaintext, protocol: "insecure"},
	}

	for _, tc := range tests {
		t.Run(tc.mode.String(), func(t *testing.T) {
			policy, err := New(Config{Mode: tc.mode})
			require.NoError(t, err)

			creds := policy.credentials("example.com")
			require.Equal(
				t, tc.protocol, creds.Info().SecurityProtocol,
			)
		})
	}

	var zero Policy
	require.Equal(
		t, "tls", zero.credentials("example.com").Info().
			SecurityProtocol,
	)
}

// TestNewInvalidConfig tests that New rejects invalid configs.
func TestNewInvalidConfig(t *testing.T) {
	srv := startTestServer(t)

	tests := []struct {
		name string
		cfg  Config
		err  string
	}{
		{
			name: "unknown mode",
			cfg: Config{
				Mode: Mode(9),
			},
			err: "unknown mode",
		},
		{
			name: "pins without verification",
			cfg: Config{
				Mode: ModeSkipVerify,
				Pins: map[string][]byte{
					"example.com": srv.certPEM,
				},
			},
			err: "require mode verify",
		},
		{
			name: "exceptions without TLS",
			cfg: Config{
				Mode:            ModePlaintext,
				SkipVerifyHosts: []string{"example.com"},
			},
			err: "require mode verify",
		},
		{
			name: "roots without verification",
			cfg: Config{
				Mode:  ModeSkipVerify,
				Roots: srv.certPEM,
			},
			err: "require mode verify",
		},
		{
			name: "invalid roots",
			cfg: Config{
				Roots: []byte("not a certificate"),
			},
			err: "no valid certificates in trusted roots",
		},
		{
			name: "invalid pin",
			cfg: Config{
				Pins: map[string][]byte{
					"example.com": []byte("not a cert"),
				},
			},
			err: "no valid certificates pinned",
		},
		{
			name: "pinned host with port",
			cfg: Config{
				Pins: map[string][]byte{
					"example.com:10029": srv.certPEM,
				},
			},
			err: "must not include a port",
		},
		{
			name: "empty exception host",
			cfg: Config{
				SkipVerifyHosts: []string{""},
			},
			err: "empty host",
		},
		{
			name: "host pinned twice",
			cfg: Config{
				Pins: map[string][]byte{
					"example.com": srv.certPEM,
					"EXAMPLE.com": srv.certPEM,
				},
			},
			err: "pinned more than once",
		},
		{
			name: "host pinned and exempt",
			cfg: Config{
				Pins: map[string][]byte{
					"example.com": srv.certPEM,
				},
				SkipVerifyHosts: []string{"Example.com"},
			},
			err: "both pinned and exempt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

// TestHostNormalization tests that config hosts and dial targets map to the
// same canonical host.
func TestHostNormalization(t *testing.T) {
	tests := []struct {
		configHost string
		target     string
		canonical  string
	}{
		{
			configHost: "Example.COM",
			target:     "example.com:10029",
			canonical:  "example.com",
		},
		{
			configHost: "example.com",
			target:     "EXAMPLE.com",
			canonical:  "example.com",
		},
		{
			configHost: "127.0.0.1",
			target:     "127.0.0.1:443",
			canonical:  "127.0.0.1",
		},
		{
			configHost: "[::1]",
			target:     "[::1]:10029",
			canonical:  "::1",
		},
		{
			configHost: "0:0:0:0:0:0:0:1",
			target:     "[::1]:10029",
			canonical:  "::1",
		},
	}

	for _, tc := range tests {
		host, err := normalizeHost(tc.configHost)
		require.NoError(t, err)
		require.Equal(t, tc.canonical, host)
		require.Equal(t, tc.canonical, hostOf(tc.target))
	}
}
