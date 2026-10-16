package tapcfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/caddyserver/certmagic"
	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/stretchr/testify/require"
)

// TestValidateReOrgSafeDepth pins the accepted range of the re-org
// safe depth. Out-of-range values used to pass startup cleanly and
// then fail every anchoring registration after its transaction had
// already broadcast.
func TestValidateReOrgSafeDepth(t *testing.T) {
	t.Parallel()

	maxConfs := int32(chainntnfs.MaxNumConfs)

	testCases := []struct {
		name  string
		depth int32
		valid bool
	}{
		{name: "negative", depth: -1, valid: false},
		{name: "zero", depth: 0, valid: false},
		{name: "one collapses act gating", depth: 1, valid: true},
		{name: "default", depth: defaultReOrgSafeDepth, valid: true},
		{
			name:  "testnet default",
			depth: testnetDefaultReOrgSafeDepth,
			valid: true,
		},
		{name: "notifier maximum", depth: maxConfs, valid: true},
		{
			name:  "beyond notifier maximum",
			depth: maxConfs + 1,
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReOrgSafeDepth(tc.depth, btclog.Disabled)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestUniverseTLSPolicy tests the parsing of the universe TLS flags and the
// policy built from them.
func TestUniverseTLSPolicy(t *testing.T) {
	t.Parallel()

	certPEM, _, err := cert.GenCertPair(
		"tapcfg test", nil, nil, false, time.Hour,
	)
	require.NoError(t, err)

	certPath := filepath.Join(t.TempDir(), "peer=1.cert")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))

	missingPath := filepath.Join(t.TempDir(), "missing.cert")

	pinFlag := "--universe.tls.pin=uni.example.com="

	testCases := []struct {
		name string
		args []string
		pins map[string]string
		err  string
	}{
		{
			name: "default",
		},
		{
			name: "pins and exceptions",
			args: []string{
				pinFlag + certPath,
				"--universe.tls.pin=[::1]=" + certPath,
				"--universe.tls.insecurehost=other.example.com",
			},
			pins: map[string]string{
				"uni.example.com": certPath,
				"[::1]":           certPath,
			},
		},
		{
			name: "insecure",
			args: []string{
				"--universe.tls.insecure",
			},
		},
		{
			name: "insecure with pin",
			args: []string{
				"--universe.tls.insecure",
				pinFlag + certPath,
			},
			err: "require mode verify",
		},
		{
			name: "pinned and exempt host",
			args: []string{
				pinFlag + certPath,
				"--universe.tls.insecurehost=uni.example.com",
			},
			err: "both pinned and exempt",
		},
		{
			name: "missing pinned certificate",
			args: []string{
				pinFlag + missingPath,
			},
			err: "unable to read certificate pinned for host " +
				"uni.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			_, err := flags.ParseArgs(&cfg, tc.args)
			require.NoError(t, err)

			if tc.pins != nil {
				require.Equal(t, tc.pins, cfg.Universe.TLS.Pins)
			}

			_, err = getUniverseTLSPolicy(
				cfg.Universe.TLS, btclog.Disabled,
			)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestValidateConfigLetsEncryptDir tests the Let's Encrypt directory of a
// validated config with a custom tapd directory.
func TestValidateConfigLetsEncryptDir(t *testing.T) {
	explicitDir := t.TempDir()

	testCases := []struct {
		name           string
		letsEncryptDir string
		expected       func(tapdDir string) string
	}{
		{
			name:           "default moves into tapd directory",
			letsEncryptDir: defaultLetsEncryptDir,
			expected: func(tapdDir string) string {
				return filepath.Join(
					tapdDir, defaultLetsEncryptDirname,
				)
			},
		},
		{
			name:           "explicit directory is kept",
			letsEncryptDir: explicitDir,
			expected: func(string) string {
				return explicitDir
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tapdDir := t.TempDir()

			cfg := DefaultConfig()
			cfg.TapdDir = tapdDir
			cfg.RpcConf.LetsEncryptDir = tc.letsEncryptDir

			validated, err := ValidateConfig(cfg, btclog.Disabled)
			require.NoError(t, err)
			require.Equal(
				t, tc.expected(tapdDir),
				validated.RpcConf.LetsEncryptDir,
			)
		})
	}
}

// TestLetsEncryptConfig tests the storage and the issuers of the Let's Encrypt
// certmagic config.
func TestLetsEncryptConfig(t *testing.T) {
	t.Parallel()

	rpcCfg := &RpcConfig{
		LetsEncryptDir:    t.TempDir(),
		LetsEncryptListen: "127.0.0.1:8080",
		LetsEncryptEmail:  "ops@example.com",
	}

	certCfg, err := letsEncryptConfig(rpcCfg)
	require.NoError(t, err)

	storage, ok := certCfg.Storage.(*certmagic.FileStorage)
	require.True(t, ok)
	require.Equal(t, rpcCfg.LetsEncryptDir, storage.Path)

	require.Len(t, certCfg.Issuers, 2)
	httpIssuer, ok := certCfg.Issuers[0].(*certmagic.ACMEIssuer)
	require.True(t, ok)
	tlsALPNIssuer, ok := certCfg.Issuers[1].(*certmagic.ACMEIssuer)
	require.True(t, ok)

	require.False(t, httpIssuer.DisableHTTPChallenge)
	require.True(t, httpIssuer.DisableTLSALPNChallenge)
	require.True(t, tlsALPNIssuer.DisableHTTPChallenge)
	require.False(t, tlsALPNIssuer.DisableTLSALPNChallenge)
	require.Zero(t, tlsALPNIssuer.AltTLSALPNPort)

	for _, issuer := range []*certmagic.ACMEIssuer{
		httpIssuer, tlsALPNIssuer,
	} {
		require.Equal(t, "127.0.0.1", issuer.ListenHost)
		require.Equal(t, 8080, issuer.AltHTTPPort)
		require.True(t, issuer.Agreed)
		require.Equal(t, rpcCfg.LetsEncryptEmail, issuer.Email)
	}

	for _, listen := range []string{"", "127.0.0.1", "127.0.0.1:http2"} {
		rpcCfg.LetsEncryptListen = listen
		_, err := letsEncryptConfig(rpcCfg)
		require.Error(t, err, listen)
	}
}
