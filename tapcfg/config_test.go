package tapcfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
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
