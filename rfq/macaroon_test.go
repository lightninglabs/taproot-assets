package rfq

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

// testCaseNewMacaroonDialOption is a test case for
// NewMacaroonDialOption.
type testCaseNewMacaroonDialOption struct {
	name        string
	setup       func(t *testing.T) string
	expectError bool
}

// runNewMacaroonDialOptionTest runs a single test case.
func runNewMacaroonDialOptionTest(t *testing.T,
	tc *testCaseNewMacaroonDialOption) {

	t.Run(tc.name, func(t *testing.T) {
		path := tc.setup(t)
		opt, err := NewMacaroonDialOption(path)

		if tc.expectError {
			require.Error(t, err)
			require.Nil(t, opt)
			return
		}

		require.NoError(t, err)
		require.NotNil(t, opt)
	})
}

// TestNewMacaroonDialOption tests the NewMacaroonDialOption function.
func TestNewMacaroonDialOption(t *testing.T) {
	testCases := []*testCaseNewMacaroonDialOption{
		{
			name: "valid macaroon",
			setup: func(t *testing.T) string {
				mac, err := macaroon.New(
					[]byte("root-key"),
					[]byte("id"),
					"loc",
					macaroon.LatestVersion,
				)
				require.NoError(t, err)

				macBytes, err := mac.MarshalBinary()
				require.NoError(t, err)

				p := filepath.Join(
					t.TempDir(), "test.macaroon",
				)
				err = os.WriteFile(
					p, macBytes, 0600,
				)
				require.NoError(t, err)

				return p
			},
			expectError: false,
		},
		{
			name: "nonexistent path",
			setup: func(t *testing.T) string {
				return filepath.Join(
					t.TempDir(), "missing.macaroon",
				)
			},
			expectError: true,
		},
		{
			name: "invalid file contents",
			setup: func(t *testing.T) string {
				p := filepath.Join(
					t.TempDir(), "bad.macaroon",
				)
				err := os.WriteFile(
					p, []byte("not a macaroon"),
					0600,
				)
				require.NoError(t, err)

				return p
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		runNewMacaroonDialOptionTest(t, tc)
	}
}
