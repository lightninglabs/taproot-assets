package rpcutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDerivationPath(t *testing.T) {
	testCases := []struct {
		name           string
		path           string
		expectedErr    string
		expectedResult []uint32
	}{{
		name:        "empty path",
		path:        "",
		expectedErr: "path cannot be empty",
	}, {
		name:        "just whitespace",
		path:        " \n\t\r",
		expectedErr: "path cannot be empty",
	}, {
		name:        "incorrect prefix",
		path:        "0/0",
		expectedErr: "path must start with m/",
	}, {
		name:        "invalid number",
		path:        "m/a'/0'",
		expectedErr: "could not parse part \"a\"",
	}, {
		name:        "double slash",
		path:        "m/0'//",
		expectedErr: "could not parse part \"\"",
	}, {
		name:        "negative number",
		path:        "m/-1",
		expectedErr: "could not parse part \"-1\"",
	}, {
		name:        "number too large",
		path:        "m/99999999999999",
		expectedErr: "could not parse part \"99999999999999\"",
	}, {
		name:        "embedded root prefix",
		path:        "m/0'/m/1",
		expectedErr: "could not parse part \"m\"",
	}, {
		name:        "repeated hardening suffix",
		path:        "m/1hh",
		expectedErr: "invalid derivation path part \"1hh\"",
	}, {
		name:           "root path",
		path:           "m/",
		expectedResult: []uint32{},
	}, {
		name:           "mixed hardening suffixes",
		path:           "m/0'/1h/2H/3/4/5/6'/7h",
		expectedResult: []uint32{0, 1, 2, 3, 4, 5, 6, 7},
	}, {
		name:           "plain path",
		path:           "m/0/1/2",
		expectedResult: []uint32{0, 1, 2},
	}, {
		name:           "full uint32 range",
		path:           "m/2147483648/4294967295",
		expectedResult: []uint32{2147483648, 4294967295},
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			result, err := parseDerivationPath(tc.path)

			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, result)
		})
	}
}
