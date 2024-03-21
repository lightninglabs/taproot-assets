//go:build loadtest

package loadtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type testCase struct {
	name string
	fn   func(t *testing.T, ctx context.Context, cfg *Config)
}

var loadTestCases = []testCase{
	{
		name: "mint",
		fn:   mintTest,
	},
	{
		name: "send",
		fn:   sendTest,
	},
	{
		name: "multisig",
		fn:   multisigTest,
	},
}

// TestPerformance executes the configured performance tests.
func TestPerformance(t *testing.T) {
	cfg, err := LoadConfig()
	require.NoError(t, err, "unable to load main config")

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, cfg.TestSuiteTimeout)
	defer cancel()

	for _, tc := range loadTestCases {
		tc := tc

		if !shouldRunCase(tc.name, cfg.TestCases) {
			t.Logf("Not running test case '%s' as not configured",
				tc.name)

			continue
		}

		success := t.Run(tc.name, func(tt *testing.T) {
			ctxt, cancel := context.WithTimeout(
				ctxt, cfg.TestTimeout,
			)
			defer cancel()

			tc.fn(t, ctxt, cfg)
		})
		if !success {
			t.Fatalf("test case %v failed", tc.name)
		}
	}
}

// shouldRunCase returns true if the given test case should be run. This will
// return true if the config file does not specify any test cases. In that case
// we can select the test cases to run using the command line
// (-test.run="TestPerformance/test_case_name")
func shouldRunCase(name string, configuredCases []string) bool {
	if len(configuredCases) == 0 {
		return true
	}

	for _, c := range configuredCases {
		if c == name {
			return true
		}
	}

	return false
}
