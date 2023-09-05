//go:build loadtest

package loadtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPerformance executes the configured performance tests.
func TestPerformance(t *testing.T) {
	cfg, err := LoadConfig()
	require.NoError(t, err, "unable to load main config")

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, cfg.TestSuiteTimeout)
	defer cancel()

	for _, testCase := range cfg.TestCases {
		execTestCase(t, ctxt, testCase, cfg)
	}
}

// execTestCase is the method in charge of executing a single test case.
func execTestCase(t *testing.T, ctx context.Context, testName string,
	cfg *Config) {

	ctxt, cancel := context.WithTimeout(ctx, cfg.TestTimeout)
	defer cancel()

	switch testName {
	case "mint_batch_stress":
		execMintBatchStressTest(t, ctxt, cfg)

	default:
		require.Fail(t, "unknown test case: %v", testName)
	}
}
