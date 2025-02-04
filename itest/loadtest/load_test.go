//go:build loadtest

package loadtest

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/stretchr/testify/require"
)

var (
	testDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "test_duration_seconds",
			Help: "Duration of the test execution, in seconds",
		},
		[]string{"test_name"},
	)
)

func init() {
	// Register the metric with Prometheus's default registry.
	prometheus.MustRegister(testDuration)
}

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
		name: "mintV2",
		fn:   mintTestV2,
	},
	{
		name: "send",
		fn:   sendTest,
	},
	{
		name: "sendV2",
		fn:   sendTestV2,
	},
	{
		name: "multisig",
		fn:   multisigTest,
	},
	{
		name: "sync",
		fn:   syncTest,
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

		// Record the start time of the test case.
		startTime := time.Now()

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

		// Calculate the test duration and push metrics if the test case
		// succeeded.
		if cfg.PrometheusGateway.Enabled {
			duration := time.Since(startTime).Seconds()

			timeTag := fmt.Sprintf("%d", time.Now().Unix())

			label := tc.name + timeTag

			// Update the metric with the test duration.
			testDuration.WithLabelValues(label).Set(duration)

			t.Logf("Pushing testDuration %v with label %v to "+
				"gateway", duration, label)

			// Create a new pusher to push the metrics.
			pusher := push.New(
				cfg.PrometheusGateway.PushURL, "load_test",
			).Collector(testDuration)

			// Push the metrics to Prometheus PushGateway.
			if err := pusher.Add(); err != nil {
				t.Logf("Could not push metrics to Prometheus "+
					"PushGateway: %v", err)
			} else {
				t.Logf("Metrics pushed for test case '%s': "+
					"duration = %v seconds", tc.name,
					duration)
			}
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

	return slices.Contains(configuredCases, name)
}
