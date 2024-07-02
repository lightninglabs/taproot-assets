//go:build loadtest

package loadtest

import (
	"context"
	"runtime"
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

	memAlloc = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "memory_alloc",
			Help: "Memory usage of the test execution, in bytes",
		},
		[]string{"test_name"},
	)

	memTotalAlloc = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "memory_total_alloc",
			Help: "Total memory allocated by the test execution, " +
				"in bytes",
		},
		[]string{"test_name"},
	)
)

func init() {
	// Register the metric with Prometheus's default registry.
	prometheus.MustRegister(testDuration)
	prometheus.MustRegister(memAlloc)
	prometheus.MustRegister(memTotalAlloc)
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
		name: "send",
		fn:   sendTest,
	},
	{
		name: "multisig",
		fn:   multisigTest,
	},
}

type memResults struct {
	Alloc      uint64
	TotalAlloc uint64
}

// monitorMemory is a goroutine which monitors the memory usage of the test
// execution. It will send the results to the results channel when the quit
// signal is received.
func monitorMemory(interval time.Duration, testName string,
	quit chan bool, results chan memResults) {

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	topAlloc := uint64(0)
	topTotalAlloc := uint64(0)

	for {
		select {
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			if m.Alloc > topAlloc {
				topAlloc = m.Alloc
			}

			if m.TotalAlloc > topTotalAlloc {
				topTotalAlloc = m.TotalAlloc
			}

		case <-quit:
			results <- memResults{
				Alloc:      topAlloc,
				TotalAlloc: topTotalAlloc,
			}

			return
		}
	}
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

		// Create a channel to receive the memory usage results.
		memResultsChan := make(chan memResults)

		// Create a channel to signal the memory monitor to quit.
		memQuitChan := make(chan bool)

		if cfg.PrometheusGateway.Enabled {
			// Start the memory monitor.
			go monitorMemory(
				1*time.Second, tc.name, memQuitChan,
				memResultsChan,
			)
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

		// Calculate the test duration and push metrics if the test case succeeded.
		if cfg.PrometheusGateway.Enabled {
			duration := time.Since(startTime).Seconds()

			// Update the metric with the test duration.
			testDuration.WithLabelValues(tc.name).Set(duration)

			// Send the quit signal to the memory monitor.
			memQuitChan <- true

			// Receive the memory usage results.
			memResults := <-memResultsChan

			// Update the metrics with the memory usage results.
			memAlloc.WithLabelValues(tc.name).Set(float64(memResults.Alloc))

			memTotalAlloc.WithLabelValues(tc.name).Set(
				float64(memResults.TotalAlloc),
			)

			// Create a new pusher to push the metrics.
			pusher := push.New(cfg.PrometheusGateway.PushURL, "load_test").
				Collector(testDuration).
				Grouping("test_case", tc.name)

			// Push the metrics to Prometheus PushGateway.
			if err := pusher.Push(); err != nil {
				t.Logf("Could not push metrics to Prometheus PushGateway: %v",
					err)
			} else {
				t.Logf("Metrics pushed for test case '%s': duration = %v seconds",
					tc.name, duration)
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

	for _, c := range configuredCases {
		if c == name {
			return true
		}
	}

	return false
}
