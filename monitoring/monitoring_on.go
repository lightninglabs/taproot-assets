//go:build monitoring

package monitoring

import (
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"google.golang.org/grpc"
)

// NewPrometheusExporter makes a new instance of the PrometheusExporter given
// the config.
func NewPrometheusExporter(cfg *PrometheusConfig) (*PrometheusExporter, error) {
	return &PrometheusExporter{
		config: cfg,
	}, nil
}

// GetPromInterceptors returns the set of interceptors for Prometheus
// monitoring.
func GetPromInterceptors(cfg *PrometheusConfig) ([]grpc.UnaryServerInterceptor,
	[]grpc.StreamServerInterceptor) {

	if cfg == nil || !cfg.Active {
		return nil, nil
	}

	opts := []grpc_prometheus.ServerMetricsOption{
		grpc_prometheus.WithServerCounterOptions(),
	}

	if cfg.PerfHistograms {
		// Set the histogram buckets in seconds.
		histogramBuckets := []float64{
			0.01, 0.1, 0.5, 1, 5, 10, 60, 120, 240, 600, 1200,
		}
		opt := grpc_prometheus.WithServerHandlingTimeHistogram(
			grpc_prometheus.WithHistogramBuckets(histogramBuckets),
		)

		opts = append(opts, opt)
	}

	// Set the global variable to the Prometheus server metrics.
	serverMetrics = grpc_prometheus.NewServerMetrics(opts...)

	unaryInterceptors := []grpc.UnaryServerInterceptor{
		serverMetrics.UnaryServerInterceptor(),
	}
	streamInterceptors := []grpc.StreamServerInterceptor{
		serverMetrics.StreamServerInterceptor(),
	}

	return unaryInterceptors, streamInterceptors
}
