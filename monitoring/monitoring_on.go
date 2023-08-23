//go:build monitoring

package monitoring

import (
	//nolint:lll
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
		opt := grpc_prometheus.WithServerHandlingTimeHistogram()
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
