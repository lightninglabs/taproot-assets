//go:build !monitoring

package monitoring

import (
	"fmt"

	"google.golang.org/grpc"
)

// NewPrometheusExporter makes a new instance of the PrometheusExporter given
// the config.
func NewPrometheusExporter(cfg *PrometheusConfig) (*PrometheusExporter, error) {
	return nil, fmt.Errorf("tapd must be built with the monitoring tag " +
		"to enable exporting Prometheus metrics")
}

// GetPromInterceptors returns the set of interceptors for Prometheus
// monitoring if monitoring is enabled, else empty slices. Monitoring is
// currently disabled.
func GetPromInterceptors(_ *PrometheusConfig) ([]grpc.UnaryServerInterceptor,
	[]grpc.StreamServerInterceptor) {

	return nil, nil
}
