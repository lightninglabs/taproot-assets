//go:build !monitoring
// +build !monitoring

package monitoring

import "fmt"

// NewPrometheusExporter makes a new instance of the PrometheusExporter given
// the config.
func NewPrometheusExporter(cfg *PrometheusConfig) (*PrometheusExporter, error) {
	return nil, fmt.Errorf("tapd must be built with the monitoring tag " +
		"to enable exporting Prometheus metrics")
}
