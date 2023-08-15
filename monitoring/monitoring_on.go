//go:build monitoring
// +build monitoring

package monitoring

// NewPrometheusExporter makes a new instance of the PrometheusExporter given
// the config.
func NewPrometheusExporter(cfg *PrometheusConfig) (*PrometheusExporter, error) {
	return &PrometheusExporter{
		config: cfg,
	}, nil
}
