package monitoring

import "github.com/prometheus/client_golang/prometheus"

// metricGroupFactory is a factory method that given the primary prometheus
// config, will create a new MetricGroup that will be managed by the main
// PrometheusExporter.
type metricGroupFactory func(*PrometheusConfig, *prometheus.Registry) (MetricGroup, error)

// MetricGroup is the primary interface of this package. The main exporter (in
// this case the PrometheusExporter), will manage these directly, ensuring that
// all MetricGroups are registered before the main prometheus exporter starts
// and any additional tracing is added.
type MetricGroup interface {
	// Collector is the embedded interface that forces every MetricGroup to
	// also be a collector.
	prometheus.Collector

	// Name is the name of the metric group. When exported to prometheus,
	// it's expected that all metric under this group have the same prefix.
	Name() string

	// RegisterMetricFuncs signals to the underlying hybrid collector that
	// it should register all metrics that it aims to export with the
	// global Prometheus registry. Rather than using the series of
	// "MustRegister" directives, implementers of this interface should
	// instead propagate back any errors related to metric registration.
	RegisterMetricFuncs() error
}
