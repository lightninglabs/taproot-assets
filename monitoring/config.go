package monitoring

import "google.golang.org/grpc"

// PrometheusConfig is the set of configuration data that specifies if
// Prometheus metric exporting is activated, and if so the listening address of
// the Prometheus server.
type PrometheusConfig struct {
	// Active, if true, then Prometheus metrics will be expired.
	Active bool `long:"active" description:"if true prometheus metrics will be exported"`

	// ListenAddr is the listening address that we should use to allow the
	// main Prometheus server to scrape our metrics.
	ListenAddr string `long:"listenaddr" description:"the interface we should listen on for prometheus"`

	// RPCServer is a pointer to the main RPC server. We use this to export
	// generic RPC metrics to monitor the health of the service.
	RPCServer *grpc.Server
}

// DefaultPrometheusConfig is the default configuration for the Prometheus
// metrics exporter.
func DefaultPrometheusConfig() PrometheusConfig {
	return PrometheusConfig{
		ListenAddr: "127.0.0.1:8989",
		Active:     false,
	}
}
