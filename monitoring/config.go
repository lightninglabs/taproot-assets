package monitoring

import (
	"time"

	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"google.golang.org/grpc"
)

// PrometheusConfig is the set of configuration data that specifies if
// Prometheus metric exporting is activated, and if so the listening address of
// the Prometheus server.
//
// nolint: lll
type PrometheusConfig struct {
	// Active, if true, then Prometheus metrics will be exported.
	Active bool `long:"active" description:"if true prometheus metrics will be exported"`

	// ListenAddr is the listening address that we should use to allow the
	// main Prometheus server to scrape our metrics.
	ListenAddr string `long:"listenaddr" description:"the interface we should listen on for prometheus"`

	// CollectorRPCTimeout is the context timeout to be used by the RPC
	// calls performed during metrics collection. This should not be greater
	// than the scrape interval of prometheus.
	CollectorRPCTimeout time.Duration `long:"collector-rpc-timeout" description:"the default timeout to be used in the RPC calls performed during metric collection"`

	// RPCServer is a pointer to the main RPC server. We use this to export
	// generic RPC metrics to monitor the health of the service.
	RPCServer *grpc.Server

	// UniverseStats is used to collect any stats that are relevant to the
	// universe.
	UniverseStats universe.Telemetry

	// AssetStore is used to collect any stats that are relevant to the
	// asset store.
	AssetStore *tapdb.AssetStore

	// AssetMinter is used to collect any stats that are relevant to the
	// asset minter.
	AssetMinter tapgarden.Planter

	// PerfHistograms indicates if the additional histogram information for
	// latency, and handling time of gRPC calls should be enabled. This
	// generates additional data, and consume more memory for the
	// Prometheus server.
	PerfHistograms bool `long:"perfhistograms" description:"enable additional histogram to track gRPC call processing performance (latency, etc)"`
}

// DefaultPrometheusConfig is the default configuration for the Prometheus
// metrics exporter.
func DefaultPrometheusConfig() PrometheusConfig {
	return PrometheusConfig{
		ListenAddr:          "127.0.0.1:8989",
		Active:              false,
		CollectorRPCTimeout: defaultTimeout,
	}
}
