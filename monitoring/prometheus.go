package monitoring

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	//nolint:lll
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// serverMetrics is a global variable that holds the Prometheus metrics
	// for the gRPC server.
	serverMetrics *grpc_prometheus.ServerMetrics
)

const (
	// dbTimeout is the default database timeout.
	dbTimeout = 20 * time.Second
)

// PrometheusExporter is a metric exporter that uses Prometheus directly. The
// internal server will interact with this struct in order to export relevant
// metrics.
type PrometheusExporter struct {
	config   *PrometheusConfig
	registry *prometheus.Registry
}

// Start registers all relevant metrics with the Prometheus library, then
// launches the HTTP server that Prometheus will hit to scrape our metrics.
func (p *PrometheusExporter) Start() error {
	log.Infof("Starting Prometheus Exporter")

	// If we're not active, then there's nothing more to do.
	if !p.config.Active {
		return nil
	}

	// Make sure that the server metrics has been created.
	if serverMetrics == nil {
		return fmt.Errorf("server metrics not set")
	}

	// Create a custom Prometheus registry.
	p.registry = prometheus.NewRegistry()
	p.registry.MustRegister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{},
	))
	p.registry.MustRegister(collectors.NewGoCollector())
	p.registry.MustRegister(serverMetrics)

	uniStatsCollector, err := newUniverseStatsCollector(p.config, p.registry)
	if err != nil {
		return err
	}
	p.registry.MustRegister(uniStatsCollector)

	assetBalancesCollecor, err :=
		newAssetBalancesCollector(p.config, p.registry)
	if err != nil {
		return err
	}
	p.registry.MustRegister(assetBalancesCollecor)

	gardenCollector, err := newGardenCollector(p.config, p.registry)
	if err != nil {
		return err
	}
	p.registry.MustRegister(gardenCollector)

	// Make ensure that all metrics exist when collecting and querying.
	serverMetrics.InitializeMetrics(p.config.RPCServer)

	// Finally, we'll launch the HTTP server that Prometheus will use to
	// scrape our metrics.
	go func() {
		// Use our custom prometheus registry.
		promMux := http.NewServeMux()
		promMux.Handle("/metrics", promhttp.HandlerFor(
			p.registry, promhttp.HandlerOpts{
				EnableOpenMetrics:   true,
				MaxRequestsInFlight: 1,
			}),
		)

		log.Infof("Prometheus listening on %v", p.config.ListenAddr)

		pprofServer := &http.Server{
			Addr:              p.config.ListenAddr,
			Handler:           promMux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		// Start the prometheus server.
		err := pprofServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("Serving prometheus got err: %v", err)
		}
	}()

	return nil
}
