package monitoring

import (
	"net/http"
	"sync"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// metricGroups is a global variable of all registered metrics
	// projected by the mutex below. All new MetricGroups should add
	// themselves to this map within the init() method of their file.
	metricGroups = make(map[string]metricGroupFactory)

	// activeGroups is a global map of all active metric groups. This can
	// be used by some of the "static' package level methods to look up the
	// target metric group to export observations.
	activeGroups = make(map[string]MetricGroup)

	// metricsMtx is a global mutex that should be held when accessing the
	// global maps.
	metricsMtx sync.Mutex
)

// PrometheusExporter is a metric exporter that uses Prometheus directly. The
// internal server will interact with this struct in order to export relevant
// metrics.
type PrometheusExporter struct {
	config *PrometheusConfig
}

// Start registers all relevant metrics with the Prometheus library, then
// launches the HTTP server that Prometheus will hit to scrape our metrics.
func (p *PrometheusExporter) Start() error {
	// If we're not active, then there's nothing more to do.
	if !p.config.Active {
		return nil
	}

	// Before we register the rpc servers, we'll ensure that the collector
	// will export latency metrics for the histogram.
	grpc_prometheus.EnableHandlingTimeHistogram()
	grpc_prometheus.Register(p.config.RPCServer)

	// Next, we'll attempt to register all our metrics. If we fail to
	// register ANY metric, then we'll fail all together.
	if err := p.registerMetrics(); err != nil {
		return err
	}

	// Finally, we'll launch the HTTP server that Prometheus will use to
	// scape our metrics.
	go func() {
		http.Handle("/metrics", promhttp.Handler())

		// TODO(positiveblue): add server timeouts?
		err := http.ListenAndServe(p.config.ListenAddr, nil) // nolint:gosec,lll
		if err != nil {
			log.Errorf("prometheus server exited with err: %v", err)
		}
	}()

	return nil
}

// registerMetrics iterates through all the registered metric groups and
// attempts to register each one. If any of the MetricGroups fail to register,
// then an error will be returned.
func (p *PrometheusExporter) registerMetrics() error {
	metricsMtx.Lock()
	defer metricsMtx.Unlock()

	for _, metricGroupFunc := range metricGroups {
		metricGroup, err := metricGroupFunc(p.config)
		if err != nil {
			return err
		}

		if err := metricGroup.RegisterMetricFuncs(); err != nil {
			return err
		}

		activeGroups[metricGroup.Name()] = metricGroup
	}

	return nil
}

// gauges is a map type that maps a gauge to its unique name.
type gauges map[string]*prometheus.GaugeVec // nolint:unused

// addGauge adds a new gauge vector to the map.
func (g gauges) addGauge(name, help string, labels []string) { // nolint:unused
	g[name] = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

// describe describes all gauges contained in the map to the given channel.
func (g gauges) describe(ch chan<- *prometheus.Desc) { // nolint:unused
	for _, gauge := range g {
		gauge.Describe(ch)
	}
}

// collect collects all metrics of the map's gauges to the given channel.
func (g gauges) collect(ch chan<- prometheus.Metric) { // nolint:unused
	for _, gauge := range g {
		gauge.Collect(ch)
	}
}

// reset resets all gauges in the map.
func (g gauges) reset() { // nolint:unused
	for _, gauge := range g {
		gauge.Reset()
	}
}
