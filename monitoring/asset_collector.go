package monitoring

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	assetCollectorName = "asset"

	numAssetsMintedMetric = "num_assets_minted"
)

type assetCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	numAssetsMinted prometheus.Gauge
}

func newAssetCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) *assetCollector {

	return &assetCollector{
		cfg:      cfg,
		registry: registry,
		numAssetsMinted: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: numAssetsMintedMetric,
				Help: "Total number of assets minted",
			}),
	}
}

func (a *assetCollector) Name() string {
	return assetCollectorName
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once the
// last descriptor has been sent.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *assetCollector) Describe(ch chan<- *prometheus.Desc) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	a.numAssetsMinted.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *assetCollector) Collect(ch chan<- prometheus.Metric) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	if a.cfg == nil {
		log.Error("cfg is nil")
		return
	}

	if a.cfg.UniverseStats == nil {
		log.Error("UniverseStats is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	universeStats, err := a.cfg.UniverseStats.AggregateSyncStats(ctx)
	if err != nil {
		log.Errorf("unable to get aggregate universe stats: %v", err)
		return
	}

	numAssets := universeStats.NumTotalAssets
	a.numAssetsMinted.Set(float64(numAssets))

	a.numAssetsMinted.Collect(ch)
}

func (a *assetCollector) RegisterMetricFuncs() error {
	err := a.registry.Register(a)
	if err != nil {
		log.Errorf("Error registering asset collector: %v", err)
		return err
	}

	return nil
}

var _ MetricGroup = (*assetCollector)(nil)

func init() {
	metricsMtx.Lock()
	defer metricsMtx.Unlock()
	metricGroups[assetCollectorName] = func(cfg *PrometheusConfig,
		registry *prometheus.Registry) (MetricGroup, error) {

		// Create the assetCollector with the provided registry.
		return newAssetCollector(cfg, registry), nil
	}
}
