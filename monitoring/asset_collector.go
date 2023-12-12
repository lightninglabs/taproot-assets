package monitoring

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	numAssetsMintedMetric = "num_assets_minted"

	numTotalGroupsMetric = "num_total_groups"

	numTotalSyncsMetric = "num_total_syncs"

	numTotalProofsMetric = "num_total_proofs"
)

// universeStatsCollector is a Prometheus collector that exports the stats of
// the universe.
type universeStatsCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	gauges map[string]prometheus.Gauge
}

func newUniverseStatsCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) (*universeStatsCollector, error) {

	if cfg == nil {
		return nil, errors.New("universe stats collector prometheus " +
			"cfg is nil")
	}

	if cfg.UniverseStats == nil {
		return nil, errors.New("universe stats collector universe " +
			"stats is nil")
	}

	gaugesMap := map[string]prometheus.Gauge{
		numAssetsMintedMetric: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: numAssetsMintedMetric,
				Help: "Total number of assets minted",
			},
		),
		numTotalGroupsMetric: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: numTotalGroupsMetric,
				Help: "Total number of groups",
			},
		),
		numTotalSyncsMetric: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: numTotalSyncsMetric,
				Help: "Total number of syncs",
			},
		),
		numTotalProofsMetric: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: numTotalProofsMetric,
				Help: "Total number of proofs",
			},
		),
	}

	return &universeStatsCollector{
		cfg:      cfg,
		registry: registry,
		gauges:   gaugesMap,
	}, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once the
// last descriptor has been sent.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *universeStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	for _, gauge := range a.gauges {
		gauge.Describe(ch)
	}
}

// Collect is called by the Prometheus registry when collecting metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *universeStatsCollector) Collect(ch chan<- prometheus.Metric) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	universeStats, err := a.cfg.UniverseStats.AggregateSyncStats(ctx)
	if err != nil {
		log.Errorf("unable to get aggregate universe stats: %v", err)
		return
	}

	a.gauges[numAssetsMintedMetric].Set(
		float64(universeStats.NumTotalAssets),
	)

	a.gauges[numTotalGroupsMetric].Set(
		float64(universeStats.NumTotalGroups),
	)

	a.gauges[numTotalSyncsMetric].Set(
		float64(universeStats.NumTotalSyncs),
	)

	a.gauges[numTotalProofsMetric].Set(
		float64(universeStats.NumTotalProofs),
	)

	for _, gauge := range a.gauges {
		gauge.Collect(ch)
	}
}
