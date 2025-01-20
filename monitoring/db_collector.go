package monitoring

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	dbSizeMetric = "total_db_size"

	assetProofSizesHistogram = "asset_proofs_sizes"
)

// dbCollector is a Prometheus collector that exports metrics related to the
// daemon's database.
type dbCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	dbSize              prometheus.Gauge
	proofSizesHistogram prometheus.Histogram
}

func newDbCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) (*dbCollector, error) {

	if cfg == nil {
		return nil, errors.New("db collector prometheus cfg is nil")
	}

	if cfg.AssetStore == nil {
		return nil, errors.New("db collector asset store is nil")
	}

	return &dbCollector{
		cfg:      cfg,
		registry: registry,
		dbSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: dbSizeMetric,
				Help: "Total size of db",
			},
		),
		proofSizesHistogram: newProofSizesHistogram(),
	}, nil
}

// newProofSizesHistogram generates a fresh instance of the proof sizes
// histogram.
func newProofSizesHistogram() (h prometheus.Histogram) {
	return prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: assetProofSizesHistogram,
			Help: "Histogram of asset proof sizes",
			Buckets: prometheus.ExponentialBuckets(
				2, 2, 32,
			),
		},
	)
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once the
// last descriptor has been sent.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *dbCollector) Describe(ch chan<- *prometheus.Desc) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	a.dbSize.Describe(ch)
	a.proofSizesHistogram.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *dbCollector) Collect(ch chan<- prometheus.Metric) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	ctxdb, cancel := context.WithTimeout(context.Background(), promTimeout)
	defer cancel()

	// Fetch the db size.
	dbSize, err := a.cfg.AssetStore.AssetsDBSize(ctxdb)
	if err != nil {
		log.Errorf("unable to fetch db size: %v", err)
		return
	}

	a.dbSize.Set(float64(dbSize))

	// Fetch all proof sizes.
	proofSizes, err := a.cfg.AssetStore.FetchAssetProofsSizes(ctxdb)
	if err != nil {
		log.Errorf("unable to fetch asset proofs: %v", err)
		return
	}

	// We use the histogram in a non-standard way. Everytime we collect data
	// we ask the database to return all proof sizes and then we feed them
	// to the histogram. That's why on every different pass we need to reset
	// the histogram instance, in order to not duplicate data on every
	// prometheus pass.
	a.proofSizesHistogram = newProofSizesHistogram()

	// We'll feed the proof sizes to the histogram.
	for _, p := range proofSizes {
		a.proofSizesHistogram.Observe(p.ProofFileLength)
	}

	a.proofSizesHistogram.Collect(ch)
	a.dbSize.Collect(ch)
}
