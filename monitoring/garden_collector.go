package monitoring

import (
	"errors"
	"sync"

	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/prometheus/client_golang/prometheus"
)

// assetBalancesCollector is a Prometheus collector that exports the balances
// of all taproot assets.
type gardenCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	pendingBatches   *prometheus.GaugeVec
	completedBatches prometheus.Gauge
}

func newGardenCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) (*gardenCollector, error) {

	if cfg == nil {
		return nil, errors.New("garden collector prometheus cfg is nil")
	}

	if cfg.AssetStore == nil {
		return nil, errors.New("garden collector asset store is nil")
	}

	return &gardenCollector{
		cfg:      cfg,
		registry: registry,
		pendingBatches: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mint_batches",
				Help: "Batched mint transactions",
			},
			[]string{"batch_pubkey"},
		),
		completedBatches: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "completed_batches",
				Help: "Total number of completed mint batches",
			},
		),
	}, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once the
// last descriptor has been sent.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *gardenCollector) Describe(ch chan<- *prometheus.Desc) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	a.pendingBatches.Describe(ch)
	a.completedBatches.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *gardenCollector) Collect(ch chan<- prometheus.Metric) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	a.completedBatches.Set(0)

	// Get the number of pending batches.
	batches, err := a.cfg.AssetMinter.ListBatches(nil)
	if err != nil {
		log.Errorf("unable to list batches: %v", err)
		return
	}

	completed := 0

	for _, batch := range batches {
		state := batch.State()

		switch {
		case state == tapgarden.BatchStatePending ||
			state == tapgarden.BatchStateFrozen ||
			state == tapgarden.BatchStateCommitted ||
			state == tapgarden.BatchStateBroadcast ||
			state == tapgarden.BatchStateConfirmed:

			if state == tapgarden.BatchStatePending {
				a.pendingBatches.WithLabelValues(
					batch.BatchKey.PubKey.X().String(),
				).Set(
					float64(len(batch.Seedlings)),
				)
			}

		case state == tapgarden.BatchStateFinalized ||
			state == tapgarden.BatchStateSeedlingCancelled ||
			state == tapgarden.BatchStateSproutCancelled:

			a.pendingBatches.DeleteLabelValues(
				batch.BatchKey.PubKey.X().String(),
			)

			if state == tapgarden.BatchStateFinalized {
				completed += 1
			}
		}
	}

	a.completedBatches.Set(float64(completed))

	a.pendingBatches.Collect(ch)
	a.completedBatches.Collect(ch)
}
