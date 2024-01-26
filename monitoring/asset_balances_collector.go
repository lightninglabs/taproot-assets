package monitoring

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// assetBalancesCollector is a Prometheus collector that exports the balances
// of all taproot assets.
type assetBalancesCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	balancesVec *prometheus.GaugeVec

	utxosVec *prometheus.GaugeVec
}

func newAssetBalancesCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) (*assetBalancesCollector, error) {

	if cfg == nil {
		return nil, errors.New("asset collector prometheus cfg is nil")
	}

	if cfg.AssetStore == nil {
		return nil, errors.New("asset collector asset store is nil")
	}

	return &assetBalancesCollector{
		cfg:      cfg,
		registry: registry,
		balancesVec: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "asset_balances",
				Help: "Balances of all taproot assets",
			},
			[]string{"asset_name"},
		),
		utxosVec: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "utxos_assets_held",
				Help: "Number of UTXOs used for taproot assets",
			},
			[]string{"outpoint"},
		),
	}, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once the
// last descriptor has been sent.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *assetBalancesCollector) Describe(ch chan<- *prometheus.Desc) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	a.balancesVec.Describe(ch)
	a.utxosVec.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (a *assetBalancesCollector) Collect(ch chan<- prometheus.Metric) {
	a.collectMx.Lock()
	defer a.collectMx.Unlock()

	ctxdb, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	assets, err := a.cfg.AssetStore.FetchAllAssets(ctxdb, false, false, nil)
	if err != nil {
		log.Errorf("unable to fetch assets: %v", err)
		return
	}

	utxos, err := a.cfg.AssetStore.FetchManagedUTXOs(ctxdb)
	if err != nil {
		log.Errorf("unable to fetch utxos: %v", err)
		return
	}

	a.utxosVec.Reset()
	a.balancesVec.Reset()

	utxoMap := make(map[string]prometheus.Gauge)

	for _, utxo := range utxos {
		utxoOutpoint := utxo.OutPoint.String()
		utxoMap[utxoOutpoint] = a.utxosVec.WithLabelValues(utxoOutpoint)
	}

	for _, asset := range assets {
		a.balancesVec.WithLabelValues(asset.Tag).
			Set(float64(asset.Amount))

		utxoGauge, ok := utxoMap[asset.AnchorOutpoint.String()]
		if !ok {
			continue
		}

		utxoGauge.Inc()
	}

	a.balancesVec.Collect(ch)
	a.utxosVec.Collect(ch)
}
