// WARNING: This is a demonstration example only and is NOT
// suitable for production use. Using this code in production
// will almost certainly result in loss of funds.
//
// basic-portfolio-pilot is an RPC portfolio pilot for a single
// USD-pegged asset, priced from a BTC/USD reference price. It shows
// what a pilot is responsible for, since tapd trades at whatever rates
// an external pilot gives and accepts:
//
//   - pilot.go prices quotes and checks the quotes of peers.
//   - price.go keeps the reference price everything is derived from.
//   - breaker.go wraps the pilot and sets the trading level: normal,
//     degraded or halted.
//   - monitor.go watches settled swaps and balances through tapd and
//     lnd, and degrades or halts trading.
//   - server.go serves the pilot over TLS and requires a macaroon.
//   - main.go parses flags and wires the parts together. The breaker
//     wraps the pilot; the price feed and the monitor report to the
//     breaker.
//
// Each file opens with the ideas it illustrates. Start with pilot.go.
// See docs/portfolio_pilot.md for usage.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
)

// config holds the runtime configuration parsed from flags.
type config struct {
	listenAddr      string
	dataDir         string
	extraDomain     string
	assetID         []byte
	groupKey        []byte
	decimalDisplay  int
	btcUSD          string
	spreadPpm       uint64
	maxDeviationPpm uint64
	quoteLifetime   time.Duration
	fillCapAsset    uint64
	fillCapMsat     uint64
	maxExposureUSD  uint64
	maxJumpPpm      uint64
	maxBadQuotes    int
	tapd            nodeConfig
	lnd             nodeConfig
	maxLossUSD      uint64
	minAssetUSD     uint64
	minBTCSat       uint64
}

// nodeConfig is the RPC address, TLS certificate and macaroon of a tapd
// or lnd node.
type nodeConfig struct {
	addr, cert, macaroon string
}

// parseFlags parses and validates command-line flags.
func parseFlags() (config, error) {
	var (
		cfg               config
		assetID, groupKey string
	)

	flag.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8096",
		"listen address")
	flag.StringVar(&cfg.dataDir, "datadir", ".",
		"directory for the TLS certificate, key, macaroon and halt "+
			"file")
	flag.StringVar(&cfg.extraDomain, "tlsextradomain", "",
		"extra domain for a generated TLS certificate")
	flag.StringVar(&assetID, "assetid", "", "hex asset ID")
	flag.StringVar(&groupKey, "groupkey", "", "hex group key")
	flag.IntVar(&cfg.decimalDisplay, "decimaldisplay", -1,
		"decimal display of the asset (required)")
	flag.StringVar(&cfg.btcUSD, "btcusd", "",
		"static BTC/USD price; empty polls CoinGecko")
	flag.Uint64Var(&cfg.spreadPpm, "spreadppm", 5_000,
		"spread applied to our quotes, in ppm")
	flag.Uint64Var(&cfg.maxDeviationPpm, "maxdeviationppm", 50_000,
		"maximum deviation of a peer's quote, in ppm")
	flag.DurationVar(&cfg.quoteLifetime, "quotelifetime",
		5*time.Minute, "lifetime of our quotes")
	flag.Uint64Var(&cfg.fillCapAsset, "fillcap-asset-units", 0,
		"fill cap for buy requests, in asset units; 0 = none")
	flag.Uint64Var(&cfg.fillCapMsat, "fillcap-msat", 0,
		"fill cap for sell requests, in msat; 0 = none")
	flag.Uint64Var(&cfg.maxExposureUSD, "maxexposureusd", 1_000,
		"halt when unexpired quotes would exceed this many USD")
	flag.Uint64Var(&cfg.maxJumpPpm, "maxpricejumpppm", 50_000,
		"halt when the price moves more between fetches, in ppm; "+
			"0 = off")
	flag.IntVar(&cfg.maxBadQuotes, "maxbadquotes", 5,
		"halt after this many peer quotes outside tolerance within "+
			"10 minutes; 0 = off")
	for _, n := range []struct {
		name string
		cfg  *nodeConfig
	}{{"tapd", &cfg.tapd}, {"lnd", &cfg.lnd}} {
		flag.StringVar(&n.cfg.addr, n.name+"rpcserver", "",
			n.name+" RPC address; empty disables its checks")
		flag.StringVar(&n.cfg.cert, n.name+"tlscertpath", "",
			n.name+" TLS certificate")
		flag.StringVar(&n.cfg.macaroon, n.name+"macaroonpath", "",
			n.name+" read-only macaroon")
	}
	flag.Uint64Var(&cfg.maxLossUSD, "maxtradelossusd", 100,
		"halt when the trade edge over an hour is below minus this "+
			"many USD, degrade below half; 0 = off")
	flag.Uint64Var(&cfg.minAssetUSD, "minassetusd", 0,
		"degrade and block buy requests below this local asset "+
			"balance; 0 = off")
	flag.Uint64Var(&cfg.minBTCSat, "minbtcsat", 0,
		"degrade and block sell requests below this local BTC "+
			"balance; 0 = off")
	flag.Parse()

	var err error
	switch {
	case (assetID == "") == (groupKey == ""):
		return cfg, errors.New("set exactly one of -assetid and " +
			"-groupkey")

	case assetID != "":
		cfg.assetID, err = hex.DecodeString(assetID)
		if err != nil || len(cfg.assetID) != 32 {
			return cfg, errors.New("invalid -assetid")
		}

	default:
		cfg.groupKey, err = hex.DecodeString(groupKey)
		if err != nil || len(cfg.groupKey) != 33 {
			return cfg, errors.New("invalid -groupkey")
		}
	}

	switch {
	case cfg.decimalDisplay < 0 || cfg.decimalDisplay > 12:
		return cfg, errors.New("-decimaldisplay must be in [0, 12]")

	case cfg.spreadPpm >= 500_000:
		return cfg, errors.New("-spreadppm must be below 500000")

	case cfg.quoteLifetime <= 0:
		return cfg, errors.New("-quotelifetime must be positive")

	case cfg.maxExposureUSD == 0 || cfg.maxExposureUSD > 1_000_000:
		return cfg, errors.New("-maxexposureusd must be in " +
			"[1, 1000000]")

	case cfg.maxBadQuotes < 0:
		return cfg, errors.New("-maxbadquotes must not be negative")

	case cfg.maxLossUSD > 1_000_000 || cfg.minAssetUSD > 1_000_000:
		return cfg, errors.New("-maxtradelossusd and -minassetusd " +
			"must not exceed 1000000")
	}

	return cfg, nil
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Invalid flags: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	unitsPerUSD := uint64(1)
	for range cfg.decimalDisplay {
		unitsPerUSD *= 10
	}

	b := &breaker{
		haltPath:     filepath.Join(cfg.dataDir, haltFile),
		maxExposure:  cfg.maxExposureUSD * unitsPerUSD,
		maxBadQuotes: cfg.maxBadQuotes,
	}
	if b.halted() {
		log.Printf("Halted: remove %s to resume trading", b.haltPath)
	}

	feed := &priceFeed{maxJumpPpm: cfg.maxJumpPpm, onJump: b.trip}
	if cfg.btcUSD != "" {
		feed.btcUSD, err = parsePrice(cfg.btcUSD)
		if err != nil {
			log.Fatalf("Invalid -btcusd: %v", err)
		}
		feed.static = true
	} else {
		go feed.poll(ctx)
	}
	p := &pilot{cfg: cfg, feed: feed, degraded: b.degraded}
	b.inner = p

	m := &monitor{
		pilot:    p,
		breaker:  b,
		maxLoss:  cfg.maxLossUSD * unitsPerUSD,
		minAsset: cfg.minAssetUSD * unitsPerUSD,
		minBTC:   cfg.minBTCSat * 1_000,
		since:    time.Now(),
		edges:    make(map[string]swapEdge),
	}
	if cfg.tapd.addr != "" {
		conn, err := dialNode(cfg.tapd.addr, cfg.tapd.cert,
			cfg.tapd.macaroon)
		if err != nil {
			log.Fatalf("tapd connection failed: %v", err)
		}
		m.tapd = rfqrpc.NewRfqClient(conn)
	}
	if cfg.lnd.addr != "" {
		conn, err := dialNode(cfg.lnd.addr, cfg.lnd.cert,
			cfg.lnd.macaroon)
		if err != nil {
			log.Fatalf("lnd connection failed: %v", err)
		}
		m.lnd = lnrpc.NewLightningClient(conn)
	}
	if m.tapd == nil || m.lnd == nil {
		log.Printf("WARNING: trade edge or inventory checks " +
			"disabled; set -tapdrpcserver and -lndrpcserver")
	}
	go m.run(ctx)

	server, err := newServer(cfg, b)
	if err != nil {
		log.Fatalf("Server setup failed: %v", err)
	}

	lis, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	log.Printf("Listening on portfoliopilotrpc://%s", cfg.listenAddr)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		server.GracefulStop()
	}()

	if err := server.Serve(lis); err != nil {
		log.Fatalf("Serve failed: %v", err)
	}
}
