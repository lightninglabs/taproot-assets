package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"

	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/taro"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/signal"
)

func main() {
	// Hook interceptor for os signals.
	shutdownInterceptor, err := signal.Intercept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Load the configuration, and parse any command line options. This
	// function will also set up logging properly.
	cfg, cfgLogger, err := LoadConfig(shutdownInterceptor)
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	// Given the config above, grab the TLS config which includes the set
	// of dial options, and also the listeners we'll use to listen on the
	// RPC system.
	serverOpts, restDialOpts, restListen, err := getTLSConfig(
		cfg, cfgLogger,
	)
	if err != nil {
		err := fmt.Errorf("unable to load TLS credentials: %v", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			//taroLog.Infof("Pprof listening on %v", cfg.Profile)
			fmt.Println(http.ListenAndServe(cfg.Profile, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	server, err := taro.NewServer(&taro.Config{
		DebugLevel:        cfg.DebugLevel,
		ChainParams:       cfg.ActiveNetParams,
		SignalInterceptor: shutdownInterceptor,
		LogWriter:         cfg.LogWriter,
		RPCConfig: &taro.RPCConfig{
			LisCfg:         &lnd.ListenerCfg{},
			RPCListeners:   cfg.rpcListeners,
			RESTListeners:  cfg.restListeners,
			GrpcServerOpts: serverOpts,
			RestDialOpts:   restDialOpts,
			RestListenFunc: restListen,
			WSPingInterval: cfg.RpcConf.WSPingInterval,
			WSPongWait:     cfg.RpcConf.WSPongWait,
			RestCORS:       cfg.RpcConf.RestCORS,
			NoMacaroons:    cfg.RpcConf.NoMacaroons,
		},
	})
	if err != nil {
		err := fmt.Errorf("unable to start server: %v", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = server.RunUntilShutdown()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
