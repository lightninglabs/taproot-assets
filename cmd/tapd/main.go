package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightningnetwork/lnd/signal"
)

// repairFlagOnCommandLine reports whether the one-shot repair flag
// was passed on the command line itself, as opposed to being read
// from a config file.
func repairFlagOnCommandLine() bool {
	const flag = "--repair.cancel-duplicate-batches"
	for _, arg := range os.Args[1:] {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}

	return false
}

func main() {
	// Hook interceptor for os signals.
	shutdownInterceptor, err := signal.Intercept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Load the configuration, and parse any command line options. This
	// function will also set up logging properly.
	cfg, cfgLogger, err := tapcfg.LoadConfig(shutdownInterceptor)
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

	// If the operator has invoked tapd in one-shot repair mode, run
	// the requested repair against the database and exit before
	// constructing the full server. The repair tool opens the DB
	// with migrations skipped, so it can recover a legacy DB whose
	// state would otherwise block a migration from applying.
	//
	// The flag is only honored when given on the command line
	// itself. Repair mode exits after running, so a value left
	// behind in tapd.conf would otherwise turn every subsequent
	// start into a no-op exit with a success code, silently taking
	// a supervised node out of service.
	if cfg.Repair != nil && cfg.Repair.CancelDuplicateBatches {
		if repairFlagOnCommandLine() {
			err := tapcfg.RunRepairTool(
				cfg, cfgLogger, shutdownInterceptor,
			)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		cfgLogger.Warnf("Ignoring repair.cancel-duplicate-batches " +
			"from the config file: repair mode exits after " +
			"running and must be requested on the command line")
	}

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			cfgLogger.Infof("Pprof listening on %v", cfg.Profile)
			//nolint:gosec
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

	// This concurrent error queue can be used by every component that can
	// raise runtime errors. Using a queue will prevent us from blocking on
	// sending errors to it, as long as the queue is running.
	errQueue := fn.NewConcurrentQueue[error](fn.DefaultQueueSize)
	errQueue.Start()
	defer errQueue.Stop()

	server, err := tapcfg.CreateServerFromConfig(
		cfg, cfgLogger, shutdownInterceptor, false, errQueue.ChanIn(),
	)
	if err != nil {
		err := fmt.Errorf("error creating server: %w", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = server.RunUntilShutdown(errQueue.ChanOut())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
