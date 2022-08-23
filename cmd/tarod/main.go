package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"

	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/ticker"
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
			cfgLogger.Infof("Pprof listening on %v", cfg.Profile)
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

	// Now that we know where the databse will live, we'll go ahead and
	// open up the default implementation of it.
	cfgLogger.Infof("Opening sqlite3 database at: %v", cfg.DatabaseFileName)
	db, err := tarodb.NewSqliteStore(&tarodb.SqliteConfig{
		DatabaseFileName: cfg.DatabaseFileName,
		CreateTables:     true,
	})
	if err != nil {
		err := fmt.Sprintf("unable to open database: %v", err)
		cfgLogger.Errorf(err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	rksDB := tarodb.NewTransactionExecutor[tarodb.KeyStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.KeyStore {

		// TODO(roasbeef): can get rid of this by emulating the
		// sqlite.DBTX interface
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	mintingStore := tarodb.NewTransactionExecutor[tarodb.PendingAssetStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.PendingAssetStore {

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	assetMintingStore := tarodb.NewAssetMintingStore(mintingStore)

	assetDB := tarodb.NewTransactionExecutor[tarodb.ActiveAssetsStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.ActiveAssetsStore {

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})

	addrBookDB := tarodb.NewTransactionExecutor[tarodb.AddrBook,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.AddrBook {

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	tarodbAddrBook := tarodb.NewTaroAddressBook(addrBookDB)

	lndConn, err := getLnd(
		cfg.ChainConf.Network, cfg.Lnd, shutdownInterceptor,
	)
	if err != nil {
		err := fmt.Sprintf("unable to connect to lnd node: %v", err)
		cfgLogger.Infof(err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lndServices := &lndConn.LndServices

	keyRing := taro.NewLndRpcKeyRing(lndServices)
	walletAnchor := taro.NewLndRpcWalletAnchor(lndServices)
	chainBridge := taro.NewLndRpcChainBridge(lndServices)
	taroChainParams := address.ParamsForChain(cfg.ActiveNetParams.Name)

	addrBook := address.NewBook(address.BookConfig{
		Store:        tarodbAddrBook,
		StoreTimeout: tarodb.DefaultStoreTimeout,
		KeyRing:      keyRing,
		Chain:        taroChainParams,
	})

	// This concurrent error queue can be used by every component that can
	// raise runtime errors. Using a queue will prevent us from blocking on
	// sending errors to it, as long as the queue is running.
	errQueue := chanutils.NewConcurrentQueue[error](
		chanutils.DefaultQueueSize,
	)
	errQueue.Start()
	defer errQueue.Stop()
	assetStore := tarodb.NewAssetStore(assetDB)

	proofFileStore, err := proof.NewFileArchiver(cfg.networkDir)
	if err != nil {
		err := fmt.Sprintf("unable to open disk archive: %v", err)
		cfgLogger.Infof(err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
		return
	}

	server, err := taro.NewServer(&taro.Config{
		DebugLevel:  cfg.DebugLevel,
		ChainParams: cfg.ActiveNetParams,
		AssetMinter: tarogarden.NewChainPlanter(tarogarden.PlanterConfig{
			GardenKit: tarogarden.GardenKit{
				Wallet:      walletAnchor,
				ChainBridge: chainBridge,
				Log:         assetMintingStore,
				KeyRing:     keyRing,
				GenSigner: taro.NewLndRpcGenSigner(
					lndServices,
				),
			},
			BatchTicker: ticker.New(cfg.BatchMintingInterval),
			ErrChan:     errQueue.ChanIn(),
		}),
		AddrBook: addrBook,
		ProofArchive: proof.NewMultiArchiver(
			&proof.BaseVerifier{}, assetStore, proofFileStore,
		),
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
			MacaroonPath:   cfg.RpcConf.MacaroonPath,
		},
		DatabaseConfig: &taro.DatabaseConfig{
			RootKeyStore: tarodb.NewRootKeyStore(rksDB),
			MintingStore: assetMintingStore,
			AssetStore:   assetStore,
			TaroAddrBook: tarodbAddrBook,
		},
	})
	if err != nil {
		err := fmt.Errorf("unable to start server: %v", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = server.RunUntilShutdown(errQueue.ChanOut())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
