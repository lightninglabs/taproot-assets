package tapcfg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/lndclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/ticker"
)

// databaseBackend is an interface that contains all methods our different
// database backends implement.
type databaseBackend interface {
	tapdb.BatchedQuerier
	WithTx(tx *sql.Tx) *sqlc.Queries
}

// genServerConfig generates a server config from the given tapd config.
//
// NOTE: The RPCConfig and SignalInterceptor fields must be set by the caller
// after generating the server config.
func genServerConfig(cfg *Config, cfgLogger btclog.Logger,
	lndServices *lndclient.LndServices,
	mainErrChan chan<- error) (*tap.Config, error) {

	var err error

	// Now that we know where the database will live, we'll go ahead and
	// open up the default implementation of it.
	var db databaseBackend
	switch cfg.DatabaseBackend {
	case DatabaseBackendSqlite:
		cfgLogger.Infof("Opening sqlite3 database at: %v",
			cfg.Sqlite.DatabaseFileName)
		db, err = tapdb.NewSqliteStore(cfg.Sqlite)

	case DatabaseBackendPostgres:
		cfgLogger.Infof("Opening postgres database at: %v",
			cfg.Postgres.DSN(true))
		db, err = tapdb.NewPostgresStore(cfg.Postgres)

	default:
		return nil, fmt.Errorf("unknown database backend: %s",
			cfg.DatabaseBackend)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}

	defaultClock := clock.NewDefaultClock()
	rksDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.KeyStore {
			return db.WithTx(tx)
		},
	)
	mintingStore := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.PendingAssetStore {
			return db.WithTx(tx)
		},
	)
	assetMintingStore := tapdb.NewAssetMintingStore(mintingStore)

	assetDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.ActiveAssetsStore {
			return db.WithTx(tx)
		},
	)

	addrBookDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.AddrBook {
			return db.WithTx(tx)
		},
	)
	tapChainParams := address.ParamsForChain(cfg.ActiveNetParams.Name)
	tapdbAddrBook := tapdb.NewTapAddressBook(
		addrBookDB, &tapChainParams, defaultClock,
	)

	keyRing := tap.NewLndRpcKeyRing(lndServices)
	walletAnchor := tap.NewLndRpcWalletAnchor(lndServices)
	chainBridge := tap.NewLndRpcChainBridge(lndServices)
	msgTransportClient := tap.NewLndMsgTransportClient(lndServices)
	lndRouterClient := tap.NewLndRouterClient(lndServices)

	assetStore := tapdb.NewAssetStore(assetDB, defaultClock)

	uniDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
	multiverseDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverse := tapdb.NewMultiverseStore(multiverseDB)

	uniStatsDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.UniverseStatsStore {
			return db.WithTx(tx)
		},
	)

	var statsOpts []tapdb.UniverseStatsOption
	if cfg.Universe.StatsCacheDuration != 0 {
		cacheOpt := tapdb.WithStatsCacheDuration(
			cfg.Universe.StatsCacheDuration,
		)
		statsOpts = append(statsOpts, cacheOpt)
	}

	universeStats := tapdb.NewUniverseStats(
		uniStatsDB, defaultClock, statsOpts...,
	)

	headerVerifier := tapgarden.GenHeaderVerifier(
		context.Background(), chainBridge,
	)
	groupVerifier := tapgarden.GenGroupVerifier(
		context.Background(), assetMintingStore,
	)
	uniCfg := universe.ArchiveConfig{
		NewBaseTree: func(id universe.Identifier) universe.BaseBackend {
			return tapdb.NewBaseUniverseTree(
				uniDB, id,
			)
		},
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		Multiverse:     multiverse,
		UniverseStats:  universeStats,
	}

	federationStore := tapdb.NewTransactionExecutor(db,
		func(tx *sql.Tx) tapdb.UniverseServerStore {
			return db.WithTx(tx)
		},
	)
	federationDB := tapdb.NewUniverseFederationDB(
		federationStore, defaultClock,
	)

	proofFileStore, err := proof.NewFileArchiver(cfg.networkDir)
	if err != nil {
		return nil, fmt.Errorf("unable to open disk archive: %w", err)
	}
	proofArchive := proof.NewMultiArchiver(
		&proof.BaseVerifier{}, tapdb.DefaultStoreTimeout,
		assetStore, proofFileStore,
	)

	federationMembers := cfg.Universe.FederationServers
	switch cfg.ChainConf.Network {
	case "mainnet":
		cfgLogger.Infof("Configuring %v as initial Universe "+
			"federation server", defaultMainnetFederationServer)

		federationMembers = append(
			federationMembers, defaultMainnetFederationServer,
		)

		// For mainnet, we need to overwrite the default universe proof
		// courier address to use the mainnet server.
		if cfg.DefaultProofCourierAddr == defaultProofCourierAddr {
			cfg.DefaultProofCourierAddr = fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				defaultMainnetFederationServer,
			)
		}

	case "testnet":
		cfgLogger.Infof("Configuring %v as initial Universe "+
			"federation server", defaultTestnetFederationServer)

		federationMembers = append(
			federationMembers, defaultTestnetFederationServer,
		)

	default:
		// For any other network, such as regtest, we can't use a
		// universe proof courier by default, as we don't know what
		// server to pick. So if there is no explicit value set, we
		// fall back to using the hashmail courier, which works in all
		// cases.
		if cfg.DefaultProofCourierAddr == defaultProofCourierAddr {
			cfg.DefaultProofCourierAddr = fmt.Sprintf(
				"%s://%s", proof.HashmailCourierType,
				fallbackHashMailAddr,
			)
		}
	}

	// If no default proof courier address is set, use the fallback hashmail
	// address.
	fallbackHashmailCourierAddr := fmt.Sprintf(
		"%s://%s", proof.HashmailCourierType, fallbackHashMailAddr,
	)
	proofCourierAddr, err := proof.ParseCourierAddress(
		fallbackHashmailCourierAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse fallback proof "+
			"courier address: %w", err)
	}

	// If default proof courier address is set, use it as the default.
	if cfg.DefaultProofCourierAddr != "" {
		proofCourierAddr, err = proof.ParseCourierAddress(
			cfg.DefaultProofCourierAddr,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse default proof "+
				"courier address: %w", err)
		}
	}

	reOrgWatcher := tapgarden.NewReOrgWatcher(&tapgarden.ReOrgWatcherConfig{
		ChainBridge: chainBridge,
		GroupVerifier: tapgarden.GenGroupVerifier(
			context.Background(), assetMintingStore,
		),
		ProofArchive: proofArchive,
		NonBuriedAssetFetcher: func(ctx context.Context,
			minHeight int32) ([]*asset.ChainAsset, error) {

			return assetStore.FetchAllAssets(
				ctx, false, true, &tapdb.AssetQueryFilters{
					MinAnchorHeight: minHeight,
				},
			)
		},
		SafeDepth: cfg.ReOrgSafeDepth,
		ErrChan:   mainErrChan,
	})

	baseUni := universe.NewArchive(uniCfg)

	universeSyncer := universe.NewSimpleSyncer(universe.SimpleSyncCfg{
		LocalDiffEngine:     baseUni,
		NewRemoteDiffEngine: tap.NewRpcUniverseDiff,
		LocalRegistrar:      baseUni,
		SyncBatchSize:       defaultUniverseSyncBatchSize,
	})

	var runtimeIDBytes [8]byte
	_, err = rand.Read(runtimeIDBytes[:])
	if err != nil {
		return nil, fmt.Errorf("unable to generate runtime ID: %w", err)
	}

	runtimeID := int64(binary.BigEndian.Uint64(runtimeIDBytes[:]))
	universeFederation := universe.NewFederationEnvoy(
		universe.FederationConfig{
			FederationDB:            federationDB,
			UniverseSyncer:          universeSyncer,
			LocalRegistrar:          baseUni,
			SyncInterval:            cfg.Universe.SyncInterval,
			NewRemoteRegistrar:      tap.NewRpcUniverseRegistrar,
			StaticFederationMembers: federationMembers,
			ServerChecker: func(addr universe.ServerAddr) error {
				return tap.CheckFederationServer(
					runtimeID, universe.DefaultTimeout,
					addr,
				)
			},
			ErrChan: mainErrChan,
		},
	)

	addrBookConfig := address.BookConfig{
		Store:        tapdbAddrBook,
		Syncer:       universeFederation,
		StoreTimeout: tapdb.DefaultStoreTimeout,
		KeyRing:      keyRing,
		Chain:        tapChainParams,
	}
	if cfg.AddrBook.DisableSyncer {
		addrBookConfig.Syncer = nil
	}
	addrBook := address.NewBook(addrBookConfig)

	virtualTxSigner := tap.NewLndRpcVirtualTxSigner(lndServices)
	coinSelect := tapfreighter.NewCoinSelect(assetStore)
	assetWallet := tapfreighter.NewAssetWallet(&tapfreighter.WalletConfig{
		CoinSelector:     coinSelect,
		AssetProofs:      proofArchive,
		AddrBook:         tapdbAddrBook,
		KeyRing:          keyRing,
		Signer:           virtualTxSigner,
		TxValidator:      &tap.ValidatorV0{},
		WitnessValidator: &tap.WitnessValidatorV0{},
		Wallet:           walletAnchor,
		ChainParams:      &tapChainParams,
	})

	// Addresses can have different proof couriers configured, but both
	// types of couriers that currently exist will receive this config upon
	// initialization.
	proofCourierDispatcher := proof.NewCourierDispatch(&proof.CourierCfg{
		HashMailCfg:    cfg.HashMailCourier,
		UniverseRpcCfg: cfg.UniverseRpcCourier,
		TransferLog:    assetStore,
		LocalArchive:   proofArchive,
	})

	multiNotifier := proof.NewMultiArchiveNotifier(assetStore, multiverse)

	// TODO(ffranr): Replace the mock price oracle with a real one.
	priceOracle := rfq.NewMockPriceOracle(3600)

	// Construct the RFQ manager.
	rfqManager, err := rfq.NewManager(
		rfq.ManagerCfg{
			PeerMessenger:   msgTransportClient,
			HtlcInterceptor: lndRouterClient,
			PriceOracle:     priceOracle,
			ErrChan:         mainErrChan,
		},
	)
	if err != nil {
		return nil, err
	}

	return &tap.Config{
		DebugLevel:   cfg.DebugLevel,
		RuntimeID:    runtimeID,
		Lnd:          lndServices,
		ChainParams:  cfg.ActiveNetParams,
		ReOrgWatcher: reOrgWatcher,
		AssetMinter: tapgarden.NewChainPlanter(tapgarden.PlanterConfig{
			GardenKit: tapgarden.GardenKit{
				Wallet:                walletAnchor,
				ChainBridge:           chainBridge,
				Log:                   assetMintingStore,
				TreeStore:             assetMintingStore,
				KeyRing:               keyRing,
				GenSigner:             virtualTxSigner,
				GenTxBuilder:          &tapscript.GroupTxBuilder{},
				TxValidator:           &tap.ValidatorV0{},
				ProofFiles:            proofFileStore,
				Universe:              universeFederation,
				ProofWatcher:          reOrgWatcher,
				UniversePushBatchSize: defaultUniverseSyncBatchSize,
			},
			BatchTicker:  ticker.NewForce(cfg.BatchMintingInterval),
			ProofUpdates: proofArchive,
			ErrChan:      mainErrChan,
		}),
		AssetCustodian: tapgarden.NewCustodian(
			&tapgarden.CustodianConfig{
				ChainParams:  &tapChainParams,
				WalletAnchor: walletAnchor,
				ChainBridge:  chainBridge,
				GroupVerifier: tapgarden.GenGroupVerifier(
					context.Background(), assetMintingStore,
				),
				AddrBook:               addrBook,
				ProofArchive:           proofArchive,
				ProofNotifier:          multiNotifier,
				ErrChan:                mainErrChan,
				ProofCourierDispatcher: proofCourierDispatcher,
				ProofRetrievalDelay:    cfg.CustodianProofRetrievalDelay, ProofWatcher: reOrgWatcher,
			},
		),
		ChainBridge:             chainBridge,
		AddrBook:                addrBook,
		AddrBookDisableSyncer:   cfg.AddrBook.DisableSyncer,
		DefaultProofCourierAddr: proofCourierAddr,
		ProofArchive:            proofArchive,
		AssetWallet:             assetWallet,
		CoinSelect:              coinSelect,
		ChainPorter: tapfreighter.NewChainPorter(
			&tapfreighter.ChainPorterConfig{
				Signer:      virtualTxSigner,
				TxValidator: &tap.ValidatorV0{},
				ExportLog:   assetStore,
				ChainBridge: chainBridge,
				GroupVerifier: tapgarden.GenGroupVerifier(
					context.Background(), assetMintingStore,
				),
				Wallet:                 walletAnchor,
				KeyRing:                keyRing,
				AssetWallet:            assetWallet,
				AssetProofs:            proofFileStore,
				ProofCourierDispatcher: proofCourierDispatcher,
				ProofWatcher:           reOrgWatcher,
				ErrChan:                mainErrChan,
			},
		),
		UniverseArchive:          baseUni,
		UniverseSyncer:           universeSyncer,
		UniverseFederation:       universeFederation,
		UniverseStats:            universeStats,
		UniversePublicAccess:     cfg.Universe.PublicAccess,
		UniverseQueriesPerSecond: cfg.Universe.UniverseQueriesPerSecond,
		UniverseQueriesBurst:     cfg.Universe.UniverseQueriesBurst,
		RfqManager:               rfqManager,
		LogWriter:                cfg.LogWriter,
		DatabaseConfig: &tap.DatabaseConfig{
			RootKeyStore: tapdb.NewRootKeyStore(rksDB),
			MintingStore: assetMintingStore,
			AssetStore:   assetStore,
			TapAddrBook:  tapdbAddrBook,
			Multiverse:   multiverse,
			FederationDB: federationDB,
		},
		Prometheus: cfg.Prometheus,
	}, nil
}

// CreateServerFromConfig creates a new Taproot Asset server from the given CLI
// config.
func CreateServerFromConfig(cfg *Config, cfgLogger btclog.Logger,
	shutdownInterceptor signal.Interceptor,
	mainErrChan chan<- error) (*tap.Server, error) {

	// Given the config above, grab the TLS config which includes the set
	// of dial options, and also the listeners we'll use to listen on the
	// RPC system.
	serverOpts, restDialOpts, restListen, err := getTLSConfig(
		cfg, cfgLogger,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load TLS credentials: %w",
			err)
	}

	cfgLogger.Infof("Attempting to establish connection to lnd...")

	lndConn, err := getLnd(
		cfg.ChainConf.Network, cfg.Lnd, shutdownInterceptor,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to lnd node: %w", err)
	}

	cfgLogger.Infof("lnd connection initialized")

	serverCfg, err := genServerConfig(
		cfg, cfgLogger, &lndConn.LndServices, mainErrChan,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate server config: %w",
			err)
	}

	serverCfg.SignalInterceptor = shutdownInterceptor

	serverCfg.RPCConfig = &tap.RPCConfig{
		LisCfg:                     &lnd.ListenerCfg{},
		RPCListeners:               cfg.rpcListeners,
		RESTListeners:              cfg.restListeners,
		GrpcServerOpts:             serverOpts,
		RestDialOpts:               restDialOpts,
		RestListenFunc:             restListen,
		WSPingInterval:             cfg.RpcConf.WSPingInterval,
		WSPongWait:                 cfg.RpcConf.WSPongWait,
		RestCORS:                   cfg.RpcConf.RestCORS,
		NoMacaroons:                cfg.RpcConf.NoMacaroons,
		MacaroonPath:               cfg.RpcConf.MacaroonPath,
		AllowPublicUniProofCourier: cfg.RpcConf.AllowPublicUniProofCourier,
		AllowPublicStats:           cfg.RpcConf.AllowPublicStats,
		LetsEncryptDir:             cfg.RpcConf.LetsEncryptDir,
		LetsEncryptListen:          cfg.RpcConf.LetsEncryptListen,
		LetsEncryptEmail:           cfg.RpcConf.LetsEncryptEmail,
		LetsEncryptDomain:          cfg.RpcConf.LetsEncryptDomain,
	}

	return tap.NewServer(serverCfg), nil
}

// CreateSubServerFromConfig creates a new Taproot Asset server from the given
// CLI config.
func CreateSubServerFromConfig(cfg *Config, cfgLogger btclog.Logger,
	lndServices *lndclient.LndServices,
	mainErrChan chan<- error) (*tap.Server, error) {

	serverCfg, err := genServerConfig(
		cfg, cfgLogger, lndServices, mainErrChan,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate server config: %w",
			err)
	}

	serverCfg.RPCConfig = &tap.RPCConfig{
		NoMacaroons:  cfg.RpcConf.NoMacaroons,
		MacaroonPath: cfg.RpcConf.MacaroonPath,
	}

	return tap.NewServer(serverCfg), nil
}
