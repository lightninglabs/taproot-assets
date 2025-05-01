package tapcfg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btclog/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/signal"
)

// genServerConfig generates a server config from the given tapd config.
//
// NOTE: The RPCConfig and SignalInterceptor fields must be set by the caller
// after generating the server config.
func genServerConfig(cfg *Config, cfgLogger btclog.Logger,
	lndServices *lndclient.LndServices, enableChannelFeatures bool,
	mainErrChan chan<- error) (*tap.Config, error) {

	var (
		err    error
		db     tapdb.DatabaseBackend
		dbType sqlc.BackendType
	)

	// Now that we know where the database will live, we'll go ahead and
	// open up the default implementation of it.
	switch cfg.DatabaseBackend {
	case DatabaseBackendSqlite:
		dbType = sqlc.BackendTypeSqlite

		cfgLogger.Infof("Opening sqlite3 database at: %v",
			cfg.Sqlite.DatabaseFileName)
		db, err = tapdb.NewSqliteStore(cfg.Sqlite)

	case DatabaseBackendPostgres:
		dbType = sqlc.BackendTypePostgres

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

	metaDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.MetaStore {
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
	assetStore := tapdb.NewAssetStore(assetDB, metaDB, defaultClock, dbType)

	keyRing := tap.NewLndRpcKeyRing(lndServices)
	walletAnchor := tap.NewLndRpcWalletAnchor(lndServices)
	chainBridge := tap.NewLndRpcChainBridge(lndServices, assetStore)
	msgTransportClient := tap.NewLndMsgTransportClient(lndServices)
	lndRouterClient := tap.NewLndRouterClient(lndServices)
	lndInvoicesClient := tap.NewLndInvoicesClient(lndServices)
	lndFeatureBitsVerifier := tap.NewLndFeatureBitVerifier(lndServices)

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

	cfgLogger.Debugf("multiverse_cache=%v",
		spew.Sdump(cfg.Universe.MultiverseCaches))

	multiverse := tapdb.NewMultiverseStore(
		multiverseDB, &tapdb.MultiverseStoreConfig{
			Caches: *cfg.Universe.MultiverseCaches,
		},
	)

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
		HeaderVerifier:       headerVerifier,
		MerkleVerifier:       proof.DefaultMerkleVerifier,
		GroupVerifier:        groupVerifier,
		ChainLookupGenerator: chainBridge,
		Multiverse:           multiverse,
		UniverseStats:        universeStats,
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
		// Add our default mainnet federation server to the list of
		// federation servers if not disabled by the user for privacy
		// reasons.
		if !cfg.Universe.NoDefaultFederation {
			cfgLogger.Infof("Configuring %v as initial Universe "+
				"federation server",
				defaultMainnetFederationServer)

			federationMembers = append(
				federationMembers,
				defaultMainnetFederationServer,
			)
		}

		// For mainnet, we need to overwrite the default universe proof
		// courier address to use the mainnet server.
		if cfg.DefaultProofCourierAddr == defaultProofCourierAddr {
			cfg.DefaultProofCourierAddr = fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				defaultMainnetFederationServer,
			)
		}

	case "testnet":
		// Add our default testnet federation server to the list of
		// federation servers if not disabled by the user for privacy
		// reasons.
		if !cfg.Universe.NoDefaultFederation {
			cfgLogger.Infof("Configuring %v as initial Universe "+
				"federation server",
				defaultTestnetFederationServer)

			federationMembers = append(
				federationMembers,
				defaultTestnetFederationServer,
			)
		}

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

	// Determine whether we should use the mock price oracle service or a
	// real price oracle service.
	var priceOracle rfq.PriceOracle

	rfqCfg := cfg.Experimental.Rfq
	switch rfqCfg.PriceOracleAddress {
	case rfq.MockPriceOracleServiceAddress:
		switch {
		case rfqCfg.MockOracleAssetsPerBTC > 0:
			priceOracle = rfq.NewMockPriceOracle(
				3600, rfqCfg.MockOracleAssetsPerBTC,
			)

		case rfqCfg.MockOracleSatsPerAsset > 0:
			priceOracle = rfq.NewMockPriceOracleSatPerAsset(
				3600, rfqCfg.MockOracleSatsPerAsset,
			)
		}

	case "":
		// Leave the price oracle as nil, which will cause the RFQ
		// manager to reject all incoming RFQ requests. It will also
		// skip setting suggested prices for outgoing quote requests.

	default:
		priceOracle, err = rfq.NewRpcPriceOracle(
			rfqCfg.PriceOracleAddress, false,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create price "+
				"oracle: %w", err)
		}
	}

	// Construct the RFQ manager.
	rfqManager, err := rfq.NewManager(
		rfq.ManagerCfg{
			PeerMessenger:   msgTransportClient,
			HtlcInterceptor: lndRouterClient,
			HtlcSubscriber:  lndRouterClient,
			PriceOracle:     priceOracle,
			ChannelLister:   walletAnchor,
			GroupLookup:     tapdbAddrBook,
			AliasManager:    lndRouterClient,
			// nolint: lll
			AcceptPriceDeviationPpm: rfqCfg.AcceptPriceDeviationPpm,
			// nolint: lll
			SkipAcceptQuotePriceCheck: rfqCfg.SkipAcceptQuotePriceCheck,
			ErrChan:                   mainErrChan,
		},
	)
	if err != nil {
		return nil, err
	}

	// For the porter, we'll make a multi-notifier comprised of all the
	// possible proof file sources to ensure it can always fetch input
	// proofs.
	porterProofReader := proof.NewMultiArchiveNotifier(
		assetStore, multiverse, proofFileStore,
	)
	chainPorter := tapfreighter.NewChainPorter(
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
			ProofReader:            porterProofReader,
			ProofWriter:            proofFileStore,
			ProofCourierDispatcher: proofCourierDispatcher,
			ProofWatcher:           reOrgWatcher,
			ErrChan:                mainErrChan,
		},
	)

	auxLeafSigner := tapchannel.NewAuxLeafSigner(
		&tapchannel.LeafSignerConfig{
			ChainParams: &tapChainParams,
			Signer:      assetWallet,
		},
	)
	channelFunder := tap.NewLndPbstChannelFunder(lndServices)
	auxFundingController := tapchannel.NewFundingController(
		tapchannel.FundingControllerCfg{
			HeaderVerifier: headerVerifier,
			GroupVerifier: tapgarden.GenGroupVerifier(
				context.Background(), assetMintingStore,
			),
			ErrReporter:        msgTransportClient,
			AssetWallet:        assetWallet,
			CoinSelector:       coinSelect,
			AddrBook:           tapdbAddrBook,
			ChainParams:        tapChainParams,
			ChainBridge:        chainBridge,
			GroupKeyIndex:      tapdbAddrBook,
			PeerMessenger:      msgTransportClient,
			ChannelFunder:      channelFunder,
			TxPublisher:        chainBridge,
			ChainWallet:        walletAnchor,
			RfqManager:         rfqManager,
			TxSender:           chainPorter,
			DefaultCourierAddr: proofCourierAddr,
			AssetSyncer:        addrBook,
			FeatureBits:        lndFeatureBitsVerifier,
			ErrChan:            mainErrChan,
		},
	)
	auxTrafficShaper := tapchannel.NewAuxTrafficShaper(
		&tapchannel.TrafficShaperConfig{
			ChainParams: &tapChainParams,
			RfqManager:  rfqManager,
		},
	)
	auxInvoiceManager := tapchannel.NewAuxInvoiceManager(
		&tapchannel.InvoiceManagerConfig{
			ChainParams:         &tapChainParams,
			InvoiceHtlcModifier: lndInvoicesClient,
			RfqManager:          rfqManager,
			LightningClient:     lndServices.Client,
		},
	)
	auxChanCloser := tapchannel.NewAuxChanCloser(
		tapchannel.AuxChanCloserCfg{
			ChainParams:        &tapChainParams,
			AddrBook:           addrBook,
			TxSender:           chainPorter,
			DefaultCourierAddr: proofCourierAddr,
			ProofArchive:       proofArchive,
			ProofFetcher:       proofCourierDispatcher,
			HeaderVerifier:     headerVerifier,
			GroupVerifier: tapgarden.GenGroupVerifier(
				context.Background(), assetMintingStore,
			),
			ChainBridge: chainBridge,
		},
	)
	auxSweeper := tapchannel.NewAuxSweeper(
		&tapchannel.AuxSweeperCfg{
			AddrBook:           addrBook,
			ChainParams:        tapChainParams,
			Signer:             assetWallet,
			TxSender:           chainPorter,
			DefaultCourierAddr: proofCourierAddr,
			ProofArchive:       proofArchive,
			ProofFetcher:       proofCourierDispatcher,
			HeaderVerifier:     headerVerifier,
			GroupVerifier: tapgarden.GenGroupVerifier(
				context.Background(), assetMintingStore,
			),
			ChainBridge: chainBridge,
		},
	)

	// Parse the universe public access status.
	universePublicAccess, err := tap.ParseUniversePublicAccessStatus(
		cfg.Universe.PublicAccess,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse universe public "+
			"access status: %w", err)
	}

	return &tap.Config{
		DebugLevel:            cfg.DebugLevel,
		RuntimeID:             runtimeID,
		EnableChannelFeatures: enableChannelFeatures,
		Lnd:                   lndServices,
		ChainParams:           tapChainParams,
		ReOrgWatcher:          reOrgWatcher,
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
			ChainParams:  tapChainParams,
			ProofUpdates: proofArchive,
			ErrChan:      mainErrChan,
		}),
		// nolint: lll
		AssetCustodian: tapgarden.NewCustodian(&tapgarden.CustodianConfig{
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
			ProofRetrievalDelay:    cfg.CustodianProofRetrievalDelay,
			ProofWatcher:           reOrgWatcher,
		}),
		ChainBridge:              chainBridge,
		AddrBook:                 addrBook,
		AddrBookDisableSyncer:    cfg.AddrBook.DisableSyncer,
		DefaultProofCourierAddr:  proofCourierAddr,
		ProofArchive:             proofArchive,
		AssetWallet:              assetWallet,
		CoinSelect:               coinSelect,
		ChainPorter:              chainPorter,
		UniverseArchive:          baseUni,
		UniverseSyncer:           universeSyncer,
		UniverseFederation:       universeFederation,
		UniFedSyncAllAssets:      cfg.Universe.SyncAllAssets,
		UniverseStats:            universeStats,
		UniversePublicAccess:     universePublicAccess,
		UniverseQueriesPerSecond: cfg.Universe.UniverseQueriesPerSecond,
		UniverseQueriesBurst:     cfg.Universe.UniverseQueriesBurst,
		RfqManager:               rfqManager,
		PriceOracle:              priceOracle,
		AuxLeafSigner:            auxLeafSigner,
		AuxFundingController:     auxFundingController,
		AuxChanCloser:            auxChanCloser,
		AuxTrafficShaper:         auxTrafficShaper,
		AuxInvoiceManager:        auxInvoiceManager,
		AuxSweeper:               auxSweeper,
		LogWriter:                cfg.LogWriter,
		LogMgr:                   cfg.LogMgr,
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
	shutdownInterceptor signal.Interceptor, enableChannelFeatures bool,
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
		cfg, cfgLogger, &lndConn.LndServices, enableChannelFeatures,
		mainErrChan,
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

	return tap.NewServer(&serverCfg.ChainParams, serverCfg), nil
}

// ConfigureSubServer updates a Taproot Asset server with the given CLI config.
func ConfigureSubServer(srv *tap.Server, cfg *Config, cfgLogger btclog.Logger,
	lndServices *lndclient.LndServices, litdIntegrated bool,
	mainErrChan chan<- error) error {

	serverCfg, err := genServerConfig(
		cfg, cfgLogger, lndServices, litdIntegrated, mainErrChan,
	)
	if err != nil {
		return fmt.Errorf("unable to generate server config: %w", err)
	}

	serverCfg.RPCConfig = &tap.RPCConfig{
		NoMacaroons:  cfg.RpcConf.NoMacaroons,
		MacaroonPath: cfg.RpcConf.MacaroonPath,
	}

	srv.UpdateConfig(serverCfg)

	return nil
}
