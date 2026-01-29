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
	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/lndservices"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rpcserver"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/clock"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/signal"
)

// genServerConfig generates a server config from the given tapd config.
//
// NOTE: The RPCConfig and SignalInterceptor fields must be set by the caller
// after generating the server config.
func genServerConfig(cfg *Config, cfgLogger btclog.Logger,
	lndServices *lndclient.LndServices, enableChannelFeatures bool,
	mainErrChan chan<- error) (*tapconfig.Config, error) {

	var (
		err    error
		db     tapdb.DatabaseBackend
		dbType sqlc.BackendType
	)

	// If we're using sqlite, we need to ensure that the temp directory is
	// writable otherwise we might encounter an error at an unexpected
	// time.
	if !cfg.Sqlite.SkipTmpDirCheck &&
		cfg.DatabaseBackend == DatabaseBackendSqlite {

		err = checkSQLiteTempDir()
		if err != nil {
			return nil, fmt.Errorf("unable to ensure sqlite tmp "+
				"dir is writable: %w", err)
		}
	}

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

	keyRing := lndservices.NewLndRpcKeyRing(lndServices)
	walletAnchor := lndservices.NewLndRpcWalletAnchor(
		lndServices,
		lndservices.WithPsbtMaxFeeRatio(cfg.Wallet.PsbtMaxFeeRatio),
	)

	rfqPolicyDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.RfqPolicyStore {
			return db.WithTx(tx)
		},
	)
	policyStore := tapdb.NewPersistedPolicyStore(rfqPolicyDB)

	rfqForwardDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.ForwardStore {
			return db.WithTx(tx)
		},
	)
	forwardStore := tapdb.NewPersistedForwardStore(rfqForwardDB)

	// Create a block header cache with default configuration.
	headerCache, err := lndservices.NewBlockHeaderCache(
		lndservices.DefaultBlockHeaderCacheConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create block header cache: "+
			"%w", err)
	}

	chainBridge := lndservices.NewLndRpcChainBridge(
		lndServices, assetStore, headerCache,
	)

	msgTransportClient := lndservices.NewLndMsgTransportClient(lndServices)
	lndRouterClient := lndservices.NewLndRouterClient(lndServices)
	lndInvoicesClient := lndservices.NewLndInvoicesClient(lndServices)
	lndFeatureBitsVerifier := lndservices.NewLndFeatureBitVerifier(
		lndServices,
	)

	lndFsmDaemonAdapters := lndservices.NewLndFsmDaemonAdapters(
		lndServices, headerCache,
	)

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

	multiverse, err := tapdb.NewMultiverseStore(
		multiverseDB, &tapdb.MultiverseStoreConfig{
			Caches: *cfg.Universe.MultiverseCaches,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create multiverse store: %w", err)
	}

	uniStatsDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.UniverseStatsStore {
			return db.WithTx(tx)
		},
	)

	authMailboxStore := tapdb.NewMailboxStore(tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.AuthMailboxStore {
			return db.WithTx(tx)
		},
	))

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

	// Construct the supply tree database backend so we can create the
	// ignore checker that's used by a number of early initialized
	// components in here.
	supplyTreeStore := tapdb.NewSupplyTreeStore(uniDB)
	ignoreChecker := tapdb.NewCachingIgnoreChecker(tapdb.IgnoreCheckerCfg{
		GroupQuery:              tapdbAddrBook,
		Store:                   supplyTreeStore,
		NegativeLookupCacheSize: cfg.Universe.SupplyIgnoreCacheSize,
	})

	ignoreCheckerOpt := lfn.Some[proof.IgnoreChecker](ignoreChecker)
	uniArchiveCfg := universe.ArchiveConfig{
		// nolint: lll
		NewBaseTree: func(id universe.Identifier) universe.StorageBackend {
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
		IgnoreChecker:        ignoreCheckerOpt,
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
		// courier address to use the mainnet server (the default is
		// the testnet3 server).
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

	case "testnet4":
		// Add our default testnet4 federation server to the list of
		// federation servers if not disabled by the user for privacy
		// reasons.
		if !cfg.Universe.NoDefaultFederation {
			cfgLogger.Infof("Configuring %v as initial Universe "+
				"federation server",
				defaultTestnet4FederationServer)

			federationMembers = append(
				federationMembers,
				defaultTestnet4FederationServer,
			)
		}

		// For testnet4, we need to overwrite the default universe proof
		// courier address to use the testnet4 server (the default is
		// the testnet3 server).
		if cfg.DefaultProofCourierAddr == defaultProofCourierAddr {
			cfg.DefaultProofCourierAddr = fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				defaultTestnet4FederationServer,
			)
		}

	case "signet":
		// Add our default signet federation server to the list of
		// federation servers if not disabled by the user for privacy
		// reasons.
		if !cfg.Universe.NoDefaultFederation {
			cfgLogger.Infof("Configuring %v as initial Universe "+
				"federation server",
				defaultSignetFederationServer)

			federationMembers = append(
				federationMembers,
				defaultSignetFederationServer,
			)
		}

		// For signet, we need to overwrite the default universe proof
		// courier address to use the signet server (the default is
		// the testnet3 server).
		if cfg.DefaultProofCourierAddr == defaultProofCourierAddr {
			cfg.DefaultProofCourierAddr = fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				defaultSignetFederationServer,
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
		ChainBridge:   chainBridge,
		GroupVerifier: groupVerifier,
		ProofArchive:  proofArchive,
		IgnoreChecker: ignoreCheckerOpt,
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

	uniArchive := universe.NewArchive(uniArchiveCfg)

	universeSyncer := universe.NewSimpleSyncer(universe.SimpleSyncCfg{
		LocalDiffEngine:     uniArchive,
		NewRemoteDiffEngine: rpcserver.NewRpcUniverseDiff,
		LocalRegistrar:      uniArchive,
		SyncBatchSize:       defaultUniverseSyncBatchSize,
	})

	var runtimeIDBytes [8]byte
	_, err = rand.Read(runtimeIDBytes[:])
	if err != nil {
		return nil, fmt.Errorf("unable to generate runtime ID: %w", err)
	}

	runtimeID := int64(binary.BigEndian.Uint64(runtimeIDBytes[:]))
	//nolint:lll
	universeFederation := universe.NewFederationEnvoy(
		universe.FederationConfig{
			FederationDB:            federationDB,
			UniverseSyncer:          universeSyncer,
			LocalRegistrar:          uniArchive,
			SyncInterval:            cfg.Universe.SyncInterval,
			NewRemoteRegistrar:      rpcserver.NewRpcUniverseRegistrar,
			StaticFederationMembers: federationMembers,
			ServerChecker: func(addr universe.ServerAddr) error {
				return rpcserver.CheckFederationServer(
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

	virtualTxSigner := lndservices.NewLndRpcVirtualTxSigner(lndServices)
	coinSelect := tapfreighter.NewCoinSelect(assetStore)
	assetWallet := tapfreighter.NewAssetWallet(&tapfreighter.WalletConfig{
		CoinSelector:     coinSelect,
		AssetProofs:      proofArchive,
		AddrBook:         tapdbAddrBook,
		KeyRing:          keyRing,
		Signer:           virtualTxSigner,
		TxValidator:      &tap.ValidatorV0{},
		WitnessValidator: &tap.WitnessValidatorV0{},
		ChainBridge:      chainBridge,
		GroupVerifier:    groupVerifier,
		IgnoreChecker:    ignoreCheckerOpt,
		Wallet:           walletAnchor,
		ChainParams:      &tapChainParams,
		SweepOrphanUtxos: cfg.Wallet.SweepOrphanUtxos,
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
	var portfolioPilot rfq.PortfolioPilot

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
		tlsConfig, err := getPriceOracleTLSConfig(rfqCfg)
		if err != nil {
			return nil, fmt.Errorf("couldn't construct price "+
				"oracle configuration: %w", err)
		}

		macaroonOpt, err := getPriceOracleMacaroonOpt(rfqCfg)
		if err != nil {
			return nil, fmt.Errorf("unable to load price "+
				"oracle macaroon: %w", err)
		}

		priceOracle, err = rfq.NewRpcPriceOracle(
			rfqCfg.PriceOracleAddress, tlsConfig,
			macaroonOpt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create price "+
				"oracle: %w", err)
		}
	}

	// Determine whether we should use an external portfolio pilot.
	switch rfqCfg.PortfolioPilotAddress {
	case "":
		// Leave the portfolio pilot as nil so the internal pilot is
		// used.

	default:
		portfolioPilot, err = rfq.NewRpcPortfolioPilot(
			rfqCfg.PortfolioPilotAddress, false,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create "+
				"portfolio pilot: %w", err)
		}
	}

	// Construct the AuxChannelNegotiator.
	auxChanNegotiator := tapfeatures.NewAuxChannelNegotiator()

	// Construct the RFQ manager.
	rfqManager, err := rfq.NewManager(rfq.ManagerCfg{
		PeerMessenger:           msgTransportClient,
		HtlcInterceptor:         lndRouterClient,
		HtlcSubscriber:          lndRouterClient,
		PriceOracle:             priceOracle,
		PortfolioPilot:          portfolioPilot,
		ChannelLister:           lndServices.Client,
		GroupLookup:             tapdbAddrBook,
		AuxChanNegotiator:       auxChanNegotiator,
		AliasManager:            lndRouterClient,
		AcceptPriceDeviationPpm: rfqCfg.AcceptPriceDeviationPpm,
		SkipQuoteAcceptVerify:   rfqCfg.SkipQuoteAcceptVerify,
		SendPriceHint:           rfqCfg.SendPriceHint,
		SendPeerId:              rfqCfg.PriceOracleSendPeerId,
		NoOpHTLCs:               cfg.Channel.NoopHTLCs,
		PolicyStore:             policyStore,
		ForwardStore:            forwardStore,
		ErrChan:                 mainErrChan,
	})
	if err != nil {
		return nil, err
	}

	auxLeafSigner := tapchannel.NewAuxLeafSigner(
		&tapchannel.LeafSignerConfig{
			ChainParams: &tapChainParams,
			Signer:      assetWallet,
		},
	)
	channelFunder := lndservices.NewLndPbstChannelFunder(lndServices)

	// Parse the universe public access status.
	universePublicAccess, err := tapconfig.ParseUniversePublicAccessStatus(
		cfg.Universe.PublicAccess,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse universe public "+
			"access status: %w", err)
	}

	// Construct the supply commit manager, which is used to
	// formulate universe supply commitment transactions.
	//
	// Construct database backends for the supply commitment state machines.
	supplyCommitDb := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.SupplyCommitStore {
			return db.WithTx(tx)
		},
	)
	supplyCommitStore := tapdb.NewSupplyCommitMachine(supplyCommitDb)

	// Setup supply syncer.
	supplySyncerStore := tapdb.NewSupplySyncerStore(uniDB)
	supplySyncer := supplyverifier.NewSupplySyncer(
		supplyverifier.SupplySyncerConfig{
			ClientFactory:          rpcserver.NewRpcSupplySync,
			Store:                  supplySyncerStore,
			UniverseFederationView: federationDB,
		},
	)

	// Create the supply commitment state machine manager, which is used to
	// manage the supply commitment state machines for each asset group.
	supplyCommitManager := supplycommit.NewManager(
		supplycommit.ManagerCfg{
			TreeView:           supplyTreeStore,
			Commitments:        supplyCommitStore,
			Wallet:             walletAnchor,
			AssetLookup:        tapdbAddrBook,
			Signer:             lndServices.Signer,
			KeyRing:            keyRing,
			Chain:              chainBridge,
			SupplySyncer:       &supplySyncer,
			DaemonAdapters:     lndFsmDaemonAdapters,
			StateLog:           supplyCommitStore,
			ChainParams:        *tapChainParams.Params,
			IgnoreCheckerCache: ignoreChecker,
		},
	)

	// Set up the supply verifier, which validates supply commitment leaves
	// published by asset issuers.
	//
	// nolint: lll
	supplyVerifyManager, err := supplyverifier.NewManager(
		supplyverifier.ManagerCfg{
			Chain:                 chainBridge,
			AssetLookup:           tapdbAddrBook,
			Lnd:                   lndServices,
			SupplyCommitView:      supplyCommitStore,
			SupplyTreeView:        supplyTreeStore,
			SupplySyncer:          supplySyncer,
			GroupFetcher:          assetMintingStore,
			IssuanceSubscriptions: universeSyncer,
			DaemonAdapters:        lndFsmDaemonAdapters,
			DisableChainWatch:     cfg.Universe.DisableSupplyVerifierChainWatch,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create supply verifier: %w",
			err)
	}

	// For the porter, we'll make a multi-notifier comprised of all the
	// possible proof file sources to ensure it can always fetch input
	// proofs.
	porterProofReader := proof.NewMultiArchiveNotifier(
		assetStore, multiverse, proofFileStore,
	)
	chainPorter := tapfreighter.NewChainPorter(
		&tapfreighter.ChainPorterConfig{
			ChainParams:            tapChainParams,
			Signer:                 virtualTxSigner,
			TxValidator:            &tap.ValidatorV0{},
			ExportLog:              assetStore,
			ChainBridge:            chainBridge,
			GroupVerifier:          groupVerifier,
			Wallet:                 walletAnchor,
			KeyRing:                keyRing,
			AssetWallet:            assetWallet,
			ProofReader:            porterProofReader,
			ProofWriter:            proofFileStore,
			ProofCourierDispatcher: proofCourierDispatcher,
			ProofWatcher:           reOrgWatcher,
			IgnoreChecker:          ignoreCheckerOpt,
			ErrChan:                mainErrChan,
			BurnCommitter:          supplyCommitManager,
			DelegationKeyChecker:   addrBook,
		},
	)

	auxFundingController := tapchannel.NewFundingController(
		tapchannel.FundingControllerCfg{
			HeaderVerifier:     headerVerifier,
			GroupVerifier:      groupVerifier,
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
			IgnoreChecker:      ignoreCheckerOpt,
			AuxChanNegotiator:  auxChanNegotiator,
			ErrChan:            mainErrChan,
		},
	)
	auxTrafficShaper := tapchannel.NewAuxTrafficShaper(
		&tapchannel.TrafficShaperConfig{
			ChainParams:       &tapChainParams,
			RfqManager:        rfqManager,
			NoopHTLCs:         cfg.Channel.NoopHTLCs,
			AuxChanNegotiator: auxChanNegotiator,
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
			GroupVerifier:      groupVerifier,
			ChainBridge:        chainBridge,
			IgnoreChecker:      ignoreCheckerOpt,
			AuxChanNegotiator:  auxChanNegotiator,
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
			GroupVerifier:      groupVerifier,
			ChainBridge:        chainBridge,
			IgnoreChecker:      ignoreCheckerOpt,
		},
	)

	// nolint: lll
	return &tapconfig.Config{
		DebugLevel:            cfg.DebugLevel,
		Version:               tap.Version(),
		RuntimeID:             runtimeID,
		EnableChannelFeatures: enableChannelFeatures,
		Lnd:                   lndServices,
		ChainParams:           tapChainParams,
		ReOrgWatcher:          reOrgWatcher,
		AssetMinter: tapgarden.NewChainPlanter(tapgarden.PlanterConfig{
			// nolint: lll
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
				IgnoreChecker:         ignoreCheckerOpt,
				MintSupplyCommitter:   supplyCommitManager,
				DelegationKeyChecker:  addrBook,
			},
			ChainParams:  tapChainParams,
			ProofUpdates: proofArchive,
			ErrChan:      mainErrChan,
		}),
		AssetCustodian: tapgarden.NewCustodian(&tapgarden.CustodianConfig{
			ChainParams:            &tapChainParams,
			WalletAnchor:           walletAnchor,
			ChainBridge:            chainBridge,
			GroupVerifier:          groupVerifier,
			AddrBook:               addrBook,
			Signer:                 lndServices.Signer,
			ProofArchive:           proofArchive,
			ProofNotifier:          multiNotifier,
			ErrChan:                mainErrChan,
			ProofCourierDispatcher: proofCourierDispatcher,
			MboxBackoffCfg:         cfg.UniverseRpcCourier.BackoffCfg,
			ProofRetrievalDelay:    cfg.CustodianProofRetrievalDelay,
			ProofWatcher:           reOrgWatcher,
			IgnoreChecker:          ignoreCheckerOpt,
		}),
		ChainBridge:              chainBridge,
		AddrBook:                 addrBook,
		AddrBookDisableSyncer:    cfg.AddrBook.DisableSyncer,
		DefaultProofCourierAddr:  proofCourierAddr,
		ProofArchive:             proofArchive,
		AssetWallet:              assetWallet,
		CoinSelect:               coinSelect,
		ChainPorter:              chainPorter,
		SweepOrphanUtxos:         cfg.Wallet.SweepOrphanUtxos,
		FsmDaemonAdapters:        lndFsmDaemonAdapters,
		SupplyCommitManager:      supplyCommitManager,
		IgnoreChecker:            ignoreChecker,
		SupplyVerifyManager:      supplyVerifyManager,
		UniverseArchive:          uniArchive,
		UniverseSyncer:           universeSyncer,
		UniverseFederation:       universeFederation,
		UniFedSyncAllAssets:      cfg.Universe.SyncAllAssets,
		UniverseStats:            universeStats,
		UniversePublicAccess:     universePublicAccess,
		UniverseQueriesPerSecond: cfg.Universe.UniverseQueriesPerSecond,
		UniverseQueriesBurst:     cfg.Universe.UniverseQueriesBurst,
		RfqManager:               rfqManager,
		PriceOracle:              priceOracle,
		PriceOracleSendPeerID:    cfg.Experimental.Rfq.PriceOracleSendPeerId,
		AuxLeafSigner:            auxLeafSigner,
		AuxFundingController:     auxFundingController,
		AuxChanCloser:            auxChanCloser,
		AuxTrafficShaper:         auxTrafficShaper,
		AuxChanNegotiator:        auxChanNegotiator,
		AuxInvoiceManager:        auxInvoiceManager,
		AuxSweeper:               auxSweeper,
		LogWriter:                cfg.LogWriter,
		LogMgr:                   cfg.LogMgr,
		MboxServerConfig: authmailbox.ServerConfig{
			AuthTimeout:    cfg.Universe.MboxAuthTimeout,
			Signer:         lndServices.Signer,
			HeaderVerifier: headerVerifier,
			MerkleVerifier: proof.DefaultMerkleVerifier,
			MsgStore:       authMailboxStore,
		},
		DatabaseConfig: &tapconfig.DatabaseConfig{
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

	serverCfg.RPCConfig = &tapconfig.RPCConfig{
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

	srv := tap.NewServer(&serverCfg.ChainParams)
	srv.UpdateConfig(serverCfg)

	return srv, nil
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

	serverCfg.RPCConfig = &tapconfig.RPCConfig{
		NoMacaroons:  cfg.RpcConf.NoMacaroons,
		MacaroonPath: cfg.RpcConf.MacaroonPath,
	}

	srv.UpdateConfig(serverCfg)

	return nil
}
