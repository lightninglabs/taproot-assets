package tarocfg

import (
	"database/sql"
	"fmt"

	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/ticker"
)

// databaseBackend is an interface that contains all methods our different
// database backends implement.
type databaseBackend interface {
	tarodb.BatchedQuerier
	WithTx(tx *sql.Tx) *sqlc.Queries
}

// CreateServerFromConfig creates a new Taro server from the given CLI config.
func CreateServerFromConfig(cfg *Config, cfgLogger btclog.Logger,
	shutdownInterceptor signal.Interceptor,
	mainErrChan chan<- error) (*taro.Server, error) {

	// Given the config above, grab the TLS config which includes the set
	// of dial options, and also the listeners we'll use to listen on the
	// RPC system.
	serverOpts, restDialOpts, restListen, err := getTLSConfig(
		cfg, cfgLogger,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load TLS credentials: %v",
			err)
	}

	// Now that we know where the database will live, we'll go ahead and
	// open up the default implementation of it.
	var db databaseBackend
	switch cfg.DatabaseBackend {
	case DatabaseBackendSqlite:
		cfgLogger.Infof("Opening sqlite3 database at: %v",
			cfg.Sqlite.DatabaseFileName)
		db, err = tarodb.NewSqliteStore(cfg.Sqlite)

	case DatabaseBackendPostgres:
		cfgLogger.Infof("Opening postgres database at: %v",
			cfg.Postgres.DSN(true))
		db, err = tarodb.NewPostgresStore(cfg.Postgres)

	default:
		return nil, fmt.Errorf("unknown database backend: %s",
			cfg.DatabaseBackend)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %v", err)
	}

	rksDB := tarodb.NewTransactionExecutor[tarodb.KeyStore](
		db, func(tx *sql.Tx) tarodb.KeyStore {
			return db.WithTx(tx)
		},
	)
	mintingStore := tarodb.NewTransactionExecutor[tarodb.PendingAssetStore](
		db, func(tx *sql.Tx) tarodb.PendingAssetStore {
			return db.WithTx(tx)
		},
	)
	assetMintingStore := tarodb.NewAssetMintingStore(mintingStore)

	assetDB := tarodb.NewTransactionExecutor[tarodb.ActiveAssetsStore](
		db, func(tx *sql.Tx) tarodb.ActiveAssetsStore {
			return db.WithTx(tx)
		},
	)

	addrBookDB := tarodb.NewTransactionExecutor[tarodb.AddrBook](
		db, func(tx *sql.Tx) tarodb.AddrBook {
			return db.WithTx(tx)
		},
	)
	taroChainParams := address.ParamsForChain(cfg.ActiveNetParams.Name)
	tarodbAddrBook := tarodb.NewTaroAddressBook(
		addrBookDB, &taroChainParams,
	)

	cfgLogger.Infof("Attempting to establish connection to lnd...")
	lndConn, err := getLnd(
		cfg.ChainConf.Network, cfg.Lnd, shutdownInterceptor,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to lnd node: %v", err)
	}
	lndServices := &lndConn.LndServices

	keyRing := taro.NewLndRpcKeyRing(lndServices)
	walletAnchor := taro.NewLndRpcWalletAnchor(lndServices)
	chainBridge := taro.NewLndRpcChainBridge(lndServices)

	cfgLogger.Infof("lnd connection initialized")

	addrBook := address.NewBook(address.BookConfig{
		Store:        tarodbAddrBook,
		StoreTimeout: tarodb.DefaultStoreTimeout,
		KeyRing:      keyRing,
		Chain:        taroChainParams,
	})

	assetStore := tarodb.NewAssetStore(assetDB)

	proofFileStore, err := proof.NewFileArchiver(cfg.networkDir)
	if err != nil {
		return nil, fmt.Errorf("unable to open disk archive: %v", err)
	}
	proofArchive := proof.NewMultiArchiver(
		&proof.BaseVerifier{}, tarodb.DefaultStoreTimeout,
		assetStore, proofFileStore,
	)

	var hashMailCourier proof.Courier[address.Taro]
	if cfg.HashMailCourier != nil {
		hashMailBox, err := proof.NewHashMailBox(
			cfg.HashMailCourier.Addr,
			cfg.HashMailCourier.TlsCertPath,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make "+
				"mailbox: %v", err)
		}
		hashMailCourier, err = proof.NewHashMailCourier(
			cfg.HashMailCourier, hashMailBox, assetStore,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make hashmail "+
				"courier: %v", err)
		}
	}

	virtualTxSigner := taro.NewLndRpcVirtualTxSigner(lndServices)
	assetWallet := tarofreighter.NewAssetWallet(&tarofreighter.WalletConfig{
		CoinSelector: assetStore,
		AssetProofs:  proofArchive,
		KeyRing:      keyRing,
		Signer:       virtualTxSigner,
		TxValidator:  &taro.ValidatorV0{},
		Wallet:       walletAnchor,
		ChainParams:  &taroChainParams,
	})
	server := taro.NewServer(&taro.Config{
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
				ProofFiles: proofFileStore,
			},
			BatchTicker: ticker.NewForce(cfg.BatchMintingInterval),
			ErrChan:     mainErrChan,
		}),
		AssetCustodian: tarogarden.NewCustodian(
			&tarogarden.CustodianConfig{
				ChainParams:  &taroChainParams,
				WalletAnchor: walletAnchor,
				ChainBridge:  chainBridge,
				AddrBook:     addrBook,
				ProofArchive: proofArchive,
				ErrChan:      mainErrChan,
				ProofCourier: hashMailCourier,
			},
		),
		ChainBridge:  chainBridge,
		AddrBook:     addrBook,
		ProofArchive: proofArchive,
		AssetWallet:  assetWallet,
		ChainPorter: tarofreighter.NewChainPorter(
			&tarofreighter.ChainPorterConfig{
				CoinSelector: assetStore,
				Signer:       virtualTxSigner,
				TxValidator:  &taro.ValidatorV0{},
				ExportLog:    assetStore,
				ChainBridge:  chainBridge,
				Wallet:       walletAnchor,
				KeyRing:      keyRing,
				AssetWallet:  assetWallet,
				AssetProofs:  proofFileStore,
				ProofCourier: hashMailCourier,
				ErrChan:      mainErrChan,
			},
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

	return server, nil
}
