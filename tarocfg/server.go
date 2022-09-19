package tarocfg

import (
	"database/sql"
	"fmt"

	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/ticker"
)

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

	// Now that we know where the databse will live, we'll go ahead and
	// open up the default implementation of it.
	cfgLogger.Infof("Opening sqlite3 database at: %v", cfg.DatabaseFileName)
	db, err := tarodb.NewSqliteStore(&tarodb.SqliteConfig{
		DatabaseFileName: cfg.DatabaseFileName,
		CreateTables:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %v", err)
	}

	rksDB := tarodb.NewTransactionExecutor[tarodb.KeyStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.KeyStore { // nolint

		// TODO(roasbeef): can get rid of this by emulating the
		// sqlite.DBTX interface
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	mintingStore := tarodb.NewTransactionExecutor[tarodb.PendingAssetStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.PendingAssetStore { // nolint

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	assetMintingStore := tarodb.NewAssetMintingStore(mintingStore)

	assetDB := tarodb.NewTransactionExecutor[tarodb.ActiveAssetsStore,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.ActiveAssetsStore { // nolint

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})

	addrBookDB := tarodb.NewTransactionExecutor[tarodb.AddrBook,
		tarodb.TxOptions](db, func(tx tarodb.Tx) tarodb.AddrBook { // nolint

		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	})
	tarodbAddrBook := tarodb.NewTaroAddressBook(addrBookDB)

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
	taroChainParams := address.ParamsForChain(cfg.ActiveNetParams.Name)

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
			ErrChan:     mainErrChan,
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
		return nil, fmt.Errorf("unable to start server: %v", err)
	}

	return server, nil
}
