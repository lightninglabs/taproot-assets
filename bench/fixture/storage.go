package fixture

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// Storage layers a sqlite-backed db and the most common subsystems onto
// Minimal. It is sufficient for query/marshalling RPCs (List*, Query*,
// Decode-with-marshal, Fetch*) and for universe read RPCs.
//
// Heavy subsystems that need lnd (Planter/Porter/Custodian, channel deps)
// are not populated here — see Mint, Send and Universe fixtures.
type Storage struct {
	*Minimal

	DB                 *tapdb.SqliteStore
	AssetStore         *tapdb.AssetStore
	TapAddrBook        *tapdb.TapAddressBook
	AddrBook           *address.Book
	Multiverse         *tapdb.MultiverseStore
	UniverseStats      universe.Telemetry
	UniverseArchive    *universe.Archive
	UniverseSyncer     *universe.SimpleSyncer
	UniverseFederation *universe.FederationEnvoy
	FederationDB       *tapdb.UniverseFederationDB
	ProofArchive       proof.NotifyArchiver
	KeyRing            *tapnodemock.KeyRing
}

// NewStorage constructs a Storage fixture, populates the rpcserver config
// with all subsystem fields it provides, and registers cleanup.
func NewStorage(tb testing.TB) *Storage {
	tb.Helper()

	min := NewMinimal(tb)
	db := tapdb.NewTestDB(tb)
	// A fixed clock keeps timing-dependent paths deterministic across
	// runs. The exact value is arbitrary; it only matters that it does
	// not advance during a bench iteration.
	testClock := clock.NewTestClock(time.Unix(1_700_000_000, 0))

	// Address book + asset store.
	addrTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.AddrBook {
			return db.WithTx(tx)
		},
	)
	tapAddrBook := tapdb.NewTapAddressBook(
		addrTx, &min.Config.ChainParams, testClock,
	)
	assetDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.ActiveAssetsStore {
			return db.WithTx(tx)
		},
	)
	metaDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.MetaStore {
			return db.WithTx(tx)
		},
	)
	assetStore := tapdb.NewAssetStore(
		assetDB, metaDB, testClock, db.Backend(),
	)

	// Address Book consumes the tapdb store + a mock key ring; no syncer
	// (benches never reach out to federation servers).
	keyRing := tapnodemock.NewKeyRing()
	addrBook := address.NewBook(address.BookConfig{
		Store:        tapAddrBook,
		Syncer:       nil,
		KeyRing:      keyRing,
		Chain:        min.Config.ChainParams,
		StoreTimeout: tapdb.DefaultStoreTimeout,
	})

	// Multiverse + universe stats.
	multiverseDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverse, err := tapdb.NewMultiverseStore(
		multiverseDB, &tapdb.MultiverseStoreConfig{},
	)
	require.NoError(tb, err)

	uniStatsDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.UniverseStatsStore {
			return db.WithTx(tx)
		},
	)
	universeStats := tapdb.NewUniverseStats(uniStatsDB, testClock)

	// Universe archive — uses mock verifiers and mock chain lookup so it
	// does not require a live chain backend.
	uniDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
	newBaseTree := func(
		id universe.Identifier,
	) universe.StorageBackend {

		return tapdb.NewBaseUniverseTree(uniDB, id)
	}
	uniArchive := universe.NewArchive(universe.ArchiveConfig{
		NewBaseTree:          newBaseTree,
		HeaderVerifier:       proof.MockHeaderVerifier,
		MerkleVerifier:       proof.DefaultMerkleVerifier,
		GroupVerifier:        proof.MockGroupVerifier,
		ChainLookupGenerator: proof.MockChainLookup,
		Multiverse:           multiverse,
		UniverseStats:        universeStats,
		IgnoreChecker:        lfn.None[proof.IgnoreChecker](),
	})

	// Federation db (no actual federation members configured).
	federationStore := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.UniverseServerStore {
			return db.WithTx(tx)
		},
	)
	federationDB := tapdb.NewUniverseFederationDB(
		federationStore, testClock,
	)

	// Universe syncer and federation envoy. The remote-side hooks are
	// stubbed: NewRemoteDiffEngine and NewRemoteRegistrar return an
	// error so any sync attempt fails cleanly rather than reaching out
	// over the network. StaticFederationMembers stays empty so the
	// envoy's startup goroutine never invokes ServerChecker.
	uniSyncer := universe.NewSimpleSyncer(universe.SimpleSyncCfg{
		LocalDiffEngine:     uniArchive,
		LocalRegistrar:      uniArchive,
		NewRemoteDiffEngine: noRemoteDiffEngine,
		SyncBatchSize:       100,
	})

	envoyErrChan := make(chan error, 1)
	uniFederation := universe.NewFederationEnvoy(
		universe.FederationConfig{
			FederationDB:       federationDB,
			UniverseSyncer:     uniSyncer,
			LocalRegistrar:     uniArchive,
			NewRemoteRegistrar: noRemoteRegistrar,
			SyncInterval:       24 * time.Hour,
			ErrChan:            envoyErrChan,
			ServerChecker:      noopServerChecker,
		},
	)
	require.NoError(tb, uniFederation.Start())
	tb.Cleanup(func() { _ = uniFederation.Stop() })

	// Proof archive — file-backed under a temp dir.
	proofFileArchiver, err := proof.NewFileArchiver(tb.TempDir())
	require.NoError(tb, err)
	proofArchive := proof.NewMultiArchiver(
		&proof.BaseVerifier{}, tapdb.DefaultStoreTimeout,
		assetStore, proofFileArchiver,
	)

	// Wire everything into the rpcserver config.
	min.Config.AssetStore = assetStore
	min.Config.TapAddrBook = tapAddrBook
	min.Config.AddrBook = addrBook
	min.Config.Multiverse = multiverse
	min.Config.UniverseStats = universeStats
	min.Config.UniverseArchive = uniArchive
	min.Config.UniverseSyncer = uniSyncer
	min.Config.UniverseFederation = uniFederation
	min.Config.FederationDB = federationDB
	min.Config.ProofArchive = proofArchive

	return &Storage{
		Minimal:            min,
		DB:                 db,
		AssetStore:         assetStore,
		TapAddrBook:        tapAddrBook,
		AddrBook:           addrBook,
		Multiverse:         multiverse,
		UniverseStats:      universeStats,
		UniverseArchive:    uniArchive,
		UniverseSyncer:     uniSyncer,
		UniverseFederation: uniFederation,
		FederationDB:       federationDB,
		ProofArchive:       proofArchive,
		KeyRing:            keyRing,
	}
}

// noRemoteDiffEngine is a NewRemoteDiffEngine stub: any attempt to
// reach a remote universe fails cleanly instead of dialing the network.
func noRemoteDiffEngine(_ universe.ServerAddr) (universe.DiffEngine, error) {
	return nil, errNoRemoteFederation
}

// noRemoteRegistrar is a NewRemoteRegistrar stub: any attempt to push a
// proof out to a remote universe fails cleanly.
func noRemoteRegistrar(_ universe.ServerAddr) (universe.Registrar, error) {
	return nil, errNoRemoteFederation
}

// noopServerChecker treats every candidate federation member as
// reachable. It is only called for entries in StaticFederationMembers,
// which the Storage fixture leaves empty.
func noopServerChecker(_ universe.ServerAddr) error { return nil }

var errNoRemoteFederation = errors.New(
	"bench fixture has no remote federation",
)
