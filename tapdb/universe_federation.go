package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnutils"
	"golang.org/x/exp/maps"
)

type (
	// UpsertFedProofSyncLogParams is used to upsert federation proof sync
	// logs.
	UpsertFedProofSyncLogParams = sqlc.UpsertFederationProofSyncLogParams

	// QueryFedProofSyncLogParams is used to query for federation proof sync
	// logs.
	QueryFedProofSyncLogParams = sqlc.QueryFederationProofSyncLogParams

	// DeleteFedProofSyncLogParams is used to delete proof sync log entries.
	DeleteFedProofSyncLogParams = sqlc.DeleteFederationProofSyncLogParams

	// ProofSyncLogEntry is a single entry from the proof sync log.
	ProofSyncLogEntry = sqlc.QueryFederationProofSyncLogRow

	// NewUniverseServer is used to create a new universe server.
	NewUniverseServer = sqlc.InsertUniverseServerParams

	// DelUniverseServer is used to delete a universe server.
	DelUniverseServer = sqlc.DeleteUniverseServerParams

	// UpsertFedGlobalSyncConfigParams is used to set the global federation
	// sync configuration for a given proof type.
	UpsertFedGlobalSyncConfigParams = sqlc.UpsertFederationGlobalSyncConfigParams

	// FedGlobalSyncConfig is the proof type specific global federation sync
	// config returned from a query.
	FedGlobalSyncConfig = sqlc.FederationGlobalSyncConfig

	// UpsertFedUniSyncConfigParams is used to set the universe specific
	// federation sync configuration.
	UpsertFedUniSyncConfigParams = sqlc.UpsertFederationUniSyncConfigParams

	// FedUniSyncConfigs is the universe specific federation sync config
	// returned from a query.
	FedUniSyncConfigs = sqlc.FederationUniSyncConfig

	// QueryUniServersParams is used to query for universe servers.
	QueryUniServersParams = sqlc.QueryUniverseServersParams
)

var (
	// defaultGlobalSyncConfigs is the default set of global federation
	// sync configs that will be used if no global configs have been set.
	defaultGlobalSyncConfigs = []*universe.FedGlobalSyncConfig{
		{
			ProofType:       universe.ProofTypeIssuance,
			AllowSyncInsert: false,
			AllowSyncExport: true,
		},
		{
			ProofType:       universe.ProofTypeTransfer,
			AllowSyncInsert: false,
			AllowSyncExport: true,
		},
	}
)

// FederationProofSyncLogStore is used to log the sync status of individual
// universe proofs.
type FederationProofSyncLogStore interface {
	BaseUniverseStore

	// UpsertFederationProofSyncLog upserts a proof sync log entry for a
	// given proof leaf and server.
	UpsertFederationProofSyncLog(ctx context.Context,
		arg UpsertFedProofSyncLogParams) (int64, error)

	// QueryFederationProofSyncLog returns the set of proof sync logs for a
	// given proof leaf.
	QueryFederationProofSyncLog(ctx context.Context,
		arg QueryFedProofSyncLogParams) ([]ProofSyncLogEntry, error)

	// DeleteFederationProofSyncLog deletes proof sync log entries.
	DeleteFederationProofSyncLog(ctx context.Context,
		arg DeleteFedProofSyncLogParams) error
}

// FederationSyncConfigStore is used to manage the set of Universe servers as
// part of a federation.
type FederationSyncConfigStore interface {
	// UpsertFederationGlobalSyncConfig sets the global federation sync
	// config for a given proof type.
	UpsertFederationGlobalSyncConfig(ctx context.Context,
		arg UpsertFedGlobalSyncConfigParams) error

	// QueryFederationGlobalSyncConfigs returns all global federation sync
	// configurations.
	QueryFederationGlobalSyncConfigs(
		ctx context.Context) ([]FedGlobalSyncConfig, error)

	// UpsertFederationUniSyncConfig inserts or updates a universe specific
	// federation sync config.
	UpsertFederationUniSyncConfig(ctx context.Context,
		arg UpsertFedUniSyncConfigParams) error

	// QueryFederationUniSyncConfigs returns the set of universe specific
	// federation sync configs.
	QueryFederationUniSyncConfigs(ctx context.Context) ([]FedUniSyncConfigs,
		error)
}

// UniverseServerStore is used to manage the set of Universe servers as part
// of a federation.
type UniverseServerStore interface {
	FederationSyncConfigStore
	FederationProofSyncLogStore

	// InsertUniverseServer inserts a new universe server in to the DB.
	InsertUniverseServer(ctx context.Context, arg NewUniverseServer) error

	// DeleteUniverseServer removes a universe server from the store.
	DeleteUniverseServer(ctx context.Context, r DelUniverseServer) error

	// LogServerSync marks that a server was just synced in the DB.
	LogServerSync(ctx context.Context, arg sqlc.LogServerSyncParams) error

	// QueryUniverseServers returns a set of universe servers.
	QueryUniverseServers(ctx context.Context,
		arg sqlc.QueryUniverseServersParams) ([]sqlc.UniverseServer,
		error)
}

// UniverseFederationOptions is the database tx object for the universe server store.
type UniverseFederationOptions struct {
	readOnly bool
}

// ReadOnly returns a new read only server.
func (b *UniverseFederationOptions) ReadOnly() bool {
	return b.readOnly
}

// NewUniverseFederationReadTx returns a new read tx for the federation.
func NewUniverseFederationReadTx() UniverseFederationOptions {
	return UniverseFederationOptions{
		readOnly: true,
	}
}

// BatchedUniverseServerStore allows for batched DB transactions for the
// universe server store.
type BatchedUniverseServerStore interface {
	UniverseServerStore

	BatchedTx[UniverseServerStore]
}

// assetSyncCfgs is a map of asset ID to universe specific sync config.
type assetSyncCfgs = lnutils.SyncMap[treeID, *universe.FedUniSyncConfig]

// globalSyncCfgs is a map of proof type to global sync config.
type globalSyncCfgs = lnutils.SyncMap[
	universe.ProofType, *universe.FedGlobalSyncConfig,
]

// UniverseFederationDB is used to manage the set of universe servers by
// sub-systems that need to manage syncing and pushing new proofs amongst the
// federation set.
type UniverseFederationDB struct {
	db BatchedUniverseServerStore

	clock clock.Clock

	globalCfg *atomic.Pointer[globalSyncCfgs]
	assetCfgs *atomic.Pointer[assetSyncCfgs]
}

// NewUniverseFederationDB makes a new Universe federation DB.
func NewUniverseFederationDB(db BatchedUniverseServerStore,
	clock clock.Clock) *UniverseFederationDB {

	var (
		globalCfgPtr atomic.Pointer[globalSyncCfgs]
		assetCfgsPtr atomic.Pointer[assetSyncCfgs]
	)

	globalCfgPtr.Store(&globalSyncCfgs{})
	assetCfgsPtr.Store(&assetSyncCfgs{})

	return &UniverseFederationDB{
		db:        db,
		clock:     clock,
		globalCfg: &globalCfgPtr,
		assetCfgs: &assetCfgsPtr,
	}
}

// UniverseServers returns the set of servers in the federation.
func (u *UniverseFederationDB) UniverseServers(
	ctx context.Context) ([]universe.ServerAddr, error) {

	var uniServers []universe.ServerAddr

	readTx := NewUniverseFederationReadTx()
	dbErr := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		servers, err := db.QueryUniverseServers(
			ctx, QueryUniServersParams{},
		)
		if err != nil {
			return err
		}

		uniServers = fn.Map(servers,
			func(s sqlc.UniverseServer) universe.ServerAddr {
				return universe.NewServerAddr(
					s.ID, s.ServerHost,
				)
			},
		)

		return nil
	})

	return uniServers, dbErr
}

// AddServers adds a slice of servers to the federation.
func (u *UniverseFederationDB) AddServers(ctx context.Context,
	addrs ...universe.ServerAddr) error {

	var writeTx UniverseFederationOptions
	err := u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		return fn.ForEachErr(addrs, func(a universe.ServerAddr) error {
			addr := NewUniverseServer{
				ServerHost:   a.HostStr(),
				LastSyncTime: time.Now(),
			}
			return db.InsertUniverseServer(ctx, addr)
		})
	})
	if err != nil {
		// Add context to unique constraint errors.
		var uniqueConstraintErr *ErrSqlUniqueConstraintViolation
		if errors.As(err, &uniqueConstraintErr) {
			return universe.ErrDuplicateUniverse
		}

		return err
	}

	return nil
}

// RemoveServers removes a set of servers from the federation.
func (u *UniverseFederationDB) RemoveServers(ctx context.Context,
	addrs ...universe.ServerAddr) error {

	var writeTx UniverseFederationOptions
	return u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		return fn.ForEachErr(addrs, func(a universe.ServerAddr) error {
			// If the host string is set, then we'll make the
			// target ID -1 so we can target _only_ based on the
			// host string instead. This avoids bugs where a user
			// doesn't set the ID value, and we try to delete the
			// very first server.
			uniID := a.ID
			if a.HostStr() != "" {
				uniID = -1
			}

			return db.DeleteUniverseServer(ctx, DelUniverseServer{
				TargetID:     uniID,
				TargetServer: a.HostStr(),
			})
		})
	})
}

// LogNewSyncs logs a new sync event for each server. This can be used to keep
// track of the last time we synced with a remote server.
func (u *UniverseFederationDB) LogNewSyncs(ctx context.Context,
	addrs ...universe.ServerAddr) error {

	var writeTx UniverseFederationOptions
	return u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		return fn.ForEachErr(addrs, func(a universe.ServerAddr) error {
			return db.LogServerSync(ctx, sqlc.LogServerSyncParams{
				NewSyncTime:  u.clock.Now().UTC(),
				TargetServer: a.HostStr(),
			})
		})
	})
}

// UpsertFederationProofSyncLog upserts a federation proof sync log entry for a
// given universe server and proof.
func (u *UniverseFederationDB) UpsertFederationProofSyncLog(
	ctx context.Context, uniID universe.Identifier,
	leafKey universe.LeafKey, addr universe.ServerAddr,
	syncDirection universe.SyncDirection,
	syncStatus universe.ProofSyncStatus,
	bumpSyncAttemptCounter bool) (int64, error) {

	// Encode the leaf key outpoint as bytes. We'll use this to look up the
	// leaf ID in the DB.
	leafKeyOutpointBytes, err := encodeOutpoint(leafKey.OutPoint)
	if err != nil {
		return 0, err
	}

	// Encode the leaf script key pub key as bytes. We'll use this to look
	// up the leaf ID in the DB.
	scriptKeyPubKeyBytes := schnorr.SerializePubKey(
		leafKey.ScriptKey.PubKey,
	)

	var (
		writeTx UniverseFederationOptions
		logID   int64
	)

	err = u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		params := UpsertFedProofSyncLogParams{
			Status:                 string(syncStatus),
			Timestamp:              time.Now().UTC(),
			SyncDirection:          string(syncDirection),
			UniverseIDNamespace:    uniID.String(),
			LeafNamespace:          uniID.String(),
			LeafMintingPointBytes:  leafKeyOutpointBytes,
			LeafScriptKeyBytes:     scriptKeyPubKeyBytes,
			ServerHost:             addr.HostStr(),
			BumpSyncAttemptCounter: bumpSyncAttemptCounter,
		}
		logID, err = db.UpsertFederationProofSyncLog(ctx, params)
		if err != nil {
			return err
		}

		return nil
	})

	return logID, err
}

// QueryFederationProofSyncLog queries the federation proof sync log and returns
// the log entries which correspond to the given universe proof leaf.
func (u *UniverseFederationDB) QueryFederationProofSyncLog(
	ctx context.Context, uniID universe.Identifier,
	leafKey universe.LeafKey,
	syncDirection universe.SyncDirection,
	syncStatus universe.ProofSyncStatus) ([]*universe.ProofSyncLogEntry,
	error) {

	// Encode the leaf key outpoint as bytes. We'll use this to look up the
	// leaf ID in the DB.
	leafKeyOutpointBytes, err := encodeOutpoint(leafKey.OutPoint)
	if err != nil {
		return nil, err
	}

	// Encode the leaf script key pub key as bytes. We'll use this to look
	// up the leaf ID in the DB.
	scriptKeyPubKeyBytes := schnorr.SerializePubKey(
		leafKey.ScriptKey.PubKey,
	)

	var (
		readTx        = NewUniverseFederationReadTx()
		proofSyncLogs []*universe.ProofSyncLogEntry
	)

	err = u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		params := QueryFedProofSyncLogParams{
			SyncDirection:         sqlStr(string(syncDirection)),
			Status:                sqlStr(string(syncStatus)),
			LeafNamespace:         sqlStr(uniID.String()),
			LeafMintingPointBytes: leafKeyOutpointBytes,
			LeafScriptKeyBytes:    scriptKeyPubKeyBytes,
		}
		logEntries, err := db.QueryFederationProofSyncLog(ctx, params)

		// Parse database proof sync logs. Multiple log entries may
		// exist for a given leaf because each log entry is unique to a
		// server.
		proofSyncLogs = make(
			[]*universe.ProofSyncLogEntry, 0, len(logEntries),
		)
		for idx := range logEntries {
			entry := logEntries[idx]

			parsedLogEntry, err := fetchProofSyncLogEntry(
				ctx, entry, db,
			)
			if err != nil {
				return err
			}

			proofSyncLogs = append(proofSyncLogs, parsedLogEntry)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	return proofSyncLogs, nil
}

// FetchPendingProofsSyncLog queries the federation proof sync log and returns
// all log entries with sync status pending.
func (u *UniverseFederationDB) FetchPendingProofsSyncLog(ctx context.Context,
	syncDirection *universe.SyncDirection) ([]*universe.ProofSyncLogEntry,
	error) {

	var (
		readTx        = NewUniverseFederationReadTx()
		proofSyncLogs []*universe.ProofSyncLogEntry
	)

	err := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		// If the sync direction is not set, then we'll query for all
		// pending proof sync log entries.
		var sqlSyncDirection sql.NullString
		if syncDirection != nil {
			sqlSyncDirection = sqlStr(string(*syncDirection))
		}

		sqlProofSyncStatus := sqlStr(
			string(universe.ProofSyncStatusPending),
		)

		params := QueryFedProofSyncLogParams{
			SyncDirection: sqlSyncDirection,
			Status:        sqlProofSyncStatus,
		}
		logEntries, err := db.QueryFederationProofSyncLog(ctx, params)
		if err != nil {
			return fmt.Errorf("unable to query proof sync log: %w",
				err)
		}

		// Parse log entries from database row.
		proofSyncLogs = make(
			[]*universe.ProofSyncLogEntry, 0, len(logEntries),
		)
		for idx := range logEntries {
			entry := logEntries[idx]

			parsedLogEntry, err := fetchProofSyncLogEntry(
				ctx, entry, db,
			)
			if err != nil {
				return err
			}

			proofSyncLogs = append(proofSyncLogs, parsedLogEntry)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return proofSyncLogs, nil
}

// fetchProofSyncLogEntry returns a proof sync log entry given a DB row.
func fetchProofSyncLogEntry(ctx context.Context, entry ProofSyncLogEntry,
	dbTx UniverseServerStore) (*universe.ProofSyncLogEntry, error) {

	// Fetch asset genesis for the leaf.
	leafAssetGen, err := fetchGenesis(ctx, dbTx, entry.LeafGenAssetID)
	if err != nil {
		return nil, err
	}

	// We only need to obtain the asset at this point, so we'll do a sparse
	// decode here to decode only the asset record.
	var leafAsset asset.Asset
	assetRecord := proof.AssetLeafRecord(&leafAsset)
	err = proof.SparseDecode(
		bytes.NewReader(entry.LeafGenesisProof), assetRecord,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof: %w", err)
	}

	leaf := &universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  leafAssetGen,
			GroupKey: leafAsset.GroupKey,
		},
		RawProof: entry.LeafGenesisProof,
		Asset:    &leafAsset,
		Amt:      leafAsset.Amount,
	}

	// Parse leaf key from leaf DB row.
	scriptKeyPub, err := schnorr.ParsePubKey(
		entry.LeafScriptKeyBytes,
	)
	if err != nil {
		return nil, err
	}
	scriptKey := asset.NewScriptKey(scriptKeyPub)

	var outPoint wire.OutPoint
	err = readOutPoint(
		bytes.NewReader(entry.LeafMintingPointBytes), 0, 0,
		&outPoint,
	)
	if err != nil {
		return nil, err
	}

	leafKey := universe.LeafKey{
		OutPoint:  outPoint,
		ScriptKey: &scriptKey,
	}

	// Parse server address from DB row.
	serverAddr := universe.NewServerAddr(entry.ServerID, entry.ServerHost)

	// Parse proof sync status directly from the DB row.
	status, err := universe.ParseStrProofSyncStatus(entry.Status)
	if err != nil {
		return nil, err
	}

	// Parse proof sync direction directly from the DB row.
	direction, err := universe.ParseStrSyncDirection(entry.SyncDirection)
	if err != nil {
		return nil, err
	}

	uniID, err := universe.NewUniIDFromRawArgs(
		entry.UniAssetID, entry.UniGroupKey,
		entry.UniProofType,
	)
	if err != nil {
		return nil, err
	}

	return &universe.ProofSyncLogEntry{
		Timestamp:      entry.Timestamp,
		SyncStatus:     status,
		SyncDirection:  direction,
		AttemptCounter: entry.AttemptCounter,
		ServerAddr:     serverAddr,

		UniID:   uniID,
		LeafKey: leafKey,
		Leaf:    *leaf,
	}, nil
}

// DeleteProofsSyncLogEntries deletes a set of proof sync log entries.
func (u *UniverseFederationDB) DeleteProofsSyncLogEntries(ctx context.Context,
	servers ...universe.ServerAddr) error {

	var writeTx UniverseFederationOptions

	err := u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		// Delete proof sync log entries which are associated with each
		// server.
		for i := range servers {
			server := servers[i]

			err := db.DeleteFederationProofSyncLog(
				ctx, DeleteFedProofSyncLogParams{
					ServerHost: sqlStr(server.HostStr()),
				},
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// UpsertFederationSyncConfig upserts both the global and universe specific
// federation sync configs.
func (u *UniverseFederationDB) UpsertFederationSyncConfig(
	ctx context.Context, globalSyncConfigs []*universe.FedGlobalSyncConfig,
	uniSyncConfigs []*universe.FedUniSyncConfig) error {

	var writeTx UniverseFederationOptions
	dbErr := u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		// Upsert global proof type specific federation sync
		// configs.
		for i := range globalSyncConfigs {
			config := globalSyncConfigs[i]

			params := UpsertFedGlobalSyncConfigParams{
				ProofType:       config.ProofType.String(),
				AllowSyncInsert: config.AllowSyncInsert,
				AllowSyncExport: config.AllowSyncExport,
			}
			err := db.UpsertFederationGlobalSyncConfig(ctx, params)
			if err != nil {
				return err
			}
		}

		// Upsert universe specific sync configs.
		for _, config := range uniSyncConfigs {
			var (
				uniID        = config.UniverseID
				groupPubKey  []byte
				assetIDBytes []byte
			)

			// If the group key is set, then we'll serialize it
			// into bytes.
			if uniID.GroupKey != nil {
				groupPubKey = uniID.GroupKey.SerializeCompressed()
			} else {
				// If the group key is not set, then we'll use
				// the asset ID. The group key supersedes the
				// asset ID.
				assetIDBytes = uniID.AssetID[:]
			}

			err := db.UpsertFederationUniSyncConfig(
				ctx, UpsertFedUniSyncConfigParams{
					Namespace:       uniID.String(),
					AssetID:         assetIDBytes,
					GroupKey:        groupPubKey,
					ProofType:       uniID.ProofType.String(),
					AllowSyncInsert: config.AllowSyncInsert,
					AllowSyncExport: config.AllowSyncExport,
				},
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if dbErr != nil {
		return dbErr
	}

	// We just updated the config, so wipe our cached versions.
	u.globalCfg.Store(&globalSyncCfgs{})
	u.assetCfgs.Store(&assetSyncCfgs{})

	return nil
}

// QueryFederationSyncConfigs returns the global and universe specific
// federation sync configs.
func (u *UniverseFederationDB) QueryFederationSyncConfigs(
	ctx context.Context) ([]*universe.FedGlobalSyncConfig,
	[]*universe.FedUniSyncConfig, error) {

	var (
		readTx UniverseFederationOptions

		globalConfigs   []*universe.FedGlobalSyncConfig
		globalConfigSet = make(
			map[universe.ProofType]*universe.FedGlobalSyncConfig,
		)
		uniConfigs []*universe.FedUniSyncConfig
	)

	// Check to see if our cache is populated, if so, then we can just
	// return them directly.
	u.globalCfg.Load().Range(func(proofType universe.ProofType,
		cfg *universe.FedGlobalSyncConfig) bool {

		globalConfigs = append(globalConfigs, cfg)

		return true
	})
	u.assetCfgs.Load().Range(func(treeID treeID,
		cfg *universe.FedUniSyncConfig) bool {

		uniConfigs = append(uniConfigs, cfg)

		return true
	})

	if len(globalConfigs) > 0 || len(uniConfigs) > 0 {
		return globalConfigs, uniConfigs, nil
	}

	err := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		// Query for global sync configs.
		globalDbConfigs, err := db.QueryFederationGlobalSyncConfigs(
			ctx,
		)
		switch {
		case globalDbConfigs == nil:
			// If the query does not return any rows then a global
			// config for each proof type has not yet been set. We
			// will return a default config for each proof type.
			globalConfigs = defaultGlobalSyncConfigs

		case err != nil:
			return err

		default:
			// Start with the default global sync configs. This
			// ensures we don't always clobber with items in the DB
			// that may be blank.
			for _, config := range defaultGlobalSyncConfigs {
				globalConfigSet[config.ProofType] = config
			}

			// Parse global db sync configs and overwrite the
			// default configs.
			for _, config := range globalDbConfigs {
				proofType, err := universe.ParseStrProofType(
					config.ProofType,
				)
				if err != nil {
					return err
				}

				globalDbConf := &universe.FedGlobalSyncConfig{
					ProofType:       proofType,
					AllowSyncInsert: config.AllowSyncInsert,
					AllowSyncExport: config.AllowSyncExport,
				}

				//nolint:lll
				globalConfigSet[globalDbConf.ProofType] = globalDbConf
			}

			// Return config options in a stable order.
			globalConfigs = maps.Values(globalConfigSet)
			sort.Slice(globalConfigs, func(i, j int) bool {
				return globalConfigs[i].ProofType <
					globalConfigs[j].ProofType
			})
		}

		// Query for universe specific sync configs.
		uniDbConfigs, err := db.QueryFederationUniSyncConfigs(ctx)
		if err != nil {
			return err
		}

		// Parse universe specific sync configs.
		uniConfigs = make(
			[]*universe.FedUniSyncConfig, len(uniDbConfigs),
		)

		for i, config := range uniDbConfigs {
			proofType, err := universe.ParseStrProofType(
				config.ProofType,
			)
			if err != nil {
				return err
			}

			// Construct group key public key from bytes.
			var pubKey *btcec.PublicKey
			if config.GroupKey != nil {
				pubKey, err = btcec.ParsePubKey(config.GroupKey)
				if err != nil {
					return fmt.Errorf("unable to parse "+
						"group key: %w", err)
				}
			}

			// Construct asset ID from bytes.
			var assetID asset.ID
			copy(assetID[:], config.AssetID)

			uniID := universe.Identifier{
				AssetID:   assetID,
				GroupKey:  pubKey,
				ProofType: proofType,
			}

			uniConfigs[i] = &universe.FedUniSyncConfig{
				UniverseID:      uniID,
				AllowSyncInsert: config.AllowSyncInsert,
				AllowSyncExport: config.AllowSyncExport,
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Update our cache with what we've read from disk.
	globalCfgs := u.globalCfg.Load()
	for _, globalCfg := range globalConfigs {
		globalCfgs.Store(globalCfg.ProofType, globalCfg)
	}
	assetCfgs := u.assetCfgs.Load()
	for _, uniCfg := range uniConfigs {
		assetCfgs.Store(treeID(uniCfg.UniverseID.String()), uniCfg)
	}

	return globalConfigs, uniConfigs, nil
}

// Check at compile time that we implement the correct interfaces.
var (
	_ universe.FederationLog          = (*UniverseFederationDB)(nil)
	_ universe.FederationSyncConfigDB = (*UniverseFederationDB)(nil)
)
