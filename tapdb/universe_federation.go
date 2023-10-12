package tapdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
)

type (
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
)

var (
	// defaultGlobalSyncConfigs is the default set of global federation
	// sync configs that will be used if no global configs have been set.
	defaultGlobalSyncConfigs = []*universe.FedGlobalSyncConfig{
		{
			ProofType:       universe.ProofTypeIssuance,
			AllowSyncInsert: true,
			AllowSyncExport: true,
		},
		{
			ProofType:       universe.ProofTypeTransfer,
			AllowSyncInsert: false,
			AllowSyncExport: true,
		},
	}
)

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

	// InsertUniverseServer inserts a new universe server in to the DB.
	InsertUniverseServer(ctx context.Context, arg NewUniverseServer) error

	// DeleteUniverseServer removes a universe server from the store.
	DeleteUniverseServer(ctx context.Context, r DelUniverseServer) error

	// LogServerSync marks that a server was just synced in the DB.
	LogServerSync(ctx context.Context, arg sqlc.LogServerSyncParams) error

	// ListUniverseServers returns the total set of all universe servers.
	ListUniverseServers(ctx context.Context) ([]sqlc.UniverseServer, error)
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

// UniverseFederationDB is used to manage the set of universe servers by
// sub-systems that need to manage syncing and pushing new proofs amongst the
// federation set.
type UniverseFederationDB struct {
	db BatchedUniverseServerStore

	clock clock.Clock
}

// NewUniverseFederationDB makes a new Universe federation DB.
func NewUniverseFederationDB(db BatchedUniverseServerStore,
	clock clock.Clock) *UniverseFederationDB {

	return &UniverseFederationDB{
		db:    db,
		clock: clock,
	}
}

// UniverseServers returns the set of servers in the federation.
func (u *UniverseFederationDB) UniverseServers(
	ctx context.Context) ([]universe.ServerAddr, error) {

	var uniServers []universe.ServerAddr

	readTx := NewUniverseFederationReadTx()
	dbErr := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		servers, err := db.ListUniverseServers(ctx)
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
			uniID := int64(a.ID)
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

// UpsertFederationSyncConfig upserts both the global and universe specific
// federation sync configs.
func (u *UniverseFederationDB) UpsertFederationSyncConfig(
	ctx context.Context, globalSyncConfigs []*universe.FedGlobalSyncConfig,
	uniSyncConfigs []*universe.FedUniSyncConfig) error {

	var writeTx UniverseFederationOptions
	return u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
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
		for i := range uniSyncConfigs {
			var (
				config = uniSyncConfigs[i]

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
}

// QueryFederationSyncConfigs returns the global and universe specific
// federation sync configs.
func (u *UniverseFederationDB) QueryFederationSyncConfigs(
	ctx context.Context) ([]*universe.FedGlobalSyncConfig,
	[]*universe.FedUniSyncConfig, error) {

	var (
		readTx UniverseFederationOptions

		globalConfigs []*universe.FedGlobalSyncConfig
		uniConfigs    []*universe.FedUniSyncConfig
	)

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
			// Parse global db sync configs.
			globalConfigs = make(
				[]*universe.FedGlobalSyncConfig,
				len(globalDbConfigs),
			)
			for i := range globalDbConfigs {
				config := globalDbConfigs[i]

				proofType, err := universe.ParseStrProofType(
					config.ProofType,
				)
				if err != nil {
					return err
				}

				globalConfigs[i] = &universe.FedGlobalSyncConfig{
					ProofType:       proofType,
					AllowSyncInsert: config.AllowSyncInsert,
					AllowSyncExport: config.AllowSyncExport,
				}
			}
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

		for i := range uniDbConfigs {
			conf := uniDbConfigs[i]

			proofType, err := universe.ParseStrProofType(
				conf.ProofType,
			)
			if err != nil {
				return err
			}

			// Construct group key public key from bytes.
			var pubKey *btcec.PublicKey
			if conf.GroupKey != nil {
				pubKey, err = btcec.ParsePubKey(conf.GroupKey)
				if err != nil {
					return fmt.Errorf("unable to parse "+
						"group key: %v", err)
				}
			}

			// Construct asset ID from bytes.
			var assetID asset.ID
			copy(assetID[:], conf.AssetID)

			uniID := universe.Identifier{
				AssetID:   assetID,
				GroupKey:  pubKey,
				ProofType: proofType,
			}

			uniConfigs[i] = &universe.FedUniSyncConfig{
				UniverseID:      uniID,
				AllowSyncInsert: conf.AllowSyncInsert,
				AllowSyncExport: conf.AllowSyncExport,
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return globalConfigs, uniConfigs, nil
}

// Check at compile time that we implement the correct interfaces.
var (
	_ universe.FederationLog          = (*UniverseFederationDB)(nil)
	_ universe.FederationSyncConfigDB = (*UniverseFederationDB)(nil)
)
