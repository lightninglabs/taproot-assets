package tapdb

import (
	"context"
	"database/sql"
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

	// SetFedGlobalSyncConfigParams is used to set the global federation
	// sync configuration.
	SetFedGlobalSyncConfigParams = sqlc.SetFederationGlobalSyncConfigParams

	// UpsertFedUniSyncConfigParams is used to set the universe specific
	// federation sync configuration.
	UpsertFedUniSyncConfigParams = sqlc.UpsertFederationUniSyncConfigParams

	// FedUniSyncConfigs is the universe specific federation sync config
	// returned from a query.
	FedUniSyncConfigs = sqlc.FederationUniSyncConfig
)

// FederationSyncConfigStore is used to manage the set of Universe servers as part
// of a federation.
type FederationSyncConfigStore interface {
	// SetFederationGlobalSyncConfig sets the global federation sync config.
	SetFederationGlobalSyncConfig(ctx context.Context,
		arg SetFedGlobalSyncConfigParams) error

	// QueryFederationGlobalSyncConfig returns the global federation sync
	// config.
	QueryFederationGlobalSyncConfig(ctx context.Context) (string, error)

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
					uint32(s.ID), s.ServerHost,
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
			uniID := int32(a.ID)
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

// UpsertFederationSyncConfig upserts both the general and universe specific
// federation sync configs.
func (u *UniverseFederationDB) UpsertFederationSyncConfig(
	ctx context.Context, globalSyncConfig *universe.FedGlobalSyncConfig,
	uniSyncConfigs []*universe.FedUniSyncConfig) error {

	var writeTx UniverseFederationOptions
	return u.db.ExecTx(ctx, &writeTx, func(db UniverseServerStore) error {
		// Upsert general federation sync config.
		err := db.SetFederationGlobalSyncConfig(
			ctx, globalSyncConfig.ProofTypes.String(),
		)
		if err != nil {
			return err
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

			params := UpsertFedUniSyncConfigParams{
				AssetID:   assetIDBytes,
				GroupKey:  groupPubKey,
				ProofType: config.ProofTypes.String(),
			}
			err := db.UpsertFederationUniSyncConfig(ctx, params)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// QueryFederationSyncConfigs returns the general and universe specific
// federation sync configs.
func (u *UniverseFederationDB) QueryFederationSyncConfigs(
	ctx context.Context) (*universe.FedGlobalSyncConfig,
	[]*universe.FedUniSyncConfig, error) {

	var (
		readTx UniverseFederationOptions

		globalConfig *universe.FedGlobalSyncConfig
		uniConfigs   []*universe.FedUniSyncConfig
	)

	err := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		// Query for global sync config.
		proofTypesStr, err := db.QueryFederationGlobalSyncConfig(
			ctx,
		)
		if err != nil {
			return err
		}
		proofTypes, err := universe.ParseProofType(
			proofTypesStr,
		)
		if err != nil {
			return err
		}

		globalConfig = &universe.FedGlobalSyncConfig{
			ProofTypes: proofTypes,
		}

		// If no rows in result set, then we haven't set the config
		// yet, so we'll default to true.
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		// Query for universe specific sync configs.
		configsDb, err := db.QueryFederationUniSyncConfigs(ctx)
		if err != nil {
			return err
		}

		for i := range configsDb {
			conf := configsDb[i]

			proofTypes, err := universe.ParseProofType(
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
				AssetID:  assetID,
				GroupKey: pubKey,
			}

			uniConfig := universe.FedUniSyncConfig{
				UniverseID: uniID,
				ProofTypes: proofTypes,
			}
			uniConfigs = append(uniConfigs, &uniConfig)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return globalConfig, uniConfigs, nil
}

// Check at compile time that we implement the correct interfaces.
var (
	_ universe.FederationLog          = (*UniverseFederationDB)(nil)
	_ universe.FederationSyncConfigDB = (*UniverseFederationDB)(nil)
)
