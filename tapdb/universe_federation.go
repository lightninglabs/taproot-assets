package tapdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/chanutils"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
)

type (
	// NewUniverseServer is used to create a new universe server.
	NewUniverseServer = sqlc.InsertUniverseServerParams

	// DelUniverseServer is used to delete a universe server.
	DelUniverseServer = sqlc.DeleteUniverseServerParams
)

// UniverseServerStore is used to managed the set of Universe servers as part
// of a federation.
type UniverseServerStore interface {
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
}

// NewUniverseFederationDB makes a new Universe federation DB.
func NewUniverseFederationDB(db BatchedUniverseServerStore,
) *UniverseFederationDB {

	return &UniverseFederationDB{
		db: db,
	}
}

// UniverseServers returns the set of servers in the federation.
func (u *UniverseFederationDB) UniverseServers(ctx context.Context,
) ([]universe.ServerAddr, error) {

	var uniServers []universe.ServerAddr

	readTx := NewUniverseFederationReadTx()
	dbErr := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		servers, err := db.ListUniverseServers(ctx)
		if err != nil {
			return err
		}

		uniServers = chanutils.Map(servers,
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
		return chanutils.ForEachErr(addrs,
			func(a universe.ServerAddr) error {
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
			return fmt.Errorf("universe name is already added: %w",
				err)
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
		return chanutils.ForEachErr(addrs, func(a universe.ServerAddr) error {
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
		return chanutils.ForEachErr(addrs, func(a universe.ServerAddr) error {
			return db.LogServerSync(ctx, sqlc.LogServerSyncParams{
				NewSyncTime:  time.Now(),
				TargetServer: a.HostStr(),
			})
		})
	})
}

var _ universe.FederationLog = (*UniverseFederationDB)(nil)
