package addressbook

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
)

// Storage is the main storage interface for the address book.
type Storage interface {
	EventStorage

	// InsertAddrs inserts a series of addresses into the database.
	InsertAddrs(ctx context.Context, addrs ...address.AddrWithKeyInfo) error

	// QueryAddrs attempts to query for a set of addresses.
	QueryAddrs(ctx context.Context,
		params address.QueryParams) ([]address.AddrWithKeyInfo, error)

	// QueryAssetGroup attempts to locate the asset group information
	// (genesis + group key) associated with a given asset.
	QueryAssetGroup(context.Context, asset.ID) (*asset.AssetGroup, error)

	// FetchAssetMetaByHash attempts to fetch an asset meta based on an
	// asset hash.
	FetchAssetMetaByHash(ctx context.Context,
		metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error)

	// FetchAssetMetaForAsset attempts to fetch an asset meta based on an
	// asset ID.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID asset.ID) (*proof.MetaReveal, error)

	// AddrByTaprootOutput returns a single address based on its Taproot
	// output key or a sql.ErrNoRows error if no such address exists.
	AddrByTaprootOutput(ctx context.Context,
		key *btcec.PublicKey) (*address.AddrWithKeyInfo, error)

	// SetAddrManaged sets an address as being managed by the internal
	// wallet.
	SetAddrManaged(ctx context.Context, addr *address.AddrWithKeyInfo,
		managedFrom time.Time) error

	// InsertInternalKey inserts an internal key into the database to make
	// sure it is identified as a local key later on when importing proofs.
	// The key can be an internal key for an asset script key or the
	// internal key of an anchor output.
	InsertInternalKey(ctx context.Context,
		keyDesc keychain.KeyDescriptor) error

	// InsertScriptKey inserts an address related script key into the
	// database, so it can be recognized as belonging to the wallet when a
	// transfer comes in later on.
	InsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
		keyType asset.ScriptKeyType) error
}

// EventStorage is the interface that a component storing address events should
// implement.
type EventStorage interface {
	// GetOrCreateEvent creates a new address event for the given status,
	// address and transaction. If an event for that address and transaction
	// already exists, then the status and transaction information is
	// updated instead.
	GetOrCreateEvent(ctx context.Context, status address.Status,
		addr *address.AddrWithKeyInfo, walletTx *lndclient.Transaction,
		outputIdx uint32) (*address.Event, error)

	// QueryAddrEvents returns a list of event that match the given query
	// parameters.
	QueryAddrEvents(ctx context.Context,
		params address.EventQueryParams) ([]*address.Event, error)

	// QueryEvent returns a single address event by its address and
	// outpoint.
	QueryEvent(ctx context.Context, addr *address.AddrWithKeyInfo,
		outpoint wire.OutPoint) (*address.Event, error)

	// CompleteEvent updates an address event as being complete and links it
	// with the proof and asset that was imported/created for it.
	CompleteEvent(ctx context.Context, event *address.Event,
		status address.Status, anchorPoint wire.OutPoint) error
}
