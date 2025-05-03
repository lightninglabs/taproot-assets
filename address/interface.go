package address

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrAssetGroupUnknown is returned when the asset genesis is not known.
	// This means an address can't be created until a Universe bootstrap or
	// manual issuance proof insertion.
	ErrAssetGroupUnknown = fmt.Errorf("asset group is unknown")

	// ErrAssetMetaNotFound is returned when an asset meta is not found in
	// the database.
	ErrAssetMetaNotFound = fmt.Errorf("asset meta not found")
)

// AddrWithKeyInfo wraps a normal Taproot Asset struct with key descriptor
// information.
type AddrWithKeyInfo struct {
	*Tap

	// ScriptKeyTweak houses the wallet specific information related to a
	// tweak key. This includes the raw key desc information along with the
	// tweak used to create the address.
	ScriptKeyTweak asset.TweakedScriptKey

	// InternalKeyDesc is the key desc for the internal key.
	InternalKeyDesc keychain.KeyDescriptor

	// TaprootOutputKey is the tweaked taproot output key that assets must
	// be sent to on chain to be received.
	TaprootOutputKey btcec.PublicKey

	// CreationTime is the time the address was created in the database.
	CreationTime time.Time

	// ManagedAfter is the time at which the address was imported into the
	// wallet.
	ManagedAfter time.Time
}

// QueryParams holds the set of query params for the address book.
type QueryParams struct {
	// CreatedAfter if set, only addresses created after the time will be
	// returned.
	CreatedAfter time.Time

	// CreatedBefore is set, only the addresses created before the time
	// will be returned.
	CreatedBefore time.Time

	// Limit if set, only this many addresses will be returned.
	Limit int32

	// Offset if set, then the final result will be offset by this many
	// addresses.
	Offset int32

	// UnmanagedOnly is a boolean pointer indicating whether only addresses
	// should be returned that are not yet managed by the wallet.
	UnmanagedOnly bool
}

// AssetSyncer is an interface that allows the address.Book to look up asset
// genesis and group information from both the local asset store and assets
// known to universe servers in our federation.
type AssetSyncer interface {
	// SyncAssetInfo queries the universes in our federation for genesis
	// and asset group information about the given asset ID.
	SyncAssetInfo(ctx context.Context, assetID *asset.ID) error

	// EnableAssetSync updates the sync config for the given asset so that
	// we sync future issuance proofs.
	EnableAssetSync(ctx context.Context, groupInfo *asset.AssetGroup) error
}

// KeyRing is used to create script and internal keys for Taproot Asset
// addresses.
type KeyRing interface {
	// DeriveNextTaprootAssetKey attempts to derive the *next* key within
	// the TaprootAsset key family.
	DeriveNextTaprootAssetKey(context.Context) (keychain.KeyDescriptor,
		error)

	// DeriveNextKey attempts to derive the *next* key within the key
	// family (account in BIP43) specified. This method should return the
	// next external child within this branch.
	DeriveNextKey(context.Context,
		keychain.KeyFamily) (keychain.KeyDescriptor, error)

	// IsLocalKey returns true if the key is under the control of the wallet
	// and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}
