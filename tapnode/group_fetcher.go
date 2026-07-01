package tapnode

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
)

// GroupFetcher is an interface that allows fetching of asset groups.
type GroupFetcher interface {
	// FetchGroupByGroupKey fetches the asset group with a matching
	// tweaked key, including the genesis information used to create
	// the group.
	FetchGroupByGroupKey(ctx context.Context,
		groupKey *btcec.PublicKey) (*asset.AssetGroup, error)
}
