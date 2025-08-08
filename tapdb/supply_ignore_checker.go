package tapdb

import (
	"context"
	"errors"
	"sync"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

var (
	// nonGroupedAsset is a zeroed out public key that is used to identify a
	// non-existent group key (for an asset that does not belong to a
	// group).
	nonGroupedAsset = asset.SerializedKey{}
)

// ignoreCheckerStore is an interface that defines the methods required to
// fetch supply leaves for the ignore checker. It abstracts away the storage
// implementation details, simplifying mocking for unit tests.
type ignoreCheckerStore interface {
	// FetchSupplyLeavesByType fetches all supply leaves for a given asset
	// specifier and a specific supply sub-tree.
	FetchSupplyLeavesByType(ctx context.Context, spec asset.Specifier,
		tree supplycommit.SupplySubTree, startHeight,
		endHeight uint32) lfn.Result[supplycommit.SupplyLeaves]
}

// assetGroupQuery is an interface that defines the method to query an asset
// group by its asset ID. This is used to determine if an asset belongs to a
// group and to fetch the group key if it does. It abstracts away the details
// of how the asset group is stored, simplifying mocking for unit tests.
type assetGroupQuery interface {
	// QueryAssetGroupByID attempts to fetch an asset group by its asset ID.
	// If the asset group cannot be found, then ErrAssetGroupUnknown is
	// returned.
	QueryAssetGroupByID(context.Context, asset.ID) (*asset.AssetGroup,
		error)
}

// IgnoreCheckerCfg is a configuration struct for the CachingIgnoreChecker.
type IgnoreCheckerCfg struct {
	// GroupQuery is used to query asset groups by their asset ID.
	GroupQuery assetGroupQuery

	// Store is used to fetch supply leaves for the ignore checker.
	Store ignoreCheckerStore
}

// CachingIgnoreChecker is a proof.IgnoreChecker that caches the results of
// whether an asset is ignored or not. It uses a map to store the group keys
// for asset IDs, and another map to store the best known height for each group
// key. It also maintains a map of ignored assets, which is populated on demand
// when checking if an asset is ignored.
// Assuming ~200k known assets and 1000 groups and 50k ignored asset points, the
// memory requirement for these three maps is approximately:
// - groupKeyLookup:     200k * (32+33) bytes   = ~12.4 MiB
// - bestHeightLookup:   1000 * 33 bytes        = 33 kiB
// - ignoredAssetPoints: 50k * (36+32+33) bytes = ~4.81 MiB
type CachingIgnoreChecker struct {
	cfg IgnoreCheckerCfg

	// Mutex is a mutex to protect concurrent access to the groupKeyLookup,
	// bestHeightLookup, and ignoredAssetPoints maps.
	sync.Mutex

	// groupKeyLookup is a map that stores the group key for each asset ID.
	// If an asset does not belong to a group, it is stored with a zeroed
	// out public key (nonGroupedAsset).
	groupKeyLookup map[asset.ID]asset.SerializedKey

	// bestHeightLookup is a map that stores the best known height for each
	// group key. This is used to speed up the lookup of ignored assets by
	// only fetching the latest ignore tuples for the group if we haven't
	// encountered the group key before or if the best height has changed.
	bestHeightLookup map[asset.SerializedKey]uint32

	// ignoredAssetPoints is a set that stores the asset points that are
	// known to be ignored. This is populated on demand when checking if an
	// asset is ignored. The set uses the asset point as the key, which
	// includes the outpoint, asset ID, and script key.
	ignoredAssetPoints fn.Set[proof.AssetPoint]
}

// NewCachingIgnoreChecker creates a new instance of CachingIgnoreChecker
// with the provided configuration.
func NewCachingIgnoreChecker(cfg IgnoreCheckerCfg) *CachingIgnoreChecker {
	return &CachingIgnoreChecker{
		cfg:                cfg,
		groupKeyLookup:     make(map[asset.ID]asset.SerializedKey),
		bestHeightLookup:   make(map[asset.SerializedKey]uint32),
		ignoredAssetPoints: make(fn.Set[proof.AssetPoint]),
	}
}

// A compile-time assertion to ensure CachingIgnoreChecker implements
// the IgnoreChecker interface.
var _ proof.IgnoreChecker = (*CachingIgnoreChecker)(nil)

// IsIgnored returns true if the given prevID is known to be invalid. A prevID
// is used here, but the check should be tested against a proof result, or
// produced output.
func (c *CachingIgnoreChecker) IsIgnored(ctx context.Context,
	prevID proof.AssetPoint) lfn.Result[bool] {

	c.Lock()
	defer c.Unlock()

	log.Tracef("Checking if asset point %s is ignored", prevID)

	// Let's do a direct lookup first to see if we already know the asset is
	// ignored.
	if c.ignoredAssetPoints.Contains(prevID) {
		log.Tracef("Asset point %s is already known to be ignored",
			prevID)
		return lfn.Ok(true)
	}

	// If it's not known to be ignored, we need to look up the group key for
	// the asset ID associated with the previous ID. This will help us to
	// decide whether it's a non-grouped asset (which is never ignored) or
	// to fetch the latest ignore tuples for the asset group.
	groupKey, groupKeyKnown := c.groupKeyLookup[prevID.ID]
	if !groupKeyKnown {
		log.Tracef("Asset point %s is not known, querying group "+
			"key for asset ID %s", prevID, prevID.ID)

		group, err := c.cfg.GroupQuery.QueryAssetGroupByID(
			ctx, prevID.ID,
		)
		switch {
		// We found the group, and it has a valid group key, we can add
		// it to our lookup map.
		case err == nil && group.GroupKey != nil:
			groupKey = asset.ToSerialized(
				&group.GroupKey.GroupPubKey,
			)
			c.groupKeyLookup[prevID.ID] = groupKey

			log.Tracef("Found group key %s for asset ID %s",
				groupKey, prevID.ID)

		// If the asset is not a grouped asset, we mark it as such in
		// our lookup map.
		case err == nil && group.GroupKey == nil:
			groupKey = nonGroupedAsset
			c.groupKeyLookup[prevID.ID] = groupKey

			log.Tracef("Asset ID %s is not grouped, using "+
				"non-grouped asset key", prevID.ID)

		case err != nil:
			// If something went wrong while querying the asset
			// group, we return an error.
			if !errors.Is(err, address.ErrAssetGroupUnknown) {
				return lfn.Errf[bool]("unable to query asset "+
					"group: %w", err)
			}

			// If we get here, it means we are not aware of this
			// asset group, so we can assume it is not ignored.
			return lfn.Ok(false)
		}
	}

	// We now have the group key, so we can check if the asset is a
	// non-grouped asset, which means it is not ignored (as that
	// functionality is only supported for grouped assets).
	if groupKey == nonGroupedAsset {
		log.Tracef("Asset point %s is a non-grouped asset, ignore "+
			"functionality not available", prevID)
		return lfn.Ok(false)
	}

	groupPubKey, err := groupKey.ToPubKey()
	if err != nil {
		return lfn.Errf[bool]("unable to decode group key: %w", err)
	}

	// If we have a valid group key, we can fetch the latest ignore
	// tuples for the asset group based on the best known height for the
	// group (or 0 if we haven't encountered this group yet).
	specifier := asset.NewSpecifierFromGroupKey(*groupPubKey)
	bestHeight := c.bestHeightLookup[groupKey]
	leaves, err := c.cfg.Store.FetchSupplyLeavesByType(
		ctx, specifier, supplycommit.IgnoreTreeType, bestHeight, 0,
	).Unpack()
	if err != nil {
		return lfn.Errf[bool]("unable to fetch supply leaves: %w", err)
	}

	// We now add all the leaves to our ignored assets map.
	log.Debugf("Fetched %d ignore leaves for group key %s",
		len(leaves.IgnoreLeafEntries), groupKey)
	for _, leaf := range leaves.IgnoreLeafEntries {
		point := proof.AssetPoint{
			OutPoint:  leaf.IgnoreTuple.Val.OutPoint,
			ID:        leaf.IgnoreTuple.Val.ID,
			ScriptKey: leaf.IgnoreTuple.Val.ScriptKey,
		}

		if !c.ignoredAssetPoints.Contains(point) {
			log.Tracef("Adding new asset point to ignore set %s",
				point)
			c.ignoredAssetPoints.Add(point)
		}

		if leaf.BlockHeight() > bestHeight {
			bestHeight = leaf.BlockHeight()
		}
	}

	// We update the best height for this group key in our lookup map, so
	// that we can use it for future queries to speed them up.
	c.bestHeightLookup[groupKey] = bestHeight

	// And now we can check if the previous ID is in our ignored assets set.
	return lfn.Ok(c.ignoredAssetPoints.Contains(prevID))
}
