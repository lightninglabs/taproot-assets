package tapdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

const (
	// DefaultNegativeLookupCacheSize is the default size of the supply
	// ignore checker's negative lookup LRU cache.
	DefaultNegativeLookupCacheSize = 10_000
)

var (
	// nonGroupedAsset is a zeroed out public key that is used to identify a
	// non-existent group key (for an asset that does not belong to a
	// group).
	nonGroupedAsset = asset.SerializedKey{}
)

// emptyCacheEntry is a type that implements the lru.CacheEntry interface
// with a size of 1 but doesn't store any data for the entry. This is useful for
// LRU caches that only need to track a certain number of keys, but not their
// values.
type emptyCacheEntry struct{}

// Size just returns 1 as we're limiting based on the total number different
// keys in the cache, not the size of the values.
func (c *emptyCacheEntry) Size() (uint64, error) {
	return 1, nil
}

// nonIgnoredCache is a type that implements a simple LRU cache for
// proof.AssetPoint keys, which are used to track asset points that are known
// to not be ignored. This cache is used to speed up the lookup of asset points
// that are not ignored, so we don't need to query the database again for the
// same asset point in the near future. The cache is evicted whenever there is a
// possibility that the list of ignored asset points changes, such as when a new
// ignore tuple is added to the asset group.
type nonIgnoredCache struct {
	cache *lru.Cache[proof.AssetPoint, *emptyCacheEntry]

	*cacheLogger
}

// HasEntry checks if the given asset point is in the list of non-ignored
// asset points.
func (c *nonIgnoredCache) HasEntry(key proof.AssetPoint) bool {
	val, notFoundErr := c.cache.Get(key)
	if notFoundErr == nil && val != nil {
		c.Hit()

		log.Tracef("Asset point %s is known to currently not be "+
			"ignored", key)

		return true
	}

	log.Tracef("Asset point %s is not in non-ignore cache", key)
	c.Miss()

	return false
}

// AddEntry adds a new asset point to the non-ignored cache.
func (c *nonIgnoredCache) AddEntry(key proof.AssetPoint) error {
	if _, err := c.cache.Put(key, &emptyCacheEntry{}); err != nil {
		return fmt.Errorf("failed to add asset point %s to negative "+
			"lookup cache: %v", key, err)
	}

	return nil
}

// newAssetPointCache creates a new LRU cache for proof.AssetPoint keys (without
// values).
func newNonIgnoredCache(cacheSize uint64) *nonIgnoredCache {
	if cacheSize == 0 {
		cacheSize = DefaultNegativeLookupCacheSize
	}

	return &nonIgnoredCache{
		cache: lru.NewCache[proof.AssetPoint, *emptyCacheEntry](
			cacheSize,
		),
		cacheLogger: newCacheLogger("non-ignored asset points"),
	}
}

// IgnoreCheckerStore is an interface that defines the methods required to
// fetch supply leaves for the ignore checker. It abstracts away the storage
// implementation details, simplifying mocking for unit tests.
type IgnoreCheckerStore interface {
	// FetchSupplyLeavesByType fetches all supply leaves for a given asset
	// specifier and a specific supply sub-tree.
	FetchSupplyLeavesByType(ctx context.Context, spec asset.Specifier,
		tree supplycommit.SupplySubTree, startHeight,
		endHeight uint32) lfn.Result[supplycommit.SupplyLeaves]
}

// AssetGroupQuery is an interface that defines the method to query an asset
// group by its asset ID. This is used to determine if an asset belongs to a
// group and to fetch the group key if it does. It abstracts away the details
// of how the asset group is stored, simplifying mocking for unit tests.
type AssetGroupQuery interface {
	// QueryAssetGroupByID attempts to fetch an asset group by its asset ID.
	// If the asset group cannot be found, then ErrAssetGroupUnknown is
	// returned.
	QueryAssetGroupByID(context.Context, asset.ID) (*asset.AssetGroup,
		error)
}

// IgnoreCheckerCfg is a configuration struct for the CachingIgnoreChecker.
type IgnoreCheckerCfg struct {
	// GroupQuery is used to query asset groups by their asset ID.
	GroupQuery AssetGroupQuery

	// Store is used to fetch supply leaves for the ignore checker.
	Store IgnoreCheckerStore

	// NegativeLookupCacheSize is the size of the negative cache for
	// asset points that are known to not be ignored.
	NegativeLookupCacheSize uint64
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

	// nonIgnoredAssetPoints is a "negative" cache that stores asset points
	// that are known to (currently!) not be ignored. This is used to speed
	// up the lookup of asset points that are not ignored if we look up the
	// same ancestor multiple times. It is imperative that this cache is
	// evicted whenever there is a possibility that the list of ignored
	// asset points changes, such as when a new ignore tuple is added to the
	// asset group.
	nonIgnoredAssetPoints *nonIgnoredCache
}

// NewCachingIgnoreChecker creates a new instance of CachingIgnoreChecker
// with the provided configuration.
func NewCachingIgnoreChecker(cfg IgnoreCheckerCfg) *CachingIgnoreChecker {
	return &CachingIgnoreChecker{
		cfg:                cfg,
		groupKeyLookup:     make(map[asset.ID]asset.SerializedKey),
		bestHeightLookup:   make(map[asset.SerializedKey]uint32),
		ignoredAssetPoints: make(fn.Set[proof.AssetPoint]),
		nonIgnoredAssetPoints: newNonIgnoredCache(
			cfg.NegativeLookupCacheSize,
		),
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

	// We also do a direct lookup to find out if the asset point currently
	// is _NOT_ ignored. This cache will only be populated for some time
	// before it is evicted, to make sure we don't miss new asset points
	// being ignored.
	if c.nonIgnoredAssetPoints.HasEntry(prevID) {
		log.Tracef("Asset point %s is known to currently not be "+
			"ignored", prevID)

		return lfn.Ok(false)
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
	isIgnored := c.ignoredAssetPoints.Contains(prevID)

	// If the asset point is currently not ignored, we add it to the
	// negative lookup cache, so we don't need to query the database again
	// for this asset point in the near future.
	if !isIgnored {
		log.Tracef("Asset point %s is not ignored, adding to "+
			"negative lookup cache", prevID)

		if err := c.nonIgnoredAssetPoints.AddEntry(prevID); err != nil {
			return lfn.Err[bool](err)
		}
	}

	log.Debugf("Asset point %s is ignored: %v", prevID, isIgnored)
	return lfn.Ok(isIgnored)
}

// InvalidateCache is used to clear the negative lookup cache for asset points
// that are known to not be ignored. This should be called whenever there is a
// possibility that the list of ignored asset points changes, such as when a new
// ignore tuple is added to the asset group.
func (c *CachingIgnoreChecker) InvalidateCache(groupKey btcec.PublicKey) {
	c.Lock()
	defer c.Unlock()

	log.Debugf("Invalidating ignore checker negative lookup cache for "+
		"group key %x", groupKey.SerializeCompressed())

	invalidatedGroupKeyBytes := groupKey.SerializeCompressed()
	c.nonIgnoredAssetPoints.cache.Range(
		func(key proof.AssetPoint, _ *emptyCacheEntry) bool {
			groupKeyInCache, ok := c.groupKeyLookup[key.ID]
			if !ok {
				// If we don't have the group key for this
				// asset point, we can't invalidate it. We know
				// for certain that we would have an entry in
				// the group key lookup map if we added an asset
				// point to the non-ignored cache.
				return true
			}

			// If the asset ID belongs to the group that we want to
			// invalidate entries for, then we remove it from the
			// non-ignored asset points cache.
			if bytes.Equal(
				groupKeyInCache[:], invalidatedGroupKeyBytes,
			) {

				c.nonIgnoredAssetPoints.cache.Delete(key)
			}

			return true
		},
	)
}
