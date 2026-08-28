package tapnode

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
)

var (
	// ErrGroupKeyUnknown is an error returned if an asset has a group key
	// that is not known to the local node.
	ErrGroupKeyUnknown = errors.New("group key not known")

	// ErrGenesisNotGroupAnchor is an error returned if an asset has a group
	// key but is not the anchor of the group.
	ErrGenesisNotGroupAnchor = errors.New("genesis not group anchor")
)

// assetGroupCacheSize is the size of the cache for group keys.
const assetGroupCacheSize = 10000

// emptyVal is a simple type def around struct{} to use as a dummy value in
// caches that only need set semantics.
type emptyVal struct{}

// singleCacheValue is a single-element cache value wrapper that also implements
// the lru.Value sizing interface.
type singleCacheValue[T any] struct {
	val T
}

// Size returns the constant size of a singleCacheValue.
func (s singleCacheValue[T]) Size() (uint64, error) {
	return 1, nil
}

// newSingleValue constructs a singleCacheValue carrying v.
func newSingleValue[T any](v T) singleCacheValue[T] {
	return singleCacheValue[T]{
		val: v,
	}
}

// emptyCacheVal is a type def for an empty cache value. In this case the cache
// is used more as a set.
type emptyCacheVal = singleCacheValue[emptyVal]

// GenGroupVerifier generates a group key verification callback function given a
// GroupFetcher.
func GenGroupVerifier(ctx context.Context,
	groupFetcher GroupFetcher) func(*btcec.PublicKey) error {

	// Cache known group keys that were previously fetched.
	assetGroups := lru.NewCache[asset.SerializedKey, emptyCacheVal](
		assetGroupCacheSize,
	)

	return func(groupKey *btcec.PublicKey) error {
		if groupKey == nil {
			return fmt.Errorf("cannot verify empty group key")
		}

		assetGroupKey := asset.ToSerialized(groupKey)
		_, err := assetGroups.Get(assetGroupKey)
		if err == nil {
			return nil
		}

		// This query will err if no stored group has a matching
		// tweaked group key.
		_, err = groupFetcher.FetchGroupByGroupKey(ctx, groupKey)
		if err != nil {
			return fmt.Errorf("%x: group verifier: %s: %w",
				assetGroupKey[:], err.Error(),
				ErrGroupKeyUnknown)
		}

		_, _ = assetGroups.Put(assetGroupKey, emptyCacheVal{})

		return nil
	}
}

// GenGroupAnchorVerifier generates a caching group anchor verification
// callback function given a GroupFetcher.
func GenGroupAnchorVerifier(ctx context.Context,
	groupFetcher GroupFetcher) func(*asset.Genesis,
	*asset.GroupKey) error {

	// Cache anchors for groups that were previously fetched.
	groupAnchors := lru.NewCache[
		asset.SerializedKey, singleCacheValue[*asset.Genesis],
	](
		assetGroupCacheSize,
	)

	return func(gen *asset.Genesis, groupKey *asset.GroupKey) error {
		assetGroupKey := asset.ToSerialized(&groupKey.GroupPubKey)
		groupAnchor, err := groupAnchors.Get(assetGroupKey)
		if err != nil {
			storedGroup, err := groupFetcher.FetchGroupByGroupKey(
				ctx, &groupKey.GroupPubKey,
			)
			if err != nil {
				return fmt.Errorf("%x: group anchor verifier: "+
					"%w", assetGroupKey[:],
					ErrGroupKeyUnknown)
			}

			isGroupAnchor, err := storedGroup.IsGroupAnchor()
			if err != nil {
				return fmt.Errorf("%x: group anchor verifier: "+
					"unable to check if genesis is "+
					"group anchor: %w", assetGroupKey[:],
					err)
			}

			if !isGroupAnchor {
				return fmt.Errorf("%x: group anchor verifier: "+
					"genesis is not a group anchor: %w",
					assetGroupKey[:], err)
			}

			groupAnchor = newSingleValue(storedGroup.Genesis)

			_, _ = groupAnchors.Put(assetGroupKey, groupAnchor)
		}

		if gen.ID() != groupAnchor.val.ID() {
			return ErrGenesisNotGroupAnchor
		}

		return nil
	}
}

// GenRawGroupAnchorVerifier generates a group anchor verification callback
// function. This anchor verifier recomputes the tweaked group key with the
// passed genesis and compares that key to the given group key. This verifier
// is used before any asset groups are stored in the DB.
func GenRawGroupAnchorVerifier(ctx context.Context) func(*asset.Genesis,
	*asset.GroupKey) error {

	// Cache group anchors we already verified.
	groupAnchors := lru.NewCache[
		asset.SerializedKey, singleCacheValue[*asset.Genesis]](
		assetGroupCacheSize,
	)

	return func(gen *asset.Genesis, groupKey *asset.GroupKey) error {
		assetGroupKey := asset.ToSerialized(&groupKey.GroupPubKey)
		groupAnchor, err := groupAnchors.Get(assetGroupKey)
		if err != nil {
			singleTweak := gen.ID()
			tweakedGroupKey, err := asset.GroupPubKeyV0(
				groupKey.RawKey.PubKey, singleTweak[:],
				groupKey.TapscriptRoot,
			)
			if err != nil {
				return err
			}

			computedGroupKey := asset.ToSerialized(tweakedGroupKey)
			if computedGroupKey != assetGroupKey {
				return ErrGenesisNotGroupAnchor
			}

			groupAnchor = newSingleValue(gen)

			_, _ = groupAnchors.Put(assetGroupKey, groupAnchor)

			return nil
		}

		if gen.ID() != groupAnchor.val.ID() {
			return ErrGenesisNotGroupAnchor
		}

		return nil
	}
}
