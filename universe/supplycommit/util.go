package supplycommit

import (
	"context"
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/fn/v2"
)

var (
	// ErrSupplyNotSupported is returned when an operation that requires
	// supply commitments is attempted on an asset that does not support
	// them.
	ErrSupplyNotSupported = errors.New("asset does not support supply " +
		"commitments")
)

// CalcTotalOutstandingSupply calculates the total outstanding supply from the
// given supply subtrees.
func CalcTotalOutstandingSupply(ctx context.Context,
	supplySubtrees SupplyTrees) fn.Result[uint64] {

	var total uint64

	// Add the total minted amount if we have a mint tree.
	if mintTree, ok := supplySubtrees[MintTreeType]; ok {
		root, err := mintTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract mint tree root: %w", err))
		}

		total = root.NodeSum()
	}

	// Return early if there's no minted supply, ignore the other subtrees.
	if total == 0 {
		return fn.Ok[uint64](0)
	}

	// Subtract the total burned amount if we have a burn tree.
	if burnTree, ok := supplySubtrees[BurnTreeType]; ok {
		root, err := burnTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract burn tree root: %w", err))
		}

		burned := root.NodeSum()
		if burned > total {
			return fn.Err[uint64](fmt.Errorf("total burned %d "+
				"exceeds total outstanding %d", burned, total))
		}

		total -= burned
	}

	// Subtract the total ignored amount if we have an ignore tree.
	if ignoreTree, ok := supplySubtrees[IgnoreTreeType]; ok {
		root, err := ignoreTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract ignore tree root: %w", err))
		}

		ignored := root.NodeSum()
		if ignored > total {
			return fn.Err[uint64](fmt.Errorf("total ignored %d "+
				"exceeds total outstanding %d", ignored, total))
		}

		total -= ignored
	}

	return fn.Ok[uint64](total)
}

// CheckSupplyCommitSupport verifies that the asset group for the given
// asset specifier supports supply commitments, and that this node can generate
// supply commitments for it.
func CheckSupplyCommitSupport(ctx context.Context, assetLookup AssetLookup,
	assetSpec asset.Specifier, locallyControlled bool) error {

	// Fetch the latest asset metadata for the asset group.
	metaReveal, err := FetchLatestAssetMetadata(
		ctx, assetLookup, assetSpec,
	)
	if err != nil {
		return fmt.Errorf("faild to fetch asset meta: %w", err)
	}

	// If the universe commitment flag is not set on the asset metadata,
	// then the asset group does not support supply commitments.
	if !metaReveal.UniverseCommitments {
		return fmt.Errorf("asset group metadata universe "+
			"commitments flag indicates unsupported supply "+
			"commitments: %w", ErrSupplyNotSupported)
	}

	// If a delegation key is not present, then the asset group does not
	// support supply commitments.
	if metaReveal.DelegationKey.IsNone() {
		return fmt.Errorf("asset group metadata does not "+
			"specify delegation key, required for supply "+
			"commitments: %w", ErrSupplyNotSupported)
	}

	// Extract supply commitment delegation pub key from the asset metadata.
	delegationPubKey, err := metaReveal.DelegationKey.UnwrapOrErr(
		fmt.Errorf("delegation key not found for given asset: %w",
			ErrSupplyNotSupported),
	)
	if err != nil {
		return err
	}

	// Fetch the delegation key locator. We need to ensure that the
	// delegation key is owned by this node, so that we can generate
	// supply commitments (ignore tuples) for this asset group.
	_, err = assetLookup.FetchInternalKeyLocator(
		ctx, &delegationPubKey,
	)
	switch {
	case errors.Is(err, address.ErrInternalKeyNotFound):
		// If local key control is expected, then we return an error
		// if the delegation key locator is not found.
		if locallyControlled {
			return fmt.Errorf("delegation key locator not found; "+
				"only delegation key owners can generate "+
				"supply commitments: %w", err)
		}

	case err != nil:
		return fmt.Errorf("failed to fetch delegation key locator: %w",
			err)
	}

	return nil
}

// IsSupplySupported checks whether the asset group for the given asset
// specifier supports supply commitments. If locallyControlled is true,
// then we also check that this node can generate supply commitments for it.
//
// NOTE: This is a convenience wrapper around CheckSupplyCommitSupport.
func IsSupplySupported(ctx context.Context, assetLookup AssetLookup,
	assetSpec asset.Specifier, locallyControlled bool) (bool, error) {

	err := CheckSupplyCommitSupport(
		ctx, assetLookup, assetSpec, locallyControlled,
	)
	switch {
	case errors.Is(err, ErrSupplyNotSupported):
		return false, nil

	case err != nil:
		return false, fmt.Errorf("failed to check asset for supply "+
			"support: %w", err)
	}

	return true, nil
}
