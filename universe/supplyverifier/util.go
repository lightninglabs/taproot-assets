package supplyverifier

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// FetchDelegationKey fetches the delegation key for the given asset specifier.
func FetchDelegationKey(ctx context.Context,
	assetLookup supplycommit.AssetLookup,
	assetSpec asset.Specifier) (btcec.PublicKey, error) {

	var zero btcec.PublicKey

	metaReveal, err := supplycommit.FetchLatestAssetMetadata(
		ctx, assetLookup, assetSpec,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch asset "+
			"metadata: %w", err)
	}

	delegationKey, err := metaReveal.DelegationKey.UnwrapOrErr(
		fmt.Errorf("missing delegation key in asset metadata"),
	)
	if err != nil {
		return zero, err
	}

	return delegationKey, nil
}

// FetchPreCommits returns all pre-commitment outputs expected to be spent by
// the anchoring transaction of the specified supply commitment.
func FetchPreCommits(ctx context.Context,
	assetLookup supplycommit.AssetLookup, supplyCommitView SupplyCommitView,
	assetSpec asset.Specifier, supplyCommit supplycommit.RootCommitment,
	mintEvents []supplycommit.NewMintEvent) ([]supplycommit.PreCommitment,
	error) {

	// Get supply commit block height. This will be used to filter out any
	// pre-commitments that are above the supply commitment height.
	chainCommit, err := supplyCommit.CommitmentBlock.UnwrapOrErr(
		fmt.Errorf("commitment block missing"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to extract supply commitment "+
			"chain block: %w", err)
	}
	supplyCommitBlockHeight := chainCommit.Height

	// Fetch all known unspent pre-commitment outputs for the asset
	// group.
	preCommits, err := supplyCommitView.UnspentPrecommits(
		ctx, assetSpec, false,
	).Unpack()
	if err != nil {
		return nil, fmt.Errorf("unable to fetch unspent "+
			"pre-commitments: %w", err)
	}

	// Filter out any pre-commitments that are above the supply commitment
	// height. These can't be spent by the current supply commitment.
	filteredPreCommits := make(
		[]supplycommit.PreCommitment, 0, len(preCommits),
	)
	for _, pc := range preCommits {
		if pc.BlockHeight <= supplyCommitBlockHeight {
			filteredPreCommits = append(filteredPreCommits, pc)
		}
	}
	preCommits = filteredPreCommits

	// If there are no mint events, then we can return early here because
	// there won't be any new pre-commitments to consider.
	if len(mintEvents) == 0 {
		return preCommits, nil
	}

	// We'll need the delegation key to extract any new pre-commitments from
	// the mint events.
	delegationKey, err := FetchDelegationKey(
		ctx, assetLookup, assetSpec,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch delegation key: %w",
			err)
	}

	// Create a set of outpoints from all known pre-commits. This will be
	// used to prevent duplicates when adding new pre-commits from the mint
	// events.
	preCommitOutPoints := fn.NewSet(fn.Map(
		preCommits, func(preCommit supplycommit.PreCommitment) string {
			return preCommit.OutPoint().String()
		},
	)...)

	// Collect pre-commitments from the mint events that we haven't already
	// seen.
	for idx := range mintEvents {
		mintEvent := mintEvents[idx]

		preCommit, err := supplycommit.NewPreCommitFromMintEvent(
			mintEvent, delegationKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to extract "+
				"pre-commitment from mint event: %w", err)
		}

		// If we already have this pre-commitment, then skip it.
		op := preCommit.OutPoint()
		if preCommitOutPoints.Contains(op.String()) {
			continue
		}

		preCommits = append(preCommits, preCommit)
	}

	return preCommits, nil
}
