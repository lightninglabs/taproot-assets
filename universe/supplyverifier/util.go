package supplyverifier

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
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
