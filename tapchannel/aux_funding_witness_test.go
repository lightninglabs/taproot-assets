package tapchannel

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

// mockWitnessChainBridge embeds the chain bridge interface and only
// implements the chain lookup generation used by validateWitness.
type mockWitnessChainBridge struct {
	tapgarden.ChainBridge
}

// GenFileChainLookup returns the mock chain lookup.
func (mockWitnessChainBridge) GenFileChainLookup(
	*proof.File) asset.ChainLookup {

	return proof.MockChainLookup
}

// TestValidateWitnessSplitOutput ensures that validateWitness validates a
// split-derived funding output's split leaf against the split commitment
// tree.
func TestValidateWitnessSplitOutput(t *testing.T) {
	t.Parallel()

	// Start with a verifiable 100-unit genesis asset owned by the peer.
	amt := uint64(100)
	genesisProof, senderKey := proof.RandGenesisProofWithKey(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)
	inputAsset := &genesisProof.Asset
	assetID := inputAsset.ID()

	// The peer splits the input: 40 units go into the channel funding
	// output (always anchored at the funding output index), 60 units of
	// change go back to the peer.
	fundingLocator := &commitment.SplitLocator{
		OutputIndex: FundingOutputIndex,
		AssetID:     assetID,
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      40,
	}
	changeLocator := &commitment.SplitLocator{
		OutputIndex: 1,
		AssetID:     assetID,
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      60,
	}
	splitCommitment, err := commitment.NewSplitCommitment(
		context.Background(), []commitment.SplitCommitmentInput{{
			Asset:    inputAsset,
			OutPoint: genesisProof.OutPoint(),
		}}, changeLocator, fundingLocator,
	)
	require.NoError(t, err)

	// Sign the split root with the input key and update the funding
	// leaf's embedded root asset, mirroring the production signing flow.
	rootAsset := splitCommitment.RootAsset
	virtualTx, _, err := tapscript.VirtualTx(
		rootAsset, splitCommitment.PrevAssets,
	)
	require.NoError(t, err)
	rootAsset.PrevWitnesses[0].TxWitness = keySpendWitness(
		t, senderKey, virtualTx, inputAsset, rootAsset, 0,
	)

	fundingAsset := &splitCommitment.SplitAssets[*fundingLocator].Asset
	fundingAsset.PrevWitnesses[0].SplitCommitment.RootAsset = *rootAsset

	controller := &FundingController{
		cfg: FundingControllerCfg{
			ChainBridge: mockWitnessChainBridge{},
		},
	}

	inputProofs := []*proof.Proof{&genesisProof}

	// The funding output must be accepted.
	err = controller.validateWitness(*fundingAsset, inputProofs)
	require.NoError(t, err)

	// A funding output whose amount is not backed by the split tree must
	// be rejected. The split commitment proof still refers to the 40-unit
	// leaf, while the claimed asset carries 1,000,000 units.
	alteredAsset := fundingAsset.Copy()
	alteredAsset.Amount = 1_000_000

	err = controller.validateWitness(*alteredAsset, inputProofs)
	require.Error(t, err)
	var vmErr vm.Error
	require.ErrorAs(t, err, &vmErr)
	require.Equal(t, vm.ErrInvalidSplitCommitmentProof, vmErr.Kind)
}
