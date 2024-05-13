package tapchannel

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

var (
	testParams = &address.RegressionNetTap

	tx = wire.MsgTx{
		TxOut: []*wire.TxOut{
			{
				Value:    1000,
				PkScript: []byte("foo"),
			},
		},
	}
)

func makeProof(t *testing.T, a *asset.Asset) *proof.Proof {
	tapCommitment, err := commitment.FromAssets(a)
	require.NoError(t, err)

	_, commitmentProof, err := tapCommitment.Proof(
		a.TapCommitmentKey(), a.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	return &proof.Proof{
		Asset:    *a,
		AnchorTx: tx,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &proof.CommitmentProof{
				Proof: *commitmentProof,
			},
		},
	}
}

func grindAssetID(t *testing.T, prefix byte) asset.Genesis {
	for {
		assetID := asset.RandGenesis(t, asset.Normal)
		if assetID.ID()[0] == prefix {
			return assetID
		}
	}
}

func TestDistributeCoinsErrors(t *testing.T) {
	_, err := DistributeCoins(nil, nil, testParams)
	require.ErrorIs(t, err, ErrMissingInputs)

	_, err = DistributeCoins([]*proof.Proof{{}}, nil, testParams)
	require.ErrorIs(t, err, ErrMissingAllocations)

	assetCollectible := asset.RandAsset(t, asset.Collectible)
	proofCollectible := makeProof(t, assetCollectible)
	_, err = DistributeCoins(
		[]*proof.Proof{proofCollectible}, []*Allocation{{}}, testParams,
	)
	require.ErrorIs(t, err, ErrNormalAssetsOnly)

	assetNormal := asset.RandAsset(t, asset.Normal)
	proofNormal := makeProof(t, assetNormal)
	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal}, []*Allocation{
			{
				Amount: assetNormal.Amount / 2,
			},
		}, testParams,
	)
	require.ErrorIs(t, err, ErrInputOutputSumMismatch)
}

func TestDistributeCoins(t *testing.T) {
	t.Parallel()

	assetID1 := grindAssetID(t, 0x01)
	groupKey1 := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	assetID2 := grindAssetID(t, 0x02)
	groupKey2 := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	assetID3 := grindAssetID(t, 0x03)
	groupKey3 := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	assetID1Tranche1 := asset.NewAssetNoErr(
		t, assetID1, 100, 0, 0, asset.RandScriptKey(t), groupKey1,
	)
	assetID1Tranche2 := asset.NewAssetNoErr(
		t, assetID1, 200, 0, 0, asset.RandScriptKey(t), groupKey1,
	)
	assetID1Tranche3 := asset.NewAssetNoErr(
		t, assetID1, 300, 0, 0, asset.RandScriptKey(t), groupKey1,
	)

	assetID2Tranche1 := asset.NewAssetNoErr(
		t, assetID2, 1000, 0, 0, asset.RandScriptKey(t), groupKey2,
	)
	assetID2Tranche2 := asset.NewAssetNoErr(
		t, assetID2, 2000, 0, 0, asset.RandScriptKey(t), groupKey2,
	)
	assetID2Tranche3 := asset.NewAssetNoErr(
		t, assetID2, 3000, 0, 0, asset.RandScriptKey(t), groupKey2,
	)

	assetID3Tranche1 := asset.NewAssetNoErr(
		t, assetID3, 10000, 0, 0, asset.RandScriptKey(t), groupKey3,
	)
	assetID3Tranche2 := asset.NewAssetNoErr(
		t, assetID3, 20000, 0, 0, asset.RandScriptKey(t), groupKey3,
	)
	assetID3Tranche3 := asset.NewAssetNoErr(
		t, assetID3, 30000, 0, 0, asset.RandScriptKey(t), groupKey3,
	)

	var (
		simple = tappsbt.TypeSimple
		split  = tappsbt.TypeSplitRoot
	)
	testCases := []struct {
		name            string
		inputs          []*proof.Proof
		allocations     []*Allocation
		expectedInputs  map[asset.ID][]asset.ScriptKey
		expectedOutputs map[asset.ID][]*tappsbt.VOutput
	}{
		{
			name: "single asset, split",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			allocations: []*Allocation{
				{
					Type:   CommitAllocationToLocal,
					Amount: 50,
				},
				{
					Type:        CommitAllocationToRemote,
					SplitRoot:   true,
					Amount:      50,
					OutputIndex: 1,
				},
			},
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID1.ID(): {
					assetID1Tranche1.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID1.ID(): {
					{
						Amount:            50,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            50,
						Type:              split,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "multiple assets, split",
			inputs: []*proof.Proof{
				makeProof(t, assetID2Tranche1),
				makeProof(t, assetID2Tranche2),
			},
			allocations: []*Allocation{
				{
					Type:      CommitAllocationToLocal,
					SplitRoot: true,
					Amount:    1200,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      1800,
					OutputIndex: 1,
				},
			},
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID2.ID(): {
					assetID2Tranche1.ScriptKey,
					assetID2Tranche2.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID2.ID(): {
					{
						Amount:            1200,
						Type:              split,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            1800,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "multiple assets, one consumed fully",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
				makeProof(t, assetID2Tranche1),
			},
			allocations: []*Allocation{
				{
					Type:      CommitAllocationToLocal,
					SplitRoot: true,
					Amount:    1050,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      50,
					OutputIndex: 1,
				},
			},
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID1.ID(): {
					assetID1Tranche1.ScriptKey,
				},
				assetID2.ID(): {
					assetID2Tranche1.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID1.ID(): {
					{
						Amount:            100,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
				},
				assetID2.ID(): {
					{
						Amount:            950,
						Type:              split,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            50,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "lots of assets",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
				makeProof(t, assetID1Tranche2),
				makeProof(t, assetID1Tranche3),
				makeProof(t, assetID2Tranche1),
				makeProof(t, assetID2Tranche2),
				makeProof(t, assetID2Tranche3),
				makeProof(t, assetID3Tranche1),
				makeProof(t, assetID3Tranche2),
				makeProof(t, assetID3Tranche3),
			},
			allocations: []*Allocation{
				{
					Type:      CommitAllocationToLocal,
					SplitRoot: true,
					Amount:    3600,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      63000,
					OutputIndex: 1,
				},
			},
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID1.ID(): {
					assetID1Tranche1.ScriptKey,
					assetID1Tranche2.ScriptKey,
					assetID1Tranche3.ScriptKey,
				},
				assetID2.ID(): {
					assetID2Tranche1.ScriptKey,
					assetID2Tranche2.ScriptKey,
					assetID2Tranche3.ScriptKey,
				},
				assetID3.ID(): {
					assetID3Tranche1.ScriptKey,
					assetID3Tranche2.ScriptKey,
					assetID3Tranche3.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID1.ID(): {
					{
						Amount:            600,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
				},
				assetID2.ID(): {
					{
						Amount:            3000,
						Type:              split,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            3000,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
				assetID3.ID(): {
					{
						Amount:            60000,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packets, err := DistributeCoins(
				tc.inputs, tc.allocations, testParams,
			)
			require.NoError(t, err)

			assertPackets(
				t, packets, tc.expectedInputs,
				tc.expectedOutputs,
			)
		})
	}
}

func assertPackets(t *testing.T, packets []*tappsbt.VPacket,
	expectedInputs map[asset.ID][]asset.ScriptKey,
	expectedOutputs map[asset.ID][]*tappsbt.VOutput) {

	for assetID, scriptKeys := range expectedInputs {
		packetsByID := fn.Filter(
			packets, func(p *tappsbt.VPacket) bool {
				return p.Inputs[0].PrevID.ID == assetID
			},
		)
		require.Len(t, packetsByID, 1)

		packet := packetsByID[0]
		inputKeys := fn.Map(
			packet.Inputs,
			func(i *tappsbt.VInput) asset.ScriptKey {
				pubKey, err := i.PrevID.ScriptKey.ToPubKey()
				require.NoError(t, err)

				return asset.NewScriptKey(pubKey)
			},
		)

		require.Equal(t, scriptKeys, inputKeys)

		outputsByID := expectedOutputs[assetID]
		require.Equal(t, len(outputsByID), len(packet.Outputs))
		for i, output := range packet.Outputs {
			require.Equal(t, outputsByID[i], output)
		}
	}
}
