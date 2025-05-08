package tapsend

import (
	"testing"

	"github.com/btcsuite/btcd/txscript"
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
	tapCommitment, err := commitment.FromAssets(
		fn.Ptr(commitment.TapCommitmentV2), a,
	)
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
	_, err := DistributeCoins(nil, nil, testParams, true, tappsbt.V1)
	require.ErrorIs(t, err, ErrMissingInputs)

	_, err = DistributeCoins(
		[]*proof.Proof{{}}, nil, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrMissingAllocations)

	assetNormal := asset.RandAsset(t, asset.Normal)
	proofNormal := makeProof(t, assetNormal)
	assetCollectible := asset.RandAsset(t, asset.Collectible)
	proofCollectible := makeProof(t, assetCollectible)
	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal, proofCollectible},
		[]*Allocation{{}}, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrInputTypesNotEqual)

	assetNormal2 := asset.RandAsset(t, asset.Normal)
	proofNormal2 := makeProof(t, assetNormal2)
	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal, proofNormal2},
		[]*Allocation{{}}, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrInputGroupMismatch)

	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal}, []*Allocation{
			{
				Amount: assetNormal.Amount / 2,
				GenScriptKey: StaticScriptKeyGen(
					asset.RandScriptKey(t),
				),
			},
		}, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrInputOutputSumMismatch)

	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal}, []*Allocation{{
			Amount:          assetNormal.Amount,
			NonAssetLeaves:  make([]txscript.TapLeaf, 1),
			SiblingPreimage: &commitment.TapscriptPreimage{},
		}}, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrInvalidSibling)

	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal}, []*Allocation{{
			Type:   CommitAllocationToLocal,
			Amount: assetNormal.Amount,
		}}, testParams, true, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrScriptKeyGenMissing)

	_, err = DistributeCoins(
		[]*proof.Proof{proofNormal}, []*Allocation{{
			Type:   CommitAllocationToLocal,
			Amount: assetNormal.Amount / 2,
			GenScriptKey: StaticScriptKeyGen(
				asset.RandScriptKey(t),
			),
		}, {
			Type:   CommitAllocationToRemote,
			Amount: assetNormal.Amount / 2,
			GenScriptKey: StaticScriptKeyGen(
				asset.RandScriptKey(t),
			),
		}}, testParams, false, tappsbt.V1,
	)
	require.ErrorIs(t, err, ErrNoSplitRoot)
}

func TestDistributeCoins(t *testing.T) {
	t.Parallel()

	groupKey := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	assetID1 := grindAssetID(t, 0x01)
	assetID2 := grindAssetID(t, 0x02)
	assetID3 := grindAssetID(t, 0x03)
	assetID4 := grindAssetID(t, 0x04)
	assetID5 := grindAssetID(t, 0x05)

	assetID1Tranche1 := asset.NewAssetNoErr(
		t, assetID1, 100, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID1Tranche2 := asset.NewAssetNoErr(
		t, assetID1, 200, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID1Tranche3 := asset.NewAssetNoErr(
		t, assetID1, 300, 0, 0, asset.RandScriptKey(t), groupKey,
	)

	assetID2Tranche1 := asset.NewAssetNoErr(
		t, assetID2, 1000, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID2Tranche2 := asset.NewAssetNoErr(
		t, assetID2, 2000, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID2Tranche3 := asset.NewAssetNoErr(
		t, assetID2, 3000, 0, 0, asset.RandScriptKey(t), groupKey,
	)

	assetID3Tranche1 := asset.NewAssetNoErr(
		t, assetID3, 10000, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID3Tranche2 := asset.NewAssetNoErr(
		t, assetID3, 20000, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID3Tranche3 := asset.NewAssetNoErr(
		t, assetID3, 30000, 0, 0, asset.RandScriptKey(t), groupKey,
	)

	assetID4Tranche1 := asset.NewAssetNoErr(
		t, assetID4, 25000, 0, 0, asset.RandScriptKey(t), groupKey,
	)
	assetID5Tranche1 := asset.NewAssetNoErr(
		t, assetID5, 25000, 0, 0, asset.RandScriptKey(t), groupKey,
	)

	var (
		simple = tappsbt.TypeSimple
		split  = tappsbt.TypeSplitRoot
	)
	testCases := []struct {
		name            string
		inputs          []*proof.Proof
		interactive     bool
		allocations     []*Allocation
		vPktVersion     tappsbt.VPacketVersion
		expectedInputs  map[asset.ID][]asset.ScriptKey
		expectedOutputs map[asset.ID][]*tappsbt.VOutput
	}{
		{
			name: "single asset, split, interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			interactive: true,
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
			vPktVersion: tappsbt.V1,
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
			name: "single asset, split, non-interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			interactive: false,
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
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            50,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "single asset, full value, interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			interactive: true,
			allocations: []*Allocation{
				{
					Type:   CommitAllocationToLocal,
					Amount: 100,
				},
				{
					Type:        CommitAllocationToRemote,
					SplitRoot:   true,
					Amount:      0,
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
						Amount:            100,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 0,
					},
				},
			},
		},
		{
			name: "single asset, full value, interactive, has " +
				"split output",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			interactive: true,
			allocations: []*Allocation{
				{
					Type:      CommitAllocationToLocal,
					Amount:    0,
					SplitRoot: true,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      100,
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
						Amount:            100,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "single asset, full value, non-interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
			},
			interactive: false,
			allocations: []*Allocation{
				{
					Type:   CommitAllocationToLocal,
					Amount: 100,
				},
				{
					Type:        CommitAllocationToRemote,
					SplitRoot:   true,
					Amount:      0,
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
						Amount:            100,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            0,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "multiple assets, split, interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID2Tranche1),
				makeProof(t, assetID2Tranche2),
			},
			interactive: true,
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
			vPktVersion: tappsbt.V1,
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID2.ID(): {
					assetID2Tranche2.ScriptKey,
					assetID2Tranche1.ScriptKey,
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
			name: "multiple assets, split, non-interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID2Tranche1),
				makeProof(t, assetID2Tranche2),
			},
			interactive: false,
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
					assetID2Tranche2.ScriptKey,
					assetID2Tranche1.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID2.ID(): {
					{
						Amount:            1200,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            1800,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "multiple assets, one consumed fully, " +
				"interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
				makeProof(t, assetID2Tranche1),
			},
			interactive: true,
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
			name: "multiple assets, one consumed fully, " +
				"non-interactive",
			inputs: []*proof.Proof{
				makeProof(t, assetID1Tranche1),
				makeProof(t, assetID2Tranche1),
			},
			interactive: false,
			allocations: []*Allocation{
				{
					Type:      CommitAllocationToLocal,
					SplitRoot: true,
					Amount:    50,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      1050,
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
						Amount:            50,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            50,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
				assetID2.ID(): {
					{
						Amount:            0,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            1000,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "lots of assets, interactive",
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
			interactive: true,
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
					assetID1Tranche3.ScriptKey,
					assetID1Tranche2.ScriptKey,
					assetID1Tranche1.ScriptKey,
				},
				assetID2.ID(): {
					assetID2Tranche3.ScriptKey,
					assetID2Tranche2.ScriptKey,
					assetID2Tranche1.ScriptKey,
				},
				assetID3.ID(): {
					assetID3Tranche3.ScriptKey,
					assetID3Tranche2.ScriptKey,
					assetID3Tranche1.ScriptKey,
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
		{
			name: "lots of assets, non-interactive",
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
			interactive: false,
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
					assetID1Tranche3.ScriptKey,
					assetID1Tranche2.ScriptKey,
					assetID1Tranche1.ScriptKey,
				},
				assetID2.ID(): {
					assetID2Tranche3.ScriptKey,
					assetID2Tranche2.ScriptKey,
					assetID2Tranche1.ScriptKey,
				},
				assetID3.ID(): {
					assetID3Tranche3.ScriptKey,
					assetID3Tranche2.ScriptKey,
					assetID3Tranche1.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID1.ID(): {
					{
						Amount:            600,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
				},
				assetID2.ID(): {
					{
						Amount:            3000,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            3000,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
				assetID3.ID(): {
					{
						Amount:            0,
						Type:              split,
						Interactive:       false,
						AnchorOutputIndex: 0,
					},
					{
						Amount:            60000,
						Type:              simple,
						Interactive:       false,
						AnchorOutputIndex: 1,
					},
				},
			},
		},
		{
			name: "lots of assets, interactive, no split root",
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
			interactive: true,
			allocations: []*Allocation{
				{
					Type:   CommitAllocationToLocal,
					Amount: 3600,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      63000,
					OutputIndex: 1,
				},
			},
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID1.ID(): {
					assetID1Tranche3.ScriptKey,
					assetID1Tranche2.ScriptKey,
					assetID1Tranche1.ScriptKey,
				},
				assetID2.ID(): {
					assetID2Tranche3.ScriptKey,
					assetID2Tranche2.ScriptKey,
					assetID2Tranche1.ScriptKey,
				},
				assetID3.ID(): {
					assetID3Tranche3.ScriptKey,
					assetID3Tranche2.ScriptKey,
					assetID3Tranche1.ScriptKey,
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
		{
			name: "multiple allocations, no split root defined",
			inputs: []*proof.Proof{
				makeProof(t, assetID4Tranche1),
				makeProof(t, assetID5Tranche1),
			},
			interactive: true,
			//nolint:lll
			allocations: []*Allocation{
				{
					Type:        CommitAllocationHtlcOutgoing,
					Amount:      5000,
					OutputIndex: 2,
				},
				{
					Type:        CommitAllocationToLocal,
					Amount:      20000,
					OutputIndex: 3,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      25000,
					OutputIndex: 4,
				},
			},
			vPktVersion: tappsbt.V1,
			expectedInputs: map[asset.ID][]asset.ScriptKey{
				assetID4.ID(): {
					assetID4Tranche1.ScriptKey,
				},
				assetID5.ID(): {
					assetID5Tranche1.ScriptKey,
				},
			},
			expectedOutputs: map[asset.ID][]*tappsbt.VOutput{
				assetID4.ID(): {
					{
						Amount:            5000,
						Type:              split,
						Interactive:       true,
						AnchorOutputIndex: 2,
					},
					{
						Amount:            20000,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 3,
					},
				},
				assetID5.ID(): {
					{
						Amount:            25000,
						Type:              simple,
						Interactive:       true,
						AnchorOutputIndex: 4,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// We don't care about script keys in this test so we
			// just set static ones.
			dummyScriptKey := asset.RandScriptKey(t)
			scriptKeyGen := StaticScriptKeyGen(dummyScriptKey)
			for _, allocation := range tc.allocations {
				allocation.GenScriptKey = scriptKeyGen
			}
			for _, outputs := range tc.expectedOutputs {
				for _, output := range outputs {
					output.ScriptKey = dummyScriptKey
				}
			}

			packets, err := DistributeCoins(
				tc.inputs, tc.allocations, testParams,
				tc.interactive, tc.vPktVersion,
			)
			require.NoError(t, err)

			assertPackets(
				t, packets, tc.expectedInputs,
				tc.expectedOutputs,
			)
			for _, pkt := range packets {
				require.Equal(t, tc.vPktVersion, pkt.Version)
			}
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

// TestAllocatePiece tests the allocation of a piece of an asset.
func TestAllocatePiece(t *testing.T) {
	dummyScriptKey := asset.RandScriptKey(t)
	scriptKeyGen := StaticScriptKeyGen(dummyScriptKey)
	tests := []struct {
		name               string
		piece              piece
		allocation         Allocation
		toFill             uint64
		interactive        bool
		expectedErr        string
		expectedAlloc      uint64
		expectedOutput     bool
		expectedOutputType tappsbt.VOutputType
	}{
		{
			name: "valid allocation",
			piece: piece{
				assetID:        asset.ID{1},
				totalAvailable: 100,
				allocated:      0,
				packet:         &tappsbt.VPacket{},
			},
			allocation: Allocation{
				Amount:       50,
				GenScriptKey: scriptKeyGen,
			},
			toFill:             50,
			interactive:        true,
			expectedAlloc:      50,
			expectedOutput:     true,
			expectedOutputType: tappsbt.TypeSimple,
		},
		{
			name: "allocation exceeds available",
			piece: piece{
				assetID:        asset.ID{1},
				totalAvailable: 100,
				allocated:      0,
				packet:         &tappsbt.VPacket{},
			},
			allocation: Allocation{
				Amount:       150,
				GenScriptKey: scriptKeyGen,
			},
			toFill:             150,
			interactive:        true,
			expectedAlloc:      100,
			expectedOutput:     true,
			expectedOutputType: tappsbt.TypeSimple,
		},
		{
			name: "allocation with zero to fill",
			piece: piece{
				assetID:        asset.ID{1},
				totalAvailable: 100,
				allocated:      0,
				packet:         &tappsbt.VPacket{},
			},
			allocation: Allocation{
				Amount:       0,
				GenScriptKey: scriptKeyGen,
			},
			toFill:         0,
			interactive:    true,
			expectedAlloc:  0,
			expectedOutput: false,
		},
		{
			name: "allocation with split root",
			piece: piece{
				assetID:        asset.ID{1},
				totalAvailable: 100,
				allocated:      0,
				packet:         &tappsbt.VPacket{},
			},
			allocation: Allocation{
				Amount:       50,
				SplitRoot:    true,
				GenScriptKey: scriptKeyGen,
			},
			toFill:             50,
			interactive:        false,
			expectedAlloc:      50,
			expectedOutput:     true,
			expectedOutputType: tappsbt.TypeSplitRoot,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			allocated, updatedPiece, err := allocatePiece(
				tc.piece, tc.allocation, tc.toFill,
				tc.interactive,
			)
			if tc.expectedErr != "" {
				require.ErrorContains(tt, err, tc.expectedErr)
				return
			}

			require.NoError(tt, err)
			require.Equal(tt, tc.expectedAlloc, allocated)
			require.Equal(
				tt, tc.piece.totalAvailable-tc.expectedAlloc,
				updatedPiece.available(),
			)

			if tc.expectedOutput {
				require.Len(tt, updatedPiece.packet.Outputs, 1)
				require.Equal(
					tt, tc.expectedOutputType,
					updatedPiece.packet.Outputs[0].Type,
				)
			}
		})
	}
}

// TestAllocationsFromTemplate tests that we can correctly turn a virtual packet
// template in a set of allocations.
func TestAllocationsFromTemplate(t *testing.T) {
	t.Parallel()

	dummyScriptKey := asset.RandScriptKey(t)
	dummyAltLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))

	var (
		simple = tappsbt.TypeSimple
		split  = tappsbt.TypeSplitRoot
	)
	testCases := []struct {
		name        string
		template    *tappsbt.VPacket
		inputSum    uint64
		expectErr   string
		interactive bool
		allocations []*Allocation
	}{
		{
			name:      "no outputs",
			template:  &tappsbt.VPacket{},
			expectErr: "spend template has no outputs",
		},
		{
			name: "mixed interactive and non-interactive",
			template: &tappsbt.VPacket{
				Outputs: []*tappsbt.VOutput{
					{
						Interactive: true,
					},
					{
						Interactive: false,
					},
				},
			},
			expectErr: "different interactive flags",
		},
		{
			name: "output greater than input",
			template: &tappsbt.VPacket{
				Outputs: []*tappsbt.VOutput{
					{
						Amount: 100,
					},
					{
						Amount: 200,
					},
				},
			},
			inputSum:  100,
			expectErr: "output amount exceeds input sum",
		},
		{
			name: "single asset, split, interactive, no " +
				"change",
			template: &tappsbt.VPacket{
				Outputs: []*tappsbt.VOutput{
					{
						Amount:      50,
						ScriptKey:   dummyScriptKey,
						Interactive: true,
						AltLeaves:   dummyAltLeaves,
					},
				},
			},
			inputSum:    100,
			interactive: true,
			allocations: []*Allocation{
				{
					Type:        CommitAllocationToLocal,
					SplitRoot:   true,
					Amount:      50,
					OutputIndex: 1,
					GenScriptKey: StaticScriptKeyGen(
						asset.NUMSScriptKey,
					),
				},
				{
					Type:   CommitAllocationToRemote,
					Amount: 50,
					GenScriptKey: StaticScriptKeyGen(
						dummyScriptKey,
					),
					AltLeaves: dummyAltLeaves,
				},
			},
		},
		{
			name: "single asset, split, interactive, w/ " +
				"change",
			template: &tappsbt.VPacket{
				Outputs: []*tappsbt.VOutput{
					{
						Type:        split,
						Interactive: true,
					},
					{
						Type:              simple,
						Interactive:       true,
						Amount:            50,
						AnchorOutputIndex: 1,
					},
				},
			},
			inputSum:    100,
			interactive: true,
			allocations: []*Allocation{
				{
					Type:        CommitAllocationToLocal,
					SplitRoot:   true,
					Amount:      50,
					OutputIndex: 0,
				},
				{
					Type:        CommitAllocationToRemote,
					Amount:      50,
					OutputIndex: 1,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocs, interactive, err := AllocationsFromTemplate(
				tc.template, tc.inputSum,
			)

			if tc.expectErr != "" {
				require.Contains(t, err.Error(), tc.expectErr)
				return
			}

			require.NoError(t, err)

			require.Equal(t, tc.interactive, interactive)

			// We first check that the allocations return the
			// correct script key from their generator.
			for idx := range allocs {
				// If the script key doesn't matter, we can
				// skip this part and also ignore the generator
				// in the comparison.
				if tc.allocations[idx].GenScriptKey == nil {
					allocs[idx].GenScriptKey = nil

					continue
				}

				var id asset.ID
				expected, _ := tc.allocations[idx].GenScriptKey(
					id,
				)
				actual, _ := allocs[idx].GenScriptKey(id)
				require.Equal(t, expected, actual)

				// We then remove the generator from the
				// allocation to make it easier to compare.
				allocs[idx].GenScriptKey = nil
				tc.allocations[idx].GenScriptKey = nil
			}

			require.Equal(t, tc.allocations, allocs)
		})
	}
}

// TestSortPiecesWithProofs tests that we can sort pieces of assets with their
// proofs. The sorting is done first by asset ID, then by the amount of the
// proofs in descending order and then by script key.
func TestSortPiecesWithProofs(t *testing.T) {
	key1 := asset.NewScriptKey(test.ParsePubKey(
		t, "03a15fd6e1fded33270ae01183dfc8f8edd1274644b7d014ac5ab576f"+
			"bf8328b05",
	))
	key2 := asset.NewScriptKey(test.ParsePubKey(
		t, "029191ec924fb3c6bbd0d264d0b3cf97fcb2fc1eb5737184e7e17e35c"+
			"6609ee853",
	))
	tests := []struct {
		name     string
		input    []*piece
		expected []*piece
	}{{
		name: "sort by asset ID and proofs by amount",
		input: []*piece{{
			assetID: asset.ID{0x02},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key1,
				},
			}, {
				Asset: asset.Asset{
					Amount:    300,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    100,
					ScriptKey: key2,
				},
			}},
		}, {
			assetID: asset.ID{0x01},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    200,
					ScriptKey: key1,
				},
			}, {
				Asset: asset.Asset{
					Amount:    150,
					ScriptKey: key2,
				},
			}},
		}},
		expected: []*piece{{
			assetID: asset.ID{0x01},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    200,
					ScriptKey: key1,
				},
			}, {
				Asset: asset.Asset{
					Amount:    150,
					ScriptKey: key2,
				},
			}},
		}, {
			assetID: asset.ID{0x02},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    300,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    100,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key1,
				},
			}},
		}},
	}, {
		name: "script keys after amount",
		input: []*piece{{
			assetID: asset.ID{0x01},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key1,
				},
			}, {
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key2,
				},
			}},
		}},
		expected: []*piece{{
			assetID: asset.ID{0x01},
			proofs: []*proof.Proof{{
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key2,
				},
			}, {
				Asset: asset.Asset{
					Amount:    50,
					ScriptKey: key1,
				},
			}},
		}},
	}, {
		name:     "empty input",
		input:    []*piece{},
		expected: []*piece{},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortPiecesWithProofs(tt.input)
			require.Equal(t, tt.expected, tt.input)
		})
	}
}
