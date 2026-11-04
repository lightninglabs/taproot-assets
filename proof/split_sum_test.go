package proof

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/vm"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// rebuildSplit returns a callback for newTestSplitAnchor that rebuilds the
// split tree of the given split, with a single split asset, as a tree of
// branches of the given version over the root locator leaf and the split
// leaf, with the given amounts, and signs the root asset.
func rebuildSplit(t *testing.T, genesis *splitGenesis, split *testSplit,
	version mssmt.BranchVersion,
	rootAmount, splitAmount uint64) func(*asset.Asset, []*asset.Asset) {

	return func(root *asset.Asset, splits []*asset.Asset) {
		require.Len(t, splits, 1)
		splitAsset := splits[0]

		ctx := context.Background()

		root.Amount = rootAmount
		splitAsset.Amount = splitAmount

		rootKey := commitment.SplitLocator{
			OutputIndex: split.rootOutput,
			AssetID:     root.ID(),
			ScriptKey:   asset.ToSerialized(root.ScriptKey.PubKey),
		}.Hash()
		splitKey := commitment.SplitLocator{
			OutputIndex: split.splitOutputs[0],
			AssetID:     splitAsset.ID(),
			ScriptKey: asset.ToSerialized(
				splitAsset.ScriptKey.PubKey,
			),
		}.Hash()

		rootLeafAsset := root.Copy()
		rootLeafAsset.SplitCommitmentRoot = nil
		rootLeafAsset.PrevWitnesses = []asset.Witness{{
			PrevID: &asset.ZeroPrevID,
		}}
		rootLeaf, err := rootLeafAsset.Leaf()
		require.NoError(t, err)

		splitLeafAsset := splitAsset.Copy()
		splitLeafAsset.PrevWitnesses[0].SplitCommitment = nil
		splitLeaf, err := splitLeafAsset.Leaf()
		require.NoError(t, err)

		tree := mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
			mssmt.WithBranchVersion(version),
		)
		_, err = tree.Insert(ctx, rootKey, rootLeaf)
		require.NoError(t, err)
		_, err = tree.Insert(ctx, splitKey, splitLeaf)
		require.NoError(t, err)

		splitRoot, err := tree.Root(ctx)
		require.NoError(t, err)
		rootProof, err := tree.MerkleProof(ctx, rootKey)
		require.NoError(t, err)
		splitProof, err := tree.MerkleProof(ctx, splitKey)
		require.NoError(t, err)

		root.SplitCommitmentRoot = mssmt.NewComputedNode(
			splitRoot.NodeHash(), splitRoot.NodeSum(),
		)
		splitAsset.PrevWitnesses[0].SplitCommitment =
			&asset.SplitCommitment{
				Proof:     *splitProof,
				RootAsset: *root.Copy(),
			}
		split.locatorProof = *rootProof

		genesis.sign(root, splits)
	}
}

// splitSumProofs creates the proofs of the root asset and the split asset of
// a split of a 100-unit genesis asset, rebuilt as by rebuildSplit, and returns
// them with a function that verifies a proof under the given split tree
// activation height. The proof is anchored at height 100, or, with
// WithSkipChainVerificationForFinalProof, unconfirmed with the block after
// the chain tip at height 100.
func splitSumProofs(t *testing.T, version mssmt.BranchVersion, rootAmount,
	splitAmount uint64) (*Proof, *Proof,
	func(*Proof, lfn.Option[uint32], ...VerifyOption) error) {

	t.Helper()

	const (
		rootOutput = iota
		splitOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	rebuild := rebuildSplit(
		t, genesis, split, version, rootAmount, splitAmount,
	)
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, rebuild, split,
	)

	rootProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.rootParams(t, split),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	splitProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.splitParams(t, split, 0),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	vCtx := withChainTip(MockVerifierCtx, 99)
	vCtx.ActivationHeight = lfn.Some(uint32(100))

	verify := func(p *Proof, splitTreeHeight lfn.Option[uint32],
		opts ...VerifyOption) error {

		vCtx := vCtx
		vCtx.SplitTreeActivationHeight = splitTreeHeight

		p.BlockHeight = 100

		f, err := NewFile(V0, genesis.proof, *p)
		require.NoError(t, err)

		_, err = f.Verify(context.Background(), vCtx, opts...)

		return err
	}

	return rootProof, splitProof, verify
}

// TestSplitTreeV1 tests that the proofs of a split with a BranchV1 split tree
// verify.
func TestSplitTreeV1(t *testing.T) {
	t.Parallel()

	rootProof, splitProof, verify := splitSumProofs(
		t, mssmt.BranchV1, 60, 40,
	)

	require.NoError(t, verify(rootProof, lfn.None[uint32]()))
	require.NoError(t, verify(splitProof, lfn.None[uint32]()))
}

// TestSplitTreeActivation tests that the proofs of a split with a BranchV0
// split tree verify only below the split tree activation height, and those of
// a split with a BranchV1 split tree verify at any height.
func TestSplitTreeActivation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		version         mssmt.BranchVersion
		splitTreeHeight lfn.Option[uint32]
		valid           bool
	}{{
		name:            "V0 without activation height",
		version:         mssmt.BranchV0,
		splitTreeHeight: lfn.None[uint32](),
		valid:           true,
	}, {
		name:            "V0 below activation height",
		version:         mssmt.BranchV0,
		splitTreeHeight: lfn.Some(uint32(101)),
		valid:           true,
	}, {
		name:            "V0 at activation height",
		version:         mssmt.BranchV0,
		splitTreeHeight: lfn.Some(uint32(100)),
	}, {
		name:            "V1 below activation height",
		version:         mssmt.BranchV1,
		splitTreeHeight: lfn.Some(uint32(101)),
		valid:           true,
	}, {
		name:            "V1 at activation height",
		version:         mssmt.BranchV1,
		splitTreeHeight: lfn.Some(uint32(100)),
		valid:           true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rootProof, splitProof, verify := splitSumProofs(
				t, tc.version, 60, 40,
			)

			for _, p := range []*Proof{rootProof, splitProof} {
				err := verify(p, tc.splitTreeHeight)
				if tc.valid {
					require.NoError(t, err)
					continue
				}

				var vmErr vm.Error
				require.ErrorAs(t, err, &vmErr)
				require.Equal(
					t, vm.ErrInvalidSplitCommitmentProof,
					vmErr.Kind,
				)
			}
		})
	}
}

// TestSplitTreeActivationUnconfirmed tests that the proofs of an unconfirmed
// split with a BranchV0 split tree verify only while the block after the chain
// tip is below the split tree activation height, and those of an unconfirmed
// split with a BranchV1 split tree verify regardless.
func TestSplitTreeActivationUnconfirmed(t *testing.T) {
	t.Parallel()

	// The block after the chain tip is at height 100.
	tests := []struct {
		name            string
		version         mssmt.BranchVersion
		splitTreeHeight lfn.Option[uint32]
		valid           bool
	}{{
		name:            "V0 below activation height",
		version:         mssmt.BranchV0,
		splitTreeHeight: lfn.Some(uint32(101)),
		valid:           true,
	}, {
		name:            "V0 at activation height",
		version:         mssmt.BranchV0,
		splitTreeHeight: lfn.Some(uint32(100)),
	}, {
		name:            "V1 below activation height",
		version:         mssmt.BranchV1,
		splitTreeHeight: lfn.Some(uint32(101)),
		valid:           true,
	}, {
		name:            "V1 at activation height",
		version:         mssmt.BranchV1,
		splitTreeHeight: lfn.Some(uint32(100)),
		valid:           true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rootProof, splitProof, verify := splitSumProofs(
				t, tc.version, 60, 40,
			)

			unconfirmed := WithSkipChainVerificationForFinalProof()
			for _, p := range []*Proof{rootProof, splitProof} {
				err := verify(
					p, tc.splitTreeHeight, unconfirmed,
				)
				if tc.valid {
					require.NoError(t, err)
					continue
				}

				var vmErr vm.Error
				require.ErrorAs(t, err, &vmErr)
				require.Equal(
					t, vm.ErrInvalidSplitCommitmentProof,
					vmErr.Kind,
				)
			}
		})
	}
}
