package tapgarden

import (
	"testing"

	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestValidateUniCommitment tests the mint batch method validateUniCommitment.
func TestValidateUniCommitment(t *testing.T) {
	t.Parallel()

	// Define test cases.
	type TestCase struct {
		name              string
		candidateSeedling Seedling
		batch             *MintingBatch
		expectErr         bool
	}

	testCases := []TestCase{
		{
			// Verifies that a group anchor candidate seedling with
			// universe commitments cannot be added to a batch with
			// the universe commitments feature enabled
			// if the batch already contains a group anchor
			// seedling.
			name: "populated batch with universe commitments; " +
				"batch already includes group anchor; " +
				"candidate seedling is also group anchor; " +
				"is not valid",

			candidateSeedling: RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: RandMintingBatch(
				t, WithTotalGroups([]int{2}),
				WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// Ensures that a group anchor candidate seedling with
			// universe commitments cannot be added to a batch that
			// already contains seedlings and has the universe
			// commitments feature disabled.
			name: "populated batch without universe commitments; " +
				"batch already includes group anchor; " +
				"candidate seedling is also group anchor; " +
				"is not valid",

			candidateSeedling: RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: RandMintingBatch(
				t, WithTotalGroups([]int{2}),
				WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// Ensures that a group candidate seedling (non-anchor)
			// with universe commitments cannot be added to a batch
			// that already contains seedlings and has the universe
			// commitments feature disabled.
			name: "populated batch without universe commitments; " +
				"candidate seedling is non-anchor with " +
				"universe commitments; is not valid",

			candidateSeedling: RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: RandMintingBatch(
				t, WithTotalGroups([]int{2}),
				WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// Ensures that a group candidate seedling (non-anchor)
			// with universe commitments cannot be added to a batch
			// that already contains seedlings and has the universe
			// commitments feature enabled.
			//
			// This is because the anchor seedling for the candidate
			// seedling is not already present in the batch.
			name: "populated batch with universe commitments; " +
				"non-anchor candidate seedling with universe " +
				"commitments; anchor not in batch; " +
				"is not valid",

			candidateSeedling: RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: RandMintingBatch(
				t, WithTotalGroups([]int{2}),
				WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// Ensures that a group anchor candidate seedling
			// with universe commitments can be added to an empty
			// batch.
			name: "empty unfunded batch; candidate seedling is " +
				"group anchor; is valid",

			candidateSeedling: RandGroupAnchorSeedling(
				t, "some-anchor-name", true,
			),
			batch:     RandMintingBatch(t, WithSkipFunding()),
			expectErr: false,
		},
	}

	// Construct a test case where a mint batch with universe commitments
	// is populated with seedlings and a group anchor seedling is present.
	// The candidate seedling is a non-anchor group seedling with
	// universe commitments which specifies the batch group anchor seedling
	// as its anchor. The candidate seedling should be deemed valid.
	batch := RandMintingBatch(
		t, WithTotalGroups([]int{2}), WithUniverseCommitments(true),
	)

	// Identify the anchor seedling in the batch.
	var anchorSeedling *Seedling
	for idx := range batch.Seedlings {
		seedling := batch.Seedlings[idx]
		if seedling.GroupAnchor == nil {
			anchorSeedling = seedling
			break
		}
	}

	// Construct a candidate seedling that is a non-anchor group seedling
	// with universe commitments and specifies the batch group anchor
	// seedling as its anchor.
	candidateSeedling := RandNonAnchorGroupSeedling(
		t, anchorSeedling.AssetVersion, anchorSeedling.AssetType,
		anchorSeedling.AssetName, anchorSeedling.Meta.Data,
		anchorSeedling.DelegationKey,
		anchorSeedling.SupplyCommitments,
	)

	testCases = append(testCases, TestCase{
		name: "populated batch with universe commitments; " +
			"candidate seedling is non-anchor group seedling " +
			"with universe commitments; anchor in batch; " +
			"is valid",
		candidateSeedling: candidateSeedling,
		batch:             batch,
		expectErr:         false,
	})

	// Construct a test case where an empty but funded mint batch is
	// populated with a group anchor seedling. The candidate seedling has
	// universe commitments enabled. We expect the candidate seedling to be
	// deemed invalid. This is because the batch is already funded and
	// therefore the universe commitments feature cannot be enabled.
	fundedEmptyBatch := RandMintingBatch(t)

	// Set the genesis packet of the empty batch to simulate funding.
	fundedEmptyBatch.GenesisPacket = &FundedMintAnchorPsbt{}

	testCases = append(testCases, TestCase{
		name: "empty funded batch; candidate seedling is anchor " +
			"group seedling with universe commitments; is valid",
		candidateSeedling: RandGroupAnchorSeedling(
			t, "some-anchor-name", true,
		),
		batch:     fundedEmptyBatch,
		expectErr: true,
	})

	// Add a test case where the batch is funded and empty but universe
	// commitments is not enabled for the candidate seedling. The candidate
	// seedling should be deemed valid. The universe commitment feature
	// restriction does not apply in this case.
	testCases = append(testCases, TestCase{
		name: "empty funded batch; candidate seedling is anchor " +
			"group seedling with universe commitments; is valid",
		candidateSeedling: RandGroupAnchorSeedling(
			t, "some-anchor-name", false,
		),
		batch:     fundedEmptyBatch,
		expectErr: false,
	})

	// Execute test cases.
	for idx := range testCases {
		tc := testCases[idx]

		t.Run(tc.name, func(t *testing.T) {
			err := tc.batch.validateUniCommitment(
				tc.candidateSeedling,
			)

			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestMintingBatchCopy tests that MintingBatch.Copy() works as expected.
func TestMintingBatchCopy(t *testing.T) {
	t.Run("deep copy seedlings", func(t *testing.T) {
		// Set to true to debug print.
		debug := false

		// Please set the depth value carefully. Sometimes our copy
		// functions are deeply nested in other packages and do not need
		// changes. Often types are recursive and too deep copy may end
		// up in stack-overlow.
		const maxDepth = 6
		p := &MintingBatch{}
		test.FillFakeData(t, debug, maxDepth, p)

		// Ensure we have deterministic seedlings to probe for aliasing.
		p.Seedlings = map[string]*Seedling{
			"seed-a": {
				AssetName: "seed-a",
				Amount:    1,
			},
			"seed-b": {
				AssetName: "seed-b",
				Amount:    2,
			},
		}

		// We allow aliasing here deep down (for now).
		strict := false
		test.AssertCopyEqual(t, debug, strict, p)

		copyBatch := p.Copy()

		// Mutate the original to ensure the seedlings map and its
		// entries were deep copied.
		p.Seedlings["seed-a"].Amount = 999
		delete(p.Seedlings, "seed-b")
		p.Seedlings["seed-c"] = &Seedling{
			AssetName: "seed-c",
			Amount:    3,
		}

		require.Len(t, copyBatch.Seedlings, 2)
		require.Contains(t, copyBatch.Seedlings, "seed-a")
		require.Contains(t, copyBatch.Seedlings, "seed-b")
		require.NotContains(t, copyBatch.Seedlings, "seed-c")
		require.Equal(
			t, uint64(1), copyBatch.Seedlings["seed-a"].Amount,
		)
	})

	t.Run("nil and empty seedlings map", func(t *testing.T) {
		var batch MintingBatch

		nilCopy := batch.Copy()
		require.Nil(t, nilCopy.Seedlings)

		batch.Seedlings = map[string]*Seedling{}
		emptyCopy := batch.Copy()

		require.NotNil(t, emptyCopy.Seedlings)
		require.Empty(t, emptyCopy.Seedlings)

		batch.Seedlings["new"] = &Seedling{AssetName: "new"}
		require.Empty(t, emptyCopy.Seedlings)
	})
}

// TestMintingOutputKeyPureInSibling pins the contract that
// MintingOutputKey is a function of (batch, sibling): two calls
// with different siblings must produce different output keys, two
// calls with the same sibling must produce the same key. A
// regression that re-introduced the memoizing cache would silently
// return the first call's value on every subsequent call regardless
// of the sibling argument.
func TestMintingOutputKeyPureInSibling(t *testing.T) {
	t.Parallel()

	// Construct a batch with a real RootAssetCommitment so
	// MintingOutputKey can compute the tapscript root.
	batchKey, _ := test.RandKeyDesc(t)
	randAsset := asset.RandAsset(t, asset.Normal)
	tapCommitment, err := commitment.FromAssets(
		fn.Ptr(commitment.TapCommitmentV2), randAsset,
	)
	require.NoError(t, err)

	batch := &MintingBatch{
		BatchKey:            batchKey,
		RootAssetCommitment: tapCommitment,
	}

	// Build two distinct sibling preimages. We use two single-leaf
	// trees with different scripts; their TapHashes will differ,
	// so a sibling-sensitive MintingOutputKey must return distinct
	// output keys.
	mkSibling := func(scriptByte byte) *commitment.TapscriptPreimage {
		leaf := txscript.NewBaseTapLeaf([]byte{scriptByte})
		nodes, err := asset.TapTreeNodesFromLeaves(
			[]txscript.TapLeaf{leaf},
		)
		require.NoError(t, err)

		preimage, err := commitment.
			NewPreimageFromTapscriptTreeNodes(*nodes)
		require.NoError(t, err)
		return preimage
	}

	siblingA := mkSibling(0x01)
	siblingB := mkSibling(0x02)

	keyA, rootA, err := batch.MintingOutputKey(siblingA)
	require.NoError(t, err)
	keyB, rootB, err := batch.MintingOutputKey(siblingB)
	require.NoError(t, err)

	// Different siblings must yield different output keys and
	// different tapscript roots. If the cache regressed, keyB
	// would equal keyA.
	require.False(
		t, keyA.IsEqual(keyB),
		"MintingOutputKey must depend on its sibling argument",
	)
	require.NotEqual(t, rootA, rootB)

	// Same sibling must yield the same key both times: the
	// function is deterministic, not stateful.
	keyAgain, rootAgain, err := batch.MintingOutputKey(siblingA)
	require.NoError(t, err)
	require.True(t, keyA.IsEqual(keyAgain))
	require.Equal(t, rootA, rootAgain)

	// Calling with nil sibling produces yet another distinct key
	// (it commits to no sibling, equivalent to "the empty tree
	// branch"). Important to assert because the caretaker's
	// BatchStateCommitted branch used to pass nil and rely on the
	// cache for the actual sibling-bearing value.
	keyNil, _, err := batch.MintingOutputKey(nil)
	require.NoError(t, err)
	require.False(
		t, keyNil.IsEqual(keyA),
		"MintingOutputKey(nil) must not return the same value "+
			"as MintingOutputKey(siblingA)",
	)
}
