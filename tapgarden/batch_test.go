package tapgarden

import (
	"encoding/hex"
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

// TestCheckSingletonInvariant pins the contract of
// checkSingletonInvariant: it returns nil for any slice of batches
// containing at most one batch in {Pending, Frozen}, and returns a
// descriptive error otherwise. Counts both states together
// (Pending ∪ Frozen), not separately, and ignores batches in any
// other state.
func TestCheckSingletonInvariant(t *testing.T) {
	t.Parallel()

	mkBatch := func(state BatchState) *MintingBatch {
		batchKey, _ := test.RandKeyDesc(t)
		b := &MintingBatch{BatchKey: batchKey}
		b.setState(state)
		return b
	}

	t.Run("empty slice is ok", func(t *testing.T) {
		require.NoError(t, checkSingletonInvariant(nil))
	})

	t.Run("single Pending is ok", func(t *testing.T) {
		err := checkSingletonInvariant([]*MintingBatch{
			mkBatch(BatchStatePending),
		})
		require.NoError(t, err)
	})

	t.Run("single Frozen is ok", func(t *testing.T) {
		err := checkSingletonInvariant([]*MintingBatch{
			mkBatch(BatchStateFrozen),
		})
		require.NoError(t, err)
	})

	t.Run("Pending plus Committed is ok", func(t *testing.T) {
		err := checkSingletonInvariant([]*MintingBatch{
			mkBatch(BatchStatePending),
			mkBatch(BatchStateCommitted),
			mkBatch(BatchStateBroadcast),
		})
		require.NoError(t, err)
	})

	t.Run("two Pending errors", func(t *testing.T) {
		err := checkSingletonInvariant([]*MintingBatch{
			mkBatch(BatchStatePending),
			mkBatch(BatchStatePending),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "singleton")
		require.Contains(t, err.Error(), "found 2 batches")
	})

	t.Run("Pending plus Frozen errors", func(t *testing.T) {
		err := checkSingletonInvariant([]*MintingBatch{
			mkBatch(BatchStatePending),
			mkBatch(BatchStateFrozen),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "singleton")
	})

	t.Run("error names offending keys and repair tool",
		func(t *testing.T) {
			a := mkBatch(BatchStatePending)
			b := mkBatch(BatchStateFrozen)

			err := checkSingletonInvariant(
				[]*MintingBatch{a, b},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(),
				"--repair.cancel-duplicate-batches")
			// Both batch keys should appear in the error.
			require.Contains(t, err.Error(),
				hex.EncodeToString(
					a.BatchKey.PubKey.
						SerializeCompressed(),
				))
			require.Contains(t, err.Error(),
				hex.EncodeToString(
					b.BatchKey.PubKey.
						SerializeCompressed(),
				))
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

// TestUniqueAnchorSeedling pins the contract of
// MintingBatch.uniqueAnchorSeedling: it deterministically returns
// the batch's single group anchor seedling (the one with GroupAnchor
// == nil) and errors loudly when that invariant doesn't hold. The
// callers (fetchDelegationKey, fetchPreCommitGroupKey) used to scan
// non-deterministically and pick whichever seedling Go's map
// iteration handed them first; this test exists to keep them from
// regressing back to that pattern.
func TestUniqueAnchorSeedling(t *testing.T) {
	t.Parallel()

	mkAnchor := func(name string) *Seedling {
		return &Seedling{
			AssetName:      name,
			AssetType:      asset.Normal,
			Amount:         1,
			EnableEmission: true,
		}
	}

	mkChild := func(name, anchorName string) *Seedling {
		s := &Seedling{
			AssetName: name,
			AssetType: asset.Normal,
			Amount:    1,
		}
		s.GroupAnchor = &anchorName
		return s
	}

	t.Run("anchor only", func(t *testing.T) {
		batch := &MintingBatch{
			Seedlings: map[string]*Seedling{
				"a": mkAnchor("a"),
			},
		}

		got, err := batch.uniqueAnchorSeedling()
		require.NoError(t, err)
		require.Equal(t, "a", got.AssetName)
	})

	t.Run("anchor plus children", func(t *testing.T) {
		batch := &MintingBatch{
			Seedlings: map[string]*Seedling{
				"a":     mkAnchor("a"),
				"child": mkChild("child", "a"),
				"other": mkChild("other", "a"),
			},
		}

		// Run many times to defeat any incidental ordering: the
		// returned anchor must be "a" regardless of how Go
		// iterates the map.
		for i := 0; i < 32; i++ {
			got, err := batch.uniqueAnchorSeedling()
			require.NoError(t, err)
			require.Equal(t, "a", got.AssetName)
		}
	})

	t.Run("multiple anchors errors", func(t *testing.T) {
		batch := &MintingBatch{
			Seedlings: map[string]*Seedling{
				"a": mkAnchor("a"),
				"b": mkAnchor("b"),
			},
		}

		_, err := batch.uniqueAnchorSeedling()
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected exactly 1")
	})

	t.Run("no anchor errors", func(t *testing.T) {
		batch := &MintingBatch{
			Seedlings: map[string]*Seedling{
				"child1": mkChild("child1", "missing"),
				"child2": mkChild("child2", "missing"),
			},
		}

		_, err := batch.uniqueAnchorSeedling()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no group anchor")
	})

	t.Run("empty batch errors", func(t *testing.T) {
		batch := &MintingBatch{}

		_, err := batch.uniqueAnchorSeedling()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no group anchor")
	})
}

// TestSeedlingValidateCommitSplit pins the invariant that
// validateSeedling never mutates the batch -- it is the read-only
// half of AddSeedling, used by callers that need to persist a
// seedling before mirroring it into the in-memory batch. A regression
// here would silently revive the §X bug shape in prepAssetSeedling:
// an in-memory mutation that precedes the DB write that justifies it.
func TestSeedlingValidateCommitSplit(t *testing.T) {
	t.Parallel()

	mkCandidate := func(name string, supplyCommitments bool) Seedling {
		return Seedling{
			AssetName:         name,
			AssetType:         asset.Normal,
			Amount:            1,
			SupplyCommitments: supplyCommitments,
			DelegationKey:     fn.None[keychain.KeyDescriptor](),
		}
	}

	t.Run("validate on populated batch leaves it unchanged",
		func(t *testing.T) {
			batch := RandMintingBatch(
				t, WithTotalSeedlings(3),
			)
			seedlingsBefore := len(batch.Seedlings)
			supplyBefore := batch.SupplyCommitments

			candidate := mkCandidate(
				"validate-only-candidate", supplyBefore,
			)

			err := batch.validateSeedling(candidate)
			require.NoError(t, err)

			require.Equal(t, seedlingsBefore, len(batch.Seedlings))
			require.Equal(
				t, supplyBefore, batch.SupplyCommitments,
			)
			require.NotContains(
				t, batch.Seedlings, candidate.AssetName,
			)
		})

	t.Run("validate failure also leaves batch unchanged",
		func(t *testing.T) {
			batch := RandMintingBatch(
				t, WithTotalSeedlings(3),
			)
			seedlingsBefore := len(batch.Seedlings)
			supplyBefore := batch.SupplyCommitments

			// Force a SupplyCommitments mismatch so
			// validateUniCommitment rejects the seedling.
			candidate := mkCandidate(
				"validate-fail-candidate", !supplyBefore,
			)

			err := batch.validateSeedling(candidate)
			require.Error(t, err)

			require.Equal(t, seedlingsBefore, len(batch.Seedlings))
			require.Equal(
				t, supplyBefore, batch.SupplyCommitments,
			)
			require.NotContains(
				t, batch.Seedlings, candidate.AssetName,
			)
		})

	t.Run("commit on empty batch adopts SupplyCommitments",
		func(t *testing.T) {
			batch := &MintingBatch{}

			candidate := mkCandidate("first-seedling", false)

			require.NoError(t, batch.validateSeedling(candidate))

			// validateSeedling must not have set
			// SupplyCommitments even though this would be
			// "the first seedling" -- only commitSeedling may
			// do that.
			require.False(t, batch.SupplyCommitments)
			require.Empty(t, batch.Seedlings)

			batch.commitSeedling(candidate)

			require.Equal(t, 1, len(batch.Seedlings))
			require.Contains(
				t, batch.Seedlings, candidate.AssetName,
			)
			require.Equal(
				t, candidate.SupplyCommitments,
				batch.SupplyCommitments,
			)
		})
}
