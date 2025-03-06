package tapgarden

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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
			name: "empty batch; candidate seedling is group " +
				"anchor; is valid",

			candidateSeedling: RandGroupAnchorSeedling(
				t, "some-anchor-name", true,
			),
			batch:     RandMintingBatch(t),
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
		anchorSeedling.UniverseCommitments,
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
