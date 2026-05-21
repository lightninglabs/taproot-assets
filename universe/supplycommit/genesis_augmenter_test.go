package supplycommit_test

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestAugmenterValidateSeedling exercises the supply-commit
// invariants that the GenesisAugmenter enforces at seedling
// intake. These tests previously lived on
// MintingBatch.validateUniCommitment in tapgarden; they moved
// with the invariant.
func TestAugmenterValidateSeedling(t *testing.T) {
	t.Parallel()

	aug := supplycommit.NewGenesisAugmenter(
		supplycommit.GenesisAugmenterCfg{},
	)

	type tc struct {
		name      string
		candidate tapgarden.Seedling
		batch     *tapgarden.MintingBatch
		expectErr bool
	}

	cases := []tc{
		{
			// Multiple group anchors in a uni-commit batch
			// is not allowed.
			name: "populated batch with universe commitments; " +
				"candidate is a second group anchor; invalid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// A uni-commit candidate cannot enter a
			// non-uni-commit batch.
			name: "populated batch without universe commitments; " +
				"uni-commit candidate; invalid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// A non-anchor uni-commit candidate referencing
			// an absent anchor must be rejected.
			name: "populated batch without universe commitments; " +
				"non-anchor uni-commit candidate; invalid",
			candidate: tapgarden.RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// A non-anchor uni-commit candidate referencing
			// an absent anchor in a uni-commit batch.
			name: "populated uni-commit batch; anchor absent; " +
				"invalid",
			candidate: tapgarden.RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// Group anchor candidate into an empty unfunded
			// batch is fine.
			name: "empty unfunded batch; group anchor candidate; " +
				"valid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "some-anchor-name", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithSkipFunding(),
			),
			expectErr: false,
		},
	}

	// Construct a positive case: a uni-commit batch with a
	// group anchor and a non-anchor candidate that correctly
	// references it.
	batch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalGroups([]int{2}),
		tapgarden.WithUniverseCommitments(true),
	)
	var anchor *tapgarden.Seedling
	for _, s := range batch.Seedlings {
		if s.GroupAnchor == nil {
			anchor = s
			break
		}
	}
	cases = append(cases, tc{
		name: "populated uni-commit batch; non-anchor " +
			"candidate references existing anchor; valid",
		candidate: tapgarden.RandNonAnchorGroupSeedling(
			t, anchor.AssetVersion, anchor.AssetType,
			anchor.AssetName, anchor.Meta.Data,
			anchor.DelegationKey, anchor.SupplyCommitments,
		),
		batch:     batch,
		expectErr: false,
	})

	// Funded-but-empty uni-commit batch must reject a
	// uni-commit candidate.
	fundedEmptyBatch := tapgarden.RandMintingBatch(t)
	fundedEmptyBatch.GenesisPacket = &tapgarden.FundedMintAnchorPsbt{}
	cases = append(cases, tc{
		name: "empty funded batch; uni-commit candidate; invalid",
		candidate: tapgarden.RandGroupAnchorSeedling(
			t, "some-anchor-name", true,
		),
		batch:     fundedEmptyBatch,
		expectErr: true,
	})
	cases = append(cases, tc{
		name: "empty funded batch; non-uni-commit candidate; valid",
		candidate: tapgarden.RandGroupAnchorSeedling(
			t, "some-anchor-name", false,
		),
		batch:     fundedEmptyBatch,
		expectErr: false,
	})

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := aug.ValidateSeedling(c.batch, c.candidate)
			if c.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
