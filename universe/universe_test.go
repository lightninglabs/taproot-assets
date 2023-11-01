package universe

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// randGenesisAsset returns a random asset that is a genesis asset.
func randGenesisAsset(t testing.TB) asset.Asset {
	a := *asset.RandAsset(t, asset.Normal)
	require.True(t, a.IsGenesisAsset())
	return a
}

// randTransferredAsset returns a random asset that is a transferred
// (non-genesis) asset.
func randTransferredAsset(t testing.TB) asset.Asset {
	a := *asset.RandAsset(t, asset.Normal)

	// Populate the previous witnesses with multiple entries to ensure that
	// the asset is not a genesis asset.
	a.PrevWitnesses = []asset.Witness{
		{
			PrevID: &asset.PrevID{
				ScriptKey: asset.RandSerializedKey(t),
			},
			TxWitness:       nil,
			SplitCommitment: nil,
		},
		{
			PrevID: &asset.PrevID{
				ScriptKey: asset.RandSerializedKey(t),
			},
			TxWitness:       nil,
			SplitCommitment: nil,
		},
	}

	require.False(t, a.IsGenesisAsset())
	return a
}

// TestValidateProofUniverseType tests that ValidateProofUniverseType returns
// the expected error when the proof type does not match the universe type.
func TestValidateProofUniverseType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		proof     proof.Proof
		uniID     Identifier
		expectErr bool
	}{
		{
			name: "transfer proof, transfer universe",
			proof: proof.Proof{
				Asset: randTransferredAsset(t),
			},
			uniID: Identifier{
				ProofType: ProofTypeTransfer,
			},
			expectErr: false,
		},
		{
			name: "transfer proof, issuance universe",
			proof: proof.Proof{
				Asset: randTransferredAsset(t),
			},
			uniID: Identifier{
				ProofType: ProofTypeIssuance,
			},
			expectErr: true,
		},
		{
			name: "issuance proof, issuance universe",
			proof: proof.Proof{
				Asset: randGenesisAsset(t),
			},
			uniID: Identifier{
				ProofType: ProofTypeIssuance,
			},
			expectErr: false,
		},
		{
			name: "issuance proof, transfer universe",
			proof: proof.Proof{
				Asset: randGenesisAsset(t),
			},
			uniID: Identifier{
				ProofType: ProofTypeTransfer,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			err := ValidateProofUniverseType(
				&tc.proof.Asset, tc.uniID,
			)
			require.True(t, tc.expectErr == (err != nil), err)
		})
	}
}
