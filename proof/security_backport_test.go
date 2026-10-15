package proof

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/stretchr/testify/require"
)

// and tapscript exclusion proofs with a zero-valued internal key are refused.
func TestVerifyTaprootProofZeroInternalKey(t *testing.T) {
	t.Parallel()

	proofs, _ := makeV0InclusionProof(t)
	p := proofs[0]
	validKey := p.InclusionProof.InternalKey

	emptyCommitment, err := commitment.NewTapCommitment(nil)
	require.NoError(t, err)
	addV0ExclusionOutput(
		t, p, emptyCommitment, p.Asset.TapCommitmentKey(),
		p.Asset.AssetCommitmentKey(), validKey, 1,
	)

	bip86Key := txscript.ComputeTaprootKeyNoScript(validKey)
	bip86Script, err := txscript.PayToTaprootScript(bip86Key)
	require.NoError(t, err)
	p.AnchorTx.TxOut = append(p.AnchorTx.TxOut, &wire.TxOut{
		PkScript: bip86Script,
	})

	testCases := []struct {
		name      string
		proof     TaprootProof
		inclusion bool
	}{
		{
			name:      "inclusion",
			proof:     p.InclusionProof,
			inclusion: true,
		},
		{
			name:  "asset exclusion",
			proof: p.ExclusionProofs[0],
		},
		{
			name: "tapscript exclusion",
			proof: TaprootProof{
				OutputIndex: 2,
				InternalKey: validKey,
				TapscriptProof: &TapscriptProof{
					Bip86: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyTaprootProof(
				&p.AnchorTx, &tc.proof, &p.Asset, tc.inclusion,
			)
			require.NoError(t, err)

			tc.proof.InternalKey = &btcec.PublicKey{}
			_, err = verifyTaprootProof(
				&p.AnchorTx, &tc.proof, &p.Asset, tc.inclusion,
			)
			require.ErrorContains(t, err, "invalid internal key")
		})
	}
}
