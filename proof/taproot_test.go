package proof

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestCreateTapscriptProof tests the creation of a TapscriptProof from a list
// of leaves.
func TestCreateTapscriptProof(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		leaves []txscript.TapLeaf
	}{
		{
			name:   "empty tree",
			leaves: nil,
		},
		{
			name: "single leaf",
			leaves: []txscript.TapLeaf{
				test.RandTapLeaf(nil),
			},
		},
		{
			name: "two leaves",
			leaves: []txscript.TapLeaf{
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
			},
		},
		{
			name: "three leaves",
			leaves: []txscript.TapLeaf{
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
			},
		},
		{
			name: "four leaves",
			leaves: []txscript.TapLeaf{
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
			},
		},
		{
			name: "more than four leaves",
			leaves: []txscript.TapLeaf{
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
				test.RandTapLeaf(nil),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsProof, err := CreateTapscriptProof(tc.leaves)
			require.NoError(t, err)

			internalKey := test.RandPubKey(t)

			var merkleRoot []byte
			if len(tc.leaves) == 0 {
				merkleRoot = []byte{}
			} else {
				tree := txscript.AssembleTaprootScriptTree(
					tc.leaves...,
				)
				merkleRoot = fn.ByteSlice(
					tree.RootNode.TapHash(),
				)
			}

			expectedKey := txscript.ComputeTaprootOutputKey(
				internalKey, merkleRoot,
			)
			expectedKey, _ = schnorr.ParsePubKey(
				schnorr.SerializePubKey(expectedKey),
			)

			proofKey, err := tsProof.DeriveTaprootKeys(internalKey)
			require.NoError(t, err)

			require.Equal(t, expectedKey, proofKey)
		})
	}
}
