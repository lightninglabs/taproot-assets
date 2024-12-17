package asset

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

type testCaseGkrEncodeDecode struct {
	testName string

	internalKey       btcec.PublicKey
	genesisAssetID    ID
	customSubtreeRoot fn.Option[chainhash.Hash]
}

// GroupKeyReveal generates a GroupKeyReveal instance from the test case.
func (tc testCaseGkrEncodeDecode) GroupKeyReveal() (GroupKeyReveal, error) {
	gkr, err := NewGroupKeyRevealV1(
		tc.internalKey, tc.genesisAssetID, tc.customSubtreeRoot,
	).Unpack()

	return &gkr, err
}

func TestGroupKeyTapscriptEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random internal public key.
	internalKey := *(test.RandPubKey(t))

	// Create a random genesis asset ID.
	randomAssetIdBytes := test.RandBytes(32)
	genesisAssetID := ID(randomAssetIdBytes)

	// Construct a custom user script leaf. This is used to validate any
	// control block.
	customScriptLeaf := txscript.NewBaseTapLeaf(
		[]byte("I'm a custom user script"),
	)
	customSubtreeRoot := fn.Some(customScriptLeaf.TapHash())

	testCases := []testCaseGkrEncodeDecode{
		{
			testName: "no custom root",

			internalKey:       internalKey,
			genesisAssetID:    genesisAssetID,
			customSubtreeRoot: fn.None[chainhash.Hash](),
		},
		{
			testName: "with custom root",

			internalKey:       internalKey,
			genesisAssetID:    genesisAssetID,
			customSubtreeRoot: customSubtreeRoot,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			gkr, err := tc.GroupKeyReveal()
			require.NoError(tt, err)

			groupPubKey, err := gkr.GroupPubKey(tc.genesisAssetID)
			require.NoError(tt, err)

			// Encode the GroupKeyReveal into buffer.
			var buffer bytes.Buffer
			var scratchBuffEncode [8]byte
			err = GroupKeyRevealEncoder(
				&buffer, &gkr, &scratchBuffEncode,
			)
			require.NoError(tt, err)

			// Decode the GroupKeyReveal from buffer.
			var gkrDecoded GroupKeyReveal
			var scratchBuffDecode [8]byte
			err = GroupKeyRevealDecoder(
				&buffer, &gkrDecoded, &scratchBuffDecode,
				uint64(buffer.Len()),
			)
			require.NoError(tt, err)

			// Prepare the original GroupKeyReveal for comparison.
			// Remove fields which are not included in
			// encoding/decoding.
			gkrV1, ok := gkr.(*GroupKeyRevealV1)
			require.True(tt, ok)
			gkrV1.tapscript.customSubtreeInclusionProof = nil

			// Compare decoded group key reveal with the original.
			require.Equal(tt, gkrV1, gkrDecoded)

			// Ensure the decoded group public key matches the
			// original.
			groupPubKeyDecoded, err := gkrDecoded.GroupPubKey(
				tc.genesisAssetID,
			)
			require.NoError(tt, err)

			require.Equal(
				tt, groupPubKey, groupPubKeyDecoded,
				"decoded GroupKeyReveal group pub key does "+
					"not match original",
			)

			// If a custom subtree root is set, ensure the control
			// block is correct.
			if tc.customSubtreeRoot.IsSome() {
				gkrDecodedV1, ok :=
					gkrDecoded.(*GroupKeyRevealV1)
				require.True(tt, ok)

				ctrlBlock, err :=
					gkrDecodedV1.ScriptSpendControlBlock(
						tc.genesisAssetID,
					).Unpack()
				require.NoError(tt, err)

				// Use the control block and the custom spend
				// script to compute the root hash.
				computedRoot := chainhash.Hash(
					ctrlBlock.RootHash(
						customScriptLeaf.Script,
					),
				)

				// Ensure the computed root matches the custom
				// subtree root.
				require.Equal(
					tt, gkrDecodedV1.tapscript.root,
					computedRoot,
				)
			}
		})
	}
}
