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
	"pgregory.net/rapid"
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
	)

	return &gkr, err
}

// TestGroupKeyRevealEncodeDecode tests encoding and decoding of GroupKeyReveal.
func TestGroupKeyRevealEncodeDecode(t *testing.T) {
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
					)
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

// TestGroupKeyRevealEncodeDecodeRapid tests encoding and decoding of
// GroupKeyReveal using rapid testing. The Rapid framework is used to generate
// random test inputs.
func TestGroupKeyRevealEncodeDecodeRapid(tt *testing.T) {
	tt.Parallel()

	rapid.Check(tt, func(t *rapid.T) {
		// Generate random test inputs using rapid generators.
		//
		// Generate a random internal key.
		internalKeyBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).
			Draw(t, "internal_key_bytes")
		_, publicKey := btcec.PrivKeyFromBytes(internalKeyBytes)
		internalKey := *publicKey

		// Generate a random genesis asset ID.
		genesisAssetID := ID(rapid.SliceOfN(rapid.Byte(), 32, 32).
			Draw(t, "genesis_id"))

		// Randomly decide whether to include a custom script.
		hasCustomScript := rapid.Bool().Draw(t, "has_custom_script")

		// If a custom script is included, generate a random script leaf
		// and subtree root.
		var customSubtreeRoot fn.Option[chainhash.Hash]
		var customScriptLeaf *txscript.TapLeaf

		if hasCustomScript {
			// Generate random script between 1-100 bytes.
			scriptSize := rapid.IntRange(1, 100).
				Draw(t, "script_size")
			customScript := rapid.SliceOfN(
				rapid.Byte(), scriptSize, scriptSize,
			).Draw(t, "custom_script")

			leaf := txscript.NewBaseTapLeaf(customScript)
			customScriptLeaf = &leaf
			customSubtreeRoot = fn.Some(customScriptLeaf.TapHash())
		} else {
			customSubtreeRoot = fn.None[chainhash.Hash]()
		}

		// Create a new GroupKeyReveal instance from the random test
		// inputs.
		gkrV1, err := NewGroupKeyRevealV1(
			internalKey,
			genesisAssetID,
			customSubtreeRoot,
		)
		require.NoError(t, err)

		// Encode the GroupKeyReveal instance into a buffer.
		var buffer bytes.Buffer
		var scratchBuffEncode [8]byte
		gkr := GroupKeyReveal(&gkrV1)
		err = GroupKeyRevealEncoder(&buffer, &gkr, &scratchBuffEncode)
		require.NoError(t, err)

		// Decode the GroupKeyReveal instance from the buffer.
		var gkrDecoded GroupKeyReveal
		var scratchBuffDecode [8]byte
		err = GroupKeyRevealDecoder(
			&buffer, &gkrDecoded, &scratchBuffDecode,
			uint64(buffer.Len()),
		)
		require.NoError(t, err)

		// Prepare for comparison by removing non-encoded fields from
		// the original GroupKeyReveal.
		gkrV1.tapscript.customSubtreeInclusionProof = nil

		// Compare decoded with original.
		require.Equal(t, &gkrV1, gkrDecoded)

		// Verify decoded group public key.
		//
		// First derive a group public key from the original.
		groupPubKey, err := gkrV1.GroupPubKey(genesisAssetID)
		require.NoError(t, err)

		// Then derive a group public key from the decoded.
		groupPubKeyDecoded, err := gkrDecoded.GroupPubKey(
			genesisAssetID,
		)
		require.NoError(t, err)

		require.Equal(t, groupPubKey, groupPubKeyDecoded)

		// If a custom subtree root is set on the decoded
		// GroupKeyReveal, ensure the derived control block is correct.
		if customSubtreeRoot.IsSome() && customScriptLeaf != nil {
			gkrDecodedV1, ok := gkrDecoded.(*GroupKeyRevealV1)
			require.True(t, ok)

			ctrlBlock, err := gkrDecodedV1.ScriptSpendControlBlock(
				genesisAssetID,
			)
			require.NoError(t, err)

			computedRoot := chainhash.Hash(
				ctrlBlock.RootHash(customScriptLeaf.Script),
			)

			// Ensure the computed root matches the tapscript root
			// for both the original and decoded GroupKeyReveal.
			require.Equal(
				t, gkrV1.tapscript.root, computedRoot,
			)
			require.Equal(
				t, gkrDecodedV1.tapscript.root, computedRoot,
			)
		}
	})
}
