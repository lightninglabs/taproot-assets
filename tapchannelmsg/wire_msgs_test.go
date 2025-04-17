package tapchannelmsg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestAssetFundingMsg tests encoding and decoding of the AssetFundingMsg
// structs.
func TestAssetFundingMsg(t *testing.T) {
	t.Parallel()

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	randGen := asset.RandGenesis(t, asset.Normal)
	scriptKey1 := test.RandPubKey(t)
	originalRandProof := proof.RandProof(
		t, randGen, scriptKey1, oddTxBlock, 0, 1,
	)

	// Proofs don't Encode everything, so we need to do a quick Encode/
	// Decode cycle to make sure we can compare it afterward.
	proofBytes, err := originalRandProof.Bytes()
	require.NoError(t, err)
	randProof, err := proof.Decode(proofBytes)
	require.NoError(t, err)

	proofChunks, err := CreateProofChunks(*randProof, 100)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		msg   AssetFundingMsg
		empty func() AssetFundingMsg
	}{
		{
			name: "TxAssetInputProof",
			msg: NewTxAssetInputProof(
				[32]byte{1}, randProof.Asset.ID(),
				randProof.Asset.Amount, proofChunks[0],
			),
			empty: func() AssetFundingMsg {
				return &TxAssetInputProof{}
			},
		},
		{
			name: "TxAssetOutputProof",
			msg: NewTxAssetOutputProof(
				[32]byte{1}, randProof.Asset, true,
			),
			empty: func() AssetFundingMsg {
				return &TxAssetOutputProof{}
			},
		},
		{
			name: "AssetFundingCreated",
			msg: NewAssetFundingCreated(
				[32]byte{1}, []*AssetOutput{
					NewAssetOutput(
						[32]byte{2}, 1, *randProof,
					),
				},
			),
			empty: func() AssetFundingMsg {
				return &AssetFundingCreated{}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the message and then deserialize it again.
			var b bytes.Buffer
			err := tc.msg.Encode(&b, 0)
			require.NoError(t, err)

			deserializedMsg := tc.empty()
			err = deserializedMsg.Decode(&b, 0)
			require.NoError(t, err)

			require.Equal(t, tc.msg, deserializedMsg)
		})
	}
}

// loadOddTxBlock loads a block from a file containing a hex-encoded block.
func loadOddTxBlock(t *testing.T, fileName string) wire.MsgBlock {
	oddTxBlockHex, err := os.ReadFile(fileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.TrimSpace(string(oddTxBlockHex)),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	return oddTxBlock
}

// TestProofChunkRoundTripProperty tests that proof chunks can be split and then
// reassembled without losing any information.
func TestProofChunkRoundTripProperty(t *testing.T) {
	oddTxBlock := loadOddTxBlock(t, oddTxBlockHexFileName)

	rapid.Check(t, func(r *rapid.T) {
		// Make sure the asset type is normal or collectible.
		randGen := asset.GenesisGen.Draw(r, "randGen")
		randGen.Type = asset.Type(
			rapid.IntRange(0, 1).Draw(r, "assetType"),
		)

		scriptKey := asset.PubKeyGen.Draw(r, "scriptKey")

		originalRandProof := proof.RandProof(
			t, randGen, scriptKey, oddTxBlock, 0, 1,
		)

		// Encode the original proof.
		var origBuf bytes.Buffer
		err := originalRandProof.Encode(&origBuf)
		require.NoError(r, err)

		// Randomize the chunk size. We ensure at least 1 to avoid
		// division by zero.
		chunkSize := rapid.IntRange(
			100, origBuf.Len()+50,
		).Draw(r, "chunkSize")

		chunks, err := CreateProofChunks(originalRandProof, chunkSize)
		require.NoError(r, err)

		// The last chunk should have the Last attribute set.
		require.True(r, chunks[len(chunks)-1].Last.Val)

		reconstructedProof, err := AssembleProofChunks(chunks)
		require.NoError(r, err)

		// Encode the reconstructed proof for comparison.
		var reconBuf bytes.Buffer
		err = reconstructedProof.Encode(&reconBuf)
		require.NoError(r, err)

		// Ensure original and reconstructed proofs match.
		require.Equal(r, origBuf.Bytes(), reconBuf.Bytes(),
			"reconstructed proof does not match the original")
	})
}

// // TestProofChunkErrorCases tests error cases for proof chunking and
// assembly. This will try invalid chunk sizes and also corrupt chunks.
func TestProofChunkErrorCases(t *testing.T) {
	oddTxBlock := loadOddTxBlock(t, oddTxBlockHexFileName)

	rapid.Check(t, func(r *rapid.T) {
		// Make sure the asset type is normal or collectible.
		randGen := asset.GenesisGen.Draw(r, "randGen")
		randGen.Type = asset.Type(
			rapid.IntRange(0, 1).Draw(r, "assetType"),
		)

		scriptKey := asset.PubKeyGen.Draw(r, "scriptKey")

		originalRandProof := proof.RandProof(
			t, randGen, scriptKey, oddTxBlock, 0, 1,
		)

		var origBuf bytes.Buffer
		err := originalRandProof.Encode(&origBuf)
		require.NoError(r, err)

		// We’ll try some invalid chunk sizes to trigger errors:
		invalidChunkSize := rapid.IntRange(-10, 0).Draw(
			r, "invalidChunkSize",
		)
		_, err = CreateProofChunks(originalRandProof, invalidChunkSize)

		// If the chunk size is invalid, we should get an error.
		if invalidChunkSize <= 0 {
			require.ErrorIs(r, err, ErrChunkSize, "Expected an "+
				"error for non-positive chunk size")
		}

		// We'll now test for invalid chunking. To start, we'll make a
		// valid set of proof chunks.
		chunkSize := rapid.IntRange(100, origBuf.Len()+10).Draw(
			r, "chunkSize",
		)
		chunks, err := CreateProofChunks(originalRandProof, chunkSize)
		require.NoError(r, err)

		// We'll modify the chunk digest to trigger an error.
		if len(chunks) > 1 {
			// Corrupt the digest in one chunk.
			badChunkIndex := rapid.IntRange(0, len(chunks)-1).Draw(
				r, "badChunkIndex",
			)
			chunks[badChunkIndex].ChunkSumID.Val = sha256.Sum256(
				[]byte("corruption"),
			)

			_, err := AssembleProofChunks(chunks)
			require.ErrorIs(
				r, err, ErrChunkDistUniformity,
				"expected error due to mismatched chunk digest",
			)
		}

		// Obtain a new set of chunks.
		chunks, err = CreateProofChunks(originalRandProof, chunkSize)
		require.NoError(r, err)

		// Next, we'll corrupt the chunk itself so decoding fails.
		if len(chunks) > 0 {
			// Introduce random bytes that can't represent a valid
			// proof.
			badChunkIndex := rapid.IntRange(0, len(chunks)-1).Draw(
				r, "badChunkIndex2",
			)
			chunks[badChunkIndex].Chunk.Val = nil

			_, err := AssembleProofChunks(chunks)
			require.ErrorIs(
				r, err, ErrChunkDigestMismatch,
				"expected error due to invalid proof "+
					"decoding, got %v", err,
			)
		}

		// We'll also test the case of an empty set of chunks.
		_, err = AssembleProofChunks([]ProofChunk{})
		require.ErrorIs(
			r, err, ErrNoChunks,
			"expected error assembling from empty chunk list",
		)
	})
}
