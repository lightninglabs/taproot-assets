package proof

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

func TestCommitmentProofsDecoderRoundTrip(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	numProofs := 4
	proofs := make(map[asset.SerializedKey]commitment.Proof, numProofs)
	for range numProofs {
		genesis := asset.RandGenesis(t, asset.Collectible)
		scriptKey := test.RandPubKey(t)
		randProof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)
		randCommitmentProof := randProof.InclusionProof.CommitmentProof
		serializedKey := asset.SerializedKey(
			test.RandPubKey(t).SerializeCompressed(),
		)
		proofs[serializedKey] = randCommitmentProof.Proof
	}

	var buf [8]byte

	// Helper function to encode a map of commitment proofs.
	encodeProofs := func(
		proofs map[asset.SerializedKey]commitment.Proof) []byte {

		var b bytes.Buffer
		err := CommitmentProofsEncoder(&b, &proofs, &buf)
		require.NoError(t, err)
		return b.Bytes()
	}

	// Helper function to decode a map of commitment proofs.
	decodeProofs := func(
		encoded []byte) map[asset.SerializedKey]commitment.Proof {

		var decodedProofs map[asset.SerializedKey]commitment.Proof
		err := CommitmentProofsDecoder(
			bytes.NewReader(encoded), &decodedProofs, &buf,
			uint64(len(encoded)),
		)
		require.NoError(t, err)
		return decodedProofs
	}

	// Test case: round trip encoding and decoding.
	t.Run(
		"encode and decode map of 4 random commitment proofs",
		func(t *testing.T) {
			// Encode the proofs.
			encoded := encodeProofs(proofs)

			// Decode the proofs.
			decodedProofs := decodeProofs(encoded)

			// Assert the decoded proofs match the original.
			require.Equal(t, proofs, decodedProofs)
		},
	)

	// Test case: empty map.
	t.Run(
		"encode and decode empty map of commitment proofs",
		func(t *testing.T) {
			// Create an empty map of commitment emptyMap.
			emptyMap := map[asset.SerializedKey]commitment.Proof{}

			// Encode the proofs.
			encoded := encodeProofs(emptyMap)

			// Decode the proofs.
			decodedMap := decodeProofs(encoded)

			// Assert the decoded proofs match the original.
			require.Equal(t, emptyMap, decodedMap)
		},
	)
}
