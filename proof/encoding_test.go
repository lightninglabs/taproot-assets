package proof

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
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

	// Helper function to decode the keys of an encoded map of commitment
	// proofs, in the order they are encoded in.
	decodeKeys := func(encoded []byte) []asset.SerializedKey {
		r := bytes.NewReader(encoded)

		numKeys, err := tlv.ReadVarInt(r, &buf)
		require.NoError(t, err)

		keys := make([]asset.SerializedKey, numKeys)
		for i := range keys {
			_, err := io.ReadFull(r, keys[i][:])
			require.NoError(t, err)

			var proofBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &proofBytes, &buf, MaxTaprootProofSizeBytes,
			)
			require.NoError(t, err)
		}
		require.Zero(t, r.Len())

		return keys
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

	// Test case: the proofs are encoded sorted by their key, whatever the
	// iteration order of the map.
	t.Run(
		"encode map of 4 random commitment proofs in key order",
		func(t *testing.T) {
			byKey := func(a, b asset.SerializedKey) int {
				return bytes.Compare(a[:], b[:])
			}

			// A single encoding may be sorted by chance, so we
			// encode the proofs several times.
			for range 10 {
				keys := decodeKeys(encodeProofs(proofs))
				require.Len(t, keys, numProofs)
				require.True(
					t, slices.IsSortedFunc(keys, byKey),
				)
			}
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

// TestRootLocatorProofDecoderTrailingData checks that a root locator proof
// record is rejected when bytes follow the compressed proof it holds.
func TestRootLocatorProofDecoderTrailingData(t *testing.T) {
	t.Parallel()

	var compressed bytes.Buffer
	err := mssmt.RandProof(t).Compress().Encode(&compressed)
	require.NoError(t, err)

	var buf [8]byte
	decode := func(proofBytes []byte) error {
		var record bytes.Buffer
		err := asset.InlineVarBytesEncoder(&record, &proofBytes, &buf)
		require.NoError(t, err)

		var decoded *mssmt.Proof
		return RootLocatorProofDecoder(
			bytes.NewReader(record.Bytes()), &decoded, &buf,
			uint64(record.Len()),
		)
	}

	require.NoError(t, decode(compressed.Bytes()))

	err = decode(append(bytes.Clone(compressed.Bytes()), 0))
	require.ErrorContains(t, err, "trailing data")
}
