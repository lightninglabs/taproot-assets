package proof

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
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

// TestTaprootProofUnknownOddType tests that an unknown odd type is allowed in a
// Taproot proof and that we can still arrive at the correct serialized version
// with it.
func TestTaprootProofUnknownOddType(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	randProof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)
	knownProof := randProof.InclusionProof

	var buf bytes.Buffer
	err := knownProof.Encode(&buf)
	require.NoError(t, err)

	knownProofBytes := fn.CopySlice(buf.Bytes())

	// With the known Taproot proof now encoded, we can add an unknown even
	// type to the encoded bytes. That should provoke an error when parsed
	// again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	var parsedProof TaprootProof
	err = parsedProof.Decode(&buf)
	require.ErrorAs(t, err, &asset.ErrUnknownType{})

	// Now clear the buffer, encode the Taproot proof again, but this time
	// add an unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()
	err = parsedProof.Encode(&buf)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	err = parsedProof.Decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	require.Equal(t, expectedUnknownTypes, parsedProof.unknownOddTypes)

	// The leaf should've changed, to make sure the unknown value was taken
	// into account when creating the serialized leaf.
	var newBuf bytes.Buffer
	err = parsedProof.Encode(&newBuf)
	require.NoError(t, err)

	require.NotEqual(t, knownProofBytes, newBuf.Bytes())
}

// TestCommitmentProofUnknownOddType tests that an unknown odd type is allowed
// in a commitment proof and that we can still arrive at the correct serialized
// version with it.
func TestCommitmentProofUnknownOddType(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	randProof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

	require.NotNil(t, randProof.InclusionProof.CommitmentProof)
	knownProof := randProof.InclusionProof.CommitmentProof

	var buf bytes.Buffer
	err := knownProof.Encode(&buf)
	require.NoError(t, err)

	knownProofBytes := fn.CopySlice(buf.Bytes())

	// With the known commitment proof now encoded, we can add an unknown
	// even type to the encoded bytes. That should provoke an error when
	// parsed again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	var parsedProof CommitmentProof
	err = parsedProof.Decode(&buf)
	require.ErrorAs(t, err, &asset.ErrUnknownType{})

	// Now clear the buffer, encode the commitment proof again, but this
	// time add an unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()
	err = parsedProof.Encode(&buf)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	err = parsedProof.Decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	require.Equal(t, expectedUnknownTypes, parsedProof.unknownOddTypes)

	// The leaf should've changed, to make sure the unknown value was taken
	// into account when creating the serialized leaf.
	var newBuf bytes.Buffer
	err = parsedProof.Encode(&newBuf)
	require.NoError(t, err)

	require.NotEqual(t, knownProofBytes, newBuf.Bytes())
}

// TestTapscriptProofUnknownOddType tests that an unknown odd type is allowed
// in a Tapscript proof and that we can still arrive at the correct serialized
// version with it.
func TestTapscriptProofUnknownOddType(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	randProof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

	require.NotNil(t, randProof.InclusionProof.CommitmentProof)
	knownProof := randProof.InclusionProof.CommitmentProof

	var buf bytes.Buffer
	err := knownProof.Encode(&buf)
	require.NoError(t, err)

	knownProofBytes := fn.CopySlice(buf.Bytes())

	// With the known Tapscript proof now encoded, we can add an unknown
	// even type to the encoded bytes. That should provoke an error when
	// parsed again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	var parsedProof TapscriptProof
	err = parsedProof.Decode(&buf)
	require.ErrorAs(t, err, &asset.ErrUnknownType{})

	// Now clear the buffer, encode the Tapscript proof again, but this time
	// add an unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()
	err = parsedProof.Encode(&buf)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	err = parsedProof.Decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	require.Equal(t, expectedUnknownTypes, parsedProof.unknownOddTypes)

	// The leaf should've changed, to make sure the unknown value was taken
	// into account when creating the serialized leaf.
	var newBuf bytes.Buffer
	err = parsedProof.Encode(&newBuf)
	require.NoError(t, err)

	require.NotEqual(t, knownProofBytes, newBuf.Bytes())
}
