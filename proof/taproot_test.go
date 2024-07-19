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

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, &knownProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof *TaprootProof) error {
			err := proof.Encode(buf)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (*TaprootProof, error) {
			var parsedProof TaprootProof
			return &parsedProof, parsedProof.Decode(buf)
		},
		func(parsedProof *TaprootProof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized proof.
			var newBuf bytes.Buffer
			err := parsedProof.Encode(&newBuf)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, &knownProof, parsedProof)
		},
	)
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

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, knownProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof *CommitmentProof) error {
			err := proof.Encode(buf)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (*CommitmentProof, error) {
			var parsedProof CommitmentProof
			return &parsedProof, parsedProof.Decode(buf)
		},
		func(parsedProof *CommitmentProof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized proof.
			var newBuf bytes.Buffer
			err := parsedProof.Encode(&newBuf)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, knownProof, parsedProof)
		},
	)
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

	require.NotNil(t, randProof.ExclusionProofs[1].TapscriptProof)
	knownProof := randProof.ExclusionProofs[1].TapscriptProof

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, knownProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof *TapscriptProof) error {
			err := proof.Encode(buf)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (*TapscriptProof, error) {
			var parsedProof TapscriptProof
			return &parsedProof, parsedProof.Decode(buf)
		},
		func(parsedProof *TapscriptProof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized proof.
			var newBuf bytes.Buffer
			err := parsedProof.Encode(&newBuf)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, knownProof, parsedProof)
		},
	)
}
