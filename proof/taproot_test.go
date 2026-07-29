package proof

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
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

// TestAddExclusionProofsTapTrees verifies that Bitcoin-only P2TR outputs can
// be proven from either BIP-0086 metadata or the exact tree shape encoded in
// PSBT_OUT_TAP_TREE.
func TestAddExclusionProofsTapTrees(t *testing.T) {
	t.Parallel()

	internalKey := test.RandPubKey(t)
	leaves := testTapLeaves(8)

	twoLeafRoot := txscript.NewTapBranch(leaves[0], leaves[1])
	manyLeafRoot := txscript.NewTapBranch(
		txscript.NewTapBranch(
			txscript.NewTapBranch(leaves[0], leaves[1]),
			txscript.NewTapBranch(leaves[2], leaves[3]),
		),
		txscript.NewTapBranch(
			txscript.NewTapBranch(leaves[4], leaves[5]),
			txscript.NewTapBranch(leaves[6], leaves[7]),
		),
	)

	// This is the split-at-n/2 shape used by Wavelength for five leaves:
	//
	//	           root
	//	          /    \
	//	       (0,1)  (2,(3,4))
	//
	// It differs from txscript.AssembleTaprootScriptTree's pair-then-merge
	// shape for a non-power-of-two leaf count.
	nonPowerOfTwoRoot := txscript.NewTapBranch(
		txscript.NewTapBranch(leaves[0], leaves[1]),
		txscript.NewTapBranch(
			leaves[2],
			txscript.NewTapBranch(leaves[3], leaves[4]),
		),
	)
	flatTree := txscript.AssembleTaprootScriptTree(leaves[:5]...)
	require.NotEqual(
		t, nonPowerOfTwoRoot.TapHash(), flatTree.RootNode.TapHash(),
	)

	testCases := []struct {
		name    string
		depths  []uint8
		leaves  []txscript.TapLeaf
		root    txscript.TapNode
		isBip86 bool
	}{
		{
			name:    "bip86",
			isBip86: true,
		},
		{
			name:   "one leaf",
			depths: []uint8{0},
			leaves: leaves[:1],
			root:   leaves[0],
		},
		{
			name:   "two leaves",
			depths: []uint8{1, 1},
			leaves: leaves[:2],
			root:   twoLeafRoot,
		},
		{
			name: "many leaves",
			depths: []uint8{
				3, 3, 3, 3, 3, 3, 3, 3,
			},
			leaves: leaves,
			root:   manyLeafRoot,
		},
		{
			name:   "non power of two exact shape",
			depths: []uint8{2, 2, 2, 3, 3},
			leaves: leaves[:5],
			root:   nonPowerOfTwoRoot,
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var tapTree []byte
			if !tc.isBip86 {
				tapTree = encodeBIP371TapTree(
					t, tc.depths, tc.leaves,
				)
			}

			pkScript := testTaprootPkScript(
				t, internalKey, tc.root,
			)
			finalTx := wire.NewMsgTx(2)
			finalTx.AddTxOut(&wire.TxOut{
				Value:    1_000,
				PkScript: pkScript,
			})
			packetOutputs := []psbt.POutput{{
				TaprootInternalKey: schnorr.SerializePubKey(
					internalKey,
				),
				TaprootTapTree: tapTree,
			}}

			baseProof := &BaseProofParams{}
			err := AddExclusionProofs(
				baseProof, finalTx, packetOutputs,
				func(uint32) bool {
					return false
				},
			)
			require.NoError(t, err)
			require.Len(t, baseProof.ExclusionProofs, 1)

			exclusionProof := baseProof.ExclusionProofs[0]
			require.Zero(t, exclusionProof.OutputIndex)
			require.True(t, exclusionProof.InternalKey.IsEqual(
				internalKey,
			))
			require.Equal(
				t, tc.isBip86,
				exclusionProof.TapscriptProof.Bip86,
			)

			proofKey, err := exclusionProof.TapscriptProof.
				DeriveTaprootKeys(internalKey)
			require.NoError(t, err)
			outputKey, err := schnorr.ParsePubKey(pkScript[2:])
			require.NoError(t, err)
			require.True(t, proofKey.IsEqual(outputKey))

			if tc.name == "non power of two exact shape" {
				require.Equal(
					t, commitment.BranchPreimage,
					exclusionProof.TapscriptProof.
						TapPreimage1.Type(),
				)
				require.Equal(
					t, commitment.BranchPreimage,
					exclusionProof.TapscriptProof.
						TapPreimage2.Type(),
				)
			}
		})
	}
}

// TestParseBIP371TapTreeRejectsMalformedEncoding verifies both tuple-level
// canonical encoding and complete depth-first binary tree structure.
func TestParseBIP371TapTreeRejectsMalformedEncoding(t *testing.T) {
	t.Parallel()

	leaf := testTapLeaves(1)[0]
	rootLeaf := encodeBIP371TapTree(
		t, []uint8{0}, []txscript.TapLeaf{leaf},
	)
	depthOneLeaf := encodeBIP371TapTree(
		t, []uint8{1}, []txscript.TapLeaf{leaf},
	)

	testCases := []struct {
		name        string
		encoded     []byte
		errContains string
	}{
		{
			name:        "empty",
			errContains: "tap tree is empty",
		},
		{
			name:        "truncated after depth",
			encoded:     []byte{0},
			errContains: "read leaf 0 version",
		},
		{
			name: "truncated compact size",
			encoded: []byte{
				0, byte(txscript.BaseLeafVersion), 0xfd, 0x01,
			},
			errContains: "read leaf 0 script length",
		},
		{
			name: "non canonical compact size",
			encoded: []byte{
				0, byte(txscript.BaseLeafVersion), 0xfd, 0x01,
				0x00, txscript.OP_TRUE,
			},
			errContains: "non-canonical",
		},
		{
			name: "truncated script",
			encoded: []byte{
				0, byte(txscript.BaseLeafVersion), 2,
				txscript.OP_TRUE,
			},
			errContains: "exceeds remaining tap tree bytes",
		},
		{
			name: "odd leaf version",
			encoded: []byte{
				0, byte(txscript.BaseLeafVersion) | 1, 1,
				txscript.OP_TRUE,
			},
			errContains: "odd leaf version",
		},
		{
			name: "depth exceeds control block maximum",
			encoded: []byte{
				txscript.ControlBlockMaxNodeCount + 1,
				byte(txscript.BaseLeafVersion), 1,
				txscript.OP_TRUE,
			},
			errContains: "exceeds maximum",
		},
		{
			name:        "incomplete branch",
			encoded:     depthOneLeaf,
			errContains: "missing node at depth 1",
		},
		{
			name: "trailing root",
			encoded: append(
				append([]byte(nil), rootLeaf...), rootLeaf...,
			),
			errContains: "trailing leaf tuples after root",
		},
		{
			name: "invalid depth first closure",
			encoded: encodeBIP371TapTree(
				t, []uint8{2, 1, 2},
				[]txscript.TapLeaf{leaf, leaf, leaf},
			),
			errContains: "cannot fill node at depth 2",
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseBIP371TapTree(tc.encoded)
			require.ErrorContains(t, err, tc.errContains)
		})
	}
}

// TestAddExclusionProofsRejectsMismatchedTaprootMetadata verifies that neither
// BIP-0086 nor tapscript output metadata can claim a different P2TR output.
func TestAddExclusionProofsRejectsMismatchedTaprootMetadata(t *testing.T) {
	t.Parallel()

	internalKey := test.RandPubKey(t)
	otherKey := test.RandPubKey(t)
	leaves := testTapLeaves(2)
	leaf := leaves[0]
	tapTree := encodeBIP371TapTree(
		t, []uint8{0}, []txscript.TapLeaf{leaf},
	)

	testCases := []struct {
		name              string
		tapTree           []byte
		outputInternalKey *btcec.PublicKey
		outputRoot        txscript.TapNode
	}{
		{
			name:              "bip86 internal key mismatch",
			outputInternalKey: otherKey,
		},
		{
			name:              "tapscript internal key mismatch",
			tapTree:           tapTree,
			outputInternalKey: otherKey,
			outputRoot:        leaf,
		},
		{
			name:              "tapscript tree mismatch",
			tapTree:           tapTree,
			outputInternalKey: internalKey,
			outputRoot:        leaves[1],
		},
	}

	for _, testCase := range testCases {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			finalTx := wire.NewMsgTx(2)
			finalTx.AddTxOut(&wire.TxOut{
				Value: 1_000,
				PkScript: testTaprootPkScript(
					t, tc.outputInternalKey, tc.outputRoot,
				),
			})
			packetOutputs := []psbt.POutput{{
				TaprootInternalKey: schnorr.SerializePubKey(
					internalKey,
				),
				TaprootTapTree: tc.tapTree,
			}}

			err := AddExclusionProofs(
				&BaseProofParams{}, finalTx, packetOutputs,
				func(uint32) bool {
					return false
				},
			)
			require.ErrorContains(
				t, err, "PSBT taproot metadata does not match "+
					"the transaction output",
			)
		})
	}
}

// TestAddExclusionProofsRejectsUnsupportedTapTreeLeaf verifies structurally
// valid BIP-371 metadata still needs to be representable by the Taproot Assets
// tapscript exclusion proof format.
func TestAddExclusionProofsRejectsUnsupportedTapTreeLeaf(t *testing.T) {
	t.Parallel()

	internalKey := test.RandPubKey(t)
	leaf := txscript.NewTapLeaf(
		txscript.TapscriptLeafVersion(
			byte(txscript.BaseLeafVersion)+2,
		),
		[]byte{txscript.OP_TRUE},
	)
	tapTree := encodeBIP371TapTree(
		t, []uint8{0}, []txscript.TapLeaf{leaf},
	)
	finalTx := wire.NewMsgTx(2)
	finalTx.AddTxOut(&wire.TxOut{
		Value: 1_000,
		PkScript: testTaprootPkScript(
			t, internalKey, leaf,
		),
	})

	err := AddExclusionProofs(
		&BaseProofParams{}, finalTx, []psbt.POutput{{
			TaprootInternalKey: schnorr.SerializePubKey(
				internalKey,
			),
			TaprootTapTree: tapTree,
		}}, func(uint32) bool {
			return false
		},
	)
	require.ErrorContains(t, err, "tapleaf version")
	require.ErrorContains(t, err, "not supported")
}

func testTapLeaves(count int) []txscript.TapLeaf {
	leaves := make([]txscript.TapLeaf, count)
	for idx := range leaves {
		leaves[idx] = txscript.NewBaseTapLeaf([]byte{
			byte(txscript.OP_1 + idx),
		})
	}

	return leaves
}

func encodeBIP371TapTree(t *testing.T, depths []uint8,
	leaves []txscript.TapLeaf) []byte {

	t.Helper()
	require.Len(t, leaves, len(depths))

	var encoded bytes.Buffer
	for idx := range leaves {
		require.NoError(t, encoded.WriteByte(depths[idx]))
		require.NoError(
			t, encoded.WriteByte(byte(leaves[idx].LeafVersion)),
		)
		require.NoError(
			t, wire.WriteVarBytes(&encoded, 0, leaves[idx].Script),
		)
	}

	return encoded.Bytes()
}

func testTaprootPkScript(t *testing.T, internalKey *btcec.PublicKey,
	root txscript.TapNode) []byte {

	t.Helper()

	var tapscriptRoot []byte
	if root != nil {
		rootHash := root.TapHash()
		tapscriptRoot = rootHash[:]
	}
	outputKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot,
	)
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	return pkScript
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
