package proof

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	// Block 100002 with 9 transactions on bitcoin mainnet.
	oddTxBlockHexFileName = filepath.Join(
		testDataFileName, "odd-block.hex",
	)

	// Block 100003 with 12 transactions on bitcoin mainnet.
	evenTxBlockHexFileName = filepath.Join(
		testDataFileName, "12-tx-block.hex",
	)

	// Block 2348332 with 70 transactions on bitcoin testnet.
	testnetTxBlockHexFileName = filepath.Join(
		testDataFileName, "70-tx-block.hex",
	)
)

func readTestData(t *testing.T) []wire.MsgBlock {
	var oddTxBlock, evenTxBlock, testnetTxBlock wire.MsgBlock

	var testBlocks []wire.MsgBlock

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	testBlocks = append(testBlocks, oddTxBlock)

	evenTxBlockHex, err := os.ReadFile(evenTxBlockHexFileName)
	require.NoError(t, err)

	evenTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(evenTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	err = evenTxBlock.Deserialize(bytes.NewReader(evenTxBlockBytes))
	require.NoError(t, err)

	testBlocks = append(testBlocks, evenTxBlock)

	testnetTxBlockHex, err := os.ReadFile(testnetTxBlockHexFileName)
	require.NoError(t, err)

	testnetTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(testnetTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	err = testnetTxBlock.Deserialize(bytes.NewReader(testnetTxBlockBytes))
	require.NoError(t, err)

	testBlocks = append(testBlocks, testnetTxBlock)

	return testBlocks
}

func TestTxMerkleProofEncoding(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	blocks := []wire.MsgBlock{
		*chaincfg.MainNetParams.GenesisBlock, // 1 transaction
	}
	blocks = append(blocks, testBlocks...)
	for _, block := range blocks {
		for i, tx := range block.Transactions {
			proof, err := NewTxMerkleProof(block.Transactions, i)
			require.NoError(t, err)
			require.True(
				t, proof.Verify(tx, block.Header.MerkleRoot),
			)

			var buf bytes.Buffer
			require.NoError(t, proof.Encode(&buf))
			var decoded TxMerkleProof
			require.NoError(t, decoded.Decode(&buf))
			require.Equal(t, *proof, decoded)
			require.True(
				t, decoded.Verify(tx, block.Header.MerkleRoot),
			)
		}
	}
}

// TestTxProofVerification tests the verification of the TxProof struct.
func TestTxProofVerification(t *testing.T) {
	var (
		errInvalidHeader      = errors.New("invalid header")
		errInvalidMerkleProof = errors.New("invalid merkle proof")
		errHeaderVerifier     = func(wire.BlockHeader, uint32) error {
			return errInvalidHeader
		}
		errMerkleVerifier = func(*wire.MsgTx, *TxMerkleProof,
			[32]byte) error {

			return errInvalidMerkleProof
		}
		testBlocks = readTestData(t)
		firstBlock = testBlocks[0]
		firstTx    = firstBlock.Transactions[1]
		testKey    = test.RandPubKey(t)
	)

	firstTxProof, err := NewTxMerkleProof(
		firstBlock.Transactions, 1,
	)
	require.NoError(t, err)

	bip86Key := txscript.ComputeTaprootKeyNoScript(testKey)
	bip86PkScript, err := txscript.PayToTaprootScript(bip86Key)
	require.NoError(t, err)

	randRoot := test.RandBytes(32)
	tapscriptKey := txscript.ComputeTaprootOutputKey(testKey, randRoot)
	tapscriptPkScript, err := txscript.PayToTaprootScript(tapscriptKey)
	require.NoError(t, err)

	bip86Tx := wire.MsgTx{
		TxOut: []*wire.TxOut{
			{
				PkScript: bip86PkScript,
			},
		},
	}
	tapscriptTx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			{
				SignatureScript: test.RandBytes(10),
			},
		},
		TxOut: []*wire.TxOut{
			{
				PkScript: tapscriptPkScript,
			},
		},
	}

	testCases := []struct {
		name           string
		proof          *TxProof
		headerVerifier HeaderVerifier
		merkleVerifier MerkleVerifier
		expectedErr    error
		expectedErrStr string
	}{
		{
			name: "hash mismatch",
			proof: &TxProof{
				MsgTx: *firstTx,
				ClaimedOutPoint: wire.OutPoint{
					Hash: test.RandHash(),
				},
			},
			expectedErr: ErrHashMismatch,
		},
		{
			name: "index mismatch",
			proof: &TxProof{
				MsgTx: *firstTx,
				ClaimedOutPoint: wire.OutPoint{
					Hash:  firstTx.TxHash(),
					Index: 123,
				},
			},
			expectedErr: ErrOutputIndexInvalid,
		},
		{
			name: "pk script mismatch",
			proof: &TxProof{
				MsgTx: *firstTx,
				ClaimedOutPoint: wire.OutPoint{
					Hash:  firstTx.TxHash(),
					Index: 0,
				},
				InternalKey: *testKey,
			},
			expectedErr: ErrClaimedOutputScriptMismatch,
		},
		{
			name: "merkle verifier mismatch",
			proof: &TxProof{
				MsgTx: bip86Tx,
				ClaimedOutPoint: wire.OutPoint{
					Hash:  bip86Tx.TxHash(),
					Index: 0,
				},
				InternalKey: *testKey,
			},
			merkleVerifier: errMerkleVerifier,
			expectedErr:    errInvalidMerkleProof,
		},
		{
			name: "header verifier mismatch",
			proof: &TxProof{
				MsgTx: bip86Tx,
				ClaimedOutPoint: wire.OutPoint{
					Hash:  bip86Tx.TxHash(),
					Index: 0,
				},
				InternalKey: *testKey,
			},
			merkleVerifier: MockMerkleVerifier,
			headerVerifier: errHeaderVerifier,
			expectedErr:    errInvalidHeader,
		},
		{
			name: "success",
			proof: &TxProof{
				MsgTx:       tapscriptTx,
				BlockHeader: testBlocks[0].Header,
				BlockHeight: 39493,
				MerkleProof: *firstTxProof,
				ClaimedOutPoint: wire.OutPoint{
					Hash:  tapscriptTx.TxHash(),
					Index: 0,
				},
				InternalKey: *testKey,
				MerkleRoot:  randRoot,
			},
			merkleVerifier: MockMerkleVerifier,
			headerVerifier: MockHeaderVerifier,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.proof.Verify(
				tc.headerVerifier, tc.merkleVerifier,
			)

			switch {
			case tc.expectedErr != nil:
				require.ErrorIs(t, err, tc.expectedErr)
				require.ErrorContains(t, err, tc.expectedErrStr)

				return

			case tc.expectedErrStr != "":
				require.ErrorContains(t, err, tc.expectedErrStr)

				return
			}

			require.NoError(t, err)

			// For a successful proof, we also check the RPC
			// marshaling and unmarshaling.
			rpcProof, err := MarshalTxProof(*tc.proof)
			require.NoError(t, err)

			newProof, err := UnmarshalTxProof(rpcProof)
			require.NoError(t, err)

			require.Equal(t, tc.proof, newProof)
		})
	}
}
