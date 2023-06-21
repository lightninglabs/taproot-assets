package proof

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
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
