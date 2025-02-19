package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/stretchr/testify/require"
)

// TestProofStitching is a manual test that can be used to stitch together
// proofs of a failed transfer. It reads a template proof from a file and then
// reads a series of suffix proofs that are supposed to be stitched to the
// template. The suffix proofs are then enhanced with the on-chain information
// and written out to new files as full provenance proof files.
func TestProofStitching(t *testing.T) {
	// This code makes a lot of assumptions on what files need to be present
	// and is really only meant for manual use to stitch together the proofs
	// of a failed transfer. Comment out the t.Skip line to run it.
	t.Skip("Code only for manual use.")

	const (
		rpcUser     = "lightning"
		rpcPassword = "lightning"
		rpcHost     = "localhost:8332"
		startIndex  = 0
		endIndex    = 12
		mindedBlock = 868229
	)

	client, err := bitcoinClient(rpcHost, rpcUser, rpcPassword)
	require.NoError(t, err)

	verifier := &bitcoindVerifier{client: client}

	tplBytes, err := os.ReadFile(filepath.Join(
		testDataFileName, "template.proof",
	))
	require.NoError(t, err)

	f := &File{}
	err = f.Decode(bytes.NewReader(tplBytes))
	require.NoError(t, err)

	vCtx := VerifierCtx{
		HeaderVerifier: verifier.VerifyHeader,
		MerkleVerifier: MockMerkleVerifier,
		GroupVerifier:  MockGroupVerifier,
		ChainLookupGen: MockChainLookup,
	}

	// We want the template to valid, otherwise all other steps are
	// meaningless.
	_, err = f.Verify(context.Background(), vCtx)
	require.NoError(t, err)

	// The template proof is the last proof in the file, that was the only
	// one fully written. We take the last proof to find out the on-chain
	// TX that was involved in the transfer.
	tplProof, err := f.LastProof()
	require.NoError(t, err)

	// Fetch the transaction to make sure it is actually known.
	txid := tplProof.AnchorTx.TxHash()
	_, err = client.GetRawTransaction(&txid)
	require.NoError(t, err)

	// Now fetch the full block the TX was mined in.
	blockHash, err := client.GetBlockHash(int64(mindedBlock))
	require.NoError(t, err)
	block, err := client.GetBlock(blockHash)
	require.NoError(t, err)

	// What's the transaction's index in the block?
	txIndex := -1
	for i, tx := range block.Transactions {
		if tx.TxHash() == txid {
			txIndex = i
			break
		}
	}
	require.NotEqual(t, -1, txIndex)

	// And with that, we can create the merkle proof for the transaction.
	merkleProof, err := NewTxMerkleProof(block.Transactions, txIndex)
	require.NoError(t, err)

	for i := startIndex; i <= endIndex; i++ {
		brokenProofHex, err := os.ReadFile(filepath.Join(
			testDataFileName, fmt.Sprintf("suffix-%d.hex", i),
		))
		require.NoError(t, err)

		brokenProofBytes, err := hex.DecodeString(
			strings.TrimSpace(string(brokenProofHex)),
		)
		require.NoError(t, err)

		brokenProof := &Proof{}
		err = brokenProof.Decode(bytes.NewReader(brokenProofBytes))
		require.NoError(t, err)

		// We can now fill in the block information for the broken
		// proof.
		brokenProof.TxMerkleProof = *merkleProof
		brokenProof.BlockHeight = mindedBlock
		brokenProof.BlockHeader = block.Header
		vCtx.MerkleVerifier = DefaultMerkleVerifier

		// We now should have a fully valid proof that we can write out
		// to a file, by replacing the last one in the template.
		err = f.ReplaceLastProof(*brokenProof)
		require.NoError(t, err)

		// We now need to find out if this is one of the proofs that
		// can't be fixed because of the script key usage. So if we
		// get an "invalid exclusion proof" error when validating, we
		// need to skip this proof.
		_, err = f.Verify(context.Background(), vCtx)
		switch {
		case errors.Is(err, commitment.ErrInvalidTaprootProof):
			t.Logf("Proof %d is invalid and can't be rescued: %v",
				i, err)

			continue

		case err != nil:
			require.NoError(t, err)
		}

		// If the proof is valid, we can write it out to a file.
		outFile, err := os.Create(filepath.Join(
			testDataFileName, fmt.Sprintf("fixed-%d.proof", i),
		))
		require.NoError(t, err)

		err = f.Encode(outFile)
		require.NoError(t, err)

		err = outFile.Close()
		require.NoError(t, err)
	}
}

func bitcoinClient(rpcHost, rpcUser,
	rpcPass string) (*rpcclient.Client, error) {

	rpcCfg := rpcclient.ConnConfig{
		Host:                 rpcHost,
		User:                 rpcUser,
		Pass:                 rpcPass,
		DisableConnectOnNew:  true,
		DisableAutoReconnect: false,
		DisableTLS:           true,
		HTTPPostMode:         true,
	}

	return rpcclient.New(&rpcCfg, nil)
}

type bitcoindVerifier struct {
	client *rpcclient.Client
}

func (b *bitcoindVerifier) VerifyHeader(header wire.BlockHeader,
	height uint32) error {

	targetHash, err := b.client.GetBlockHash(int64(height))
	if err != nil {
		return fmt.Errorf("unable to get block hash: %w", err)
	}

	if *targetHash != header.BlockHash() {
		return fmt.Errorf("block hash mismatch")
	}

	return nil
}
