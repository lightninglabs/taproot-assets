package backup

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// mockChainQuerier is a mock implementation of ChainQuerier for tests.
type mockChainQuerier struct {
	blocks map[int64]*wire.MsgBlock
}

func newMockChainQuerier() *mockChainQuerier {
	return &mockChainQuerier{
		blocks: make(map[int64]*wire.MsgBlock),
	}
}

func (m *mockChainQuerier) GetBlockByHeight(_ context.Context,
	height int64) (*wire.MsgBlock, error) {

	block, ok := m.blocks[height]
	if !ok {
		return nil, fmt.Errorf("block not found at height %d", height)
	}
	return block, nil
}

// makeTestBlock creates a block containing the given transactions with a valid
// merkle root.
func makeTestBlock(t *testing.T,
	txs ...*wire.MsgTx) *wire.MsgBlock {

	t.Helper()

	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   2,
			Timestamp: time.Now().Truncate(time.Second),
			Bits:      0x1d00ffff,
			Nonce:     12345,
		},
		Transactions: txs,
	}

	// Compute the merkle root using the same method as btcd so our
	// merkle proofs verify correctly.
	block.Header.MerkleRoot = computeMerkleRoot(t, txs)

	return block
}

// computeMerkleRoot computes the merkle root from a list of transactions using
// the same double-SHA256 algorithm as Bitcoin.
func computeMerkleRoot(t *testing.T,
	txs []*wire.MsgTx) chainhash.Hash {

	t.Helper()

	if len(txs) == 0 {
		return chainhash.Hash{}
	}

	// Use a single-transaction merkle proof to extract the root.
	// For a single tx, the root is just the txid. For multiple, we build
	// the tree properly.
	if len(txs) == 1 {
		return txs[0].TxHash()
	}

	// Build the merkle tree manually using double-SHA256 like Bitcoin.
	hashes := make([]chainhash.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.TxHash()
	}

	for len(hashes) > 1 {
		var next []chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			left := hashes[i]
			right := left
			if i+1 < len(hashes) {
				right = hashes[i+1]
			}
			var combined [64]byte
			copy(combined[:32], left[:])
			copy(combined[32:], right[:])
			next = append(next, chainhash.DoubleHashH(
				combined[:],
			))
		}
		hashes = next
	}

	return hashes[0]
}

// makeTestProofFile creates a realistic proof file for testing strip/rehydrate.
// Returns the encoded proof file blob, the block, and the block height.
func makeTestProofFile(t *testing.T) ([]byte, *wire.MsgBlock, uint32) {
	t.Helper()

	// Create a coinbase transaction and a regular transaction.
	coinbaseTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
			SignatureScript:  []byte{0x04, 0xff, 0xff, 0x00, 0x1d},
		}},
		TxOut: []*wire.TxOut{{
			Value:    50_0000_0000,
			PkScript: []byte{0x51},
		}},
	}

	anchorTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  coinbaseTx.TxHash(),
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: test.RandBytes(34),
		}},
	}

	blockHeight := uint32(100)
	block := makeTestBlock(t, coinbaseTx, anchorTx)

	// Build a merkle proof for the anchor tx (index 1).
	txMerkleProof, err := proof.NewTxMerkleProof(
		block.Transactions, 1,
	)
	require.NoError(t, err)

	// Create a minimal proof with all blockchain fields populated.
	genesis := asset.Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  coinbaseTx.TxHash(),
			Index: 0,
		},
		Tag:         "test-asset",
		OutputIndex: 0,
		Type:        asset.Normal,
	}

	scriptKey := asset.NewScriptKey(test.RandPubKey(t))
	internalKey := test.RandPubKey(t)

	// Create a minimal tap commitment for the inclusion proof.
	testAsset := asset.NewAssetNoErr(
		t, genesis, 1000, 0, 0, scriptKey, nil,
	)
	tapCommitment, _, err := commitment.Mint(
		nil, genesis, nil, &commitment.AssetDetails{
			Type:      asset.Normal,
			ScriptKey: test.PubToKeyDesc(scriptKey.PubKey),
			Amount:    fn.Ptr(uint64(1000)),
		},
	)
	require.NoError(t, err)

	_, commitmentProof, err := tapCommitment.Proof(
		testAsset.TapCommitmentKey(),
		testAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	p := proof.Proof{
		PrevOut:       genesis.FirstPrevOut,
		BlockHeader:   block.Header,
		BlockHeight:   blockHeight,
		AnchorTx:      *anchorTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         *testAsset,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: internalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof: *commitmentProof,
			},
		},
		GenesisReveal: &genesis,
	}

	// Build a proof file.
	proofFile, err := proof.NewFile(proof.V0, p)
	require.NoError(t, err)

	proofBlob, err := proof.EncodeFile(proofFile)
	require.NoError(t, err)

	return proofBlob, block, blockHeight
}

// TestStripRehydrateRoundTrip tests that stripping a proof file and
// rehydrating it produces a result that decodes to equivalent proofs.
func TestStripRehydrateRoundTrip(t *testing.T) {
	t.Parallel()

	proofBlob, block, blockHeight := makeTestProofFile(t)

	// Strip the proof file.
	strippedBlob, hints, err := StripProofFile(proofBlob)
	require.NoError(t, err)

	// Verify hints are correct.
	require.Len(t, hints.Hints, 1)
	require.Equal(t, blockHeight, hints.Hints[0].BlockHeight)

	expectedTxHash := block.Transactions[1].TxHash()
	require.Equal(t,
		expectedTxHash,
		chainhash.Hash(hints.Hints[0].AnchorTxHash),
	)

	// Stripped blob should be smaller than the original.
	t.Logf("Original: %d bytes, Stripped: %d bytes, Savings: %d bytes",
		len(proofBlob), len(strippedBlob),
		len(proofBlob)-len(strippedBlob))
	require.Less(t, len(strippedBlob), len(proofBlob))

	// The stripped blob should still be decodable as a proof file.
	strippedFile, err := proof.DecodeFile(strippedBlob)
	require.NoError(t, err)
	require.Equal(t, 1, strippedFile.NumProofs())

	// Rehydrate using a mock chain querier.
	chain := newMockChainQuerier()
	chain.blocks[int64(blockHeight)] = block

	ctx := context.Background()
	rehydratedBlob, err := RehydrateProofFile(
		ctx, strippedBlob, hints, chain,
	)
	require.NoError(t, err)

	// The rehydrated proof should decode and have the correct fields.
	rehydratedFile, err := proof.DecodeFile(rehydratedBlob)
	require.NoError(t, err)
	require.Equal(t, 1, rehydratedFile.NumProofs())

	rehydratedProof, err := rehydratedFile.ProofAt(0)
	require.NoError(t, err)

	// Verify the blockchain fields were reconstructed.
	require.Equal(t, block.Header, rehydratedProof.BlockHeader)
	require.Equal(t, blockHeight, rehydratedProof.BlockHeight)
	require.Equal(t,
		expectedTxHash, rehydratedProof.AnchorTx.TxHash(),
	)

	// Verify the merkle proof is valid.
	require.True(t, rehydratedProof.TxMerkleProof.Verify(
		&rehydratedProof.AnchorTx,
		rehydratedProof.BlockHeader.MerkleRoot,
	))

	// Verify the non-blockchain fields survived the round trip.
	originalFile, err := proof.DecodeFile(proofBlob)
	require.NoError(t, err)
	originalProof, err := originalFile.ProofAt(0)
	require.NoError(t, err)

	require.Equal(t,
		originalProof.PrevOut, rehydratedProof.PrevOut,
	)
	require.Equal(t,
		originalProof.Asset.Amount, rehydratedProof.Asset.Amount,
	)
	require.True(t, originalProof.Asset.ScriptKey.PubKey.IsEqual(
		rehydratedProof.Asset.ScriptKey.PubKey,
	))
}

// TestHintsEncodeDecode tests the round-trip encoding of FileHints.
func TestHintsEncodeDecode(t *testing.T) {
	t.Parallel()

	original := FileHints{
		Hints: []ProofHint{
			{
				AnchorTxHash: [32]byte{1, 2, 3, 4, 5},
				BlockHeight:  100,
			},
			{
				AnchorTxHash: [32]byte{6, 7, 8, 9, 10},
				BlockHeight:  200,
			},
			{
				AnchorTxHash: [32]byte{0xff, 0xfe, 0xfd},
				BlockHeight:  999999,
			},
		},
	}

	// Encode.
	var buf bytes.Buffer
	err := EncodeFileHints(&buf, original)
	require.NoError(t, err)

	// Verify expected size: 1 byte varint + 3 * 36 bytes = 109.
	require.Equal(t, 1+3*proofHintSize, buf.Len())

	// Decode.
	decoded, err := DecodeFileHints(&buf)
	require.NoError(t, err)

	require.Equal(t, original, decoded)
}

// TestHintsEncodeDecodeEmpty tests encoding/decoding of empty hints.
func TestHintsEncodeDecodeEmpty(t *testing.T) {
	t.Parallel()

	original := FileHints{
		Hints: []ProofHint{},
	}

	var buf bytes.Buffer
	err := EncodeFileHints(&buf, original)
	require.NoError(t, err)

	decoded, err := DecodeFileHints(&buf)
	require.NoError(t, err)

	require.Len(t, decoded.Hints, 0)
}

// TestRehydrateMismatchedHints tests that rehydrate fails when hint count
// doesn't match proof count.
func TestRehydrateMismatchedHints(t *testing.T) {
	t.Parallel()

	proofBlob, _, _ := makeTestProofFile(t)

	strippedBlob, _, err := StripProofFile(proofBlob)
	require.NoError(t, err)

	// Use wrong number of hints.
	wrongHints := FileHints{
		Hints: []ProofHint{
			{BlockHeight: 1},
			{BlockHeight: 2},
		},
	}

	chain := newMockChainQuerier()
	ctx := context.Background()

	_, err = RehydrateProofFile(ctx, strippedBlob, wrongHints, chain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hint count mismatch")
}
