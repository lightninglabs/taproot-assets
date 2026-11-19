package proof

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type dagOccurrence struct {
	txID          chainhash.Hash
	blockHeader   wire.BlockHeader
	blockHeight   uint32
	txMerkleProof TxMerkleProof
}

func TestNewVerifiedBlockContext(t *testing.T) {
	t.Parallel()

	amount := uint64(1)
	anchorProof, _ := genRandomGenesisWithProof(
		t, asset.Normal, &amount, nil, true, nil, nil, nil, nil,
		asset.V0,
	)

	blockHeader := anchorProof.BlockHeader
	blockHeader.MerkleRoot = anchorProof.AnchorTx.TxHash()
	blockHeader.Timestamp = time.Unix(1_700_000_000, 0)
	txMerkleProof, err := NewTxMerkleProof(
		[]*wire.MsgTx{&anchorProof.AnchorTx}, 0,
	)
	require.NoError(t, err)

	context, err := NewVerifiedBlockContext(
		&anchorProof.AnchorTx, blockHeader, 101, *txMerkleProof,
	)
	require.NoError(t, err)
	require.Equal(t, anchorProof.AnchorTx.TxHash(), context.AnchorTxID())
	require.Equal(t, blockHeader.BlockHash(), context.BlockHash())
	require.Equal(t, uint32(101), context.BlockHeight())
	require.Equal(t, uint32(0), context.TxIndex())
	require.Equal(t, blockHeader, context.BlockHeader())

	blockHeader.MerkleRoot = chainhash.Hash{}
	_, err = NewVerifiedBlockContext(
		&anchorProof.AnchorTx, blockHeader, 101, *txMerkleProof,
	)
	require.ErrorIs(t, err, ErrInvalidTxMerkleProof)

	_, err = NewVerifiedBlockContext(
		nil, blockHeader, 101, *txMerkleProof,
	)
	require.ErrorIs(t, err, ErrInvalidTxMerkleProof)

	_, err = NewVerifiedBlockContext(
		&anchorProof.AnchorTx, blockHeader, 101, TxMerkleProof{
			Nodes: []chainhash.Hash{{1}},
		},
	)
	require.ErrorIs(t, err, ErrInvalidTxMerkleProof)
}

// TestProofDAGRestampProperties asserts the value-level properties that can't
// be expressed by VerifiedBlockContext's sealed type: traversal completeness,
// replacement of every occurrence, preservation of unrelated contexts,
// checksum propagation and idempotence.
func TestProofDAGRestampProperties(t *testing.T) {
	t.Parallel()

	const templateCount = 3
	templates := make([]Proof, templateCount)
	for idx := range templates {
		amount := uint64(idx + 1)
		templates[idx], _ = genRandomGenesisWithProof(
			t, asset.Normal, &amount, nil, true, nil, nil, nil,
			nil, asset.V0,
		)
	}

	rapid.Check(t, func(rt *rapid.T) {
		targetIdx := rapid.IntRange(0, templateCount-1).Draw(
			rt, "target_idx",
		)
		randomDAG := drawProofDAG(rt, templates, 2, "random")

		// Force the target transaction to occur at multiple depths. A
		// following proof also exercises chained-hash updates.
		innerTarget := templates[targetIdx]
		innerTarget.AdditionalInputs = []File{*randomDAG}
		innerFile, err := NewFile(V0, innerTarget)
		require.NoError(rt, err)

		outerTarget := templates[targetIdx]
		outerTarget.AdditionalInputs = []File{*innerFile}
		follower := templates[(targetIdx+1)%templateCount]
		proofFile, err := NewFile(V0, outerTarget, follower)
		require.NoError(rt, err)

		before, err := flattenProofDAG(proofFile)
		require.NoError(rt, err)

		expectedTxIDs := uniqueTxIDs(before)
		actualTxIDs, err := proofFile.AnchorTxIDs()
		require.NoError(rt, err)
		require.Equal(rt, expectedTxIDs, actualTxIDs)

		targetTx := &templates[targetIdx].AnchorTx
		blockHeader := templates[targetIdx].BlockHeader
		blockHeader.MerkleRoot = targetTx.TxHash()
		blockHeader.Timestamp = time.Unix(1_700_000_000, 0)
		blockHeader.Nonce++
		txMerkleProof, err := NewTxMerkleProof(
			[]*wire.MsgTx{targetTx}, 0,
		)
		require.NoError(rt, err)
		blockHeight := templates[targetIdx].BlockHeight + 100
		context, err := NewVerifiedBlockContext(
			targetTx, blockHeader, blockHeight, *txMerkleProof,
		)
		require.NoError(rt, err)

		restamped, err := proofFile.RestampAnchor(context)
		require.NoError(rt, err)
		require.Equal(rt, expectedTxIDs, restamped.AnchorTxIDs())
		matchCount := restamped.Matches()

		after, err := flattenProofDAG(proofFile)
		require.NoError(rt, err)
		require.Len(rt, after, len(before))

		var expectedMatches uint64
		for idx := range before {
			require.Equal(rt, before[idx].txID, after[idx].txID)
			if before[idx].txID != context.AnchorTxID() {
				require.Equal(rt, before[idx], after[idx])
				continue
			}

			expectedMatches++
			require.Equal(rt, blockHeader, after[idx].blockHeader)
			require.Equal(rt, blockHeight, after[idx].blockHeight)
			require.Equal(
				rt, *txMerkleProof, after[idx].txMerkleProof,
			)
		}
		require.Equal(rt, expectedMatches, matchCount)

		var encoded bytes.Buffer
		require.NoError(rt, proofFile.Encode(&encoded))
		require.Equal(rt, encoded.Bytes(), []byte(restamped.Blob()))
		decoded := &File{}
		reader := bytes.NewReader(encoded.Bytes())
		require.NoError(rt, decoded.Decode(reader))
		decodedOccurrences, err := flattenProofDAG(decoded)
		require.NoError(rt, err)
		require.Equal(rt, after, decodedOccurrences)

		// Restamping an already-current DAG has no observable effect.
		again, err := proofFile.RestampAnchor(context)
		require.NoError(rt, err)
		require.Equal(rt, expectedMatches, again.Matches())
		var encodedAgain bytes.Buffer
		require.NoError(rt, proofFile.Encode(&encodedAgain))
		require.Equal(rt, encoded.Bytes(), encodedAgain.Bytes())
	})
}

func drawProofDAG(rt *rapid.T, templates []Proof, depth int,
	label string) *File {

	proofCount := rapid.IntRange(1, 3).Draw(rt, label+"_proof_count")
	proofs := make([]Proof, proofCount)
	for proofIdx := range proofs {
		templateIdx := rapid.IntRange(0, len(templates)-1).Draw(
			rt, fmt.Sprintf("%s_template_%d", label, proofIdx),
		)
		proofs[proofIdx] = templates[templateIdx]
		proofs[proofIdx].AdditionalInputs = nil

		if depth == 0 {
			continue
		}

		inputCount := rapid.IntRange(0, 2).Draw(
			rt, fmt.Sprintf("%s_input_count_%d", label, proofIdx),
		)
		proofs[proofIdx].AdditionalInputs = make([]File, inputCount)
		for inputIdx := 0; inputIdx < inputCount; inputIdx++ {
			inputLabel := fmt.Sprintf(
				"%s_proof_%d_input_%d", label, proofIdx,
				inputIdx,
			)
			inputFile := drawProofDAG(
				rt, templates, depth-1, inputLabel,
			)
			proofs[proofIdx].AdditionalInputs[inputIdx] = *inputFile
		}
	}

	proofFile, err := NewFile(V0, proofs...)
	if err != nil {
		rt.Fatalf("create proof DAG: %v", err)
	}

	return proofFile
}

func flattenProofDAG(proofFile *File) ([]dagOccurrence, error) {
	occurrences := make([]dagOccurrence, 0, proofFile.NumProofs())
	err := proofFile.walkProofDAG(func(proof *Proof) {
		occurrences = append(occurrences, dagOccurrence{
			txID:          proof.AnchorTx.TxHash(),
			blockHeader:   proof.BlockHeader,
			blockHeight:   proof.BlockHeight,
			txMerkleProof: proof.TxMerkleProof,
		})
	})
	if err != nil {
		return nil, err
	}

	return occurrences, nil
}

func uniqueTxIDs(occurrences []dagOccurrence) []chainhash.Hash {
	seen := make(map[chainhash.Hash]struct{})
	unique := make([]chainhash.Hash, 0, len(occurrences))
	for _, occurrence := range occurrences {
		if _, ok := seen[occurrence.txID]; ok {
			continue
		}

		seen[occurrence.txID] = struct{}{}
		unique = append(unique, occurrence.txID)
	}

	return unique
}
