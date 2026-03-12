package backup

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// proofHintSize is the serialized size of a single ProofHint:
	// 32 bytes for AnchorTxHash + 4 bytes for BlockHeight.
	proofHintSize = 32 + 4
)

// ProofHint contains the minimal info needed to reconstruct blockchain-
// derivable fields for a single proof transition.
type ProofHint struct {
	// AnchorTxHash is the txid of the anchor transaction. This is used
	// to locate the transaction within its block during rehydration.
	AnchorTxHash [32]byte

	// BlockHeight is the height of the block containing the anchor
	// transaction.
	BlockHeight uint32
}

// FileHints contains one hint per proof in a file, in chain order (genesis
// first).
type FileHints struct {
	// Hints contains the rehydration hints for each proof transition.
	Hints []ProofHint
}

// EncodeFileHints serializes FileHints to a writer. The format is:
// [varint num_hints][hint_0][hint_1]...
// where each hint is [32 bytes AnchorTxHash][4 bytes BlockHeight big-endian].
func EncodeFileHints(w io.Writer, hints FileHints) error {
	var tlvBuf [8]byte
	err := tlv.WriteVarInt(w, uint64(len(hints.Hints)), &tlvBuf)
	if err != nil {
		return fmt.Errorf("failed to write hint count: %w", err)
	}

	for i, hint := range hints.Hints {
		if _, err := w.Write(hint.AnchorTxHash[:]); err != nil {
			return fmt.Errorf("failed to write anchor tx hash "+
				"for hint %d: %w", i, err)
		}

		err := binary.Write(w, binary.BigEndian, hint.BlockHeight)
		if err != nil {
			return fmt.Errorf("failed to write block height "+
				"for hint %d: %w", i, err)
		}
	}

	return nil
}

// DecodeFileHints deserializes FileHints from a reader.
func DecodeFileHints(r io.Reader) (FileHints, error) {
	var tlvBuf [8]byte
	numHints, err := tlv.ReadVarInt(r, &tlvBuf)
	if err != nil {
		return FileHints{}, fmt.Errorf("failed to read hint "+
			"count: %w", err)
	}

	// Guard against OOM from malformed input. A proof file cannot have
	// more transitions than the backup has assets.
	if numHints > maxBackupAssets {
		return FileHints{}, fmt.Errorf("hint count %d exceeds "+
			"maximum %d", numHints, maxBackupAssets)
	}

	hints := make([]ProofHint, numHints)
	for i := uint64(0); i < numHints; i++ {
		_, err := io.ReadFull(r, hints[i].AnchorTxHash[:])
		if err != nil {
			return FileHints{}, fmt.Errorf("failed to read "+
				"anchor tx hash for hint %d: %w", i, err)
		}

		err = binary.Read(r, binary.BigEndian, &hints[i].BlockHeight)
		if err != nil {
			return FileHints{}, fmt.Errorf("failed to read "+
				"block height for hint %d: %w", i, err)
		}
	}

	return FileHints{Hints: hints}, nil
}
