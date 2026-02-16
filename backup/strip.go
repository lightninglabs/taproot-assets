package backup

import (
	"bytes"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/tlv"
)

// StripProofFile takes a complete proof file blob and returns a stripped
// version with blockchain-derivable fields removed, along with hints needed
// to reconstruct those fields later.
//
// The following TLV fields are stripped from each proof transition:
//   - BlockHeader (type 4) — 80 bytes, fetchable by block height
//   - AnchorTx (type 6) — ~250-500 bytes, findable in block by txid
//   - TxMerkleProof (type 8) — ~200-300 bytes, reconstructable from block
//   - BlockHeight (type 22) — 4 bytes, stored in hint
//
// AdditionalInputs (nested proof files) are kept as-is.
func StripProofFile(proofBlob []byte) ([]byte, FileHints, error) {
	file, err := proof.DecodeFile(proofBlob)
	if err != nil {
		return nil, FileHints{}, fmt.Errorf("failed to decode "+
			"proof file: %w", err)
	}

	numProofs := file.NumProofs()
	if numProofs == 0 {
		return nil, FileHints{}, fmt.Errorf("proof file is empty")
	}

	hints := FileHints{
		Hints: make([]ProofHint, numProofs),
	}
	strippedProofs := make([]proof.Proof, numProofs)

	for i := 0; i < numProofs; i++ {
		p, err := file.ProofAt(uint32(i))
		if err != nil {
			return nil, FileHints{}, fmt.Errorf("failed to "+
				"decode proof at index %d: %w", i, err)
		}

		// Extract the hint data before stripping.
		txHash := p.AnchorTx.TxHash()
		hints.Hints[i] = ProofHint{
			AnchorTxHash: txHash,
			BlockHeight:  p.BlockHeight,
		}

		// Copy the full proof. The blockchain fields are still
		// present in memory but are omitted during encoding by
		// encodeStrippedProof, which only encodes non-blockchain
		// TLV records.
		strippedProofs[i] = *p
	}

	// Build a new file from stripped proofs using our custom encoder.
	strippedFile, err := newStrippedFile(file.Version, strippedProofs)
	if err != nil {
		return nil, FileHints{}, fmt.Errorf("failed to create "+
			"stripped proof file: %w", err)
	}

	strippedBlob, err := proof.EncodeFile(strippedFile)
	if err != nil {
		return nil, FileHints{}, fmt.Errorf("failed to encode "+
			"stripped proof file: %w", err)
	}

	return strippedBlob, hints, nil
}

// newStrippedFile builds a proof.File from proofs using stripped encoding.
// This is similar to proof.NewFile but uses encodeStrippedProof to omit
// blockchain-derivable fields.
func newStrippedFile(v proof.Version,
	proofs []proof.Proof) (*proof.File, error) {

	file := proof.NewEmptyFile(v)

	for i := range proofs {
		strippedBytes, err := encodeStrippedProof(&proofs[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encode stripped "+
				"proof at index %d: %w", i, err)
		}

		if err := file.AppendProofRaw(strippedBytes); err != nil {
			return nil, fmt.Errorf("failed to append stripped "+
				"proof at index %d: %w", i, err)
		}
	}

	return file, nil
}

// encodeStrippedProof encodes a Proof using the same TLV format as
// Proof.Encode() but omitting the blockchain-derivable fields:
// BlockHeader (4), AnchorTx (6), TxMerkleProof (8), BlockHeight (22).
func encodeStrippedProof(p *proof.Proof) ([]byte, error) {
	records := strippedEncodeRecords(p)

	var buf bytes.Buffer

	// Write the magic bytes prefix, same as Proof.Encode().
	if _, err := buf.Write(proof.PrefixMagicBytes[:]); err != nil {
		return nil, err
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return nil, err
	}

	if err := stream.Encode(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// strippedEncodeRecords returns the TLV record set for encoding a proof
// without blockchain-derivable fields. This mirrors Proof.EncodeRecords()
// but skips BlockHeaderRecord, AnchorTxRecord, TxMerkleProofRecord, and
// BlockHeightRecord.
//
// WARNING: This function must be kept in sync with proof.Proof.EncodeRecords().
// If new even TLV types are added to the proof encoding, they must be
// explicitly included here or they will be silently dropped from stripped
// backups.
func strippedEncodeRecords(p *proof.Proof) []tlv.Record {
	records := make([]tlv.Record, 0, 12)

	// Type 0: Version (keep).
	records = append(records, proof.VersionRecord(&p.Version))

	// Type 2: PrevOut (keep).
	records = append(records, proof.PrevOutRecord(&p.PrevOut))

	// Type 4: BlockHeader — STRIPPED.
	// Type 6: AnchorTx — STRIPPED.
	// Type 8: TxMerkleProof — STRIPPED.

	// Type 10: AssetLeaf (keep).
	records = append(records, proof.AssetLeafRecord(&p.Asset))

	// Type 12: InclusionProof (keep).
	records = append(records, proof.InclusionProofRecord(&p.InclusionProof))

	// Type 13: ExclusionProofs (keep, optional).
	if len(p.ExclusionProofs) > 0 {
		records = append(records, proof.ExclusionProofsRecord(
			&p.ExclusionProofs,
		))
	}

	// Type 15: SplitRootProof (keep, optional).
	if p.SplitRootProof != nil {
		records = append(records, proof.SplitRootProofRecord(
			&p.SplitRootProof,
		))
	}

	// Type 17: MetaReveal (keep, optional).
	if p.MetaReveal != nil {
		records = append(records, proof.MetaRevealRecord(
			&p.MetaReveal,
		))
	}

	// Type 19: AdditionalInputs (keep as-is, optional).
	if len(p.AdditionalInputs) > 0 {
		records = append(records, proof.AdditionalInputsRecord(
			&p.AdditionalInputs,
		))
	}

	// Type 21: ChallengeWitness (keep, optional).
	if p.ChallengeWitness != nil {
		records = append(records, proof.ChallengeWitnessRecord(
			&p.ChallengeWitness,
		))
	}

	// Type 22: BlockHeight — STRIPPED.

	// Type 23: GenesisReveal (keep, optional).
	if p.GenesisReveal != nil {
		records = append(records, proof.GenesisRevealRecord(
			&p.GenesisReveal,
		))
	}

	// Type 25: GroupKeyReveal (keep, optional).
	if p.GroupKeyReveal != nil {
		records = append(records, proof.GroupKeyRevealRecord(
			&p.GroupKeyReveal,
		))
	}

	// Type 27: AltLeaves (keep, optional).
	if len(p.AltLeaves) > 0 {
		records = append(records, proof.AltLeavesRecord(
			&p.AltLeaves,
		))
	}

	// Preserve any unknown odd types.
	return asset.CombineRecords(records, p.UnknownOddTypes)
}
