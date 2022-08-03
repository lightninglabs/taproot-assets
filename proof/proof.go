package proof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/sync/errgroup"
)

var (
	// ErrInvalidTaprootProof is an error returned upon verifying an invalid
	// Taproot proof.
	ErrInvalidTaprootProof = errors.New("invalid taproot proof")

	// ErrInvalidTxMerkleProof is an error returned upon verifying an
	// invalid on-chain transaction merkle proof.
	ErrInvalidTxMerkleProof = errors.New("invalid transaction merkle proof")

	// ErrMissingExclusionProofs is an error returned upon noticing an
	// exclusion proof for a P2TR output is missing.
	ErrMissingExclusionProofs = errors.New("missing exclusion proof(s)")
)

// Proof encodes all of the data necessary to prove a valid state transition for
// an asset has occurred within an on-chain transaction.
type Proof struct {
	// PrevOut is the previous on-chain outpoint of the asset.
	PrevOut wire.OutPoint

	// BlockHeader is the current block header committing to the on-chain
	// transaction attempting an asset state transition.
	BlockHeader wire.BlockHeader

	// AnchorTx is the on-chain transaction attempting the asset state
	// transition.
	AnchorTx wire.MsgTx

	// TxMerkleProof is the merkle proof for AnchorTx used to prove its
	// inclusion within BlockHeader.
	TxMerkleProof TxMerkleProof

	// Asset is the resulting asset after its state transition.
	Asset asset.Asset

	// InclusionProof is the TaprootProof proving the new inclusion of the
	// resulting asset within AnchorTx.
	InclusionProof TaprootProof

	// ExclusionProofs is the set of TaprootProofs proving the exclusion of
	// the resulting asset from all other Taproot outputs within AnchorTx.
	ExclusionProofs []TaprootProof

	// AdditionalInputs is a nested full proof for any additional inputs
	// found within the resulting asset.
	AdditionalInputs []File
}

// verifyTaprootProof attempts to verify a TaprootProof for inclusion or
// exclusion of an asset.
func (p *Proof) verifyTaprootProof(proof *TaprootProof, inclusion bool) error {
	// Extract the final taproot key from the output including/excluding the
	// asset, which we'll use to compare our derived key against.
	expectedTaprootKey, err := extractTaprootKey(
		&p.AnchorTx, proof.OutputIndex,
	)
	if err != nil {
		return err
	}

	// Derive the possible taproot keys based on the proof.
	var possibleKeys []*btcec.PublicKey
	if inclusion {
		possibleKeys, err = proof.DeriveByAssetInclusion(&p.Asset)
	} else if proof.CommitmentProof != nil {
		possibleKeys, err = proof.DeriveByAssetExclusion(
			p.Asset.AssetCommitmentKey(),
			p.Asset.TaroCommitmentKey(),
		)
	} else if proof.TapscriptProof != nil {
		possibleKeys, err = proof.DeriveByTapscriptProof()
	}
	if err != nil {
		return err
	}

	// Check that at least one of them matches the expected key.
	for _, key := range possibleKeys {
		if key.IsEqual(expectedTaprootKey) {
			return nil
		}
	}

	return ErrInvalidTaprootProof
}

// verifyInclusionProof verifies the InclusionProof is valid.
func (p *Proof) verifyInclusionProof() error {
	return p.verifyTaprootProof(&p.InclusionProof, true)
}

// verifyExclusionProofs verifies all ExclusionProofs are valid.
func (p *Proof) verifyExclusionProofs() error {
	// Gather all P2TR outputs in the on-chain transaction.
	p2trOutputs := make(map[uint32]struct{})
	for i, txOut := range p.AnchorTx.TxOut {
		if uint32(i) == p.InclusionProof.OutputIndex {
			continue
		}
		if txscript.IsPayToTaproot(txOut.PkScript) {
			p2trOutputs[uint32(i)] = struct{}{}
		}
	}

	// Verify all of the encoded exclusion proofs.
	for _, exclusionProof := range p.ExclusionProofs {
		exclusionProof := exclusionProof
		err := p.verifyTaprootProof(&exclusionProof, false)
		if err != nil {
			return err
		}
		delete(p2trOutputs, exclusionProof.OutputIndex)
	}

	// If any outputs are missing a proof, fail.
	if len(p2trOutputs) > 0 {
		return ErrMissingExclusionProofs
	}
	return nil
}

// verifyAssetStateTransition verifies an asset's witnesses resulting from a
// state transition.
func (p *Proof) verifyAssetStateTransition(ctx context.Context,
	prev *AssetSnapshot) error {

	// Determine whether we have an asset split based on the resulting
	// asset's witness. If so, extract the root asset from the split asset.
	newAsset := &p.Asset
	var splitAsset *commitment.SplitAsset
	if vm.HasSplitCommitmentWitness(newAsset) {
		// In this case, an asset was created via a split, so we need
		// to first verify that asset that created the split (the new
		// asset).
		splitAsset = &commitment.SplitAsset{
			Asset:       *newAsset,
			OutputIndex: p.InclusionProof.OutputIndex,
		}
		newAsset = &splitAsset.PrevWitnesses[0].SplitCommitment.RootAsset
	}

	// Gather the set of asset inputs leading to the state transition.
	var prevAssets commitment.InputSet
	if prev != nil {
		prevAssets = commitment.InputSet{
			asset.PrevID{
				OutPoint:  p.PrevOut,
				ID:        prev.Asset.Genesis.ID(),
				ScriptKey: *prev.Asset.ScriptKey.PubKey,
			}: prev.Asset,
		}
	}

	// We'll use an err group to be able to validate all the inputs in
	// parallel, limiting the total number of goroutines to the number of
	// available CPUs. We'll also pass in a cotnext, which'll enable us to
	// bail out as soon as any of the active goroutines encounters an
	// error.
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(runtime.NumCPU())

	var assetsMtx sync.Mutex
	for _, inputProof := range p.AdditionalInputs {

		inputProof := inputProof

		errGroup.Go(func() error {
			result, err := inputProof.Verify(ctx)
			if err != nil {
				return err
			}

			assetsMtx.Lock()
			defer assetsMtx.Unlock()
			prevID := asset.PrevID{
				OutPoint:  result.OutPoint,
				ID:        result.Asset.Genesis.ID(),
				ScriptKey: *result.Asset.ScriptKey.PubKey,
			}
			prevAssets[prevID] = result.Asset

			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return fmt.Errorf("inputs invalid: %w", err)
	}

	// Spawn a new VM instance to verify the asset's state transition.
	vm, err := vm.New(newAsset, splitAsset, prevAssets)
	if err != nil {
		return err
	}
	return vm.Execute()
}

// Verify verifies the proof by ensuring that:
//
// 1. A transaction that spends the previous asset output has a valid merkle
//    proof within a block in the chain.
// 2. A valid inclusion proof for the resulting asset is included.
// 3. A set of valid exclusion proofs for the resulting asset are included.
// 4. A set of asset inputs with valid witnesses are included that satisfy the
//    resulting state transition.
func (p *Proof) Verify(ctx context.Context,
	prev *AssetSnapshot) (*AssetSnapshot, error) {

	// 1. A transaction that spends the previous asset output has a valid
	// merkle proof within a block in the chain.
	if prev != nil && p.PrevOut != prev.OutPoint {
		return nil, ErrInvalidTaprootProof // TODO
	}
	if !txSpendsPrevOut(&p.AnchorTx, &p.PrevOut) {
		return nil, ErrInvalidTaprootProof // TODO
	}
	// TODO: Cross check BlockHeader with a bitcoin node.
	if !p.TxMerkleProof.Verify(&p.AnchorTx, p.BlockHeader.MerkleRoot) {
		return nil, ErrInvalidTxMerkleProof
	}

	// 2. A valid inclusion proof for the resulting asset is included.
	if err := p.verifyInclusionProof(); err != nil {
		return nil, err
	}

	// 3. A set of valid exclusion proofs for the resulting asset are
	// included.
	if err := p.verifyExclusionProofs(); err != nil {
		return nil, err
	}

	// 4. A set of asset inputs with valid witnesses are included that
	// satisfy the resulting state transition.
	if err := p.verifyAssetStateTransition(ctx, prev); err != nil {
		return nil, err
	}

	return &AssetSnapshot{
		Asset: &p.Asset,
		OutPoint: wire.OutPoint{
			Hash:  p.AnchorTx.TxHash(),
			Index: p.InclusionProof.OutputIndex,
		},
	}, nil
}

// EncodeRecords returns the set of known TLV records to encode a Proof.
func (p *Proof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 8)
	records = append(records, PrevOutRecord(&p.PrevOut))
	records = append(records, BlockHeaderRecord(&p.BlockHeader))
	records = append(records, AnchorTxRecord(&p.AnchorTx))
	records = append(records, TxMerkleProofRecord(&p.TxMerkleProof))
	records = append(records, AssetLeafRecord(&p.Asset))
	records = append(records, InclusionProofRecord(&p.InclusionProof))
	if len(p.ExclusionProofs) > 0 {
		records = append(records, ExclusionProofsRecord(
			&p.ExclusionProofs,
		))
	}
	if len(p.AdditionalInputs) > 0 {
		records = append(records, AdditionalInputsRecord(
			&p.AdditionalInputs,
		))
	}
	return records
}

// DecodeRecords returns the set of known TLV records to decode a Proof.
func (p *Proof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		PrevOutRecord(&p.PrevOut),
		BlockHeaderRecord(&p.BlockHeader),
		AnchorTxRecord(&p.AnchorTx),
		TxMerkleProofRecord(&p.TxMerkleProof),
		AssetLeafRecord(&p.Asset),
		InclusionProofRecord(&p.InclusionProof),
		ExclusionProofsRecord(&p.ExclusionProofs),
		AdditionalInputsRecord(&p.AdditionalInputs),
	}
}

// Encode encodes a Proof into `w`.
func (p *Proof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Encode decodes a Proof from `r`.
func (p *Proof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}
