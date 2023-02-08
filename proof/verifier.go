package proof

import (
	"context"
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
	"golang.org/x/sync/errgroup"
)

// Verifier abstracts away from the task of verifying a proof file blob.
type Verifier interface {
	// Verify takes the passed serialized proof file, and returns a nil
	// error if the proof file is valid. A valid file should return an
	// AssetSnapshot of the final state transition of the file.
	Verify(c context.Context, blobReader io.Reader,
		headerVerifier HeaderVerifier) (*AssetSnapshot, error)
}

// BaseVerifier implements a simple verifier that loads the entire proof file
// into memory and then verifies it all at once.
type BaseVerifier struct {
}

// Verify takes the passed serialized proof file, and returns a nil
// error if the proof file is valid. A valid file should return an
// AssetSnapshot of the final state transition of the file.
func (b *BaseVerifier) Verify(ctx context.Context, blobReader io.Reader,
	headerVerifier HeaderVerifier) (*AssetSnapshot, error) {

	var proofFile File
	err := proofFile.Decode(blobReader)
	if err != nil {
		return nil, fmt.Errorf("unable to parse proof: %w", err)
	}

	return proofFile.Verify(ctx, headerVerifier)
}

// verifyTaprootProof attempts to verify a TaprootProof for inclusion or
// exclusion of an asset. If the taproot proof was an inclusion proof, then the
// TaroCommitment is returned as well.
func verifyTaprootProof(anchor *wire.MsgTx, proof *TaprootProof,
	asset *asset.Asset, inclusion bool) (*commitment.TaroCommitment,
	error) {

	// Extract the final taproot key from the output including/excluding the
	// asset, which we'll use to compare our derived key against.
	expectedTaprootKey, err := ExtractTaprootKey(
		anchor, proof.OutputIndex,
	)
	if err != nil {
		return nil, err
	}

	// For each proof type, we'll map this to a single key based on the
	// self-identified pre-image type in the specified proof.
	var (
		derivedKey     *btcec.PublicKey
		taroCommitment *commitment.TaroCommitment
	)
	switch {
	// If this is an inclusion proof, then we'll derive the expected
	// taproot output key based on the revealed asset MS-SMT proof. The
	// root of this tree will then be used to assemble the top of the
	// tapscript tree, which will then be tweaked as normal with the
	// internal key to derive the expected output key.
	case inclusion:
		derivedKey, taroCommitment, err = proof.DeriveByAssetInclusion(
			asset,
		)

	// If the commitment proof is present, then this is actually a
	// non-inclusion proof: we want to verify that either no root
	// commitment exists, or one does, but the asset in question isn't
	// present.
	case proof.CommitmentProof != nil:
		derivedKey, err = proof.DeriveByAssetExclusion(
			asset.AssetCommitmentKey(),
			asset.TaroCommitmentKey(),
		)

	// If this is a tapscript proof, then we want to verify that the target
	// output DOES NOT contain any sort of Taro commitment.
	case proof.TapscriptProof != nil:
		derivedKey, err = proof.DeriveByTapscriptProof()
	}
	if err != nil {
		return nil, err
	}

	// The derive key should match the extracted key.
	if derivedKey.IsEqual(expectedTaprootKey) {
		return taroCommitment, nil
	}

	return nil, ErrInvalidTaprootProof
}

// verifyInclusionProof verifies the InclusionProof is valid.
func (p *Proof) verifyInclusionProof() (*commitment.TaroCommitment, error) {
	return verifyTaprootProof(
		&p.AnchorTx, &p.InclusionProof, p.Asset, true,
	)
}

// verifySplitRootProof verifies the SplitRootProof is valid.
func (p *Proof) verifySplitRootProof() error {
	rootAsset := &p.Asset.PrevWitnesses[0].SplitCommitment.RootAsset
	_, err := verifyTaprootProof(
		&p.AnchorTx, p.SplitRootProof, rootAsset, true,
	)

	return err
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
		_, err := verifyTaprootProof(
			&p.AnchorTx, &exclusionProof, p.Asset, false,
		)
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
// state transition. This method returns the split asset information if this
// state transition represents an asset split.
func (p *Proof) verifyAssetStateTransition(ctx context.Context,
	prev *AssetSnapshot, headerVerifier HeaderVerifier) (
	*commitment.SplitAsset, error) {

	// Determine whether we have an asset split based on the resulting
	// asset's witness. If so, extract the root asset from the split asset.
	newAsset := p.Asset
	var splitAsset *commitment.SplitAsset
	if newAsset.HasSplitCommitmentWitness() {
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
				OutPoint: p.PrevOut,
				ID:       prev.Asset.Genesis.ID(),
				ScriptKey: asset.ToSerialized(
					prev.Asset.ScriptKey.PubKey,
				),
			}: prev.Asset,
		}
	}

	// We'll use an err group to be able to validate all the inputs in
	// parallel, limiting the total number of goroutines to the number of
	// available CPUs. We'll also pass in a context, which'll enable us to
	// bail out as soon as any of the active goroutines encounters an
	// error.
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(runtime.NumCPU())

	var assetsMtx sync.Mutex
	for _, inputProof := range p.AdditionalInputs {
		inputProof := inputProof

		errGroup.Go(func() error {
			result, err := inputProof.Verify(ctx, headerVerifier)
			if err != nil {
				return err
			}

			assetsMtx.Lock()
			defer assetsMtx.Unlock()
			prevID := asset.PrevID{
				OutPoint: result.OutPoint,
				ID:       result.Asset.Genesis.ID(),
				ScriptKey: asset.ToSerialized(
					result.Asset.ScriptKey.PubKey,
				),
			}
			prevAssets[prevID] = result.Asset

			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("inputs invalid: %w", err)
	}

	// Spawn a new VM instance to verify the asset's state transition.
	var splitAssets []*commitment.SplitAsset
	if splitAsset != nil {
		splitAssets = append(splitAssets, splitAsset)
	}
	engine, err := vm.New(newAsset, splitAssets, prevAssets)
	if err != nil {
		return nil, err
	}
	return splitAsset, engine.Execute()
}

// HeaderVerifier is a callback function which returns an error if the given
// block header is invalid (usually: not present on chain).
type HeaderVerifier func(blockHeader wire.BlockHeader) error

// Verify verifies the proof by ensuring that:
//
//  1. A transaction that spends the previous asset output has a valid merkle
//     proof within a block in the chain.
//  2. A valid inclusion proof for the resulting asset is included.
//  3. A valid inclusion proof for the split root, if the resulting asset
//     is a split asset.
//  4. A set of valid exclusion proofs for the resulting asset are included.
//  5. A set of asset inputs with valid witnesses are included that satisfy the
//     resulting state transition.
func (p *Proof) Verify(ctx context.Context, prev *AssetSnapshot,
	headerVerifier HeaderVerifier) (*AssetSnapshot, error) {

	// 1. A transaction that spends the previous asset output has a valid
	// merkle proof within a block in the chain.
	if prev != nil && p.PrevOut != prev.OutPoint {
		return nil, ErrInvalidTaprootProof // TODO
	}
	if !txSpendsPrevOut(&p.AnchorTx, &p.PrevOut) {
		return nil, ErrInvalidTaprootProof // TODO
	}

	// Cross-check block header with a bitcoin node.
	err := headerVerifier(p.BlockHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to validate proof block "+
			"header: %w", err)
	}

	if !p.TxMerkleProof.Verify(&p.AnchorTx, p.BlockHeader.MerkleRoot) {
		return nil, ErrInvalidTxMerkleProof
	}

	// 2. A valid inclusion proof for the resulting asset is included.
	taroCommitment, err := p.verifyInclusionProof()
	if err != nil {
		return nil, err
	}

	// 3. A valid inclusion proof for the split root, if the resulting asset
	// is a split asset.
	if p.Asset.HasSplitCommitmentWitness() {
		if p.SplitRootProof == nil {
			return nil, ErrMissingSplitRootProof
		}

		if err := p.verifySplitRootProof(); err != nil {
			return nil, err
		}
	}

	// 4. A set of valid exclusion proofs for the resulting asset are
	// included.
	if err := p.verifyExclusionProofs(); err != nil {
		return nil, err
	}

	// 5. A set of asset inputs with valid witnesses are included that
	// satisfy the resulting state transition.
	splitAsset, err := p.verifyAssetStateTransition(ctx, prev, headerVerifier)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): need tx index and block height as well

	return &AssetSnapshot{
		Asset: p.Asset,
		OutPoint: wire.OutPoint{
			Hash:  p.AnchorTx.TxHash(),
			Index: p.InclusionProof.OutputIndex,
		},
		AnchorBlockHash: p.BlockHeader.BlockHash(),
		AnchorTx:        &p.AnchorTx,
		OutputIndex:     p.InclusionProof.OutputIndex,
		InternalKey:     p.InclusionProof.InternalKey,
		ScriptRoot:      taroCommitment,
		SplitAsset:      splitAsset != nil,
	}, nil
}

// Verify attempts to verify a full proof file starting from the asset's
// genesis.
//
// The passed context can be used to exit early from the inner proof
// verification loop.
//
// TODO(roasbeef): pass in the expected genesis point here?
func (f *File) Verify(ctx context.Context, headerVerifier HeaderVerifier) (
	*AssetSnapshot, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var prev *AssetSnapshot
	for idx := range f.proofs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		decodedProof, err := f.ProofAt(uint32(idx))
		if err != nil {
			return nil, err
		}

		result, err := decodedProof.Verify(ctx, prev, headerVerifier)
		if err != nil {
			return nil, err
		}
		prev = result
	}

	return prev, nil
}
