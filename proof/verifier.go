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
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/vm"
	"golang.org/x/sync/errgroup"
)

// Verifier abstracts away from the task of verifying a proof file blob.
type Verifier interface {
	// Verify takes the passed serialized proof file, and returns a nil
	// error if the proof file is valid. A valid file should return an
	// AssetSnapshot of the final state transition of the file.
	Verify(c context.Context, blobReader io.Reader,
		headerVerifier HeaderVerifier, merkleVerifier MerkleVerifier,
		groupVerifier GroupVerifier) (*AssetSnapshot, error)
}

// BaseVerifier implements a simple verifier that loads the entire proof file
// into memory and then verifies it all at once.
type BaseVerifier struct {
}

// Verify takes the passed serialized proof file, and returns a nil
// error if the proof file is valid. A valid file should return an
// AssetSnapshot of the final state transition of the file.
func (b *BaseVerifier) Verify(ctx context.Context, blobReader io.Reader,
	headerVerifier HeaderVerifier, merkleVerifier MerkleVerifier,
	groupVerifier GroupVerifier) (*AssetSnapshot, error) {

	var proofFile File
	err := proofFile.Decode(blobReader)
	if err != nil {
		return nil, fmt.Errorf("unable to parse proof: %w", err)
	}

	return proofFile.Verify(
		ctx, headerVerifier, merkleVerifier, groupVerifier,
	)
}

// verifyTaprootProof attempts to verify a TaprootProof for inclusion or
// exclusion of an asset. If the taproot proof was an inclusion proof, then the
// TapCommitment is returned as well.
func verifyTaprootProof(anchor *wire.MsgTx, proof *TaprootProof,
	asset *asset.Asset, inclusion bool) (*commitment.TapCommitment,
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
		derivedKey    *btcec.PublicKey
		tapCommitment *commitment.TapCommitment
	)
	switch {
	// If this is an inclusion proof, then we'll derive the expected
	// taproot output key based on the revealed asset MS-SMT proof. The
	// root of this tree will then be used to assemble the top of the
	// tapscript tree, which will then be tweaked as normal with the
	// internal key to derive the expected output key.
	case inclusion:
		log.Tracef("Verifying inclusion proof for asset %v", asset.ID())
		derivedKey, tapCommitment, err = proof.DeriveByAssetInclusion(
			asset,
		)

	// If the commitment proof is present, then this is actually a
	// non-inclusion proof: we want to verify that either no root
	// commitment exists, or one does, but the asset in question isn't
	// present.
	case proof.CommitmentProof != nil:
		log.Tracef("Verifying exclusion proof for asset %v", asset.ID())
		derivedKey, err = proof.DeriveByAssetExclusion(
			asset.AssetCommitmentKey(),
			asset.TapCommitmentKey(),
		)

	// If this is a tapscript proof, then we want to verify that the target
	// output DOES NOT contain any sort of Taproot Asset commitment.
	case proof.TapscriptProof != nil:
		log.Tracef("Verifying tapscript proof")
		derivedKey, err = proof.DeriveByTapscriptProof()
	}
	if err != nil {
		return nil, err
	}

	// The derive key should match the extracted key.
	if derivedKey.IsEqual(expectedTaprootKey) {
		return tapCommitment, nil
	}

	return nil, commitment.ErrInvalidTaprootProof
}

// verifyInclusionProof verifies the InclusionProof is valid.
func (p *Proof) verifyInclusionProof() (*commitment.TapCommitment, error) {
	return verifyTaprootProof(
		&p.AnchorTx, &p.InclusionProof, &p.Asset, true,
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
			&p.AnchorTx, &exclusionProof, &p.Asset, false,
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
	prev *AssetSnapshot, headerVerifier HeaderVerifier,
	merkleVerifier MerkleVerifier, groupVerifier GroupVerifier) (bool,
	error) {

	// Determine whether we have an asset split based on the resulting
	// asset's witness. If so, extract the root asset from the split asset.
	newAsset := &p.Asset
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
			result, err := inputProof.Verify(
				ctx, headerVerifier, merkleVerifier,
				groupVerifier,
			)
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
		return false, fmt.Errorf("inputs invalid: %w", err)
	}

	// Spawn a new VM instance to verify the asset's state transition.
	var splitAssets []*commitment.SplitAsset
	if splitAsset != nil {
		splitAssets = append(splitAssets, splitAsset)
	}
	engine, err := vm.New(newAsset, splitAssets, prevAssets)
	if err != nil {
		return false, err
	}
	return splitAsset != nil, engine.Execute()
}

// verifyChallengeWitness verifies the challenge witness by constructing a
// well-defined 1-in-1-out packet and verifying the witness is valid for that
// virtual transaction.
func (p *Proof) verifyChallengeWitness() (bool, error) {
	// The challenge witness packet always has one input and one output,
	// independent of how the asset was created. The chain params are only
	// needed when encoding/decoding a vPkt, so it doesn't matter what
	// network we choose as we only need the packet to get the witness.
	ownedAsset := p.Asset.Copy()
	prevId, proofAsset := CreateOwnershipProofAsset(ownedAsset)

	// The 1-in-1-out packet for the challenge witness is well-defined, we
	// don't have to do any extra checks, just set the witness and then
	// validate it.
	proofAsset.PrevWitnesses[0].TxWitness = p.ChallengeWitness

	prevAssets := commitment.InputSet{
		prevId: ownedAsset,
	}
	engine, err := vm.New(proofAsset, nil, prevAssets)
	if err != nil {
		return false, err
	}

	return p.Asset.HasSplitCommitmentWitness(), engine.Execute()
}

// CreateOwnershipProofAsset creates a virtual asset that can be used to prove
// ownership of an asset. The virtual asset is created by spending the full
// asset into a NUMS key.
func CreateOwnershipProofAsset(
	ownedAsset *asset.Asset) (asset.PrevID, *asset.Asset) {

	// We create the ownership proof by creating a virtual input and output
	// that spends the full asset into a NUMS key. But in order to prevent
	// that witness to be used in an actual state transition by a malicious
	// actor, we create the signature over an empty outpoint. This means the
	// witness is fully valid, but a full transition proof can never be
	// created, as the previous outpoint would not match the one that
	// actually goes on chain.
	//
	// TODO(guggero): Revisit this proof once we support pocket universes.
	emptyOutPoint := wire.OutPoint{}
	prevId := asset.PrevID{
		ID:       ownedAsset.ID(),
		OutPoint: emptyOutPoint,
		ScriptKey: asset.ToSerialized(
			ownedAsset.ScriptKey.PubKey,
		),
	}

	outputAsset := ownedAsset.Copy()
	outputAsset.ScriptKey = asset.NUMSScriptKey
	outputAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &prevId,
	}}

	return prevId, outputAsset
}

// verifyGenesisReveal checks that the genesis reveal present in the proof at
// minting validates against the asset ID and proof details.
func (p *Proof) verifyGenesisReveal() error {
	reveal := p.GenesisReveal
	if reveal == nil {
		return ErrGenesisRevealRequired
	}

	// Make sure the genesis reveal is consistent with the TLV fields in
	// the state transition proof.
	if reveal.FirstPrevOut != p.PrevOut {
		return ErrGenesisRevealPrevOutMismatch
	}

	// If this asset has an empty meta reveal, then the meta hash must be
	// empty. Otherwise, the meta hash must match the meta reveal.
	var proofMeta [asset.MetaHashLen]byte
	if p.MetaReveal == nil && reveal.MetaHash != proofMeta {
		return ErrGenesisRevealMetaRevealRequired
	}

	if p.MetaReveal != nil {
		proofMeta = p.MetaReveal.MetaHash()
	}

	if reveal.MetaHash != proofMeta {
		return ErrGenesisRevealMetaHashMismatch
	}

	if reveal.OutputIndex != p.InclusionProof.OutputIndex {
		return ErrGenesisRevealOutputIndexMismatch
	}

	// The genesis reveal determines the ID of an asset, so make sure it is
	// consistent. Since the asset ID commits to all fields of the genesis,
	// this is equivalent to checking equality for the genesis tag and type
	// fields that have not yet been verified.
	assetID := p.Asset.ID()
	if reveal.ID() != assetID {
		return ErrGenesisRevealAssetIDMismatch
	}

	return nil
}

// verifyGenesisGroupKey verifies that the group key attached to the asset in
// this proof has already been verified.
func (p *Proof) verifyGenesisGroupKey(groupVerifier GroupVerifier) error {
	groupKey := p.Asset.GroupKey.GroupPubKey
	err := groupVerifier(&groupKey)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrGroupKeyUnknown, err.Error())
	}

	return nil
}

// verifyGroupKeyReveal verifies that the group key reveal can be used to derive
// the same key as the group key specified for the asset.
func (p *Proof) verifyGroupKeyReveal() error {
	groupKey := p.Asset.GroupKey
	reveal := p.GroupKeyReveal

	revealedKey, err := reveal.GroupPubKey(p.Asset.ID())
	if err != nil {
		return err
	}

	// Make sure the derived key matches what we expect.
	if !groupKey.GroupPubKey.IsEqual(revealedKey) {
		return ErrGroupKeyRevealMismatch
	}

	return nil
}

// HeaderVerifier is a callback function which returns an error if the given
// block header is invalid (usually: not present on chain).
type HeaderVerifier func(blockHeader wire.BlockHeader, blockHeight uint32) error

// MerkleVerifier is a callback function which returns an error if the given
// merkle proof is invalid.
type MerkleVerifier func(tx *wire.MsgTx, proof *TxMerkleProof,
	merkleRoot [32]byte) error

// DefaultMerkleVerifier is a default implementation of the MerkleVerifier
// callback function. It verifies the merkle proof by checking that the
// transaction hash is included in the merkle tree with the given merkle root.
func DefaultMerkleVerifier(tx *wire.MsgTx, proof *TxMerkleProof,
	merkleRoot [32]byte) error {

	if !proof.Verify(tx, merkleRoot) {
		return ErrInvalidTxMerkleProof
	}

	return nil
}

// GroupVerifier is a callback function which returns an error if the given
// group key has not been imported by the tapd daemon. This can occur if the
// issuance proof for the group anchor has not been imported or synced.
type GroupVerifier func(groupKey *btcec.PublicKey) error

// GroupAnchorVerifier is a callback function which returns an error if the
// given genesis is not the asset genesis of the group anchor. This callback
// should return an error for any reissuance into an existing group.
type GroupAnchorVerifier func(gen *asset.Genesis,
	groupKey *asset.GroupKey) error

// Verify verifies the proof by ensuring that:
//
//  0. A proof has a valid version.
//  1. A transaction that spends the previous asset output has a valid merkle
//     proof within a block in the chain.
//  2. A valid inclusion proof for the resulting asset is included.
//  3. A valid inclusion proof for the split root, if the resulting asset
//     is a split asset.
//  4. A set of valid exclusion proofs for the resulting asset are included.
//  5. A set of asset inputs with valid witnesses are included that satisfy the
//     resulting state transition.
func (p *Proof) Verify(ctx context.Context, prev *AssetSnapshot,
	headerVerifier HeaderVerifier, merkleVerifier MerkleVerifier,
	groupVerifier GroupVerifier) (*AssetSnapshot, error) {

	// 0. Check only for the proof version.
	if p.IsUnknownVersion() {
		return nil, ErrUnknownVersion
	}

	// Ensure proof asset is valid.
	if err := p.Asset.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate proof asset: "+
			"%w", err)
	}

	// 1. A transaction that spends the previous asset output has a valid
	// merkle proof within a block in the chain.
	if prev != nil && p.PrevOut != prev.OutPoint {
		return nil, fmt.Errorf("%w: prev output mismatch",
			commitment.ErrInvalidTaprootProof)
	}
	if !txSpendsPrevOut(&p.AnchorTx, &p.PrevOut) {
		return nil, fmt.Errorf("%w: doesn't spend prev output",
			commitment.ErrInvalidTaprootProof)
	}

	// Cross-check block header with a bitcoin node.
	err := headerVerifier(p.BlockHeader, p.BlockHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to validate proof block "+
			"header: %w", err)
	}

	// Assert that the transaction is in the block via the merkle proof.
	err = merkleVerifier(
		&p.AnchorTx, &p.TxMerkleProof, p.BlockHeader.MerkleRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to validate merkle proof: "+
			"%w", err, ErrInvalidTxMerkleProof)
	}

	// TODO(jhb): check for genesis asset and populate asset fields before
	// further verification

	// 2. A valid inclusion proof for the resulting asset is included.
	tapCommitment, err := p.verifyInclusionProof()
	if err != nil {
		return nil, fmt.Errorf("invalid inclusion proof: %w", err)
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
		return nil, fmt.Errorf("invalid exclusion proof: %w", err)
	}

	// 5. If this is a genesis asset, start by verifying the
	// genesis reveal, which should be present for genesis assets.
	// Non-genesis assets must not have a genesis or meta reveal.
	isGenesisAsset := p.Asset.IsGenesisAsset()
	hasGenesisReveal := p.GenesisReveal != nil
	hasMetaReveal := p.MetaReveal != nil

	switch {
	case !isGenesisAsset && hasGenesisReveal:
		return nil, ErrNonGenesisAssetWithGenesisReveal
	case !isGenesisAsset && hasMetaReveal:
		return nil, ErrNonGenesisAssetWithMetaReveal
	case isGenesisAsset && !hasGenesisReveal:
		return nil, ErrGenesisRevealRequired
	case isGenesisAsset && hasGenesisReveal:
		if err := p.verifyGenesisReveal(); err != nil {
			return nil, err
		}
	}

	// 6. Verify group key and group key reveal for genesis assets. Not all
	// assets have a group key, and should therefore not have a group key
	// reveal. The group key reveal must be present for group anchors, and
	// the group key must be present for any reissuance into an asset group.
	hasGroupKeyReveal := p.GroupKeyReveal != nil
	hasGroupKey := p.Asset.GroupKey != nil
	switch {
	case !isGenesisAsset && hasGroupKeyReveal:
		return nil, ErrNonGenesisAssetWithGroupKeyReveal

	case isGenesisAsset && !hasGroupKey && hasGroupKeyReveal:
		return nil, ErrGroupKeyRequired

	case isGenesisAsset && hasGroupKey && !hasGroupKeyReveal:
		// A reissuance must be for an asset group that has already
		// been imported and verified.
		if err := p.verifyGenesisGroupKey(groupVerifier); err != nil {
			return nil, err
		}

	case isGenesisAsset && hasGroupKey && hasGroupKeyReveal:
		if err := p.verifyGroupKeyReveal(); err != nil {
			return nil, err
		}
	}

	// 7. Verify group key for asset transfers. Any asset with a group key
	// must carry a group key that has already been imported and verified.
	if !isGenesisAsset && hasGroupKey {
		if err := p.verifyGenesisGroupKey(groupVerifier); err != nil {
			return nil, err
		}
	}

	// 8. Either a set of asset inputs with valid witnesses is included that
	// satisfy the resulting state transition or a challenge witness is
	// provided as part of an ownership proof.
	var splitAsset bool
	switch {
	case prev == nil && p.ChallengeWitness != nil:
		splitAsset, err = p.verifyChallengeWitness()

	default:
		splitAsset, err = p.verifyAssetStateTransition(
			ctx, prev, headerVerifier, merkleVerifier,
			groupVerifier,
		)
	}
	if err != nil {
		return nil, err
	}

	// 8. At this point we know there is an inclusion proof, which must be
	// a commitment proof. So we can extract the tapscript preimage directly
	// from there.
	tapscriptPreimage := p.InclusionProof.CommitmentProof.TapSiblingPreimage

	// TODO(roasbeef): need tx index as well

	return &AssetSnapshot{
		Asset: &p.Asset,
		OutPoint: wire.OutPoint{
			Hash:  p.AnchorTx.TxHash(),
			Index: p.InclusionProof.OutputIndex,
		},
		AnchorBlockHash:   p.BlockHeader.BlockHash(),
		AnchorBlockHeight: p.BlockHeight,
		AnchorTx:          &p.AnchorTx,
		OutputIndex:       p.InclusionProof.OutputIndex,
		InternalKey:       p.InclusionProof.InternalKey,
		ScriptRoot:        tapCommitment,
		TapscriptSibling:  tapscriptPreimage,
		SplitAsset:        splitAsset,
		MetaReveal:        p.MetaReveal,
	}, nil
}

// Verify attempts to verify a full proof file starting from the asset's
// genesis.
//
// The passed context can be used to exit early from the inner proof
// verification loop.
//
// TODO(roasbeef): pass in the expected genesis point here?
func (f *File) Verify(ctx context.Context, headerVerifier HeaderVerifier,
	merkleVerifier MerkleVerifier, groupVerifier GroupVerifier) (

	*AssetSnapshot, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check only for the proof file version and not file emptiness,
	// since an empty proof file should return a nil error.
	if f.IsUnknownVersion() {
		return nil, ErrUnknownVersion
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

		result, err := decodedProof.Verify(
			ctx, prev, headerVerifier, merkleVerifier,
			groupVerifier,
		)
		if err != nil {
			return nil, err
		}
		prev = result
	}

	return prev, nil
}
