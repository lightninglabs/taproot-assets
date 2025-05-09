package proof

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/vm"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

// ChainLookupGenerator is an interface that allows the creation of a chain
// lookup interface for a given proof file or single proof.
type ChainLookupGenerator interface {
	// GenFileChainLookup generates a chain lookup interface for the given
	// proof file that can be used to validate proofs.
	GenFileChainLookup(f *File) asset.ChainLookup

	// GenProofChainLookup generates a chain lookup interface for the given
	// single proof that can be used to validate proofs.
	GenProofChainLookup(p *Proof) (asset.ChainLookup, error)
}

// AssetPoint is similar to PrevID but is meant to be used for created asset
// outputs rather than those that are spent. This is similar to the concept of
// an outpoint in normal Bitcoin.
type AssetPoint = asset.PrevID

// IgnoreChecker is used during proof validation to optionally fail validation
// if a proof is known to be invalid. This can be used as a caching mechanism to
// avoid expensive validation for already known invalid proofs.
type IgnoreChecker interface {
	// IsIgnored returns true if the given prevID is known to be invalid. A
	// prevID is used here, but the check should be tested against a proof
	// result, or produced output.
	IsIgnored(prevID AssetPoint) bool
}

// VerifierCtx is a context struct that is used to pass in various interfaces
// needed during proof verification.
type VerifierCtx struct {
	HeaderVerifier HeaderVerifier

	MerkleVerifier MerkleVerifier

	GroupVerifier GroupVerifier

	GroupAnchorVerifier GroupAnchorVerifier

	ChainLookupGen ChainLookupGenerator

	IgnoreChecker lfn.Option[IgnoreChecker]
}

// Verifier abstracts away from the task of verifying a proof file blob.
type Verifier interface {
	// Verify takes the passed serialized proof file, and returns a nil
	// error if the proof file is valid. A valid file should return an
	// AssetSnapshot of the final state transition of the file.
	Verify(c context.Context, blobReader io.Reader,
		ctx VerifierCtx) (*AssetSnapshot, error)
}

// BaseVerifier implements a simple verifier that loads the entire proof file
// into memory and then verifies it all at once.
type BaseVerifier struct {
}

// P2TROutputsSTXOs is used to track stxo proofs per p2tr output in the anchor
// transaction.
type P2TROutputsSTXOs = map[uint32]fn.Set[asset.SerializedKey]

type CommittedVersions = map[uint32][]commitment.TapCommitmentVersion

// Verify takes the passed serialized proof file, and returns a nil
// error if the proof file is valid. A valid file should return an
// AssetSnapshot of the final state transition of the file.
func (b *BaseVerifier) Verify(ctx context.Context, blobReader io.Reader,
	vCtx VerifierCtx) (*AssetSnapshot, error) {

	var proofFile File
	err := proofFile.Decode(blobReader)
	if err != nil {
		return nil, fmt.Errorf("unable to parse proof: %w", err)
	}

	return proofFile.Verify(ctx, vCtx)
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
	var derivedKeys ProofCommitmentKeys
	switch {
	// If this is an inclusion proof, then we'll derive the expected
	// taproot output key based on the revealed asset MS-SMT proof. The
	// root of this tree will then be used to assemble the top of the
	// tapscript tree, which will then be tweaked as normal with the
	// internal key to derive the expected output key.
	case inclusion:
		log.Tracef("Verifying inclusion proof for asset %v", asset.ID())
		derivedKeys, err = proof.DeriveByAssetInclusion(asset, nil)

	// If the commitment proof is present, then this is actually a
	// non-inclusion proof: we want to verify that either no root
	// commitment exists, or one does, but the asset in question isn't
	// present.
	case proof.CommitmentProof != nil:
		log.Tracef("Verifying exclusion proof for asset %v", asset.ID())
		derivedKeys, err = proof.DeriveByAssetExclusion(
			asset.AssetCommitmentKey(),
			asset.TapCommitmentKey(),
		)

	// If this is a tapscript proof, then we want to verify that the target
	// output DOES NOT contain any sort of Taproot Asset commitment.
	case proof.TapscriptProof != nil:
		log.Tracef("Verifying tapscript proof")
		var derivedKey *btcec.PublicKey
		derivedKey, err = proof.DeriveByTapscriptProof()

		// The derived key must match the expected taproot key.
		if derivedKey.IsEqual(expectedTaprootKey) {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}

	// One of the derived keys should match the expected key.
	expectedKey := schnorr.SerializePubKey(expectedTaprootKey)
	for derivedKey, derivedCommitment := range derivedKeys {
		if bytes.Equal(expectedKey, derivedKey.SchnorrSerialized()) {
			return derivedCommitment, nil
		}
	}

	return nil, fmt.Errorf("%w: derived_keys=%s, expected_key=%x",
		commitment.ErrInvalidTaprootProof,
		spew.Sdump(maps.Keys(derivedKeys)), expectedKey)
}

// verifyInclusionProof verifies the InclusionProof is valid.
func (p *Proof) verifyInclusionProof() (*commitment.TapCommitment, error) {
	// Determine if we're dealing with v0 or v1 proofs.
	hasV1Proofs := p.IsVersionV1() &&
		p.InclusionProof.CommitmentProof != nil &&
		len(p.InclusionProof.CommitmentProof.STXOProofs) > 0

	if !hasV1Proofs {
		return verifyTaprootProof(
			&p.AnchorTx, &p.InclusionProof, &p.Asset, true,
		)
	}

	commitVersions := make(map[uint32][]commitment.TapCommitmentVersion)
	p2trOutputs := make(P2TROutputsSTXOs)
	outIdx := p.InclusionProof.OutputIndex
	p2trOutputs[outIdx] = make(fn.Set[asset.SerializedKey])

	// Collect the STXOs from the new asset.
	stxoAssets, err := asset.CollectSTXO(&p.Asset)
	if err != nil {
		return nil, fmt.Errorf("error collecting STXO assets: %w", err)
	}

	// Map STXOs by serialized key.
	assetMap := make(map[asset.SerializedKey]*asset.Asset)
	for idx := range stxoAssets {
		stxoAsset := stxoAssets[idx].(*asset.Asset)
		key := asset.ToSerialized(stxoAsset.ScriptKey.PubKey)
		assetMap[key] = stxoAsset
		p2trOutputs[outIdx].Add(key)
	}

	baseProof := p.InclusionProof

	verifiedCommitment, err := verifySTXOProofSet(
		&p.AnchorTx, baseProof, assetMap, p2trOutputs, commitVersions,
		true,
	)
	if err != nil {
		return nil, err
	}

	if len(p2trOutputs) > 0 {
		return nil, ErrInvalidCommitmentProof
	}

	return verifiedCommitment, nil
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
func (p *Proof) verifyExclusionProofs() (*commitment.TapCommitmentVersion,
	error) {

	// Gather all P2TR outputs in the on-chain transaction. The STXO proofs
	// are tracked using a set of serialized keys. We ignore that set when
	// verifying V0 exclusion proofs.
	p2trOutputs := make(fn.Set[uint32])
	for i, txOut := range p.AnchorTx.TxOut {
		if uint32(i) == p.InclusionProof.OutputIndex {
			continue
		}
		if !txscript.IsPayToTaproot(txOut.PkScript) {
			continue
		}

		p2trOutputs.Add(uint32(i))
	}

	// There is nothing to check so return early.
	if len(p2trOutputs) == 0 {
		return nil, nil
	}

	commitVersions := make(CommittedVersions)

	p2trOutputCopy := fn.NewSet(p2trOutputs.ToSlice()...)
	err := p.verifyV0ExclusionProofs(p2trOutputCopy, commitVersions)
	if err != nil {
		return nil, err
	}

	// Early pass to determine if we're dealing with v0 or v1 proofs.
	hasV1Proofs := p.IsVersionV1() &&
		len(p.ExclusionProofs) > 0 &&
		p.ExclusionProofs[0].CommitmentProof != nil &&
		len(p.ExclusionProofs[0].CommitmentProof.STXOProofs) > 0

	if hasV1Proofs {
		p2trOutputCopy = fn.NewSet(p2trOutputs.ToSlice()...)
		err := p.verifyV1ExclusionProofs(p2trOutputCopy, commitVersions)
		if err != nil {
			return nil, err
		}
	}

	// If no commitments in proofs, no version to return.
	if len(commitVersions) == 0 {
		return nil, nil
	}

	// All proofs must have similar versions.
	return verifySTXOVersions(commitVersions)
}

// verifyV0ExclusionProofs verifies all version 1 exclusion proofs.
func (p *Proof) verifyV0ExclusionProofs(p2trOutputs fn.Set[uint32],
	commitVersions CommittedVersions) error {

	// Verify all of the encoded v0 exclusion proofs.
	for idx := range p.ExclusionProofs {
		exclusionProof := p.ExclusionProofs[idx]

		derivedCommitment, err := verifyTaprootProof(
			&p.AnchorTx, &exclusionProof, &p.Asset, false,
		)
		if err != nil {
			return fmt.Errorf("error verifying STXO proof: %w", err)
		}

		outputIdx := exclusionProof.OutputIndex
		delete(p2trOutputs, exclusionProof.OutputIndex)

		// Store commitment version if Taproot Asset commitment present.
		if derivedCommitment != nil {
			commitVersions[outputIdx] = append(
				commitVersions[outputIdx],
				derivedCommitment.Version,
			)
		}
	}

	// If any outputs are missing a proof, fail.
	if len(p2trOutputs) > 0 {
		return ErrMissingExclusionProofs
	}

	return nil
}

// verifyV1ExclusionProofs verifies all version 2 exclusion proofs.
func (p *Proof) verifyV1ExclusionProofs(p2trOutputs fn.Set[uint32],
	commitVersions CommittedVersions) error {

	// Collect the STXOs from the new asset.
	stxoAssets, err := asset.CollectSTXO(&p.Asset)
	if err != nil {
		return fmt.Errorf("error collecting STXO assets: %w", err)
	}

	// Create a P2TROutputsSTXOs from p2trOutputs and map STXOs by
	// serialized key.
	assetMap := make(map[asset.SerializedKey]*asset.Asset)
	p2trOutputsSTXOs := make(P2TROutputsSTXOs)
	for outIdx := range p2trOutputs {
		p2trOutputsSTXOs[outIdx] = make(fn.Set[asset.SerializedKey])
	}

	for idx := range stxoAssets {
		stxoAsset := stxoAssets[idx].(*asset.Asset)
		key := asset.ToSerialized(stxoAsset.ScriptKey.PubKey)
		assetMap[key] = stxoAsset
		for outIdx := range p2trOutputs {
			p2trOutputsSTXOs[outIdx].Add(key)
		}
	}

	for idx := range p.ExclusionProofs {
		exclusionProof := p.ExclusionProofs[idx]
		if exclusionProof.TapscriptProof != nil &&
			exclusionProof.TapscriptProof.Bip86 {

			continue
		}

		_, err := verifySTXOProofSet(
			&p.AnchorTx, exclusionProof, assetMap, p2trOutputsSTXOs,
			commitVersions, false,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifySTXOProofSet verifies a set of STXO proofs.
func verifySTXOProofSet(anchorTx *wire.MsgTx, baseProof TaprootProof,
	assetMap map[asset.SerializedKey]*asset.Asset,
	p2trOutputs P2TROutputsSTXOs,
	commitVersions map[uint32][]commitment.TapCommitmentVersion,
	inclusion bool) (*commitment.TapCommitment, error) {

	var verifiedCommitment *commitment.TapCommitment
	for key := range baseProof.CommitmentProof.STXOProofs {
		stxoProof := baseProof.CommitmentProof.STXOProofs[key]
		stxoAsset := assetMap[key]
		stxoCombinedProof := MakeSTXOProof(baseProof, &stxoProof)

		var err error
		verifiedCommitment, err = verifyTaprootProof(
			anchorTx, &stxoCombinedProof, stxoAsset, inclusion,
		)
		if err != nil {
			return nil, fmt.Errorf("error verifying STXO "+
				"proof: %w", err)
		}

		outIdx := stxoCombinedProof.OutputIndex
		delete(p2trOutputs[outIdx], key)
		if len(p2trOutputs[outIdx]) == 0 {
			delete(p2trOutputs, outIdx)
		}

		commitVersions[outIdx] = append(
			commitVersions[outIdx], verifiedCommitment.Version,
		)
	}

	return verifiedCommitment, nil
}

// MakeSTXOProof creates a new proof for an STXO reusing the base proof while
// replacing commitmentProof but the stxoProof.
func MakeSTXOProof(baseProof TaprootProof,
	stxoProof *commitment.Proof) TaprootProof {

	return TaprootProof{
		OutputIndex: baseProof.OutputIndex,
		InternalKey: baseProof.InternalKey,
		CommitmentProof: &CommitmentProof{
			Proof: commitment.Proof{
				TaprootAssetProof: stxoProof.TaprootAssetProof,
				AssetProof:        stxoProof.AssetProof,
				UnknownOddTypes:   stxoProof.UnknownOddTypes,
			},
			TapSiblingPreimage: baseProof.CommitmentProof.
				TapSiblingPreimage,
		},
		TapscriptProof:  baseProof.TapscriptProof,
		UnknownOddTypes: baseProof.UnknownOddTypes,
	}
}

// verifySTXOVersions verifies all STXO versions match.
func verifySTXOVersions(versions map[uint32][]commitment.TapCommitmentVersion) (
	*commitment.TapCommitmentVersion, error) {

	firstVersion := maps.Values(versions)[0][0]

	for outIdx, stxoVersions := range versions {
		for idx := range stxoVersions {
			ver := stxoVersions[idx]
			if !commitment.IsSimilarTapCommitmentVersion(
				&firstVersion, &ver,
			) {

				log.Tracef("output %d commit version %d, "+
					"first version %d",
					outIdx, ver, firstVersion)

				return nil, fmt.Errorf("mixed anchor " +
					"commitment versions")
			}
		}
	}

	return &firstVersion, nil
}

// verifyAssetStateTransition verifies an asset's witnesses resulting from a
// state transition. This method returns the split asset information if this
// state transition represents an asset split.
func (p *Proof) verifyAssetStateTransition(ctx context.Context,
	prev *AssetSnapshot, chainLookup asset.ChainLookup,
	vCtx VerifierCtx) (bool, error) {

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
	errGroup.SetLimit(runtime.GOMAXPROCS(0))

	var assetsMtx sync.Mutex
	for _, inputProof := range p.AdditionalInputs {
		inputProof := inputProof

		errGroup.Go(func() error {
			result, err := inputProof.Verify(ctx, vCtx)
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

	verifyOpts := []vm.NewEngineOpt{
		vm.WithChainLookup(chainLookup),
		vm.WithBlockHeight(p.BlockHeight),
	}
	engine, err := vm.New(newAsset, splitAssets, prevAssets, verifyOpts...)
	if err != nil {
		return false, err
	}
	return splitAsset != nil, engine.Execute()
}

// verifyChallengeWitness verifies the challenge witness by constructing a
// well-defined 1-in-1-out packet and verifying the witness is valid for that
// virtual transaction.
func (p *Proof) verifyChallengeWitness(_ context.Context,
	chainLookup asset.ChainLookup,
	challengeBytes fn.Option[[32]byte]) (bool, error) {

	// The challenge witness packet always has one input and one output,
	// independent of how the asset was created. The chain params are only
	// needed when encoding/decoding a vPkt, so it doesn't matter what
	// network we choose as we only need the packet to get the witness.
	ownedAsset := p.Asset.Copy()
	prevId, proofAsset := CreateOwnershipProofAsset(
		ownedAsset, challengeBytes,
	)

	// The 1-in-1-out packet for the challenge witness is well-defined, we
	// don't have to do any extra checks, just set the witness and then
	// validate it.
	proofAsset.PrevWitnesses[0].TxWitness = p.ChallengeWitness

	prevAssets := commitment.InputSet{
		prevId: ownedAsset,
	}

	verifyOpts := vm.WithChainLookup(chainLookup)
	engine, err := vm.New(proofAsset, nil, prevAssets, verifyOpts)
	if err != nil {
		return false, err
	}

	return p.Asset.HasSplitCommitmentWitness(), engine.Execute()
}

// CreateOwnershipProofAsset creates a virtual asset that can be used to prove
// ownership of an asset. The virtual asset is created by spending the full
// asset into a NUMS key. If a challenge is defined, the NUMS key will be
// modified based on that value.
func CreateOwnershipProofAsset(ownedAsset *asset.Asset,
	challengeBytes fn.Option[[32]byte]) (asset.PrevID, *asset.Asset) {

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

	// The ownership proof needs to be a 1-in-1-out transaction. So it will
	// definitely not have a split commitment. Keeping the split commitment
	// of the copied owned asset would lead to an issue with the
	// non-inflation check we have in the VM that takes the split commitment
	// root sum as the expected total output amount. We also clear any time
	// locks, as they don't apply to the ownership proof.
	//
	// This is handled by CopySpendTemplate.
	outputAsset := ownedAsset.CopySpendTemplate()

	outputAsset.ScriptKey = asset.GenChallengeNUMS(challengeBytes)
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

// ProofVerificationOption is an option that may be applied on
// *proofVerificationOpts.
type ProofVerificationOption func(p *proofVerificationParams)

// proofVerificationParams is a struct containing various options that may be
// used during proof verification
type proofVerificationParams struct {
	// ChallengeBytes is an optional field that is used when verifying an
	// ownership proof. This field is only populated when the corresponding
	// ProofVerificationOption option is defined.
	ChallengeBytes fn.Option[[32]byte]
}

// WithChallengeBytes is a ProofVerificationOption that defines some challenge
// bytes to be used when verifying this proof.
func WithChallengeBytes(challenge [32]byte) ProofVerificationOption {
	return func(p *proofVerificationParams) {
		var byteCopy [32]byte
		copy(byteCopy[:], challenge[:])
		p.ChallengeBytes = fn.Some(byteCopy)
	}
}

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
	chainLookup asset.ChainLookup, vCtx VerifierCtx,
	opts ...ProofVerificationOption) (*AssetSnapshot, error) {

	var verificationParams proofVerificationParams

	for _, opt := range opts {
		opt(&verificationParams)
	}

	// 0. Check only for the proof version.
	if p.IsUnknownVersion() {
		return nil, ErrUnknownVersion
	}

	// Ensure proof asset is valid.
	if err := p.Asset.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate proof asset: "+
			"%w", err)
	}

	assetPoint := AssetPoint{
		OutPoint:  p.OutPoint(),
		ID:        p.Asset.ID(),
		ScriptKey: asset.ToSerialized(p.Asset.ScriptKey.PubKey),
	}

	// Before we do any other validation, we'll check to see if we can halt
	// validation here, as the proof is already known to be invalid. This
	// can be used as a rejection caching mechanism.
	fail := lfn.MapOptionZ(vCtx.IgnoreChecker, func(c IgnoreChecker) bool {
		return c.IsIgnored(assetPoint)
	})
	if fail {
		return prev, fmt.Errorf("%w: asset_point=%v is ignored",
			ErrProofInvalid, assetPoint)
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
	err := vCtx.HeaderVerifier(p.BlockHeader, p.BlockHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to validate proof block "+
			"header: %w", err)
	}

	// Assert that the transaction is in the block via the merkle proof.
	err = vCtx.MerkleVerifier(
		&p.AnchorTx, &p.TxMerkleProof, p.BlockHeader.MerkleRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to validate merkle proof: "+
			"%w", err, ErrInvalidTxMerkleProof)
	}

	// TODO(jhb): check for genesis asset and populate asset fields before
	// further verification

	// The VerifyProofs method will verify the following steps:
	// 2. A valid inclusion proof for the resulting asset is included.
	// 3. A valid inclusion proof for the split root, if the resulting asset
	//    is a split asset.
	// 4. A set of valid exclusion proofs for the resulting asset are
	//    included.
	tapCommitment, err := p.VerifyProofs()
	if err != nil {
		return nil, fmt.Errorf("error verifying proofs: %w", err)
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
		err := p.verifyGenesisGroupKey(vCtx.GroupVerifier)
		if err != nil {
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
		err := p.verifyGenesisGroupKey(vCtx.GroupVerifier)
		if err != nil {
			return nil, err
		}
	}

	// 8. Either a set of asset inputs with valid witnesses is included that
	// satisfy the resulting state transition or a challenge witness is
	// provided as part of an ownership proof.
	var splitAsset bool
	switch {
	case prev == nil && p.ChallengeWitness != nil:
		splitAsset, err = p.verifyChallengeWitness(
			ctx, chainLookup, verificationParams.ChallengeBytes,
		)

	default:
		splitAsset, err = p.verifyAssetStateTransition(
			ctx, prev, chainLookup, vCtx,
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
		Asset:             &p.Asset,
		OutPoint:          p.OutPoint(),
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

// VerifyProofs verifies the inclusion and exclusion proofs as well as the split
// root proof.
func (p *Proof) VerifyProofs() (*commitment.TapCommitment, error) {
	// A valid inclusion proof for the resulting asset is included.
	tapCommitment, err := p.verifyInclusionProof()
	if err != nil {
		return nil, fmt.Errorf("invalid inclusion proof: %w", err)
	}

	// A valid inclusion proof for the split root, if the resulting asset is
	// a split asset.
	if p.Asset.HasSplitCommitmentWitness() {
		if p.SplitRootProof == nil {
			return nil, ErrMissingSplitRootProof
		}

		if err := p.verifySplitRootProof(); err != nil {
			return nil, err
		}
	}

	// A set of valid exclusion proofs for the resulting asset are included.
	exclusionCommitVersion, err := p.verifyExclusionProofs()
	if err != nil {
		return nil, fmt.Errorf("invalid exclusion proof: %w", err)
	}

	// If all exclusion proofs were Tapscript proofs, then no version
	// checking is needed.
	if exclusionCommitVersion == nil {
		return tapCommitment, nil
	}

	// The inclusion proof must have a similar version to all exclusion
	// proofs.
	if !commitment.IsSimilarTapCommitmentVersion(
		&tapCommitment.Version, exclusionCommitVersion,
	) {

		return nil, fmt.Errorf("mixed commitment versions, inclusion "+
			"%d, exclusion %d", tapCommitment.Version,
			*exclusionCommitVersion)
	}

	return tapCommitment, nil
}

// Verify attempts to verify a full proof file starting from the asset's
// genesis.
//
// The passed context can be used to exit early from the inner proof
// verification loop.
//
// TODO(roasbeef): pass in the expected genesis point here?
func (f *File) Verify(ctx context.Context,
	vCtx VerifierCtx) (*AssetSnapshot, error) {

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

	chainLookup := vCtx.ChainLookupGen.GenFileChainLookup(f)

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
			ctx, prev, chainLookup, vCtx,
		)
		if err != nil {
			return nil, err
		}

		// At this point, we'll check to see if we can halt validation
		// here, as the proof is already known to be invalid. This can
		// be used as a rejection caching mechanism.
		fail := lfn.MapOptionZ(
			vCtx.IgnoreChecker, func(checker IgnoreChecker) bool {
				assetPoint := AssetPoint{
					OutPoint: result.OutPoint,
					ID:       result.Asset.ID(),
					ScriptKey: asset.ToSerialized(
						result.Asset.ScriptKey.PubKey,
					),
				}

				return checker.IsIgnored(assetPoint)
			},
		)
		if fail {
			return prev, ErrProofFileInvalid
		}

		prev = result
	}

	return prev, nil
}
