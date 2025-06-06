package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
)

// GenConfig is a struct that holds the configuration for creating Taproot Asset
// proofs.
type GenConfig struct {
	// TransitionVersion is the version of the asset state transition proof
	// that is going to be used.
	TransitionVersion TransitionVersion

	// NoSTXOProofs indicates whether to skip the generation of STXO
	// inclusion and exclusion proofs for the transition proof.
	NoSTXOProofs bool
}

// DefaultGenConfig returns a default proof generation configuration.
func DefaultGenConfig() GenConfig {
	return GenConfig{
		TransitionVersion: TransitionV0,
	}
}

// GenOption is a function type that can be used to modify the proof generation
// configuration.
type GenOption func(*GenConfig)

// WithVersion is an option that can be used to create a transition proof of the
// given version.
func WithVersion(v TransitionVersion) GenOption {
	return func(cfg *GenConfig) {
		cfg.TransitionVersion = v
	}
}

// WithNoSTXOProofs is an option that can be used to skip the generation of
// STXO inclusion and exclusion proofs for the transition proof.
func WithNoSTXOProofs() GenOption {
	return func(cfg *GenConfig) {
		cfg.NoSTXOProofs = true
	}
}

// TransitionParams holds the set of chain level information needed to append a
// proof to an existing file for the given asset state transition.
type TransitionParams struct {
	// BaseProofParams houses the basic chain level parameters needed to
	// construct a proof.
	BaseProofParams

	// NewAsset is the new asset created by the asset transition.
	NewAsset *asset.Asset

	// RootOutputIndex is the index of the output that commits to the split
	// root asset, if present.
	RootOutputIndex uint32

	// RootInternalKey is the internal key of the output at RootOutputIndex.
	RootInternalKey *btcec.PublicKey

	// RootTaprootAssetTree is the commitment root that commitments to the
	// inclusion of the root split asset at the RootOutputIndex.
	RootTaprootAssetTree *commitment.TapCommitment

	// RootTapscriptSibling is the tapscript sibling of the output at
	// commits to the asset split root.
	RootTapscriptSibling *commitment.TapscriptPreimage
}

// AppendTransition appends a new proof for a state transition to the given
// encoded proof file. Because multiple assets can be committed to in the same
// on-chain output, this function takes the script key of the asset to return
// the proof for. This method returns both the encoded full provenance (proof
// chain) and the added latest proof.
func AppendTransition(blob Blob, params *TransitionParams, vCtx VerifierCtx,
	opts ...GenOption) (Blob, *Proof, error) {

	// Decode the proof blob into a proper file structure first.
	f := NewEmptyFile(V0)
	if err := f.Decode(bytes.NewReader(blob)); err != nil {
		return nil, nil, fmt.Errorf("error decoding proof file: %w",
			err)
	}

	// Cannot add a transition to an empty proof file.
	if f.IsEmpty() {
		return nil, nil, fmt.Errorf("invalid empty proof file")
	}

	lastProof, err := f.LastProof()
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching last proof: %w",
			err)
	}

	lastPrevOut := wire.OutPoint{
		Hash:  lastProof.AnchorTx.TxHash(),
		Index: lastProof.InclusionProof.OutputIndex,
	}

	// We can now create the new proof entry for the asset in the params.
	newProof, err := CreateTransitionProof(lastPrevOut, params, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating transition "+
			"proof: %w", err)
	}

	// Before we encode and return the proof, we want to validate it. For
	// that we need to start at the beginning.
	ctx := context.Background()
	if err := f.AppendProof(*newProof); err != nil {
		return nil, nil, fmt.Errorf("error appending proof: %w", err)
	}

	_, err = f.Verify(ctx, vCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("error verifying proof: %w", err)
	}

	// Encode the full file again, with the new proof appended.
	var buf bytes.Buffer
	if err := f.Encode(&buf); err != nil {
		return nil, nil, fmt.Errorf("error encoding proof file: %w",
			err)
	}

	return buf.Bytes(), newProof, nil
}

// UpdateTransitionProof computes a new transaction merkle proof from the given
// proof parameters, and updates a proof to be anchored at the given anchor
// transaction. This is needed to reflect confirmation of an anchor transaction.
func (p *Proof) UpdateTransitionProof(params *BaseProofParams) error {
	// We only use the block, transaction, and transaction index parameters,
	// so we only need to check the nil-ness of the block and transaction.
	if params.Block == nil || params.Tx == nil {
		return fmt.Errorf("missing block or TX to update proof")
	}

	// Recompute the proof fields that depend on anchor TX confirmation.
	proofHeader, err := coreProof(params)
	if err != nil {
		return err
	}

	p.BlockHeader = proofHeader.BlockHeader
	p.BlockHeight = proofHeader.BlockHeight
	p.AnchorTx = proofHeader.AnchorTx
	p.TxMerkleProof = proofHeader.TxMerkleProof
	return nil
}

// CreateTransitionProof creates a proof for an asset transition, based on the
// last proof of the last asset state and the new asset in the params.
func CreateTransitionProof(prevOut wire.OutPoint, params *TransitionParams,
	opts ...GenOption) (*Proof, error) {

	cfg := DefaultGenConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	proof, err := baseProof(
		&params.BaseProofParams, prevOut, cfg.TransitionVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating base proofs: %w", err)
	}

	proof.Asset = *params.NewAsset.Copy()

	// Copy any AltLeaves from the anchor commitment to the proof.
	altLeaves, err := params.TaprootAssetRoot.FetchAltLeaves()
	if err != nil {
		return nil, err
	}

	if len(altLeaves) > 0 {
		proof.AltLeaves = asset.ToAltLeaves(altLeaves)
	}

	// With the base information contained, we'll now need to generate our
	// series of MS-SMT inclusion proofs that prove the existence of the
	// asset.
	_, assetMerkleProof, err := params.TaprootAssetRoot.Proof(
		proof.Asset.TapCommitmentKey(),
		proof.Asset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, err
	}

	// With the merkle proof obtained, we can now set that in the main
	// inclusion proof.
	proof.InclusionProof.CommitmentProof = &CommitmentProof{
		Proof:              *assetMerkleProof,
		TapSiblingPreimage: params.TapscriptSibling,
	}

	if proof.Asset.IsTransferRoot() && !cfg.NoSTXOProofs {
		stxoInclusionProofs := make(
			map[asset.SerializedKey]commitment.Proof,
			len(proof.Asset.PrevWitnesses),
		)
		for _, wit := range proof.Asset.PrevWitnesses {
			spentAsset, err := asset.MakeSpentAsset(wit)
			if err != nil {
				return nil, fmt.Errorf("error creating "+
					"altLeaf: %w", err)
			}

			// Generate an STXO inclusion proof for each prev
			// witness.
			_, stxoProof, err := params.TaprootAssetRoot.Proof(
				asset.EmptyGenesisID,
				spentAsset.AssetCommitmentKey(),
			)
			if err != nil {
				return nil, err
			}
			keySerialized := asset.ToSerialized(
				spentAsset.ScriptKey.PubKey,
			)
			stxoInclusionProofs[keySerialized] = *stxoProof
		}

		if len(stxoInclusionProofs) == 0 {
			return nil, fmt.Errorf("no stxo inclusion proofs")
		}

		proof.InclusionProof.CommitmentProof.STXOProofs =
			stxoInclusionProofs
	}

	// If the asset is a split asset, we also need to generate MS-SMT
	// inclusion proofs that prove the existence of the split root asset.
	if proof.Asset.HasSplitCommitmentWitness() {
		splitAsset := proof.Asset
		rootAsset := &splitAsset.PrevWitnesses[0].SplitCommitment.RootAsset

		rootTree := params.RootTaprootAssetTree
		committedRoot, rootMerkleProof, err := rootTree.Proof(
			rootAsset.TapCommitmentKey(),
			rootAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// If the asset wasn't committed to, the proof is invalid.
		if committedRoot == nil {
			return nil, fmt.Errorf("no asset commitment found")
		}

		// Make sure the committed asset matches the root asset exactly.
		// We allow the TxWitness to mismatch for assets with version 1
		// as they would not include the witness when the proof is
		// created.
		if !committedRoot.DeepEqualAllowSegWitIgnoreTxWitness(
			rootAsset,
		) {

			return nil, fmt.Errorf("root asset mismatch")
		}

		proof.SplitRootProof = &TaprootProof{
			OutputIndex: params.RootOutputIndex,
			InternalKey: params.RootInternalKey,
			CommitmentProof: &CommitmentProof{
				Proof:              *rootMerkleProof,
				TapSiblingPreimage: params.RootTapscriptSibling,
			},
		}
	}

	return proof, nil
}
