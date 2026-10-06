package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/mssmt"
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
		TransitionVersion: TransitionV1,
	}
}

// NewGenConfig applies the given options to the default proof generation
// configuration. A version 1 transfer proof must carry STXO proofs, so
// omitting them selects transition version 0 regardless of any version
// option, and no caller can produce a proof whose version promises data
// it does not carry.
func NewGenConfig(opts ...GenOption) GenConfig {
	cfg := DefaultGenConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.NoSTXOProofs {
		cfg.TransitionVersion = TransitionV0
	}

	return cfg
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
// STXO inclusion and exclusion proofs for the transition proof. A version 1
// transfer proof must carry them, so omitting them also selects transition
// version 0.
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

	// RootLocatorProof is the MS-SMT Merkle proof for the root locator's
	// split leaf within the split commitment tree. It must be set whenever
	// the transition is a split, meaning the new asset is either the split
	// root asset (carrying a split commitment root) or a split asset
	// (carrying a split commitment witness). The proof binds the root
	// asset's amount, script key and anchor output index to the split
	// tree.
	RootLocatorProof *mssmt.Proof
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

	cfg := NewGenConfig(opts...)

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
		stxoProofs, err := stxoInclusionProofs(
			&proof.Asset, params.TaprootAssetRoot,
		)
		if err != nil {
			return nil, err
		}

		proof.InclusionProof.CommitmentProof.STXOProofs = stxoProofs

		spenderProofs, err := spenderInclusionProofs(
			&proof.Asset, params.TaprootAssetRoot,
		)
		if err != nil {
			return nil, err
		}

		proof.InclusionProof.CommitmentProof.SpenderProofs =
			spenderProofs
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

		// A split asset takes part in the transfer of its root asset,
		// so its proof carries the STXO proofs for the inputs spent by
		// the root asset.
		if !cfg.NoSTXOProofs {
			err := addSplitSTXOProofs(proof, params, rootAsset)
			if err != nil {
				return nil, err
			}
		}
	}

	// If this transition is a split, we also include the MS-SMT inclusion
	// proof of the root locator's split leaf, so a verifier can validate
	// the root leaf like any other split leaf.
	isSplit := proof.Asset.HasSplitCommitmentWitness() ||
		proof.Asset.SplitCommitmentRoot != nil
	if isSplit {
		if params.RootLocatorProof == nil {
			return nil, fmt.Errorf("missing root locator proof " +
				"for split transition")
		}

		proof.RootLocatorProof = params.RootLocatorProof
	}

	return proof, nil
}

// addSplitSTXOProofs adds the STXO proofs for the inputs spent by the root
// asset to the proof of one of its split assets. The anchor output of the root
// asset commits to the STXOs, so the split root proof carries their inclusion
// proofs. The anchor output of the split asset must not commit to them, so the
// inclusion proof of the split asset carries their exclusion proofs, unless
// the two assets share an anchor output. The split root proof also carries the
// inclusion proofs of the spender leaves, if the anchor output of the root
// asset commits to them.
func addSplitSTXOProofs(proof *Proof, params *TransitionParams,
	rootAsset *asset.Asset) error {

	inclusionProofs, err := stxoInclusionProofs(
		rootAsset, params.RootTaprootAssetTree,
	)
	if err != nil {
		return err
	}

	proof.SplitRootProof.CommitmentProof.STXOProofs = inclusionProofs

	spenderProofs, err := spenderInclusionProofs(
		rootAsset, params.RootTaprootAssetTree,
	)
	if err != nil {
		return err
	}

	proof.SplitRootProof.CommitmentProof.SpenderProofs = spenderProofs

	if params.OutputIndex == int(params.RootOutputIndex) {
		return nil
	}

	exclusionProofs, err := stxoExclusionProofs(
		rootAsset, params.TaprootAssetRoot,
	)
	if err != nil {
		return err
	}

	proof.InclusionProof.CommitmentProof.STXOProofs = exclusionProofs

	return nil
}

// stxoInclusionProofs generates an STXO inclusion proof for each input spent
// by the given root asset of a transfer, from the commitment of the anchor
// output the root asset is committed to.
func stxoInclusionProofs(rootAsset *asset.Asset,
	rootTree *commitment.TapCommitment) (
	map[asset.SerializedKey]commitment.Proof, error) {

	assetCommitments := rootTree.Commitments()
	altCommitment, ok := assetCommitments[asset.EmptyGenesisID]
	if !ok {
		return nil, fmt.Errorf("no alt leaves for transfer root asset")
	}

	// If this is a transfer root, then we also expect there to be prev
	// witnesses.
	if len(rootAsset.PrevWitnesses) == 0 {
		return nil, fmt.Errorf("no prev witnesses for transfer root " +
			"asset")
	}

	// We should have at least as many alt leaves as we have prev witnesses.
	// We may have additional alt leaves which are not related to stxo
	// proofs.
	if len(altCommitment.Assets()) < len(rootAsset.PrevWitnesses) {
		return nil, fmt.Errorf("not enough alt leaves for transfer " +
			"root asset")
	}

	stxoProofs := make(
		map[asset.SerializedKey]commitment.Proof,
		len(rootAsset.PrevWitnesses),
	)

	for _, wit := range rootAsset.PrevWitnesses {
		spentAsset, err := asset.MakeSpentAsset(wit)
		if err != nil {
			return nil, fmt.Errorf("error creating altLeaf: %w",
				err)
		}

		// Generate an STXO inclusion proof for each prev witness.
		_, stxoProof, err := rootTree.Proof(
			asset.EmptyGenesisID, spentAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// Sanity-check the STXO proof to ensure the asset proof is
		// present. STXO inclusion proofs must always include a valid
		// asset proof.
		if stxoProof == nil {
			return nil, fmt.Errorf("stxo inclusion proof is nil")
		}

		if stxoProof.AssetProof == nil {
			return nil, commitment.ErrMissingAssetProof
		}

		keySerialized := asset.ToSerialized(spentAsset.ScriptKey.PubKey)
		stxoProofs[keySerialized] = *stxoProof
	}

	// For assets representing a root transfer (normal assets), each spent
	// input corresponds to an entry in PrevWitnesses. Therefore, the number
	// of PrevWitnesses should match the number of STXO inclusion proofs.
	if len(stxoProofs) != len(rootAsset.PrevWitnesses) {
		return nil, fmt.Errorf("stxo inclusion proof count mismatch: "+
			"expected %d, got %d", len(rootAsset.PrevWitnesses),
			len(stxoProofs))
	}

	if len(stxoProofs) == 0 {
		return nil, fmt.Errorf("no stxo inclusion proofs")
	}

	return stxoProofs, nil
}

// stxoExclusionProofs generates an STXO exclusion proof for each input spent
// by the given root asset of a transfer, from the commitment of an anchor
// output other than the one the root asset is committed to.
func stxoExclusionProofs(rootAsset *asset.Asset,
	tapTree *commitment.TapCommitment) (
	map[asset.SerializedKey]commitment.Proof, error) {

	stxoAssets, err := asset.CollectSTXO(rootAsset)
	if err != nil {
		return nil, fmt.Errorf("error collecting STXO assets: %w", err)
	}

	stxoProofs := make(
		map[asset.SerializedKey]commitment.Proof, len(stxoAssets),
	)
	for idx := range stxoAssets {
		stxoAsset := stxoAssets[idx].(*asset.Asset)

		_, stxoProof, err := tapTree.Proof(
			stxoAsset.TapCommitmentKey(),
			stxoAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		keySerialized := asset.ToSerialized(stxoAsset.ScriptKey.PubKey)
		stxoProofs[keySerialized] = *stxoProof
	}

	return stxoProofs, nil
}

// spenderInclusionProofs generates an inclusion proof for the spender leaf of
// each input spent by the given root asset of a transfer, from the commitment
// of the anchor output the root asset is committed to. Not every anchor output
// commits to spender leaves, so no proofs are returned if there are none.
func spenderInclusionProofs(rootAsset *asset.Asset,
	rootTree *commitment.TapCommitment) (
	map[asset.SerializedKey]commitment.Proof, error) {

	spenderAssets, err := asset.CollectSpenders(rootAsset)
	if err != nil {
		return nil, fmt.Errorf("error collecting spender assets: %w",
			err)
	}

	spenderProofs := make(
		map[asset.SerializedKey]commitment.Proof, len(spenderAssets),
	)
	for idx := range spenderAssets {
		spenderAsset := spenderAssets[idx].(*asset.Asset)

		committed, spenderProof, err := rootTree.Proof(
			spenderAsset.TapCommitmentKey(),
			spenderAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// The anchor output doesn't commit to a spender leaf for this
		// input.
		if committed == nil {
			continue
		}

		// A spender leaf that names another asset can't be proven for
		// the root asset.
		committedLeaf, err := committed.Leaf()
		if err != nil {
			return nil, err
		}
		spenderLeaf, err := spenderAsset.Leaf()
		if err != nil {
			return nil, err
		}
		if !mssmt.IsEqualNode(committedLeaf, spenderLeaf) {
			return nil, fmt.Errorf("spender leaf does not name " +
				"transfer root asset")
		}

		keySerialized := asset.ToSerialized(
			spenderAsset.ScriptKey.PubKey,
		)
		spenderProofs[keySerialized] = *spenderProof
	}

	// The spender leaves are committed to for all the inputs of a transfer
	// or for none of them.
	switch {
	case len(spenderProofs) == 0:
		return nil, nil

	case len(spenderProofs) != len(rootAsset.PrevWitnesses):
		return nil, fmt.Errorf("spender inclusion proof count "+
			"mismatch: expected %d, got %d",
			len(rootAsset.PrevWitnesses), len(spenderProofs))
	}

	return spenderProofs, nil
}
