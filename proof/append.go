package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
)

// TransitionParams holds the set of chain level information needed to append a
// proof to an existing file for the given asset state transition.
type TransitionParams struct {
	// BaseProofParams houses the basic chain level parameters needed to
	// construct a proof.
	//
	// TODO(roasbeef): assumes only 2 outputs in the TX (minting output and
	// change), need more information to make exclusion proofs for the
	// others.
	BaseProofParams

	// NewAsset is the new asset created by the asset transition.
	NewAsset *asset.Asset
}

// AppendTransition appends a new proof for a state transition to the given
// encoded proof file. Because multiple assets can be committed to in the same
// on-chain output, this function takes the script key of the asset to return
// the proof for. This method returns both the encoded full provenance (proof
// chain) and the added latest proof.
func AppendTransition(blob Blob, params *TransitionParams) (Blob, *Proof,
	error) {

	// Decode the proof blob into a proper file structure first.
	f := NewFile(V0)
	if err := f.Decode(bytes.NewReader(blob)); err != nil {
		return nil, nil, fmt.Errorf("error decoding proof file: %w",
			err)
	}

	// Cannot add a transition to an empty proof file.
	if len(f.Proofs) == 0 {
		return nil, nil, fmt.Errorf("invalid empty proof file")
	}

	lastProof := f.Proofs[len(f.Proofs)-1]

	// We can now create the new proof entry for the asset in the params.
	newProof, err := createTransitionProof(&lastProof, params)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating transition "+
			"proof: %w", err)
	}

	// Before we encode and return the proof, we want to validate it. For
	// that we need to start at the beginning.
	ctx := context.Background()
	f.Proofs = append(f.Proofs, *newProof)
	if _, err := f.Verify(ctx); err != nil {
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

// createTransitionProof creates a proof for an asset transition, based on the
// last proof of the last asset state and the new asset in the params.
func createTransitionProof(lastProof *Proof, params *TransitionParams) (*Proof,
	error) {

	prevOut := wire.OutPoint{
		Hash:  lastProof.AnchorTx.TxHash(),
		Index: lastProof.InclusionProof.OutputIndex,
	}

	proof, err := baseProof(&params.BaseProofParams, prevOut)
	if err != nil {
		return nil, fmt.Errorf("error creating base proofs: %w", err)
	}

	proof.Asset = *params.NewAsset.Copy()

	// With the base information contained, we'll now need to generate our
	// series of MS-SMT inclusion proofs that prove the existence of the
	// asset.
	_, assetMerkleProof, err := params.TaroRoot.Proof(
		proof.Asset.TaroCommitmentKey(),
		proof.Asset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, err
	}

	// With the merkle proof obtained, we can now set that in the main
	// inclusion proof.
	//
	// NOTE: We don't add a TapSiblingPreimage here since we assume that
	// this minting output ONLY commits to the Taro commitment.
	proof.InclusionProof.CommitmentProof = &CommitmentProof{
		Proof: *assetMerkleProof,
	}

	return proof, nil
}
