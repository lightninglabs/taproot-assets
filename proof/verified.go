package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
)

// VerifiedAnnotatedProof is an annotated proof that has been verified and
// enriched with locator metadata. Only the proof package can construct
// instances of this interface.
type VerifiedAnnotatedProof interface {
	// AnnotatedProof returns the underlying proof.
	AnnotatedProof() *AnnotatedProof

	// verified prevents external packages from implementing
	// VerifiedAnnotatedProof.
	verified()
}

// verifiedAnnotatedProof wraps a verified annotated proof and enforces package
// scoped construction.
type verifiedAnnotatedProof struct {
	// proof is the verified and enriched annotated proof.
	proof *AnnotatedProof
}

// newVerifiedAnnotatedProof wraps a verified annotated proof.
func newVerifiedAnnotatedProof(proof *AnnotatedProof) VerifiedAnnotatedProof {
	return verifiedAnnotatedProof{proof: proof}
}

// AnnotatedProof returns the underlying proof.
func (v verifiedAnnotatedProof) AnnotatedProof() *AnnotatedProof {
	return v.proof
}

// verified prevents external packages from implementing VerifiedAnnotatedProof.
func (v verifiedAnnotatedProof) verified() {}

// VerifyAnnotatedProofs verifies and enriches the given proofs with a default
// verifier and returns the verified wrappers.
func VerifyAnnotatedProofs(ctx context.Context, vCtx VerifierCtx,
	proofs ...*AnnotatedProof) ([]VerifiedAnnotatedProof, error) {

	return VerifyAnnotatedProofsWithVerifier(
		ctx, &BaseVerifier{}, vCtx, proofs...,
	)
}

// VerifyAnnotatedProofsWithVerifier verifies and enriches the given proofs
// with the specified verifier and returns the verified wrappers.
func VerifyAnnotatedProofsWithVerifier(ctx context.Context, verifier Verifier,
	vCtx VerifierCtx,
	proofs ...*AnnotatedProof) ([]VerifiedAnnotatedProof, error) {

	if verifier == nil {
		return nil, fmt.Errorf("verifier is required")
	}

	if len(proofs) == 0 {
		return nil, nil
	}

	err := fn.ParSlice(ctx, proofs, func(c context.Context,
		proof *AnnotatedProof) error {

		return verifyAnnotatedProof(c, verifier, vCtx, proof)
	})
	if err != nil {
		return nil, err
	}

	verified := fn.Map(proofs, newVerifiedAnnotatedProof)
	return verified, nil
}

// verifyAnnotatedProof verifies and enriches a single annotated proof using
// the given verifier and context.
func verifyAnnotatedProof(ctx context.Context, verifier Verifier,
	vCtx VerifierCtx, proof *AnnotatedProof) error {

	finalStateTransition, err := verifier.Verify(
		ctx, bytes.NewReader(proof.Blob), vCtx,
	)
	if err != nil {
		return fmt.Errorf("unable to verify proof: %w", err)
	}

	proof.AssetSnapshot = finalStateTransition

	finalAsset := finalStateTransition.Asset

	if proof.AssetID == nil {
		assetID := finalAsset.ID()
		proof.AssetID = &assetID

		if finalAsset.GroupKey != nil {
			proof.GroupKey = &finalAsset.GroupKey.GroupPubKey
		}

		proof.ScriptKey = *finalAsset.ScriptKey.PubKey
	}

	return nil
}
