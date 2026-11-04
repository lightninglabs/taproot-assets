package tapchannel

import (
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwire"
)

// STXOFeatures records which of the STXO related alt leaves the commitments
// of a channel carry, and the branch version of their split commitment trees.
// Both peers of a channel must arrive at the same commitments, so a feature is
// only used if both peers support it.
type STXOFeatures struct {
	// STXO is set if the STXOs of the inputs spent by a transfer are
	// committed to.
	STXO bool

	// Spender is set if the spender leaves of the inputs are committed to
	// as well, next to their STXOs.
	Spender bool

	// SplitTreeV1 is set if the split commitment trees have BranchV1
	// branches, and otherwise they have BranchV0 branches.
	SplitTreeV1 bool
}

// NewSTXOFeatures returns the STXO features supported by a peer, as given by
// its feature vector. Spender leaves presuppose STXOs.
func NewSTXOFeatures(features lnwire.FeatureVector) STXOFeatures {
	stxo := features.HasFeature(tapfeatures.STXOOptional)
	spender := features.HasFeature(tapfeatures.STXOSpenderOptional)

	return STXOFeatures{
		STXO:    stxo,
		Spender: stxo && spender,
		SplitTreeV1: features.HasFeature(
			tapfeatures.SplitTreeV1Optional,
		),
	}
}

// CommitmentSTXOFeatures returns the STXO features recorded by the given
// commitment.
func CommitmentSTXOFeatures(commitment *cmsg.Commitment) STXOFeatures {
	stxo := commitment.STXO.Val

	return STXOFeatures{
		STXO:        stxo,
		Spender:     stxo && commitment.Spender.Val,
		SplitTreeV1: commitment.SplitTreeV1.Val,
	}
}

// SplitTreeVersion returns the branch version of the split commitment trees.
func (f STXOFeatures) SplitTreeVersion() mssmt.BranchVersion {
	if f.SplitTreeV1 {
		return mssmt.BranchV1
	}

	return mssmt.BranchV0
}

// CommitOpts returns the options for creating output commitments that carry
// the leaves of the features.
func (f STXOFeatures) CommitOpts() []tapsend.OutputCommitmentOption {
	var opts []tapsend.OutputCommitmentOption
	if !f.STXO {
		opts = append(opts, tapsend.WithNoSTXOProofs())
	}
	if f.Spender {
		opts = append(opts, tapsend.WithSpenderLeaves())
	}

	return opts
}

// ProofOpts returns the options for creating proofs for the output
// commitments that carry the leaves of the features.
func (f STXOFeatures) ProofOpts() []proof.GenOption {
	if !f.STXO {
		return []proof.GenOption{proof.WithNoSTXOProofs()}
	}

	return nil
}
