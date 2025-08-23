package supplyverifier

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// VerifierCfg is the configuration for the verifier.
type VerifierCfg struct {
	// Chain is our access to the current main chain.
	Chain tapgarden.ChainBridge

	// SupplyCommitView allows us to look up supply commitments and
	// pre-commitments.
	SupplyCommitView SupplyCommitView

	// SupplyTreeView is used to fetch supply leaves by height.
	SupplyTreeView SupplyTreeView
}

// Verifier is responsible for verifying supply commitments.
type Verifier struct {
	// cfg is the configuration for the verifier.
	cfg VerifierCfg
}

// NewVerifier creates a new Verifier with the given configuration.
func NewVerifier(chain tapgarden.ChainBridge,
	supplyCommitView SupplyCommitView,
	supplyTreeView SupplyTreeView) (Verifier, error) {

	var zero Verifier

	if chain == nil {
		return zero, fmt.Errorf("chain is required")
	}

	if supplyCommitView == nil {
		return zero, fmt.Errorf("supply commit view is required")
	}

	if supplyTreeView == nil {
		return zero, fmt.Errorf("supply tree view is required")
	}

	return Verifier{
		cfg: VerifierCfg{
			Chain:            chain,
			SupplyCommitView: supplyCommitView,
			SupplyTreeView:   supplyTreeView,
		},
	}, nil
}

// ensurePrecommitsSpent verifies that all unspent pre-commitment outputs for
// the specified asset group, which could have been spent by the supply
// commitment transaction, were actually spent.
func (v *Verifier) ensurePrecommitsSpent(ctx context.Context,
	assetSpec asset.Specifier,
	commitment supplycommit.RootCommitment) error {

	// Fetch all unspent pre-commitment outputs for the asset group.
	allPreCommits, err := v.cfg.SupplyCommitView.UnspentPrecommits(
		ctx, assetSpec,
	).Unpack()
	if err != nil {
		return fmt.Errorf("unable to fetch unspent pre-commitments: %w",
			err)
	}

	// Filter pre-commits to only include those that are at block heights
	// less than or equal to the commitment's anchor block height. All
	// unspent pre-commitments at or before the commitment's anchor block
	// height must be spent by the commitment transaction.
	commitmentBlock, err := commitment.CommitmentBlock.UnwrapOrErr(
		fmt.Errorf("missing commitment block"),
	)
	if err != nil {
		return err
	}

	var preCommits []supplycommit.PreCommitment
	for idx := range allPreCommits {
		preCommit := allPreCommits[idx]
		if preCommit.BlockHeight <= commitmentBlock.Height {
			preCommits = append(preCommits, preCommit)
		}
	}

	// Keep track of all matched pre-commitment outpoints to ensure that
	// we spend each one exactly once.
	matchedOutPoints := make(map[string]struct{})
	for idxCommitTxIn := range commitment.Txn.TxIn {
		commitTxIn := commitment.Txn.TxIn[idxCommitTxIn]

		for idxPreCommit := range preCommits {
			preCommit := preCommits[idxPreCommit]
			preCommitOutPoint := preCommit.OutPoint()

			if commitTxIn.PreviousOutPoint == preCommitOutPoint {
				opStr := preCommitOutPoint.String()
				matchedOutPoints[opStr] = struct{}{}
				break
			}
		}
	}

	if len(matchedOutPoints) != len(preCommits) {
		// Log which pre-commitment outpoints were not matched.
		var unmatched []string
		for idx := range preCommits {
			preCommit := preCommits[idx]
			preCommitOutPoint := preCommit.OutPoint()
			opStr := preCommitOutPoint.String()
			if _, ok := matchedOutPoints[opStr]; !ok {
				unmatched = append(unmatched, opStr)
			}
		}

		log.Errorf("Unmatched pre-commitment outpoints in supply "+
			"commit anchor tx inputs set:\n%s",
			strings.Join(unmatched, "\n"))

		return fmt.Errorf("supply commitment does not spend all "+
			"known pre-commitments: expected %d, found %d",
			len(preCommits), len(matchedOutPoints))
	}

	return nil
}

// verifyInitialCommit verifies the first (starting) supply commitment for a
// given asset group.
func (v *Verifier) verifyInitialCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	// Check to ensure that we don't already have a starting
	// commitment for the asset group. If we do, then we require a spent
	// outpoint to be set on the commitment or that the outpoint is
	// the same as the given commitment outpoint.
	initCommit, err := v.cfg.SupplyCommitView.FetchStartingCommitment(
		ctx, assetSpec,
	)
	switch {
	case err == nil:
		// An initial commitment was found for the asset group. This
		// means the given supply commitment is either the initial
		// commitment itself, or it is missing a spent outpoint.
		if initCommit.CommitPoint() == commitment.CommitPoint() {
			// The spent outpoint matches the current commitment
			// outpoint. This indicates the commitment has already
			// been verified and stored, so we return nil to
			// signal verification is complete.
			return nil
		}

		return fmt.Errorf("found initial commitment for asset group; "+
			"cannot insert supply commitment without a specified "+
			"spent supply commit outpoint (asset=%s)",
			assetSpec.String())

	case errors.Is(err, ErrCommitmentNotFound):
		// This is the first commitment for the asset group, so we can
		// proceed without a spent outpoint.

	default:
		return fmt.Errorf("failed to check for starting commitment: "+
			"%w", err)
	}

	// Confirm that the given supply commitment transaction spends all known
	// unspent pre-commitment outputs. Pre-commitment outputs are outputs
	// that were created at the time of asset issuance, and are the
	// starting point for the supply commitment chain. Each asset issuance
	// anchor transaction can have at most one pre-commitment output.
	err = v.ensurePrecommitsSpent(ctx, assetSpec, commitment)
	if err != nil {
		return fmt.Errorf("unable to verify pre-commitment spends: %w",
			err)
	}

	// Confirm that the given supply leaves are consistent with the
	// given commitment root.
	//
	// Apply leaves to empty supply trees to generate the initial set of
	// supply subtrees.
	supplyTrees, err := supplycommit.ApplyTreeUpdates(
		supplycommit.SupplyTrees{}, leaves.AllUpdates(),
	)
	if err != nil {
		return fmt.Errorf("unable to generate supply subtrees from "+
			"supply leaves: %w", err)
	}

	// Create a new empty root supply tree and apply the supply subtrees
	// generated above.
	emptyRootSupplyTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	rootSupplyTree, err := supplycommit.UpdateRootSupplyTree(
		ctx, emptyRootSupplyTree, supplyTrees,
	)
	if err != nil {
		return fmt.Errorf("unable to formulate root supply tree: %w",
			err)
	}

	// Ensure that the root of the formulated supply tree matches the
	// commitment root.
	genRoot, err := rootSupplyTree.Root(ctx)
	if err != nil {
		return fmt.Errorf("unable to compute root of generated "+
			"supply tree: %w", err)
	}

	if genRoot.NodeHash() != commitment.SupplyRoot.NodeHash() {
		return fmt.Errorf("generated supply tree root does not match " +
			"commitment supply root")
	}

	return nil
}

// verifyIncrementalCommit verifies an incremental supply commitment for a
// given asset group. Verification succeeds only if the previous supply
// commitment is known and verified, and the given supply leaves are
// consistent with the commitment root.
func (v *Verifier) verifyIncrementalCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	// Fetch previous supply commitment based on the spent outpoint. This
	// step ensures that we have already verified the previous
	// commitment, and that it is present in the database.
	spentOutPoint, err := commitment.SpentCommitment.UnwrapOrErr(
		fmt.Errorf("missing spent supply commitment outpoint"),
	)
	if err != nil {
		return err
	}

	spentCommit, err :=
		v.cfg.SupplyCommitView.FetchCommitmentByOutpoint(
			ctx, assetSpec, spentOutPoint,
		)
	if err != nil {
		return ErrPrevCommitmentNotFound
	}

	// Check that the given commitment spends the previous commitment's
	// outpoint that is referenced by the given spent outpoint field.
	checkSpendPrevOutPoint := false
	for idx := range commitment.Txn.TxIn {
		txIn := commitment.Txn.TxIn[idx]
		if txIn.PreviousOutPoint == spentOutPoint {
			checkSpendPrevOutPoint = true
			break
		}
	}

	if !checkSpendPrevOutPoint {
		return fmt.Errorf("supply commitment does not spend " +
			"provided previous commitment outpoint")
	}

	// Verify that every unspent pre-commitment output eligible by block
	// height is actually spent by the supply commitment transaction.
	err = v.ensurePrecommitsSpent(ctx, assetSpec, commitment)
	if err != nil {
		return fmt.Errorf("unable to verify pre-commitment spends: %w",
			err)
	}

	// Get latest supply root tree and subtrees from the local db. Ensure
	// that they correspond to the spent supply commitment outpoint.
	spentRootTree, spentSubtrees, err :=
		v.cfg.SupplyTreeView.FetchSupplyTrees(
			ctx, assetSpec,
		)
	if err != nil {
		return fmt.Errorf("unable to fetch spent root supply tree: %w",
			err)
	}

	storedSpentRoot, err := spentRootTree.Root(ctx)
	if err != nil {
		return fmt.Errorf("unable to compute root of local spent "+
			"supply tree: %w", err)
	}

	if storedSpentRoot.NodeHash() != spentCommit.SupplyRoot.NodeHash() {
		return fmt.Errorf("local spent supply tree root does not " +
			"match spent commitment supply root")
	}

	// Apply new leaves to the spent subtrees to generate the new set of
	// supply subtrees.
	newSupplyTrees, err := supplycommit.ApplyTreeUpdates(
		*spentSubtrees, leaves.AllUpdates(),
	)
	if err != nil {
		return fmt.Errorf("unable to apply tree updates to spent "+
			"commitment: %w", err)
	}

	// Reconstruct the root supply tree by applying the new leaves to
	// the previous root supply tree.
	expectedSupplyTree, err := supplycommit.UpdateRootSupplyTree(
		ctx, spentRootTree, newSupplyTrees,
	)
	if err != nil {
		return fmt.Errorf("unable to generate expected root supply "+
			"tree: %w", err)
	}

	expectedRoot, err := expectedSupplyTree.Root(ctx)
	if err != nil {
		return fmt.Errorf("unable to compute root of expected supply "+
			"tree: %w", err)
	}

	// Ensure that the root of the reconstructed supply tree matches
	// the commitment root.
	if expectedRoot.NodeHash() != commitment.SupplyRoot.NodeHash() {
		return fmt.Errorf("expected supply tree root does not match " +
			"commitment supply root")
	}

	return nil
}

// VerifyCommit verifies a supply commitment for a given asset group.
// Verification succeeds only if all previous supply commitment dependencies
// are known and verified. The dependency chain must be traceable back to the
// asset issuance anchoring transaction and its pre-commitment output(s).
func (v *Verifier) VerifyCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	// TODO(ffranr): Consider: should we require some leaves to be present?
	//  Or for forward compatibility, allow no leaves?

	// Perform static on-chain verification of the supply commitment's
	// anchoring block header. This provides a basic proof-of-work guarantee
	// that gates further verification steps.
	headerVerifier := tapgarden.GenHeaderVerifier(ctx, v.cfg.Chain)
	err := commitment.VerifyChainAnchor(
		proof.DefaultMerkleVerifier, headerVerifier,
	)
	if err != nil {
		return fmt.Errorf("unable to verify supply commitment: %w", err)
	}

	// Perform basic validation of the provided supply leaves.
	err = leaves.Validate()
	if err != nil {
		return fmt.Errorf("supply leaves validation failed: %w", err)
	}

	// Attempt to fetch the supply commitment by its outpoint, to
	// ensure that it is not already present in the database.
	_, err = v.cfg.SupplyCommitView.FetchCommitmentByOutpoint(
		ctx, assetSpec, commitment.CommitPoint(),
	)
	switch {
	case err == nil:
		// Found commitment, assume already verified and stored.
		return nil

	case errors.Is(err, ErrCommitmentNotFound):
		// Do nothing, continue to verification of given commitment.

	default:
		return fmt.Errorf("failed to check for existing supply "+
			"commitment with given outpoint: %w", err)
	}

	// If the commitment does not specify a spent outpoint, then we dispatch
	// to the initial commitment verification routine.
	if commitment.SpentCommitment.IsNone() {
		return v.verifyInitialCommit(ctx, assetSpec, commitment, leaves)
	}

	// Otherwise, we dispatch to the incremental commitment verification
	// routine.
	return v.verifyIncrementalCommit(ctx, assetSpec, commitment, leaves)
}
