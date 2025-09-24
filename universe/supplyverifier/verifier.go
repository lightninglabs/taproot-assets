package supplyverifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/keychain"
)

// VerifierCfg is the configuration for the verifier.
type VerifierCfg struct {
	// AssetSpec is the asset specifier for the asset group being verified.
	AssetSpec asset.Specifier

	// Chain is our access to the chain.
	ChainBridge tapgarden.ChainBridge

	// AssetLookup is used to look up asset information such as asset groups
	// and asset metadata.
	AssetLookup supplycommit.AssetLookup

	// Lnd is a collection of useful LND clients.
	Lnd *lndclient.LndServices

	// GroupFetcher is used to fetch asset groups.
	GroupFetcher tapgarden.GroupFetcher

	// SupplyCommitView allows us to look up supply commitments and
	// pre-commitments.
	SupplyCommitView SupplyCommitView

	// SupplyTreeView is used to fetch supply leaves by height.
	SupplyTreeView SupplyTreeView
}

// Validate performs basic validation on the verifier configuration.
func (v *VerifierCfg) Validate() error {
	if v.ChainBridge == nil {
		return fmt.Errorf("chain bridge is required")
	}

	if v.AssetLookup == nil {
		return fmt.Errorf("asset lookup is required")
	}

	if v.Lnd == nil {
		return fmt.Errorf("lnd services is required")
	}

	if v.GroupFetcher == nil {
		return fmt.Errorf("group fetcher is required")
	}

	if v.SupplyCommitView == nil {
		return fmt.Errorf("supply commit view is required")
	}

	if v.SupplyTreeView == nil {
		return fmt.Errorf("supply tree view is required")
	}

	return nil
}

// Verifier is responsible for verifying supply commitments.
type Verifier struct {
	// cfg is the configuration for the verifier.
	cfg VerifierCfg

	// assetLog is the asset-specific logger for this verifier.
	assetLog btclog.Logger
}

// NewVerifier creates a new Verifier with the given configuration.
func NewVerifier(cfg VerifierCfg) (Verifier, error) {
	var zero Verifier

	if err := cfg.Validate(); err != nil {
		return zero, fmt.Errorf("invalid verifier config: %w", err)
	}

	assetLog := NewAssetLogger(cfg.AssetSpec.String())
	assetLog.Debugf("Created new supply verifier")

	return Verifier{
		cfg:      cfg,
		assetLog: assetLog,
	}, nil
}

// verifyPrecommitsSpent verifies that all unspent pre-commitment outputs for
// the specified asset group, which could have been spent by the supply
// commitment transaction, were actually spent.
func (v *Verifier) verifyPrecommitsSpent(commitment supplycommit.RootCommitment,
	allPreCommits supplycommit.PreCommits) error {

	v.assetLog.Debugf("Verifying pre-commitments spent")

	// If no supply-commitment spend is recorded, require at least one
	// unspent mint pre-commitment output for the initial supply commitment.
	if commitment.SpentCommitment.IsNone() && len(allPreCommits) == 0 {
		return fmt.Errorf("no unspent supply pre-commitment outputs " +
			"for the initial supply commitment")
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

		v.assetLog.Errorf("Unmatched pre-commitment outpoints in "+
			"supply commit anchor tx inputs set:\n%s",
			strings.Join(unmatched, "\n"))

		return fmt.Errorf("supply commitment does not spend all "+
			"known pre-commitments: expected %d, found %d",
			len(preCommits), len(matchedOutPoints))
	}

	v.assetLog.Debugf("Successfully verified %d pre-commitment spends",
		len(matchedOutPoints))

	return nil
}

// verifyInitialCommit verifies the first (starting) supply commitment for a
// given asset group.
func (v *Verifier) verifyInitialCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	unspentPreCommits supplycommit.PreCommits) error {

	v.assetLog.Infof("Verifying initial supply commitment")

	// Assert that the given commitment does not specify a spent outpoint.
	// This must be the case for an initial commitment (which is what this
	// function verifies).
	if commitment.SpentCommitment.IsSome() {
		return fmt.Errorf("initial supply commitment must not " +
			"specify a spent commitment outpoint")
	}

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

		return fmt.Errorf("found alternative initial commitment for "+
			"asset group (asset=%s)", assetSpec.String())

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
	err = v.verifyPrecommitsSpent(commitment, unspentPreCommits)
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

	v.assetLog.Infof("Successfully verified initial supply commitment, "+
		"root_hash=%x", genRoot.NodeHash())

	return nil
}

// verifyIncrementalCommit verifies an incremental supply commitment for a
// given asset group. Verification succeeds only if the previous supply
// commitment is known and verified, and the given supply leaves are
// consistent with the commitment root.
func (v *Verifier) verifyIncrementalCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	unspentPreCommits supplycommit.PreCommits) error {

	v.assetLog.Infof("Verifying incremental supply commitment")

	// Fetch previous supply commitment based on the spent outpoint. This
	// step ensures that we have already verified the previous
	// commitment, and that it is present in the database.
	spentOutPoint, err := commitment.SpentCommitment.UnwrapOrErr(
		fmt.Errorf("missing spent supply commitment outpoint"),
	)
	if err != nil {
		return err
	}

	v.assetLog.Debugf("Fetching previous commitment at outpoint: %s",
		spentOutPoint.String())

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
	err = v.verifyPrecommitsSpent(commitment, unspentPreCommits)
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

	v.assetLog.Infof("Successfully verified incremental supply "+
		"commitment, root_hash=%x, spent_outpoint=%s",
		expectedRoot.NodeHash(), spentOutPoint.String())

	return nil
}

// proofVerifierCtx returns a verifier context that can be used to verify
// proofs.
func (v *Verifier) proofVerifierCtx(ctx context.Context) proof.VerifierCtx {
	headerVerifier := tapgarden.GenHeaderVerifier(ctx, v.cfg.ChainBridge)
	merkleVerifier := proof.DefaultMerkleVerifier
	groupVerifier := tapgarden.GenGroupVerifier(ctx, v.cfg.GroupFetcher)
	groupAnchorVerifier := tapgarden.GenGroupAnchorVerifier(
		ctx, v.cfg.GroupFetcher,
	)

	return proof.VerifierCtx{
		HeaderVerifier:      headerVerifier,
		MerkleVerifier:      merkleVerifier,
		GroupVerifier:       groupVerifier,
		GroupAnchorVerifier: groupAnchorVerifier,
		ChainLookupGen:      v.cfg.ChainBridge,
	}
}

// IsEquivalentPubKeys reports whether two public keys are equivalent
// when compared in their BIP340-serialized form. This avoids issues
// with multiple encodings of the same elliptic curve point, since
// BIP340 serialization provides a unique, canonical byte representation.
//
// TODO(ffranr): This should be a method on btcec.PublicKey.
func IsEquivalentPubKeys(a, b *btcec.PublicKey) bool {
	return bytes.Equal(
		schnorr.SerializePubKey(a),
		schnorr.SerializePubKey(b),
	)
}

// verifyIssuanceLeaf verifies a single issuance leaf entry.
func (v *Verifier) verifyIssuanceLeaf(ctx context.Context,
	assetSpec asset.Specifier, delegationKey btcec.PublicKey,
	issuanceEntry supplycommit.NewMintEvent) error {

	v.assetLog.Tracef("Verifying issuance leaf")

	issuanceLeaf := issuanceEntry.IssuanceProof

	var issuanceProof proof.Proof
	err := issuanceProof.Decode(
		bytes.NewReader(issuanceLeaf.RawProof),
	)
	if err != nil {
		return fmt.Errorf("unable to decode issuance proof: %w", err)
	}

	vCtx := v.proofVerifierCtx(ctx)
	lookup, err := vCtx.ChainLookupGen.GenProofChainLookup(
		&issuanceProof,
	)
	if err != nil {
		return fmt.Errorf("unable to generate proof chain lookup: %w",
			err)
	}

	_, err = issuanceProof.Verify(ctx, nil, lookup, vCtx)
	if err != nil {
		return fmt.Errorf("issuance proof failed verification: %w",
			err)
	}

	// Ensure block height in leaf matches block height in proof.
	if issuanceEntry.MintHeight != issuanceProof.BlockHeight {
		return fmt.Errorf("mint height in issuance leaf does not " +
			"match issuance proof block height")
	}

	// Ensure that issuance leaf fields match issuance proof fields.
	if issuanceLeaf.Amt != issuanceProof.Asset.Amount {
		return fmt.Errorf("amount in issuance leaf does not match " +
			"amount in issuance proof")
	}

	if issuanceLeaf.IsBurn {
		return fmt.Errorf("IsBurn is unexpectedly true for issuance " +
			"leaf")
	}

	leafAsset := issuanceLeaf.Asset
	if leafAsset == nil {
		return fmt.Errorf("missing asset in issuance leaf")
	}

	if !issuanceProof.Asset.DeepEqual(leafAsset) {
		return fmt.Errorf("asset in issuance leaf does not match " +
			"asset in issuance proof")
	}

	if issuanceLeaf.Genesis != *issuanceProof.GenesisReveal {
		return fmt.Errorf("genesis in issuance leaf does not match " +
			"genesis in issuance proof")
	}

	if issuanceLeaf.GroupKey == nil {
		return fmt.Errorf("missing group key in issuance leaf")
	}

	// Check to ensure that the group key in the issuance leaf matches
	// the group key in the issuance proof.
	proofGroupPubKey := issuanceProof.Asset.GroupKey.GroupPubKey
	leafGroupPubKey := issuanceLeaf.GroupKey.GroupPubKey
	if !IsEquivalentPubKeys(&proofGroupPubKey, &leafGroupPubKey) {
		return fmt.Errorf("group key in issuance leaf does not match " +
			"group key in issuance proof")
	}

	// Ensure that the leaf key asset ID matches the asset ID in the
	// issuance proof.
	leafKeyAssetID := issuanceEntry.LeafKey.LeafAssetID()
	proofAssetID := issuanceProof.Asset.Genesis.ID()

	if leafKeyAssetID != proofAssetID {
		return fmt.Errorf("issance leaf key asset id does not match " +
			"issance proof asset id")
	}

	// Verify that the proof asset group is the expected asset group.
	expectedGroupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to extract group key from asset "+
			"specifier when verifying issuance leaf: %w", err)
	}

	if issuanceProof.Asset.GroupKey == nil {
		return fmt.Errorf("missing asset group key in issuance proof")
	}
	leafGroupKey := issuanceProof.Asset.GroupKey.GroupPubKey

	if !IsEquivalentPubKeys(&leafGroupKey, expectedGroupKey) {
		return fmt.Errorf("asset group key in issuance proof " +
			"does not match expected asset group key")
	}

	// Attempt to extract the pre-commitment output from the issuance proof
	// anchor transaction.
	_, err = ExtractPreCommitOutput(issuanceProof, delegationKey)
	if err != nil {
		return fmt.Errorf("unable to extract pre-commit output from "+
			"issuance proof anchor tx: %w", err)
	}

	return nil
}

// verifyIgnoreLeaf verifies a single ignore leaf entry.
func (v *Verifier) verifyIgnoreLeaf(ctx context.Context,
	assetSpec asset.Specifier, delegationPubKey btcec.PublicKey,
	ignoreEntry supplycommit.NewIgnoreEvent) error {

	v.assetLog.Tracef("Verifying ignore leaf")

	signedIgnore := ignoreEntry.SignedIgnoreTuple
	sigBytes := signedIgnore.Sig.Val.Signature.Serialize()

	digest, err := signedIgnore.IgnoreTuple.Val.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute ignore tuple digest: %w",
			err)
	}

	pubKeyByteSlice := delegationPubKey.SerializeCompressed()
	var pubKeyBytes [33]byte
	copy(pubKeyBytes[:], pubKeyByteSlice)

	sigVerifyResult, err := v.cfg.Lnd.Signer.VerifyMessage(
		ctx, digest[:], sigBytes, pubKeyBytes,
		lndclient.VerifySchnorr(),
	)
	if err != nil {
		return fmt.Errorf("error when verifying signed message: %w",
			err)
	}

	if !sigVerifyResult {
		return fmt.Errorf("failed to verify signed ignore tuple " +
			"signature")
	}

	// Verify that the asset ID in the ignore leaf belongs to the expected
	// asset group.
	//
	// Retrieve the asset group for the asset ID in the ignore leaf.
	assetGroup, err := v.cfg.AssetLookup.QueryAssetGroupByID(
		ctx, signedIgnore.IgnoreTuple.Val.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to query asset group for ignore "+
			"leaf: %w", err)
	}

	expectedGroupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to extract group key from asset "+
			"specifier when verifying ignore leaf: %w", err)
	}

	if !IsEquivalentPubKeys(&assetGroup.GroupPubKey, expectedGroupKey) {
		return fmt.Errorf("asset group key for ignore leaf asset " +
			"does not match expected asset group key")
	}

	return nil
}

// verifyBurnLeaf verifies a single burn leaf entry.
func (v *Verifier) verifyBurnLeaf(ctx context.Context,
	assetSpec asset.Specifier, burnEntry supplycommit.NewBurnEvent) error {

	v.assetLog.Tracef("Verifying burn leaf")

	burnProof := burnEntry.BurnProof
	if burnProof == nil {
		return fmt.Errorf("missing burn proof for burn leaf")
	}

	vCtx := v.proofVerifierCtx(ctx)
	lookup, err := vCtx.ChainLookupGen.GenProofChainLookup(
		burnProof,
	)
	if err != nil {
		return fmt.Errorf("unable to generate proof chain lookup: %w",
			err)
	}

	_, err = burnProof.Verify(ctx, nil, lookup, vCtx)
	if err != nil {
		return fmt.Errorf("burn leaf proof failed verification: %w",
			err)
	}

	// Ensure that the leaf key asset ID matches the asset ID in the burn
	// proof.
	leafKeyAssetID := burnEntry.BurnLeaf.UniverseKey.LeafAssetID()
	proofAssetID := burnProof.Asset.Genesis.ID()

	if leafKeyAssetID != proofAssetID {
		return fmt.Errorf("burn leaf key asset id does not match " +
			"burn proof asset id")
	}

	// Assert that the asset in the burn proof is a burn asset.
	if !burnProof.Asset.IsBurn() {
		return fmt.Errorf("asset in burn proof is not a burn asset")
	}

	// Verify that the proof asset group is the expected asset group.
	expectedGroupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to extract group key from asset "+
			"specifier when verifying burn leaf: %w", err)
	}

	if burnProof.Asset.GroupKey == nil {
		return fmt.Errorf("missing asset group key in burn proof")
	}
	leafGroupKey := burnProof.Asset.GroupKey.GroupPubKey

	if !IsEquivalentPubKeys(&leafGroupKey, expectedGroupKey) {
		return fmt.Errorf("asset group key in burn proof " +
			"does not match expected asset group key")
	}

	return nil
}

// verifySupplyLeaves performs validation of the provided supply leaves.
func (v *Verifier) verifySupplyLeaves(ctx context.Context,
	assetSpec asset.Specifier, delegationPubKey btcec.PublicKey,
	leaves supplycommit.SupplyLeaves) error {

	v.assetLog.Debugf("Verifying supply leaves, "+
		"issuance_leaves=%d, ignore_leaves=%d, burn_leaves=%d",
		len(leaves.IssuanceLeafEntries),
		len(leaves.IgnoreLeafEntries), len(leaves.BurnLeafEntries))

	// Ensure that all supply leaf block heights are set.
	err := leaves.ValidateBlockHeights()
	if err != nil {
		return fmt.Errorf("supply leaves validation failed: %w", err)
	}

	// Verify issuance leaves, if any are present.
	for idx := range leaves.IssuanceLeafEntries {
		issuanceEntry := leaves.IssuanceLeafEntries[idx]

		err = v.verifyIssuanceLeaf(
			ctx, assetSpec, delegationPubKey, issuanceEntry,
		)
		if err != nil {
			return fmt.Errorf("issuance leaf failed "+
				"verification: %w", err)
		}
	}

	// Verify ignore leaves, if any are present.
	for idx := range leaves.IgnoreLeafEntries {
		ignoreEntry := leaves.IgnoreLeafEntries[idx]

		err = v.verifyIgnoreLeaf(
			ctx, assetSpec, delegationPubKey, ignoreEntry,
		)
		if err != nil {
			return fmt.Errorf("ignore leaf failed verification: %w",
				err)
		}
	}

	// Verify burn leaves, if any are present.
	for idx := range leaves.BurnLeafEntries {
		burnEntry := leaves.BurnLeafEntries[idx]

		err = v.verifyBurnLeaf(ctx, assetSpec, burnEntry)
		if err != nil {
			return fmt.Errorf("burn leaf failed verification: %w",
				err)
		}
	}

	v.assetLog.Debugf("Successfully verified all supply leaves")

	return nil
}

// VerifyCommit verifies a supply commitment for a given asset group.
// Verification succeeds only if all previous supply commitment dependencies
// are known and verified. The dependency chain must be traceable back to the
// asset issuance anchoring transaction and its pre-commitment output(s).
func (v *Verifier) VerifyCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	unspentPreCommits supplycommit.PreCommits) error {

	v.assetLog.Infof("Starting supply commitment verification, "+
		"commitment_outpoint=%s",
		commitment.CommitPoint().String())

	// TODO(ffranr): Consider: should we require some leaves to be present?
	//  Or for forward compatibility, allow no leaves?

	// Perform static on-chain verification of the supply commitment's
	// anchoring block header. This provides a basic proof-of-work guarantee
	// that gates further verification steps.
	v.assetLog.Debugf("Verifying chain anchor for commitment")
	headerVerifier := tapgarden.GenHeaderVerifier(ctx, v.cfg.ChainBridge)
	err := commitment.VerifyChainAnchor(
		proof.DefaultMerkleVerifier, headerVerifier,
	)
	if err != nil {
		return fmt.Errorf("unable to verify supply commitment: %w", err)
	}

	// Attempt to fetch the supply commitment by its outpoint, to
	// ensure that it is not already present in the database.
	_, err = v.cfg.SupplyCommitView.FetchCommitmentByOutpoint(
		ctx, assetSpec, commitment.CommitPoint(),
	)
	switch {
	case err == nil:
		// Found commitment, assume already verified and stored.
		v.assetLog.Debugf("Commitment already verified and stored: %s",
			commitment.CommitPoint().String())
		return nil

	case errors.Is(err, ErrCommitmentNotFound):
		// Do nothing, continue to verification of given commitment.
		v.assetLog.Debugf("Commitment not found in database, " +
			"proceeding with verification")

	default:
		return fmt.Errorf("failed to check for existing supply "+
			"commitment with given outpoint: %w", err)
	}

	delegationKey, err := FetchDelegationKey(
		ctx, v.cfg.AssetLookup, assetSpec,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch delegation key: %w", err)
	}

	// Assert that asset group is specified in the asset specifier.
	_, err = assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("asset specifier must specify an asset "+
			"group when verifying supply commitment: %w", err)
	}

	// Perform validation of the provided supply leaves.
	err = v.verifySupplyLeaves(ctx, assetSpec, delegationKey, leaves)
	if err != nil {
		return fmt.Errorf("unable to verify supply leaves: %w", err)
	}

	// If the commitment does not specify a spent outpoint, then we dispatch
	// to the initial commitment verification routine.
	if commitment.SpentCommitment.IsNone() {
		return v.verifyInitialCommit(
			ctx, assetSpec, commitment, leaves,
			unspentPreCommits,
		)
	}

	// Otherwise, we dispatch to the incremental commitment verification
	// routine.
	return v.verifyIncrementalCommit(
		ctx, assetSpec, commitment, leaves,
		unspentPreCommits,
	)
}

// ExtractPreCommitOutput extracts and returns the supply pre-commitment output
// from the given issuance proof and asset metadata reveal.
func ExtractPreCommitOutput(issuanceProof proof.Proof,
	delegationKey btcec.PublicKey) (supplycommit.PreCommitment, error) {

	var zero supplycommit.PreCommitment

	// Identify txOut in mint anchor transaction which corresponds to the
	// supply pre-commitment output.
	//
	// Construct the expected pre-commit tx out.
	expectedTxOut, err := tapgarden.PreCommitTxOut(delegationKey)
	if err != nil {
		return zero, fmt.Errorf("unable to derive expected pre-commit "+
			"txout: %w", err)
	}

	var preCommitTxOutIndex int32 = -1
	for idx := range issuanceProof.AnchorTx.TxOut {
		txOut := *issuanceProof.AnchorTx.TxOut[idx]

		// Compare txOut to the expected pre-commit tx out.
		isValueEqual := txOut.Value == expectedTxOut.Value
		isPkScriptEqual := bytes.Equal(
			txOut.PkScript, expectedTxOut.PkScript,
		)

		if isValueEqual && isPkScriptEqual {
			preCommitTxOutIndex = int32(idx)
		}
	}

	// If we didn't find the pre-commit tx out, then return an error.
	if preCommitTxOutIndex == -1 {
		return zero, fmt.Errorf("unable to find pre-commit tx out in " +
			"issuance anchor tx")
	}

	// Calculate the outpoint of the supply pre-commitment.
	return supplycommit.PreCommitment{
		BlockHeight: issuanceProof.BlockHeight,
		MintingTxn:  &issuanceProof.AnchorTx,
		OutIdx:      uint32(preCommitTxOutIndex),
		InternalKey: keychain.KeyDescriptor{
			PubKey: &delegationKey,
		},
		GroupPubKey: issuanceProof.Asset.GroupKey.GroupPubKey,
	}, nil
}
