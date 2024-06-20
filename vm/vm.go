package vm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

// Engine is a virtual machine capable of executing and verifying Taproot asset
// state transitions.
type Engine struct {
	// newAsset represents the final state of an asset undergoing a state
	// transition.
	newAsset *asset.Asset

	// splitAssets represents zero or more asset splits committed to within
	// the newAsset's SplitCommitmentRoot.
	splitAssets []*commitment.SplitAsset

	// prevAssets maps newAsset's inputs by the hash of their PrevID to
	// their asset.
	prevAssets commitment.InputSet

	// skipTimeLockValidation is a flag that indicates whether the engine
	// should skip validating lock times.
	skipTimeLockValidation bool

	// blockHeight is an optional block height that the time locks should be
	// validated against. If this is None, the current best known block
	// height will be used.
	blockHeight fn.Option[uint32]

	// chainLookup is an interface that can be used to look up certain
	// information on chain.
	chainLookup asset.ChainLookup
}

// newEngineOptions is a struct that is used to customize how a new engine is to
// be created.
type newEngineOptions struct {
	skipTimeLockValidation bool
	blockHeight            fn.Option[uint32]
	chainLookup            asset.ChainLookup
}

// NewEngineOpt is used to modify how a new engine is to be created.
type NewEngineOpt func(*newEngineOptions)

// defaultNewEngineOptions returns the default set of engine options.
func defaultNewEngineOptions() *newEngineOptions {
	return &newEngineOptions{
		skipTimeLockValidation: false,
	}
}

// WithChainLookup can be used to create an engine that is capable of validating
// time locks.
func WithChainLookup(chainLookup asset.ChainLookup) NewEngineOpt {
	return func(o *newEngineOptions) {
		o.chainLookup = chainLookup
	}
}

// WithBlockHeight can be used to create an engine that validates time locks
// against the given block height instead of the current best known block.
func WithBlockHeight(blockHeight uint32) NewEngineOpt {
	return func(o *newEngineOptions) {
		o.blockHeight = fn.Some(blockHeight)
	}
}

// WithSkipTimeLockValidation can be used to create an engine that skips
// validating time locks.
func WithSkipTimeLockValidation() NewEngineOpt {
	return func(o *newEngineOptions) {
		o.skipTimeLockValidation = true
	}
}

// New returns a new virtual machine capable of executing and verifying Taproot
// Asset state transitions.
func New(newAsset *asset.Asset, splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet, opts ...NewEngineOpt) (*Engine, error) {

	options := defaultNewEngineOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &Engine{
		newAsset:               newAsset,
		splitAssets:            splitAssets,
		prevAssets:             prevAssets,
		skipTimeLockValidation: options.skipTimeLockValidation,
		blockHeight:            options.blockHeight,
		chainLookup:            options.chainLookup,
	}, nil
}

// matchesPrevGenesis determines whether certain key parameters of the new
// asset continue to hold its previous genesis.
func matchesPrevGenesis(prevID asset.ID, groupKey *asset.GroupKey,
	tag string, prevAsset *asset.Asset) bool {

	switch {
	// Matched genesis ID, gg.
	case prevID == prevAsset.Genesis.ID():
		return true

	// Mismatched ID and nil GroupKey, ouch.
	case groupKey == nil && prevAsset.GroupKey == nil:
		fallthrough
	case groupKey == nil && prevAsset.GroupKey != nil:
		fallthrough
	case groupKey != nil && prevAsset.GroupKey == nil:
		return false

	// Mismatched ID and non-nil GroupKey, there's hope!
	case groupKey != nil && prevAsset.GroupKey != nil:
		// Mismatched ID and GroupKey, sigh.
		if !groupKey.IsEqual(prevAsset.GroupKey) {
			return false
		}

		// Matched ID and GroupKey, there's still hope!
		return tag == prevAsset.Genesis.Tag

	// How did we get here?
	default:
		// TODO(roasbeef): actually make into an error?
		panic("unreachable")
	}
}

// matchesAssetParams ensures that a new asset continues to adhere to the
// static parameters of its predecessor.
func matchesAssetParams(newAsset, prevAsset *asset.Asset,
	prevAssetWitness *asset.Witness) error {

	scriptKey := asset.ToSerialized(prevAsset.ScriptKey.PubKey)
	if prevAssetWitness.PrevID.ScriptKey != scriptKey {
		return newErrKind(ErrScriptKeyMismatch)
	}

	if !matchesPrevGenesis(
		prevAssetWitness.PrevID.ID, newAsset.GroupKey,
		newAsset.Genesis.Tag, prevAsset,
	) {

		return newErrKind(ErrIDMismatch)
	}

	if newAsset.Type != prevAsset.Type {
		return newErrKind(ErrTypeMismatch)
	}

	return nil
}

// ValidateWitnesses is a helper method that checks the witnesses provided over
// an asset transfer. This method may be used for transfers that are not yet
// complete, in order to check if the existing signatures are valid.
func ValidateWitnesses(newAsset *asset.Asset,
	splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet) error {

	vm, err := New(newAsset, splitAssets, prevAssets)
	if err != nil {
		return err
	}

	// If we have an asset split, then we need to validate the state
	// transition by verifying the split commitment proof before verify the
	// final asset witness.
	for _, splitAsset := range vm.splitAssets {
		if err := vm.validateSplit(splitAsset); err != nil {
			return err
		}
	}

	switch {
	case len(vm.newAsset.PrevWitnesses) == 0:
		return fmt.Errorf("%w: prev witness zero", ErrNoInputs)

	case vm.newAsset.Type == asset.Collectible &&
		len(vm.newAsset.PrevWitnesses) > 1:

		inner := fmt.Errorf("collectible has more than one prev input")
		return newErrInner(ErrInvalidTransferWitness, inner)
	}

	// Now that we know we're not dealing with a genesis state
	// transition, we'll map our set of asset inputs and outputs to
	// the 1-input 1-output virtual transaction.
	virtualTx, _, err := tapscript.VirtualTx(vm.newAsset, vm.prevAssets)
	if err != nil {
		return err
	}

	for i, witness := range vm.newAsset.PrevWitnesses {
		witness := witness
		prevAsset, ok := vm.prevAssets[*witness.PrevID]
		if !ok {
			return fmt.Errorf("%w: no prev asset for "+
				"input_prev_id=%v", ErrNoInputs,
				spew.Sdump(witness.PrevID))
		}

		switch prevAsset.ScriptVersion {
		case asset.ScriptV0:
			err := vm.validateWitnessV0(
				virtualTx, uint32(i), &witness, prevAsset,
			)
			if err != nil {
				return err
			}
		default:
			return ErrInvalidScriptVersion
		}
	}

	return nil
}

// validateSplit attempts to validate an asset resulting from a split on its
// input. This is done by verifying the asset split is committed to within the
// new asset's split commitment root through its split commitment proof.
func (vm *Engine) validateSplit(splitAsset *commitment.SplitAsset) error {
	// The asset type must match for all parts of a split, and the change
	// asset should have a split commitment root.
	switch {
	case vm.newAsset.Type != splitAsset.Type:
		return newErrKind(ErrInvalidSplitAssetType)

	case vm.newAsset.SplitCommitmentRoot == nil:
		return newErrKind(ErrNoSplitCommitment)
	}

	// Split assets should always have a single witness with a non-nil
	// PrevID and empty TxWitness.
	if !splitAsset.Asset.HasSplitCommitmentWitness() {
		return newErrKind(ErrInvalidSplitCommitmentWitness)
	}

	// We'll use the input of the new asset here, as the splits have a
	// prevID of zero, as the inherit the prev ID from the root asset.
	//
	// TODO(roasbeef): revisit post multi input
	rootWitness := vm.newAsset.PrevWitnesses[0]
	splitWitness := splitAsset.PrevWitnesses[0]

	// The prevID of the split commitment should be the ID of the asset
	// generating the split in the transaction.
	//
	// TODO(roasbeef): revisit?
	prevAsset, ok := vm.prevAssets[*rootWitness.PrevID]
	if !ok {
		return fmt.Errorf("%w: root_witness_prev_id=%v, "+
			"num_prev_assets=%v", ErrNoInputs,
			spew.Sdump(rootWitness.PrevID),
			len(vm.prevAssets))
	}
	err := matchesAssetParams(
		&splitAsset.Asset, prevAsset, &rootWitness,
	)
	if err != nil {
		return err
	}

	// If the split requires a zero-value root asset, the root asset must
	// be un-spendable. Non-inflation of the split is enforced elsewhere, at
	// the end of vm.Execute().
	if vm.newAsset.Amount == 0 && !vm.newAsset.IsUnSpendable() {
		return newErrKind(ErrInvalidRootAsset)
	}

	// If we are validating the root asset of the split, the root split must
	// also be un-spendable.
	if splitAsset.Amount == 0 && !splitAsset.IsUnSpendable() {
		return newErrKind(ErrInvalidRootAsset)
	}

	// Finally, verify that the split commitment proof for the split asset
	// resolves to the split commitment root found within the change asset.
	locator := &commitment.SplitLocator{
		OutputIndex: splitAsset.OutputIndex,
		AssetID:     splitAsset.Genesis.ID(),
		ScriptKey:   asset.ToSerialized(splitAsset.ScriptKey.PubKey),
		Amount:      splitAsset.Amount,
	}
	splitNoWitness := splitAsset.Copy()
	splitNoWitness.PrevWitnesses[0].SplitCommitment = nil

	// Lock times should not invalidate the split commitment proof.
	splitNoWitness.LockTime = vm.newAsset.LockTime
	splitNoWitness.RelativeLockTime = vm.newAsset.RelativeLockTime

	splitLeaf, err := splitNoWitness.Leaf()
	if err != nil {
		return err
	}

	if !mssmt.VerifyMerkleProof(
		locator.Hash(), splitLeaf, &splitWitness.SplitCommitment.Proof,
		vm.newAsset.SplitCommitmentRoot,
	) {

		return newErrKind(ErrInvalidSplitCommitmentProof)
	}

	return nil
}

// validateWitnessV0 attempts to validate a new asset's witness based on the
// initial Taproot Asset script version generated over the virtual transaction
// represented by the state transition.
func (vm *Engine) validateWitnessV0(virtualTx *wire.MsgTx, inputIdx uint32,
	witness *asset.Witness, prevAsset *asset.Asset) error {

	// We only support version 0 scripts atm.
	if prevAsset.ScriptVersion != asset.ScriptV0 {
		return ErrInvalidScriptVersion
	}

	// An input must have a valid witness.
	if len(witness.TxWitness) == 0 {
		inner := fmt.Errorf("input has no witness")
		return newErrInner(ErrInvalidTransferWitness, inner)
	}

	var (
		prevOutFetcher *txscript.CannedPrevOutputFetcher
		err            error
	)

	// Genesis grouped assets will have a nil PrevID and match the prevAsset
	// since it is a copy of the original asset. The prevOut used will need
	// to built from the group key and not the script key.
	switch {
	case vm.newAsset.HasGenesisWitnessForGroup():
		prevOutFetcher, err = asset.GenesisPrevOutFetcher(*prevAsset)

	default:
		// An input MUST have a prev out and also a valid witness.
		if witness.PrevID == nil {
			inner := fmt.Errorf("input has nil prev ID")
			return newErrInner(ErrInvalidTransferWitness, inner)
		}

		// The parameters of the new and old asset much match exactly.
		err = matchesAssetParams(vm.newAsset, prevAsset, witness)
		if err != nil {
			return err
		}

		prevOutFetcher, err = tapscript.InputPrevOutFetcher(*prevAsset)
	}
	if err != nil {
		if errors.Is(err, tapscript.ErrInvalidScriptVersion) {
			return ErrInvalidScriptVersion
		}
		return err
	}

	// Obtain the prev out created above, we can pass in a null outpoint
	// here as it's a canned fetcher, so it'll return the same prev out
	// every time.
	prevOut := prevOutFetcher.FetchPrevOutput(wire.OutPoint{})

	// Update the virtual transaction input with details for the specific
	// Taproot Asset input and proceed to validate its witness.
	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, vm.newAsset.LockTime, vm.newAsset.RelativeLockTime,
		inputIdx, witness.TxWitness,
	)

	sigHashes := txscript.NewTxSigHashes(virtualTxCopy, prevOutFetcher)

	// With all the components mapped into a virtual transaction, will
	// execute it using the normal Tapscript VM, which does most of the
	// heavy lifting here.
	engine, err := txscript.NewEngine(
		prevOut.PkScript, virtualTxCopy, 0, txscript.StandardVerifyFlags,
		nil, sigHashes, prevOut.Value, prevOutFetcher,
	)
	if err != nil {
		return newErrInner(ErrInvalidTransferWitness, err)
	}
	if err := engine.Execute(); err != nil {
		return newErrInner(ErrInvalidTransferWitness, err)
	}

	return nil
}

// validateStateTransition attempts to validate a normal state transition where
// an asset (normal or collectible) is fully consumed without splits. This is
// done by verifying each input has a valid witness generated over the virtual
// transaction representing the state transition.
func (vm *Engine) validateStateTransition() error {
	switch {
	case len(vm.newAsset.PrevWitnesses) == 0:
		return fmt.Errorf("%w: prev witness zero", ErrNoInputs)

	case vm.newAsset.Type == asset.Collectible &&
		len(vm.newAsset.PrevWitnesses) > 1:

		inner := fmt.Errorf("collectible has more than one prev input")
		return newErrInner(ErrInvalidTransferWitness, inner)
	}

	// Now that we know we're not dealing with a genesis state
	// transition, we'll map our set of asset inputs and outputs to
	// the 1-input 1-output virtual transaction.
	virtualTx, inputTree, err := tapscript.VirtualTx(
		vm.newAsset, vm.prevAssets,
	)
	if err != nil {
		return err
	}

	// Enforce that assets aren't being inflated.
	ctxb := context.Background()
	treeRoot, err := inputTree.Root(ctxb)
	if err != nil {
		return err
	}
	if treeRoot.NodeSum() !=
		uint64(virtualTx.TxOut[0].Value) {

		return newErrInner(ErrAmountMismatch, fmt.Errorf("expected "+
			"output value=%v, got=%v", treeRoot.NodeSum(),
			virtualTx.TxOut[0].Value))
	}

	for idx := range vm.newAsset.PrevWitnesses {
		witness := vm.newAsset.PrevWitnesses[idx]

		prevAsset, ok := vm.prevAssets[*witness.PrevID]
		if !ok {
			return fmt.Errorf("%w: no prev asset for "+
				"input_prev_id=%v", ErrNoInputs,
				spew.Sdump(witness.PrevID))
		}

		if !vm.skipTimeLockValidation {
			if vm.chainLookup == nil {
				return fmt.Errorf("chain lookup required for " +
					"time lock validation")
			}

			bestBlockHeight, err := vm.chainLookup.CurrentHeight(
				ctxb,
			)
			if err != nil {
				return fmt.Errorf("error getting current "+
					"height: %w", err)
			}

			blockHeight := vm.blockHeight.UnwrapOr(bestBlockHeight)
			err = checkLockTime(
				ctxb, vm.newAsset, &witness, blockHeight,
				vm.chainLookup,
			)
			if err != nil {
				return err
			}
		}

		switch prevAsset.ScriptVersion {
		case asset.ScriptV0:
			err := vm.validateWitnessV0(
				virtualTx, uint32(idx), &witness, prevAsset,
			)
			if err != nil {
				return err
			}
		default:
			return ErrInvalidScriptVersion
		}
	}

	return nil
}

// Execute attempts to execute an asset's state transition to determine whether
// it was valid or not represented by the error returned.
func (vm *Engine) Execute() error {
	// A genesis asset should have a single witness and a PrevID of all
	// zeros and empty witness and split commitment proof.
	if vm.newAsset.HasGenesisWitness() {
		if len(vm.splitAssets) > 0 || len(vm.prevAssets) > 0 {
			return newErrKind(ErrInvalidGenesisStateTransition)
		}

		// A genesis asset with a group key must have a witness before
		// being validated.
		if vm.newAsset.GroupKey != nil {
			return newErrKind(ErrInvalidGenesisStateTransition)
		}
		return nil
	}

	// Genesis assets in an asset group have a witness that must be
	// verified to prove group membership.
	if vm.newAsset.HasGenesisWitnessForGroup() {
		if len(vm.splitAssets) > 0 || len(vm.prevAssets) > 0 {
			return newErrKind(ErrInvalidGenesisStateTransition)
		}

		// For genesis assets in an asset group, set the previous asset
		// as the genesis asset.
		vm.prevAssets = commitment.InputSet{
			asset.ZeroPrevID: vm.newAsset,
		}
	}

	// If we have an asset split, then we need to validate the state
	// transition by verifying the split commitment proof before verify the
	// final asset witness.
	for _, splitAsset := range vm.splitAssets {
		if err := vm.validateSplit(splitAsset); err != nil {
			return err
		}
	}

	return vm.validateStateTransition()
}

// checkLockTime checks the absolute and relative lock time of the previous
// asset. `blockTimestamp` is ignored for now.
func checkLockTime(ctx context.Context, newAsset *asset.Asset,
	witness *asset.Witness, blockHeight uint32,
	chainLookup asset.ChainLookup) error {

	// Check absolute lock time. This is easy as we can just compare the
	// input asset's lock time to the current block height that we are aware
	// of.
	if newAsset.LockTime != 0 {
		switch {
		// If the lock time is a timestamp, we need to parse it as such
		// and compare it to the current block height.
		case newAsset.LockTime > txscript.LockTimeThreshold:
			// To save some lookups, we only query the reference
			// block's mean time if we really have to, which is now.
			blockMeanTime, err := chainLookup.MeanBlockTimestamp(
				ctx, blockHeight,
			)
			if err != nil {
				return fmt.Errorf("unable to obtain current "+
					"height's timestamp: %w", err)
			}

			timeLock := time.Unix(int64(newAsset.LockTime), 0)
			if blockMeanTime.Before(timeLock) {
				inner := fmt.Errorf("block_time=%v, "+
					"min_time=%v", blockMeanTime, timeLock)
				return newErrInner(ErrUnfinalizedAsset, inner)
			}

		// Otherwise, we can just compare the lock time to the current
		// block height.
		case blockHeight < uint32(newAsset.LockTime):
			inner := fmt.Errorf("block_height=%v, "+
				"lock_time=%v", blockHeight, newAsset.LockTime)
			return newErrInner(ErrUnfinalizedAsset, inner)
		}
	}

	// Now check any relative lock time. For this we need to look up the
	// height of the block the input's anchor transaction was confirmed in.
	if newAsset.RelativeLockTime != 0 {
		// First, since this is a _relative_ time lock, we need to find
		// out in which block the input we're spending was confirmed.
		inputConfirmHeight, err := chainLookup.TxBlockHeight(
			ctx, witness.PrevID.OutPoint.Hash,
		)
		if err != nil {
			return fmt.Errorf("error looking up input confirm "+
				"height: %w", err)
		}

		// Given a sequence number, we apply the relative time lock
		// mask in order to obtain the time lock delta required before
		// this input can be spent.
		sequenceNum := newAsset.RelativeLockTime
		relativeLock := sequenceNum & wire.SequenceLockTimeMask

		switch {
		// Relative time locks are disabled for this input, so we can
		// skip any further calculation.
		case sequenceNum&wire.SequenceLockTimeDisabled ==
			wire.SequenceLockTimeDisabled:

			// Do nothing, continue below.

		case sequenceNum&wire.SequenceLockTimeIsSeconds ==
			wire.SequenceLockTimeIsSeconds:

			// This input requires a relative time lock expressed
			// in seconds before it can be spent. Therefore, we
			// need to query for the block prior to the one in
			// which this input was included within, so we can
			// compute the past median time for the block prior to
			// the one which included this referenced output.
			prevInputHeight := inputConfirmHeight - 1
			if prevInputHeight < 0 {
				prevInputHeight = 0
			}
			inMedianTime, err := chainLookup.MeanBlockTimestamp(
				ctx, prevInputHeight,
			)
			if err != nil {
				return err
			}

			// Time based relative time-locks as defined by BIP 68
			// have a time granularity of RelativeLockSeconds, so
			// we shift left by this amount to convert to the
			// proper relative time-lock. We also subtract one from
			// the relative lock to maintain the original lockTime
			// semantics.
			timeLockSeconds := (relativeLock <<
				wire.SequenceLockTimeGranularity) - 1

			timeLock := inMedianTime.Add(
				time.Duration(timeLockSeconds) * time.Second,
			)

			// To save some lookups, we only query the reference
			// block's mean time if we really have to, which is now.
			blockMeanTime, err := chainLookup.MeanBlockTimestamp(
				ctx, blockHeight,
			)
			if err != nil {
				return fmt.Errorf("unable to obtain current "+
					"height's timestamp: %w", err)
			}

			// If the time lock is before the current block time,
			// then the input is not yet finalized.
			if blockMeanTime.Before(timeLock) {
				inner := fmt.Errorf("block_time=%v, "+
					"min_time=%v", blockMeanTime, timeLock)
				return newErrInner(ErrUnfinalizedAsset, inner)
			}

		default:
			// The relative lock-time for this input is expressed in
			// blocks, so we calculate the relative offset from the
			// input's height as its converted absolute lock-time.
			minHeight := overflowSafeAdd(
				uint64(inputConfirmHeight), relativeLock,
			)

			if uint64(blockHeight) < minHeight {
				inner := fmt.Errorf("block_height=%v, "+
					"min_height=%v", blockHeight, minHeight)
				return newErrInner(ErrUnfinalizedAsset, inner)
			}
		}
	}

	return nil
}

// overflowSafeAdd adds two uint64 values and returns the result. If an overflow
// could occur, the maximum uint64 value is returned instead.
func overflowSafeAdd(x, y uint64) uint64 {
	if y > math.MaxUint64-x {
		// Overflow would occur, return maximum uint64 value.
		return math.MaxUint64
	}

	return x + y
}
