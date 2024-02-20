package vm

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
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
}

// New returns a new virtual machine capable of executing and verifying Taproot
// Asset state transitions.
func New(newAsset *asset.Asset, splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet) (*Engine, error) {

	return &Engine{
		newAsset:    newAsset,
		splitAssets: splitAssets,
		prevAssets:  prevAssets,
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

		return newErrKind(ErrInvalidTransferWitness)
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
		return newErrKind(ErrInvalidTransferWitness)
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
			return newErrKind(ErrInvalidTransferWitness)
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
		virtualTx, prevAsset, inputIdx, witness.TxWitness,
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

		return newErrKind(ErrInvalidTransferWitness)
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
	treeRoot, err := inputTree.Root(context.Background())
	if err != nil {
		return err
	}
	if treeRoot.NodeSum() !=
		uint64(virtualTx.TxOut[0].Value) {

		return newErrKind(ErrAmountMismatch)
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
