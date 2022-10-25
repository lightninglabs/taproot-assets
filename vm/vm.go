package vm

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/taroscript"
)

// Engine is a virtual machine capable of executing and verifying Taro asset
// state transitions.
type Engine struct {
	// newAsset represents the final state of an asset undergoing a state
	// transition.
	newAsset *asset.Asset

	// splitAsset represents an asset split committed to within the
	// newAsset's SplitCommitmentRoot if one exists.
	splitAsset *commitment.SplitAsset

	// prevAssets maps newAsset's inputs by the hash of their PrevID to
	// their asset.
	prevAssets commitment.InputSet
}

// New returns a new virtual machine capable of executing and verifying Taro
// asset state transitions.
func New(newAsset *asset.Asset, splitAsset *commitment.SplitAsset,
	prevAssets commitment.InputSet) (*Engine, error) {

	return &Engine{
		newAsset:   newAsset,
		splitAsset: splitAsset,
		prevAssets: prevAssets,
	}, nil
}

// matchesPrevGenesis determines whether certain key parameters of the new
// asset continue to hold its previous genesis.
func matchesPrevGenesis(prevID asset.ID, familyKey *asset.FamilyKey,
	tag string, prevAsset *asset.Asset) bool {

	switch {
	// Matched genesis ID, gg.
	case prevID == prevAsset.Genesis.ID():
		return true

	// Mismatched ID and nil FamilyKey, ouch.
	case familyKey == nil && prevAsset.FamilyKey == nil:
		fallthrough
	case familyKey == nil && prevAsset.FamilyKey != nil:
		fallthrough
	case familyKey != nil && prevAsset.FamilyKey == nil:
		return false

	// Mismatched ID and non-nil FamilyKey, there's hope!
	case familyKey != nil && prevAsset.FamilyKey != nil:
		// Mismatched ID and FamilyKey, sigh.
		if !familyKey.IsEqual(prevAsset.FamilyKey) {
			return false
		}

		// Matched ID and FamilyKey, there's still hope!
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
		prevAssetWitness.PrevID.ID, newAsset.FamilyKey,
		newAsset.Genesis.Tag, prevAsset,
	) {

		return newErrKind(ErrIDMismatch)
	}

	if newAsset.Type != prevAsset.Type {
		return newErrKind(ErrTypeMismatch)
	}

	return nil
}

// validateSplit attempts to validate an asset resulting from a split on its
// input. This is done by verifying the asset split is committed to within the
// new asset's split commitment root through its split commitment proof.
func (vm *Engine) validateSplit() error {
	// Only `Normal` assets can be split, and the change asset should have
	// a split commitment root.
	switch {
	case vm.newAsset.Type != asset.Normal ||
		vm.splitAsset.Type != asset.Normal:

		return newErrKind(ErrInvalidSplitAssetType)

	case vm.newAsset.SplitCommitmentRoot == nil:
		return newErrKind(ErrNoSplitCommitment)
	}

	// Split assets should always have a single witness with a non-nil
	// PrevID and empty TxWitness.
	if !vm.splitAsset.Asset.HasSplitCommitmentWitness() {
		return newErrKind(ErrInvalidSplitCommitmentWitness)
	}

	// We'll use the input of the new asset here, as the splits have a
	// prevID of zero, as the inherit the prev ID from the root asset.
	//
	// TODO(roasbeef): revisit post multi input
	rootWitness := vm.newAsset.PrevWitnesses[0]
	splitWitness := vm.splitAsset.PrevWitnesses[0]

	// The prevID of the split commitment should be the ID of the asset
	// generating the split in the transaction.
	//
	// TODO(roasbeef): revisit?
	prevAsset, ok := vm.prevAssets[*rootWitness.PrevID]
	if !ok {
		return ErrNoInputs
	}
	err := matchesAssetParams(
		&vm.splitAsset.Asset, prevAsset, &rootWitness,
	)
	if err != nil {
		return err
	}

	// If the split requires a zero-value root asset, the root asset must
	// be unspendable. Non-inflation of the split is enforced elsewhere, at
	// the end of vm.Execute().
	if vm.newAsset.Amount == 0 && !vm.newAsset.IsUnspendable() {
		return newErrKind(ErrInvalidRootAsset)
	}

	// If we are validating the root asset of the split, the root split must
	// also be unspendable.
	if vm.splitAsset.Amount == 0 && !vm.splitAsset.IsUnspendable() {
		return newErrKind(ErrInvalidRootAsset)
	}

	// Finally, verify that the split commitment proof for the split asset
	// resolves to the split commitment root found within the change asset.
	locator := &commitment.SplitLocator{
		OutputIndex: vm.splitAsset.OutputIndex,
		AssetID:     vm.splitAsset.Genesis.ID(),
		ScriptKey:   asset.ToSerialized(vm.splitAsset.ScriptKey.PubKey),
		Amount:      vm.splitAsset.Amount,
	}
	splitNoWitness := vm.splitAsset.Copy()
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
// initial Taro script version generated over the virtual transaction
// represented by the state transition.
func (vm *Engine) validateWitnessV0(virtualTx *wire.MsgTx, inputIdx uint32,
	witness *asset.Witness, prevAsset *asset.Asset) error {

	// We only support version 0 scripts atm.
	if prevAsset.ScriptVersion != asset.ScriptV0 {
		return ErrInvalidScriptVersion
	}

	// An input MUST have a prev out and also a valid witness.
	if witness.PrevID == nil || len(witness.TxWitness) == 0 {
		return newErrKind(ErrInvalidTransferWitness)
	}

	// The parameters of the new and old asset much match exactly.
	err := matchesAssetParams(vm.newAsset, prevAsset, witness)
	if err != nil {
		return err
	}

	for _, witnessItem := range witness.TxWitness {
		// Signatures can either be 64, with SIGHASH_DEFAULT, or 65
		// bytes otherwise.
		//
		// TODO(roasbeef): remove? will go thru normal sig parse
		// checks, untested as is
		// TODO: This is wrong
		if len(witnessItem) == 65 {
			_, err = schnorr.ParseSignature(witnessItem[1:])
			if err != nil {
				// Not a valid signature, so it must be some
				// arbitrary data push.
				continue
			}
			return newErrKind(ErrInvalidSigHashFlag)
		}
	}

	// Update the virtual transaction input with details for the specific
	// Taro input and proceed to validate its witness.
	virtualTxCopy := taroscript.VirtualTxWithInput(
		virtualTx, prevAsset, inputIdx, witness.TxWitness,
	)

	prevOutFetcher, err := taroscript.InputPrevOutFetcher(*prevAsset)
	if err != nil {
		if errors.Is(err, taroscript.ErrInvalidScriptVersion) {
			return ErrInvalidScriptVersion
		}
		return err
	}

	// Obtain the prev out created above, we can pass in a null outpoint
	// here as it's a canned fetcher, so it'll return the same prev out
	// every time.
	prevOut := prevOutFetcher.FetchPrevOutput(wire.OutPoint{})

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
func (vm *Engine) validateStateTransition(virtualTx *wire.MsgTx) error {
	switch {
	case len(vm.newAsset.PrevWitnesses) == 0:
		return ErrNoInputs

	case vm.newAsset.Type == asset.Collectible &&
		len(vm.newAsset.PrevWitnesses) > 1:

		return newErrKind(ErrInvalidTransferWitness)
	}

	for i, witness := range vm.newAsset.PrevWitnesses {
		witness := witness
		prevAsset, ok := vm.prevAssets[*witness.PrevID]
		if !ok {
			return ErrNoInputs
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
		if vm.splitAsset != nil || len(vm.prevAssets) > 0 {
			return newErrKind(ErrInvalidGenesisStateTransition)
		}
		return nil
	}

	// If we have an asset split, then we need to validate the state
	// transition by verifying the split commitment proof before verify the
	// final asset witness.
	if vm.splitAsset != nil {
		if err := vm.validateSplit(); err != nil {
			return err
		}
	}

	// Now that we know we're not dealing with a genesis state transition,
	// we'll map our set of asset inputs and outputs to the 1-input 1-output
	// virtual transaction.
	virtualTx, inputTree, err := taroscript.VirtualTx(
		vm.newAsset, vm.prevAssets,
	)
	if err != nil {
		if errors.Is(err, taroscript.ErrInputMismatch) {
			return ErrInputMismatch
		}
		if errors.Is(err, taroscript.ErrNoInputs) {
			return ErrNoInputs
		}
		return err
	}

	// Enforce that assets aren't being inflated.
	treeRoot, err := inputTree.Root(context.Background())
	if err != nil {
		return err
	}
	if treeRoot.NodeSum() != uint64(virtualTx.TxOut[0].Value) {
		return newErrKind(ErrAmountMismatch)
	}

	// Finally, we'll validate the asset witness.
	return vm.validateStateTransition(virtualTx)
}
