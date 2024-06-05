package taprootassets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
)

const (
	// medianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	medianTimeBlocks = 11
)

var (
	// errTxNotfound is an error that is returned when a transaction
	// couldn't be found in the proof file.
	errTxNotFound = fmt.Errorf("transaction not found in proof file")
)

// ValidatorV0 is an implementation of the tapscript.TxValidator interface
// that supports Taproot Asset script version 0.
type ValidatorV0 struct{}

// Execute creates and runs an instance of the Taproot Asset script V0 VM.
func (v *ValidatorV0) Execute(newAsset *asset.Asset,
	splitAssets []*commitment.SplitAsset, prevAssets commitment.InputSet,
	chainLookup asset.ChainLookup) error {

	verifyOpts := vm.WithChainLookup(chainLookup)
	engine, err := vm.New(newAsset, splitAssets, prevAssets, verifyOpts)
	if err != nil {
		return err
	}

	if err = engine.Execute(); err != nil {
		return err
	}

	return nil
}

// A compile time assertion to ensure ValidatorV0 meets the
// tapscript.TxValidator interface.
var _ tapscript.TxValidator = (*ValidatorV0)(nil)

// WitnessValidatorV0 is an implementation of the tapscript.WitnessValidator
// interface that supports Taproot Asset script version 0.
type WitnessValidatorV0 struct{}

// ValidateWitnesses validates the created witnesses of an asset transfer.
func (v *WitnessValidatorV0) ValidateWitnesses(newAsset *asset.Asset,
	splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet) error {

	return vm.ValidateWitnesses(newAsset, splitAssets, prevAssets)
}

// A compile time assertion to ensure WitnessValidatorV0 meets the
// tapscript.WitnessValidator interface.
var _ tapscript.WitnessValidator = (*WitnessValidatorV0)(nil)

// ProofChainLookup is an implementation of the asset.ChainLookup interface
// that uses a proof file to look up block height information of previous inputs
// while validating proofs.
type ProofChainLookup struct {
	chainBridge tapgarden.ChainBridge

	assetStore *tapdb.AssetStore

	proofFile *proof.File
}

// NewProofChainLookup creates a new ProofChainLookup instance.
func NewProofChainLookup(chainBridge tapgarden.ChainBridge,
	assetStore *tapdb.AssetStore, proofFile *proof.File) *ProofChainLookup {

	return &ProofChainLookup{
		chainBridge: chainBridge,
		assetStore:  assetStore,
		proofFile:   proofFile,
	}
}

// CurrentHeight returns the current height of the main chain.
func (l *ProofChainLookup) CurrentHeight(ctx context.Context) (uint32, error) {
	return l.chainBridge.CurrentHeight(ctx)
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (l *ProofChainLookup) TxBlockHeight(ctx context.Context,
	txid chainhash.Hash) (uint32, error) {

	// If we don't have a proof available as context, we can only look up
	// the transaction in the database. Querying it on-chain would cause a
	// re-scan which might be very time costly for light clients.
	if l.proofFile == nil || l.proofFile.NumProofs() == 0 {
		return l.assetStore.TxHeight(ctx, txid)
	}

	// Let's walk back the proof chain and try to find the transaction.
	height, err := findTxHeightInProofFile(l.proofFile, txid)
	switch {
	case errors.Is(err, errTxNotFound):
		// Our last ditch attempt is to look up the transaction in the
		// database. But we might not have it there if the proof is for
		// a transaction that happened before the asset reached our
		// node.
		return l.assetStore.TxHeight(ctx, txid)

	case err != nil:
		return 0, fmt.Errorf("error fetching proof from context file: "+
			"%w", err)
	}

	return height, nil
}

// findTxHeightInProofFile is a helper function that recursively searches for
// the block height of a transaction in a proof file.
func findTxHeightInProofFile(f *proof.File, txid chainhash.Hash) (uint32,
	error) {

	for i := f.NumProofs() - 1; i >= 0; i-- {
		p, err := f.ProofAt(uint32(i))
		if err != nil {
			return 0, fmt.Errorf("error fetching proof from "+
				"file: %w", err)
		}

		if p.AnchorTx.TxHash() == txid {
			return p.BlockHeight, nil
		}

		for idx := range p.AdditionalInputs {
			additionalInput := p.AdditionalInputs[idx]
			height, err := findTxHeightInProofFile(
				&additionalInput, txid,
			)
			switch {
			case errors.Is(err, errTxNotFound):
				continue

			case err != nil:
				return 0, fmt.Errorf("error fetching proof "+
					"from additional input file: %w", err)
			}

			return height, nil
		}
	}

	// If we arrive here, we couldn't find the transaction in the proof
	// file.
	return 0, errTxNotFound
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 11 blocks.
func (l *ProofChainLookup) MeanBlockTimestamp(ctx context.Context,
	blockHeight uint32) (time.Time, error) {

	// Create a slice of the previous few block timestamps used to calculate
	// the median per the number defined by the constant medianTimeBlocks.
	//
	// NOTE: The code below is an adaptation of the code in btcd's
	// blockchain.CalcPastMedianTime function.
	timestamps := make([]int64, medianTimeBlocks)
	numNodes := 0
	for i := uint32(0); i < medianTimeBlocks; i++ {
		// If we have reached the beginning of the blockchain, we can't
		// go back any further. This also prevents an underflow in the
		// next step.
		if i > blockHeight {
			break
		}

		unixTs := l.chainBridge.GetBlockTimestamp(ctx, blockHeight-i)
		if unixTs == 0 {
			return time.Time{}, fmt.Errorf("couldn't find "+
				"timestamp for block height %d", blockHeight)
		}

		timestamps[i] = unixTs
		numNodes++
	}

	// Prune the slice to the actual number of available timestamps which
	// will be fewer than desired near the beginning of the blockchain and
	// sort them.
	timestamps = timestamps[:numNodes]
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// NOTE: The consensus rules incorrectly calculate the median for even
	// numbers of blocks.  A true median averages the middle two elements
	// for a set with an even number of elements in it.   Since the constant
	// for the previous number of blocks to be used is odd, this is only an
	// issue for a few blocks near the beginning of the chain.  I suspect
	// this is an optimization even though the result is slightly wrong for
	// a few of the first blocks since after the first few blocks, there
	// will always be an odd number of blocks in the set per the constant.
	//
	// This code follows suit to ensure the same rules are used, however, be
	// aware that should the medianTimeBlocks constant ever be changed to an
	// even number, this code will be wrong.
	medianTimestamp := timestamps[numNodes/2]
	return time.Unix(medianTimestamp, 0), nil
}

var _ asset.ChainLookup = (*ProofChainLookup)(nil)
