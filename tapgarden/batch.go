package tapgarden

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
)

// AssetMetas maps the serialized script key of an asset to the meta reveal for
// that asset, if it has one.
type AssetMetas map[asset.SerializedKey]*proof.MetaReveal

// MintingBatch packages the pending state of a batch, this includes the batch
// key, the state of the batch and the assets to be created.
//
// TODO(roasbeef): split this up after all? into two struts? Either[A, B]?
type MintingBatch struct {
	// CreationTime is the time that this batch was created.
	CreationTime time.Time

	// HeightHint is the recorded block height at time of creating this
	// batch. We use it to know where to start looking for the signed batch
	// transaction.
	HeightHint uint32

	// batchState is the state of the batch.
	batchState atomic.Uint32

	// BatchKey is the unique identifier for a batch.
	BatchKey keychain.KeyDescriptor

	// Seedlings is the set of seedlings for this batch. This maps an
	// asset's name to the seedling itself.
	//
	// NOTE: This field is only set if the state is BatchStateFrozen or
	// BatchStatePending.
	Seedlings map[string]*Seedling

	// GenesisPacket is the funded genesis packet that may or may not be
	// fully signed. When broadcast, this will create all assets stored
	// within this batch.
	//
	// NOTE: This field is only set if the state is beyond
	// BatchStateCommitted.
	GenesisPacket *tapsend.FundedPsbt

	// RootAssetCommitment is the root Taproot Asset commitment for all the
	// assets contained in this batch.
	//
	// NOTE: This field is only set if the state is beyond
	// BatchStateCommitted.
	RootAssetCommitment *commitment.TapCommitment

	// AssetMetas maps the serialized script key of an asset to the meta
	// reveal for that asset, if it has one.
	AssetMetas AssetMetas

	// mintingPubKey is the top-level Taproot output key that will be used
	// to commit to the Taproot Asset commitment above.
	mintingPubKey *btcec.PublicKey

	// tapSibling is an optional root hash of a tapscript tree that will be
	// used with the taprootAssetScriptRoot to construct the mintingPubKey.
	tapSibling *chainhash.Hash

	// taprootAssetScriptRoot is the root hash of the Taproot Asset
	// commitment. If this is nil, then the mintingPubKey will be as well.
	taprootAssetScriptRoot []byte
}

// TODO(roasbeef): add batch validate method re unique names?

// AddSeedling adds a new seedling to the batch.
func (m *MintingBatch) addSeedling(s *Seedling) error {
	if _, ok := m.Seedlings[s.AssetName]; ok {
		return fmt.Errorf("asset with name %v already in batch",
			s.AssetName)
	}

	m.Seedlings[s.AssetName] = s
	return nil
}

// validateGroupAnchor checks if the group anchor for a seedling is valid.
// A valid anchor must already be part of the batch and have emission enabled.
func (m *MintingBatch) validateGroupAnchor(s *Seedling) error {
	anchor, ok := m.Seedlings[*s.GroupAnchor]

	if !ok {
		return fmt.Errorf("group anchor %v not present in batch",
			s.GroupAnchor)
	}
	if !anchor.EnableEmission {
		return fmt.Errorf("group anchor %v has emission disabled",
			*s.GroupAnchor)
	}

	return nil
}

// MintingOutputKey derives the output key that once mined, will commit to the
// Taproot asset root, thereby creating the set of included assets.
func (m *MintingBatch) MintingOutputKey(sibling *commitment.TapscriptPreimage) (
	*btcec.PublicKey, []byte, error) {

	if m.mintingPubKey != nil {
		return m.mintingPubKey, m.taprootAssetScriptRoot, nil
	}

	if m.RootAssetCommitment == nil {
		return nil, nil, fmt.Errorf("no asset commitment present")
	}

	var (
		siblingHash *chainhash.Hash
		err         error
	)

	if sibling != nil {
		siblingHash, err = sibling.TapHash()
		if err != nil {
			return nil, nil, err
		}
	}

	taprootAssetScriptRoot := m.RootAssetCommitment.TapscriptRoot(
		siblingHash,
	)

	m.taprootAssetScriptRoot = taprootAssetScriptRoot[:]
	m.mintingPubKey = txscript.ComputeTaprootOutputKey(
		m.BatchKey.PubKey, taprootAssetScriptRoot[:],
	)

	return m.mintingPubKey, m.taprootAssetScriptRoot, nil
}

// genesisScript returns the script that should be placed in the minting output
// within the genesis transaction.
func (m *MintingBatch) genesisScript(sibling *commitment.TapscriptPreimage) (
	[]byte, error) {

	mintingOutputKey, _, err := m.MintingOutputKey(sibling)
	if err != nil {
		return nil, err
	}

	return tapscript.PayToTaprootScript(mintingOutputKey)
}

// State returns the private state of the batch.
func (m *MintingBatch) State() BatchState {
	currentBatchState := m.batchState.Load()

	// Drop the error when converting the stored state to a BatchState, as
	// we verify the batch state before storing it.
	batchStateCopy, _ := NewBatchState(uint8(currentBatchState))
	return batchStateCopy
}

// UpdateState updates the state of a batch to a value that has been verified to
// be a valid batch state.
func (m *MintingBatch) UpdateState(state BatchState) {
	m.batchState.Store(uint32(state))
}

// TapSibling returns the optional tapscript sibling for the batch, which is a
// root hash of a tapscript tree.
func (m *MintingBatch) TapSibling() []byte {
	if m.tapSibling == nil {
		return nil
	}

	return m.tapSibling.CloneBytes()
}

// UpdateTapSibling updates the optional tapscript sibling for the batch.
func (m *MintingBatch) UpdateTapSibling(sibling *chainhash.Hash) {
	m.tapSibling = sibling
}
