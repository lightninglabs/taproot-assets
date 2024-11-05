package tapgarden

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
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

	// EnableUniAnnounce is a flag that indicates whether the minting
	// event should support universe announcements. If set to true,
	// the batch must include only assets that share the same asset group
	// key, which must also be set.
	EnableUniAnnounce bool

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

// VerboseBatch is a MintingBatch that includes seedlings with their pending
// asset group information. The Seedlings map is empty, and all seedlings are
// stored as UnsealedSeedlings.
type VerboseBatch struct {
	*MintingBatch
	UnsealedSeedlings map[string]*UnsealedSeedling
}

// Copy creates a deep copy of the batch.
func (m *MintingBatch) Copy() *MintingBatch {
	batchCopy := &MintingBatch{
		CreationTime: m.CreationTime,
		HeightHint:   m.HeightHint,
		// The following values are expected to not change once they are
		// set, so a shallow copy is sufficient.
		BatchKey:            m.BatchKey,
		RootAssetCommitment: m.RootAssetCommitment,
		mintingPubKey:       m.mintingPubKey,
		tapSibling:          m.tapSibling,
	}
	batchCopy.UpdateState(m.State())

	if m.Seedlings != nil {
		batchCopy.Seedlings = make(
			map[string]*Seedling, len(m.Seedlings),
		)
		for k, v := range m.Seedlings {
			batchCopy.Seedlings[k] = v
		}
	}

	if m.GenesisPacket != nil {
		batchCopy.GenesisPacket = m.GenesisPacket.Copy()
	}

	if m.AssetMetas != nil {
		batchCopy.AssetMetas = make(AssetMetas, len(m.AssetMetas))
		for k, v := range m.AssetMetas {
			batchCopy.AssetMetas[k] = v
		}
	}

	if m.taprootAssetScriptRoot != nil {
		batchCopy.taprootAssetScriptRoot = fn.CopySlice(
			m.taprootAssetScriptRoot,
		)
	}

	return batchCopy
}

// validateGroupAnchor checks if the group anchor for a seedling is valid.
// A valid anchor must already be part of the batch and have emission enabled.
func (m *MintingBatch) validateGroupAnchor(s *Seedling) error {
	anchor, ok := m.Seedlings[*s.GroupAnchor]

	if anchor == nil || !ok {
		return fmt.Errorf("group anchor %v not present in batch",
			s.GroupAnchor)
	}
	if !anchor.EnableEmission {
		return fmt.Errorf("group anchor %v has emission disabled",
			*s.GroupAnchor)
	}

	// The decimal display of the seedling must match that of the group
	// anchor. We already validated the seedling metadata, so we don't care
	// if the value is explicit or if the metadata is JSON, but we must
	// compute the same value for both assets.
	_, seedlingDecDisplay, _ := s.Meta.GetDecDisplay()
	_, anchorDecDisplay, _ := anchor.Meta.GetDecDisplay()
	if seedlingDecDisplay != anchorDecDisplay {
		return fmt.Errorf("seedling decimal display does not match "+
			"group anchor: %d, %d", seedlingDecDisplay,
			anchorDecDisplay)
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

// VerifyOutputScript recomputes a batch genesis output script from a batch key,
// tapscript sibling, and set of assets. It checks multiple tap commitment
// versions to account for legacy batches.
func VerifyOutputScript(batchKey *btcec.PublicKey, tapSibling *chainhash.Hash,
	genesisScript []byte, assets []*asset.Asset) (*commitment.TapCommitment,
	error) {

	// Construct a TapCommitment from the batch sprouts, and verify that the
	// version is correct by recomputing the genesis output script.
	buildTrimmedCommitment := func(vers *commitment.TapCommitmentVersion,
		assets ...*asset.Asset) (*commitment.TapCommitment, error) {

		tapCommitment, err := commitment.FromAssets(vers, assets...)
		if err != nil {
			return nil, err
		}

		return commitment.TrimSplitWitnesses(vers, tapCommitment)
	}

	tapCommitment, err := buildTrimmedCommitment(
		fn.Ptr(commitment.TapCommitmentV2), assets...,
	)
	if err != nil {
		return nil, err
	}

	computedScript, err := tapscript.PayToAddrScript(
		*batchKey, tapSibling, *tapCommitment,
	)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(genesisScript, computedScript) {
		// The batch may have used a non-V2 commitment; check against a
		// non-V2 commitment.
		tapCommitment, err = buildTrimmedCommitment(nil, assets...)
		if err != nil {
			return nil, err
		}

		computedScriptV0, err := tapscript.PayToAddrScript(
			*batchKey, tapSibling, *tapCommitment,
		)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(genesisScript, computedScriptV0) {
			return nil, fmt.Errorf("invalid commitment to asset "+
				"sprouts: batch %x",
				batchKey.SerializeCompressed(),
			)
		}
	}

	return tapCommitment, nil
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

// IsFunded checks if the batch already has a funded genesis packet.
func (m *MintingBatch) IsFunded() bool {
	return m.GenesisPacket != nil
}

// HasSeedlings checks if the batch has any seedlings. A batch with no seedlings
// cannot be sealed nor finalized.
func (m *MintingBatch) HasSeedlings() bool {
	return len(m.Seedlings) != 0
}

// ValidateSeedling checks if a seedling is valid for the batch.
func (m *MintingBatch) ValidateSeedling(newSeedling Seedling) error {
	// Ensure that the seedling and batch agree on the enabled universe
	// announcements.
	if m.EnableUniAnnounce != newSeedling.EnableUniAnnounce {
		return fmt.Errorf("batch and seedling do not agree on " +
			"enabled universe announcements")
	}

	// If the seedling supports universe announcements, it must have a group
	// anchor or the same group key as all the other seedlings in the batch.
	if newSeedling.EnableUniAnnounce {
		if newSeedling.GroupAnchor == nil &&
			newSeedling.GroupInfo == nil {

			return fmt.Errorf("universe announcement enabled for " +
				"seedling but group info/anchor is absent")
		}

		if newSeedling.GroupInfo != nil {
			// TODO(ffranr): Add check to ensure that this new
			//  seedling has the same group key as the other
			//  seedlings in the batch.
		}
	}

	return nil
}

// ToMintingBatch creates a new MintingBatch from a VerboseBatch.
func (v *VerboseBatch) ToMintingBatch() *MintingBatch {
	newBatch := v.MintingBatch.Copy()
	if v.UnsealedSeedlings != nil {
		newBatch.Seedlings = make(
			map[string]*Seedling, len(v.UnsealedSeedlings),
		)
		for k, v := range v.UnsealedSeedlings {
			newBatch.Seedlings[k] = v.Seedling
		}
	}

	return newBatch
}
