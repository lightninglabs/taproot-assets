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
	GenesisPacket *FundedMintAnchorPsbt

	// RootAssetCommitment is the root Taproot Asset commitment for all the
	// assets contained in this batch.
	//
	// NOTE: This field is only set if the state is beyond
	// BatchStateCommitted.
	RootAssetCommitment *commitment.TapCommitment

	// AssetMetas maps the serialized script key of an asset to the meta
	// reveal for that asset, if it has one.
	AssetMetas AssetMetas

	// UniverseCommitments is a flag that determines whether the minting
	// event supports universe commitments. When set to true, the batch must
	// include only assets that share the same asset group key.
	//
	// Universe commitments are minter-controlled, on-chain anchored
	// attestations regarding the state of the universe.
	UniverseCommitments bool

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
	if s.GroupAnchor == nil {
		return fmt.Errorf("group anchor unspecified")
	}

	anchor, ok := m.Seedlings[*s.GroupAnchor]

	if anchor == nil || !ok {
		return fmt.Errorf("group anchor %v not present in batch",
			s.GroupAnchor)
	}
	if !anchor.EnableEmission {
		return fmt.Errorf("group anchor %v isn't starting a new group",
			*s.GroupAnchor)
	}

	return validateAnchorMeta(s.Meta, anchor.Meta)
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

	return txscript.PayToTaprootScript(mintingOutputKey)
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

// validateDelegationKey ensures that the delegation key is valid for a seedling
// being considered for inclusion in the batch.
func (m *MintingBatch) validateDelegationKey(newSeedling Seedling) error {
	// If the universe commitment flag is disabled, then the delegation key
	// should not be set.
	if !newSeedling.UniverseCommitments {
		if newSeedling.DelegationKey.IsSome() {
			return fmt.Errorf("delegation key must not be set " +
				"for seedling without universe commitments")
		}

		// If the universe commitment flag is disabled and the
		// delegation key is correctly unset, no further checks are
		// needed.
		return nil
	}

	// At this point, we know that the universe commitment flag is enabled
	// for the seedling. Therefore, the delegation key must be set.
	delegationKey, err := newSeedling.DelegationKey.UnwrapOrErr(
		fmt.Errorf("delegation key must be set for seedling with " +
			"universe commitments"),
	)
	if err != nil {
		return err
	}

	// validateKeyDesc is a helper function to validate a key descriptor.
	validateKeyDesc := func(keyDesc keychain.KeyDescriptor) error {
		if keyDesc.PubKey == nil {
			return fmt.Errorf("pubkey is nil")
		}

		if !keyDesc.PubKey.IsOnCurve() {
			return fmt.Errorf("pubkey is not on curve")
		}

		return nil
	}

	// Ensure that the delegation key is valid.
	err = validateKeyDesc(delegationKey)
	if err != nil {
		return fmt.Errorf("candidate seedling delegation "+
			"key validation failed: %w", err)
	}

	// Ensure that the delegation key is the same for all seedlings in the
	// batch.
	for _, seedling := range m.Seedlings {
		// Ensure that the delegation key matches that of the candidate
		// seedling.
		keyDesc, err := seedling.DelegationKey.UnwrapOrErr(
			fmt.Errorf("delegation key must be set for seedling " +
				"with universe commitments"),
		)
		if err != nil {
			return err
		}

		if !delegationKey.PubKey.IsEqual(keyDesc.PubKey) {
			return fmt.Errorf("delegation key mismatch")
		}
	}

	return nil
}

// validateUniCommitment verifies that the seedling adheres to the universe
// commitment feature restrictions in the context of the current batch state.
func (m *MintingBatch) validateUniCommitment(newSeedling Seedling) error {
	// If the batch is empty, the first seedling will set the universe
	// commitment flag for the batch.
	if !m.HasSeedlings() {
		// If there are no seedlings in the batch, and the first
		// (subject) seedling doesn't enable universe commitment, we can
		// accept it without further checks.
		if !newSeedling.UniverseCommitments {
			return nil
		}

		// At this point, the given seedling is the first to be added to
		// the batch, and it has the universe commitment flag enabled.
		//
		// The minting batch funding step records the genesis
		// transaction in the database. Additionally, the uni-commitment
		// feature requires the change output to be locked, ensuring it
		// can only be spent by `tapd`. Therefore, to leverage the
		// uni-commitment feature, the batch must be populated with
		// seedlings, with the uni-commitment flag correctly set before
		// any funding attempt is made.
		//
		// As such, when adding the first seedling with uni-commitment
		// support to the batch, it is essential to verify that the
		// batch has not yet been funded.
		if m.IsFunded() {
			return fmt.Errorf("attempting to add first seedling " +
				"with universe commitment flag enabled to " +
				"funded batch")
		}

		// At this point, we know the batch is empty, and the candidate
		// seedling will be the first to be added. Consequently, if the
		// seedling has the universe commitment flag enabled, it must
		// specify a re-issuable asset group key.
		if !newSeedling.EnableEmission {
			return fmt.Errorf("the 'new grouped asset' flag must " +
				"be enabled for the first asset in a batch " +
				"with the universe commitment flag enabled")
		}

		if !newSeedling.HasGroupKey() {
			return fmt.Errorf("a group key must be specified " +
				"for the first seedling in the batch when " +
				"the universe commitment flag is enabled")
		}

		// No further checks are required for the first seedling in the
		// batch.
		return nil
	}

	// At this stage, we know that the batch contains seedlings.
	// Furthermore, the universe commitment flag for the batch should have
	// been correctly updated when the existing seedlings were added.
	//
	// Therefore, when evaluating this new candidate seedling for inclusion
	// in the batch, we must ensure that its universe commitment flag state
	// matches the flag state of the batch.
	if m.UniverseCommitments != newSeedling.UniverseCommitments {
		return fmt.Errorf("seedling universe commitment flag does " +
			"not match batch")
	}

	// If the universe commitment flag is disabled for both the seedling and
	// the batch, no additional checks are required.
	if !m.UniverseCommitments && !newSeedling.UniverseCommitments {
		return nil
	}

	// Logically, by this point, the following must be true:
	// * the universe commitment flag is enabled for both the seedling and
	//   the batch
	// * the batch contains at least one seedling.
	//
	// For clarity, we will assert these conditions now.
	if !m.UniverseCommitments || !newSeedling.UniverseCommitments ||
		!m.HasSeedlings() {

		return fmt.Errorf("unexpected code path reached")
	}

	// At this point, the candidate seedling (with uni commitments enabled)
	// must have a group anchor that is already part of the batch. The group
	// anchor must have been added to the batch before the candidate
	// seedling.
	if newSeedling.GroupAnchor == nil {
		return fmt.Errorf("non-empty batch with uni commit enabled " +
			"but candidate seedling does not have group anchor " +
			"specified")
	}

	// For clarity, we will assert that the candidate seedling refers to a
	// group anchor that is already part of the batch.
	if _, ok := m.Seedlings[*newSeedling.GroupAnchor]; !ok {
		return fmt.Errorf("group anchor for candidate seedling not " +
			"present in batch")
	}

	// Next, we will also assert that there is only one group anchor in the
	// batch.
	var anchorCount int
	for _, seedling := range m.Seedlings {
		if seedling.GroupAnchor != nil {
			anchorCount++
		}
	}
	if anchorCount > 1 {
		return fmt.Errorf("multiple group anchors present in batch " +
			"with universe commitments enabled")
	}

	// Ensure that the group anchor for the candidate seedling is already
	// present in the batch.
	err := m.validateGroupAnchor(&newSeedling)
	if err != nil {
		return fmt.Errorf("group anchor validation failed: %w", err)
	}

	return nil
}

// AddSeedling adds a new seedling to the batch.
func (m *MintingBatch) AddSeedling(newSeedling Seedling) error {
	// Ensure that the seedling adheres to the universe commitment feature
	// restrictions in relation to the current batch state.
	err := m.validateUniCommitment(newSeedling)
	if err != nil {
		return fmt.Errorf("seedling does not comply with universe "+
			"commitment feature: %w", err)
	}

	// At this stage, the seedling has been confirmed to comply with the
	// universe commitment feature restrictions. If this is the first
	// seedling being added to the batch, the batch universe commitment flag
	// can be set to match the seedling's flag state.
	if !m.HasSeedlings() {
		m.UniverseCommitments = newSeedling.UniverseCommitments
	}

	// Ensure that the delegation key is valid for the seedling being
	// considered for inclusion in the batch.
	err = m.validateDelegationKey(newSeedling)
	if err != nil {
		return fmt.Errorf("delegation key validation failed: %w", err)
	}

	// Add the seedling to the batch.
	if m.Seedlings == nil {
		m.Seedlings = make(map[string]*Seedling)
	}

	m.Seedlings[newSeedling.AssetName] = &newSeedling

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
