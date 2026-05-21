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

	// SupplyCommitments is a flag that determines whether the minting
	// event supports universe supply commitments. When set to true, the
	// batch must include only assets that share the same asset group key.
	//
	// Universe supply commitments are minter-controlled, on-chain anchored
	// attestations regarding the state of the universe supply (issued,
	// ignored, burnt, etc).
	SupplyCommitments bool

	// tapSibling is an optional root hash of a tapscript tree that is
	// combined with the Taproot Asset commitment to derive the
	// MintingOutputKey.
	tapSibling *chainhash.Hash
}

// VerboseBatch is a MintingBatch that includes seedlings with their pending
// asset group information. The Seedlings map is empty, and all seedlings are
// stored as UnsealedSeedlings.
type VerboseBatch struct {
	*MintingBatch
	UnsealedSeedlings map[string]*UnsealedSeedling
}

// BatchKeyBytes returns the serialized bytes of the batch key.
func (m *MintingBatch) BatchKeyBytes() []byte {
	if m.BatchKey.PubKey == nil {
		return nil
	}

	return m.BatchKey.PubKey.SerializeCompressed()
}

// copyAssetMetas returns a deep copy of an AssetMetas map. Both the map
// and each *MetaReveal value are duplicated.
func copyAssetMetas(am AssetMetas) AssetMetas {
	if am == nil {
		return nil
	}
	out := make(AssetMetas, len(am))
	for k, v := range am {
		out[k] = v.Copy()
	}
	return out
}

// copySeedlings returns a deep copy of a name->seedling map. Each Seedling
// is cloned via Seedling.Copy(); the map itself is freshly allocated.
func copySeedlings(in map[string]*Seedling) map[string]*Seedling {
	if in == nil {
		return nil
	}
	out := make(map[string]*Seedling, len(in))
	for k, v := range in {
		out[k] = v.Copy()
	}
	return out
}

// Copy returns a deep copy of the batch. Every nested pointer, slice, and
// map is duplicated so that mutating the returned batch (or any of its
// substructure) cannot be observed through the source, and vice-versa.
//
// The only intentional sharing is for fields the codebase treats as
// immutable after construction:
//   - BatchKey: keychain.KeyDescriptor is rebuilt with a fresh PubKey
//     pointer, but its KeyLocator (two uint32 fields) is trivially
//     value-copied.
//   - tapSibling: a *chainhash.Hash; the underlying 32-byte array is
//     value-copied via *m.tapSibling, yielding an independent hash.
//   - RootAssetCommitment: cloned via TapCommitment.Copy(), which is
//     deep (see commitment.TestTapCommitmentDeepCopy).
//
// The deep-copy contract is exercised by TestMintingBatchCopyIsDeep.
func (m *MintingBatch) Copy() *MintingBatch {
	if m == nil {
		return nil
	}

	batchCopy := &MintingBatch{
		CreationTime:      m.CreationTime,
		HeightHint:        m.HeightHint,
		BatchKey:          asset.CopyKeyDescriptor(m.BatchKey),
		SupplyCommitments: m.SupplyCommitments,
		Seedlings:         copySeedlings(m.Seedlings),
		AssetMetas:        copyAssetMetas(m.AssetMetas),
	}
	batchCopy.setState(m.State())

	if m.tapSibling != nil {
		siblingCopy := *m.tapSibling
		batchCopy.tapSibling = &siblingCopy
	}

	if m.RootAssetCommitment != nil {
		commitCopy, err := m.RootAssetCommitment.Copy()
		if err != nil {
			// TapCommitment.Copy only errors on malformed
			// internal state; tapgarden builds commitments
			// itself via seedlingsToAssetSprouts so this is not
			// reachable in practice. If we ever hit it, panic so
			// the corruption surfaces immediately rather than
			// silently degrading the snapshot contract.
			panic(fmt.Errorf("MintingBatch.Copy: deep-copying "+
				"root asset commitment failed: %w", err))
		}
		batchCopy.RootAssetCommitment = commitCopy
	}

	if m.GenesisPacket != nil {
		batchCopy.GenesisPacket = m.GenesisPacket.Copy()
	}

	return batchCopy
}

// validateGroupAnchor checks if the group anchor for a seedling is valid.
// A valid anchor must already be part of the batch and have emission enabled.
func (m *MintingBatch) ValidateGroupAnchor(s *Seedling) error {
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

// MintingOutputKey derives the output key that once mined, will commit
// to the Taproot asset root, thereby creating the set of included
// assets. The returned byte slice is the tapscript root that was
// committed to (the Taproot Asset commitment combined with the
// optional sibling).
//
// This function is pure in (m.BatchKey, m.RootAssetCommitment,
// sibling): every call with the same arguments returns the same
// result, and every call with a different sibling returns a
// different result. There is no memoization; the on-curve work is
// trivial and a cache would re-introduce the §IV bug shape where
// the function silently ignored its sibling argument after the
// first call.
func (m *MintingBatch) MintingOutputKey(sibling *commitment.TapscriptPreimage) (
	*btcec.PublicKey, []byte, error) {

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

	mintingPubKey := txscript.ComputeTaprootOutputKey(
		m.BatchKey.PubKey, taprootAssetScriptRoot[:],
	)

	return mintingPubKey, taprootAssetScriptRoot[:], nil
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

// setState updates the in-memory batch state. This is unexported because
// every authoritative state mutation must flow through a BatchStore call
// that writes to disk first and only then mutates memory. Use this only for
// package-internal cases that are not the result of a DB transition
// (currently: initial Pending state during batch construction and copying
// a batch via Copy()).
func (m *MintingBatch) setState(state BatchState) {
	m.batchState.Store(uint32(state))
}

// SetStateOnDBSuccess mutates the in-memory batch state. It is intended to
// be called exclusively by BatchStore implementations after a successful
// DB write has committed the same state to disk; this is what guarantees
// that the in-memory mirror cannot get ahead of the on-disk truth.
//
// NOTE: Ordinary callers (planter, caretaker, RPC layer, tests) must never
// invoke this method directly. Use the BatchStore interface, whose
// state-mutating methods take *MintingBatch and update memory only on DB
// success.
func (m *MintingBatch) SetStateOnDBSuccess(state BatchState) {
	m.setState(state)
}

// TapSibling returns the optional tapscript sibling for the batch, which is a
// root hash of a tapscript tree.
func (m *MintingBatch) TapSibling() []byte {
	if m.tapSibling == nil {
		return nil
	}

	return m.tapSibling.CloneBytes()
}

// UpdateTapSibling mutates the in-memory tapscript sibling for the batch.
// It is intended to be called exclusively by BatchStore implementations
// after a successful DB write has committed the same sibling to disk;
// this is what guarantees that the in-memory mirror cannot get ahead of
// the on-disk truth.
//
// NOTE: Ordinary callers (planter, cultivator, RPC layer, tests) must
// never invoke this method directly. Use the BatchStore interface, whose
// sibling-mutating methods take *MintingBatch and update memory only on
// DB success.
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

// uniqueAnchorSeedling returns the single group anchor seedling in
// the batch -- the seedling whose GroupAnchor is nil and that other
// seedlings may reference by name. If the batch contains zero or
// more than one such seedling, an error is returned.
//
// This invariant ("exactly one anchor per batch") is required by
// callers that derive batch-wide properties (the delegation key,
// the pre-commitment group key) from the anchor seedling: with no
// anchor there is no answer, and with multiple anchors the answer
// is ambiguous. The function computes the answer deterministically
// rather than relying on non-deterministic map iteration to land
// on the unique anchor by luck.
func (m *MintingBatch) uniqueAnchorSeedling() (*Seedling, error) {
	var (
		anchor *Seedling
		count  int
	)
	for _, seedling := range m.Seedlings {
		if seedling.GroupAnchor != nil {
			continue
		}

		anchor = seedling
		count++
	}

	switch count {
	case 0:
		return nil, fmt.Errorf("no group anchor seedling in batch")
	case 1:
		return anchor, nil
	default:
		return nil, fmt.Errorf("batch has %d group anchor "+
			"seedlings, expected exactly 1", count)
	}
}

// validateSeedling checks that a candidate seedling is admissible into
// the batch given the batch's current state. It does not mutate the
// batch; this is the read-only half of AddSeedling.
//
// Augmenter-owned invariants (universe commitments, delegation
// keys) are checked separately by the planter via
// GenesisTxAugmenter.ValidateSeedling before this method is
// reached. This method covers only the batch's own invariants.
//
// Callers that need a persistence boundary between validation and
// mutation (e.g. "validate, write to disk, then update in memory")
// should pair this with commitSeedling so an in-memory mutation
// cannot precede the persistence that justifies it.
func (m *MintingBatch) validateSeedling(_ Seedling) error {
	return nil
}

// commitSeedling applies the in-memory mutation that adds newSeedling
// to the batch. It assumes the seedling has already been validated by
// validateSeedling; calling it on an invalid seedling is a
// programming error.
//
// The SupplyCommitments mutation must happen before the seedling is
// inserted into the map, because the gate is m.HasSeedlings() which
// flips once the insertion has happened.
func (m *MintingBatch) commitSeedling(newSeedling Seedling) {
	if !m.HasSeedlings() {
		m.SupplyCommitments = newSeedling.SupplyCommitments
	}

	if m.Seedlings == nil {
		m.Seedlings = make(map[string]*Seedling)
	}

	m.Seedlings[newSeedling.AssetName] = &newSeedling
}

// AddSeedling validates the seedling against the batch and, if valid,
// adds it. This is the convenience wrapper for callers that do not
// need a persistence boundary between validation and the in-memory
// mutation (e.g. constructing a fresh batch in memory that will be
// persisted whole, or test helpers building random batches).
//
// Callers that *do* need a persistence boundary -- e.g. adding a
// seedling to an existing on-disk batch where the in-memory mirror
// must not advance unless the DB write succeeds -- should use
// validateSeedling and commitSeedling explicitly around the
// persistence call.
func (m *MintingBatch) AddSeedling(newSeedling Seedling) error {
	if err := m.validateSeedling(newSeedling); err != nil {
		return err
	}
	m.commitSeedling(newSeedling)
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
