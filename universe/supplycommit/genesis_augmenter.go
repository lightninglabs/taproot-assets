package supplycommit

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/keychain"
)

// SupplyPreCommitReader is the subset of the tapdb supply-pre-commit
// store that the augmenter consumes. It is defined here (not
// imported from tapdb) so supplycommit can express its dependency
// on the lookup without taking on tapdb as a dependency.
type SupplyPreCommitReader interface {
	// FetchDelegationKey returns the delegation key associated
	// with the given asset-group public key, when known.
	FetchDelegationKey(ctx context.Context,
		groupKey btcec.PublicKey) (
		fn.Option[keychain.KeyDescriptor], error)
}

// MintEventEmitter is the subset of supplycommit.Manager that the
// augmenter needs at batch-confirmation time. Defining it as an
// interface lets tests substitute the manager without instantiating
// one.
type MintEventEmitter interface {
	// SendMintEvent forwards a mint event to the appropriate
	// supply-commitment state machine.
	SendMintEvent(ctx context.Context, assetSpec asset.Specifier,
		leafKey universe.UniqueLeafKey, issuanceProof universe.Leaf,
		mintBlockHeight uint32) error
}

// GenesisAugmenterCfg bundles the dependencies that the augmenter
// needs at minting time. All fields are required; passing a
// fully-constructed GenesisAugmenter through to tapgarden's
// GardenKit lets the planter remain free of any supply-commit
// knowledge.
type GenesisAugmenterCfg struct {
	// PreCommitStore is consulted during PrepareSeedling when
	// looking up the delegation key for an existing asset
	// group.
	PreCommitStore SupplyPreCommitReader

	// KeyRing derives a new delegation key when the planter is
	// minting a fresh group with the supply-commit flag set.
	KeyRing tapnode.KeyRing

	// DelegationKeyChecker decides, at batch-confirmation time,
	// which newly-minted assets the local node owns the
	// delegation key for. Only those become mint events.
	DelegationKeyChecker address.DelegationKeyChecker

	// MintEvents forwards mint events to the supply-commit
	// state machine after batch confirmation.
	MintEvents MintEventEmitter

	// ChainParams supplies the BIP32 coin type used when
	// stamping derivation metadata onto the pre-commitment
	// output's PSBT entry.
	ChainParams address.ChainParams
}

// GenesisAugmenter implements tapgarden.GenesisTxAugmenter for
// the supply-commitment substance. It contributes the
// pre-commitment output to the genesis transaction, persists
// the supply-pre-commit row through tapgarden's binding API,
// and emits mint events once the batch confirms.
type GenesisAugmenter struct {
	cfg GenesisAugmenterCfg
}

// NewGenesisAugmenter returns a new augmenter wired with the
// supplied dependencies.
func NewGenesisAugmenter(cfg GenesisAugmenterCfg) *GenesisAugmenter {
	return &GenesisAugmenter{cfg: cfg}
}

// PrepareSeedling finalizes the seedling's delegation key. If the
// seedling does not enable supply commitments, this is a no-op.
// Otherwise the augmenter:
//
//   - reuses the delegation key from the batch's group-anchor
//     seedling when one is referenced;
//   - reuses the delegation key already persisted on disk when an
//     existing group key is being reissued into;
//   - derives a fresh key from the key ring when a brand-new
//     group is being minted.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.PrepareSeedling.
func (a *GenesisAugmenter) PrepareSeedling(ctx context.Context,
	batch *tapgarden.MintingBatch, req *tapgarden.Seedling) error {

	if !req.SupplyCommitments {
		return nil
	}

	if req.DelegationKey.IsSome() {
		return nil
	}

	// Reuse the delegation key from a referenced group-anchor
	// seedling in the same batch.
	if req.GroupAnchor != nil {
		if batch == nil {
			return fmt.Errorf("group anchor seedling " +
				"referenced but batch is nil")
		}

		anchorName := *req.GroupAnchor
		anchor, ok := batch.Seedlings[anchorName]
		if !ok || anchor == nil {
			return fmt.Errorf("group anchor seedling not "+
				"present in batch (anchor_seedling_name=%s)",
				anchorName)
		}

		if anchor.DelegationKey.IsNone() {
			return fmt.Errorf("group anchor seedling has no "+
				"delegation key (anchor_seedling_name=%s)",
				anchorName)
		}

		req.DelegationKey = anchor.DelegationKey
		return nil
	}

	// Reuse the delegation key previously persisted on disk for
	// an existing group being reissued into.
	if req.GroupInfo != nil && req.GroupInfo.GroupKey != nil {
		dKey, err := a.cfg.PreCommitStore.FetchDelegationKey(
			ctx, req.GroupInfo.GroupKey.GroupPubKey,
		)
		if err != nil {
			return fmt.Errorf("unable to fetch delegation key "+
				"for group key: %w", err)
		}

		if dKey.IsSome() {
			req.DelegationKey = dKey
			return nil
		}
	}

	// Derive a fresh delegation key for a brand-new group.
	if req.EnableEmission && req.GroupAnchor == nil {
		newKey, err := a.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to derive "+
				"pre-commitment output key: %w", err)
		}

		req.DelegationKey = fn.Some(newKey)
		return nil
	}

	return fmt.Errorf("failed to finalize delegation key for "+
		"seedling %s", req.AssetName)
}

// ValidateSeedling enforces the supply-commit invariants on a
// candidate seedling. The batch is either entirely on the
// supply-commit path or entirely off it; the first seedling
// sets the flag and subsequent seedlings must match.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.ValidateSeedling.
func (a *GenesisAugmenter) ValidateSeedling(batch *tapgarden.MintingBatch,
	req tapgarden.Seedling) error {

	if err := a.validateUniCommitment(batch, req); err != nil {
		return err
	}

	return a.validateDelegationKey(batch, req)
}

// validateUniCommitment is the augmenter half of the universe-
// commitment intake gate. It is moved verbatim from the planter
// (formerly MintingBatch.validateUniCommitment) so the
// invariants it captures remain unchanged.
func (a *GenesisAugmenter) validateUniCommitment(batch *tapgarden.MintingBatch,
	req tapgarden.Seedling) error {

	// First-seedling-into-empty-batch path: the seedling sets
	// the batch's SupplyCommitments flag.
	if !batch.HasSeedlings() {
		if !req.SupplyCommitments {
			return nil
		}

		// The minting batch funding step records the genesis
		// transaction in the database. Additionally, the
		// uni-commitment feature requires the change output to
		// be locked, ensuring it can only be spent by tapd.
		// Therefore, to leverage the uni-commitment feature,
		// the batch must be populated with seedlings, with the
		// uni-commitment flag correctly set before any funding
		// attempt is made.
		if batch.IsFunded() {
			return fmt.Errorf("attempting to add first " +
				"seedling with universe commitment flag " +
				"enabled to funded batch")
		}

		// The first uni-committed seedling must either create
		// a new asset group or issue into an existing one.
		if !req.EnableEmission && !req.HasGroupKey() {
			return fmt.Errorf("universe commitment " +
				"enabled: seedling must either create a " +
				"new asset group or issue into an " +
				"existing one")
		}

		return nil
	}

	// Subsequent-seedling path: must match the batch's flag.
	if batch.SupplyCommitments != req.SupplyCommitments {
		return fmt.Errorf("seedling universe commitment flag " +
			"does not match batch")
	}

	if !batch.SupplyCommitments && !req.SupplyCommitments {
		return nil
	}

	// At this point both the seedling and the batch have uni
	// commitments enabled. The candidate must reference a
	// group-anchor seedling that is already part of the batch.
	if req.GroupAnchor == nil {
		return fmt.Errorf("non-empty batch with uni commit " +
			"enabled but candidate seedling does not have " +
			"group anchor specified")
	}

	if _, ok := batch.Seedlings[*req.GroupAnchor]; !ok {
		return fmt.Errorf("group anchor for candidate seedling " +
			"not present in batch")
	}

	// Assert single-group-anchor invariant. The original
	// invariant (preserved verbatim) counts seedlings that
	// reference an anchor; multiple referencers across distinct
	// anchors would violate uniqueness.
	var anchorCount int
	for _, s := range batch.Seedlings {
		if s.GroupAnchor != nil {
			anchorCount++
		}
	}
	if anchorCount > 1 {
		return fmt.Errorf("multiple group anchors present in " +
			"batch with universe commitments enabled")
	}

	// Run the batch's own group-anchor compatibility check
	// (anchor exists, has EnableEmission, meta is compatible).
	return batch.ValidateGroupAnchor(&req)
}

// validateDelegationKey is the augmenter half of the delegation-
// key intake gate. It is moved verbatim from the planter
// (formerly MintingBatch.validateDelegationKey).
func (a *GenesisAugmenter) validateDelegationKey(batch *tapgarden.MintingBatch,
	req tapgarden.Seedling) error {

	if !req.SupplyCommitments {
		if req.DelegationKey.IsSome() {
			return fmt.Errorf("delegation key must not be " +
				"set for seedling without universe " +
				"commitments")
		}
		return nil
	}

	delegationKey, err := req.DelegationKey.UnwrapOrErr(
		fmt.Errorf("delegation key must be set for seedling " +
			"with universe commitments"),
	)
	if err != nil {
		return err
	}

	if delegationKey.PubKey == nil {
		return fmt.Errorf("candidate seedling delegation key " +
			"validation failed: pubkey is nil")
	}
	if !delegationKey.PubKey.IsOnCurve() {
		return fmt.Errorf("candidate seedling delegation key " +
			"validation failed: pubkey is not on curve")
	}

	// All seedlings in the batch must share the same
	// delegation key.
	for _, s := range batch.Seedlings {
		other, err := s.DelegationKey.UnwrapOrErr(
			fmt.Errorf("delegation key must be set for " +
				"seedling with universe commitments"),
		)
		if err != nil {
			return err
		}

		if !delegationKey.PubKey.IsEqual(other.PubKey) {
			return fmt.Errorf("delegation key mismatch")
		}
	}

	return nil
}

// ExtraOutputs returns the pre-commitment output for this batch,
// when supply commitments are enabled. The output's PkScript is
// deterministic from the batch's anchor seedling's delegation
// key, so the augmenter can locate the same output in the funded
// PSBT later.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.ExtraOutputs.
func (a *GenesisAugmenter) ExtraOutputs(_ context.Context,
	batch *tapgarden.MintingBatch) ([]wire.TxOut, error) {

	dKey, err := delegationKeyFromBatch(batch)
	if err != nil {
		return nil, err
	}
	if dKey.IsNone() {
		return nil, nil
	}

	internalKey, err := dKey.UnwrapOrErr(
		fmt.Errorf("delegation key unexpectedly absent"),
	)
	if err != nil {
		return nil, err
	}

	out, err := PreCommitTxOut(*internalKey.PubKey)
	if err != nil {
		return nil, err
	}

	return []wire.TxOut{out}, nil
}

// PostFund stamps BIP32 derivation metadata onto the
// pre-commitment output in the funded PSBT. It locates the
// output by matching its PkScript against the deterministic
// pre-commitment script.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.PostFund.
func (a *GenesisAugmenter) PostFund(_ context.Context,
	batch *tapgarden.MintingBatch, funded *tapsend.FundedPsbt) error {

	dKey, err := delegationKeyFromBatch(batch)
	if err != nil {
		return err
	}
	if dKey.IsNone() {
		return nil
	}

	internalKey, err := dKey.UnwrapOrErr(
		fmt.Errorf("delegation key unexpectedly absent"),
	)
	if err != nil {
		return err
	}

	outIdx, err := findPreCommitOutputIdx(funded, *internalKey.PubKey)
	if err != nil {
		return err
	}
	if outIdx.IsNone() {
		return fmt.Errorf("pre-commit output not found in " +
			"funded psbt")
	}

	idx, _ := outIdx.UnwrapOrErr(
		fmt.Errorf("pre-commit output index unexpectedly absent"),
	)

	bip32, trBip32 := tappsbt.Bip32DerivationFromKeyDesc(
		internalKey, a.cfg.ChainParams.HDCoinType,
	)
	pOut := &funded.Pkt.Outputs[idx]
	pOut.Bip32Derivation = []*psbt.Bip32Derivation{bip32}
	pOut.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{trBip32}
	pOut.TaprootInternalKey = trBip32.XOnlyPubKey

	return nil
}

// BindData returns the PreCommitBindData for the batch's
// pre-commitment output. The output index is resolved by
// scanning the batch's funded PSBT (post-funding it is in
// batch.GenesisPacket); the group key is read from the anchor
// seedling's GroupInfo, which becomes known no later than seal
// time.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.BindData.
func (a *GenesisAugmenter) BindData(_ context.Context,
	batch *tapgarden.MintingBatch) (
	fn.Option[tapgarden.PreCommitBindData], error) {

	var zero fn.Option[tapgarden.PreCommitBindData]

	if batch == nil || !batch.SupplyCommitments {
		return zero, nil
	}
	if batch.GenesisPacket == nil {
		return zero, nil
	}

	dKey, err := delegationKeyFromBatch(batch)
	if err != nil {
		return zero, err
	}
	if dKey.IsNone() {
		return zero, nil
	}

	internalKey, err := dKey.UnwrapOrErr(
		fmt.Errorf("delegation key unexpectedly absent"),
	)
	if err != nil {
		return zero, err
	}

	outIdx, err := findPreCommitOutputIdx(
		&batch.GenesisPacket.FundedPsbt, *internalKey.PubKey,
	)
	if err != nil {
		return zero, err
	}
	if outIdx.IsNone() {
		return zero, nil
	}

	idx, _ := outIdx.UnwrapOrErr(
		fmt.Errorf("pre-commit output index unexpectedly absent"),
	)

	groupKey, err := groupKeyFromBatch(batch)
	if err != nil {
		return zero, err
	}

	bind, err := tapgarden.NewPreCommitBindData(
		idx, internalKey, groupKey,
	)
	if err != nil {
		return zero, err
	}
	return fn.Some(bind), nil
}

// OnBatchConfirmed emits a mint event for each newly-confirmed
// asset whose delegation key the local node controls.
//
// NOTE: This implements tapgarden.GenesisTxAugmenter.OnBatchConfirmed.
func (a *GenesisAugmenter) OnBatchConfirmed(ctx context.Context,
	_ *tapgarden.MintingBatch, anchorAssets,
	nonAnchorAssets []*asset.Asset,
	mintingProofs proof.AssetProofs) error {

	if a.cfg.MintEvents == nil {
		return nil
	}

	allAssets := append(
		make([]*asset.Asset, 0, len(anchorAssets)+len(nonAnchorAssets)),
		anchorAssets...,
	)
	allAssets = append(allAssets, nonAnchorAssets...)

	withDelegation := fn.Filter(allAssets, func(m *asset.Asset) bool {
		has, err := a.cfg.DelegationKeyChecker.HasDelegationKey(
			ctx, m.ID(),
		)
		if err != nil {
			log.Warnf("HasDelegationKey(%v): %v; dropping "+
				"asset from mint-event emission", m.ID(), err)
			return false
		}
		return has
	})

	for _, m := range withDelegation {
		scriptKey := asset.ToSerialized(m.ScriptKey.PubKey)
		mintingProof, ok := mintingProofs[scriptKey]
		if !ok {
			return fmt.Errorf("missing minting proof for "+
				"asset with script key %x", scriptKey[:])
		}

		proofBlob, err := proof.EncodeAsProofFile(mintingProof)
		if err != nil {
			return fmt.Errorf("unable to encode proof as "+
				"file: %w", err)
		}
		proofFile, err := proof.DecodeFile(proofBlob)
		if err != nil {
			return fmt.Errorf("unable to decode proof file: "+
				"%w", err)
		}
		leafProof, err := proofFile.LastProof()
		if err != nil {
			return fmt.Errorf("unable to get leaf proof: %w",
				err)
		}

		var leafBuf bytes.Buffer
		if err := leafProof.Encode(&leafBuf); err != nil {
			return fmt.Errorf("unable to encode leaf proof: "+
				"%w", err)
		}

		uniqueLeafKey := universe.AssetLeafKey{
			BaseLeafKey: universe.BaseLeafKey{
				OutPoint:  leafProof.OutPoint(),
				ScriptKey: &m.ScriptKey,
			},
			AssetID: m.ID(),
		}
		universeLeaf := universe.Leaf{
			GenesisWithGroup: universe.GenesisWithGroup{
				Genesis:  m.Genesis,
				GroupKey: m.GroupKey,
			},
			RawProof: leafBuf.Bytes(),
			Asset:    &leafProof.Asset,
			Amt:      m.Amount,
		}
		assetSpec := asset.NewSpecifierOptionalGroupKey(
			m.ID(), m.GroupKey,
		)

		err = a.cfg.MintEvents.SendMintEvent(
			ctx, assetSpec, uniqueLeafKey, universeLeaf,
			leafProof.BlockHeight,
		)
		if err != nil {
			return fmt.Errorf("unable to send mint event for "+
				"asset %x: %w", m.ID(), err)
		}
	}

	return nil
}

// PreCommitTxOut returns the wire.TxOut for the pre-commitment
// output corresponding to the given internal key. The output's
// PkScript is the BIP-341 key-only P2TR script, so it is
// deterministic from the key and can be matched against funded
// PSBT outputs.
//
// This is exported because the supply-commit verifier (env.go)
// uses the same script construction to identify pre-commitment
// outputs in mint anchor transactions, independently of the
// minting flow.
func PreCommitTxOut(internalKey btcec.PublicKey) (wire.TxOut, error) {
	var zero wire.TxOut
	taprootOutputKey := txscript.ComputeTaprootKeyNoScript(&internalKey)
	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	if err != nil {
		return zero, fmt.Errorf("unable to create "+
			"pre-commitment output pk script: %w", err)
	}
	return wire.TxOut{
		Value:    int64(tapsend.DummyAmtSats),
		PkScript: pkScript,
	}, nil
}

// delegationKeyFromBatch returns the delegation key from the
// batch's unique group-anchor seedling, when present. When the
// batch has no seedlings or supply commitments are disabled the
// result is None.
func delegationKeyFromBatch(batch *tapgarden.MintingBatch) (
	fn.Option[keychain.KeyDescriptor], error) {

	var zero fn.Option[keychain.KeyDescriptor]

	if batch == nil || !batch.SupplyCommitments {
		return zero, nil
	}
	if len(batch.Seedlings) == 0 {
		return zero, nil
	}

	anchor, err := uniqueAnchorSeedling(batch)
	if err != nil {
		return zero, fmt.Errorf("unable to identify group "+
			"anchor seedling: %w", err)
	}

	return anchor.DelegationKey, nil
}

// groupKeyFromBatch returns the group key for the batch's
// pre-commitment payload, when the batch's anchor seedling has
// a populated GroupInfo. Before seal time the group is typically
// not yet derived; after seal time it is.
func groupKeyFromBatch(batch *tapgarden.MintingBatch) (
	fn.Option[btcec.PublicKey], error) {

	var zero fn.Option[btcec.PublicKey]

	if batch == nil || !batch.SupplyCommitments {
		return zero, nil
	}
	if len(batch.Seedlings) == 0 {
		return zero, nil
	}

	anchor, err := uniqueAnchorSeedling(batch)
	if err != nil {
		return zero, fmt.Errorf("unable to identify group "+
			"anchor seedling: %w", err)
	}

	if anchor.GroupInfo == nil {
		return zero, nil
	}

	return fn.Some(anchor.GroupInfo.GroupPubKey), nil
}

// uniqueAnchorSeedling returns the single group-anchor seedling
// in the batch -- the seedling whose GroupAnchor is nil and that
// other seedlings may reference by name. Returns an error if the
// batch contains zero or more than one such seedling.
func uniqueAnchorSeedling(
	batch *tapgarden.MintingBatch) (*tapgarden.Seedling, error) {

	var (
		anchor *tapgarden.Seedling
		count  int
	)
	for _, s := range batch.Seedlings {
		if s.GroupAnchor != nil {
			continue
		}
		anchor = s
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

// findPreCommitOutputIdx scans the funded PSBT for the
// pre-commitment output associated with the given internal
// key. Returns None when the output is absent.
func findPreCommitOutputIdx(funded *tapsend.FundedPsbt,
	internalKey btcec.PublicKey) (fn.Option[uint32], error) {

	var zero fn.Option[uint32]
	if funded == nil || funded.Pkt == nil {
		return zero, nil
	}

	expectedOut, err := PreCommitTxOut(internalKey)
	if err != nil {
		return zero, err
	}

	tx := funded.Pkt.UnsignedTx
	if tx == nil {
		return zero, nil
	}

	for i, txOut := range tx.TxOut {
		if int32(i) == funded.ChangeOutputIndex {
			continue
		}
		if bytes.Equal(txOut.PkScript, expectedOut.PkScript) {
			return fn.Some(uint32(i)), nil
		}
	}

	return zero, nil
}

// A compile-time assertion to ensure GenesisAugmenter implements
// tapgarden.GenesisTxAugmenter.
var _ tapgarden.GenesisTxAugmenter = (*GenesisAugmenter)(nil)
