package tapgarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"golang.org/x/exp/maps"
)

// MintSupplyCommitter is used during minting to update the on-chain supply
// commitment of a new minted asset.
type MintSupplyCommitter interface {
	// SendMintEvent sends a mint event to the supply commitment state
	// machine.
	SendMintEvent(ctx context.Context, assetSpec asset.Specifier,
		leafKey universe.UniqueLeafKey, issuanceProof universe.Leaf,
		mintBlockHeight uint32) error
}

// GardenKit holds the set of shared fundamental interfaces all sub-systems of
// the tapgarden need to function.
type GardenKit struct {
	// Wallet is an active on chain wallet for the target chain.
	Wallet tapnode.WalletAnchor

	// ChainBridge provides access to the chain for confirmation
	// notification, and other block related actions.
	ChainBridge tapnode.ChainBridge

	// Log stores the current state of any active batch, throughout the
	// various states the planter will progress it through.
	Log MintingStore

	// TreeStore provides access to optional tapscript trees used with
	// script keys, minting output keys, and group keys.
	TreeStore asset.TapscriptTreeManager

	// KeyRing is used for obtaining internal keys for the anchor
	// transaction, as well as script keys for each asset and group keys
	// for assets created that permit ongoing emission.
	KeyRing tapnode.KeyRing

	// GenSigner is used to generate signatures for the key group tweaked
	// by the genesis point when creating assets that permit on going
	// emission.
	GenSigner asset.GenesisSigner

	// GenTxBuilder is used to create virtual transactions for the group
	// witness generation process.
	GenTxBuilder asset.GenesisTxBuilder

	// TxValidator is used to validate group witnesses when creating assets
	// that support reissuance.
	TxValidator tapscript.TxValidator

	// ProofFiles stores the set of flat proof files.
	ProofFiles proof.Archiver

	// Universe is used to register new asset issuance with a local/remote
	// base universe instance.
	Universe universe.BatchRegistrar

	// ProofWatcher is used to watch new proofs for their anchor transaction
	// to be confirmed safely with a minimum number of confirmations.
	ProofWatcher proof.Watcher

	// UniversePushBatchSize is the number of minted items to push to the
	// local universe in a single batch.
	UniversePushBatchSize int

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]

	// MintSupplyCommitter is used to commit the minting of new assets to
	// the supply commitment state machine.
	MintSupplyCommitter MintSupplyCommitter

	// DelegationKeyChecker is used to verify that we control the delegation
	// key for a given asset, which is required for creating supply
	// commitments.
	DelegationKeyChecker address.DelegationKeyChecker
}

// PlanterConfig is the main config for the ChainPlanter.
type PlanterConfig struct {
	GardenKit

	// ChainParams defines the chain parameters for the target blockchain
	// network. It specifies whether the network is Bitcoin mainnet or
	// testnet.
	ChainParams address.ChainParams

	// ProofUpdates is the storage backend for updated proofs.
	ProofUpdates proof.Archiver

	// ErrChan is the main error channel the planter will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// CustomAnchorLeaseRenewalInterval controls how often wallet-owned
	// inputs in a caller-funded batch are re-leased while awaiting an
	// external signer. Zero uses the production default.
	CustomAnchorLeaseRenewalInterval time.Duration

	// TODO(roasbeef): something notification related?
}

// BatchKey is a type alias for a serialized public key.
type BatchKey = asset.SerializedKey

// CancelResp is the response from a caretaker attempting to cancel a batch.
type CancelResp struct {
	cancelAttempted bool
	err             error
}

type stateRequest interface {
	Resolve(any)
	Error(error)
	Return(any, error)
	Type() reqType
	Param() any
}

type stateReq[T any] struct {
	resp    chan T
	err     chan error
	reqType reqType
}

func newStateReq[T any](req reqType) *stateReq[T] {
	return &stateReq[T]{
		resp:    make(chan T, 1),
		err:     make(chan error, 1),
		reqType: req,
	}
}

type stateParamReq[T, S any] struct {
	stateReq[T]

	param S
}

// ListBatchesParams are the options available to specify which minting batches
// are listed, and how verbose the listing should be.
type ListBatchesParams struct {
	BatchKey *btcec.PublicKey
	Verbose  bool
}

// PendingAssetGroup is the group key request and virtual TX necessary to
// produce an asset group witness for a seedling.
type PendingAssetGroup struct {
	asset.GroupKeyRequest
	asset.GroupVirtualTx
}

// PSBT returns a PSBT packet that can be used to create a group witness for the
// asset group.
func (p *PendingAssetGroup) PSBT(
	params chaincfg.Params) (*psbt.Packet, error) {

	// Generate PSBT equivalent of the group virtual tx.
	packet, err := psbt.NewFromUnsignedTx(&p.GroupVirtualTx.Tx)
	if err != nil {
		return nil, fmt.Errorf("error producing group virtual PSBT "+
			"from tx: %w", err)
	}

	vIn := &packet.Inputs[0]
	vIn.WitnessUtxo = &p.GroupVirtualTx.PrevOut
	vIn.TaprootMerkleRoot = p.GroupKeyRequest.TapscriptRoot
	vIn.TaprootInternalKey = schnorr.SerializePubKey(
		p.GroupKeyRequest.RawKey.PubKey,
	)

	switch {
	case p.GroupKeyRequest.ExternalKey.IsSome():
		externalKey := p.GroupKeyRequest.ExternalKey.UnwrapToPtr()
		pubKey, err := externalKey.PubKey()
		if err != nil {
			return nil, fmt.Errorf("error deriving public key "+
				"from external key: %w", err)
		}

		bip32Main := &psbt.Bip32Derivation{
			PubKey:               pubKey.SerializeCompressed(),
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            externalKey.DerivationPath,
		}
		trBip32Main := &psbt.TaprootBip32Derivation{
			XOnlyPubKey:          bip32Main.PubKey[1:],
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            externalKey.DerivationPath,
			LeafHashes:           make([][]byte, 0),
		}

		xPub := externalKey.XPub
		xPubPath := externalKey.DerivationPath[:xPub.Depth()]
		packet.XPubs = append(packet.XPubs, psbt.XPub{
			ExtendedKey:          psbt.EncodeExtendedKey(&xPub),
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            xPubPath,
		})

		vIn.Bip32Derivation = []*psbt.Bip32Derivation{
			bip32Main,
		}
		vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32Main,
		}

		// TODO(guggero): Make this switch dependent on the non-spend
		// leaf version, once we allow the user to configure that.
		if true {
			assetID := p.AnchorGen.ID()
			numsXPub, numsKey, err := asset.TweakedNumsKey(assetID)
			if err != nil {
				return nil, fmt.Errorf("error deriving nums "+
					"key: %w", err)
			}

			// For the fake/NUMS key, we use a specific static
			// fingerprint, which will allow us to identify it in
			// the HWI library in order to construct the correct
			// miniscript policy for this type of spend.
			numsFP := asset.PedersenXPubMasterKeyFingerprint
			numsKeyBytes := numsKey.SerializeCompressed()
			bip32Nums := &psbt.Bip32Derivation{
				PubKey:               numsKeyBytes,
				MasterKeyFingerprint: numsFP,
				// We use the same derivation path as for the
				// "real" key, but it doesn't really matter,
				// since it's a fake key anyway.
				Bip32Path: externalKey.DerivationPath,
			}
			trBip32Nums := &psbt.TaprootBip32Derivation{
				XOnlyPubKey:          numsKeyBytes[1:],
				MasterKeyFingerprint: numsFP,
				// We use the same derivation path as for the
				// "real" key, but it doesn't really matter,
				// since it's a fake key anyway.
				Bip32Path:  externalKey.DerivationPath,
				LeafHashes: make([][]byte, 0),
			}

			vIn.Bip32Derivation = append(
				vIn.Bip32Derivation, bip32Nums,
			)
			vIn.TaprootBip32Derivation = append(
				vIn.TaprootBip32Derivation, trBip32Nums,
			)

			numsXPub, err = numsXPub.CloneWithVersion(
				params.HDPublicKeyID[:],
			)
			if err != nil {
				return nil, fmt.Errorf("error cloning nums "+
					"key: %w", err)
			}
			packet.XPubs = append(packet.XPubs, psbt.XPub{
				ExtendedKey: psbt.EncodeExtendedKey(
					numsXPub,
				),
				MasterKeyFingerprint: numsFP,
				Bip32Path:            xPubPath,
			})
		}

	default:
		bip32, trBip32 := tappsbt.Bip32DerivationFromKeyDesc(
			p.GroupKeyRequest.RawKey, params.HDCoinType,
		)
		vIn.Bip32Derivation = []*psbt.Bip32Derivation{bip32}
		vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32,
		}
	}

	return packet, nil
}

// UnsealedSeedling is a previously submitted seedling and its associated
// PendingAssetGroup, which can be used to produce an asset group witness.
type UnsealedSeedling struct {
	*Seedling
	*PendingAssetGroup
}

// FinalizeParams are the options available to change how a batch is finalized,
// and how the genesis TX is constructed.
type FinalizeParams struct {
	FeeRate        fn.Option[chainfee.SatPerKWeight]
	SiblingTapTree fn.Option[asset.TapscriptTreeNodes]
	SignedPsbt     *psbt.Packet
}

// FundParams are the options available to change how a batch is funded, and how
// the genesis TX is constructed.
type FundParams struct {
	FeeRate        fn.Option[chainfee.SatPerKWeight]
	SiblingTapTree fn.Option[asset.TapscriptTreeNodes]

	// AnchorPsbt is an optional caller-authored anchor transaction. When
	// present, the wallet funding step is skipped and the caller-selected
	// inputs, outputs and PSBT metadata are preserved.
	AnchorPsbt *psbt.Packet

	// AssetAnchorOutIdx selects the output whose script will be replaced by
	// the final Taproot Asset commitment during batch preparation.
	AssetAnchorOutIdx uint32

	// ChangeOutputIndex identifies a pre-existing change output in the
	// caller-authored PSBT. A value of -1 means that there is no change
	// output.
	ChangeOutputIndex int32

	// PreCommitOutputIndex selects the caller-provided supply commitment
	// pre-commitment output. It must be set when the pending batch enables
	// supply commitments.
	PreCommitOutputIndex fn.Option[uint32]
}

var customAnchorPsbtMarker = []byte{
	0xfc, 0x04, 't', 'a', 'p', 'd', 0x01,
}

var customAnchorPublishMarker = []byte{
	0xfc, 0x04, 't', 'a', 'p', 'd', 0x02,
}

type customAnchorPublishState byte

type customAnchorLeaseMarkerState byte

const (
	customAnchorPublishNone customAnchorPublishState = iota
	customAnchorPublishPending
	customAnchorPublishRejected
	customAnchorImportPending

	maxFinalScriptWitnessSize = 4_000_000
	maxFinalWitnessItems      = 100_000

	customAnchorLeaseRenewalInterval = 5 * time.Minute
)

const (
	customAnchorLeaseMarkerMissing customAnchorLeaseMarkerState = iota
	customAnchorLeaseMarkerLegacy
	customAnchorLeaseMarkerCurrent
)

func markCustomAnchorPsbt(packet *psbt.Packet) {
	if isCustomAnchorPsbt(packet) {
		return
	}

	packet.Unknowns = append(packet.Unknowns, &psbt.Unknown{
		Key:   fn.CopySlice(customAnchorPsbtMarker),
		Value: []byte{1},
	})
}

// SetCustomAnchorLockedUTXOs records the wallet-owned inputs leased for a
// custom anchor transaction in tapd's existing proprietary PSBT marker. Caller
// metadata is left untouched, and the marker is persisted with the packet.
func SetCustomAnchorLockedUTXOs(packet *psbt.Packet, ops []wire.OutPoint) {
	if packet == nil {
		return
	}

	value := make([]byte, 5+36*len(ops))
	value[0] = 1
	binary.LittleEndian.PutUint32(value[1:5], uint32(len(ops)))
	offset := 5
	for _, op := range ops {
		copy(value[offset:offset+32], op.Hash[:])
		binary.LittleEndian.PutUint32(value[offset+32:offset+36], op.Index)
		offset += 36
	}

	unknowns := packet.Unknowns[:0]
	for _, unknown := range packet.Unknowns {
		if !bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			unknowns = append(unknowns, unknown)
		}
	}
	packet.Unknowns = append(unknowns, &psbt.Unknown{
		Key: fn.CopySlice(customAnchorPsbtMarker), Value: value,
	})
}

// parseCustomAnchorLockedUTXOs validates and returns the wallet-owned custom
// anchor inputs stored in tapd's PSBT marker. The original one-byte marker is
// reported as legacy so callers can rediscover and lease wallet-owned inputs
// before publication. Malformed current markers must never be interpreted as
// an external-only transaction.
func parseCustomAnchorLockedUTXOs(packet *psbt.Packet) ([]wire.OutPoint,
	customAnchorLeaseMarkerState, error) {

	if packet == nil {
		return nil, customAnchorLeaseMarkerMissing, nil
	}

	var marker *psbt.Unknown
	for _, unknown := range packet.Unknowns {
		if !bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			continue
		}
		if marker != nil {
			return nil, customAnchorLeaseMarkerCurrent,
				fmt.Errorf("duplicate custom anchor lease marker")
		}
		marker = unknown
	}

	if marker == nil {
		return nil, customAnchorLeaseMarkerMissing, nil
	}
	if len(marker.Value) == 1 && marker.Value[0] == 1 {
		return nil, customAnchorLeaseMarkerLegacy, nil
	}
	if len(marker.Value) < 5 || marker.Value[0] != 1 {
		return nil, customAnchorLeaseMarkerCurrent,
			fmt.Errorf("malformed custom anchor lease marker")
	}

	count := binary.LittleEndian.Uint32(marker.Value[1:5])
	if uint64(count) > uint64((len(marker.Value)-5)/36) ||
		len(marker.Value) != 5+int(count)*36 {

		return nil, customAnchorLeaseMarkerCurrent,
			fmt.Errorf("malformed custom anchor lease marker length")
	}

	ops := make([]wire.OutPoint, count)
	seen := make(map[wire.OutPoint]struct{}, count)
	offset := 5
	for idx := range ops {
		copy(ops[idx].Hash[:], marker.Value[offset:offset+32])
		ops[idx].Index = binary.LittleEndian.Uint32(
			marker.Value[offset+32 : offset+36],
		)
		offset += 36
		if _, ok := seen[ops[idx]]; ok {
			return nil, customAnchorLeaseMarkerCurrent,
				fmt.Errorf("duplicate custom anchor leased input %v", ops[idx])
		}
		seen[ops[idx]] = struct{}{}
	}

	if len(ops) > 0 && packet.UnsignedTx == nil {
		return nil, customAnchorLeaseMarkerCurrent,
			fmt.Errorf("custom anchor lease marker has no transaction")
	}
	for _, op := range ops {
		matched := false
		for _, txIn := range packet.UnsignedTx.TxIn {
			if txIn.PreviousOutPoint == op {
				matched = true
				break
			}
		}
		if !matched {
			return nil, customAnchorLeaseMarkerCurrent,
				fmt.Errorf("custom anchor leased input %v is not in the "+
					"transaction", op)
		}
	}

	return ops, customAnchorLeaseMarkerCurrent, nil
}

// CustomAnchorLockedUTXOs returns the wallet-owned custom-anchor inputs stored
// in tapd's PSBT marker. Strict publication paths use the parser above and
// fail closed on malformed data; this compatibility accessor returns no leases
// for legacy or malformed markers.
func CustomAnchorLockedUTXOs(packet *psbt.Packet) []wire.OutPoint {
	ops, _, err := parseCustomAnchorLockedUTXOs(packet)
	if err != nil {
		return nil
	}

	return ops
}

// acquireCustomAnchorLeases leases all inputs controlled by the backing
// wallet while allowing foreign inputs to remain under an external signer's
// control. Only leases acquired during this call are rolled back on failure.
func acquireCustomAnchorLeases(ctx context.Context, wallet tapnode.WalletAnchor,
	leaseID tapnode.CustomAnchorLeaseID, packet *psbt.Packet,
	previouslyLocked []wire.OutPoint) ([]wire.OutPoint, error) {

	if packet == nil || packet.UnsignedTx == nil {
		return nil, fmt.Errorf("custom anchor PSBT is missing a transaction")
	}
	leaser, ok := wallet.(tapnode.CustomAnchorLeaser)
	if !ok {
		return nil, fmt.Errorf("wallet does not support custom anchor leases")
	}

	previous := make(map[wire.OutPoint]struct{}, len(previouslyLocked))
	for _, op := range previouslyLocked {
		previous[op] = struct{}{}
	}

	locked := make([]wire.OutPoint, 0, len(packet.UnsignedTx.TxIn))
	newlyLocked := make([]wire.OutPoint, 0, len(packet.UnsignedTx.TxIn))
	seen := make(map[wire.OutPoint]struct{}, len(packet.UnsignedTx.TxIn))
	for _, txIn := range packet.UnsignedTx.TxIn {
		op := txIn.PreviousOutPoint
		if _, ok := seen[op]; ok {
			releaseErr := rollbackCustomAnchorOutpoints(
				ctx, wallet, leaseID, newlyLocked,
			)
			return nil, errors.Join(fmt.Errorf(
				"custom anchor PSBT repeats input %v", op,
			), releaseErr)
		}
		seen[op] = struct{}{}
		owned, err := leaser.LeaseInput(ctx, leaseID, op)
		if err != nil {
			releaseErr := rollbackCustomAnchorOutpoints(
				ctx, wallet, leaseID, newlyLocked,
			)
			return nil, errors.Join(
				fmt.Errorf("unable to lease custom anchor input %v: %w",
					op, err), releaseErr,
			)
		}
		if !owned {
			if _, wasLocked := previous[op]; wasLocked {
				releaseErr := rollbackCustomAnchorOutpoints(
					ctx, wallet, leaseID, newlyLocked,
				)
				return nil, errors.Join(fmt.Errorf(
					"unable to renew custom anchor input lease %v", op,
				), releaseErr)
			}
			continue
		}

		locked = append(locked, op)
		if _, wasLocked := previous[op]; !wasLocked {
			newlyLocked = append(newlyLocked, op)
		}
	}

	return locked, nil
}

// rollbackCustomAnchorOutpoints releases leases acquired by an operation that
// failed. The acquisition context may itself be the reason for the failure, so
// cleanup must not inherit its cancellation or deadline. The bounded timeout
// keeps shutdown from waiting indefinitely on an unresponsive wallet RPC.
func rollbackCustomAnchorOutpoints(ctx context.Context,
	wallet tapnode.WalletAnchor, leaseID tapnode.CustomAnchorLeaseID,
	ops []wire.OutPoint) error {

	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), DefaultTimeout,
	)
	defer cancel()

	return releaseCustomAnchorOutpoints(
		cleanupCtx, wallet, leaseID, ops,
	)
}

func newlyAcquiredLeases(locked, previous []wire.OutPoint) []wire.OutPoint {
	previousSet := make(map[wire.OutPoint]struct{}, len(previous))
	for _, op := range previous {
		previousSet[op] = struct{}{}
	}

	var newlyLocked []wire.OutPoint
	for _, op := range locked {
		if _, ok := previousSet[op]; !ok {
			newlyLocked = append(newlyLocked, op)
		}
	}

	return newlyLocked
}

func releaseCustomAnchorOutpoints(ctx context.Context,
	wallet tapnode.WalletAnchor, leaseID tapnode.CustomAnchorLeaseID,
	ops []wire.OutPoint) error {

	leaser, ok := wallet.(tapnode.CustomAnchorLeaser)
	if !ok {
		return fmt.Errorf("wallet does not support custom anchor leases")
	}

	var releaseErr error
	for _, op := range ops {
		if err := leaser.ReleaseInput(ctx, leaseID, op); err != nil {
			releaseErr = errors.Join(releaseErr, fmt.Errorf(
				"unable to release custom anchor input %v: %w", op, err,
			))
		}
	}

	return releaseErr
}

func releaseCustomAnchorLeases(ctx context.Context,
	wallet tapnode.WalletAnchor, leaseID tapnode.CustomAnchorLeaseID,
	funded *FundedMintAnchorPsbt) error {

	if funded == nil {
		return nil
	}
	if err := releaseCustomAnchorOutpoints(
		ctx, wallet, leaseID, funded.LockedUTXOs,
	); err != nil {
		return err
	}

	funded.LockedUTXOs = nil
	SetCustomAnchorLockedUTXOs(funded.Pkt, nil)
	return nil
}

func renewCustomAnchorLeases(ctx context.Context, wallet tapnode.WalletAnchor,
	leaseID tapnode.CustomAnchorLeaseID, funded *FundedMintAnchorPsbt) error {

	if funded == nil {
		return nil
	}
	leaser, ok := wallet.(tapnode.CustomAnchorLeaser)
	if !ok {
		return fmt.Errorf("wallet does not support custom anchor leases")
	}

	markerOps, markerState, err := parseCustomAnchorLockedUTXOs(funded.Pkt)
	if err != nil {
		return fmt.Errorf("invalid custom anchor lease marker: %w", err)
	}
	if markerState == customAnchorLeaseMarkerLegacy {
		locked, err := acquireCustomAnchorLeases(
			ctx, wallet, leaseID, funded.Pkt, nil,
		)
		if err != nil {
			return fmt.Errorf("unable to upgrade legacy custom anchor "+
				"leases: %w", err)
		}

		funded.LockedUTXOs = locked
		SetCustomAnchorLockedUTXOs(funded.Pkt, locked)
		return nil
	} else if markerState == customAnchorLeaseMarkerCurrent {
		funded.LockedUTXOs = markerOps
	}

	for _, op := range funded.LockedUTXOs {
		owned, err := leaser.LeaseInput(ctx, leaseID, op)
		if err != nil {
			return fmt.Errorf("unable to renew custom anchor input %v: %w",
				op, err)
		}
		if !owned {
			return fmt.Errorf("custom anchor input %v is no longer available "+
				"to the backing wallet", op)
		}
	}

	return nil
}

// customAnchorLeaseID derives a restart-stable, batch-specific lease owner.
// The domain separator prevents the ID from colliding with unrelated uses of
// the batch key.
func customAnchorLeaseID(
	batchKey *btcec.PublicKey) tapnode.CustomAnchorLeaseID {

	preimage := append(
		[]byte("tapd-custom-anchor-psbt-lease-v1:"),
		batchKey.SerializeCompressed()...,
	)

	return tapnode.CustomAnchorLeaseID(sha256.Sum256(preimage))
}

func isCustomAnchorPsbt(packet *psbt.Packet) bool {
	if packet == nil {
		return false
	}

	for _, unknown := range packet.Unknowns {
		if bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			return true
		}
	}

	return false
}

func setCustomAnchorPublishState(packet *psbt.Packet,
	state customAnchorPublishState) {

	unknowns := packet.Unknowns[:0]
	for _, unknown := range packet.Unknowns {
		if !bytes.Equal(unknown.Key, customAnchorPublishMarker) {
			unknowns = append(unknowns, unknown)
		}
	}
	packet.Unknowns = unknowns
	if state == customAnchorPublishNone {
		return
	}

	packet.Unknowns = append(packet.Unknowns, &psbt.Unknown{
		Key:   fn.CopySlice(customAnchorPublishMarker),
		Value: []byte{byte(state)},
	})
}

func getCustomAnchorPublishState(
	packet *psbt.Packet) customAnchorPublishState {

	if packet == nil {
		return customAnchorPublishNone
	}

	for _, unknown := range packet.Unknowns {
		if !bytes.Equal(unknown.Key, customAnchorPublishMarker) {
			continue
		}
		if len(unknown.Value) == 1 {
			state := customAnchorPublishState(unknown.Value[0])
			switch state {
			case customAnchorPublishRejected:
				// Older builds wrote this marker only after submitting the
				// fully signed bytes. Treat it as publication-ambiguous so an
				// upgrade cannot expose cancellation or release its leases.
				return customAnchorPublishPending

			case customAnchorPublishPending,
				customAnchorImportPending:

				return state
			}
		}

		// An unknown or malformed persisted value is conservative: a
		// publication attempt might have happened, so don't make the batch
		// cancellable.
		return customAnchorPublishPending
	}

	return customAnchorPublishNone
}

func stripCustomAnchorPublishState(packet *psbt.Packet) {
	setCustomAnchorPublishState(packet, customAnchorPublishNone)
}

func stripTapdCustomAnchorMarkers(packet *psbt.Packet) {
	if packet == nil {
		return
	}

	unknowns := packet.Unknowns[:0]
	for _, unknown := range packet.Unknowns {
		if bytes.Equal(unknown.Key, customAnchorPsbtMarker) ||
			bytes.Equal(unknown.Key, customAnchorPublishMarker) {

			continue
		}
		unknowns = append(unknowns, unknown)
	}
	packet.Unknowns = unknowns
}

func customAnchorPublicationPending(batch *MintingBatch) bool {
	return batch != nil && batch.GenesisPacket != nil &&
		isCustomAnchorPsbt(batch.GenesisPacket.Pkt) &&
		getCustomAnchorPublishState(batch.GenesisPacket.Pkt) ==
			customAnchorPublishPending
}

// PendingGroupWitness specifies the asset group witness for an asset seedling
// in an unsealed minting batch.
type PendingGroupWitness struct {
	GenID   asset.ID
	Witness wire.TxWitness
}

// SealParams change how asset groups in a minting batch are created.
type SealParams struct {
	GroupWitnesses []PendingGroupWitness

	// SignedGroupVirtualPsbts are the signed group virtual PSBTs that
	// will be used to create the group witness for the asset group.
	SignedGroupVirtualPsbts []psbt.Packet
}

func newStateParamReq[T, S any](req reqType, param S) *stateParamReq[T, S] {
	return &stateParamReq[T, S]{
		stateReq: *newStateReq[T](req),
		param:    param,
	}
}

func (s *stateReq[T]) Resolve(resp any) {
	s.resp <- resp.(T)
	close(s.err)
}

func (s *stateReq[T]) Error(err error) {
	s.err <- err
	close(s.resp)
}

func (s *stateReq[T]) Return(resp any, err error) {
	s.resp <- resp.(T)
	s.err <- err
}

func (s *stateReq[T]) Type() reqType {
	return s.reqType
}

func (s *stateReq[T]) Param() any {
	return nil
}

func (s *stateParamReq[T, S]) Param() any {
	return s.param
}

func typedParam[T any](req stateRequest) (*T, error) {
	if param, ok := req.Param().(T); ok {
		return &param, nil
	}

	return nil, fmt.Errorf("invalid type")
}

type reqType uint8

const (
	reqTypePendingBatch = iota
	reqTypeNumActiveBatches
	reqTypeListBatches
	reqTypeFinalizeBatch
	reqTypeCancelBatch
	reqTypeFundBatch
	reqTypeSealBatch
	reqTypePrepareBatch
)

// ChainPlanter is responsible for accepting new incoming requests to create
// taproot assets. The planter will periodically batch those requests into a new
// minting batch, which is handed off to a caretaker. While batches are
// progressing through maturity the planter will be responsible for sending
// notifications back to the relevant caller.
type ChainPlanter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg PlanterConfig

	// seedlingReqs is used to accept new asset issuance requests.
	seedlingReqs chan *Seedling

	// pendingBatch is the current pending, non-frozen batch. Only one of
	// these will exist at any given time.
	pendingBatch *MintingBatch

	// caretakers maps a batch key (which is used as the internal key for
	// the transaction that mints the assets) to the caretaker that will
	// progress the batch through the final phases.
	caretakers map[BatchKey]*BatchCaretaker

	// customAnchorKeyErrors maps historical custom-anchor batches to the
	// actionable health result produced by the startup key audit. The map is
	// owned by the gardener after startup and attached to ListBatches results.
	customAnchorKeyErrors map[BatchKey]string

	// completionSignals is a channel used to allow the caretakers to
	// signal that the batch is fully final, allowing garbage collection of
	// any relevant resources.
	completionSignals chan BatchKey

	// startupCaretakerResults carries the first publication result from a
	// custom caretaker that was resumed during startup. The gardener is the
	// sole owner of the corresponding caretaker and pending batch mutations.
	startupCaretakerResults chan startupCaretakerResult

	// stateReqs is the channel that any outside requests for the state of
	// the planter will come across.
	stateReqs chan stateRequest

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*fn.EventReceiver[fn.Event]

	// subscriberMtx guards the subscribers map.
	subscriberMtx sync.Mutex

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// startupCaretakerResult is the first publication result from a custom batch
// caretaker that was resumed during startup.
type startupCaretakerResult struct {
	batchKey  BatchKey
	caretaker *BatchCaretaker
	err       error
}

// attachCustomAnchorKeyErrors adds startup audit health to freshly queried
// batches. The health is intentionally in-memory: it is deterministically
// rebuilt from retained state before the planter serves ListBatches.
func (c *ChainPlanter) attachCustomAnchorKeyErrors(batches []*VerboseBatch) {
	for _, batch := range batches {
		key := asset.ToSerialized(batch.BatchKey.PubKey)
		batch.CustomAnchorKeyError = c.customAnchorKeyErrors[key]
	}
}

// attachCustomAnchorRuntimeStatus overlays transient custom anchor health from
// the gardener-owned pending batch or an active caretaker onto fresh store
// results. This makes degradation queryable by clients that subscribe after
// the corresponding event was emitted.
func (c *ChainPlanter) attachCustomAnchorRuntimeStatus(
	batches []*VerboseBatch) {

	var pendingKey BatchKey
	if c.pendingBatch != nil {
		pendingKey = asset.ToSerialized(c.pendingBatch.BatchKey.PubKey)
	}

	for _, batch := range batches {
		key := asset.ToSerialized(batch.BatchKey.PubKey)
		if c.pendingBatch != nil && key == pendingKey {
			batch.CustomAnchorLeaseError =
				c.pendingBatch.CustomAnchorLeaseError
			batch.CustomAnchorPublishError =
				c.pendingBatch.CustomAnchorPublishError
		}

		caretaker, ok := c.caretakers[key]
		if !ok {
			continue
		}

		leaseErr, publishErr := caretaker.customAnchorStatus()
		batch.CustomAnchorLeaseError = leaseErr
		batch.CustomAnchorPublishError = publishErr
	}
}

// NewChainPlanter creates a new ChainPlanter instance given the passed config.
func NewChainPlanter(cfg PlanterConfig) *ChainPlanter {
	return &ChainPlanter{
		cfg:                     cfg,
		caretakers:              make(map[BatchKey]*BatchCaretaker),
		customAnchorKeyErrors:   make(map[BatchKey]string),
		completionSignals:       make(chan BatchKey),
		startupCaretakerResults: make(chan startupCaretakerResult, 1),
		seedlingReqs:            make(chan *Seedling),
		stateReqs:               make(chan stateRequest),
		subscribers: make(
			map[uint64]*fn.EventReceiver[fn.Event],
		),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// newCaretakerForBatch creates a new BatchCaretaker for a given batch and
// inserts it into the caretaker map.
func (c *ChainPlanter) newCaretakerForBatch(batch *MintingBatch,
	feeRate *chainfee.SatPerKWeight) *BatchCaretaker {

	batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
	batchConfig := &BatchCaretakerConfig{
		Batch:                 batch,
		GardenKit:             c.cfg.GardenKit,
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
		SignalCompletion: func() {
			c.completionSignals <- batchKey
		},
		CancelReqChan:       make(chan struct{}, 1),
		CancelRespChan:      make(chan CancelResp, 1),
		UpdateMintingProofs: c.updateMintingProofs,
		PublishMintEvent:    c.publishSubscriberEvent,
		ErrChan:             c.cfg.ErrChan,
		CustomAnchorLeaseRenewalInterval: c.cfg.
			CustomAnchorLeaseRenewalInterval,
	}
	if feeRate != nil {
		batchConfig.BatchFeeRate = feeRate
	}

	caretaker := NewBatchCaretaker(batchConfig)
	c.caretakers[batchKey] = caretaker

	return caretaker
}

// Start starts the ChainPlanter and any goroutines it needs to carry out its
// duty.
func (c *ChainPlanter) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		log.Infof("Starting ChainPlanter")

		// First, we'll read out any minting batches that aren't yet
		// fully finalized (minting transaction well confirmed on
		// chain). This includes batches that were still pending before
		// our last restart, so were never frozen in the first place.
		// The caretaker will handle progressing the batch to the
		// frozen state, and beyond.
		//
		// TODO(roasbeef): instead do RBF here? so only a single
		// pending batch at a time? but would end up changing assetIDs.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()

		// Historical custom-anchor builds could persist the batch key as
		// the managed UTXO internal key. Audit those retained rows only
		// after the wallet key ring is available, and automatically repair
		// only descriptors proven to be local. Unverifiable historical
		// rows require wallet-validated operator recovery and are surfaced
		// loudly instead of being guessed or silently ignored.
		if repairStore, ok := c.cfg.Log.(CustomAnchorKeyRepairStore); ok {
			repairHealth, err := AuditAndRepairCustomAnchorKeys(
				ctx, repairStore, c.cfg.KeyRing, c.cfg.ChainParams,
			)
			if err != nil {
				startErr = err
				return
			}

			for _, health := range repairHealth {
				if health.RequiresIntervention() {
					batchKey, err := btcec.ParsePubKey(health.BatchKey)
					if err != nil {
						log.Errorf("Unable to index historical custom "+
							"anchor key health for batch_key=%x: %v",
							health.BatchKey, err)
					} else {
						key := asset.ToSerialized(batchKey)
						c.customAnchorKeyErrors[key] = fmt.Sprintf(
							"status=%s, outpoint=%v: %s",
							health.Status, health.Outpoint,
							health.Detail,
						)
					}

					log.Errorf("Historical custom anchor key requires "+
						"operator action: status=%s, batch_key=%x, "+
						"outpoint=%v, detail=%s", health.Status,
						health.BatchKey, health.Outpoint,
						health.Detail)
					continue
				}

				batchKey, err := btcec.ParsePubKey(health.BatchKey)
				if err == nil {
					delete(
						c.customAnchorKeyErrors,
						asset.ToSerialized(batchKey),
					)
				}

				if health.Status == CustomAnchorKeyRepaired {
					log.Infof("Repaired historical custom anchor key: "+
						"batch_key=%x, outpoint=%v", health.BatchKey,
						health.Outpoint)
				}
			}
		}

		nonFinalBatches, err := c.cfg.Log.FetchNonFinalBatches(ctx)
		if err != nil {
			startErr = err
			return
		}

		log.Infof("Retrieved %v non-finalized batches from DB",
			len(nonFinalBatches))

		// Enforce the singleton invariant: at most one batch may
		// be in BatchStatePending or BatchStateFrozen at a time.
		// The DB constraint added in migration 000061 should
		// already make this impossible, but a legacy DB that was
		// migrated post-population, or a manually-modified row,
		// could still violate it. Surfacing the error here gives
		// the operator a human-readable diagnostic instead of an
		// opaque SQL one later.
		if err := checkSingletonInvariant(nonFinalBatches); err != nil {
			startErr = err
			return
		}

		// Now for each of these non-final batches, we'll make a new
		// caretaker which'll handle progressing each batch to
		// completion. We'll skip batches that were cancelled.
		for _, batch := range nonFinalBatches {
			batchState := batch.State()
			batchKey := batch.BatchKey.PubKey.SerializeCompressed()

			if batchState == BatchStateSeedlingCancelled ||
				batchState == BatchStateSproutCancelled {

				continue
			}

			// All restored batches need a writable metadata map before any
			// custom batch can be resumed through preparation or proof work.
			if batch.AssetMetas == nil {
				batch.AssetMetas = make(AssetMetas)
			}

			// A custom batch is paused only while awaiting an external signer.
			// A finalized Committed packet with any historical publication
			// marker instead
			// resumes automatically: it may already have reached the backend
			// before a crash and therefore must not become cancellable.
			customBatch := batch.GenesisPacket != nil &&
				isCustomAnchorPsbt(batch.GenesisPacket.Pkt)
			publishState := customAnchorPublishNone
			if customBatch {
				publishState = getCustomAnchorPublishState(
					batch.GenesisPacket.Pkt,
				)
			}
			awaitingExternalSigner := customBatch &&
				(batchState == BatchStatePending ||
					batchState == BatchStateFrozen ||
					(batchState == BatchStateCommitted &&
						publishState != customAnchorPublishPending &&
						publishState != customAnchorImportPending))
			leaseRenewalFailed := false
			if customBatch && (batchState == BatchStatePending ||
				batchState == BatchStateFrozen ||
				batchState == BatchStateCommitted) {

				if err := renewCustomAnchorLeases(
					ctx, c.cfg.Wallet,
					customAnchorLeaseID(batch.BatchKey.PubKey),
					batch.GenesisPacket,
				); err != nil {
					batch.CustomAnchorLeaseError = fmt.Sprintf(
						"custom anchor input lease renewal degraded during "+
							"startup; Finalize will retry and fail closed: %v",
						err,
					)
					log.Warnf("Unable to renew custom anchor input "+
						"leases during startup: %v", err)
					leaseRenewalFailed = true
				} else {
					batch.CustomAnchorLeaseError = ""
				}
			}

			// A pre-publication batch cannot advance after a failed lease
			// renewal. Keep it available for Cancel or a Finalize retry. A
			// publish-pending batch may already be on chain and must resume
			// monitoring regardless.
			if leaseRenewalFailed &&
				publishState != customAnchorPublishPending {

				awaitingExternalSigner = true
			}
			if awaitingExternalSigner {
				if c.pendingBatch != nil {
					startErr = fmt.Errorf("multiple custom batches " +
						"awaiting external signatures")
					return
				}
				c.pendingBatch = batch
				continue
			}

			// A custom batch with a signed transaction awaiting import or
			// publication is resumed automatically. Adopt it as the exclusive
			// pending batch before launching its caretaker so no new batch can
			// be admitted while recovery is in flight.
			startupCustomRecovery := customBatch &&
				batchState == BatchStateCommitted &&
				(publishState == customAnchorImportPending ||
					publishState == customAnchorPublishPending)
			if startupCustomRecovery {
				if c.pendingBatch != nil {
					startErr = fmt.Errorf("multiple custom batches " +
						"require startup recovery")
					return
				}

				// The caretaker mutates its batch while crossing import and
				// publication boundaries. Reserve an independent copy so API
				// reads and the gardener never race those mutations.
				c.pendingBatch = batch.Copy()
			}

			// If batch funding or sealing fail during startup, the
			// batch will be marked as cancelled. The batch can
			// still be displayed by the planter, and can be
			// resubmitted manually.
			cancelBatch := func() {
				log.Warnf("Marking batch as cancelled (%x)",
					batchKey)
				err := c.cfg.Log.UpdateBatchState(
					ctx, batch,
					BatchStateSeedlingCancelled,
				)

				// If updating the batch state fails, the batch
				// will still be skipped on this startup; we can
				// continue without passing the error further.
				if err != nil {
					log.Warnf("Unable to cancel batch (%x)",
						batchKey)
				}
			}

			// TODO(jhb): Log manual fee rates?
			// If the batch was still pending, or if batch
			// finalization was interrupted, it may need to be
			// funded or sealed before being assigned a caretaker.
			// A batch that was already properly frozen at this
			// point should not be modified before being assigned a
			// caretaker.
			if batchState == BatchStatePending ||
				batchState == BatchStateFrozen {

				var (
					fundErr error
					sealErr error
				)

				if !batch.IsFunded() {
					log.Infof("Funding non-finalized "+
						"batch from DB (%x)", batchKey)
					fundErr = c.applyFundingToBatch(
						ctx, FundParams{}, batch,
					)
				}

				if fundErr != nil {
					log.Warnf("Failed to fund batch from "+
						"DB (%x): %s",
						batchKey, fundErr.Error())
					cancelBatch()
					continue
				}

				log.Infof("Sealing non-finalized batch from "+
					"DB (%x)", batchKey)
				sealedBatch, sealErr := c.sealBatch(
					ctx, SealParams{}, batch,
				)
				if sealErr != nil {
					if !errors.Is(
						sealErr, ErrBatchAlreadySealed,
					) {

						log.Warnf("Failed to seal "+
							"batch from DB (%x): "+
							"%s", batchKey,
							sealErr.Error())
						cancelBatch()
						continue
					}
				}

				// If the sealBatch call returned a sealed
				// batch, update the pending batch accordingly.
				if sealedBatch != nil {
					batch = sealedBatch
				}

				// Any pending batch that was funded and sealed
				// can now be set as frozen. We are already not
				// able to add new seedlings to the batch. The
				// store call below moves both the on-disk row
				// and the in-memory mirror atomically; if it
				// fails, neither has moved.
				err := c.cfg.Log.UpdateBatchState(
					ctx, batch, BatchStateFrozen,
				)
				if err != nil {
					log.Warnf("Failed to update batch "+
						"state to frozen (%x): %s",
						batchKey, err.Error())
					cancelBatch()
					continue
				}
			}

			log.Infof("Launching ChainCaretaker(%x)", batchKey)
			caretaker := c.newCaretakerForBatch(batch, nil)
			if err := caretaker.Start(); err != nil {
				delete(c.caretakers, asset.ToSerialized(
					batch.BatchKey.PubKey,
				))
				startErr = err
				return
			}

			if startupCustomRecovery {
				batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
				c.Wg.Add(1)
				go c.forwardStartupCaretakerResult(
					batchKey, caretaker,
				)
			} else if batch.State() != BatchStateConfirmed {
				// The caretaker advances the batch in the background,
				// and nothing else reads its broadcast channels on
				// this path: BroadcastErrChan is otherwise only
				// consumed by the interactive finalize handler. Watch
				// for a pre-broadcast failure so a failed resume
				// cannot leave the batch occupying the singleton slot
				// enforced by the migration 000061 index, which would
				// block all further minting. A batch resumed at
				// BatchStateConfirmed skips the broadcast phase
				// entirely and reports through the completion signal,
				// so there is nothing to watch.
				c.Wg.Add(1)
				go c.watchResumedCaretaker(caretaker)
			}
		}

		// With all the caretakers for each minting batch launched,
		// we'll start up the main gardener goroutine so we can accept
		// new minting requests.
		c.Wg.Add(1)
		go c.gardener()
	})

	return startErr
}

// forwardStartupCaretakerResult forwards exactly one publication result from
// a custom caretaker resumed during startup. It never mutates planter state;
// the gardener processes the result serially with all API requests.
func (c *ChainPlanter) forwardStartupCaretakerResult(batchKey BatchKey,
	caretaker *BatchCaretaker) {

	defer c.Wg.Done()

	var result startupCaretakerResult
	result.batchKey = batchKey
	result.caretaker = caretaker

	select {
	case <-caretaker.cfg.BroadcastCompleteChan:

	case result.err = <-caretaker.cfg.BroadcastErrChan:

	case <-c.Quit:
		return
	}

	select {
	case c.startupCaretakerResults <- result:
	case <-c.Quit:
	}
}

// Stop signals the ChainPlanter to halt all operations gracefully.
func (c *ChainPlanter) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		log.Infof("Stopping ChainPlanter")

		close(c.Quit)
		c.Wg.Wait()

		// Remove all subscribers.
		c.subscriberMtx.Lock()
		defer c.subscriberMtx.Unlock()

		for _, subscriber := range c.subscribers {
			subscriber.Stop()
			delete(c.subscribers, subscriber.ID())
		}
	})

	return stopErr
}

// stopCaretakers attempts to gracefully stop all the active caretakers.
func (c *ChainPlanter) stopCaretakers() {
	for batchKey, caretaker := range c.caretakers {
		log.Debugf("Stopping ChainCaretaker(%x)", batchKey[:])

		if err := caretaker.Stop(); err != nil {
			// TODO(roasbeef): continue and stop the rest
			// of them?
			log.Warnf("Unable to stop ChainCaretaker(%x)",
				batchKey[:])
			return
		}
	}
}

// newBatch creates a new minting batch, which includes deriving a new internal
// key. The batch is not written to disk nor set as the pending batch.
func (c *ChainPlanter) newBatch() (*MintingBatch, error) {
	ctx, cancel := c.WithCtxQuit()
	defer cancel()

	// To create a new batch we'll first need to grab a new internal key,
	// which will be used in the output we create, and also will serve as
	// the primary identifier for a batch.
	log.Infof("Creating new MintingBatch")
	newInternalKey, err := c.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return nil, err
	}

	currentHeight, err := c.cfg.ChainBridge.CurrentHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get current height: %w", err)
	}

	// Create the new batch.
	newBatch := &MintingBatch{
		CreationTime: time.Now(),
		HeightHint:   currentHeight,
		BatchKey:     newInternalKey,
		Seedlings:    make(map[string]*Seedling),
		AssetMetas:   make(AssetMetas),
	}
	// The batch is private to this caller until CommitMintingBatch
	// succeeds, so setting the in-memory state directly here does not
	// open a two-truth window: the next DB call is the first to publish
	// the row, with state=Pending.
	newBatch.setState(BatchStatePending)
	return newBatch, nil
}

// unfundedAnchorPsbt creates an unfunded PSBT packet for the minting anchor
// transaction.
func unfundedAnchorPsbt(preCommitmentTxOut fn.Option[wire.TxOut]) (psbt.Packet,
	error) {

	var zero psbt.Packet

	// Construct a template transaction for our minting anchor transaction.
	txTemplate := wire.NewMsgTx(2)

	// Add one output to anchor all assets which are being minted.
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())

	// If universe commitments are enabled, we add an output to the
	// transaction which will be used as the pre-commitment output.
	// This output is spent by the universe commitment transaction.
	preCommitmentTxOut.WhenSome(func(txOut wire.TxOut) {
		txTemplate.AddTxOut(&txOut)
	})

	// Formulate the PSBT packet from the template transaction.
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return zero, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	return *genesisPkt, nil
}

// AnchorTxOutputIndexes specifies the output indexes of the batch mint anchor
// transaction.
type AnchorTxOutputIndexes struct {
	// AssetAnchorOutIdx is the index of the asset anchor output in the
	// transaction.
	AssetAnchorOutIdx uint32

	// ChangeOutIdx is the index of the change output in the transaction.
	ChangeOutIdx uint32

	// PreCommitOutIdx is the index of the pre-commitment output in the
	// transaction. This field is only set if universe commitments are
	// enabled for the batch.
	PreCommitOutIdx fn.Option[uint32]
}

// anchorTxOutputIndexes specifies the output indexes of the anchor transaction.
func anchorTxOutputIndexes(fundedPsbt tapsend.FundedPsbt,
	preCommitmentTxOut fn.Option[wire.TxOut]) (AnchorTxOutputIndexes,
	error) {

	var (
		zero AnchorTxOutputIndexes

		// assetAnchorOutIdxOpt will contain the index of the asset
		// anchor output in the transaction.
		assetAnchorOutIdxOpt fn.Option[uint32]

		// preCommitOutIdx will contain the index of the pre-commitment
		// output in the transaction. This field is only
		// set if universe commitments are enabled for the batch.
		preCommitOutIdx fn.Option[uint32]
	)

	// Formulate the expected asset anchor output that we will use to
	// identify the asset anchor output in the transaction.
	expectedAssetAnchorOutput := tapsend.CreateDummyOutput()
	expectedAssetAnchorPkScript := expectedAssetAnchorOutput.PkScript

	// Inspect each output in the transaction to determine the output
	// indexes.
	for idx := range fundedPsbt.Pkt.UnsignedTx.TxOut {
		// Skip the change output based on its index.
		if int32(idx) == fundedPsbt.ChangeOutputIndex {
			continue
		}

		// We will inspect the output script pubkey to determine whether
		// it is the asset anchor output or the pre-commitment output.
		txOut := fundedPsbt.Pkt.UnsignedTx.TxOut[idx]

		// If the output script pubkey matches the expected asset anchor
		// output script pubkey, we have found the asset anchor output.
		if bytes.Equal(txOut.PkScript, expectedAssetAnchorPkScript) {
			assetAnchorOutIdxOpt = fn.Some(uint32(idx))
			continue
		}

		// If universe commitments are enabled, we will inspect the
		// output script pubkey to determine whether it is the
		// pre-commitment output.
		preCommitmentTxOut.WhenSome(
			func(preCommitTxOut wire.TxOut) {
				// If the output script pubkey matches the
				// pre-commitment output script pubkey, we have
				// found the pre-commitment output.
				outputMatch := bytes.Equal(
					txOut.PkScript, preCommitTxOut.PkScript,
				)
				if outputMatch {
					preCommitOutIdx = fn.Some(uint32(idx))
				}
			},
		)
	}

	// Unpack the asset anchor output index. Return an error if the output
	// index is not found.
	assetAnchorOutIdx, err := assetAnchorOutIdxOpt.UnwrapOrErr(
		fmt.Errorf("asset anchor output index not found"),
	)
	if err != nil {
		return zero, err
	}

	// If the pre-commitment output is expected, but not found, we return an
	// error.
	if preCommitmentTxOut.IsSome() && !preCommitOutIdx.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index not found")
	}

	return AnchorTxOutputIndexes{
		AssetAnchorOutIdx: assetAnchorOutIdx,
		ChangeOutIdx:      uint32(fundedPsbt.ChangeOutputIndex),
		PreCommitOutIdx:   preCommitOutIdx,
	}, nil
}

// DelegationKey is a type alias for a key descriptor used as a supply
// commitment delegation key.
type DelegationKey = keychain.KeyDescriptor

// fetchDelegationKey retrieves the delegation key from the given batch.
// The key is read from the batch's unique group anchor seedling; an
// error is returned if the anchor cannot be identified
// deterministically.
func fetchDelegationKey(pendingBatch *MintingBatch) (fn.Option[DelegationKey],
	error) {

	var zero fn.Option[DelegationKey]

	// Ensure that a pending batch is provided.
	if pendingBatch == nil {
		return zero, fmt.Errorf("no pending batch provided when " +
			"creating pre-commitment output")
	}

	// Ensure that the batch has at least one seedling.
	if len(pendingBatch.Seedlings) == 0 {
		return zero, fmt.Errorf("failed to derive pre-commitment " +
			"delegation key: no seedlings in batch")
	}

	anchor, err := pendingBatch.uniqueAnchorSeedling()
	if err != nil {
		return zero, fmt.Errorf("unable to identify group anchor "+
			"seedling: %w", err)
	}

	return anchor.DelegationKey, nil
}

// fetchPreCommitGroupKey retrieves the group key associated with the
// pre-commitment output from the batch, if the pre-commitment feature is
// enabled and a group key is available.
func fetchPreCommitGroupKey(
	pendingBatch *MintingBatch) (fn.Option[btcec.PublicKey], error) {

	var zero fn.Option[btcec.PublicKey]

	// Return None if no pending batch is provided.
	if pendingBatch == nil {
		return zero, nil
	}

	// If universe commitments are disabled, there is no group key available
	// from the batch to associate with the pre-commitment. Therefore, we
	// return None.
	if !pendingBatch.SupplyCommitments {
		return zero, nil
	}

	// If the batch has no seedlings, we can't derive a group key.
	if len(pendingBatch.Seedlings) == 0 {
		return zero, nil
	}

	anchor, err := pendingBatch.uniqueAnchorSeedling()
	if err != nil {
		return zero, fmt.Errorf("unable to identify group anchor "+
			"seedling: %w", err)
	}

	// If the group info is unset, then there is no pre-commitment group pub
	// key defined in the batch.
	if anchor.GroupInfo == nil {
		return zero, nil
	}

	return fn.Some(anchor.GroupInfo.GroupPubKey), nil
}

// anchorTxFeeRate computes the fee rate for the anchor transaction. If a fee
// rate is manually assigned for the batch, it is used. Otherwise, the fee rate
// is estimated based on the current network conditions.
func (c *ChainPlanter) anchorTxFeeRate(ctx context.Context,
	manualFeeRateOpt fn.Option[chainfee.SatPerKWeight]) (
	chainfee.SatPerKWeight, error) {

	var zero chainfee.SatPerKWeight

	// First, we'll fetch the minimum relay fee for the target chain.
	// We'll use this to ensure that the fee rate we use meets the
	// minimum requirements.
	minRelayFee, err := c.cfg.Wallet.MinRelayFee(ctx)
	if err != nil {
		return zero, fmt.Errorf("unable to obtain min relay fee: %w",
			err)
	}

	// If provided and valid, use the manual fee rate.
	if manualFeeRateOpt.IsSome() {
		manualFeeRate, err := manualFeeRateOpt.UnwrapOrErr(
			fmt.Errorf("code error: no manual fee rate"),
		)
		if err != nil {
			return zero, err
		}

		log.Debug("Manual fee rate specified for batch anchor tx: %s",
			manualFeeRate.String())

		// Ensure that the manual fee rate is above the minimum relay
		// fee.
		if manualFeeRate < minRelayFee {
			return zero, fmt.Errorf("manual fee rate less than "+
				"min relay fee: (manual_fee_rate=%s, "+
				"min_relay_fee=%s)", manualFeeRate.String(),
				minRelayFee.String())
		}

		return manualFeeRate, nil
	}

	log.Debug("No manual fee rate specified for batch, " +
		"querying chain backend for fee rate")

	// We'll ask the chain backend to estimate a fee rate that should get
	// the batch anchor tx into the next block.
	chainFeeRate, err := c.cfg.ChainBridge.EstimateFee(
		ctx, GenesisConfTarget,
	)
	if err != nil {
		return zero, fmt.Errorf("failed to call chain backend for "+
			"fee estimate: %w", err)
	}

	log.Debugf("Chain backend returned fee rate: %s", chainFeeRate.String())

	// If the chain backend provided fee rate is less than the minimum relay
	// fee, we'll use the min relay fee instead.
	if chainFeeRate < minRelayFee {
		log.Debugf("Chain backend provided fee rate less than min "+
			"relay fee, using min relay fee "+
			"(chain_backend_fee_rate=%s, min_relay_fee=%s)",
			chainFeeRate.String(), minRelayFee.String())
		return minRelayFee, nil
	}

	// Otherwise, we'll use the fee rate as provided by the chain
	// backend.
	log.Debugf("Using fee rate from chain backend: %s",
		chainFeeRate.String())
	return chainFeeRate, nil
}

// WalletFundPsbt is a function that funds a PSBT packet.
type WalletFundPsbt = func(ctx context.Context,
	anchorPkt psbt.Packet) (tapsend.FundedPsbt, error)

// fundGenesisPsbt generates a PSBT packet we'll use to create an asset.  In
// order to be able to create an asset, we need an initial genesis outpoint. To
// obtain this we'll ask the wallet to fund a PSBT template for GenesisAmtSats
// (all outputs need to hold some BTC to not be dust), and with a dummy script.
// We need to use a dummy script as we can't know the actual script key since
// that's dependent on the genesis outpoint.
func fundGenesisPsbt(ctx context.Context, chainParams address.ChainParams,
	pendingBatch *MintingBatch,
	walletFundPsbt WalletFundPsbt) (FundedMintAnchorPsbt, error) {

	var zero FundedMintAnchorPsbt

	// If universe commitments are enabled, we formulate a pre-commitment
	// output. This output is spent by the universe commitment transaction.
	var delegationKey fn.Option[DelegationKey]
	if pendingBatch != nil && pendingBatch.SupplyCommitments {
		delegationK, err := fetchDelegationKey(pendingBatch)
		if err != nil {
			return zero, fmt.Errorf("unable to create "+
				"pre-commitment output: %w", err)
		}

		delegationKey = delegationK
	}

	// Derive wire.TxOut from the pre-commitment delegation key, if
	// available. The delegation key is used as the output internal key.
	var preCommitmentTxOut fn.Option[wire.TxOut]
	if delegationKey.IsSome() {
		txOut, err := fn.MapOptionZ(
			delegationKey,
			func(key DelegationKey) lfn.Result[wire.TxOut] {
				return lfn.NewResult(
					PreCommitTxOut(*key.PubKey),
				)
			},
		).Unpack()
		if err != nil {
			return zero, err
		}

		preCommitmentTxOut = fn.Some(txOut)
	}

	// Construct an unfunded anchor PSBT which will eventually become a
	// funded minting anchor transaction.
	genesisPkt, err := unfundedAnchorPsbt(preCommitmentTxOut)
	if err != nil {
		return zero, fmt.Errorf("unable to create anchor template tx: "+
			"%w", err)
	}
	log.Tracef("Unfunded batch anchor PSBT: %v", spew.Sdump(genesisPkt))

	fundedGenesisPkt, err := walletFundPsbt(ctx, genesisPkt)
	if err != nil {
		return zero, fmt.Errorf("unable to fund psbt: %w", err)
	}

	// Sanity check the funded PSBT.
	if fundedGenesisPkt.ChangeOutputIndex == -1 {
		return zero, fmt.Errorf("undefined change output index in " +
			"funded anchor transaction")
	}

	log.Tracef("GenesisPacket: %v", spew.Sdump(fundedGenesisPkt))

	// Classify anchor transaction output indexes.
	anchorOutIndexes, err := anchorTxOutputIndexes(
		fundedGenesisPkt, preCommitmentTxOut,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to determine output indexes: "+
			"%w", err)
	}

	// The presence of a delegation key indicates that a pre-commitment
	// output should exist. Therefore, the index of that output is expected
	// to be defined at this point.
	if delegationKey.IsSome() &&
		anchorOutIndexes.PreCommitOutIdx.IsNone() {

		return zero, fmt.Errorf("pre-commitment output index not found")
	}

	// If pre-commitment output is some, assign the output index to the
	// pre-commitment output.
	var preCommitOutIdx fn.Option[uint32]
	if delegationKey.IsSome() {
		// Ensure that a pre-commitment output index is found.
		outIdx, err := anchorOutIndexes.PreCommitOutIdx.UnwrapOrErr(
			fmt.Errorf("pre-commitment output index not found"),
		)
		if err != nil {
			return zero, err
		}

		preCommitOutIdx = fn.Some(outIdx)
	}

	// If there is a group pub key to associate with the pre-commitment
	// output, fetch it now.
	preCommitGroupPubKey, err := fetchPreCommitGroupKey(pendingBatch)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch pre-commitment "+
			"group key: %w", err)
	}

	// Formulate the pre-commitment output descriptor and finalize
	// pre-commitment output in fundedGenesisPkt.
	var preCommitOut fn.Option[PreCommitmentOutput]
	if delegationKey.IsSome() {
		dKey, err := delegationKey.UnwrapOrErr(
			fmt.Errorf("code error: expected delegation key"),
		)
		if err != nil {
			return zero, err
		}

		outIdx, err := preCommitOutIdx.UnwrapOrErr(
			fmt.Errorf("code error: expected pre-commitment " +
				"output index"),
		)
		if err != nil {
			return zero, err
		}

		preCommitOut = fn.Some(NewPreCommitmentOutput(
			outIdx, dKey, preCommitGroupPubKey,
		))

		// Finalize the pre-commitment output in the fundedGenesisPkt.
		// An output is already present in the unsigned transaction, so
		// we just need to set the corresponding fields in the PSBT.
		bip32Derivation, trBip32Derivation :=
			tappsbt.Bip32DerivationFromKeyDesc(
				dKey, chainParams.HDCoinType,
			)

		pOut := &fundedGenesisPkt.Pkt.Outputs[outIdx]

		pOut.Bip32Derivation = []*psbt.Bip32Derivation{bip32Derivation}
		pOut.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32Derivation,
		}
		pOut.TaprootInternalKey = trBip32Derivation.XOnlyPubKey
	}

	// Formulate a funded minting anchor PSBT from the funded PSBT.
	fundedMintAnchorPsbt, err := NewFundedMintAnchorPsbt(
		fundedGenesisPkt, anchorOutIndexes, preCommitOut,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to create funded minting "+
			"anchor PSBT: %w", err)
	}

	return fundedMintAnchorPsbt, nil
}

// customGenesisPsbt validates and packages a caller-authored mint anchor
// PSBT. Unlike fundGenesisPsbt, this path doesn't ask the backing wallet to
// add or reorder anything in the packet.
func customGenesisPsbt(chainParams address.ChainParams,
	pendingBatch *MintingBatch, packet *psbt.Packet,
	assetAnchorOutIdx uint32,
	changeOutputIndex int32,
	preCommitOutputIndex fn.Option[uint32]) (FundedMintAnchorPsbt, error) {

	var zero FundedMintAnchorPsbt

	if packet == nil || packet.UnsignedTx == nil {
		return zero, fmt.Errorf("custom anchor PSBT is missing its " +
			"unsigned transaction")
	}
	// Run pure structural checks before serialization so malformed callers
	// retain the established, actionable validation errors. None of these
	// checks mutate the caller's packet.
	if len(packet.UnsignedTx.TxIn) == 0 {
		return zero, fmt.Errorf("custom anchor PSBT must have at least " +
			"one input")
	}
	if len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {
		return zero, fmt.Errorf("custom anchor PSBT input maps don't " +
			"match unsigned transaction inputs")
	}
	if len(packet.Outputs) != len(packet.UnsignedTx.TxOut) {
		return zero, fmt.Errorf("custom anchor PSBT output maps don't " +
			"match unsigned transaction outputs")
	}
	if uint64(assetAnchorOutIdx) >= uint64(len(packet.UnsignedTx.TxOut)) {
		return zero, fmt.Errorf("asset anchor output index %d out of "+
			"range", assetAnchorOutIdx)
	}
	if changeOutputIndex < -1 ||
		changeOutputIndex >= int32(len(packet.UnsignedTx.TxOut)) {

		return zero, fmt.Errorf("change output index %d out of range",
			changeOutputIndex)
	}
	if changeOutputIndex == int32(assetAnchorOutIdx) {
		return zero, fmt.Errorf("asset anchor and change output indexes " +
			"must be distinct")
	}

	if err := packet.SanityCheck(); err != nil {
		return zero, fmt.Errorf("invalid custom anchor PSBT: %w", err)
	}
	fee, err := packet.GetTxFee()
	if err != nil {
		return zero, fmt.Errorf("custom anchor PSBT has incomplete or "+
			"invalid input values: %w", err)
	}
	if fee < 0 {
		return zero, fmt.Errorf("custom anchor PSBT outputs exceed " +
			"known input value")
	}
	anchorOutput := packet.UnsignedTx.TxOut[assetAnchorOutIdx]
	eventualAnchorOutput := tapsend.CreateDummyOutput()
	eventualAnchorOutput.Value = anchorOutput.Value
	if eventualAnchorOutput.Value <
		mempool.GetDustThreshold(eventualAnchorOutput) {

		return zero, fmt.Errorf("custom asset anchor output is dust")
	}

	for idx := range packet.Inputs {
		pIn := &packet.Inputs[idx]
		if len(pIn.PartialSigs) != 0 || len(pIn.FinalScriptSig) != 0 ||
			len(pIn.FinalScriptWitness) != 0 ||
			len(pIn.TaprootKeySpendSig) != 0 ||
			len(pIn.TaprootScriptSpendSig) != 0 {

			return zero, fmt.Errorf("custom anchor PSBT must be " +
				"unsigned before batch preparation")
		}
	}

	// A custom anchor's internal key is carried in the standard PSBT output
	// field. This lets the caretaker derive the final output script without
	// conflating the externally controlled key with the batch key.
	pOut := packet.Outputs[assetAnchorOutIdx]
	if len(pOut.TaprootInternalKey) != schnorr.PubKeyBytesLen {
		return zero, fmt.Errorf("custom asset anchor output must specify " +
			"a taproot internal key")
	}
	if _, err := schnorr.ParsePubKey(pOut.TaprootInternalKey); err != nil {
		return zero, fmt.Errorf("invalid custom asset anchor internal "+
			"key: %w", err)
	}
	if _, err := customAnchorKeyDesc(
		chainParams, packet, assetAnchorOutIdx,
	); err != nil {

		return zero, err
	}
	if pOut.TaprootTapTree != nil {
		return zero, fmt.Errorf("custom asset anchor output must not " +
			"specify a PSBT tap tree; use the batch sibling fields")
	}

	// For ordinary batches, exclusion-proof validation is also entirely
	// read-only and must run before serialization so malformed metadata gets
	// its established, precise error without touching the caller's packet.
	if pendingBatch == nil || !pendingBatch.SupplyCommitments {
		if err := validateExclusionProofOutputs(
			packet, assetAnchorOutIdx,
		); err != nil {

			return zero, err
		}
	}

	// All caller-authored validation above is pure. Only now make the deep
	// copy that tapd will retain and mutate with lifecycle/precommit metadata.
	var packetBytes bytes.Buffer
	if err := packet.Serialize(&packetBytes); err != nil {
		return zero, fmt.Errorf("unable to copy custom anchor PSBT: %w", err)
	}
	packet, err = psbt.NewFromRawBytes(&packetBytes, false)
	if err != nil {
		return zero, fmt.Errorf("unable to copy custom anchor PSBT: %w", err)
	}
	stripTapdCustomAnchorMarkers(packet)

	funded := tapsend.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: changeOutputIndex,
	}
	markCustomAnchorPsbt(packet)

	var preCommitOut fn.Option[PreCommitmentOutput]
	var preCommitIdx fn.Option[uint32]
	if pendingBatch != nil && pendingBatch.SupplyCommitments {
		idx, err := preCommitOutputIndex.UnwrapOrErr(fmt.Errorf(
			"custom supply commitment batch requires a pre-commitment " +
				"output index",
		))
		if err != nil {
			return zero, err
		}
		if uint64(idx) >= uint64(len(packet.UnsignedTx.TxOut)) ||
			idx == assetAnchorOutIdx || idx == uint32(changeOutputIndex) {

			return zero, fmt.Errorf("invalid pre-commitment output "+
				"index %d", idx)
		}

		delegationKey, err := fetchDelegationKey(pendingBatch)
		if err != nil {
			return zero, err
		}
		dKey, err := delegationKey.UnwrapOrErr(fmt.Errorf(
			"missing supply commitment delegation key",
		))
		if err != nil {
			return zero, err
		}
		expectedOutput, err := PreCommitTxOut(*dKey.PubKey)
		if err != nil {
			return zero, err
		}
		actualOutput := packet.UnsignedTx.TxOut[idx]
		if actualOutput.Value != expectedOutput.Value ||
			!bytes.Equal(actualOutput.PkScript, expectedOutput.PkScript) {

			return zero, fmt.Errorf("pre-commitment output %d doesn't "+
				"match the batch delegation key", idx)
		}

		bip32Derivation, trBip32Derivation :=
			tappsbt.Bip32DerivationFromKeyDesc(
				dKey, chainParams.HDCoinType,
			)
		pOut := &packet.Outputs[idx]
		pOut.Bip32Derivation = []*psbt.Bip32Derivation{bip32Derivation}
		pOut.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32Derivation,
		}
		pOut.TaprootInternalKey = trBip32Derivation.XOnlyPubKey

		groupKey, err := fetchPreCommitGroupKey(pendingBatch)
		if err != nil {
			return zero, err
		}
		preCommitOut = fn.Some(NewPreCommitmentOutput(
			idx, dKey, groupKey,
		))
		preCommitIdx = fn.Some(idx)
	} else if preCommitOutputIndex.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index specified " +
			"for batch without supply commitments")
	}
	if err := validateExclusionProofOutputs(
		packet, assetAnchorOutIdx,
	); err != nil {

		return zero, err
	}
	indexes := AnchorTxOutputIndexes{
		AssetAnchorOutIdx: assetAnchorOutIdx,
		ChangeOutIdx:      0,
		PreCommitOutIdx:   preCommitIdx,
	}

	return NewFundedMintAnchorPsbt(
		funded, indexes, preCommitOut,
	)
}

// customAnchorKeyDesc extracts the lnd key locator that controls a caller's
// selected anchor internal key. Both BIP32 output records are required and
// cross-checked so a random point or forged locator can't be persisted as a
// wallet-managed output.
func customAnchorKeyDesc(chainParams address.ChainParams, packet *psbt.Packet,
	assetAnchorOutIdx uint32) (keychain.KeyDescriptor, error) {

	var zero keychain.KeyDescriptor
	if packet == nil || uint64(assetAnchorOutIdx) >=
		uint64(len(packet.Outputs)) {

		return zero, fmt.Errorf("custom anchor output metadata is missing")
	}

	pOut := packet.Outputs[assetAnchorOutIdx]
	if len(pOut.Bip32Derivation) != 1 ||
		len(pOut.TaprootBip32Derivation) != 1 {

		return zero, fmt.Errorf("custom asset anchor output must specify " +
			"exactly one BIP32 and Taproot BIP32 derivation")
	}

	bip32Derivation := pOut.Bip32Derivation[0]
	taprootDerivation := pOut.TaprootBip32Derivation[0]
	desc, err := tappsbt.KeyDescFromBip32Derivation(bip32Derivation)
	if err != nil {
		return zero, fmt.Errorf("invalid custom anchor key derivation: %w",
			err)
	}

	expectedBip32, expectedTaproot := tappsbt.Bip32DerivationFromKeyDesc(
		desc, chainParams.HDCoinType,
	)
	if !bytes.Equal(expectedBip32.PubKey, bip32Derivation.PubKey) ||
		!slices.Equal(expectedBip32.Bip32Path, bip32Derivation.Bip32Path) ||
		!bytes.Equal(
			expectedTaproot.XOnlyPubKey,
			taprootDerivation.XOnlyPubKey,
		) || !slices.Equal(
		expectedTaproot.Bip32Path, taprootDerivation.Bip32Path,
	) || len(taprootDerivation.LeafHashes) != 0 ||
		!bytes.Equal(
			pOut.TaprootInternalKey,
			taprootDerivation.XOnlyPubKey,
		) {

		return zero, fmt.Errorf("custom anchor key derivation doesn't " +
			"match its internal key or network path")
	}

	return desc, nil
}

// validateExclusionProofOutputs ensures every non-anchor P2TR output can be
// represented in the minting proofs. Doing this before broadcast prevents an
// otherwise valid mint from becoming unprovable only after confirmation.
func validateExclusionProofOutputs(packet *psbt.Packet,
	assetAnchorOutIdx uint32) error {

	if packet == nil || packet.UnsignedTx == nil {
		return fmt.Errorf("cannot validate exclusion proof outputs without " +
			"an unsigned transaction")
	}

	baseProof := &proof.BaseProofParams{}
	err := proof.AddExclusionProofs(
		baseProof, packet.UnsignedTx, packet.Outputs,
		func(outputIndex uint32) bool {
			return outputIndex == assetAnchorOutIdx
		},
	)
	if err != nil {
		return fmt.Errorf("anchor PSBT cannot produce exclusion "+
			"proofs: %w", err)
	}

	return nil
}

// filterSeedlingsWithGroup separates a set of seedlings into two sets based on
// their relation to an asset group, which has not been constructed yet.
func filterSeedlingsWithGroup(
	seedlings map[string]*Seedling) (map[string]*Seedling,
	map[string]*Seedling) {

	withGroup := make(map[string]*Seedling)
	withoutGroup := make(map[string]*Seedling)
	fn.ForEachMapItem(seedlings, func(name string, seedling *Seedling) {
		switch {
		case seedling.GroupInfo != nil || seedling.GroupAnchor != nil ||
			seedling.EnableEmission:

			withGroup[name] = seedling

		default:
			withoutGroup[name] = seedling
		}
	})

	return withGroup, withoutGroup
}

// buildGroupReqs creates group key requests and asset group genesis TXs for
// seedlings that are part of a funded batch.
func buildGroupReqs(genesisPoint wire.OutPoint, assetOutputIndex uint32,
	genBuilder asset.GenesisTxBuilder,
	groupSeedlings map[string]*Seedling) ([]asset.GroupKeyRequest,
	[]asset.GroupVirtualTx, error) {

	// Seedlings that anchor a group may be referenced by other seedlings,
	// and therefore need to be mapped to sprouts first so that we derive
	// the initial tweaked group key early.
	orderedSeedlings := SortSeedlings(maps.Values(groupSeedlings))
	newGroups := make(map[string]*asset.AssetGroup)
	groupReqs := make([]asset.GroupKeyRequest, 0, len(orderedSeedlings))
	genTXs := make([]asset.GroupVirtualTx, 0, len(orderedSeedlings))

	for _, seedlingName := range orderedSeedlings {
		seedling := groupSeedlings[seedlingName]
		assetGen := seedling.Genesis(genesisPoint, assetOutputIndex)

		// If the seedling has a meta data reveal set, then we'll bind
		// that by including the hash of the meta data in the asset
		// genesis.
		if seedling.Meta != nil {
			assetGen.MetaHash = seedling.Meta.MetaHash()
		}

		var (
			amount uint64

			// groupInfo represents the group key and genesis data
			// for the asset group. This is populated if the
			// seedling specifies a group key or if it specifies
			// a group anchor and the corresponding group already
			// exists.
			groupInfo *asset.AssetGroup

			protoAsset *asset.Asset
			err        error
		)

		// Determine the amount for the actual asset.
		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		// If the seedling has a group key specified,
		// that group key was validated earlier. We need to
		// sign the new genesis with that group key.
		if seedling.HasGroupKey() {
			groupInfo = seedling.GroupInfo
		}

		// If the seedling has a group anchor specified, that anchor
		// was validated earlier and the corresponding group has already
		// been created. We need to look up the group key and sign
		// the asset genesis with that key.
		if seedling.GroupAnchor != nil {
			groupInfo = newGroups[*seedling.GroupAnchor]
		}

		// If a group witness needs to be produced, then we will need a
		// partially filled asset as part of the signing process.
		if groupInfo != nil || seedling.EnableEmission {
			protoAsset, err = asset.New(
				assetGen, amount, 0, 0, seedling.ScriptKey,
				nil,
				asset.WithAssetVersion(seedling.AssetVersion),
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to create "+
					"asset for group key signing: %w", err)
			}
		}

		// If groupInfo is specified, a group key already exists for the
		// seedling. This key will be used to create a placeholder group
		// key request, which will then be used to generate a group
		// virtual transaction.
		if groupInfo != nil {
			groupReq, err := asset.NewGroupKeyRequest(
				groupInfo.GroupKey.RawKey, seedling.ExternalKey,
				*groupInfo.Genesis, protoAsset,
				groupInfo.GroupKey.TapscriptRoot,
				groupInfo.GroupKey.CustomTapscriptRoot,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to "+
					"request asset group membership: %w",
					err)
			}

			genTx, err := groupReq.BuildGroupVirtualTx(
				genBuilder,
			)
			if err != nil {
				return nil, nil, err
			}

			groupReqs = append(groupReqs, *groupReq)
			genTXs = append(genTXs, *genTx)

			// TODO(ffranr): Should we continue to the next seedling
			//  at this point? The group key request and virtual
			//  transaction have been created.
		}

		// If emission isn't enabled, we don't have to do anything else
		// for this seedling.
		if !seedling.EnableEmission {
			continue
		}

		// If emission is enabled, an internal key for the group should
		// already be specified. Use that to derive the key group
		// signature along with the tweaked key group.
		if seedling.GroupInternalKey == nil &&
			seedling.ExternalKey.IsNone() {

			return nil, nil, fmt.Errorf("unable to " +
				"derive group key, both internal and " +
				"external keys are unspecified")
		}

		// If seedling.GroupTapscriptRoot is specified and the
		// seedling includes an external key, we must use group
		// key V1. As a result, seedling.GroupTapscriptRoot will
		// be treated as a custom tapscript subtree root, which
		// we will graft into the group key's tapscript tree. We
		// will proceed with this now.
		var (
			tsRoot         = seedling.GroupTapscriptRoot
			customRootHash fn.Option[chainhash.Hash]
		)
		if seedling.ExternalKey.IsSome() {
			// If seedling.GroupTapscriptRoot is specified,
			// set it to the custom root hash. Then we will
			// calculate a new tapscript root hash which
			// includes the custom root as a grafted
			// subtree.
			if len(tsRoot) > 0 {
				r, err := chainhash.NewHash(tsRoot)
				if err != nil {
					return nil, nil, err
				}

				customRootHash = fn.Some(*r)
			}

			// Construct an asset group tapscript tree,
			// incorporating the optional custom subtree
			// through grafting.
			//
			// At this point, we are constructing the group
			// tapscript tree root whether the
			// customRootHash is defined.
			tapscriptTree, _, err := asset.NewGroupKeyTapscriptRoot(
				// TODO(guggero): Make this configurable in the
				// future.
				asset.PedersenVersion, assetGen.ID(),
				customRootHash,
			)
			if err != nil {
				return nil, nil, err
			}

			// Update the group tapscript tree root hash to
			// the new root hash. If customRootHash is
			// defined, the new root hash incorporates it as
			// a subtree.
			tsRoot = fn.ByteSlice(tapscriptTree.Root())
		}

		// The group internal key should be set at this point.
		//
		// If an external key is present, the internal key
		// should be a public key derived from the external
		// key.
		if seedling.GroupInternalKey == nil {
			return nil, nil, fmt.Errorf("internal key is " +
				"missing for seedling")
		}

		groupReq, err := asset.NewGroupKeyRequest(
			*seedling.GroupInternalKey,
			seedling.ExternalKey, assetGen,
			protoAsset, tsRoot, customRootHash,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to "+
				"request asset group creation: %w", err)
		}

		genTx, err := groupReq.BuildGroupVirtualTx(
			genBuilder,
		)
		if err != nil {
			return nil, nil, err
		}

		groupReqs = append(groupReqs, *groupReq)
		genTXs = append(genTXs, *genTx)

		newGroupKey := &asset.GroupKey{
			Version:             groupReq.Version,
			RawKey:              *seedling.GroupInternalKey,
			TapscriptRoot:       seedling.GroupTapscriptRoot,
			CustomTapscriptRoot: customRootHash,
		}

		newGroups[seedlingName] = &asset.AssetGroup{
			Genesis:  &assetGen,
			GroupKey: newGroupKey,
		}
	}

	return groupReqs, genTXs, nil
}

// freezeMintingBatch freezes a target minting batch which means that no new
// assets can be added to the batch.
func freezeMintingBatch(ctx context.Context, batchStore MintingStore,
	batch *MintingBatch) error {

	batchKey := batch.BatchKey.PubKey

	log.Infof("Freezing MintingBatch(key=%x, num_assets=%v)",
		batchKey.SerializeCompressed(), len(batch.Seedlings))

	// In order to freeze a batch, we need to update the state of the batch
	// to BatchStateFrozen, meaning that no other changes can happen.
	//
	// TODO(roasbeef): assert not in some other state first?
	return batchStore.UpdateBatchState(
		ctx, batch, BatchStateFrozen,
	)
}

// ErrDuplicatePreBroadcastBatch is returned when a new minting batch
// cannot be persisted because another batch already occupies the
// pre-broadcast singleton slot (BatchStatePending or
// BatchStateFrozen) enforced by the partial unique index added in
// migration 000061. This can happen transiently right after a
// restart, while a resumed batch is still working towards broadcast.
var ErrDuplicatePreBroadcastBatch = errors.New("another minting batch " +
	"is already awaiting broadcast; wait for it to be broadcast or " +
	"cancel it before creating a new batch")

// checkSingletonInvariant verifies that at most one batch in the
// supplied slice is in a pre-broadcast state (BatchStatePending or
// BatchStateFrozen). The invariant is enforced at the DB layer by
// the partial unique index added in migration 000061; this Go-level
// check exists as defense in depth and to produce a human-readable
// diagnostic naming the offending batch keys, since a raw SQL
// constraint error from a downstream insert is harder to act on.
//
// The check is called from ChainPlanter.Start() after
// FetchNonFinalBatches. If it fails, startup is aborted so the
// operator can investigate rather than letting the daemon run with
// ambiguous "which batch is current?" semantics.
func checkSingletonInvariant(batches []*MintingBatch) error {
	var preBroadcastKeys []string
	for _, batch := range batches {
		switch batch.State() {
		case BatchStatePending, BatchStateFrozen:
			preBroadcastKeys = append(
				preBroadcastKeys,
				hex.EncodeToString(
					batch.BatchKey.PubKey.
						SerializeCompressed(),
				),
			)

		default:
			// Only pre-broadcast states are constrained by
			// the singleton index; ignore everything else.
		}
	}

	if len(preBroadcastKeys) <= 1 {
		return nil
	}

	return fmt.Errorf("singleton pre-broadcast batch invariant "+
		"violated: found %d batches in BatchStatePending or "+
		"BatchStateFrozen (keys: %v); at most one is permitted. "+
		"Resolve by running `tapd --repair.cancel-duplicate-batches` "+
		"to cancel all but the most recent, then restart",
		len(preBroadcastKeys), preBroadcastKeys)
}

// filterFinalizedBatches separates a set of batches into two sets based on
// their batch state.
func filterFinalizedBatches(batches []*MintingBatch) ([]*MintingBatch,
	[]*MintingBatch) {

	finalized := []*MintingBatch{}
	nonFinalized := []*MintingBatch{}

	fn.ForEach(batches, func(batch *MintingBatch) {
		switch batch.State() {
		case BatchStateFinalized:
			finalized = append(finalized, batch)
		default:
			nonFinalized = append(nonFinalized, batch)
		}
	})

	return finalized, nonFinalized
}

// fetchFinalizedBatch fetches the assets of a batch in their genesis state,
// given a batch populated with seedlings.
func fetchFinalizedBatch(ctx context.Context, batchStore MintingStore,
	archiver proof.Archiver, batch *MintingBatch) (*MintingBatch, error) {

	genesisPkt := batch.GenesisPacket

	if genesisPkt == nil {
		return nil, fmt.Errorf("batch is missing anchor tx packet")
	}

	// Collect genesis TX information from the batch to build the proof
	// locators.
	anchorOutputIndex := genesisPkt.AssetAnchorOutIdx

	genOutpoint, err := genesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	signedTx, err := psbt.Extract(batch.GenesisPacket.Pkt)
	if err != nil {
		return nil, err
	}

	genScript := signedTx.TxOut[anchorOutputIndex].PkScript
	anchorOutpoint := wire.OutPoint{
		Hash:  signedTx.TxHash(),
		Index: anchorOutputIndex,
	}

	batchAssets := make([]*asset.Asset, 0, len(batch.Seedlings))
	assetMetas := make(AssetMetas)
	for _, seedling := range batch.Seedlings {
		gen := seedling.Genesis(genOutpoint, anchorOutputIndex)
		issuanceProof, err := archiver.FetchIssuanceProof(
			ctx, gen.ID(), anchorOutpoint,
		)
		if err != nil {
			return nil, err
		}

		proofFile, err := issuanceProof.AsFile()
		if err != nil {
			return nil, err
		}

		if proofFile.NumProofs() != 1 {
			return nil, fmt.Errorf("expected single proof for " +
				"issuance proof")
		}

		rawProof, err := proofFile.RawLastProof()
		if err != nil {
			return nil, err
		}

		// Decode the sprouted asset from the issuance proof.
		var sproutedAsset asset.Asset
		assetRecord := proof.AssetLeafRecord(&sproutedAsset)
		err = proof.SparseDecode(bytes.NewReader(rawProof), assetRecord)
		if err != nil {
			return nil, fmt.Errorf("unable to decode issuance "+
				"proof: %w", err)
		}

		if !sproutedAsset.IsGenesisAsset() {
			return nil, fmt.Errorf("decoded asset is not a " +
				"genesis asset")
		}

		// Populate the key info for the script key and group key.
		if sproutedAsset.ScriptKey.PubKey == nil {
			return nil, fmt.Errorf("decoded asset is missing " +
				"script key")
		}

		tweakedScriptKey, err := batchStore.FetchScriptKeyByTweakedKey(
			ctx, sproutedAsset.ScriptKey.PubKey,
		)
		if err != nil {
			return nil, err
		}

		sproutedAsset.ScriptKey.TweakedScriptKey = tweakedScriptKey
		if sproutedAsset.GroupKey != nil {
			assetGroup, err := batchStore.FetchGroupByGroupKey(
				ctx, &sproutedAsset.GroupKey.GroupPubKey,
			)
			if err != nil {
				return nil, err
			}

			sproutedAsset.GroupKey = assetGroup.GroupKey
		}

		batchAssets = append(batchAssets, &sproutedAsset)
		scriptKey := asset.ToSerialized(sproutedAsset.ScriptKey.PubKey)
		assetMetas[scriptKey] = seedling.Meta
	}

	// Verify that we can reconstruct the genesis output script used in the
	// anchor TX.
	batchSibling := batch.TapSibling()
	var tapSibling *chainhash.Hash
	if len(batchSibling) != 0 {
		var err error
		tapSibling, err = chainhash.NewHash(batchSibling)
		if err != nil {
			return nil, err
		}
	}

	mintingInternalKey, err := batch.MintingInternalKey()
	if err != nil {
		return nil, err
	}
	tapCommitment, err := VerifyOutputScript(
		mintingInternalKey, tapSibling, genScript, batchAssets,
	)

	if err != nil {
		return nil, err
	}

	// With the batch assets validated, construct the populated finalized
	// batch.
	batch.Seedlings = nil
	finalizedBatch := batch.Copy()
	finalizedBatch.RootAssetCommitment = tapCommitment
	finalizedBatch.AssetMetas = assetMetas

	return finalizedBatch, nil
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func listBatches(ctx context.Context, batchStore MintingStore,
	archiver proof.Archiver, genBuilder asset.GenesisTxBuilder,
	params ListBatchesParams) ([]*VerboseBatch, error) {

	var (
		batches []*MintingBatch
		err     error
	)

	switch {
	case params.BatchKey == nil:
		batches, err = batchStore.FetchAllBatches(ctx)
	default:
		var batch *MintingBatch
		batch, err = batchStore.FetchMintingBatch(ctx, params.BatchKey)
		batches = []*MintingBatch{batch}
	}
	if err != nil {
		return nil, err
	}

	var (
		finalBatches, nonFinalBatches = filterFinalizedBatches(batches)
		sortedBatches                 []*MintingBatch
	)

	switch {
	case len(finalBatches) == 0:
		sortedBatches = batches

	// For finalized batches, we need to fetch the assets from the proof
	// archiver, not the DB.
	default:
		finalizedBatches := make([]*MintingBatch, 0, len(finalBatches))
		for _, batch := range finalBatches {
			finalizedBatch, err := fetchFinalizedBatch(
				ctx, batchStore, archiver, batch,
			)
			if err != nil {
				return nil, err
			}

			finalizedBatches = append(
				finalizedBatches, finalizedBatch,
			)
		}

		// Re-sort the batches by creation time for consistent display.
		allBatches := append(nonFinalBatches, finalizedBatches...)
		slices.SortFunc(allBatches, func(a, b *MintingBatch) int {
			return a.CreationTime.Compare(b.CreationTime)
		})

		sortedBatches = allBatches
	}

	// Return the batches without any extra asset group info.
	if !params.Verbose {
		batches := fn.Map(
			sortedBatches,
			func(b *MintingBatch) *VerboseBatch {
				return &VerboseBatch{
					MintingBatch:      b,
					UnsealedSeedlings: nil,
				}
			},
		)

		return batches, nil
	}

	// Formulate verbose batches from the sorted batches.
	verboseBatches := make([]*VerboseBatch, 0, len(sortedBatches))

	for idx := range sortedBatches {
		currentBatch := sortedBatches[idx]

		// The batch must be pending, funded, and have seedlings for us
		// to show pending asset group information.
		switch {
		case currentBatch.State() != BatchStatePending:
			continue
		case !currentBatch.IsFunded():
			// The batch isn't funded yet, so we can't display any
			// pending asset group information. Funding is required
			// because the anchor transaction outpoint is needed to
			// formulate pending asset group key requests.
			continue
		case len(currentBatch.Seedlings) == 0:
			continue
		default:
		}

		verboseBatch, err := newVerboseBatch(currentBatch, genBuilder)
		if err != nil {
			return nil, err
		}

		verboseBatches = append(verboseBatches, verboseBatch)
	}

	return verboseBatches, nil
}

// newVerboseBatch constructs a new verbose batch from a given minting batch.
// The verbose batch includes extra information about the asset group, if any.
func newVerboseBatch(currentBatch *MintingBatch,
	genBuilder asset.GenesisTxBuilder) (*VerboseBatch, error) {

	verboseBatch := &VerboseBatch{
		MintingBatch: currentBatch.Copy(),
	}

	// Filter the batch seedlings to only consider those that will become
	// grouped assets. If there are no such seedlings, then there is no
	// extra information to add.
	groupSeedlings, _ := filterSeedlingsWithGroup(
		currentBatch.Seedlings,
	)
	if len(groupSeedlings) == 0 {
		return verboseBatch, nil
	}

	// Before we can build the group key requests for each seedling, we must
	// fetch the genesis point and anchor index for the batch.
	anchorOutputIndex := currentBatch.GenesisPacket.AssetAnchorOutIdx

	genesisPkt := currentBatch.GenesisPacket
	genesisPoint, err := genesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	// Construct the group key requests and group virtual TXs for each
	// seedling. With these we can verify provided asset group witnesses, or
	// attempt to derive asset group witnesses if needed.
	groupReqs, genTXs, err := buildGroupReqs(
		genesisPoint, anchorOutputIndex, genBuilder, groupSeedlings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to build group requests: %w",
			err)
	}

	if len(groupReqs) != len(genTXs) {
		return nil, fmt.Errorf("mismatched number of group requests " +
			"and virtual TXs")
	}

	// Copy existing seedlings into the unsealed seedling map; we'll clear
	// the batch seedlings after adding group information.
	verboseBatch.UnsealedSeedlings = make(
		map[string]*UnsealedSeedling,
		len(currentBatch.Seedlings),
	)
	for k, v := range currentBatch.Seedlings {
		verboseBatch.UnsealedSeedlings[k] = &UnsealedSeedling{
			Seedling:          v,
			PendingAssetGroup: nil,
		}
	}

	// Match each group key request and group virtual TX with the
	// corresponding seedling.
	for i := 0; i < len(groupReqs); i++ {
		seedlingName := groupReqs[i].NewAsset.Genesis.Tag
		seedling, ok := verboseBatch.
			UnsealedSeedlings[seedlingName]
		if !ok {
			return nil, fmt.Errorf("unable to find seedling with "+
				"tag matching asset group: %s", seedlingName)
		}

		seedling.PendingAssetGroup = &PendingAssetGroup{
			GroupKeyRequest: groupReqs[i],
			GroupVirtualTx:  genTXs[i],
		}
	}

	// Clear the original batch seedlings so each asset is only represented
	// once.
	verboseBatch.Seedlings = nil

	return verboseBatch, nil
}

// canCancelBatch returns a batch key if the planter is in a state where a batch
// can be cancelled. This does not account for the state of a caretaker that
// may be managing a batch.
func (c *ChainPlanter) canCancelBatch() (*btcec.PublicKey, error) {
	caretakerCount := len(c.caretakers)

	switch caretakerCount {
	case 0:
		// If there are no caretakers, the only batch we could cancel
		// would be the current pending batch.
		if c.pendingBatch == nil {
			return nil, fmt.Errorf("no pending batch")
		}

		return c.pendingBatch.BatchKey.PubKey, nil
	case 1:
		// If there is exactly one caretaker, our pending batch
		// must be empty for the cancel target to be
		// unambiguous. Both can coexist legitimately: the
		// caretaker may be handling a post-broadcast batch
		// (Committed/Broadcast/Confirmed) while a fresh
		// Pending/Frozen batch has begun in c.pendingBatch. The
		// singleton constraint added in migration 000061 only
		// applies to {Pending, Frozen}, so this case is real,
		// not unreachable.
		if c.pendingBatch != nil {
			return nil, fmt.Errorf("cancellation ambiguous: " +
				"pending batch and an active caretaker " +
				"coexist; cancel-by-batch-key not " +
				"implemented")
		}

		batchKeys := maps.Keys(c.caretakers)
		batchKey, err := btcec.ParsePubKey(batchKeys[0][:])
		if err != nil {
			return nil, fmt.Errorf("bad caretaker key: %w", err)
		}

		return batchKey, nil
	default:
	}

	// Multiple caretakers can coexist when several post-broadcast
	// batches are awaiting confirmation in parallel. The singleton
	// constraint added in migration 000061 does not forbid this; it
	// only constrains {Pending, Frozen}.
	return nil, fmt.Errorf("cancellation ambiguous: %d active "+
		"caretakers; cancel-by-batch-key not implemented",
		caretakerCount)
}

// cancelMintingBatch attempts to cancel a target minting batch. This can fail
// if the batch is managed by a caretaker and has already been broadcast.
func (c *ChainPlanter) cancelMintingBatch(ctx context.Context,
	batchKey *btcec.PublicKey) error {

	// The target batch may have already been assigned a caretaker. If so,
	// we need to signal to the caretaker to cancel the batch.
	batchKeySerialized := asset.ToSerialized(batchKey)
	caretaker, ok := c.caretakers[batchKeySerialized]
	if ok {
		log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
			batchKeySerialized, len(caretaker.cfg.Batch.Seedlings))

		caretaker.cfg.CancelReqChan <- struct{}{}

		// Wait for the caretaker to reply to the cancellation request.
		// If the request succeeded, the caretaker will update the
		// batch state on disk.
		select {
		case cancelResp := <-caretaker.cfg.CancelRespChan:
			// If the caretaker returned a batch state, then batch
			// cancellation was possible and attempted. This means
			// that the caretaker is shut down and the planter
			// must delete it.
			if cancelResp.cancelAttempted {
				delete(c.caretakers, batchKeySerialized)
			}

			return cancelResp.err

		case <-c.Quit:
			return nil
		}
	}

	log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
		batchKeySerialized, len(c.pendingBatch.Seedlings))

	// If the target batch was not assigned a caretaker, the only
	// non-cancelled batch in play is c.pendingBatch (canCancelBatch
	// guarantees this). Determine the correct terminal state, then update
	// both the disk row and the in-memory batch in a single atomic call.
	var cancelState BatchState
	switch c.pendingBatch.State() {
	case BatchStatePending, BatchStateFrozen:
		cancelState = BatchStateSeedlingCancelled

	case BatchStateCommitted:
		if customAnchorPublicationPending(c.pendingBatch) {

			return fmt.Errorf("custom anchor publication status is " +
				"ambiguous and is not cancellable")
		}

		cancelState = BatchStateSproutCancelled

	default:
		return fmt.Errorf("batch state %v is not cancellable",
			c.pendingBatch.State())
	}

	err := c.cfg.Log.UpdateBatchState(
		ctx, c.pendingBatch, cancelState,
	)
	if err != nil {
		return fmt.Errorf("unable to cancel minting batch: %w", err)
	}

	// Only release leases after cancellation is durable. A partial wallet
	// RPC failure can then at worst leave a short-lived stale lease; it can
	// never leave an active batch partially unprotected. Cancellation itself
	// remains successful and the release helper attempts every recorded input.
	if c.pendingBatch.GenesisPacket != nil &&
		isCustomAnchorPsbt(c.pendingBatch.GenesisPacket.Pkt) {

		if err := releaseCustomAnchorLeases(
			ctx, c.cfg.Wallet,
			customAnchorLeaseID(c.pendingBatch.BatchKey.PubKey),
			c.pendingBatch.GenesisPacket,
		); err != nil {
			log.Warnf("Unable to release one or more cancelled custom "+
				"anchor input leases: %v", err)
		}
	}

	return nil
}

// cancelFailedBatch cancels a batch whose caretaker reported a
// broadcast-path error, so the batch isn't left occupying the
// pre-broadcast singleton slot enforced by the migration 000061
// index. Only Pending and Frozen batches are cancelled: those are
// the states the index constrains, and no sprouts exist yet, so
// SeedlingCancelled applies. Batches at Committed or beyond are
// left untouched. They don't occupy the singleton slot, and the
// restart path resumes and retries them, so cancelling here would
// turn a transient failure (say, a brief signer outage) into a
// permanent one that forces a re-mint with new asset IDs.
//
// The returned error is non-nil only when the batch occupied the
// singleton slot and the on-disk cancellation failed, i.e. exactly
// when the slot is still occupied and the batch still needs an
// owner.
func (c *ChainPlanter) cancelFailedBatch(batch *MintingBatch) error {
	batchKeySerial := asset.ToSerialized(batch.BatchKey.PubKey)

	batchState := batch.State()
	if batchState != BatchStatePending && batchState != BatchStateFrozen {
		log.Infof("Leaving failed batch (%x) at state %v; restart "+
			"will resume it", batchKeySerial[:], batchState)
		return nil
	}

	ctx, cancel := c.WithCtxQuit()
	defer cancel()
	err := c.cfg.Log.UpdateBatchState(
		ctx, batch, BatchStateSeedlingCancelled,
	)
	if err != nil {
		return fmt.Errorf("unable to cancel failed batch (%x): %w",
			batchKeySerial[:], err)
	}

	return nil
}

// watchResumedCaretaker waits for a caretaker launched for a resumed
// batch to either broadcast its batch or fail beforehand. On a
// pre-broadcast failure it cancels the batch, freeing the singleton
// slot enforced by the migration 000061 index, and hands the dead
// caretaker to the gardener via the completion signal so it is
// stopped and removed from the caretaker set (the gardener owns that
// set, so removal must happen there). The interactive finalize
// handler performs the equivalent duties for caretakers launched via
// FinalizeBatch.
func (c *ChainPlanter) watchResumedCaretaker(caretaker *BatchCaretaker) {
	defer c.Wg.Done()

	batchKey := asset.ToSerialized(caretaker.cfg.Batch.BatchKey.PubKey)

	select {
	case <-caretaker.cfg.BroadcastCompleteChan:
		// The batch reached broadcast; from here on the caretaker
		// reports completion through the completion signal on its
		// own.

	case err := <-caretaker.cfg.BroadcastErrChan:
		log.Errorf("Resumed batch (%x) failed before broadcast: %v",
			batchKey[:], err)

		// On the resume path there is no in-memory owner to
		// preserve, so a failed cancellation can only be
		// logged; restarting tapd retries the resume.
		cancelErr := c.cancelFailedBatch(caretaker.cfg.Batch)
		if cancelErr != nil {
			log.Errorf("%v; the pre-broadcast singleton slot is "+
				"still occupied on disk, so new batches will "+
				"be rejected until tapd is restarted",
				cancelErr)
		}

		select {
		case c.completionSignals <- batchKey:
		case <-c.Quit:
		}

	case <-c.Quit:
	}
}

// gardener is responsible for collecting new potential taproot asset
// seeds/seedlings into a batch to ultimately be anchored in a genesis output
// creating the assets from seedlings into sprouts, and eventually fully grown
// assets.
func (c *ChainPlanter) gardener() {
	defer c.Wg.Done()
	leaseRenewalInterval := c.cfg.CustomAnchorLeaseRenewalInterval
	if leaseRenewalInterval <= 0 {
		leaseRenewalInterval = customAnchorLeaseRenewalInterval
	}
	leaseRenewalTicker := time.NewTicker(leaseRenewalInterval)
	defer leaseRenewalTicker.Stop()

	// When this exits due to the quit signal, we also want to stop all the
	// active caretakers as well.
	defer c.stopCaretakers()

	log.Infof("Gardener for ChainPlanter now active!")

	for {
		select {
		case result := <-c.startupCaretakerResults:
			caretaker, ok := c.caretakers[result.batchKey]
			if !ok || caretaker != result.caretaker {
				// A fast confirmation can remove the caretaker before the
				// gardener consumes its forwarded publication success. The
				// matching reservation is still safe to release.
				if result.err == nil && c.pendingBatch != nil &&
					asset.ToSerialized(
						c.pendingBatch.BatchKey.PubKey,
					) == result.batchKey {

					c.pendingBatch = nil
				}

				log.Warnf("Ignoring stale startup caretaker result for %x",
					result.batchKey[:])
				continue
			}

			if result.err == nil {
				// Publication succeeded. Release the exclusive recovery
				// slot, but retain the caretaker while it waits for
				// confirmation.
				if c.pendingBatch != nil &&
					asset.ToSerialized(
						c.pendingBatch.BatchKey.PubKey,
					) == result.batchKey {

					c.pendingBatch = nil
				}

				continue
			}

			// The caretaker has exited before publication completed. Remove
			// it before returning the same batch to the pending slot so
			// Finalize and Cancel cannot target a dead caretaker.
			if err := caretaker.Stop(); err != nil {
				log.Warnf("Unable to stop failed startup caretaker: %v",
					err)
			}
			delete(c.caretakers, result.batchKey)
			c.pendingBatch = caretaker.cfg.Batch
			log.Warnf("Startup recovery failed for batch %x: %v",
				result.batchKey[:], result.err)

		case <-leaseRenewalTicker.C:
			batch := c.pendingBatch
			if batch == nil || batch.GenesisPacket == nil ||
				!isCustomAnchorPsbt(batch.GenesisPacket.Pkt) {

				continue
			}

			// A startup recovery caretaker owns lease renewal until its first
			// publication result. The pending batch is only an immutable
			// reservation while that caretaker is active.
			batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
			if _, ok := c.caretakers[batchKey]; ok {
				continue
			}
			switch batch.State() {
			case BatchStatePending, BatchStateFrozen,
				BatchStateCommitted:

				ctx, cancel := c.WithCtxQuit()
				err := renewCustomAnchorLeases(
					ctx, c.cfg.Wallet,
					customAnchorLeaseID(batch.BatchKey.PubKey),
					batch.GenesisPacket,
				)
				cancel()
				if err != nil {
					statusErr := fmt.Errorf("custom anchor input lease "+
						"renewal degraded; Finalize will retry and "+
						"fail closed: %w", err)
					if batch.CustomAnchorLeaseError !=
						statusErr.Error() {

						batch.CustomAnchorLeaseError = statusErr.Error()
						c.publishSubscriberEvent(
							newAssetMintErrorEvent(
								statusErr, batch.State(), batch,
							),
						)
					}
					log.Warnf("Unable to renew custom anchor input "+
						"leases: %v", err)
					continue
				}

				if batch.CustomAnchorLeaseError != "" {
					batch.CustomAnchorLeaseError = ""
					c.publishSubscriberEvent(newAssetMintEvent(
						batch.State(), batch,
					))
				}
			}

		// A request for new asset issuance just arrived, add this to
		// the pending batch and acknowledge the receipt back to the
		// caller.
		case req := <-c.seedlingReqs:
			// After some basic validation, prepare the asset
			// seedling (soon to be a sprout) by committing it to
			// disk as part of the latest batch.
			//
			// This method will also include the seedling in any
			// existing pending batch or create a new pending batch
			// if necessary.
			ctx, cancel := c.WithCtxQuit()
			err := c.prepAssetSeedling(ctx, req)
			cancel()
			if err != nil {
				// Something went wrong, so then an error
				// update back to the caller.
				req.updates <- SeedlingUpdate{
					Error: err,
				}
				continue
			}

			log.Infof("Request for new seedling: %v", req)

			// Otherwise if we've got to this point then we can
			// return a response back to the caller that the
			// seedling has been added to the next batch.
			//
			// TODO(roasbeef): extend the ticker by a certain
			// portion?

			// Copy the pending batch to prevent potential
			// concurrent read/write issues.
			var batchCopy *MintingBatch
			if c.pendingBatch != nil {
				batchCopy = c.pendingBatch.Copy()
			}
			req.updates <- SeedlingUpdate{
				PendingBatch: batchCopy,
			}

		// A caretaker has finished processing their batch to full
		// Taproot Asset maturity. We'll clean up our local state, and
		// signal that it can exit.
		//
		// TODO(roasbeef): also need a channel to send out additional
		// notifications?
		case batchKey := <-c.completionSignals:
			caretaker, ok := c.caretakers[batchKey]
			if !ok {
				log.Warnf("Unknown caretaker: %x", batchKey[:])
				continue
			}

			log.Infof("ChainCaretaker(%x) has finished", batchKey[:])

			if err := caretaker.Stop(); err != nil {
				log.Warnf("Unable to stop caretaker: %v", err)
			}

			delete(c.caretakers, batchKey)

			// A recovered custom caretaker can confirm before its forwarded
			// publication success is selected. Release its exact reservation
			// here as well so event ordering cannot strand a Committed batch.
			if c.pendingBatch != nil &&
				asset.ToSerialized(
					c.pendingBatch.BatchKey.PubKey,
				) == batchKey {

				c.pendingBatch = nil
			}

			// TODO(roasbeef): send completion signal?

		// A new request just came along to query our internal state.
		case req := <-c.stateReqs:
			switch req.Type() {
			case reqTypePendingBatch:
				// Resolve a copy of the state to prevent
				// potential concurrent read/write issues.
				if c.pendingBatch == nil {
					req.Resolve((*MintingBatch)(nil))
				} else {
					req.Resolve(c.pendingBatch.Copy())
				}

			case reqTypeNumActiveBatches:
				req.Resolve(len(c.caretakers))

			case reqTypeListBatches:
				listBatchesParams, err :=
					typedParam[ListBatchesParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad list batch "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				batches, err := listBatches(
					ctx, c.cfg.Log, c.cfg.ProofFiles,
					c.cfg.GenTxBuilder, *listBatchesParams,
				)
				cancel()
				if err != nil {
					req.Error(err)
					break
				}

				c.attachCustomAnchorKeyErrors(batches)
				c.attachCustomAnchorRuntimeStatus(batches)

				req.Resolve(batches)

			case reqTypeFundBatch:
				if c.pendingBatch != nil &&
					c.pendingBatch.State() != BatchStatePending {

					req.Error(fmt.Errorf("batch in state %v cannot be "+
						"funded", c.pendingBatch.State()))
					break
				}
				if c.pendingBatch != nil &&
					c.pendingBatch.IsFunded() {

					req.Error(fmt.Errorf("batch already " +
						"funded"))
					break
				}

				fundReqParams, err :=
					typedParam[FundParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad fund "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				err = c.fundPendingBatch(
					ctx, *fundReqParams,
				)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to fund "+
						"minting batch: %w", err))
					break
				}

				// Formulate a verbose batch to return to the
				// caller.
				verboseBatch, err := newVerboseBatch(
					c.pendingBatch, c.cfg.GenTxBuilder,
				)
				if err != nil {
					req.Error(err)
					break
				}

				req.Resolve(&FundBatchResp{
					Batch: verboseBatch,
				})

			case reqTypeSealBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending " +
						"batch"))
					break
				}
				if c.pendingBatch.State() != BatchStatePending &&
					c.pendingBatch.State() != BatchStateFrozen {
					req.Error(fmt.Errorf("batch in state %v cannot be "+
						"sealed", c.pendingBatch.State()))
					break
				}

				sealReqParams, err :=
					typedParam[SealParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad seal "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				sealedBatch, err := c.sealBatch(
					ctx, *sealReqParams, c.pendingBatch,
				)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to seal "+
						"minting batch: %w", err))
					break
				}

				// If seal batch executed successfully, and
				// returned a sealed batch, then we can update
				// the pending batch.
				if err == nil && sealedBatch != nil {
					c.pendingBatch = sealedBatch
				}

				// Resolve a copy of the state to prevent
				// potential concurrent read/write issues.
				if c.pendingBatch == nil {
					req.Resolve((*MintingBatch)(nil))
				} else {
					req.Resolve(c.pendingBatch.Copy())
				}

			case reqTypePrepareBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending batch"))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				preparedBatch, err := c.prepareBatch(
					ctx, c.pendingBatch,
				)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to prepare minting "+
						"batch: %w", err))
					break
				}

				c.pendingBatch = preparedBatch
				req.Resolve(preparedBatch.Copy())

			case reqTypeFinalizeBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending " +
						"batch"))
					break
				}

				batchKey := c.pendingBatch.BatchKey.PubKey
				batchKeySerial := asset.ToSerialized(batchKey)
				// Determine the batch kind before starting the caretaker. The
				// caretaker owns and mutates the batch once Start returns, so the
				// gardener must not inspect that shared packet afterwards.
				customBatch := c.pendingBatch.GenesisPacket != nil &&
					isCustomAnchorPsbt(
						c.pendingBatch.GenesisPacket.Pkt,
					)
				if _, ok := c.caretakers[batchKeySerial]; ok {
					req.Error(fmt.Errorf("batch recovery is in progress"))
					break
				}
				log.Infof("Finalizing batch %x", batchKeySerial)

				finalizeReqParams, err :=
					typedParam[FinalizeParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad finalize "+
						"params: %w", err))
					break
				}

				caretaker, err := c.finalizeBatch(
					*finalizeReqParams,
				)
				if err != nil {
					freezeErr := fmt.Errorf("unable to "+
						"finalize minting batch: %w",
						err)
					log.Warnf(freezeErr.Error())
					req.Error(freezeErr)
					break
				}

				// We now wait for the caretaker to either
				// broadcast the batch or fail to do so.
				select {
				case <-caretaker.cfg.BroadcastCompleteChan:
					req.Resolve(caretaker.cfg.Batch)

					// The batch has been broadcast, so we
					// can remove the pending batch.
					c.pendingBatch = nil

				case err := <-caretaker.cfg.BroadcastErrChan:
					// Stop the failed caretaker directly. Custom
					// batches remain pending so the same signed
					// transaction can be retried; legacy batches
					// retain their existing terminal behavior.
					stopErr := caretaker.Stop()
					if stopErr != nil {
						log.Warnf("Unable to stop "+
							"caretaker "+
							"gracefully: %v", err)
					}

					delete(c.caretakers, batchKeySerial)

					// Cancel the failed batch on disk if
					// it is still pre-broadcast, so it
					// isn't left wedged in a state the
					// migration 000061 singleton index
					// forbids. Only drop the in-memory
					// reference if the batch no longer
					// occupies the singleton slot;
					// otherwise keep it so a retried
					// cancel request can still find and
					// cancel the batch.
					cancelErr := c.cancelFailedBatch(
						caretaker.cfg.Batch,
					)
					if cancelErr != nil {
						log.Errorf("%v; retry "+
							"cancelling the "+
							"batch, or restart "+
							"tapd", cancelErr)
						break
					}

					if !customBatch {
						c.pendingBatch = nil
					}

					// Only release the synchronous caller after the
					// failed caretaker is stopped and removed. Callers
					// may immediately retry or cancel after an error,
					// so returning earlier exposes a dead caretaker in
					// the exclusive slot.
					req.Error(err)

				case <-c.Quit:
					return
				}

			case reqTypeCancelBatch:
				if c.pendingBatch != nil {
					batchKey := asset.ToSerialized(
						c.pendingBatch.BatchKey.PubKey,
					)
					if _, ok := c.caretakers[batchKey]; ok {
						req.Error(fmt.Errorf("batch recovery is in progress"))
						break
					}
				}

				batchKey, err := c.canCancelBatch()
				if err != nil {
					req.Error(err)
					break
				}

				// Attempt to cancel the current batch, and then
				// clear the pending batch in the planter.
				ctx, cancel := c.WithCtxQuit()
				err = c.cancelMintingBatch(ctx, batchKey)
				cancel()
				// Only drop the in-memory reference if the
				// on-disk cancellation went through. If it
				// failed, the row still occupies the
				// pre-broadcast singleton slot, and orphaning
				// it here would wedge new batch creation
				// until restart.
				if err == nil {
					c.pendingBatch = nil
				}

				// Always return the key of the batch we tried
				// to cancel.
				req.Return(batchKey, err)
			}

		case <-c.Quit:
			return
		}
	}
}

// fundingPrep stores a tapscript-sibling root hash (already persisted
// to the tree store) and a closure that computes a funded mint anchor
// PSBT for a given batch without mutating it. Both fields are
// populated by prepareFunding and consumed by createFundedBatch /
// applyFundingToBatch.
type fundingPrep struct {
	// rootHash is the persisted root hash of the optional tapscript
	// sibling supplied via FundParams. nil if no sibling was given.
	rootHash *chainhash.Hash

	// computeFunding builds the funded genesis PSBT for a batch
	// without mutating it. Callers must apply the result only after
	// all persistence has succeeded, so a failure leaves the batch
	// unchanged.
	computeFunding func(batch *MintingBatch) (*FundedMintAnchorPsbt,
		error)
}

// prepareFunding stores the optional tapscript sibling and constructs
// the funding-computation closure shared by createFundedBatch and
// applyFundingToBatch.
func (c *ChainPlanter) prepareFunding(ctx context.Context,
	params FundParams) (fundingPrep, error) {

	var (
		zero     fundingPrep
		rootHash *chainhash.Hash
		err      error
	)

	// If a tapscript tree was specified for this batch, we'll store
	// it on disk. The caretaker we start for this batch will use it
	// when deriving the final Taproot output key.
	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		rootHash, err = c.cfg.TreeStore.StoreTapscriptTree(ctx, tn)
	})
	if err != nil {
		return zero, fmt.Errorf("unable to store tapscript tree "+
			"for minting batch: %w", err)
	}

	computeFunding := func(batch *MintingBatch) (
		*FundedMintAnchorPsbt, error) {
		if params.AnchorPsbt != nil {
			anchorKeyDesc, err := customAnchorKeyDesc(
				c.cfg.ChainParams, params.AnchorPsbt,
				params.AssetAnchorOutIdx,
			)
			if err != nil {
				return nil, err
			}
			if !c.cfg.KeyRing.IsLocalKey(ctx, anchorKeyDesc) {
				return nil, fmt.Errorf("custom asset anchor internal " +
					"key is not controlled by the backing wallet")
			}

			funded, err := customGenesisPsbt(
				c.cfg.ChainParams, batch, params.AnchorPsbt,
				params.AssetAnchorOutIdx,
				params.ChangeOutputIndex,
				params.PreCommitOutputIndex,
			)
			if err != nil {
				return nil, err
			}

			locked, err := acquireCustomAnchorLeases(
				ctx, c.cfg.Wallet,
				customAnchorLeaseID(batch.BatchKey.PubKey), funded.Pkt,
				nil,
			)
			if err != nil {
				return nil, err
			}
			funded.LockedUTXOs = locked
			SetCustomAnchorLockedUTXOs(funded.Pkt, locked)

			return &funded, nil
		}

		feeRate, err := c.anchorTxFeeRate(ctx, params.FeeRate)
		if err != nil {
			return nil, fmt.Errorf("unable to determine anchor "+
				"TX fee rate: %w", err)
		}

		batchKey := asset.ToSerialized(batch.BatchKey.PubKey)

		// walletFundPsbt is a closure that will be used to fund
		// the batch with the specified fee rate.
		walletFundPsbt := func(ctx context.Context,
			anchorPkt psbt.Packet) (tapsend.FundedPsbt, error) {

			var zero tapsend.FundedPsbt

			fundedPkt, err := c.cfg.Wallet.FundPsbt(
				ctx, &anchorPkt, 1, feeRate, -1,
			)
			if err != nil {
				return zero, err
			}

			return *fundedPkt, nil
		}

		log.Infof("Attempting to fund batch: %x", batchKey)
		mintAnchorTx, err := fundGenesisPsbt(
			ctx, c.cfg.ChainParams, batch, walletFundPsbt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund minting PSBT "+
				"for batch: %x %w", batchKey[:], err)
		}

		log.Infof("Funded GenesisPacket for batch: %x", batchKey)
		return &mintAnchorTx, nil
	}

	return fundingPrep{
		rootHash:       rootHash,
		computeFunding: computeFunding,
	}, nil
}

// createFundedBatch derives a fresh minting batch, computes its
// funding, and persists the funded batch to disk as a single new row.
// On any failure no new batch is committed and no in-memory state is
// touched; the caller may try again. The returned batch is ready to
// be installed as c.pendingBatch by the caller.
//
// NOTE: This is the create half of what used to be a single fundBatch
// function with two purposes. The split exists so that "create a new
// funded batch" cannot be silently dispatched into "update an
// existing batch's funding" (or vice-versa) by callers passing a
// stale or wrong reference -- the bug shape behind #2136.
func (c *ChainPlanter) createFundedBatch(ctx context.Context,
	params FundParams) (*MintingBatch, error) {

	prep, err := c.prepareFunding(ctx, params)
	if err != nil {
		return nil, err
	}

	newBatch, err := c.newBatch()
	if err != nil {
		return nil, fmt.Errorf("unable to create new batch: %w", err)
	}

	mintAnchorTx, err := prep.computeFunding(newBatch)
	if err != nil {
		return nil, err
	}

	// Apply the funding to the local batch and commit. If the
	// commit fails, newBatch is discarded and the caller's planter
	// state is never assigned.
	newBatch.GenesisPacket = mintAnchorTx
	if prep.rootHash != nil {
		newBatch.tapSibling = prep.rootHash
	}

	if err := c.cfg.Log.CommitMintingBatch(ctx, newBatch); err != nil {
		releaseErr := releaseCustomAnchorLeases(
			ctx, c.cfg.Wallet,
			customAnchorLeaseID(newBatch.BatchKey.PubKey), mintAnchorTx,
		)
		return nil, errors.Join(err, releaseErr)
	}

	return newBatch, nil
}

// applyFundingToBatch computes funding for an existing on-disk batch,
// persists the funding atomically (sibling + genesis TX in one DB
// transaction), and only then mirrors the funding into the in-memory
// batch. On any failure neither disk nor memory is mutated.
//
// NOTE: This is the update half of the former fundBatch. It must
// never be called with a batch that has not yet been written to disk
// -- use createFundedBatch for that case.
func (c *ChainPlanter) applyFundingToBatch(ctx context.Context,
	params FundParams, batch *MintingBatch) error {

	if batch == nil {
		return fmt.Errorf("applyFundingToBatch requires non-nil " +
			"batch; use createFundedBatch to create a new one")
	}

	prep, err := c.prepareFunding(ctx, params)
	if err != nil {
		return err
	}

	mintAnchorTx, err := prep.computeFunding(batch)
	if err != nil {
		return err
	}

	// Persist the sibling and genesis TX atomically. Combining
	// both writes in a single transaction ensures a partial
	// failure cannot leave the batch with one persisted and the
	// other absent.
	err = c.cfg.Log.CommitBatchFunding(
		ctx, batch.BatchKey.PubKey, prep.rootHash, *mintAnchorTx,
	)
	if err != nil {
		releaseErr := releaseCustomAnchorLeases(
			ctx, c.cfg.Wallet,
			customAnchorLeaseID(batch.BatchKey.PubKey), mintAnchorTx,
		)
		return errors.Join(
			fmt.Errorf("unable to commit batch funding: %w", err),
			releaseErr,
		)
	}

	// All persistence succeeded; mirror the funding into memory.
	batch.GenesisPacket = mintAnchorTx
	if prep.rootHash != nil {
		batch.tapSibling = prep.rootHash
	}

	return nil
}

// fundPendingBatch funds c.pendingBatch, creating it first if it does
// not yet exist. This is the convenience wrapper used by the
// gardener's fund-batch request handler and by finalizeBatch; both
// have the same "I want the pending batch funded, regardless of
// whether it exists yet" semantics. c.pendingBatch is updated only on
// success of the create path; the update path mutates the existing
// batch in place via applyFundingToBatch.
func (c *ChainPlanter) fundPendingBatch(ctx context.Context,
	params FundParams) error {

	if c.pendingBatch == nil {
		newBatch, err := c.createFundedBatch(ctx, params)
		if err != nil {
			return err
		}

		c.pendingBatch = newBatch
		return nil
	}

	return c.applyFundingToBatch(ctx, params, c.pendingBatch)
}

// matchPsbtToGroupReq attempts to match a signed group virtual PSBT to a
// corresponding group key request.
func matchPsbtToGroupReq(psbt psbt.Packet,
	groupReqs []asset.GroupKeyRequest) (fn.Option[asset.GroupKeyRequest],
	error) {

	// Sanity check PSBT.
	if len(psbt.Inputs) != 1 {
		return fn.None[asset.GroupKeyRequest](), fmt.Errorf(
			"PSBT must have a single input")
	}

	psbtInPrevOut := psbt.UnsignedTx.TxIn[0].PreviousOutPoint

	// Match the signed PSBT to the corresponding group request.
	for idxReq := range groupReqs {
		req := groupReqs[idxReq]

		// Formulate the group virtual TX for the group key request so
		// we can extract the previous output.
		tx, err := req.BuildGroupVirtualTx(
			&tapscript.GroupTxBuilder{},
		)
		if err != nil {
			return fn.None[asset.GroupKeyRequest](), err
		}

		// Sanity check that the group virtual TX.
		if len(tx.Tx.TxIn) != 1 {
			return fn.None[asset.GroupKeyRequest](), fmt.Errorf(
				"group virtual TX must have a single input")
		}
		vTxInPrevOut := tx.Tx.TxIn[0].PreviousOutPoint

		// If the previous output of the signed PSBT matches the
		// previous output of the group virtual TX, we have a match.
		if vTxInPrevOut.Hash == psbtInPrevOut.Hash {
			return fn.Some(req), nil
		}
	}

	return fn.None[asset.GroupKeyRequest](), nil
}

// sealBatchPreCommit injects the group public key obtained during the sealing
// phase into the pre‑commitment output descriptor of the batch's genesis
// packet.
//
// Preconditions:
//   - batch.SupplyCommitments must be true – otherwise the function is a NOP.
//   - batch.GenesisPacket must not be nil.
//
// Post‑conditions:
//   - batch.GenesisPacket.PreCommitmentOutput is populated with the group key.
//
// NOTE: The function mutates the supplied *MintingBatch in place.
func sealBatchPreCommit(batch *MintingBatch) error {
	// Fast‑exit if Universe Commitments are disabled – nothing to update.
	if !batch.SupplyCommitments {
		return nil
	}

	// A valid genesis packet is mandatory once Universe Commitments are on.
	if batch.GenesisPacket == nil {
		return fmt.Errorf("batch genesis packet is unexpectedly " +
			"nil, cannot update mint anchor pre-commitment output")
	}

	// Retrieve the group public key recorded during sealing.
	groupKeyOpt, err := fetchPreCommitGroupKey(batch)
	if err != nil {
		return fmt.Errorf("unable to fetch pre-commit group key: %w",
			err)
	}

	groupKey, err := groupKeyOpt.UnwrapOrErr(
		fmt.Errorf("pre-commitment output group key is unexpectedly " +
			"absent"),
	)
	if err != nil {
		return err
	}

	// Ensure that the group key is set in the genesis packet
	// pre-commitment output descriptor.
	fundedAnchor := batch.GenesisPacket
	if fundedAnchor == nil {
		return fmt.Errorf("funded anchor is unexpectedly nil, " +
			"cannot update mint anchor pre-commitment output " +
			"descriptor")
	}

	// Formulate the pre-commitment output descriptor with the group key.
	preCommitDesc := fn.MapOptionZ(
		fundedAnchor.PreCommitmentOutput,
		// nolint: lll
		func(preCommit PreCommitmentOutput) fn.Option[PreCommitmentOutput] {
			preCommit.GroupPubKey = fn.Some(groupKey)
			return fn.Some(preCommit)
		},
	)

	batch.GenesisPacket.PreCommitmentOutput = preCommitDesc

	return nil
}

// sealBatch will verify that each grouped asset in the pending batch has an
// asset group witness, and will attempt to create asset group witnesses when
// possible if they are not provided. After all asset group witnesses have been
// validated, they are saved to disk to be used by the caretaker during batch
// finalization.
func (c *ChainPlanter) sealBatch(ctx context.Context, params SealParams,
	workingBatch *MintingBatch) (*MintingBatch, error) {

	// A batch should exist with 1+ seedlings and be funded before being
	// sealed.
	if !workingBatch.HasSeedlings() {
		return nil, fmt.Errorf("no seedlings in batch")
	}

	if !workingBatch.IsFunded() {
		return nil, fmt.Errorf("batch is not funded")
	}

	// Filter the batch seedlings to only consider those that will become
	// grouped assets. If there are no such seedlings, then there is nothing
	// to seal and no action is needed.
	groupSeedlings, _ := filterSeedlingsWithGroup(workingBatch.Seedlings)
	if len(groupSeedlings) == 0 {
		return workingBatch, nil
	}

	// Before we can build the group key requests for each seedling, we must
	// fetch the genesis point and anchor index for the batch.
	workingGenesisPkt := workingBatch.GenesisPacket
	anchorOutputIndex := workingGenesisPkt.AssetAnchorOutIdx

	genesisPoint, err := workingGenesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	// Check if the batch is already sealed by picking a random grouped
	// seedling and trying to fetch the full asset group.
	var singleSeedling []*Seedling
	for _, seedling := range groupSeedlings {
		singleSeedling = append(singleSeedling, seedling)
		break
	}

	// If the batch was previously sealed, each grouped seedling will have
	// its asset genesis already stored on disk.
	existingGroups, err := c.cfg.Log.FetchSeedlingGroups(
		ctx, genesisPoint, anchorOutputIndex, singleSeedling,
	)

	switch {
	case len(existingGroups) != 0:
		return nil, ErrBatchAlreadySealed
	case err != nil:
		// The only expected error is for a missing asset genesis.
		if !errors.Is(err, ErrNoGenesis) {
			return nil, err
		}
	}

	// Construct the group key requests and group virtual TXs for each
	// seedling. With these we can verify provided asset group witnesses,
	// or attempt to derive asset group witnesses if needed.
	groupReqs, genTXs, err := buildGroupReqs(
		genesisPoint, anchorOutputIndex, c.cfg.GenTxBuilder,
		groupSeedlings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to build group requests: "+
			"%w", err)
	}
	if len(groupReqs) != len(genTXs) {
		return nil, fmt.Errorf("mismatched number of group requests " +
			"and virtual TXs")
	}

	// Each provided group witness must have a corresponding seedling in the
	// current batch.
	seedlingAssetIDs := fn.NewSet(fn.Map(
		groupReqs, func(req asset.GroupKeyRequest) asset.ID {
			return req.NewAsset.ID()
		})...,
	)

	externalWitnesses := make(map[asset.ID]PendingGroupWitness)
	for _, wit := range params.GroupWitnesses {
		if !seedlingAssetIDs.Contains(wit.GenID) {
			return nil, fmt.Errorf("witness has no matching "+
				"seedling: %v", wit)
		}

		externalWitnesses[wit.GenID] = wit
	}

	// Extract witnesses from signed group virtual PSBTs.
	for idxPsbt := range params.SignedGroupVirtualPsbts {
		psbtPacket := params.SignedGroupVirtualPsbts[idxPsbt]

		// Match the signed PSBT to the corresponding group request.
		groupReqMatch, err := matchPsbtToGroupReq(
			psbtPacket, groupReqs,
		)
		if err != nil {
			return nil, fmt.Errorf("encountered error while "+
				"matching signed PSBT to group request: %w",
				err)
		}

		// Ensure that a matching group key reveal has been found.
		if groupReqMatch.IsNone() {
			return nil, fmt.Errorf("failed to find matching " +
				"group key request for signed group virtual " +
				"PSBT")
		}

		// Ensure that an external witness has not already been
		// specified for the given genesis asset ID.
		genesisAssetID := fn.MapOptionZ(
			groupReqMatch,
			func(req asset.GroupKeyRequest) asset.ID {
				return req.NewAsset.ID()
			},
		)

		if _, ok := externalWitnesses[genesisAssetID]; ok {
			return nil, fmt.Errorf("signed PSBT is a duplicate "+
				"witness for asset ID: %v", genesisAssetID)
		}

		// Finalize the signed PSBT.
		err = psbt.MaybeFinalizeAll(&psbtPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to finalize signed "+
				"PSBT for asset ID: %v, %w", genesisAssetID,
				err)
		}

		// Extract the signed transaction from the PSBT.
		tx, err := psbt.Extract(&psbtPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to extract signed "+
				"PSBT for asset ID: %v, %w", genesisAssetID,
				err)
		}

		if len(tx.TxIn) != 1 {
			return nil, fmt.Errorf("expected exactly 1 input in "+
				"signed PSBT for asset ID: %v", genesisAssetID)
		}

		// Add the witness to the set of external witnesses.
		externalWitnesses[genesisAssetID] = PendingGroupWitness{
			GenID:   genesisAssetID,
			Witness: tx.TxIn[0].Witness,
		}
	}

	// Formulate new asset groups from the group key requests.
	newAssetGroups := make([]*asset.AssetGroup, 0, len(groupReqs))
	for i := 0; i < len(groupReqs); i++ {
		var (
			genTX      = genTXs[i]
			groupReq   = groupReqs[i]
			protoAsset = groupReq.NewAsset
			groupKey   *asset.GroupKey
			err        error
		)

		// Check for an externally-provided asset group witness before
		// trying to derive a witness.
		reqAssetID := protoAsset.ID()
		groupWitness, ok := externalWitnesses[reqAssetID]
		switch {
		case ok:
			// Set the provided witness; it will be validated below.
			subtreeRoot := groupReq.CustomTapscriptRoot
			groupKey = &asset.GroupKey{
				Version:             groupReq.Version,
				RawKey:              groupReq.RawKey,
				GroupPubKey:         genTX.TweakedKey,
				TapscriptRoot:       groupReq.TapscriptRoot,
				CustomTapscriptRoot: subtreeRoot,
				Witness:             groupWitness.Witness,
			}

		default:
			// Derive the asset group witness.
			groupKey, err = asset.DeriveGroupKey(
				c.cfg.GenSigner, genTX, groupReq, nil,
			)
			if err != nil {
				return nil, err
			}
		}
		// Recreate the asset with the populated group key and validate
		// the asset group witness.
		groupedAsset, err := asset.New(
			protoAsset.Genesis, protoAsset.Amount,
			protoAsset.LockTime, protoAsset.RelativeLockTime,
			protoAsset.ScriptKey, groupKey,
			asset.WithAssetVersion(protoAsset.Version),
		)
		if err != nil {
			return nil, err
		}

		// Validate the asset with the Taproot Assets VM. Lock times in
		// the group key scripts are checked against the current block
		// height. And CSV (relative lock times) don't make sense in
		// the context of a group key script (since there's no input to
		// verify against), so those will fail anyway. So we don't
		// provide a proof as context to the chain lookup, which will
		// definitely cause any CSV checks to fail.
		noProofLookup := c.cfg.ChainBridge.GenFileChainLookup(nil)
		err = c.cfg.TxValidator.Execute(
			groupedAsset, nil, nil, noProofLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to verify asset group "+
				"witness: %s, %w", reqAssetID.String(), err)
		}

		newGroup := &asset.AssetGroup{
			Genesis:  &protoAsset.Genesis,
			GroupKey: groupKey,
		}

		newAssetGroups = append(newAssetGroups, newGroup)
	}

	// Assign each newly created asset group to its corresponding seedling.
	batchWithGroupInfo := workingBatch.Copy()
	for _, group := range newAssetGroups {
		assetName := group.Genesis.Tag
		batchWithGroupInfo.Seedlings[assetName].GroupInfo = group
	}

	// Persist the newly generated group-key metadata in the batch’s
	// pre-commitment output—needed only when Universe Commitments are on—
	// before passing the batch to the minting store.
	if batchWithGroupInfo.SupplyCommitments {
		err := sealBatchPreCommit(batchWithGroupInfo)
		if err != nil {
			return nil, err
		}
	}

	// With all the asset group witnesses validated, we can now save them
	// to disk effectively sealing the batch.
	err = c.cfg.Log.SealBatch(ctx, batchWithGroupInfo, newAssetGroups)
	if err != nil {
		return nil, fmt.Errorf("unable to write seedling groups: "+
			"%w", err)
	}

	return batchWithGroupInfo, nil
}

// prepareBatch commits the asset tree into a caller-authored anchor PSBT and
// then pauses at the committed state so the packet can be signed externally.
func (c *ChainPlanter) prepareBatch(ctx context.Context,
	batch *MintingBatch) (*MintingBatch, error) {

	if !batch.IsFunded() || !isCustomAnchorPsbt(batch.GenesisPacket.Pkt) {
		return nil, fmt.Errorf("batch does not use a custom anchor PSBT")
	}
	if batch.State() != BatchStatePending &&
		batch.State() != BatchStateFrozen {

		return nil, fmt.Errorf("batch is not ready for preparation: %v",
			batch.State())
	}

	// Legacy raw-only custom packets must fail before sealing, freezing or
	// clearing BIP-371 fields. Without an exact wallet-owned locator we cannot
	// safely persist a spendable managed output descriptor.
	_, err := customAnchorMintingKeyDescriptor(
		ctx, c.cfg.KeyRing, batch.GenesisPacket.Pkt,
		batch.GenesisPacket.AssetAnchorOutIdx,
	)
	if err != nil {
		return nil, fmt.Errorf("custom anchor wallet key preflight failed: %w",
			err)
	}

	sealedBatch, err := c.sealBatch(ctx, SealParams{}, batch)
	if err != nil && !errors.Is(err, ErrBatchAlreadySealed) {
		return nil, err
	}
	if sealedBatch != nil {
		batch = sealedBatch
	}

	if batch.State() == BatchStatePending {
		if err := freezeMintingBatch(ctx, c.cfg.Log, batch); err != nil {
			return nil, err
		}
	}

	caretaker := c.newCaretakerForBatch(batch, nil)
	nextState, err := caretaker.stateStep(BatchStateFrozen)
	delete(c.caretakers, asset.ToSerialized(batch.BatchKey.PubKey))
	if err != nil {
		return nil, err
	}
	if nextState != BatchStateCommitted {
		return nil, fmt.Errorf("unexpected prepared batch state: %v",
			nextState)
	}

	return batch, nil
}

// mergeSignedCustomPsbt accepts only signing/finalization fields from an
// externally signed packet. All transaction-defining and descriptive fields
// remain those that were persisted during preparation.
func mergeSignedCustomPsbt(stored,
	signed *psbt.Packet) (*psbt.Packet, error) {

	if stored == nil || signed == nil {
		return nil, fmt.Errorf("signed custom anchor PSBT is missing")
	}
	if err := signed.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid signed custom anchor PSBT: %w", err)
	}
	normalizePacket := func(pkt *psbt.Packet) (*psbt.Packet, error) {
		var buf bytes.Buffer
		if err := pkt.Serialize(&buf); err != nil {
			return nil, err
		}
		return psbt.NewFromRawBytes(&buf, false)
	}
	storedNorm, err := normalizePacket(stored)
	if err != nil {
		return nil, err
	}
	signedNorm, err := normalizePacket(signed)
	if err != nil {
		return nil, err
	}
	// Publication state is internal recovery metadata added after the
	// caller signs. It isn't part of the prepared transaction contract and
	// therefore isn't required in a resubmitted external packet.
	stripTapdCustomAnchorMarkers(storedNorm)
	stripTapdCustomAnchorMarkers(signedNorm)
	if !reflect.DeepEqual(storedNorm.UnsignedTx, signedNorm.UnsignedTx) ||
		!reflect.DeepEqual(storedNorm.Outputs, signedNorm.Outputs) ||
		!reflect.DeepEqual(storedNorm.XPubs, signedNorm.XPubs) ||
		!reflect.DeepEqual(storedNorm.Unknowns, signedNorm.Unknowns) ||
		len(stored.Inputs) != len(signed.Inputs) {

		return nil, fmt.Errorf("signed custom anchor PSBT changes prepared " +
			"transaction or metadata")
	}

	hasSignature := false
	for idx := range stored.Inputs {
		storedCmp := stored.Inputs[idx]
		signedCmp := signed.Inputs[idx]
		isFinal := signedCmp.FinalScriptSig != nil ||
			signedCmp.FinalScriptWitness != nil
		if isFinal {
			// Standard PSBT finalizers intentionally prune all input
			// fields except the UTXO and final scripts. The stored packet
			// remains authoritative for those omitted fields.
			if signedCmp.WitnessUtxo != nil &&
				!reflect.DeepEqual(
					storedCmp.WitnessUtxo, signedCmp.WitnessUtxo,
				) {

				return nil, fmt.Errorf("signed custom anchor PSBT " +
					"changes input UTXO")
			}
			if signedCmp.NonWitnessUtxo != nil &&
				!reflect.DeepEqual(
					storedCmp.NonWitnessUtxo,
					signedCmp.NonWitnessUtxo,
				) {

				return nil, fmt.Errorf("signed custom anchor PSBT " +
					"changes input UTXO")
			}
			if signedCmp.WitnessUtxo == nil &&
				signedCmp.NonWitnessUtxo == nil {

				return nil, fmt.Errorf("finalized custom anchor PSBT " +
					"drops input UTXO")
			}

			hasSignature = true
			continue
		}

		storedCmp.PartialSigs = nil
		storedCmp.FinalScriptSig = nil
		storedCmp.FinalScriptWitness = nil
		storedCmp.TaprootKeySpendSig = nil
		storedCmp.TaprootScriptSpendSig = nil
		signedCmp.PartialSigs = nil
		signedCmp.FinalScriptSig = nil
		signedCmp.FinalScriptWitness = nil
		signedCmp.TaprootKeySpendSig = nil
		signedCmp.TaprootScriptSpendSig = nil

		if !reflect.DeepEqual(storedCmp, signedCmp) {
			return nil, fmt.Errorf("signed custom anchor PSBT changes input "+
				"%d metadata", idx)
		}

		src := &signed.Inputs[idx]
		if len(src.PartialSigs) != 0 || src.FinalScriptSig != nil ||
			src.FinalScriptWitness != nil ||
			len(src.TaprootKeySpendSig) != 0 ||
			len(src.TaprootScriptSpendSig) != 0 {

			hasSignature = true
		}
	}

	if !hasSignature {
		return nil, fmt.Errorf("signed custom anchor PSBT has no signatures")
	}

	var buf bytes.Buffer
	if err := stored.Serialize(&buf); err != nil {
		return nil, err
	}
	merged, err := psbt.NewFromRawBytes(&buf, false)
	if err != nil {
		return nil, err
	}
	for idx := range merged.Inputs {
		src := &signed.Inputs[idx]
		dst := &merged.Inputs[idx]
		dst.PartialSigs = src.PartialSigs
		dst.FinalScriptSig = src.FinalScriptSig
		dst.FinalScriptWitness = src.FinalScriptWitness
		dst.TaprootKeySpendSig = src.TaprootKeySpendSig
		dst.TaprootScriptSpendSig = src.TaprootScriptSpendSig
	}

	return merged, nil
}

// validateFinalizedAnchorPsbt executes every input script locally before the
// caretaker persists a broadcast state. This keeps a malformed external
// witness retryable at the prepared state.
func validateFinalizedAnchorPsbt(packet *psbt.Packet) error {
	for idx := range packet.Inputs {
		witness := packet.Inputs[idx].FinalScriptWitness
		if witness == nil {
			continue
		}
		if err := validateFinalScriptWitness(witness); err != nil {
			return fmt.Errorf("invalid final witness for input %d: %w",
				idx, err)
		}
	}

	tx, err := psbt.Extract(packet)
	if err != nil {
		return err
	}

	prevOuts := txscript.NewMultiPrevOutFetcher(nil)
	for idx := range packet.Inputs {
		pIn := &packet.Inputs[idx]
		var prevOut *wire.TxOut
		switch {
		case pIn.WitnessUtxo != nil:
			prevOut = pIn.WitnessUtxo

		case pIn.NonWitnessUtxo != nil:
			outpoint := tx.TxIn[idx].PreviousOutPoint
			if int(outpoint.Index) >= len(pIn.NonWitnessUtxo.TxOut) ||
				pIn.NonWitnessUtxo.TxHash() != outpoint.Hash {

				return fmt.Errorf("invalid non-witness UTXO for input %d",
					idx)
			}
			prevOut = pIn.NonWitnessUtxo.TxOut[outpoint.Index]

		default:
			return fmt.Errorf("missing UTXO for input %d", idx)
		}

		prevOuts.AddPrevOut(tx.TxIn[idx].PreviousOutPoint, prevOut)
	}

	sigHashes := txscript.NewTxSigHashes(tx, prevOuts)
	for idx := range tx.TxIn {
		prevOut := prevOuts.FetchPrevOutput(
			tx.TxIn[idx].PreviousOutPoint,
		)
		vm, err := txscript.NewEngine(
			prevOut.PkScript, tx, idx, txscript.StandardVerifyFlags,
			nil, sigHashes, prevOut.Value, prevOuts,
		)
		if err != nil {
			return fmt.Errorf("unable to validate input %d: %w", idx,
				err)
		}
		if err := vm.Execute(); err != nil {
			return fmt.Errorf("invalid witness for input %d: %w", idx,
				err)
		}
	}

	return nil
}

func validateFinalScriptWitness(serialized []byte) error {
	if len(serialized) > maxFinalScriptWitnessSize {
		return fmt.Errorf("serialized witness exceeds %d bytes",
			maxFinalScriptWitnessSize)
	}

	reader := bytes.NewReader(serialized)
	itemCount, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		return fmt.Errorf("unable to read witness item count: %w", err)
	}
	if itemCount > maxFinalWitnessItems {
		return fmt.Errorf("witness item count %d exceeds limit %d",
			itemCount, maxFinalWitnessItems)
	}

	for itemIdx := uint64(0); itemIdx < itemCount; itemIdx++ {
		itemSize, err := wire.ReadVarInt(reader, 0)
		if err != nil {
			return fmt.Errorf("unable to read witness item %d size: %w",
				itemIdx, err)
		}
		if itemSize > uint64(reader.Len()) {
			return fmt.Errorf("witness item %d exceeds serialized data",
				itemIdx)
		}
		if _, err := reader.Seek(int64(itemSize), 1); err != nil {
			return fmt.Errorf("unable to skip witness item %d: %w",
				itemIdx, err)
		}
	}
	if reader.Len() != 0 {
		return fmt.Errorf("serialized witness has %d trailing bytes",
			reader.Len())
	}

	return nil
}

// validateCustomAnchorFeeRate ensures an externally signed anchor transaction
// meets the backing node's current minimum relay fee before the batch is moved
// into its irreversible broadcast state.
func (c *ChainPlanter) validateCustomAnchorFeeRate(ctx context.Context,
	packet *psbt.Packet) error {

	fee, err := packet.GetTxFee()
	if err != nil {
		return fmt.Errorf("unable to determine custom anchor fee: %w", err)
	}

	signedTx, err := psbt.Extract(packet)
	if err != nil {
		return fmt.Errorf("unable to extract custom anchor transaction: %w",
			err)
	}
	weight := lntypes.WeightUnit(
		blockchain.GetTransactionWeight(btcutil.NewTx(signedTx)),
	)

	minRelayFee, err := c.cfg.Wallet.MinRelayFee(ctx)
	if err != nil {
		return fmt.Errorf("unable to obtain minimum relay fee: %w", err)
	}
	minFee := minRelayFee.FeeForWeightRoundUp(weight)
	if fee < minFee {
		return fmt.Errorf("custom anchor fee does not meet minrelayfee: "+
			"(fee=%d, minimum_fee=%d, minrelayfee=%s)", fee, minFee,
			minRelayFee.String())
	}

	return nil
}

// finalizeBatch creates a new caretaker for the batch and starts it.
func (c *ChainPlanter) finalizeBatch(params FinalizeParams) (*BatchCaretaker,
	error) {

	var (
		feeRate *chainfee.SatPerKWeight
		err     error
	)

	// Before modifying the pending batch, check if the batch was already
	// funded. If so, reject any provided parameters, as they would conflict
	// with those previously used for batch funding.
	haveParams := params.FeeRate.IsSome() || params.SiblingTapTree.IsSome()
	if params.SignedPsbt != nil {
		if haveParams {
			return nil, fmt.Errorf("signed PSBT cannot be combined with " +
				"fee rate or tapscript sibling")
		}
		state := c.pendingBatch.State()
		// A broadcast custom packet can be resubmitted after an ambiguous
		// publication or confirmation-registration error. The merge below
		// still requires the prepared transaction and metadata to be identical.
		if (state != BatchStateCommitted && state != BatchStateBroadcast) ||
			!isCustomAnchorPsbt(c.pendingBatch.GenesisPacket.Pkt) {

			return nil, fmt.Errorf("no prepared or broadcast custom batch " +
				"available for external finalization")
		}
		merged, err := mergeSignedCustomPsbt(
			c.pendingBatch.GenesisPacket.Pkt, params.SignedPsbt,
		)
		if err != nil {
			return nil, err
		}
		if err := validateFinalizedAnchorPsbt(merged); err != nil {
			return nil, fmt.Errorf("externally signed PSBT is not fully "+
				"valid: %w", err)
		}
		persistedTx, persistedErr := psbt.Extract(
			c.pendingBatch.GenesisPacket.Pkt,
		)
		if state == BatchStateBroadcast || persistedErr == nil {
			if persistedErr != nil {
				return nil, fmt.Errorf("unable to extract persisted custom "+
					"anchor transaction: %w", persistedErr)
			}

			retryTx, err := psbt.Extract(merged)
			if err != nil {
				return nil, fmt.Errorf("unable to extract custom anchor "+
					"retry transaction: %w", err)
			}

			var persistedBytes, retryBytes bytes.Buffer
			if err := persistedTx.Serialize(&persistedBytes); err != nil {
				return nil, fmt.Errorf("unable to serialize persisted custom "+
					"anchor transaction: %w", err)
			}
			if err := retryTx.Serialize(&retryBytes); err != nil {
				return nil, fmt.Errorf("unable to serialize custom anchor "+
					"retry transaction: %w", err)
			}
			if !bytes.Equal(persistedBytes.Bytes(), retryBytes.Bytes()) {
				if state == BatchStateBroadcast {
					return nil, fmt.Errorf("broadcast retry changes " +
						"finalized transaction")
				}

				return nil, fmt.Errorf("committed retry changes " +
					"finalized transaction")
			}

			// The signed transaction was already recorded before an earlier
			// publication attempt. Reuse that exact persisted packet instead
			// of replacing it with caller-supplied retry data.
			merged = c.pendingBatch.GenesisPacket.Pkt
		}
		if state == BatchStateCommitted {
			// A retry can select the already persisted packet above. Work on
			// an independent copy so marker changes cannot split in-memory
			// state from disk if the subsequent store fails.
			var mergedBytes bytes.Buffer
			if err := merged.Serialize(&mergedBytes); err != nil {
				return nil, fmt.Errorf("unable to copy custom anchor "+
					"PSBT before finalization: %w", err)
			}
			merged, err = psbt.NewFromRawBytes(&mergedBytes, false)
			if err != nil {
				return nil, fmt.Errorf("unable to copy custom anchor "+
					"PSBT before finalization: %w", err)
			}

			ctx, cancel := c.WithCtxQuit()
			err = c.validateCustomAnchorFeeRate(ctx, merged)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("externally signed PSBT has an invalid "+
					"fee rate: %w", err)
			}

			_, err = customAnchorMintingKeyDescriptor(
				ctx, c.cfg.KeyRing, merged,
				c.pendingBatch.GenesisPacket.AssetAnchorOutIdx,
			)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("custom anchor wallet key "+
					"preflight failed: %w", err)
			}

			previousLocks := fn.CopySlice(
				c.pendingBatch.GenesisPacket.LockedUTXOs,
			)
			locked, err := acquireCustomAnchorLeases(
				ctx, c.cfg.Wallet,
				customAnchorLeaseID(c.pendingBatch.BatchKey.PubKey),
				merged, previousLocks,
			)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("unable to lease custom anchor "+
					"inputs before finalization: %w", err)
			}
			c.pendingBatch.CustomAnchorLeaseError = ""
			newLocks := newlyAcquiredLeases(locked, previousLocks)
			SetCustomAnchorLockedUTXOs(merged, locked)
			setCustomAnchorPublishState(
				merged, customAnchorImportPending,
			)

			// Store the signed packet before starting the caretaker. If
			// any WalletKit publication attempt is made, the exact signed
			// transaction survives restart and must progress into watched,
			// immutable Broadcast handling regardless of the returned error.
			signedFundedPsbt := c.pendingBatch.GenesisPacket.FundedPsbt
			signedFundedPsbt.Pkt = merged
			signedFundedPsbt.LockedUTXOs = locked
			ctx, cancel = c.WithCtxQuit()
			err = c.cfg.Log.StoreSignedGenesisPsbt(
				ctx, c.pendingBatch.BatchKey.PubKey,
				&signedFundedPsbt,
			)
			cancel()
			if err != nil {
				ctx, cancel = c.WithCtxQuit()
				releaseErr := releaseCustomAnchorOutpoints(
					ctx, c.cfg.Wallet,
					customAnchorLeaseID(
						c.pendingBatch.BatchKey.PubKey,
					), newLocks,
				)
				cancel()
				return nil, fmt.Errorf("unable to store externally signed "+
					"PSBT: %w", errors.Join(err, releaseErr))
			}

			c.pendingBatch.GenesisPacket.Pkt = merged
			c.pendingBatch.GenesisPacket.LockedUTXOs = locked
		}

		caretaker := c.newCaretakerForBatch(c.pendingBatch, nil)
		if err := caretaker.Start(); err != nil {
			return nil, fmt.Errorf("unable to start new caretaker: %w",
				err)
		}

		return caretaker, nil
	}
	if c.pendingBatch.IsFunded() && c.pendingBatch.GenesisPacket != nil &&
		isCustomAnchorPsbt(c.pendingBatch.GenesisPacket.Pkt) {

		return nil, fmt.Errorf("custom anchor batch must be prepared and " +
			"finalized with an externally signed PSBT")
	}
	if haveParams && c.pendingBatch.IsFunded() {
		return nil, fmt.Errorf("cannot provide finalize parameters " +
			"if batch already funded")
	}

	// Process the finalize parameters.
	feeRate = params.FeeRate.UnwrapToPtr()

	ctx, cancel := c.WithCtxQuit()
	defer cancel()

	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		_, err = c.cfg.TreeStore.StoreTapscriptTree(ctx, tn)
	})

	if err != nil {
		return nil, fmt.Errorf("unable to store tapscript tree for "+
			"minting batch: %w", err)
	}
	// Fund the batch if it hasn't been funded yet. If funding
	// fails, the batch stays pending so the user can retry.
	//
	// finalizeBatch is only reached when c.pendingBatch is
	// non-nil (the gardener short-circuits with an error
	// otherwise), so the "create" path of fundPendingBatch is
	// not exercised here; calling fundPendingBatch keeps the
	// dispatch in one place rather than re-checking pending-ness
	// here.
	if !c.pendingBatch.IsFunded() {
		err = c.fundPendingBatch(ctx, FundParams{
			FeeRate:        params.FeeRate,
			SiblingTapTree: params.SiblingTapTree,
		})
		if err != nil {
			return nil, err
		}
	}

	// If the batch needs to be sealed, we'll use the default
	// behavior for generating asset group witnesses. Any custom
	// behavior requires calling SealBatch() explicitly, before
	// batch finalization.
	sealedBatch, err := c.sealBatch(
		ctx, SealParams{}, c.pendingBatch,
	)
	if err != nil {
		if !errors.Is(err, ErrBatchAlreadySealed) {
			return nil, err
		}
	}

	// If seal batch executed successfully, and returned a
	// sealed batch, then we can update the pending batch.
	if err == nil && sealedBatch != nil {
		c.pendingBatch = sealedBatch
	}

	// Now that funding and sealing have succeeded, freeze the
	// batch on disk and in memory. This means no further
	// seedlings can be added to this batch. freezeMintingBatch
	// updates both the on-disk row and the in-memory state in a
	// single atomic step via the MintingStore.
	err = freezeMintingBatch(ctx, c.cfg.Log, c.pendingBatch)
	if err != nil {
		return nil, err
	}
	caretaker := c.newCaretakerForBatch(c.pendingBatch, feeRate)
	if err := caretaker.Start(); err != nil {
		return nil, fmt.Errorf("unable to start new caretaker: %w", err)
	}

	return caretaker, nil
}

// PendingBatch returns the current pending batch, or nil if no batch is
// pending.
func (c *ChainPlanter) PendingBatch() (*MintingBatch, error) {
	req := newStateReq[*MintingBatch](reqTypePendingBatch)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// NumActiveBatches returns the total number of active batches that have an
// outstanding caretaker assigned.
func (c *ChainPlanter) NumActiveBatches() (int, error) {
	req := newStateReq[int](reqTypeNumActiveBatches)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return 0, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func (c *ChainPlanter) ListBatches(params ListBatchesParams) ([]*VerboseBatch,
	error) {

	req := newStateParamReq[[]*VerboseBatch](reqTypeListBatches, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// FundBatch sends a signal to the planter to fund the current batch, or create
// a funded batch.
func (c *ChainPlanter) FundBatch(params FundParams) (*FundBatchResp, error) {
	req := newStateParamReq[*FundBatchResp](reqTypeFundBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// PrepareBatch commits a caller-authored batch into its selected anchor
// output and returns the packet for external signing.
func (c *ChainPlanter) PrepareBatch() (*MintingBatch, error) {
	req := newStateReq[*MintingBatch](reqTypePrepareBatch)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// SealBatch attempts to seal the current batch, by providing or deriving all
// witnesses necessary to create the final genesis TX.
func (c *ChainPlanter) SealBatch(params SealParams) (*MintingBatch, error) {
	req := newStateParamReq[*MintingBatch](reqTypeSealBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// FinalizeBatch sends a signal to the planter to finalize the current batch.
func (c *ChainPlanter) FinalizeBatch(params FinalizeParams) (*MintingBatch,
	error) {

	req := newStateParamReq[*MintingBatch](reqTypeFinalizeBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// CancelBatch sends a signal to the planter to cancel the current batch.
func (c *ChainPlanter) CancelBatch() (*btcec.PublicKey, error) {
	req := newStateReq[*btcec.PublicKey](reqTypeCancelBatch)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// prepSeedlingDelegationKey finalizes the seedling delegation key.
func (c *ChainPlanter) prepSeedlingDelegationKey(ctx context.Context,
	req *Seedling) error {

	// If the universe commitments feature is disabled for this seedling,
	// we can skip any further delegation key considerations.
	if !req.SupplyCommitments {
		return nil
	}

	// If the delegation key is already set, we can skip any further
	// delegation key considerations.
	if req.DelegationKey.IsSome() {
		return nil
	}

	// At this point, we know that the universe commitments feature is
	// enabled for the seedling. If a group anchor seedling is specified
	// we will use its delegation key.
	if req.GroupAnchor != nil {
		// Retrieve the group anchor seedling from the pending batch.
		anchorSeedlingName := *req.GroupAnchor

		anchor, ok := c.pendingBatch.Seedlings[anchorSeedlingName]
		if anchor == nil || !ok {
			return fmt.Errorf("group anchor seedling not present "+
				"in batch (anchor_seedling_name=%s)",
				anchorSeedlingName)
		}

		if anchor.DelegationKey.IsNone() {
			return fmt.Errorf("group anchor seedling has no "+
				"delegation key (anchor_seedling_name=%s)",
				anchorSeedlingName)
		}

		// Set the delegation key for the seedling to the delegation key
		// of the group anchor seedling.
		req.DelegationKey = anchor.DelegationKey

		// Return early, no further seedling prep required for universe
		// commitments feature.
		return nil
	}

	// If an existing group key is set, we can use that to look up the
	// delegation key.
	if req.GroupInfo != nil && req.GroupInfo.GroupKey != nil {
		dKeyOpt, err := c.cfg.Log.FetchDelegationKey(
			ctx, req.GroupInfo.GroupKey.GroupPubKey,
		)
		if err != nil {
			return fmt.Errorf("unable to fetch delegation key "+
				"for group key: %w", err)
		}

		// Return early if a corresponding delegation key is found.
		if dKeyOpt.IsSome() {
			req.DelegationKey = dKeyOpt
			return nil
		}
	}

	// On the other hand, if we're handling the group anchor seedling,
	// and the delegation key is unset, we must generate a new one.
	if req.EnableEmission && req.GroupAnchor == nil {
		newKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to derive pre-commitment "+
				"output key: %w", err)
		}

		req.DelegationKey = fn.Some(newKey)
		return nil
	}

	return fmt.Errorf("failed to finalize delegation key for "+
		"seedling %s", req.AssetName)
}

// prepAssetSeedling performs some basic validation for the Seedling, then
// either adds it to an existing pending batch or creates a new batch for it.
func (c *ChainPlanter) prepAssetSeedling(ctx context.Context,
	req *Seedling) error {
	// This must be the first operation. Once preparation freezes or commits
	// the asset root, no request validation, key derivation or metadata
	// assignment may run for an additional seedling.
	if c.pendingBatch != nil &&
		c.pendingBatch.State() != BatchStatePending {

		return fmt.Errorf("batch in state %v cannot accept new seedlings",
			c.pendingBatch.State())
	}

	// If the seedling has the universe/supply commitment feature enabled,
	// finalize the delegation key.
	if req.SupplyCommitments {
		err := c.prepSeedlingDelegationKey(ctx, req)
		if err != nil {
			return err
		}
	}

	// Set seedling asset metadata fields.
	req.Meta.UniverseCommitments = req.SupplyCommitments

	// If a delegation key is set in the seedling, set it in the metadata.
	if req.DelegationKey.IsSome() {
		keyDesc, err := req.DelegationKey.UnwrapOrErr(
			fmt.Errorf("delegation key is not set"),
		)
		if err != nil {
			return err
		}

		if keyDesc.PubKey == nil {
			return fmt.Errorf("delegation key has no public key")
		}

		req.Meta.DelegationKey = fn.Some(*keyDesc.PubKey)
	}

	// We will perform basic validation on the seedling, including metadata
	// validation.
	if err := req.validateFields(); err != nil {
		return err
	}

	// The seedling name must be unique within the pending batch.
	if c.pendingBatch != nil {
		if _, ok := c.pendingBatch.Seedlings[req.AssetName]; ok {
			return fmt.Errorf("asset with name %v already in batch",
				req.AssetName)
		}
	}

	// If emission is enabled and a group key is specified, we need to
	// make sure the asset types match and that we can sign with that key.
	if req.HasGroupKey() {
		groupKeyBytes := req.GroupInfo.GroupPubKey.
			SerializeCompressed()
		groupInfo, err := c.cfg.Log.FetchGroupByGroupKey(
			ctx, &req.GroupInfo.GroupPubKey,
		)
		if err != nil {
			return fmt.Errorf("group key %x not found: %w",
				groupKeyBytes, err,
			)
		}

		anchorMeta, err := c.cfg.Log.FetchAssetMeta(
			ctx, groupInfo.Genesis.ID(),
		)
		if err != nil {
			return fmt.Errorf("group anchor genesis %x not found: "+
				"%w", groupKeyBytes, err,
			)
		}

		err = req.validateGroupKey(*groupInfo, anchorMeta)
		if err != nil {
			return err
		}

		req.GroupInfo = groupInfo
	}

	// If a group anchor is specified, we need to ensure that the anchor
	// seedling is already in the batch and has emission enabled.
	if req.GroupAnchor != nil {
		if c.pendingBatch == nil {
			return fmt.Errorf("batch empty, group anchor %v "+
				"invalid", *req.GroupAnchor)
		}

		err := c.pendingBatch.validateGroupAnchor(req)
		if err != nil {
			return err
		}
	}

	// If a group internal key or tapscript root is specified, emission must
	// also be enabled.
	if !req.EnableEmission {
		// For re-issuing grouped assets or regular (non-grouped)
		// assets, the group internal key shouldn't be set. It is,
		// however, set for re-issuance with an external key, because
		// the internal group key is the key we compare the external key
		// against.
		if req.GroupInternalKey != nil && req.ExternalKey.IsNone() {
			return fmt.Errorf("cannot specify group internal key " +
				"without creating a new grouped asset")
		}

		if req.GroupTapscriptRoot != nil {
			return fmt.Errorf("cannot specify group tapscript " +
				"root without creating a new grouped asset")
		}
	}

	// For group anchors, derive an internal key for the future group key if
	// none was provided.
	if req.EnableEmission && req.GroupInternalKey == nil {
		groupInternalKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to obtain internal key for "+
				"group key for seedling: %s %w", req.AssetName,
				err)
		}

		req.GroupInternalKey = &groupInternalKey
	}

	// Now that we've validated the seedling, we can derive a script key to
	// be used for this asset, if an external script key was not provided.
	if req.ScriptKey.PubKey == nil {
		scriptKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to obtain script key for "+
				"seedling: %s %w", req.AssetName, err)
		}

		// Default to BIP86 for the script key tweaking method.
		req.ScriptKey = asset.NewScriptKeyBip86(scriptKey)
	}

	// Now that we know the seedling is valid, we'll check to see if a batch
	// already exists.
	switch {
	// No batch, so we'll create a new one with only this seedling as part
	// of the batch.
	case c.pendingBatch == nil:
		newBatch, err := c.newBatch()
		if err != nil {
			return err
		}

		log.Infof("Attempting to add a seedling to a new batch "+
			"(seedling=%v)", req)

		// Stage the seedling on the local newBatch and persist
		// the whole batch atomically via CommitMintingBatch. The
		// planter's pendingBatch is assigned only after the DB
		// write succeeds; on any failure newBatch is discarded
		// and the planter state is unchanged.
		err = newBatch.AddSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.CommitMintingBatch(ctx, newBatch)
		if err != nil {
			return err
		}

		c.pendingBatch = newBatch

	// A batch already exists, so we'll add this seedling to the batch,
	// committing it to disk fully before we move on.
	case c.pendingBatch != nil:
		log.Infof("Attempting to add a seedling to batch (seedling=%v)",
			req)

		// Validate first without mutating the in-memory batch,
		// then persist, then mirror the seedling into memory.
		// This ordering ensures the in-memory batch never
		// advances unless the DB write succeeded: a failed
		// AddSeedlingsToBatch leaves both disk and memory at
		// their prior state.
		err := c.pendingBatch.validateSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.AddSeedlingsToBatch(
			ctx, c.pendingBatch.BatchKey.PubKey, req,
		)
		if err != nil {
			return err
		}

		c.pendingBatch.commitSeedling(*req)
	}

	// Now that we have the batch committed to disk, we'll return back to
	// the caller if we should finalize the batch immediately or not based
	// on its preference.
	return nil
}

// updateMintingProofs is called by the re-org watcher when it detects a re-org
// and has updated the minting proofs. This cannot be done by the caretaker
// itself, because its job is already done at the point that a re-org can happen
// (the batch is finalized after a single confirmation).
func (c *ChainPlanter) updateMintingProofs(proofs []*proof.Proof) error {
	ctx, cancel := c.WithCtxQuitNoTimeout()
	defer cancel()

	// This is a bit of a hacky part. If we have a chain of transactions
	// that were re-organized, we can't verify the whole chain until all of
	// the transactions were confirmed and all proofs were updated with the
	// new blocks and merkle roots. So we'll skip the verification here
	// since we don't know if the whole chain has been updated yet (the
	// confirmations might come in out of order).
	// TODO(guggero): Find a better way to do this.
	vCtx := c.verifierCtx(ctx)
	vCtx.HeaderVerifier = func(wire.BlockHeader, uint32) error {
		return nil
	}

	for idx := range proofs {
		p := proofs[idx]

		existingProofs, err := c.cfg.ProofUpdates.FetchProofs(
			ctx, p.Asset.ID(),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch proofs: %w", err)
		}

		updatedProofs, err := proof.ReplaceProofInFiles(
			p, existingProofs,
		)
		if err != nil {
			return fmt.Errorf("unable to update minted proofs: %w",
				err)
		}

		if len(updatedProofs) > 0 {
			err = c.cfg.ProofUpdates.ImportProofs(
				ctx, vCtx, true, updatedProofs...,
			)
			if err != nil {
				return fmt.Errorf("unable to import updated "+
					"minted proofs: %w", err)
			}
		}

		// The universe ID serves to identify the universe root we want
		// to update this asset in. This is either the assetID or the
		// group key.
		uniID := universe.Identifier{
			AssetID: p.Asset.ID(),
		}
		if p.Asset.GroupKey != nil {
			uniID.GroupKey = &p.Asset.GroupKey.GroupPubKey
		}

		log.Debugf("Updating issuance proof for asset with universe, "+
			"key=%v", spew.Sdump(uniID))

		// The base key is the set of bytes that keys into the universe,
		// this'll be the outpoint where it was created at and the
		// script key for that asset.
		leafKey := universe.BaseLeafKey{
			OutPoint: wire.OutPoint{
				Hash:  p.AnchorTx.TxHash(),
				Index: p.InclusionProof.OutputIndex,
			},
			ScriptKey: &p.Asset.ScriptKey,
		}

		// The universe leaf stores the raw proof, so we'll encode it
		// here now.
		proofBytes, err := p.Bytes()
		if err != nil {
			return fmt.Errorf("unable to encode proof: %w", err)
		}

		// With both of those assembled, we can now update issuance
		// which takes the amount and proof of the minting event.
		uniGen := universe.GenesisWithGroup{
			Genesis: p.Asset.Genesis,
		}
		if p.Asset.GroupKey != nil {
			uniGen.GroupKey = p.Asset.GroupKey
		}
		mintingLeaf := &universe.Leaf{
			GenesisWithGroup: uniGen,
			RawProof:         proofBytes,
			Amt:              p.Asset.Amount,
			Asset:            &p.Asset,
		}
		_, err = c.cfg.Universe.UpsertProofLeaf(
			ctx, uniID, leafKey, mintingLeaf,
		)
		if err != nil {
			return fmt.Errorf("unable to update issuance: %w", err)
		}
	}

	return nil
}

// QueueNewSeedling attempts to queue a new seedling request (the intent for
// New asset creation or ongoing issuance) to the ChainPlanter. A channel is
// returned where future updates will be sent over. If an error is returned no
// issuance operation was possible.
//
// NOTE: This is part of the Planter interface.
func (c *ChainPlanter) QueueNewSeedling(req *Seedling) (SeedlingUpdates, error) {
	req.updates = make(SeedlingUpdates, 1)

	// Attempt to send the new request, or exit if the quit channel
	// triggered first.
	if !fn.SendOrQuit(c.seedlingReqs, req, c.Quit) {
		return nil, fmt.Errorf("planter shutting down")
	}

	return req.updates, nil
}

// CancelSeedling attempts to cancel the creation of a new asset identified by
// its name. If the seedling has already progressed to a point where the
// genesis PSBT has been broadcasted, an error is returned.
//
// NOTE: This is part of the Planter interface.
func (c *ChainPlanter) CancelSeedling() error {
	// TODO(roasbeef): actually needed?
	return nil
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new events that are broadcast.
func (c *ChainPlanter) RegisterSubscriber(
	receiver *fn.EventReceiver[fn.Event], _, _ bool) error {

	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	c.subscribers[receiver.ID()] = receiver

	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (c *ChainPlanter) RemoveSubscriber(
	subscriber *fn.EventReceiver[fn.Event]) error {

	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	_, ok := c.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(c.subscribers, subscriber.ID())

	return nil
}

// publishSubscriberEvent publishes an event to all subscribers.
func (c *ChainPlanter) publishSubscriberEvent(event fn.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	for _, sub := range c.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// verifierCtx returns a verifier context that can be used to verify proofs.
func (c *ChainPlanter) verifierCtx(ctx context.Context) proof.VerifierCtx {
	headerVerifier := tapnode.GenHeaderVerifier(ctx, c.cfg.ChainBridge)
	merkleVerifier := proof.DefaultMerkleVerifier
	groupVerifier := GenGroupVerifier(ctx, c.cfg.Log)

	return proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: merkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: c.cfg.ChainBridge,
		IgnoreChecker:  c.cfg.IgnoreChecker,
	}
}

// A compile-time assertion to make sure that ChainPlanter implements the
// tapgarden.Planter interface.
var _ Planter = (*ChainPlanter)(nil)

// A compile-time assertion to make sure BatchCaretaker satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[fn.Event, bool] = (*ChainPlanter)(nil)

// PreCommitmentOutput provides metadata related to the pre-commitment output
// of a mint anchor transaction. This output serves as an intermediate step
// before being spent by the universe commitment transaction.
type PreCommitmentOutput struct {
	// OutIdx specifies the index of the pre-commitment output within the
	// batch mint anchor transaction.
	OutIdx uint32

	// InternalKey is the Taproot internal public key associated with the
	// pre-commitment output.
	InternalKey DelegationKey

	// GroupPubKey is the asset-group public key for this pre-commitment.
	//
	// Optional:
	//   - Present when the group key is already known—either reused from an
	//     existing group at funding time or generated once the batch is
	//     sealed.
	//   - Absent while an unsealed batch without a prior group key is still
	//     in progress.
	GroupPubKey fn.Option[btcec.PublicKey]
}

// NewPreCommitmentOutput creates a new PreCommitmentOutput instance.
func NewPreCommitmentOutput(outIdx uint32, internalKey DelegationKey,
	groupPubKey fn.Option[btcec.PublicKey]) PreCommitmentOutput {

	return PreCommitmentOutput{
		OutIdx:      outIdx,
		InternalKey: internalKey,
		GroupPubKey: groupPubKey,
	}
}

// PreCommitTxOut returns the pre-commitment output as a wire.TxOut instance.
func PreCommitTxOut(internalKey btcec.PublicKey) (wire.TxOut, error) {
	var zero wire.TxOut

	// Formulate a taproot output key from the taproot internal key.
	taprootOutputKey := txscript.ComputeTaprootKeyNoScript(&internalKey)

	// Create a new pay-to-taproot pk script from the taproot output key.
	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	if err != nil {
		return zero, fmt.Errorf("unable to create pre-commitment "+
			"output pk script: %w", err)
	}

	// Return the minting anchor transaction pre-commitment output.
	return wire.TxOut{
		Value:    int64(tapsend.DummyAmtSats),
		PkScript: pkScript,
	}, nil
}

// FundedMintAnchorPsbt is a struct that contains a funded minting anchor
// transaction PSBT.
type FundedMintAnchorPsbt struct {
	// FundedPsbt is the PSBT packet that has been funded by the wallet.
	tapsend.FundedPsbt

	// AssetAnchorOutIdx is the index of the asset anchor output in the
	// transaction.
	AssetAnchorOutIdx uint32

	// PreCommitmentOutput contains metadata describing the pre-commitment
	// output.
	//
	// This field is set only if the pre-commitment output exists in the
	// transaction. The pre-commitment output is later spent by the universe
	// commitment transaction.
	PreCommitmentOutput fn.Option[PreCommitmentOutput]
}

// NewFundedMintAnchorPsbt creates a new funded minting anchor PSBT package from
// a funded PSBT.
func NewFundedMintAnchorPsbt(
	fundedPsbt tapsend.FundedPsbt, anchorOutIndexes AnchorTxOutputIndexes,
	preCommitOut fn.Option[PreCommitmentOutput]) (FundedMintAnchorPsbt,
	error) {

	var zero FundedMintAnchorPsbt

	// Sanity check pre-commitment output arguments.
	if anchorOutIndexes.PreCommitOutIdx.IsSome() != preCommitOut.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index and " +
			"pre-commitment output must be both set or both unset")
	}

	return FundedMintAnchorPsbt{
		FundedPsbt:          fundedPsbt,
		AssetAnchorOutIdx:   anchorOutIndexes.AssetAnchorOutIdx,
		PreCommitmentOutput: preCommitOut,
	}, nil
}

// GenesisOutpoint returns the genesis outpoint of the mint anchor PSBT, which
// is the first input in the genesis transaction.
func (f *FundedMintAnchorPsbt) GenesisOutpoint() fn.Option[wire.OutPoint] {
	var zero fn.Option[wire.OutPoint]

	if f.Pkt == nil {
		return zero
	}

	if f.Pkt.UnsignedTx == nil {
		return zero
	}

	if len(f.Pkt.UnsignedTx.TxIn) == 0 {
		return zero
	}

	return fn.Some(f.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint)
}

// Copy creates a deep copy of FundedMintAnchorPsbt.
func (f *FundedMintAnchorPsbt) Copy() *FundedMintAnchorPsbt {
	newMintAnchorPsbt := &FundedMintAnchorPsbt{
		FundedPsbt: tapsend.FundedPsbt{
			ChangeOutputIndex: f.ChangeOutputIndex,
			ChainFees:         f.ChainFees,
			LockedUTXOs:       fn.CopySlice(f.LockedUTXOs),
		},
		AssetAnchorOutIdx:   f.AssetAnchorOutIdx,
		PreCommitmentOutput: f.PreCommitmentOutput,
	}

	if f.Pkt != nil {
		if f.Pkt.UnsignedTx == nil {
			newMintAnchorPsbt.Pkt = copyMalformedPsbt(f.Pkt)
		} else {
			var buf bytes.Buffer
			serializeErr := f.Pkt.Serialize(&buf)
			if serializeErr == nil {
				var parseErr error
				newMintAnchorPsbt.Pkt, parseErr = psbt.NewFromRawBytes(
					&buf, false,
				)
				if parseErr != nil {
					log.Warnf("Unable to parse serialized mint anchor "+
						"PSBT while copying: %v", parseErr)
				}
			} else {
				log.Warnf("Unable to serialize mint anchor PSBT while "+
					"copying: %v", serializeErr)
			}
			if newMintAnchorPsbt.Pkt == nil {
				newMintAnchorPsbt.Pkt = copyMalformedPsbt(f.Pkt)
			}
		}
	}

	return newMintAnchorPsbt
}

func copyMalformedPsbt(pkt *psbt.Packet) *psbt.Packet {
	copyUnknowns := func(src []*psbt.Unknown) []*psbt.Unknown {
		if src == nil {
			return nil
		}
		dst := make([]*psbt.Unknown, len(src))
		for idx, unknown := range src {
			if unknown == nil {
				continue
			}
			dst[idx] = &psbt.Unknown{
				Key:   fn.CopySlice(unknown.Key),
				Value: fn.CopySlice(unknown.Value),
			}
		}
		return dst
	}

	var txCopy *wire.MsgTx
	if pkt.UnsignedTx != nil {
		txCopy = pkt.UnsignedTx.Copy()
	}
	return &psbt.Packet{
		UnsignedTx: txCopy,
		Inputs:     fn.CopySlice(pkt.Inputs),
		Outputs:    fn.CopySlice(pkt.Outputs),
		XPubs:      fn.CopySlice(pkt.XPubs),
		Unknowns:   copyUnknowns(pkt.Unknowns),
	}
}
