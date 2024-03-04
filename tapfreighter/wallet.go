package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	// defaultCoinLeaseDuration is the default duration for which we lease
	// managed UTXOs of asset outputs from the wallet.
	defaultCoinLeaseDuration = 10 * time.Minute

	// defaultBroadcastCoinLeaseDuration is the default duration for which
	// we lease managed UTXOs of asset outputs from the wallet when we have
	// broadcast a transaction that spends them. This represents a full year
	// and avoids the same UTXO being used in another transaction if the
	// confirmation of the first transaction takes a long time.
	defaultBroadcastCoinLeaseDuration = 365 * 24 * time.Hour
)

var (
	// defaultWalletLeaseIdentifier is the binary representation of the
	// SHA256 hash of the string "tapd-internal-lock-id" and is used for
	// UTXO leases/locks/reservations to identify that we ourselves are
	// leasing an UTXO, for example when giving out a funded vPSBT. The ID
	// corresponds to the hex value of
	// 6d7cd7ee247587eef86766140262685819deebc034ad80664fb74ec2ad6e11d7.
	defaultWalletLeaseIdentifier = [32]byte{
		0x6d, 0x7c, 0xd7, 0xee, 0x24, 0x75, 0x87, 0xee,
		0xf8, 0x67, 0x66, 0x14, 0x02, 0x62, 0x68, 0x58,
		0x19, 0xde, 0xeb, 0xc0, 0x34, 0xad, 0x80, 0x66,
		0x4f, 0xb7, 0x4e, 0xc2, 0xad, 0x6e, 0x11, 0xd7,
	}

	// ErrFullBurnNotSupported is returned when we attempt to burn all
	// assets of an anchor output, which is not supported.
	ErrFullBurnNotSupported = errors.New("burning all assets of an " +
		"anchor output is not supported")
)

// Wallet is an interface for funding and signing asset transfers.
type Wallet interface {
	// FundAddressSend funds a virtual transaction, selecting assets to
	// spend in order to pay the given address. It also returns supporting
	// data which assists in processing the virtual transaction: passive
	// asset re-anchors and the Taproot Asset level commitment of the
	// selected assets.
	FundAddressSend(ctx context.Context,
		receiverAddrs ...*address.Tap) (*FundedVPacket, error)

	// FundPacket funds a virtual transaction, selecting assets to spend
	// in order to pay the given recipient. The selected input is then added
	// to the given virtual transaction.
	FundPacket(ctx context.Context, fundDesc *tapsend.FundingDescriptor,
		vPkt *tappsbt.VPacket) (*FundedVPacket, error)

	// FundBurn funds a virtual transaction for burning the given amount of
	// units of the given asset.
	FundBurn(ctx context.Context,
		fundDesc *tapsend.FundingDescriptor) (*FundedVPacket, error)

	// SignVirtualPacket signs the virtual transaction of the given packet
	// and returns the input indexes that were signed.
	SignVirtualPacket(vPkt *tappsbt.VPacket,
		optFuncs ...SignVirtualPacketOption) ([]uint32, error)

	// CreatePassiveAssets creates passive asset packets for the given
	// active packets and input Taproot Asset commitments.
	CreatePassiveAssets(ctx context.Context,
		activePackets []*tappsbt.VPacket,
		inputCommitments tappsbt.InputCommitments) ([]*tappsbt.VPacket,
		error)

	// SignPassiveAssets signs the given passive asset packets.
	SignPassiveAssets(passiveAssets []*tappsbt.VPacket) error

	// AnchorVirtualTransactions creates a BTC level anchor transaction that
	// anchors all the virtual transactions of the given packets (for both
	// sending and passive asset re-anchoring).
	//
	// This method returns both the funded anchor TX with all the output
	// information intact for later exclusion proof creation, and the fully
	// signed and finalized anchor TX along with the total amount of sats
	// paid in chain fees by the anchor TX.
	AnchorVirtualTransactions(ctx context.Context,
		params *AnchorVTxnsParams) (*tapsend.AnchorTransaction, error)

	// SignOwnershipProof creates and signs an ownership proof for the given
	// owned asset. The ownership proof consists of a valid witness of a
	// signed virtual packet that spends the asset fully to the NUMS key.
	SignOwnershipProof(ownedAsset *asset.Asset) (wire.TxWitness, error)

	// FetchScriptKey attempts to fetch the full tweaked script key struct
	// (including the key descriptor) for the given tweaked script key. If
	// the key cannot be found, then address.ErrScriptKeyNotFound is
	// returned.
	FetchScriptKey(ctx context.Context,
		tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey,
		error)

	// FetchInternalKeyLocator attempts to fetch the key locator information
	// for the given raw internal key. If the key cannot be found, then
	// address.ErrInternalKeyNotFound is returned.
	FetchInternalKeyLocator(ctx context.Context,
		rawKey *btcec.PublicKey) (keychain.KeyLocator, error)
}

// AddrBook is an interface that provides access to the address book.
type AddrBook interface {
	// FetchScriptKey attempts to fetch the full tweaked script key struct
	// (including the key descriptor) for the given tweaked script key. If
	// the key cannot be found, then ErrScriptKeyNotFound is returned.
	FetchScriptKey(ctx context.Context,
		tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey,
		error)

	// FetchInternalKeyLocator attempts to fetch the key locator information
	// for the given raw internal key. If the key cannot be found, then
	// ErrInternalKeyNotFound is returned.
	FetchInternalKeyLocator(ctx context.Context,
		rawKey *btcec.PublicKey) (keychain.KeyLocator, error)
}

// AnchorVTxnsParams holds all the parameters needed to create a BTC level
// anchor transaction that anchors multiple virtual transactions.
type AnchorVTxnsParams struct {
	// FeeRate is the fee rate that should be used to fund the anchor
	// transaction.
	FeeRate chainfee.SatPerKWeight

	// ActivePackets is a list of all the virtual transactions that should
	// be anchored by the anchor transaction.
	ActivePackets []*tappsbt.VPacket

	// PassivePackets is a list of all the virtual transactions which
	// re-anchor passive assets.
	PassivePackets []*tappsbt.VPacket
}

// NewCoinSelect creates a new CoinSelect.
func NewCoinSelect(coinLister CoinLister) *CoinSelect {
	return &CoinSelect{
		coinLister: coinLister,
	}
}

// CoinSelect selects asset coins to spend in order to fund a send
// transaction.
type CoinSelect struct {
	coinLister CoinLister

	// coinLock is a read/write mutex that is used to ensure that only one
	// goroutine is attempting to call any coin selection related methods at
	// any time. This is necessary as some of the calls to the store (e.g.
	// ListEligibleCoins -> LeaseCoin) are called after each other and
	// cannot be placed within the same database transaction. So calls to
	// those methods must hold this coin lock.
	coinLock sync.Mutex
}

// SelectCoins returns a set of not yet leased coins that satisfy the given
// constraints and strategy. The coins returned are leased for the default lease
// duration.
func (s *CoinSelect) SelectCoins(ctx context.Context,
	constraints CommitmentConstraints,
	strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment, error) {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	// Before we select any coins, let's do some cleanup of expired leases.
	if err := s.coinLister.DeleteExpiredLeases(ctx); err != nil {
		return nil, fmt.Errorf("unable to delete expired leases: %w",
			err)
	}

	listConstraints := CommitmentConstraints{
		GroupKey: constraints.GroupKey,
		AssetID:  constraints.AssetID,
		MinAmt:   1,
	}
	eligibleCommitments, err := s.coinLister.ListEligibleCoins(
		ctx, listConstraints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list eligible coins: %w", err)
	}

	log.Infof("Identified %v eligible asset inputs for send of %d to %x",
		len(eligibleCommitments), constraints.MinAmt,
		constraints.AssetID[:])

	selectedCoins, err := s.selectForAmount(
		constraints.MinAmt, eligibleCommitments, strategy,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to select coins: %w", err)
	}

	// We now need to lock/lease/reserve those selected coins so
	// that they can't be used by other processes.
	expiry := time.Now().Add(defaultCoinLeaseDuration)
	coinOutPoints := fn.Map(
		selectedCoins, func(c *AnchoredCommitment) wire.OutPoint {
			return c.AnchorPoint
		},
	)
	err = s.coinLister.LeaseCoins(
		ctx, defaultWalletLeaseIdentifier, expiry, coinOutPoints...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to lease coin: %w", err)
	}

	return selectedCoins, nil
}

// LeaseCoins leases/locks/reserves coins for the given lease owner until the
// given expiry. This is used to prevent multiple concurrent coin selection
// attempts from selecting the same coin(s).
func (s *CoinSelect) LeaseCoins(ctx context.Context, leaseOwner [32]byte,
	expiry time.Time, utxoOutpoints ...wire.OutPoint) error {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	return s.coinLister.LeaseCoins(
		ctx, leaseOwner, expiry, utxoOutpoints...,
	)
}

// ReleaseCoins releases/unlocks coins that were previously leased and makes
// them available for coin selection again.
func (s *CoinSelect) ReleaseCoins(ctx context.Context,
	utxoOutpoints ...wire.OutPoint) error {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	return s.coinLister.ReleaseCoins(ctx, utxoOutpoints...)
}

// selectForAmount selects a subset of the given eligible commitments which
// cumulatively sum to at least the minimum required amount. The selection
// strategy determines how the commitments are selected.
func (s *CoinSelect) selectForAmount(minTotalAmount uint64,
	eligibleCommitments []*AnchoredCommitment,
	strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment,
	error) {

	// Select the first subset of eligible commitments which cumulatively
	// sum to at least the minimum required amount.
	var selectedCommitments []*AnchoredCommitment
	amountSum := uint64(0)

	switch strategy {
	case PreferMaxAmount:
		// Sort eligible commitments from the largest amount to
		// smallest.
		sort.Slice(
			eligibleCommitments, func(i, j int) bool {
				isLess := eligibleCommitments[i].Asset.Amount <
					eligibleCommitments[j].Asset.Amount

				// Negate the result to sort in descending
				// order.
				return !isLess
			},
		)

		// Select the first subset of eligible commitments which
		// cumulatively sum to at least the minimum required amount.
		for _, anchoredCommitment := range eligibleCommitments {
			selectedCommitments = append(
				selectedCommitments, anchoredCommitment,
			)

			// Keep track of the total amount of assets we've seen
			// so far.
			amountSum += uint64(anchoredCommitment.Asset.Amount)
			if amountSum >= minTotalAmount {
				// At this point a target min amount was
				// specified and has been reached.
				break
			}
		}

	default:
		return nil, fmt.Errorf("unknown multi coin selection "+
			"strategy: %v", strategy)
	}

	// Having examined all the eligible commitments, return an error if the
	// minimal funding amount was not reached.
	if amountSum < minTotalAmount {
		return nil, ErrMatchingAssetsNotFound
	}
	return selectedCommitments, nil
}

var _ CoinSelector = (*CoinSelect)(nil)

// WalletConfig holds the configuration for a new Wallet.
type WalletConfig struct {
	// CoinSelector is the interface used to select input coins (assets)
	// for the transfer.
	CoinSelector CoinSelector

	// AssetProofs is used to write the proof files on disk for the
	// receiver during a transfer.
	//
	// TODO(roasbeef): replace with proof.Courier in the future/
	AssetProofs proof.Archiver

	// AddrBook is used to fetch information about local address book
	// related data in the database.
	AddrBook AddrBook

	// KeyRing is used to generate new keys throughout the transfer
	// process.
	KeyRing KeyRing

	// Signer implements the Taproot Asset level signing we need to sign a
	// virtual transaction.
	Signer Signer

	// TxValidator allows us to validate each Taproot Asset virtual
	// transaction we create.
	TxValidator tapscript.TxValidator

	// WitnessValidator allows us to validate the witnesses of vPSBTs
	// we create.
	WitnessValidator tapscript.WitnessValidator

	// Wallet is used to fund+sign PSBTs for the transfer transaction.
	Wallet WalletAnchor

	// ChainParams is the chain params of the chain we operate on.
	ChainParams *address.ChainParams
}

// AssetWallet is an implementation of the Wallet interface that can create
// virtual transactions, sign them and commit them on-chain.
type AssetWallet struct {
	cfg *WalletConfig
}

// NewAssetWallet creates a new AssetWallet instance from the given
// configuration.
func NewAssetWallet(cfg *WalletConfig) *AssetWallet {
	return &AssetWallet{
		cfg: cfg,
	}
}

// FundedVPacket is the result from an attempt to fund a given Taproot Asset
// address send request via a call to FundAddressSend.
type FundedVPacket struct {
	// VPacket is the virtual transaction that was created to fund the
	// transfer.
	VPacket *tappsbt.VPacket

	// InputCommitments is a map from virtual package input index to its
	// associated Taproot Asset commitment.
	InputCommitments tappsbt.InputCommitments
}

// FundAddressSend funds a virtual transaction, selecting assets to spend in
// order to pay the given address. It also returns supporting data which assists
// in processing the virtual transaction: passive asset re-anchors and the
// Taproot Asset level commitment of the selected assets.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) FundAddressSend(ctx context.Context,
	receiverAddrs ...*address.Tap) (*FundedVPacket, error) {

	// We start by creating a new virtual transaction that will be used to
	// hold the asset transfer. Because sending to an address is always a
	// non-interactive process, we can use this function that always creates
	// a change output.
	vPkt, err := tappsbt.FromAddresses(receiverAddrs, 1)
	if err != nil {
		return nil, fmt.Errorf("unable to create virtual transaction "+
			"from addresses: %w", err)
	}

	fundDesc, err := tapsend.DescribeAddrs(receiverAddrs)
	if err != nil {
		return nil, fmt.Errorf("unable to describe recipients: %w", err)
	}

	fundedVPkt, err := f.FundPacket(ctx, fundDesc, vPkt)
	if err != nil {
		return nil, err
	}

	return fundedVPkt, nil
}

// createPassivePacket creates a virtual packet for the given passive asset.
func createPassivePacket(params *address.ChainParams, passiveAsset *asset.Asset,
	activePackets []*tappsbt.VPacket, anchorOutputIndex uint32,
	anchorOutputInternalKey keychain.KeyDescriptor, prevOut wire.OutPoint,
	inputProof *proof.Proof) (*tappsbt.VPacket, error) {

	// Specify virtual input.
	inputAsset := passiveAsset.Copy()
	vInput := tappsbt.VInput{
		Proof: inputProof,
		PInput: psbt.PInput{
			SighashType: txscript.SigHashDefault,
		},
	}

	// Passive assets by definition are in the same anchor input as some of
	// the active assets. So to avoid needing to reconstruct the anchor here
	// again, we just copy the anchor of an active packet.
	for _, activePacket := range activePackets {
		for idx := range activePacket.Inputs {
			if activePacket.Inputs[idx].PrevID.OutPoint == prevOut {
				vInput.Anchor = activePacket.Inputs[idx].Anchor

				vInput.PrevID = asset.PrevID{
					OutPoint: prevOut,
					ID:       inputAsset.ID(),
					ScriptKey: asset.ToSerialized(
						inputAsset.ScriptKey.PubKey,
					),
				}

				break
			}
		}
	}

	// If we didn't find the anchor in an active packet, something
	// definitely went wrong.
	emptyPrevID := asset.PrevID{}
	if vInput.PrevID == emptyPrevID {
		return nil, fmt.Errorf("unable to find anchor for passive "+
			"asset %v", passiveAsset.ID())
	}

	// Specify virtual output.
	outputAsset := passiveAsset.Copy()

	// Clear the split commitment root, as we'll be transferring the whole
	// asset.
	outputAsset.SplitCommitmentRoot = nil

	// Clear the output asset witness data. We'll be creating a new witness.
	outputAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &vInput.PrevID,
	}}

	vOutput := tappsbt.VOutput{
		Amount:       outputAsset.Amount,
		AssetVersion: outputAsset.Version,

		// In this case, the receiver of the output is also the sender.
		// We therefore set interactive to true to indicate that the
		// receiver is aware of the transfer.
		Interactive: true,

		AnchorOutputIndex: anchorOutputIndex,
		ScriptKey:         outputAsset.ScriptKey,
		Asset:             outputAsset,
	}

	// Set output internal key.
	vOutput.SetAnchorInternalKey(anchorOutputInternalKey, params.HDCoinType)

	// Create VPacket.
	vPacket := &tappsbt.VPacket{
		Inputs:      []*tappsbt.VInput{&vInput},
		Outputs:     []*tappsbt.VOutput{&vOutput},
		ChainParams: params,
	}

	// Set the input asset. The input asset proof is not provided as it is
	// not needed for the re-anchoring process.
	vPacket.SetInputAsset(0, inputAsset)

	return vPacket, nil
}

// FundPacket funds a virtual transaction, selecting assets to spend in order to
// pay the given recipient. The selected input is then added to the given
// virtual transaction.
func (f *AssetWallet) FundPacket(ctx context.Context,
	fundDesc *tapsend.FundingDescriptor,
	vPkt *tappsbt.VPacket) (*FundedVPacket, error) {

	// The input and address networks must match.
	if !address.IsForNet(vPkt.ChainParams.TapHRP, f.cfg.ChainParams) {
		return nil, address.ErrMismatchedHRP
	}

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taproot asset coin selection.
	constraints := CommitmentConstraints{
		GroupKey: fundDesc.GroupKey,
		AssetID:  &fundDesc.ID,
		MinAmt:   fundDesc.Amount,
	}
	selectedCommitments, err := f.cfg.CoinSelector.SelectCoins(
		ctx, constraints, PreferMaxAmount,
	)
	if err != nil {
		return nil, err
	}

	return f.fundPacketWithInputs(ctx, fundDesc, vPkt, selectedCommitments)
}

// FundBurn funds a virtual transaction for burning the given amount of units of
// the given asset.
func (f *AssetWallet) FundBurn(ctx context.Context,
	fundDesc *tapsend.FundingDescriptor) (*FundedVPacket, error) {

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taproot asset coin selection.
	constraints := CommitmentConstraints{
		GroupKey: fundDesc.GroupKey,
		AssetID:  &fundDesc.ID,
		MinAmt:   fundDesc.Amount,
	}
	selectedCommitments, err := f.cfg.CoinSelector.SelectCoins(
		ctx, constraints, PreferMaxAmount,
	)
	if err != nil {
		return nil, err
	}

	// If we return with an error, we want to release the coins we've
	// selected.
	success := false
	defer func() {
		if !success {
			outpoints := fn.Map(
				selectedCommitments,
				func(c *AnchoredCommitment) wire.OutPoint {
					return c.AnchorPoint
				},
			)
			err := f.cfg.CoinSelector.ReleaseCoins(
				ctx, outpoints...,
			)
			if err != nil {
				log.Errorf("Unable to release coins: %v", err)
			}
		}
	}()

	activeAssets := fn.Filter(
		selectedCommitments, func(c *AnchoredCommitment) bool {
			return c.Asset.ID() == fundDesc.ID
		},
	)

	maxVersion := asset.V0
	for _, activeAsset := range activeAssets {
		if activeAsset.Asset.Version > maxVersion {
			maxVersion = activeAsset.Asset.Version
		}
	}

	// Now that we know what inputs we're going to spend, we know that by
	// definition, we use the first input's info as the burn's PrevID.
	firstInput := activeAssets[0]
	firstPrevID := asset.PrevID{
		OutPoint: firstInput.AnchorPoint,
		ID:       firstInput.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			firstInput.Asset.ScriptKey.PubKey,
		),
	}
	burnKey := asset.NewScriptKey(asset.DeriveBurnKey(firstPrevID))
	newInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return nil, err
	}

	// We want both the burn output and the change to be in the same anchor
	// output, that's why we create the packet manually.
	vPkt := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{
				ID: fundDesc.ID,
			},
		}},
		Outputs: []*tappsbt.VOutput{{
			Amount:            fundDesc.Amount,
			Type:              tappsbt.TypeSimple,
			Interactive:       true,
			AnchorOutputIndex: 0,
			AssetVersion:      maxVersion,
			ScriptKey:         burnKey,
		}},
		ChainParams: f.cfg.ChainParams,
	}
	vPkt.Outputs[0].SetAnchorInternalKey(
		newInternalKey, f.cfg.ChainParams.HDCoinType,
	)

	// The virtual transaction is now ready to be further enriched with the
	// split commitment and other data.
	fundedPkt, err := f.fundPacketWithInputs(
		ctx, fundDesc, vPkt, selectedCommitments,
	)
	if err != nil {
		return nil, err
	}

	// We want to avoid a BTC output being created that just sits there
	// without an actual commitment in it. So if we are not getting any
	// change or passive assets in this output, we'll not want to go through
	// with it.
	firstOut := fundedPkt.VPacket.Outputs[0]
	if len(fundedPkt.VPacket.Outputs) == 1 &&
		firstOut.Amount == fundDesc.Amount {

		// A burn is an interactive transfer. So we don't expect there
		// to be a tombstone unless there are passive assets in the same
		// commitment, in which case the wallet has marked the change
		// output as tappsbt.TypePassiveSplitRoot. If that's not the
		// case, we'll return as burning all assets in an anchor output
		// is not supported.
		otherAssets, err := f.hasOtherAssets(
			fundedPkt.InputCommitments, []*tappsbt.VPacket{vPkt},
		)
		if err != nil {
			return nil, err
		}

		if !otherAssets {
			return nil, ErrFullBurnNotSupported
		}
	}

	// Don't release the coins we've selected, as so far we've been
	// successful.
	success = true
	return fundedPkt, nil
}

// hasOtherAssets returns true if the given input commitments contain any other
// assets than the ones given in the virtual packets.
func (f *AssetWallet) hasOtherAssets(inputCommitments tappsbt.InputCommitments,
	vPackets []*tappsbt.VPacket) (bool, error) {

	for idx := range inputCommitments {
		tapCommitment := inputCommitments[idx]

		passiveCommitments, err := tapsend.RemovePacketsFromCommitment(
			tapCommitment, vPackets,
		)
		if err != nil {
			return false, err
		}

		if len(passiveCommitments.CommittedAssets()) > 0 {
			return true, nil
		}
	}

	return false, nil
}

// fundPacketWithInputs funds a virtual transaction with the given inputs.
func (f *AssetWallet) fundPacketWithInputs(ctx context.Context,
	fundDesc *tapsend.FundingDescriptor, vPkt *tappsbt.VPacket,
	selectedCommitments []*AnchoredCommitment) (*FundedVPacket, error) {

	log.Infof("Selected %v asset inputs for send of %d to %x",
		len(selectedCommitments), fundDesc.Amount, fundDesc.ID[:])

	assetType := selectedCommitments[0].Asset.Type

	totalInputAmt := uint64(0)
	for _, anchorAsset := range selectedCommitments {
		// We only use the sum of all assets of the same TAP commitment
		// key to avoid counting passive assets as well. We'll filter
		// out the passive assets from the selected commitments in a
		// later step.
		if anchorAsset.Asset.TapCommitmentKey() !=
			fundDesc.TapCommitmentKey() {

			continue
		}

		totalInputAmt += anchorAsset.Asset.Amount
	}

	inputCommitments, err := f.setVPacketInputs(
		ctx, selectedCommitments, vPkt,
	)
	if err != nil {
		return nil, err
	}

	fullValue, err := tapsend.ValidateInputs(
		inputCommitments, assetType, fundDesc,
	)
	if err != nil {
		return nil, err
	}

	// We want to know if we are sending to ourselves. We detect that by
	// looking at the key descriptor of the script key. Because that is not
	// part of addresses and might not be specified by the user through the
	// PSBT interface, we now attempt to detect all local script keys and
	// mark them as such by filling in the descriptor.
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]

		tweakedKey, err := f.cfg.AddrBook.FetchScriptKey(
			ctx, vOut.ScriptKey.PubKey,
		)
		switch {
		case err == nil:
			// We found a tweaked key for this output, so we'll
			// update the key with the full descriptor info.
			vOut.ScriptKey.TweakedScriptKey = tweakedKey

		case errors.Is(err, address.ErrScriptKeyNotFound):
			// This is not a local key, or at least we don't know of
			// it in the database.
			continue

		default:
			return nil, fmt.Errorf("cannot fetch script key: %w",
				err)
		}
	}

	// We expect some change back, or have passive assets to commit to, so
	// let's make sure we create a transfer output.
	var changeOut *tappsbt.VOutput
	if !fullValue {
		// Do we need to add a change output?
		changeOut, err = vPkt.SplitRootOutput()
		if err != nil {
			lastOut := vPkt.Outputs[len(vPkt.Outputs)-1]
			splitOutIndex := lastOut.AnchorOutputIndex + 1
			changeOut = &tappsbt.VOutput{
				Type:              tappsbt.TypeSplitRoot,
				Interactive:       lastOut.Interactive,
				AnchorOutputIndex: splitOutIndex,

				// We want to handle deriving a real key in a
				// generic manner, so we'll do that just below.
				ScriptKey: asset.NUMSScriptKey,
			}

			vPkt.Outputs = append(vPkt.Outputs, changeOut)
		}

		// Since we know we're going to receive some change back, we
		// need to make sure it is going to an address that we control.
		// This should only be the case where we create the default
		// change output with the NUMS key to avoid deriving too many
		// keys prematurely. We don't need to derive a new key if we
		// only have passive assets to commit to, since they all have
		// their own script key and the output is more of a placeholder
		// to attach the passive assets to.
		unSpendable, err := changeOut.ScriptKey.IsUnSpendable()
		if err != nil {
			return nil, fmt.Errorf("cannot determine if script "+
				"key is spendable: %w", err)
		}
		if unSpendable && !fullValue {
			changeScriptKey, err := f.cfg.KeyRing.DeriveNextKey(
				ctx, asset.TaprootAssetsKeyFamily,
			)
			if err != nil {
				return nil, err
			}

			// We'll assume BIP-0086 everywhere, and use the tweaked
			// key from here on out.
			changeOut.ScriptKey = asset.NewScriptKeyBip86(
				changeScriptKey,
			)
		}

		// For existing change outputs, we'll just update the amount
		// since we might not have known what coin would've been
		// selected and how large the change would turn out to be.
		changeOut.Amount = totalInputAmt - fundDesc.Amount

		// The asset version of the output should be the max of the set
		// of input versions. We need to set this now as in
		// PrepareOutputAssets locators are created which includes the
		// version from the vOut. If we don't set it here, a v1 asset
		// spent that becomes change will be a v0 if combined with such
		// inputs.
		//
		// TODO(roasbeef): remove as not needed?
		maxVersion := func(maxVersion asset.Version,
			vInput *tappsbt.VInput) asset.Version {

			if vInput.Asset().Version > maxVersion {
				return vInput.Asset().Version
			}

			return maxVersion
		}
		changeOut.AssetVersion = fn.Reduce(vPkt.Inputs, maxVersion)
	}

	// Before we can prepare output assets for our send, we need to generate
	// a new internal key for the anchor outputs. We assume any output that
	// hasn't got an internal key set is going to a local anchor, and we
	// provide the internal key for that.
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]
		if vOut.AnchorOutputInternalKey != nil {
			continue
		}

		newInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return nil, err
		}
		vOut.SetAnchorInternalKey(
			newInternalKey, f.cfg.ChainParams.HDCoinType,
		)
	}

	if err := tapsend.PrepareOutputAssets(ctx, vPkt); err != nil {
		return nil, fmt.Errorf("unable to create split commit: %w", err)
	}

	return &FundedVPacket{
		VPacket:          vPkt,
		InputCommitments: inputCommitments,
	}, nil
}

// setVPacketInputs sets the inputs of the given vPkt to the given send eligible
// commitments. It also returns the assets that were used as inputs.
func (f *AssetWallet) setVPacketInputs(ctx context.Context,
	eligibleCommitments []*AnchoredCommitment,
	vPkt *tappsbt.VPacket) (tappsbt.InputCommitments, error) {

	vPkt.Inputs = make([]*tappsbt.VInput, len(eligibleCommitments))
	inputCommitments := make(tappsbt.InputCommitments)

	for idx := range eligibleCommitments {
		// If the key found for the input UTXO cannot be identified as
		// belonging to the lnd wallet, we won't be able to sign for it.
		// This would happen if a user manually imported an asset that
		// was issued/received for/on another node. We should probably
		// not create asset entries for such imported assets in the
		// first place, as we won't be able to spend it anyway. But for
		// now we just put this check in place.
		assetInput := eligibleCommitments[idx]

		// We'll also include an inclusion proof for the input asset in
		// the virtual transaction. With that a signer can verify that
		// the asset was actually committed to in the anchor output.
		inputProof, err := f.fetchInputProof(
			ctx, assetInput.Asset, assetInput.AnchorPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching input proof: %w",
				err)
		}

		// Create the virtual packet input including the chain anchor
		// information.
		err = createAndSetInput(
			vPkt, idx, f.cfg.ChainParams, assetInput, inputProof,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create and set "+
				"input: %w", err)
		}

		prevID := vPkt.Inputs[idx].PrevID
		inputCommitments[prevID] = assetInput.Commitment
	}

	return inputCommitments, nil
}

// createAndSetInput creates a virtual packet input for the given asset input
// and sets it on the given virtual packet.
func createAndSetInput(vPkt *tappsbt.VPacket, idx int,
	params *address.ChainParams, assetInput *AnchoredCommitment,
	inputProof *proof.Proof) error {

	internalKey := assetInput.InternalKey
	derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
		internalKey, params.HDCoinType,
	)

	anchorPkScript, anchorMerkleRoot, _, err := tapsend.AnchorOutputScript(
		internalKey.PubKey, assetInput.TapscriptSibling,
		assetInput.Commitment,
	)
	if err != nil {
		return fmt.Errorf("cannot calculate input asset pk script: %w",
			err)
	}

	// Add some trace logging for easier debugging of what we expect to be
	// in the commitment we spend (we did the same when creating the output,
	// so differences should be apparent when debugging).
	tapsend.LogCommitment(
		"Input", idx, assetInput.Commitment, internalKey.PubKey,
		anchorPkScript, anchorMerkleRoot[:],
	)

	tapscriptSiblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		assetInput.TapscriptSibling,
	)
	if err != nil {
		return fmt.Errorf("cannot encode tapscript sibling: %w", err)
	}

	// At this point, we have a valid "coin" to spend in the commitment, so
	// we'll add the relevant information to the virtual TX's input.
	prevID := asset.PrevID{
		OutPoint: assetInput.AnchorPoint,
		ID:       assetInput.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			assetInput.Asset.ScriptKey.PubKey,
		),
	}
	vPkt.Inputs[idx] = &tappsbt.VInput{
		PrevID: prevID,
		Anchor: tappsbt.Anchor{
			Value:            assetInput.AnchorOutputValue,
			PkScript:         anchorPkScript,
			InternalKey:      internalKey.PubKey,
			MerkleRoot:       anchorMerkleRoot[:],
			TapscriptSibling: tapscriptSiblingBytes,
			Bip32Derivation:  []*psbt.Bip32Derivation{derivation},
			TrBip32Derivation: []*psbt.TaprootBip32Derivation{
				trDerivation,
			},
		},
		Proof: inputProof,
		PInput: psbt.PInput{
			SighashType: txscript.SigHashDefault,
		},
	}
	vPkt.SetInputAsset(idx, assetInput.Asset)

	return nil
}

// fetchInputProof fetches the proof for the given asset input from the archive.
func (f *AssetWallet) fetchInputProof(ctx context.Context,
	inputAsset *asset.Asset, anchorPoint wire.OutPoint) (*proof.Proof,
	error) {

	assetID := inputAsset.ID()
	proofLocator := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *inputAsset.ScriptKey.PubKey,
		OutPoint:  &anchorPoint,
	}
	if inputAsset.GroupKey != nil {
		proofLocator.GroupKey = &inputAsset.GroupKey.GroupPubKey
	}
	inputProofBlob, err := f.cfg.AssetProofs.FetchProof(
		ctx, proofLocator,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch proof for input "+
			"asset: %w", err)
	}
	inputProofFile := &proof.File{}
	err = inputProofFile.Decode(bytes.NewReader(inputProofBlob))
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof for input "+
			"asset: %w", err)
	}
	inputProof, err := inputProofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("cannot get last proof for "+
			"input asset: %w", err)
	}

	return inputProof, nil
}

// SignVirtualPacketOptions is a set of functional options that allow callers to
// further modify the virtual packet signing process.
type SignVirtualPacketOptions struct {
	// SkipInputProofVerify skips virtual input proof verification when true.
	SkipInputProofVerify bool
}

// defaultSignVirtualPacketOptions returns the set of default options for the
// virtual packet signing function.
func defaultSignVirtualPacketOptions() *SignVirtualPacketOptions {
	return &SignVirtualPacketOptions{}
}

// SignVirtualPacketOption is a functional option that allows a caller to modify
// the virtual packet signing process.
type SignVirtualPacketOption func(*SignVirtualPacketOptions)

// SkipInputProofVerify sets an optional argument flag such that
// SignVirtualPacket skips virtual input proof verification.
func SkipInputProofVerify() SignVirtualPacketOption {
	return func(o *SignVirtualPacketOptions) {
		o.SkipInputProofVerify = true
	}
}

// SignVirtualPacket signs the virtual transaction of the given packet and
// returns the input indexes that were signed (referring to the virtual
// transaction's inputs).
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SignVirtualPacket(vPkt *tappsbt.VPacket,
	optFuncs ...SignVirtualPacketOption) ([]uint32, error) {

	opts := defaultSignVirtualPacketOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	for idx := range vPkt.Inputs {
		// Conditionally skip the inclusion proof verification. We may
		// not need to verify the input proof if we're only using the
		// input to generate a new virtual output proof during
		// re-anchoring.
		if !opts.SkipInputProofVerify {
			// Before we sign the transaction, we want to make sure
			// the inclusion proof is valid and the asset is
			// actually committed in the anchor transaction.
			err := verifyInclusionProof(vPkt.Inputs[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to verify "+
					"inclusion proof: %w", err)
			}
		}
	}

	// Now we'll use the signer to sign all the inputs for the new Taproot
	// Asset leaves. The witness data for each input will be assigned for
	// us.
	err := tapsend.SignVirtualTransaction(
		vPkt, f.cfg.Signer, f.cfg.WitnessValidator,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate Taproot Asset "+
			"witness data: %w", err)
	}

	// Mark all inputs as signed.
	signedInputs := make([]uint32, len(vPkt.Inputs))
	for idx := range vPkt.Inputs {
		signedInputs[idx] = uint32(idx)
	}

	return signedInputs, nil
}

// verifyInclusionProof verifies that the given virtual input's asset is
// actually committed in the anchor transaction.
func verifyInclusionProof(vIn *tappsbt.VInput) error {
	assetProof := vIn.Proof

	if assetProof == nil {
		return fmt.Errorf("input proof is nil")
	}

	// Before we look at the inclusion proof, we'll make sure that the input
	// anchor information matches the proof's anchor transaction.
	//
	// TODO(guggero): Also check if the block is in the chain by calling
	// into ChainBridge.
	op := vIn.PrevID.OutPoint
	anchorTxHash := assetProof.AnchorTx.TxHash()

	if op.Hash != anchorTxHash {
		return fmt.Errorf("proof anchor tx hash %v doesn't match "+
			"input anchor outpoint %v", anchorTxHash, op.Hash)
	}
	if op.Index >= uint32(len(assetProof.AnchorTx.TxOut)) {
		return fmt.Errorf("input anchor outpoint index out of range")
	}

	anchorTxOut := assetProof.AnchorTx.TxOut[op.Index]
	if !bytes.Equal(anchorTxOut.PkScript, vIn.Anchor.PkScript) {
		return fmt.Errorf("proof anchor tx pk script %x doesn't "+
			"match input anchor script %x", anchorTxOut.PkScript,
			vIn.Anchor.PkScript)
	}

	anchorKey, err := proof.ExtractTaprootKeyFromScript(vIn.Anchor.PkScript)
	if err != nil {
		return fmt.Errorf("unable to parse anchor pk script %x "+
			"taproot key: %w", vIn.Anchor.PkScript, err)
	}

	inclusionProof := assetProof.InclusionProof
	proofKey, _, err := inclusionProof.DeriveByAssetInclusion(
		vIn.Asset(),
	)
	if err != nil {
		return fmt.Errorf("unable to derive inclusion proof: %w", err)
	}

	if !proofKey.IsEqual(anchorKey) {
		return fmt.Errorf("proof key doesn't match anchor key")
	}

	return nil
}

// determinePassiveAssetAnchorOutput determines the best anchor output to attach
// passive assets to. If no suitable output is found, a new anchor output is
// created.
func (f *AssetWallet) determinePassiveAssetAnchorOutput(ctx context.Context,
	activePackets []*tappsbt.VPacket) (*keychain.KeyDescriptor, uint32,
	error) {

	var (
		maxAnchorOutputIndex uint32
		candidates           []*tappsbt.VOutput
		candidateDescriptors []*keychain.KeyDescriptor
	)
	for idx := range activePackets {
		vPkt := activePackets[idx]

		for _, vOut := range vPkt.Outputs {
			anchorKeyDesc, err := vOut.AnchorKeyToDesc()
			if err != nil {
				// We can't determine the key descriptor for
				// this output, so we'll skip it as it very
				// likely doesn't belong to us then.
				continue
			}

			// Ignore any anchor outputs that are not local to us.
			if !f.cfg.KeyRing.IsLocalKey(ctx, anchorKeyDesc) {
				continue
			}

			candidates = append(candidates, vOut)
			candidateDescriptors = append(
				candidateDescriptors, &anchorKeyDesc,
			)
		}

		// In case we need to create a new anchor output, we'll want to
		// know the next anchor output index we can use. So we find the
		// maximum currently used index.
		for _, vOut := range vPkt.Outputs {
			if vOut.AnchorOutputIndex > maxAnchorOutputIndex {
				maxAnchorOutputIndex = vOut.AnchorOutputIndex
			}
		}
	}

	// From the candidates, we want to select one in descending order of
	// preference:
	//	1. A split root output (as that's usually the change).
	//	2. A normal output to a new script key (probably a full-value
	//	   send to ourselves).
	//
	// We start with the split root outputs:
	for idx, vOut := range candidates {
		if vOut.Type == tappsbt.TypeSplitRoot {
			return candidateDescriptors[idx], vOut.AnchorOutputIndex,
				nil
		}
	}

	// We're still here, so let's try to find a normal output to a new
	// script key.
	for idx, vOut := range candidates {
		// Skip any incomplete outputs that would cause the below
		// statement to panic.
		if vOut.Asset == nil || len(vOut.Asset.PrevWitnesses) == 0 ||
			vOut.ScriptKey.PubKey == nil {

			continue
		}

		fromKey := vOut.Asset.PrevWitnesses[0].PrevID.ScriptKey
		toKey := asset.ToSerialized(vOut.ScriptKey.PubKey)
		if fromKey != toKey {
			return candidateDescriptors[idx], vOut.AnchorOutputIndex,
				nil
		}
	}

	// If we're _still_ here, it means we haven't found a good candidate to
	// attach our passive assets to. We'll create a new anchor output for
	// them.
	newInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("error deriving new anchor internal "+
			"key for passive assets: %w", err)
	}

	return &newInternalKey, maxAnchorOutputIndex + 1, nil
}

// CreatePassiveAssets creates passive asset packets for the given active
// packets and input Taproot Asset commitments.
func (f *AssetWallet) CreatePassiveAssets(ctx context.Context,
	activePackets []*tappsbt.VPacket,
	inputCommitments tappsbt.InputCommitments) ([]*tappsbt.VPacket, error) {

	// We want to identify the best anchor output to use to attach our
	// passive assets. This is only for the database entry, so we can show
	// the number of passive assets in a transfer to the user somewhere. If
	// we don't find an appropriate output, it might mean we're not creating
	// transfer input/output entries at all, and we can just create a new
	// output for them.
	anchorOutDesc, anchorOutIdx, err := f.determinePassiveAssetAnchorOutput(
		ctx, activePackets,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to determine passive asset "+
			"anchor output: %w", err)
	}

	// Gather passive assets found in each input Taproot Asset commitment.
	var passivePackets []*tappsbt.VPacket
	for prevID := range inputCommitments {
		tapCommitment := inputCommitments[prevID]

		// Each virtual input is associated with a distinct Taproot
		// Asset commitment. Therefore, each input may be associated
		// with a distinct set of passive assets.
		passiveCommitments, err := tapsend.RemovePacketsFromCommitment(
			tapCommitment, activePackets,
		)
		if err != nil {
			return nil, err
		}

		prunedAssets := tapsend.ExtractUnSpendable(passiveCommitments)
		passiveCommitments, err = tapsend.RemoveAssetsFromCommitment(
			passiveCommitments, prunedAssets,
		)
		if err != nil {
			return nil, err
		}

		passiveAssets := passiveCommitments.CommittedAssets()
		if len(passiveAssets) == 0 {
			continue
		}

		// When there are left over passive assets, we need to create
		// packets for them as well.
		for _, passiveAsset := range passiveAssets {
			inputProof, err := f.fetchInputProof(
				ctx, passiveAsset, prevID.OutPoint,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching input "+
					"proof: %w", err)
			}

			passivePacket, err := createPassivePacket(
				f.cfg.ChainParams, passiveAsset, activePackets,
				anchorOutIdx, *anchorOutDesc, prevID.OutPoint,
				inputProof,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"passive packet: %w", err)
			}

			passivePackets = append(passivePackets, passivePacket)
		}
	}

	return passivePackets, nil
}

// SignPassiveAssets signs the given passive asset packets.
func (f *AssetWallet) SignPassiveAssets(
	passiveAssets []*tappsbt.VPacket) error {

	// Sign all the passive assets virtual packets.
	for idx := range passiveAssets {
		passiveAsset := passiveAssets[idx]
		_, err := f.SignVirtualPacket(passiveAsset)
		if err != nil {
			return fmt.Errorf("unable to sign passive asset "+
				"virtual packet: %w", err)
		}
	}

	return nil
}

// AnchorVirtualTransactions creates a BTC level anchor transaction that anchors
// all the virtual transactions of the given packets (for both sending and
// passive asset re-anchoring).
//
// This method returns both the funded anchor TX with all the output information
// intact for later exclusion proof creation, and the fully signed and finalized
// anchor TX along with the total amount of sats paid in chain fees by the
// anchor TX.
func (f *AssetWallet) AnchorVirtualTransactions(ctx context.Context,
	params *AnchorVTxnsParams) (*tapsend.AnchorTransaction, error) {

	allPackets := append([]*tappsbt.VPacket{}, params.ActivePackets...)
	allPackets = append(allPackets, params.PassivePackets...)
	outputCommitments, err := tapsend.CreateOutputCommitments(allPackets)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	// Construct our template PSBT to commits to the set of dummy locators
	// we use to make fee estimation work.
	sendPacket, err := tapsend.CreateAnchorTx(allPackets)
	if err != nil {
		return nil, fmt.Errorf("error creating anchor TX: %w", err)
	}

	anchorPkt, err := f.cfg.Wallet.FundPsbt(
		ctx, sendPacket, 1, params.FeeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	// We'll need to know the total input value of all anchor transactions
	// that are going to be spent.
	amountByInput := make(map[wire.OutPoint]int64)
	for _, vPkt := range params.ActivePackets {
		for _, vIn := range vPkt.Inputs {
			amountByInput[vIn.PrevID.OutPoint] = int64(
				vIn.Anchor.Value,
			)
		}
	}
	inputSum := int64(0)
	for _, amount := range amountByInput {
		inputSum += amount
	}

	// TODO(roasbeef): also want to log the total fee to disk for
	// accounting, etc.

	// Move the change output to the highest-index output, so that
	// we don't overwrite it when embedding our Taproot Asset commitments.
	//
	// TODO(jhb): Do we need richer handling for the change output?
	// We could reassign the change value to our Taproot Asset change output
	// and remove the change output entirely.
	adjustFundedPsbt(anchorPkt, inputSum)

	log.Infof("Received funded PSBT packet")
	log.Tracef("Packet: %v", spew.Sdump(anchorPkt.Pkt))

	// We need the PSBT output information in the unsigned packet later to
	// create the exclusion proofs. So we continue on a copy of the PSBT
	// because those fields get removed when we sign it.
	signAnchorPkt, err := copyPsbt(anchorPkt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to copy PSBT: %w", err)
	}

	// First, we'll update the PSBT packets to insert the _real_ outputs we
	// need to commit to the asset transfer.
	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			signAnchorPkt, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot "+
				"output keys: %w", err)
		}
	}

	// Now that all the real outputs are in the PSBT, we'll also
	// add our anchor inputs as well, since the wallet can sign for
	// it itself.
	err = addAnchorPsbtInputs(
		signAnchorPkt, params.ActivePackets, params.FeeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("error adding anchor input: %w", err)
	}
	anchorPkt.Pkt = signAnchorPkt

	// With all the input and output information in the packet, we
	// can now ask lnd to sign it, and then extract the final
	// version ourselves.
	log.Debugf("Signing PSBT")
	log.Tracef("PSBT: %s", spew.Sdump(signAnchorPkt))
	signedPsbt, err := f.cfg.Wallet.SignPsbt(ctx, signAnchorPkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign psbt: %w", err)
	}
	log.Debugf("Got signed PSBT")
	log.Tracef("PSBT: %s", spew.Sdump(signedPsbt))

	// Before we finalize, we need to calculate the actual, final fees that
	// we pay.
	chainFees, err := signedPsbt.GetTxFee()
	if err != nil {
		return nil, fmt.Errorf("unable to get on-chain fees for psbt: "+
			"%w", err)
	}
	log.Infof("PSBT absolute fee: %d sats", chainFees)

	err = psbt.MaybeFinalizeAll(signedPsbt)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize psbt: %w", err)
	}

	// Extract the final packet from the PSBT transaction (has all sigs
	// included).
	finalTx, err := psbt.Extract(signedPsbt)
	if err != nil {
		return nil, fmt.Errorf("unable to extract psbt: %w", err)
	}

	// Final TX sanity check.
	err = blockchain.CheckTransactionSanity(btcutil.NewTx(finalTx))
	if err != nil {
		return nil, fmt.Errorf("anchor TX failed final checks: %w", err)
	}

	anchorTx := &tapsend.AnchorTransaction{
		FundedPsbt:    anchorPkt,
		FinalTx:       finalTx,
		TargetFeeRate: params.FeeRate,
		ChainFees:     int64(chainFees),
	}

	// Now that we have a valid transaction, we can create the proof
	// suffixes for the active and passive assets.
	for idx := range params.ActivePackets {
		activeAsset := params.ActivePackets[idx]

		for outIdx := range activeAsset.Outputs {
			activeProof, err := tapsend.CreateProofSuffix(
				anchorTx, activeAsset, outputCommitments,
				outIdx, allPackets,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create "+
					"proof: %w", err)
			}

			activeAsset.Outputs[outIdx].ProofSuffix = activeProof
		}
	}

	for idx := range params.PassivePackets {
		passiveAsset := params.PassivePackets[idx]

		// Generate passive asset re-anchoring proofs. Passive assets
		// only have one virtual output at index 0.
		outIndex := 0
		passiveProof, err := tapsend.CreateProofSuffix(
			anchorTx, passiveAsset, outputCommitments,
			outIndex, allPackets,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create re-anchor "+
				"proof: %w", err)
		}

		passiveAsset.Outputs[outIndex].ProofSuffix = passiveProof
	}

	return anchorTx, nil
}

// SignOwnershipProof creates and signs an ownership proof for the given owned
// asset. The ownership proof consists of a signed virtual packet that spends
// the asset fully to the NUMS key.
func (f *AssetWallet) SignOwnershipProof(
	ownedAsset *asset.Asset) (wire.TxWitness, error) {

	outputAsset := ownedAsset.Copy()
	log.Infof("Generating ownership proof for asset %v", outputAsset.ID())

	vPkt := tappsbt.OwnershipProofPacket(
		ownedAsset.Copy(), f.cfg.ChainParams,
	)
	err := tapsend.SignVirtualTransaction(
		vPkt, f.cfg.Signer, f.cfg.WitnessValidator,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate Taproot Asset "+
			"witness data: %w", err)
	}

	return vPkt.Outputs[0].Asset.PrevWitnesses[0].TxWitness, nil
}

// FetchScriptKey attempts to fetch the full tweaked script key struct
// (including the key descriptor) for the given tweaked script key. If the key
// cannot be found, then address.ErrScriptKeyNotFound is returned.
func (f *AssetWallet) FetchScriptKey(ctx context.Context,
	tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey, error) {

	return f.cfg.AddrBook.FetchScriptKey(ctx, tweakedScriptKey)
}

// FetchInternalKeyLocator attempts to fetch the key locator information for the
// given raw internal key. If the key cannot be found, then
// address.ErrInternalKeyNotFound is returned.
func (f *AssetWallet) FetchInternalKeyLocator(ctx context.Context,
	rawKey *btcec.PublicKey) (keychain.KeyLocator, error) {

	return f.cfg.AddrBook.FetchInternalKeyLocator(ctx, rawKey)
}

// adjustFundedPsbt takes a funded PSBT which may have used BIP-0069 sorting,
// and creates a new one with outputs shuffled such that the change output is
// the last output.
func adjustFundedPsbt(fPkt *tapsend.FundedPsbt, anchorInputValue int64) {
	// If there is no change there's nothing we need to do.
	changeIndex := fPkt.ChangeOutputIndex
	if changeIndex == -1 {
		return
	}

	// Store the script and value of the change output.
	maxOutputIndex := len(fPkt.Pkt.UnsignedTx.TxOut) - 1
	changeOutput := fPkt.Pkt.UnsignedTx.TxOut[changeIndex]

	// Overwrite the existing change output, and restore in at the
	// highest-index output.
	fPkt.Pkt.UnsignedTx.TxOut[changeIndex] = tapsend.CreateDummyOutput()
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].PkScript = changeOutput.PkScript
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value = changeOutput.Value

	// Since we're adding the input of the anchor output of our prior asset
	// later, we need to add this value here, so we don't lose the amount
	// to fees.
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value += anchorInputValue

	// If the change output already is the last output, we don't need to
	// overwrite anything in the PSBT outputs.
	if changeIndex == int32(maxOutputIndex) {
		return
	}

	// We also need to re-assign the PSBT level output information.
	changeOutputInfo := fPkt.Pkt.Outputs[changeIndex]
	fPkt.Pkt.Outputs[maxOutputIndex] = psbt.POutput{
		RedeemScript:           changeOutputInfo.RedeemScript,
		WitnessScript:          changeOutputInfo.WitnessScript,
		Bip32Derivation:        changeOutputInfo.Bip32Derivation,
		TaprootInternalKey:     changeOutputInfo.TaprootInternalKey,
		TaprootTapTree:         changeOutputInfo.TaprootTapTree,
		TaprootBip32Derivation: changeOutputInfo.TaprootBip32Derivation,
	}
	fPkt.Pkt.Outputs[changeIndex] = psbt.POutput{}
	fPkt.ChangeOutputIndex = int32(maxOutputIndex)
}

// addAnchorPsbtInputs adds anchor information from all inputs to the PSBT
// packet. This is called after the PSBT has been funded, but before signing.
func addAnchorPsbtInputs(btcPkt *psbt.Packet, vPackets []*tappsbt.VPacket,
	feeRate chainfee.SatPerKWeight) error {

	for _, vPkt := range vPackets {
		for idx := range vPkt.Inputs {
			// With the BIP-0032 information completed, we'll now
			// add the information as a partial input and also add
			// the input to the unsigned transaction.
			vIn := vPkt.Inputs[idx]
			a := vIn.Anchor

			// Multiple virtual transaction inputs can point to the
			// same on-chain outpoint. We need to de-duplicate the
			// inputs to avoid adding the same input multiple times.
			if tapsend.HasInput(
				btcPkt.UnsignedTx, vIn.PrevID.OutPoint,
			) {

				continue
			}

			btcPkt.Inputs = append(btcPkt.Inputs, psbt.PInput{
				WitnessUtxo: &wire.TxOut{
					Value:    int64(a.Value),
					PkScript: a.PkScript,
				},
				SighashType:            a.SigHashType,
				Bip32Derivation:        a.Bip32Derivation,
				TaprootBip32Derivation: a.TrBip32Derivation,
				TaprootInternalKey: schnorr.SerializePubKey(
					a.InternalKey,
				),
				TaprootMerkleRoot: a.MerkleRoot,
			})
			btcPkt.UnsignedTx.TxIn = append(
				btcPkt.UnsignedTx.TxIn, &wire.TxIn{
					PreviousOutPoint: vIn.PrevID.OutPoint,
				},
			)
		}
	}

	// Now that we've added an extra input, we'll want to re-calculate the
	// total vsize of the transaction and the necessary fee at the desired
	// fee rate.
	inputScripts := make([][]byte, 0, len(btcPkt.Inputs))
	for inputIdx, input := range btcPkt.Inputs {
		if input.WitnessUtxo == nil {
			return fmt.Errorf("PSBT input %d doesn't specify "+
				"witness UTXO, which is not supported",
				inputIdx)
		}

		if len(input.WitnessUtxo.PkScript) == 0 {
			return fmt.Errorf("input %d on psbt missing "+
				"pkscript", inputIdx)
		}

		inputScripts = append(inputScripts, input.WitnessUtxo.PkScript)
	}

	estimatedSize, requiredFee := tapscript.EstimateFee(
		inputScripts, btcPkt.UnsignedTx.TxOut, feeRate,
	)
	log.Infof("Estimated TX vsize: %d", estimatedSize)
	log.Infof("TX required fee before change adjustment: %d at feerate "+
		"%d sat/vB", requiredFee, feeRate.FeePerKVByte()/1000)

	// Given the current fee (which doesn't account for our input) and the
	// total fee we want to pay, we'll adjust the wallet's change output
	// accordingly.
	//
	// Earlier in adjustFundedPsbt we set wallet's change output to be the
	// very last output in the transaction.
	lastIdx := len(btcPkt.UnsignedTx.TxOut) - 1
	currentFee, err := btcPkt.GetTxFee()
	if err != nil {
		return err
	}

	feeDelta := int64(requiredFee) - int64(currentFee)
	changeValue := btcPkt.UnsignedTx.TxOut[lastIdx].Value

	log.Infof("Current fee: %d, fee delta: %d", currentFee, feeDelta)
	// The fee may exceed the total value of the change output, which means
	// this spend is impossible with the given inputs and fee rate.
	if changeValue-feeDelta < 0 {
		return fmt.Errorf("fee exceeds change amount: (fee=%d, "+
			"change=%d) ", requiredFee, changeValue)
	}

	// Even if the change amount would be non-negative, it may still be
	// below the dust threshold.
	// TODO(jhb): Remove the change output in this case instead of failing
	possibleChangeOutput := wire.NewTxOut(
		changeValue-feeDelta, btcPkt.UnsignedTx.TxOut[lastIdx].PkScript,
	)
	err = txrules.CheckOutput(
		possibleChangeOutput, txrules.DefaultRelayFeePerKb,
	)
	if err != nil {
		return fmt.Errorf("change output is dust: %w", err)
	}

	btcPkt.UnsignedTx.TxOut[lastIdx].Value -= feeDelta

	log.Infof("Adjusting send pkt fee by delta of %d from %d sats to %d "+
		"sats", feeDelta, currentFee, requiredFee)

	return nil
}

// copyPsbt creates a deep copy of a PSBT packet by serializing and
// de-serializing it.
func copyPsbt(packet *psbt.Packet) (*psbt.Packet, error) {
	var buf bytes.Buffer
	if err := packet.Serialize(&buf); err != nil {
		return nil, err
	}

	return psbt.NewFromRawBytes(&buf, false)
}
