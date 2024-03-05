package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
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

	// VPkts is a list of all the virtual transactions that should be
	// anchored by the anchor transaction.
	VPkts []*tappsbt.VPacket

	// PassiveAssetsVPkts is a list of all the virtual transactions which
	// re-anchor passive assets.
	PassiveAssetsVPkts []*tappsbt.VPacket
}

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

// passiveAssetVPacket creates a virtual packet for the given passive asset.
func passiveAssetVPacket(params *address.ChainParams, passiveAsset *asset.Asset,
	anchorPoint wire.OutPoint, anchorOutputIndex uint32,
	internalKey *keychain.KeyDescriptor) *tappsbt.VPacket {

	// Specify virtual input.
	inputAsset := passiveAsset.Copy()
	inputPrevId := asset.PrevID{
		OutPoint: anchorPoint,
		ID:       inputAsset.ID(),
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}
	vInput := tappsbt.VInput{
		PrevID: inputPrevId,
	}

	// Specify virtual output.
	outputAsset := passiveAsset.Copy()

	// Clear the split commitment root, as we'll be transferring the
	// whole asset.
	outputAsset.SplitCommitmentRoot = nil

	// Clear the output asset witness data. We'll be creating a new witness.
	outputAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &inputPrevId,
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
	vOutput.SetAnchorInternalKey(*internalKey, params.HDCoinType)

	// Create VPacket.
	vPacket := &tappsbt.VPacket{
		Inputs:      []*tappsbt.VInput{&vInput},
		Outputs:     []*tappsbt.VOutput{&vOutput},
		ChainParams: params,
	}

	// Set the input asset. The input asset proof is not provided as it is
	// not needed for the re-anchoring process.
	vPacket.SetInputAsset(0, inputAsset)

	return vPacket
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

		passiveCommitments, err := removeActiveCommitments(
			tapCommitment, vPackets,
		)
		if err != nil {
			return false, err
		}

		if len(passiveCommitments) > 0 {
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

	// Gather Taproot Asset commitments from the selected anchored assets.
	var selectedTapCommitments []*commitment.TapCommitment
	for _, selectedCommitment := range selectedCommitments {
		selectedTapCommitments = append(
			selectedTapCommitments, selectedCommitment.Commitment,
		)
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

	// We now also need to remove all tombstone or burns from our active
	// commitments.
	for idx := range inputCommitments {
		inputCommitments[idx], err = pruneTombstonesAndBurns(
			inputCommitments[idx],
		)
		if err != nil {
			return nil, err
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
		// spent that beocmes change will be a v0 if combined with such
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
		internalKey := assetInput.InternalKey
		if !f.cfg.KeyRing.IsLocalKey(ctx, internalKey) {
			return nil, fmt.Errorf("invalid internal key family "+
				"for selected input, not known to lnd: "+
				"key=%x, fam=%v, idx=%v",
				internalKey.PubKey.SerializeCompressed(),
				internalKey.Family, internalKey.Index)
		}

		inBip32Derivation, inTrBip32Derivation :=
			tappsbt.Bip32DerivationFromKeyDesc(
				internalKey, f.cfg.ChainParams.HDCoinType,
			)

		anchorPkScript, anchorMerkleRoot, err := inputAnchorPkScript(
			assetInput,
		)
		if err != nil {
			return nil, fmt.Errorf("cannot calculate input asset "+
				"pk script: %w", err)
		}

		// Add some trace logging for easier debugging of what we expect
		// to be in the commitment we spend (we did the same when
		// creating the output, so differences should be apparent when
		// debugging).
		tapsend.LogCommitment(
			"Input", idx, assetInput.Commitment, internalKey.PubKey,
			anchorPkScript, anchorMerkleRoot[:],
		)

		// We'll also include an inclusion proof for the input asset in
		// the virtual transaction. With that a signer can verify that
		// the asset was actually committed to in the anchor output.
		assetID := assetInput.Asset.ID()
		proofLocator := proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *assetInput.Asset.ScriptKey.PubKey,
			OutPoint:  &assetInput.AnchorPoint,
		}
		if assetInput.Asset.GroupKey != nil {
			proofLocator.GroupKey = &assetInput.Asset.GroupKey.GroupPubKey
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

		tapscriptSiblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
			assetInput.TapscriptSibling,
		)
		if err != nil {
			return nil, fmt.Errorf("cannot encode tapscript "+
				"sibling: %w", err)
		}

		// At this point, we have a valid "coin" to spend in the
		// commitment, so we'll add the relevant information to the
		// virtual TX's input.
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
				MerkleRoot:       anchorMerkleRoot,
				TapscriptSibling: tapscriptSiblingBytes,
				Bip32Derivation: []*psbt.Bip32Derivation{
					inBip32Derivation,
				},
				TrBip32Derivation: []*psbt.TaprootBip32Derivation{
					inTrBip32Derivation,
				},
			},
			Proof: inputProof,
			PInput: psbt.PInput{
				SighashType: txscript.SigHashDefault,
			},
		}
		vPkt.SetInputAsset(idx, assetInput.Asset)

		inputCommitments[prevID] = assetInput.Commitment
	}

	return inputCommitments, nil
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

// pruneTombstonesAndBurns removes all tombstones and burns from the active
// input commitment.
func pruneTombstonesAndBurns(
	inputCommitment *commitment.TapCommitment) (*commitment.TapCommitment,
	error) {

	committedAssets := inputCommitment.CommittedAssets()
	committedAssets = fn.Filter(committedAssets, func(a *asset.Asset) bool {
		return !a.IsUnSpendable() && !a.IsBurn()
	})

	return commitment.FromAssets(committedAssets...)
}

// removeActiveCommitments removes all active commitments from the given input
// commitment and only returns a tree of passive commitments.
func removeActiveCommitments(inputCommitment *commitment.TapCommitment,
	vPackets []*tappsbt.VPacket) (commitment.AssetCommitments, error) {

	// Gather passive assets found in the commitment. This creates a copy of
	// the commitment map, so we can remove things freely.
	passiveCommitments := inputCommitment.Commitments()

	// removeAsset is a helper function that removes the given asset from
	// the passed asset commitment and updates the top level Taproot Asset
	// commitment with the new asset commitment, if that still contains any
	// assets.
	removeAsset := func(assetCommitment *commitment.AssetCommitment,
		toRemove *asset.Asset, tapKey [32]byte) error {

		// We need to make a copy in order to not modify the original
		// commitment, as the above call to get all commitments just
		// creates a new slice, but we still have a pointer to the
		// original asset commitment.
		var err error
		assetCommitment, err = assetCommitment.Copy()
		if err != nil {
			return fmt.Errorf("unable to copy asset commitment: %w",
				err)
		}

		// Now we can remove the asset from the commitment.
		err = assetCommitment.Delete(toRemove)
		if err != nil {
			return fmt.Errorf("unable to delete asset "+
				"commitment: %w", err)
		}

		// Since we're not returning the root Taproot Asset commitment
		// but a map of all asset commitments, we need to prune the
		// asset commitment manually if it is empty now.
		rootHash := assetCommitment.TreeRoot.NodeHash()
		if rootHash == mssmt.EmptyTreeRootHash {
			delete(passiveCommitments, tapKey)

			return nil
		}

		// There are other leaves of this asset in our asset tree, let's
		// now update our passive commitment map so these will be
		// carried along.
		passiveCommitments[tapKey] = assetCommitment

		return nil
	}

	// First, we remove any tombstones or burns that might be in the
	// commitment. We needed to select them from the DB to arrive at the
	// correct input Taproot Asset tree but can now remove them for good as
	// they are no longer relevant and don't need to be carried over to the
	// next tree.
	for tapKey := range passiveCommitments {
		assetCommitment := passiveCommitments[tapKey]
		committedAssets := assetCommitment.Assets()

		for assetKey := range committedAssets {
			committedAsset := committedAssets[assetKey]
			if committedAsset.IsUnSpendable() ||
				committedAsset.IsBurn() {

				err := removeAsset(
					assetCommitment, committedAsset, tapKey,
				)
				if err != nil {
					return nil, fmt.Errorf("unable to "+
						"delete asset: %w", err)
				}
			}
		}
	}

	// Remove input assets (the assets being spent) from list of assets to
	// re-sign.
	for _, vPkt := range vPackets {
		for _, vIn := range vPkt.Inputs {
			key := vIn.Asset().TapCommitmentKey()
			assetCommitment, ok := passiveCommitments[key]
			if !ok {
				continue
			}

			err := removeAsset(assetCommitment, vIn.Asset(), key)
			if err != nil {
				return nil, fmt.Errorf("unable to "+
					"delete asset: %w", err)
			}
		}
	}

	return passiveCommitments, nil
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
	var passiveAssets []*tappsbt.VPacket
	for prevID := range inputCommitments {
		tapCommitment := inputCommitments[prevID]

		// Each virtual input is associated with a distinct Taproot
		// Asset commitment. Therefore, each input may be associated
		// with a distinct set of passive assets.
		passiveCommitments, err := removeActiveCommitments(
			tapCommitment, activePackets,
		)
		if err != nil {
			return nil, err
		}
		if len(passiveCommitments) == 0 {
			continue
		}

		// When there are left over passive assets, we need to create
		// packets for them as well.
		for tapKey := range passiveCommitments {
			passiveCommitment := passiveCommitments[tapKey]
			for _, passiveAsset := range passiveCommitment.Assets() {
				passiveAssets = append(
					passiveAssets, passiveAssetVPacket(
						f.cfg.ChainParams,
						passiveAsset, prevID.OutPoint,
						anchorOutIdx, anchorOutDesc,
					),
				)
			}
		}
	}

	return passiveAssets, nil
}

// SignPassiveAssets signs the given passive asset packets.
func (f *AssetWallet) SignPassiveAssets(
	passiveAssets []*tappsbt.VPacket) error {

	// Sign all the passive assets virtual packets.
	for idx := range passiveAssets {
		passiveAsset := passiveAssets[idx]
		_, err := f.SignVirtualPacket(
			passiveAsset, SkipInputProofVerify(),
		)
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

	// We currently only support anchoring a single virtual transaction.
	//
	// TODO(guggero): Support merging and anchoring multiple virtual
	// transactions.
	if len(params.VPkts) != 1 {
		return nil, fmt.Errorf("only a single virtual transaction is " +
			"supported for now")
	}
	vPacket := params.VPkts[0]

	allPackets := append(
		[]*tappsbt.VPacket{vPacket}, params.PassiveAssetsVPkts...,
	)
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

	// TODO(roasbeef): also want to log the total fee to disk for
	// accounting, etc.

	// Move the change output to the highest-index output, so that
	// we don't overwrite it when embedding our Taproot Asset commitments.
	//
	// TODO(jhb): Do we need richer handling for the change output?
	// We could reassign the change value to our Taproot Asset change output
	// and remove the change output entirely.
	adjustFundedPsbt(anchorPkt, int64(vPacket.Inputs[0].Anchor.Value))

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
	err = addAnchorPsbtInputs(signAnchorPkt, vPacket, params.FeeRate)
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
	for idx := range params.VPkts {
		activeAsset := params.VPkts[idx]

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

	for idx := range params.PassiveAssetsVPkts {
		passiveAsset := params.PassiveAssetsVPkts[idx]

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

// inputAnchorPkScript returns the top-level Taproot output script of the input
// anchor output as well as the Taproot Asset script root of the output (the
// Taproot tweak).
func inputAnchorPkScript(assetInput *AnchoredCommitment) ([]byte, []byte,
	error) {

	// If any of the assets were received non-interactively, then the
	// Taproot Asset tree of the input anchor output was built with asset
	// leaves that had empty SplitCommitments. We need to replicate this
	// here as well.
	inputCommitment, err := trimSplitWitnesses(assetInput.Commitment)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to trim split "+
			"witnesses: %w", err)
	}

	// Decode the Tapscript sibling preimage if there was one, so we can
	// arrive at the correct merkle root hash.
	var siblingHash *chainhash.Hash
	if assetInput.TapscriptSibling != nil {
		siblingHash, err = assetInput.TapscriptSibling.TapHash()
		if err != nil {
			return nil, nil, err
		}
	}

	merkleRoot := inputCommitment.TapscriptRoot(siblingHash)
	anchorPubKey := txscript.ComputeTaprootOutputKey(
		assetInput.InternalKey.PubKey, merkleRoot[:],
	)

	pkScript, err := tapscript.PayToTaprootScript(anchorPubKey)
	return pkScript, merkleRoot[:], err
}

// trimSplitWitnesses returns a copy of the input commitment in which all assets
// with a split commitment witness have their SplitCommitment field set to nil.
func trimSplitWitnesses(
	original *commitment.TapCommitment) (*commitment.TapCommitment,
	error) {

	// If the input asset was received non-interactively, then the Taproot
	// Asset tree of the input anchor output was built with asset leaves
	// that had empty SplitCommitments. However, the SplitCommitment field
	// was populated when the transfer of the input asset was verified.
	// To recompute the correct output script, we need to build a Taproot
	// Asset tree from the input asset without any SplitCommitment.
	tapCommitmentCopy, err := original.Copy()
	if err != nil {
		return nil, err
	}

	allAssets := tapCommitmentCopy.CommittedAssets()
	for _, inputAsset := range allAssets {
		inputAssetCopy := inputAsset.Copy()

		// Assets received via non-interactive split should have one
		// witness, with an empty PrevID and a SplitCommitment present.
		if inputAssetCopy.HasSplitCommitmentWitness() &&
			*inputAssetCopy.PrevWitnesses[0].PrevID == asset.ZeroPrevID {

			inputAssetCopy.PrevWitnesses[0].SplitCommitment = nil

			// Build the new Taproot Asset tree by first updating
			// the asset commitment tree with the new asset leaf,
			// and then the top-level Taproot Asset tree.
			inputCommitments := tapCommitmentCopy.Commitments()
			inputCommitmentKey := inputAssetCopy.TapCommitmentKey()
			inputAssetTree := inputCommitments[inputCommitmentKey]
			err = inputAssetTree.Upsert(inputAssetCopy)
			if err != nil {
				return nil, err
			}

			err = tapCommitmentCopy.Upsert(inputAssetTree)
			if err != nil {
				return nil, err
			}
		}
	}

	return tapCommitmentCopy, nil
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
	fPkt.Pkt.UnsignedTx.TxOut[changeIndex] = createDummyOutput()
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
func addAnchorPsbtInputs(btcPkt *psbt.Packet, vPkt *tappsbt.VPacket,
	feeRate chainfee.SatPerKWeight) error {

	for idx := range vPkt.Inputs {
		// With the BIP-0032 information completed, we'll now add the
		// information as a partial input and also add the input to the
		// unsigned transaction.
		vIn := vPkt.Inputs[idx]
		btcPkt.Inputs = append(btcPkt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    int64(vIn.Anchor.Value),
				PkScript: vIn.Anchor.PkScript,
			},
			SighashType:            vIn.Anchor.SigHashType,
			Bip32Derivation:        vIn.Anchor.Bip32Derivation,
			TaprootBip32Derivation: vIn.Anchor.TrBip32Derivation,
			TaprootInternalKey: schnorr.SerializePubKey(
				vIn.Anchor.InternalKey,
			),
			TaprootMerkleRoot: vIn.Anchor.MerkleRoot,
		})
		btcPkt.UnsignedTx.TxIn = append(
			btcPkt.UnsignedTx.TxIn, &wire.TxIn{
				PreviousOutPoint: vIn.PrevID.OutPoint,
			},
		)
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
