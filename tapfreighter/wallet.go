package tapfreighter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"golang.org/x/exp/maps"
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
)

// Wallet is an interface for funding and signing asset transfers.
type Wallet interface {
	// FundAddressSend funds a virtual transaction, selecting assets to
	// spend in order to pay the given address. It also returns supporting
	// data which assists in processing the virtual transaction: passive
	// asset re-anchors and the Taproot Asset level commitment of the
	// selected assets.
	FundAddressSend(ctx context.Context,
		scriptKeyType fn.Option[asset.ScriptKeyType],
		prevIDs []asset.PrevID,
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
	SignVirtualPacket(ctx context.Context, vPkt *tappsbt.VPacket,
		optFuncs ...SignVirtualPacketOption) ([]uint32, error)

	// CreatePassiveAssets creates passive asset packets for the given
	// active packets and input Taproot Asset commitments.
	CreatePassiveAssets(ctx context.Context,
		activePackets []*tappsbt.VPacket,
		inputCommitments tappsbt.InputCommitments) ([]*tappsbt.VPacket,
		error)

	// SignPassiveAssets signs the given passive asset packets.
	SignPassiveAssets(ctx context.Context,
		passiveAssets []*tappsbt.VPacket) error

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
	// A challenge may be accepted, which modifies the NUMS key, binding the
	// ownership proof to the provided challenge.
	SignOwnershipProof(ownedAsset *asset.Asset,
		challenge fn.Option[[32]byte]) (wire.TxWitness, error)

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

	// ReleaseCoins releases/unlocks coins that were previously leased and
	// makes them available for coin selection again.
	ReleaseCoins(ctx context.Context, utxoOutpoints ...wire.OutPoint) error
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

	// InsertScriptKey inserts an address related script key into the
	// database, so it can be recognized as belonging to the wallet when a
	// transfer comes in later on.
	InsertScriptKey(ctx context.Context,
		scriptKey asset.ScriptKey, keyType asset.ScriptKeyType) error
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

	// ZeroValueInputs is a list of zero-value UTXOs that should be swept
	// as additional inputs to the transaction.
	ZeroValueInputs []*ZeroValueInput
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

	// ChainBridge is our bridge to the chain we operate on.
	ChainBridge ChainBridge

	// GroupVerifier is used to verify the validity of the group key for a
	// genesis proof.
	GroupVerifier proof.GroupVerifier

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]

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
	// VPackets is a list of virtual transaction that was created to fund
	// the transfer.
	VPackets []*tappsbt.VPacket

	// InputCommitments is a map from virtual package input index to its
	// associated Taproot Asset commitment.
	InputCommitments tappsbt.InputCommitments

	// ZeroValueInputs is a list of zero-value UTXOs that should be swept
	// as additional inputs to the transaction.
	ZeroValueInputs []*ZeroValueInput
}

// FundAddressSend funds a virtual transaction, selecting assets to spend in
// order to pay the given address. It also returns supporting data which assists
// in processing the virtual transaction: passive asset re-anchors and the
// Taproot Asset level commitment of the selected assets.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) FundAddressSend(ctx context.Context,
	scriptKeyType fn.Option[asset.ScriptKeyType], prevIDs []asset.PrevID,
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

	// We need to constrain the prevIDs if they are provided.
	if len(prevIDs) > 0 {
		fundDesc.PrevIDs = prevIDs
	}

	fundDesc.ScriptKeyType = scriptKeyType
	fundedVPkt, err := f.FundPacket(ctx, fundDesc, vPkt)
	if err != nil {
		return nil, fmt.Errorf("error funding packet: %w", err)
	}

	// If we're sending to a V2 address, we need to create the send fragment
	// for the receiver later. For that we need to add the address to the
	// virtual outputs and also derive a unique script key.
	hasV2Addr := fn.Any(receiverAddrs, func(a *address.Tap) bool {
		return a.Version >= address.V2
	})

	// If there isn't a V2 address, we can return early, as we have
	// everything we need.
	if !hasV2Addr {
		return fundedVPkt, nil
	}

	return prepareV2Outputs(ctx, fundedVPkt)
}

// prepareAddressV2Outputs prepares the outputs of a funded virtual packet
// for V2 addresses. It derives a unique script key for each output that has
// a V2 address set.
func prepareV2Outputs(ctx context.Context,
	fundedVPkt *FundedVPacket) (*FundedVPacket, error) {

	for pktIdx := range fundedVPkt.VPackets {
		vPkt := fundedVPkt.VPackets[pktIdx]
		assetID, err := vPkt.AssetID()
		if err != nil {
			return nil, fmt.Errorf("unable to determine asset "+
				"specifier: %w", err)
		}

		for outIdx := range vPkt.Outputs {
			vOut := vPkt.Outputs[outIdx]

			// A send fragment can only be created for an output
			// that has an address with version 2 set.
			if vOut.Address == nil {
				continue
			}
			if !vOut.Address.UsesSendManifests() {
				continue
			}

			receiverKey := vOut.Address.ScriptKey
			scriptKey, err := asset.DeriveUniqueScriptKey(
				receiverKey, assetID,
				asset.ScriptKeyDerivationUniquePedersen,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to derive "+
					"unique script key: %w", err)
			}

			vOut.ScriptKey = scriptKey

			// Now that we've created the unique script key, we also
			// assign a random alt leaf to the asset, asserting that
			// sends with the exact same amount and asset ID will
			// still result in a different on-chain output,
			// increasing the privacy of the transfer when addresses
			// are being re-used. This is possible with V2 addresses
			// (vs. V0/V1) because the recipient isn't able to
			// predict the on-chain output anyway, so the send
			// fragment will inform the recipient about the location
			// to fetch the proofs from. And the parameters required
			// to fetch a proof are independent of the actual
			// on-chain commitment output and therefore the actual
			// asset leaf.
			randKey, err := btcec.NewPrivateKey()
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"random private key: %w", err)
			}
			randScriptKey := asset.NewScriptKey(randKey.PubKey())
			randAltLeaf, err := asset.NewAltLeaf(
				randScriptKey, asset.ScriptV0,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"random alt leaf: %w", err)
			}

			vOut.AltLeaves = append(vOut.AltLeaves, randAltLeaf)
		}

		// We need to re-create the output assets because we potentially
		// changed the script keys.
		if err := tapsend.PrepareOutputAssets(ctx, vPkt); err != nil {
			log.Errorf("Error preparing output assets: %v, "+
				"packets: %v", err, limitSpewer.Sdump(vPkt))
			return nil, fmt.Errorf("unable to prepare outputs: %w",
				err)
		}
	}

	return fundedVPkt, nil
}

// createSendManifests creates the send manifests and fragments for the given
// funded virtual packets. The send fragments are used to reconstruct the
// information required to fetch proofs from the universe, and to materialize
// the asset outputs on the receiver's side. We assume that the receiver has
// access to the TAP address that was used to send the assets.
func createSendManifests(chainParams *address.ChainParams,
	parcel *OutboundParcel) (map[uint32]*proof.SendManifest, error) {

	result := make(map[uint32]*proof.SendManifest)
	addToFragment := func(addr *address.Tap, assetID asset.ID,
		vOut TransferOutput) error {

		var (
			courierAddr *url.URL
			err         error
		)
		if len(vOut.ProofCourierAddr) == 0 {
			return fmt.Errorf("no proof courier address "+
				"set for output %d", vOut.Anchor.OutPoint.Index)
		}

		courierAddr, err = url.Parse(string(vOut.ProofCourierAddr))
		if err != nil {
			return fmt.Errorf("unable to parse proof courier "+
				"address for output %d: %w",
				vOut.Anchor.OutPoint.Index, err)
		}

		receiverKey := addr.ScriptKey

		manifest, ok := result[vOut.Anchor.OutPoint.Index]
		if !ok {
			manifest = &proof.SendManifest{
				Receiver:   receiverKey,
				CourierURL: *courierAddr,
				Fragment: proof.SendFragment{
					Version: proof.SendFragmentV1,
					Outputs: make(
						map[asset.ID]proof.SendOutput,
					),
				},
			}
			result[vOut.Anchor.OutPoint.Index] = manifest
		}

		scriptKey, err := asset.DeriveUniqueScriptKey(
			receiverKey, assetID,
			asset.ScriptKeyDerivationUniquePedersen,
		)
		if err != nil {
			return fmt.Errorf("unable to derive unique script "+
				"key: %w", err)
		}

		// As a sanity check, we make sure that the unique script key
		// we just re-derived is the same that's already set on the
		// virtual output.
		if !scriptKey.PubKey.IsEqual(vOut.ScriptKey.PubKey) {
			return fmt.Errorf("derived unique pedersen script key "+
				"%x doesn't match virtual output script key %x",
				scriptKey.PubKey.SerializeCompressed(),
				vOut.ScriptKey.PubKey.SerializeCompressed())
		}

		manifest.Fragment.Outputs[assetID] = proof.SendOutput{
			AssetVersion: vOut.AssetVersion,
			Amount:       vOut.Amount,
			ScriptKey:    asset.ToSerialized(scriptKey.PubKey),
		}

		return nil
	}

	for outIdx, tOut := range parcel.Outputs {
		assetID, err := tOut.AssetID()
		if err != nil {
			return nil, fmt.Errorf("unable to determine asset ID: "+
				"%w", err)
		}

		// A send fragment can only be created for an output that has an
		// address with version 2 set.
		if len(tOut.TapAddress) == 0 {
			log.Tracef("Skipping output %d for fragment, "+
				"no address set", outIdx)
			continue
		}

		addr, err := address.DecodeAddress(tOut.TapAddress, chainParams)
		if err != nil {
			return nil, fmt.Errorf("unable to decode address "+
				"for output %d: %w", outIdx, err)
		}

		if addr.Version < address.V2 {
			log.Tracef("Skipping output %d for fragment, "+
				"address not V2", outIdx)
			continue
		}

		log.Debugf("Adding send fregment for output %d", outIdx)
		err = addToFragment(addr, assetID, tOut)
		if err != nil {
			return nil, fmt.Errorf("unable to add output "+
				"to send fragment: %w", err)
		}
	}

	return result, nil
}

// createPassivePacket creates a virtual packet for the given passive asset.
func createPassivePacket(passiveAsset *asset.Asset,
	activePackets []*tappsbt.VPacket, anchorOutputIndex uint32,
	anchorOutputInternalKey keychain.KeyDescriptor, prevOut wire.OutPoint,
	inputProof *proof.Proof) (*tappsbt.VPacket, error) {

	if len(activePackets) == 0 {
		return nil, errors.New("no active packets provided")
	}

	if activePackets[0].ChainParams == nil {
		return nil, errors.New("chain params not set in active packet")
	}

	params := activePackets[0].ChainParams

	// Specify virtual input.
	inputAsset := inputProof.Asset.Copy()
	vInput := tappsbt.VInput{
		Proof: inputProof,
		PInput: psbt.PInput{
			SighashType: txscript.SigHashDefault,
		},
	}

	// The passive asset is the asset queried from the database, and it
	// might contain the script key internal key and type (which the asset
	// from the proof won't have). So we copy over the script key to make
	// sure we have all the required signing information.
	inputAsset.ScriptKey = passiveAsset.ScriptKey

	err := tapsend.ValidateVPacketVersions(activePackets)
	if err != nil {
		return nil, err
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
	var emptyPrevID asset.PrevID
	if vInput.PrevID == emptyPrevID {
		return nil, fmt.Errorf("unable to find anchor for passive "+
			"asset %v", passiveAsset.ID())
	}

	// Specify virtual output.
	outputAsset := passiveAsset.CopySpendTemplate()

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
	activePktVersion := activePackets[0].Version
	vPacket := &tappsbt.VPacket{
		Inputs:      []*tappsbt.VInput{&vInput},
		Outputs:     []*tappsbt.VOutput{&vOutput},
		ChainParams: params,
		Version:     activePktVersion,
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

	// Each anchor output must have a valid set of AltLeaves at this point.
	outputAltLeaves := make(map[uint32][]asset.AltLeaf[asset.Asset])
	for _, vOut := range vPkt.Outputs {
		outputAltLeaves[vOut.AnchorOutputIndex] = append(
			outputAltLeaves[vOut.AnchorOutputIndex],
			asset.CopyAltLeaves(vOut.AltLeaves)...,
		)
	}

	for anchorIdx, leaves := range outputAltLeaves {
		err := asset.ValidAltLeaves(leaves)
		if err != nil {
			return nil, fmt.Errorf("anchor output %d invalid alt "+
				"leaves: %w", anchorIdx, err)
		}
	}

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taproot asset coin selection.
	constraints := CommitmentConstraints{
		AssetSpecifier:    fundDesc.AssetSpecifier,
		MinAmt:            fundDesc.Amount,
		ScriptKeyType:     fundDesc.ScriptKeyType,
		PrevIDs:           fundDesc.PrevIDs,
		DistinctSpecifier: fundDesc.DistinctSpecifier,
	}

	anchorVersion, err := tappsbt.CommitmentVersion(vPkt.Version)
	if err != nil {
		return nil, err
	}

	if anchorVersion == nil {
		anchorVersion = fn.Ptr(commitment.TapCommitmentV1)
	}

	selectedCommitments, err := f.cfg.CoinSelector.SelectCoins(
		ctx, constraints, PreferMaxAmount, *anchorVersion,
	)
	if err != nil {
		return nil, err
	}

	var zeroValueInputs []*ZeroValueInput

	// If we return with an error, we want to release all the coins we've
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

			// Also release any zero-value UTXOs we may have leased.
			zeroValueOutpoints := fn.Map(
				zeroValueInputs,
				func(z *ZeroValueInput) wire.OutPoint {
					return z.OutPoint
				},
			)
			outpoints = append(outpoints, zeroValueOutpoints...)

			err := f.cfg.CoinSelector.ReleaseCoins(
				ctx, outpoints...,
			)
			if err != nil {
				log.Errorf("Unable to release coins: %v", err)
			}
		}
	}()

	if f.cfg.SweepOrphanUtxos {
		zeroValueInputs, err = f.cfg.CoinSelector.SelectOrphanCoins(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to select zero-value "+
				"UTXOs: %w", err)
		}
	}

	pkt, err := createFundedPacketWithInputs(
		ctx, f.cfg.AssetProofs, f.cfg.KeyRing, f.cfg.AddrBook, fundDesc,
		vPkt, selectedCommitments, zeroValueInputs,
	)
	if err != nil {
		return nil, err
	}

	success = true
	return pkt, nil
}

// FundBurn funds a virtual transaction for burning the given amount of units of
// the given asset.
func (f *AssetWallet) FundBurn(ctx context.Context,
	fundDesc *tapsend.FundingDescriptor) (*FundedVPacket, error) {

	// Extract the asset ID and group key from the funding descriptor.
	assetId, err := fundDesc.AssetSpecifier.UnwrapIdOrErr()
	if err != nil {
		return nil, err
	}

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taproot asset coin selection.
	constraints := CommitmentConstraints{
		AssetSpecifier: fundDesc.AssetSpecifier,
		MinAmt:         fundDesc.Amount,
	}
	selectedCommitments, err := f.cfg.CoinSelector.SelectCoins(
		ctx, constraints, PreferMaxAmount, commitment.TapCommitmentV2,
	)
	if err != nil {
		return nil, err
	}

	var zeroValueInputs []*ZeroValueInput

	// If we return with an error, we want to release all the coins we've
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

			// Also release any zero-value UTXOs we may have leased.
			zeroValueOutpoints := fn.Map(
				zeroValueInputs,
				func(z *ZeroValueInput) wire.OutPoint {
					return z.OutPoint
				},
			)
			outpoints = append(outpoints, zeroValueOutpoints...)

			err := f.cfg.CoinSelector.ReleaseCoins(
				ctx, outpoints...,
			)
			if err != nil {
				log.Errorf("Unable to release coins: %v", err)
			}
		}
	}()

	if f.cfg.SweepOrphanUtxos {
		zeroValueInputs, err = f.cfg.CoinSelector.SelectOrphanCoins(
			ctx,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to select zero-value "+
				"UTXOs: %w", err)
		}
	}

	activeAssets := fn.Filter(
		selectedCommitments, func(c *AnchoredCommitment) bool {
			return c.Asset.ID() == assetId
		},
	)

	maxVersion := asset.V0
	for _, activeAsset := range activeAssets {
		if activeAsset.Asset.Version > maxVersion {
			maxVersion = activeAsset.Asset.Version
		}
	}

	// Now that we know what inputs we're going to spend, we know that by
	// definition, we use the first input's info as the burn's PrevID. But
	// to know which input will actually be assigned as the first input in
	// the allocated virtual packet, we first apply the same sorting that
	// the allocation code will also apply.
	slices.SortFunc(activeAssets, func(a, b *AnchoredCommitment) int {
		return tapsend.AssetSortForInputs(*a.Asset, *b.Asset)
	})
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
				ID: assetId,
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
		Version:     tappsbt.V1,
	}
	vPkt.Outputs[0].SetAnchorInternalKey(
		newInternalKey, f.cfg.ChainParams.HDCoinType,
	)

	// The virtual transaction is now ready to be further enriched with the
	// split commitment and other data.
	fundedPkt, err := createFundedPacketWithInputs(
		ctx, f.cfg.AssetProofs, f.cfg.KeyRing, f.cfg.AddrBook, fundDesc,
		vPkt, selectedCommitments, zeroValueInputs,
	)
	if err != nil {
		return nil, err
	}

	// We don't support burning by group key yet, so we only expect a single
	// vPacket (which implies a single asset ID is involved).
	if len(fundedPkt.VPackets) != 1 {
		return nil, fmt.Errorf("expected a single vPacket, got %d",
			len(fundedPkt.VPackets))
	}

	// Don't release the coins we've selected, as so far we've been
	// successful.
	success = true
	return fundedPkt, nil
}

// SignVirtualPacketOptions is a set of functional options that allow callers to
// further modify the virtual packet signing process.
type SignVirtualPacketOptions struct {
	// SkipInputProofVerify skips virtual input proof verification when
	// true.
	SkipInputProofVerify bool

	// WitnessValidator validates a signature after it's been created.
	WitnessValidator tapscript.WitnessValidator
}

// defaultSignVirtualPacketOptions returns the set of default options for the
// virtual packet signing function.
func defaultSignVirtualPacketOptions(
	defaultValidator tapscript.WitnessValidator) *SignVirtualPacketOptions {

	return &SignVirtualPacketOptions{
		WitnessValidator: defaultValidator,
	}
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

// WithValidator sets an optional argument that allows the caller to specify a
// custom witness validator to use when signing the virtual packet.
func WithValidator(
	validator tapscript.WitnessValidator) SignVirtualPacketOption {

	return func(o *SignVirtualPacketOptions) {
		o.WitnessValidator = validator
	}
}

// SignVirtualPacket signs the virtual transaction of the given packet and
// returns the input indexes that were signed (referring to the virtual
// transaction's inputs).
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SignVirtualPacket(ctx context.Context,
	vPkt *tappsbt.VPacket, signOpts ...SignVirtualPacketOption) ([]uint32,
	error) {

	opts := defaultSignVirtualPacketOptions(f.cfg.WitnessValidator)
	for _, optFunc := range signOpts {
		optFunc(opts)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, f.cfg.ChainBridge)
	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  f.cfg.GroupVerifier,
		ChainLookupGen: f.cfg.ChainBridge,
		IgnoreChecker:  f.cfg.IgnoreChecker,
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
			assetProof := vPkt.Inputs[idx].Proof
			if assetProof == nil {
				return nil, fmt.Errorf("input proof is nil")
			}

			_, err := assetProof.VerifyProofIntegrity(ctx, vCtx)
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
		vPkt, f.cfg.Signer, opts.WitnessValidator,
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

// determinePassiveAssetAnchorOutput determines the best anchor output to attach
// passive assets to. If no suitable output is found, a new anchor output is
// created.
func determinePassiveAssetAnchorOutput(ctx context.Context, keyRing KeyRing,
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
			if !keyRing.IsLocalKey(ctx, anchorKeyDesc) {
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
	newInternalKey, err := keyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("error deriving new anchor internal "+
			"key for passive assets: %w", err)
	}

	return &newInternalKey, maxAnchorOutputIndex + 1, nil
}

// CreatePassiveAssets creates passive asset packets for the given active
// packets and input Taproot Asset commitments. This is just a convenience
// wrapper around the function with the same name. This avoids callers needing
// to have references to a key ring and proof exporter if they already have an
// instance of AssetWallet.
func (f *AssetWallet) CreatePassiveAssets(ctx context.Context,
	activePackets []*tappsbt.VPacket,
	inputCommitments tappsbt.InputCommitments) ([]*tappsbt.VPacket, error) {

	return CreatePassiveAssets(
		ctx, f.cfg.KeyRing, f.cfg.AssetProofs, activePackets,
		inputCommitments,
	)
}

// CreatePassiveAssets creates passive asset packets for the given active
// packets and input Taproot Asset commitments.
func CreatePassiveAssets(ctx context.Context, keyRing KeyRing,
	exporter proof.Exporter, activePackets []*tappsbt.VPacket,
	inputCommitments tappsbt.InputCommitments) ([]*tappsbt.VPacket, error) {

	// We want to identify the best anchor output to use to attach our
	// passive assets. This is only for the database entry, so we can show
	// the number of passive assets in a transfer to the user somewhere. If
	// we don't find an appropriate output, it might mean we're not creating
	// transfer input/output entries at all, and we can just create a new
	// output for them.
	anchorOutDesc, anchorOutIdx, err := determinePassiveAssetAnchorOutput(
		ctx, keyRing, activePackets,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to determine passive asset "+
			"anchor output: %w", err)
	}

	// Gather passive assets found in each input Taproot Asset commitment.
	passivePackets := make(map[asset.PrevID]*tappsbt.VPacket)
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

		// We're trying to determine what assets are left over after
		// removing the active assets. But we don't want to count the
		// alt leaves as "assets" in this context, so we'll trim them
		// out.
		trimmedPassives, _, err := commitment.TrimAltLeaves(
			passiveCommitments,
		)
		if err != nil {
			return nil, err
		}

		passiveAssets := trimmedPassives.CommittedAssets()
		if len(passiveAssets) == 0 {
			continue
		}

		// When there are left over passive assets, we need to create
		// packets for them as well.
		for _, passiveAsset := range passiveAssets {
			inputProof, err := fetchInputProof(
				ctx, exporter, passiveAsset, prevID.OutPoint,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching input "+
					"proof: %w", err)
			}

			scriptKey := passiveAsset.ScriptKey.PubKey
			passivePrevID := asset.PrevID{
				OutPoint:  prevID.OutPoint,
				ID:        passiveAsset.ID(),
				ScriptKey: asset.ToSerialized(scriptKey),
			}
			log.Tracef("Adding passive packet for asset_id=%v, "+
				"script_key=%x", passiveAsset.ID().String(),
				scriptKey.SerializeCompressed())

			passivePacket, err := createPassivePacket(
				passiveAsset, activePackets,
				anchorOutIdx, *anchorOutDesc, prevID.OutPoint,
				inputProof,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"passive packet: %w", err)
			}

			passivePackets[passivePrevID] = passivePacket
		}
	}

	return maps.Values(passivePackets), nil
}

// SignPassiveAssets signs the given passive asset packets.
func (f *AssetWallet) SignPassiveAssets(ctx context.Context,
	passiveAssets []*tappsbt.VPacket) error {

	// Sign all the passive assets virtual packets.
	for idx := range passiveAssets {
		passiveAsset := passiveAssets[idx]
		_, err := f.SignVirtualPacket(ctx, passiveAsset)
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

	// TODO(roasbeef): also want to log the total fee to disk for
	// accounting, etc.

	// First, we'll update the PSBT packets to insert the _real_ outputs we
	// need to commit to the asset transfer.
	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			sendPacket, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot "+
				"output keys: %w", err)
		}
	}

	// Now that all the real outputs are in the PSBT, we'll also
	// add our anchor inputs as well, since the wallet can sign for
	// it itself.
	addAnchorPsbtInputs(sendPacket, params.ActivePackets)

	// Add zero-value inputs that should be swept as additional inputs.
	numZeroValueInputs := len(params.ZeroValueInputs)
	if numZeroValueInputs > 0 {
		log.DebugS(ctx, "Sweeping zero-value UTXOs",
			"n", numZeroValueInputs)
		addZeroValuePsbtInputs(
			sendPacket, params.ZeroValueInputs, f.cfg.ChainParams,
		)
	}

	// We now fund the packet, placing the change on the last output.
	anchorPkt, err := f.cfg.Wallet.FundPsbt(
		ctx, sendPacket, 1, params.FeeRate, -1,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}
	log.Tracef("Got funded PSBT packet: %v", spew.Sdump(anchorPkt.Pkt))

	// With all the input and output information in the packet, we
	// can now ask lnd to sign it, and then extract the final
	// version ourselves.
	signedPsbt, err := f.cfg.Wallet.SignPsbt(ctx, anchorPkt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign psbt: %w", err)
	}
	log.Tracef("Got signed PSBT: %s", spew.Sdump(signedPsbt))

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
				finalTx, anchorPkt.Pkt.Outputs, activeAsset,
				outputCommitments, outIdx, allPackets,
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
			finalTx, anchorPkt.Pkt.Outputs, passiveAsset,
			outputCommitments, outIndex, allPackets,
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
func (f *AssetWallet) SignOwnershipProof(ownedAsset *asset.Asset,
	challenge fn.Option[[32]byte]) (wire.TxWitness, error) {

	outputAsset := ownedAsset.Copy()
	log.Infof("Generating ownership proof for asset %v", outputAsset.ID())

	vPkt := tappsbt.OwnershipProofPacket(
		ownedAsset.Copy(), challenge, f.cfg.ChainParams,
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

// ReleaseCoins releases/unlocks coins that were previously leased and makes
// them available for coin selection again.
func (f *AssetWallet) ReleaseCoins(ctx context.Context,
	utxoOutpoints ...wire.OutPoint) error {

	return f.cfg.CoinSelector.ReleaseCoins(ctx, utxoOutpoints...)
}

// addAnchorPsbtInputs adds anchor information from all inputs to the PSBT
// packet. This is called after the PSBT has been funded, but before signing.
func addAnchorPsbtInputs(btcPkt *psbt.Packet, vPackets []*tappsbt.VPacket) {
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
}

// addZeroValuePsbtInputs adds zero-value UTXOs as inputs to the PSBT.
func addZeroValuePsbtInputs(btcPkt *psbt.Packet,
	zeroValueInputs []*ZeroValueInput, chainParams *address.ChainParams) {

	for _, utxo := range zeroValueInputs {
		// Check if this input is already added to avoid duplicates.
		if tapsend.HasInput(btcPkt.UnsignedTx, utxo.OutPoint) {
			continue
		}

		// Create the BIP32 derivation info for signing.
		bip32Derivation, trDerivation := tappsbt.
			Bip32DerivationFromKeyDesc(
				utxo.InternalKey, chainParams.HDCoinType,
			)

		btcPkt.Inputs = append(btcPkt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    int64(utxo.OutputValue),
				PkScript: utxo.PkScript,
			},
			SighashType: txscript.SigHashDefault,
			Bip32Derivation: []*psbt.Bip32Derivation{
				bip32Derivation,
			},
			TaprootInternalKey: schnorr.SerializePubKey(
				utxo.InternalKey.PubKey,
			),
			TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{
				trDerivation,
			},
			TaprootMerkleRoot: utxo.MerkleRoot,
		})
		btcPkt.UnsignedTx.TxIn = append(
			btcPkt.UnsignedTx.TxIn, &wire.TxIn{
				PreviousOutPoint: utxo.OutPoint,
			},
		)
	}
}
