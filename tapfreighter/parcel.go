package tapfreighter

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"golang.org/x/exp/maps"
)

// SendState is an enum that describes the current state of a pending outbound
// parcel (asset transfer).
type SendState uint8

const (
	// SendStateStartHandleAddrParcel is the initial state entered when
	// the state machine begins processing a new address parcel.
	SendStateStartHandleAddrParcel SendState = iota

	// SendStateVirtualCommitmentSelect is the state for performing input
	// coin selection to pick out which assets inputs should be spent.
	SendStateVirtualCommitmentSelect

	// SendStateVirtualSign is used to generate the Taproot Asset level
	// witness data for any inputs being spent.
	SendStateVirtualSign

	// SendStateAnchorSign is the state we enter after the PSBT has been
	// funded. In this state, we'll ask the wallet to sign the PSBT and
	// then finalize to place the necessary signatures in the transaction.
	SendStateAnchorSign

	// SendStateStorePreBroadcast is the state in which the finalized fully
	// signed transaction is written to persistent storage before broadcast.
	SendStateStorePreBroadcast

	// SendStateBroadcast broadcasts the transfer transaction to the
	// network, and imports the taproot output back into the wallet to
	// ensure it properly tracks the coins allocated to the anchor output.
	SendStateBroadcast

	// SendStateWaitTxConf is a state in which we will wait for the transfer
	// transaction to confirm on-chain.
	SendStateWaitTxConf

	// SendStateStorePostAnchorTxConf is the state in which we will update
	// the send package in store to reflect the confirmation of the anchor
	// transaction. This includes:
	// * writing the sender and receiver proofs to the proof archive
	// * marking the transfer change outputs as spendable.
	SendStateStorePostAnchorTxConf

	// SendStateTransferProofs is the state where we attempt to transfer
	// on-chain transaction proof(s) to the receiving party or parties.
	SendStateTransferProofs

	// SendStateComplete is the state which is reached once entire asset
	// transfer process is complete.
	SendStateComplete
)

// String returns a human-readable version of SendState.
func (s SendState) String() string {
	switch s {
	case SendStateStartHandleAddrParcel:
		return "SendStateStartHandleAddrParcel"

	case SendStateVirtualCommitmentSelect:
		return "SendStateVirtualCommitmentSelect"

	case SendStateVirtualSign:
		return "SendStateVirtualSign"

	case SendStateAnchorSign:
		return "SendStateAnchorSign"

	case SendStateStorePreBroadcast:
		return "SendStateStorePreBroadcast"

	case SendStateBroadcast:
		return "SendStateBroadcast"

	case SendStateWaitTxConf:
		return "SendStateWaitTxConf"

	case SendStateStorePostAnchorTxConf:
		return "SendStateStorePostAnchorTxConf"

	case SendStateTransferProofs:
		return "SendStateTransferProofs"

	case SendStateComplete:
		return "SendStateComplete"

	default:
		return fmt.Sprintf("<unknown_state(%d)>", s)
	}
}

// Parcel is an interface that each parcel type must implement.
type Parcel interface {
	// pkg returns the send package that should be delivered.
	pkg() *sendPackage

	// kit returns the parcel kit used for delivery.
	kit() *parcelKit

	// Validate validates the parcel. The validation focuses on the
	// necessary fields being present in order for the porter not to panic.
	// Any business logic validation is assumed to already have happened.
	Validate() error
}

// parcelKit is a struct that contains the channels that are used to deliver
// responses to the parcel creator.
type parcelKit struct {
	// respChan is the channel a response will be sent over.
	respChan chan *OutboundParcel

	// errChan is the channel the error will be sent over.
	errChan chan error
}

// AddressParcel is the main request to issue an asset transfer. This packages a
// destination address, and also response context.
type AddressParcel struct {
	*parcelKit

	// destAddrs is the list of address that should be used to satisfy the
	// transfer.
	destAddrs []*address.Tap

	// transferFeeRate is an optional manually-set feerate specified when
	// requesting an asset transfer.
	transferFeeRate *chainfee.SatPerKWeight

	// label is an optional user provided transfer label.
	label string

	// skipProofCourierPingCheck bool is a flag that indicates whether the
	// proof courier ping check should be skipped. This is useful for
	// testing purposes or to force transfer attempts even if the
	// proof courier is not immediately reachable.
	skipProofCourierPingCheck bool
}

// A compile-time assertion to ensure AddressParcel implements the parcel
// interface.
var _ Parcel = (*AddressParcel)(nil)

// NewAddressParcel creates a new AddressParcel.
func NewAddressParcel(feeRate *chainfee.SatPerKWeight, label string,
	skipProofCourierPingCheck bool,
	destAddrs ...*address.Tap) *AddressParcel {

	return &AddressParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		destAddrs:                 destAddrs,
		transferFeeRate:           feeRate,
		label:                     label,
		skipProofCourierPingCheck: skipProofCourierPingCheck,
	}
}

// pkg returns the send package that should be delivered.
func (p *AddressParcel) pkg() *sendPackage {
	log.Infof("Received to send request to %d addrs: %v", len(p.destAddrs),
		p.destAddrs)

	// Initialize a package with the destination address.
	return &sendPackage{
		Parcel:                    p,
		Label:                     p.label,
		SkipProofCourierPingCheck: p.skipProofCourierPingCheck,
	}
}

// kit returns the parcel kit used for delivery.
func (p *AddressParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel. The validation focuses on the necessary fields
// being present in order for the porter not to panic. Any business logic
// validation is assumed to already have happened.
func (p *AddressParcel) Validate() error {
	// We need at least one address to send to in an address parcel.
	if len(p.destAddrs) < 1 {
		return fmt.Errorf("at least one Tap address must be " +
			"specified in address parcel")
	}

	firstAddrVersion := p.destAddrs[0].Version
	for idx := range p.destAddrs {
		tapAddr := p.destAddrs[idx]

		// All addresses must have the same version.
		if tapAddr.Version != firstAddrVersion {
			return fmt.Errorf("mixed address versions")
		}

		// Validate proof courier addresses.
		err := proof.ValidateCourierAddress(&tapAddr.ProofCourierAddr)
		if err != nil {
			return fmt.Errorf("invalid proof courier address: %w",
				err)
		}
	}

	return nil
}

// PendingParcel is a parcel that has not yet completed delivery.
type PendingParcel struct {
	*parcelKit

	outboundPkg *OutboundParcel
}

// NewPendingParcel creates a new PendingParcel.
func NewPendingParcel(outboundPkg *OutboundParcel) *PendingParcel {
	return &PendingParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		outboundPkg: outboundPkg,
	}
}

// pkg returns the send package that should be delivered.
func (p *PendingParcel) pkg() *sendPackage {
	// A pending parcel has already had its transfer transaction broadcast.
	// We set the send package state such that the send process will
	// rebroadcast and then wait for the transfer to confirm.
	return &sendPackage{
		OutboundPkg: p.outboundPkg,
		SendState:   SendStateBroadcast,
		Label:       p.outboundPkg.Label,
	}
}

// kit returns the parcel kit used for delivery.
func (p *PendingParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel. The validation focuses on the necessary fields
// being present in order for the porter not to panic. Any business logic
// validation is assumed to already have happened.
func (p *PendingParcel) Validate() error {
	// A pending parcel should have already been validated.
	return nil
}

// PreSignedParcel is a request to issue an asset transfer of a pre-signed
// parcel. This packages a virtual transaction, the input commitment, and also
// the response context.
type PreSignedParcel struct {
	*parcelKit

	// vPackets is the list of virtual transaction that should be delivered.
	vPackets []*tappsbt.VPacket

	// inputCommitments are the commitments for the input that are being
	// spent in the virtual transaction.
	inputCommitments tappsbt.InputCommitments

	// note is a string that provides any user defined description for this
	// transfer.
	note string
}

// A compile-time assertion to ensure PreSignedParcel implements the parcel
// interface.
var _ Parcel = (*PreSignedParcel)(nil)

// NewPreSignedParcel creates a new PreSignedParcel.
func NewPreSignedParcel(vPackets []*tappsbt.VPacket,
	inputCommitments tappsbt.InputCommitments,
	note string) *PreSignedParcel {

	return &PreSignedParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		vPackets:         vPackets,
		inputCommitments: inputCommitments,
		note:             note,
	}
}

// pkg returns the send package that should be delivered.
func (p *PreSignedParcel) pkg() *sendPackage {
	log.Infof("New signed delivery request with %d packets",
		len(p.vPackets))

	// Initialize a package the signed virtual transaction and input
	// commitment.
	return &sendPackage{
		Parcel:           p,
		SendState:        SendStateAnchorSign,
		VirtualPackets:   p.vPackets,
		InputCommitments: p.inputCommitments,
		Note:             p.note,
	}
}

// kit returns the parcel kit used for delivery.
func (p *PreSignedParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel. The validation focuses on the necessary fields
// being present in order for the porter not to panic. Any business logic
// validation is assumed to already have happened.
func (p *PreSignedParcel) Validate() error {
	if len(p.vPackets) == 0 {
		return fmt.Errorf("no virtual transaction in pre-signed parcel")
	}

	err := tapsend.ValidateVPacketVersions(p.vPackets)
	if err != nil {
		return err
	}

	for _, vPkt := range p.vPackets {
		if len(vPkt.Outputs) == 0 {
			return fmt.Errorf("no outputs in virtual transaction")
		}
	}

	if p.inputCommitments == nil {
		return fmt.Errorf("no input commitments in pre-signed parcel")
	}

	inputCommitVersions := maps.Values(p.inputCommitments)
	if inputCommitVersions[0] == nil {
		return fmt.Errorf("missing input commitment in pre-signed " +
			"parcel")
	}

	firstCommitVersion := inputCommitVersions[0].Version
	for _, inputCommit := range p.inputCommitments {
		if !commitment.IsSimilarTapCommitmentVersion(
			&firstCommitVersion, &inputCommit.Version,
		) {

			return fmt.Errorf("mixed input commitment versions")
		}
	}

	return nil
}

// PreAnchoredParcel is a request to log and publish an asset transfer of a
// pre-anchored parcel. All virtual PSBTs and the on-chain BTC level anchor
// transaction must be fully signed and ready to be broadcast.
type PreAnchoredParcel struct {
	*parcelKit

	virtualPackets []*tappsbt.VPacket

	passiveAssets []*tappsbt.VPacket

	anchorTx *tapsend.AnchorTransaction
}

// A compile-time assertion to ensure PreAnchoredParcel implements the Parcel
// interface.
var _ Parcel = (*PreAnchoredParcel)(nil)

// NewPreAnchoredParcel creates a new PreAnchoredParcel.
func NewPreAnchoredParcel(vPackets []*tappsbt.VPacket,
	passiveAssets []*tappsbt.VPacket,
	anchorTx *tapsend.AnchorTransaction) *PreAnchoredParcel {

	return &PreAnchoredParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		virtualPackets: vPackets,
		passiveAssets:  passiveAssets,
		anchorTx:       anchorTx,
	}
}

// pkg returns the send package that should be delivered.
func (p *PreAnchoredParcel) pkg() *sendPackage {
	log.Infof("New anchored delivery request with %d packets",
		len(p.virtualPackets))

	// Initialize a package the signed virtual transaction and input
	// commitment.
	return &sendPackage{
		Parcel:         p,
		SendState:      SendStateStorePreBroadcast,
		VirtualPackets: p.virtualPackets,
		PassiveAssets:  p.passiveAssets,
		AnchorTx:       p.anchorTx,
	}
}

// kit returns the parcel kit used for delivery.
func (p *PreAnchoredParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel. The validation focuses on the necessary fields
// being present in order for the porter not to panic. Any business logic
// validation is assumed to already have happened.
func (p *PreAnchoredParcel) Validate() error {
	if len(p.virtualPackets) == 0 {
		return fmt.Errorf("no virtual transactions in pre-anchored " +
			"parcel")
	}

	err := tapsend.ValidateVPacketVersions(p.virtualPackets)
	if err != nil {
		return err
	}

	for _, vPkt := range p.virtualPackets {
		if len(vPkt.Outputs) == 0 {
			return fmt.Errorf("no outputs in virtual transaction")
		}
	}

	if p.anchorTx == nil {
		return fmt.Errorf("no anchor transaction in pre-anchored " +
			"parcel")
	}

	if p.anchorTx.FinalTx == nil {
		return fmt.Errorf("no final transaction in anchor transaction")
	}

	if p.anchorTx.FundedPsbt == nil {
		return fmt.Errorf("no funded PSBT in anchor transaction")
	}

	return nil
}

// sendPackage houses the information we need to complete a package transfer.
type sendPackage struct {
	// SendState is the current send state of this parcel.
	SendState SendState

	// VirtualPackets is the list of virtual packets that should be shipped.
	VirtualPackets []*tappsbt.VPacket

	// InputCommitments is a map from virtual package input index to its
	// associated Taproot Asset commitment.
	InputCommitments tappsbt.InputCommitments

	// PassiveAssets is the data used in re-anchoring passive assets.
	PassiveAssets []*tappsbt.VPacket

	// Parcel is the asset transfer request that kicked off this transfer.
	Parcel Parcel

	// AnchorTx is the BTC level anchor transaction with all its information
	// as it was used when funding/signing it.
	AnchorTx *tapsend.AnchorTransaction

	// OutboundPkg is the on-disk level information that tracks the pending
	// transfer.
	OutboundPkg *OutboundParcel

	// FinalProofs is the set of final full proof chain files that are going
	// to be stored on disk, one for each output in the outbound parcel,
	// keyed by their unique output key (hash of asset ID and script key).
	FinalProofs map[OutputIdentifier]*proof.AnnotatedProof

	// TransferTxConfEvent contains transfer transaction on-chain
	// confirmation data.
	TransferTxConfEvent *chainntnfs.TxConfirmation

	// Label is a user provided short label for this transfer.
	Label string

	// Note is a user provided description for this transfer. This is
	// currently only used by asset burn transfers.
	Note string

	// SkipProofCourierPingCheck bool is a flag that indicates whether the
	// proof courier ping check should be skipped. This is useful for
	// testing purposes or to force transfer attempts even if the
	// proof courier is not immediately reachable.
	SkipProofCourierPingCheck bool
}

// ConvertToTransfer prepares the finished send data for storing to the database
// as a transfer. We generally understand a "transfer" as everything that
// happened on the asset level within a single bitcoin anchor transaction.
// Virtual transactions grouped into "active" transfers are movements that the
// user explicitly initiated. These usually can be identified as either creating
// a split (for partial amounts) or (for full value sends) as sending to a
// script key. Passive virtual transactions are state updates for all assets
// that were committed to in the same anchor transaction as the active assets
// being spent but remain under the daemon's control. These can be identified as
// 1-input-1-output virtual transactions that send to the same script key as
// they were already committed at.
func ConvertToTransfer(currentHeight uint32, activeTransfers []*tappsbt.VPacket,
	anchorTx *tapsend.AnchorTransaction, passiveAssets []*tappsbt.VPacket,
	isLocalKey func(asset.ScriptKey) bool, label string) (*OutboundParcel,
	error) {

	var passiveAssetAnchor *Anchor
	if len(passiveAssets) > 0 {
		// If we have passive assets, we need to create a new anchor
		// for them. They all anchor into the same output, so we can
		// just use the first one.
		firstPassiveVOutput := passiveAssets[0].Outputs[0]
		if firstPassiveVOutput.ProofSuffix == nil {
			return nil, fmt.Errorf("no proof suffix for passive " +
				"assets")
		}

		var err error
		passiveAssetAnchor, err = outputAnchor(
			anchorTx, firstPassiveVOutput, nil,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create passive "+
				"asset anchor: %w", err)
		}
	}

	parcel := &OutboundParcel{
		AnchorTx:           anchorTx.FinalTx,
		AnchorTxHeightHint: currentHeight,
		// TODO(bhandras): use clock.Clock instead.
		TransferTime: time.Now(),
		ChainFees:    anchorTx.ChainFees,
		Inputs:       make([]TransferInput, 0, len(activeTransfers)),
		Outputs: make(
			// This is just a heuristic to pre-allocate something,
			// assuming most transfers have around two outputs.
			[]TransferOutput, 0, len(activeTransfers)*2,
		),
		PassiveAssets:       passiveAssets,
		PassiveAssetsAnchor: passiveAssetAnchor,
		Label:               label,
	}

	allPackets := append(activeTransfers, passiveAssets...)
	if err := tapsend.AssertInputsUnique(allPackets); err != nil {
		return nil, fmt.Errorf("unable to convert to transfer: %w", err)
	}

	for pIdx := range activeTransfers {
		vPkt := activeTransfers[pIdx]

		for idx := range vPkt.Inputs {
			tIn, err := transferInput(vPkt.Inputs[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to convert "+
					"input %d: %w", idx, err)
			}

			parcel.Inputs = append(parcel.Inputs, *tIn)
		}
	}

	// The outputPosition represents the index of the output within the list
	// of output transfers. It is continuously incremented across all
	// outputs and virtual packets.
	outputPosition := uint64(0)

	for pIdx := range activeTransfers {
		vPkt := activeTransfers[pIdx]

		for vPktOutputIdx := range vPkt.Outputs {
			// Burn and tombstone keys are the only keys that we
			// don't explicitly store in the DB before this point.
			// But we'll want them to have the correct type when
			// creating the transfer, as they'll be inserted into
			// the DB, assigned to this transfer.
			detectUnSpendableKeys(vPkt.Outputs[vPktOutputIdx])

			tOut, err := transferOutput(
				vPkt, vPktOutputIdx, outputPosition, anchorTx,
				passiveAssets, isLocalKey,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to convert "+
					"output %d: %w", vPktOutputIdx, err)
			}
			outputPosition += 1

			parcel.Outputs = append(parcel.Outputs, *tOut)
		}
	}

	return parcel, nil
}

// transferInput creates a TransferInput from a virtual input and the anchor
// packet.
func transferInput(vIn *tappsbt.VInput) (*TransferInput, error) {
	var emptyPrevID asset.PrevID
	if vIn.PrevID == emptyPrevID {
		return nil, fmt.Errorf("invalid input, prev id missing")
	}

	return &TransferInput{
		PrevID: vIn.PrevID,
		Amount: vIn.Asset().Amount,
	}, nil
}

// transferOutput creates a TransferOutput from a virtual output and the anchor
// packet.
func transferOutput(vPkt *tappsbt.VPacket, vOutIdx int, position uint64,
	anchorTx *tapsend.AnchorTransaction, passiveAssets []*tappsbt.VPacket,
	isLocalKey func(asset.ScriptKey) bool) (*TransferOutput, error) {

	vOut := vPkt.Outputs[vOutIdx]

	// Convert any proof courier address associated with this output
	// to bytes for db storage.
	var proofCourierAddrBytes []byte
	if vOut.ProofDeliveryAddress != nil {
		proofCourierAddrBytes = []byte(
			vOut.ProofDeliveryAddress.String(),
		)
	}

	// We should have an asset and proof suffix now.
	if vOut.Asset == nil || vOut.ProofSuffix == nil {
		return nil, fmt.Errorf("invalid output %d, asset or proof "+
			"missing", vOutIdx)
	}

	proofSuffixBytes, err := vOut.ProofSuffix.Bytes()
	if err != nil {
		return nil, fmt.Errorf("unable to encode proof %d: %w",
			vOutIdx, err)
	}

	anchor, err := outputAnchor(anchorTx, vOut, passiveAssets)
	if err != nil {
		return nil, fmt.Errorf("unable to create anchor: %w", err)
	}

	out := TransferOutput{
		Anchor:              *anchor,
		Type:                vOut.Type,
		ScriptKey:           vOut.ScriptKey,
		Amount:              vOut.Amount,
		LockTime:            vOut.Asset.LockTime,
		RelativeLockTime:    vOut.Asset.RelativeLockTime,
		AssetVersion:        vOut.AssetVersion,
		WitnessData:         vOut.Asset.PrevWitnesses,
		SplitCommitmentRoot: vOut.Asset.SplitCommitmentRoot,
		ProofSuffix:         proofSuffixBytes,
		ProofCourierAddr:    proofCourierAddrBytes,
		ScriptKeyLocal:      isLocalKey(vOut.ScriptKey),
		Position:            position,
	}

	// Determine whether an associated proof needs to be delivered to a peer
	// based on the currently set fields.
	shouldDeliverProof, err := out.ShouldDeliverProof()
	if err != nil {
		return nil, fmt.Errorf("unable to determine if transfer "+
			"output proof should be delivery to a peer: %w", err)
	}

	if shouldDeliverProof {
		// Set the `ProofDeliveryComplete` field to `Some(false)` to
		// indicate that proof delivery is pending. Once the proof has
		// been successfully  delivered, this field will be updated to
		// `Some(true)`.
		//
		// If it was determined that the proof should not be delivered,
		// the `ProofDeliveryComplete` field would remain `None`.
		out.ProofDeliveryComplete = fn.Some(false)
	}

	return &out, nil
}

// outputAnchor creates an Anchor from an anchor transaction and a virtual
// output.
func outputAnchor(anchorTx *tapsend.AnchorTransaction, vOut *tappsbt.VOutput,
	passiveAssets []*tappsbt.VPacket) (*Anchor, error) {

	anchorTXID := anchorTx.FinalTx.TxHash()
	anchorInternalKey := keychain.KeyDescriptor{
		PubKey: vOut.AnchorOutputInternalKey,
	}
	if vOut.AnchorOutputBip32Derivation != nil {
		var err error
		anchorInternalKey, err = vOut.AnchorKeyToDesc()
		if err != nil {
			return nil, fmt.Errorf("unable to get anchor "+
				"key desc: %w", err)
		}
	}

	preimageBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		vOut.AnchorOutputTapscriptSibling,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to encode tapscript "+
			"preimage: %w", err)
	}

	anchorOut := &anchorTx.FundedPsbt.Pkt.Outputs[vOut.AnchorOutputIndex]
	merkleRoot := tappsbt.ExtractCustomField(
		anchorOut.Unknowns, tappsbt.PsbtKeyTypeOutputTaprootMerkleRoot,
	)
	taprootAssetRoot := tappsbt.ExtractCustomField(
		anchorOut.Unknowns, tappsbt.PsbtKeyTypeOutputAssetRoot,
	)

	// Fetch the Taproot asset commitment version from the output's proof
	// suffix.
	commitmentVersion, err := vOut.TapCommitmentVersion()
	if err != nil {
		return nil, err
	}

	// If there are passive assets, are they anchored in the same anchor
	// output as this transfer output? If yes, then we show this to the user
	// by just attaching the number of passive assets.
	var numPassiveAssets uint32
	if len(passiveAssets) > 0 {
		// All passive assets should be at the same anchor output index.
		firstPassive := passiveAssets[0]
		anchorOutputIndex := firstPassive.Outputs[0].AnchorOutputIndex
		if anchorOutputIndex == vOut.AnchorOutputIndex {
			numPassiveAssets = uint32(len(passiveAssets))
		}
	}

	txOut := anchorTx.FinalTx.TxOut[vOut.AnchorOutputIndex]
	return &Anchor{
		OutPoint: wire.OutPoint{
			Hash:  anchorTXID,
			Index: vOut.AnchorOutputIndex,
		},
		Value:             btcutil.Amount(txOut.Value),
		InternalKey:       anchorInternalKey,
		TaprootAssetRoot:  taprootAssetRoot[:],
		CommitmentVersion: fn.Ptr(uint8(*commitmentVersion)),
		MerkleRoot:        merkleRoot[:],
		TapscriptSibling:  preimageBytes,
		NumPassiveAssets:  numPassiveAssets,
		PkScript:          txOut.PkScript,
	}, nil
}

// deliverTxBroadcastResp delivers a response for the parcel back to the
// receiver over the response channel.
func (s *sendPackage) deliverTxBroadcastResp() {
	// Ensure that we have a response channel to deliver the response over.
	// We may not have one if the package send process was recommenced after
	// a restart.
	if s.Parcel == nil {
		log.Warnf("No response channel for resumed parcel, not " +
			"delivering notification")
		return
	}

	txHash := s.OutboundPkg.AnchorTx.TxHash()
	log.Infof("Outbound parcel with txid %v now pending (num_inputs=%d, "+
		"num_outputs=%d), delivering notification", txHash,
		len(s.OutboundPkg.Inputs), len(s.OutboundPkg.Outputs))

	s.Parcel.kit().respChan <- s.OutboundPkg
}

// validateReadyForPublish checks that the virtual packets are ready to be
// published to the network. The pruned assets (assets that were present in the
// input TAP tree but are not re-created by any of the active or passive packets
// because they were burns or tombstones) are required to be supplied in order
// for the full input TAP tree to be reconstructed and validated.
func (s *sendPackage) validateReadyForPublish(
	prunedAssets map[wire.OutPoint][]*asset.Asset) error {

	// At this point all the virtual packet inputs and outputs should fully
	// match the BTC level anchor transaction. Version 0 assets should also
	// be signed now.
	allPackets := append([]*tappsbt.VPacket{}, s.VirtualPackets...)
	allPackets = append(allPackets, s.PassiveAssets...)
	if err := tapsend.AssertInputAnchorsEqual(allPackets); err != nil {
		return fmt.Errorf("input anchors don't match: %w", err)
	}
	if err := tapsend.AssertOutputAnchorsEqual(allPackets); err != nil {
		return fmt.Errorf("output anchors don't match: %w", err)
	}

	btcPkt := s.AnchorTx.FundedPsbt.Pkt
	err := tapsend.ValidateAnchorInputs(btcPkt, allPackets, prunedAssets)
	if err != nil {
		return fmt.Errorf("error validating anchor inputs: %w", err)
	}
	err = tapsend.ValidateAnchorOutputs(btcPkt, allPackets, true)
	if err != nil {
		return fmt.Errorf("error validating anchor outputs: %w", err)
	}

	return nil
}
