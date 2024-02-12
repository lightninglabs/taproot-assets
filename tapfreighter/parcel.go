package tapfreighter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// SendState is an enum that describes the current state of a pending outbound
// parcel (asset transfer).
type SendState uint8

const (
	// SendStateVirtualCommitmentSelect is the state for performing input
	// coin selection to pick out which assets inputs should be spent.
	SendStateVirtualCommitmentSelect SendState = iota

	// SendStateVirtualSign is used to generate the Taproot Asset level
	// witness data for any inputs being spent.
	SendStateVirtualSign

	// SendStateAnchorSign is the state we enter after the PSBT has been
	// funded. In this state, we'll ask the wallet to sign the PSBT and
	// then finalize to place the necessary signatures in the transaction.
	SendStateAnchorSign

	// SendStateLogCommit is the final in memory state. In this state,
	// we'll extract the signed transaction from the PSBT and log the
	// transfer information to disk. At this point, after a restart, the
	// transfer can be resumed.
	SendStateLogCommit

	// SendStateBroadcast broadcasts the transfer transaction to the
	// network, and imports the taproot output back into the wallet to
	// ensure it properly tracks the coins allocated to the anchor output.
	SendStateBroadcast

	// SendStateWaitTxConf is a state in which we will wait for the transfer
	// transaction to confirm on-chain.
	SendStateWaitTxConf

	// SendStateStoreProofs is the state in which we will write the sender
	// and receiver proofs to the proof archive.
	SendStateStoreProofs

	// SendStateReceiverProofTransfer is the state in which we will commence
	// the receiver proof transfer process.
	SendStateReceiverProofTransfer

	// SendStateComplete is the state which is reached once entire asset
	// transfer process is complete.
	SendStateComplete
)

// String returns a human-readable version of SendState.
func (s SendState) String() string {
	switch s {
	case SendStateVirtualCommitmentSelect:
		return "SendStateVirtualCommitmentSelect"

	case SendStateVirtualSign:
		return "SendStateVirtualSign"

	case SendStateAnchorSign:
		return "SendStateAnchorSign"

	case SendStateLogCommit:
		return "SendStateLogCommit"

	case SendStateBroadcast:
		return "SendStateBroadcast"

	case SendStateWaitTxConf:
		return "SendStateWaitTxConf"

	case SendStateStoreProofs:
		return "SendStateStoreProofs"

	case SendStateReceiverProofTransfer:
		return "SendStateReceiverProofTransfer"

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

	// Validate validates the parcel.
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
}

// A compile-time assertion to ensure AddressParcel implements the parcel
// interface.
var _ Parcel = (*AddressParcel)(nil)

// NewAddressParcel creates a new AddressParcel.
func NewAddressParcel(feeRate *chainfee.SatPerKWeight,
	destAddrs ...*address.Tap) *AddressParcel {

	return &AddressParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		destAddrs:       destAddrs,
		transferFeeRate: feeRate,
	}
}

// pkg returns the send package that should be delivered.
func (p *AddressParcel) pkg() *sendPackage {
	log.Infof("Received to send request to %d addrs: %v", len(p.destAddrs),
		p.destAddrs)

	// Initialize a package with the destination address.
	return &sendPackage{
		Parcel: p,
	}
}

// kit returns the parcel kit used for delivery.
func (p *AddressParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel.
func (p *AddressParcel) Validate() error {
	// We need at least one address to send to in an address parcel.
	if len(p.destAddrs) < 1 {
		return fmt.Errorf("at least one Tap address must be " +
			"specified in address parcel")
	}

	for idx := range p.destAddrs {
		tapAddr := p.destAddrs[idx]

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
	}
}

// kit returns the parcel kit used for delivery.
func (p *PendingParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel.
func (p *PendingParcel) Validate() error {
	// A pending parcel should have already been validated.
	return nil
}

// PreSignedParcel is a request to issue an asset transfer of a pre-signed
// parcel. This packages a virtual transaction, the input commitment, and also
// the response context.
type PreSignedParcel struct {
	*parcelKit

	// vPkt is the virtual transaction that should be delivered.
	vPkt *tappsbt.VPacket

	// inputCommitments are the commitments for the input that are being
	// spent in the virtual transaction.
	inputCommitments tappsbt.InputCommitments
}

// A compile-time assertion to ensure PreSignedParcel implements the parcel
// interface.
var _ Parcel = (*PreSignedParcel)(nil)

// NewPreSignedParcel creates a new PreSignedParcel.
func NewPreSignedParcel(vPkt *tappsbt.VPacket,
	inputCommitments tappsbt.InputCommitments) *PreSignedParcel {

	return &PreSignedParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *OutboundParcel, 1),
			errChan:  make(chan error, 1),
		},
		vPkt:             vPkt,
		inputCommitments: inputCommitments,
	}
}

// pkg returns the send package that should be delivered.
func (p *PreSignedParcel) pkg() *sendPackage {
	log.Infof("New signed delivery request with %d outputs",
		len(p.vPkt.Outputs))

	// Initialize a package the signed virtual transaction and input
	// commitment.
	return &sendPackage{
		Parcel:           p,
		SendState:        SendStateAnchorSign,
		VirtualPacket:    p.vPkt,
		InputCommitments: p.inputCommitments,
	}
}

// kit returns the parcel kit used for delivery.
func (p *PreSignedParcel) kit() *parcelKit {
	return p.parcelKit
}

// Validate validates the parcel.
func (p *PreSignedParcel) Validate() error {
	// TODO(ffranr): Add validation where appropriate.
	return nil
}

// sendPackage houses the information we need to complete a package transfer.
type sendPackage struct {
	// SendState is the current send state of this parcel.
	SendState SendState

	// VirtualPacket is the virtual packet that we'll use to construct the
	// virtual asset transition transaction.
	VirtualPacket *tappsbt.VPacket

	// OutputIdxToAddr is a map from a VPacket's VOutput index to its
	// associated Tap address.
	OutputIdxToAddr tappsbt.OutputIdxToAddr

	// InputCommitments is a map from virtual package input index to its
	// associated Taproot Asset commitment.
	InputCommitments tappsbt.InputCommitments

	// PassiveAssets is the data used in re-anchoring passive assets.
	PassiveAssets []*PassiveAssetReAnchor

	// Parcel is the asset transfer request that kicked off this transfer.
	Parcel Parcel

	// AnchorTx is the BTC level anchor transaction with all its information
	// as it was used when funding/signing it.
	AnchorTx *AnchorTransaction

	// OutboundPkg is the on-disk level information that tracks the pending
	// transfer.
	OutboundPkg *OutboundParcel

	// FinalProofs is the set of final full proof chain files that are going
	// to be stored on disk, one for each output in the outbound parcel,
	// keyed by their script key.
	FinalProofs map[asset.SerializedKey]*proof.AnnotatedProof

	// TransferTxConfEvent contains transfer transaction on-chain
	// confirmation data.
	TransferTxConfEvent *chainntnfs.TxConfirmation
}

// prepareForStorage prepares the send package for storing to the database.
func (s *sendPackage) prepareForStorage(currentHeight uint32) (*OutboundParcel,
	error) {

	// Gather newly generated data required for re-anchoring passive assets.
	for idx := range s.PassiveAssets {
		passiveAsset := s.PassiveAssets[idx]

		// Generate passive asset re-anchoring proofs.
		newProof, err := s.createReAnchorProof(passiveAsset.VPacket)
		if err != nil {
			return nil, fmt.Errorf("failed to create re-anchor "+
				"proof: %w", err)
		}

		passiveAsset.NewProof = newProof
		signedAsset := passiveAsset.VPacket.Outputs[0].Asset
		passiveAsset.NewWitnessData = signedAsset.PrevWitnesses
	}

	vPkt := s.VirtualPacket
	anchorTXID := s.AnchorTx.FinalTx.TxHash()
	parcel := &OutboundParcel{
		AnchorTx:           s.AnchorTx.FinalTx,
		AnchorTxHeightHint: currentHeight,
		// TODO(bhandras): use clock.Clock instead.
		TransferTime:  time.Now(),
		ChainFees:     s.AnchorTx.ChainFees,
		Inputs:        make([]TransferInput, len(vPkt.Inputs)),
		Outputs:       make([]TransferOutput, len(vPkt.Outputs)),
		PassiveAssets: s.PassiveAssets,
	}

	for idx := range vPkt.Inputs {
		vIn := vPkt.Inputs[idx]

		// We don't know the actual outpoint the input is spending, so
		// we need to look it up by the pkScript in the anchor TX.
		var anchorOutPoint *wire.OutPoint
		for inIdx := range s.AnchorTx.FundedPsbt.Pkt.Inputs {
			pIn := s.AnchorTx.FundedPsbt.Pkt.Inputs[inIdx]
			if pIn.WitnessUtxo == nil {
				return nil, fmt.Errorf("anchor input %d has "+
					"no witness utxo", idx)
			}
			utxo := pIn.WitnessUtxo
			if bytes.Equal(utxo.PkScript, vIn.Anchor.PkScript) {
				txIn := s.AnchorTx.FinalTx.TxIn[inIdx]
				anchorOutPoint = &txIn.PreviousOutPoint
				break
			}
		}
		if anchorOutPoint == nil {
			return nil, fmt.Errorf("unable to find anchor "+
				"outpoint for input %d", idx)
		}

		parcel.Inputs[idx] = TransferInput{
			PrevID: asset.PrevID{
				OutPoint: *anchorOutPoint,
				ID:       vIn.Asset().ID(),
				ScriptKey: asset.ToSerialized(
					vIn.Asset().ScriptKey.PubKey,
				),
			},
			Amount: vIn.Asset().Amount,
		}
	}

	outputCommitments := s.AnchorTx.OutputCommitments
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]

		// Convert any proof courier address associated with this output
		// to bytes for db storage.
		var proofCourierAddrBytes []byte
		if s.OutputIdxToAddr != nil {
			if addr, ok := s.OutputIdxToAddr[idx]; ok {
				proofCourierAddrBytes = []byte(
					addr.ProofCourierAddr.String(),
				)
			}
		}

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

		preimageBytes, siblingHash, err := commitment.MaybeEncodeTapscriptPreimage(
			vOut.AnchorOutputTapscriptSibling,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to encode tapscript "+
				"preimage: %w", err)
		}

		outCommitment := outputCommitments[vOut.AnchorOutputIndex]
		merkleRoot := outCommitment.TapscriptRoot(siblingHash)
		taprootAssetRoot := outCommitment.TapscriptRoot(nil)

		var (
			numPassiveAssets    uint32
			proofSuffixBuf      bytes.Buffer
			witness             []asset.Witness
			splitCommitmentRoot mssmt.Node
		)

		// If there are passive assets, they are always committed to the
		// output that is marked as the split root.
		if vOut.Type.CanCarryPassive() {
			numPassiveAssets = uint32(len(s.PassiveAssets))
		}

		// Either we have an asset that we commit to or we have an
		// output just for the passive assets, which we mark as an
		// interactive split root.
		switch {
		// This is a "valid" output for just carrying passive assets
		// (marked as interactive split root and not committing to an
		// active asset transfer).
		case vOut.Interactive && vOut.Type.IsSplitRoot() && vOut.Asset == nil:
			vOut.Type = tappsbt.TypePassiveAssetsOnly

		// In any other case we expect an active asset transfer to be
		// committed to.
		case vOut.Asset != nil:
			proofSuffix, err := CreateProofSuffix(
				s.AnchorTx, s.VirtualPacket, idx, nil,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"proof %d: %w", idx, err)
			}
			err = proofSuffix.Encode(&proofSuffixBuf)
			if err != nil {
				return nil, fmt.Errorf("unable to encode "+
					"proof %d: %w", idx, err)
			}
			witness = vOut.Asset.PrevWitnesses
			splitCommitmentRoot = vOut.Asset.SplitCommitmentRoot

		default:
			return nil, fmt.Errorf("invalid output %d, asset "+
				"missing and not marked for passive assets",
				idx)
		}

		txOut := s.AnchorTx.FinalTx.TxOut[vOut.AnchorOutputIndex]
		parcel.Outputs[idx] = TransferOutput{
			Anchor: Anchor{
				OutPoint: wire.OutPoint{
					Hash:  anchorTXID,
					Index: vOut.AnchorOutputIndex,
				},
				Value:            btcutil.Amount(txOut.Value),
				InternalKey:      anchorInternalKey,
				TaprootAssetRoot: taprootAssetRoot[:],
				MerkleRoot:       merkleRoot[:],
				TapscriptSibling: preimageBytes,
				NumPassiveAssets: numPassiveAssets,
			},
			Type:                vOut.Type,
			ScriptKey:           vOut.ScriptKey,
			Amount:              vOut.Amount,
			AssetVersion:        vOut.AssetVersion,
			WitnessData:         witness,
			SplitCommitmentRoot: splitCommitmentRoot,
			ProofSuffix:         proofSuffixBuf.Bytes(),
			ProofCourierAddr:    proofCourierAddrBytes,
		}
	}

	return parcel, nil
}

// CreateProofSuffix creates the new proof for the given output. This is the
// final state transition that will be added to the proofs of the receiver. The
// proof returned will have all the Taproot Asset level proof information, but
// contains dummy data for the on-chain part.
func CreateProofSuffix(anchorTx *AnchorTransaction, vPacket *tappsbt.VPacket,
	outIndex int, allAnchoredVPackets []*tappsbt.VPacket) (*proof.Proof,
	error) {

	inputPrevID := vPacket.Inputs[0].PrevID

	params, err := proofParams(
		anchorTx, vPacket, outIndex, allAnchoredVPackets,
	)
	if err != nil {
		return nil, err
	}

	isAnchor := func(anchorOutputIndex uint32) bool {
		// Does the current virtual packet anchor into this output?
		for outIdx := range vPacket.Outputs {
			vOut := vPacket.Outputs[outIdx]
			if vOut.AnchorOutputIndex == anchorOutputIndex {
				return true
			}
		}

		// Maybe any of the other anchored virtual packets anchor into
		// this output?
		for _, vPkt := range allAnchoredVPackets {
			for _, vOut := range vPkt.Outputs {
				if vOut.AnchorOutputIndex == anchorOutputIndex {
					return true
				}
			}
		}

		// No virtual packet anchors into this output, it must be a
		// pure BTC output.
		return false
	}

	// We also need to account for any P2TR change outputs.
	if len(anchorTx.FundedPsbt.Pkt.UnsignedTx.TxOut) > 1 {
		err := proof.AddExclusionProofs(
			&params.BaseProofParams, anchorTx.FundedPsbt.Pkt,
			isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion "+
				"proof for output %d: %w", outIndex, err)
		}
	}

	proofSuffix, err := proof.CreateTransitionProof(
		inputPrevID.OutPoint, params,
	)
	if err != nil {
		return nil, err
	}

	return proofSuffix, nil
}

// newParams is used to create a set of new params for the final state
// transition.
func newParams(anchorTx *AnchorTransaction, a *asset.Asset, outputIndex int,
	internalKey *btcec.PublicKey, taprootAssetRoot *commitment.TapCommitment,
	siblingPreimage *commitment.TapscriptPreimage) *proof.TransitionParams {

	return &proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Transactions: []*wire.MsgTx{
					anchorTx.FinalTx,
				},
			},
			Tx:               anchorTx.FinalTx,
			TxIndex:          0,
			OutputIndex:      outputIndex,
			InternalKey:      internalKey,
			TaprootAssetRoot: taprootAssetRoot,
			TapscriptSibling: siblingPreimage,
		},
		NewAsset: a,
	}
}

// proofParams creates the set of parameters that will be used to create the
// proofs for the sender and receiver.
func proofParams(anchorTx *AnchorTransaction, vPkt *tappsbt.VPacket,
	outIndex int,
	allAnchoredVPackets []*tappsbt.VPacket) (*proof.TransitionParams, error) {

	outputCommitments := anchorTx.OutputCommitments

	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return nil, err
	}

	allVirtualOutputs := append([]*tappsbt.VOutput{}, vPkt.Outputs...)
	for _, otherVPkt := range allAnchoredVPackets {
		allVirtualOutputs = append(
			allVirtualOutputs, otherVPkt.Outputs...,
		)
	}

	// Is this the split root? Then we need exclusion proofs from all the
	// split outputs. We can also use this path for interactive full value
	// send case, where we also just commit to an asset that has a TX
	// witness. We just need an inclusion proof and the exclusion proofs for
	// any other outputs.
	if vPkt.Outputs[outIndex].Type.IsSplitRoot() || !isSplit {
		rootOut := vPkt.Outputs[outIndex]
		rootIndex := rootOut.AnchorOutputIndex
		rootTapTree := outputCommitments[rootIndex]

		rootParams := newParams(
			anchorTx, rootOut.Asset, int(rootIndex),
			rootOut.AnchorOutputInternalKey, rootTapTree,
			rootOut.AnchorOutputTapscriptSibling,
		)

		// Add exclusion proofs for all the other outputs.
		err = addOtherOutputExclusionProofs(
			allVirtualOutputs, rootOut.Asset, rootParams,
			outputCommitments,
		)
		if err != nil {
			return nil, err
		}

		return rootParams, nil
	}

	// If this isn't the split root, then we need an exclusion proof from
	// just the split root.
	splitRootOut, err := vPkt.SplitRootOutput()
	if err != nil {
		return nil, fmt.Errorf("error getting split root output: %w",
			err)
	}

	splitRootIndex := splitRootOut.AnchorOutputIndex
	splitRootTree := outputCommitments[splitRootIndex]

	splitOut := vPkt.Outputs[outIndex]
	splitIndex := splitOut.AnchorOutputIndex
	splitTapTree := outputCommitments[splitIndex]

	_, splitRootExclusionProof, err := splitRootTree.Proof(
		splitOut.Asset.TapCommitmentKey(),
		splitOut.Asset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, err
	}

	splitRootPreimage := splitRootOut.AnchorOutputTapscriptSibling
	splitParams := newParams(
		anchorTx, splitOut.Asset, int(splitIndex),
		splitOut.AnchorOutputInternalKey, splitTapTree,
		splitOut.AnchorOutputTapscriptSibling,
	)
	splitParams.RootOutputIndex = splitRootIndex
	splitParams.RootInternalKey = splitRootOut.AnchorOutputInternalKey
	splitParams.RootTaprootAssetTree = splitRootTree
	splitParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: splitRootIndex,
		InternalKey: splitRootOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof:              *splitRootExclusionProof,
			TapSiblingPreimage: splitRootPreimage,
		},
	}}

	// Add exclusion proofs for all the other outputs.
	err = addOtherOutputExclusionProofs(
		allVirtualOutputs, splitOut.Asset, splitParams,
		outputCommitments,
	)
	if err != nil {
		return nil, err
	}

	return splitParams, nil
}

// addOtherOutputExclusionProofs adds exclusion proofs for all the outputs that
// are asset outputs but haven't been processed yet (the skip function needs to
// return false for not yet processed outputs, otherwise they'll be skipped).
func addOtherOutputExclusionProofs(outputs []*tappsbt.VOutput,
	asset *asset.Asset, params *proof.TransitionParams,
	outputCommitments map[uint32]*commitment.TapCommitment) error {

	for idx := range outputs {
		vOut := outputs[idx]

		haveIProof := params.HaveInclusionProof(vOut.AnchorOutputIndex)
		haveEProof := params.HaveExclusionProof(vOut.AnchorOutputIndex)
		if haveIProof || haveEProof {
			continue
		}

		outIndex := vOut.AnchorOutputIndex
		tapTree := outputCommitments[outIndex]

		_, splitExclusionProof, err := tapTree.Proof(
			asset.TapCommitmentKey(),
			asset.AssetCommitmentKey(),
		)
		if err != nil {
			return err
		}

		log.Tracef("Generated exclusion proof for anchor output index "+
			"%d with asset_id=%v, taproot_asset_root=%x, "+
			"internal_key=%x", outIndex, asset.ID(),
			fn.ByteSlice(tapTree.TapscriptRoot(nil)),
			vOut.AnchorOutputInternalKey.SerializeCompressed())

		siblingPreimage := vOut.AnchorOutputTapscriptSibling
		exclusionProof := proof.TaprootProof{
			OutputIndex: outIndex,
			InternalKey: vOut.AnchorOutputInternalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *splitExclusionProof,
				TapSiblingPreimage: siblingPreimage,
			},
		}
		params.ExclusionProofs = append(
			params.ExclusionProofs, exclusionProof,
		)
	}

	return nil
}

// createReAnchorProof creates the new proof for the re-anchoring of a passive
// asset.
func (s *sendPackage) createReAnchorProof(
	passivePkt *tappsbt.VPacket) (*proof.Proof, error) {

	// Passive asset transfers only have a single input and a single output.
	passiveIn := passivePkt.Inputs[0]
	passiveOut := passivePkt.Outputs[0]

	// Passive assets are always anchored at a specific marked output, which
	// normally contains asset change. But it can also be that the split
	// root output was just created for the passive assets, if there is no
	// active transfer or no change.
	passiveCarrierOut, err := s.VirtualPacket.PassiveAssetsOutput()
	if err != nil {
		return nil, fmt.Errorf("anchor output for passive assets not "+
			"found: %w", err)
	}

	outputCommitments := s.AnchorTx.OutputCommitments
	passiveOutputIndex := passiveOut.AnchorOutputIndex
	passiveTapTree := outputCommitments[passiveOutputIndex]

	// The base parameters include the inclusion proof of the passive asset
	// in the split root output.
	passiveParams := newParams(
		s.AnchorTx, passiveOut.Asset, int(passiveOutputIndex),
		passiveCarrierOut.AnchorOutputInternalKey, passiveTapTree,
		passiveCarrierOut.AnchorOutputTapscriptSibling,
	)

	// Since a transfer might contain other anchor outputs, we need to
	// provide an exclusion proof of the passive asset for each of the other
	// BTC level outputs.
	err = addOtherOutputExclusionProofs(
		s.VirtualPacket.Outputs, passiveOut.Asset, passiveParams,
		outputCommitments,
	)
	if err != nil {
		return nil, err
	}

	// Add exclusion proof(s) for any P2TR (=BIP-0086, not carrying any
	// assets) change outputs.
	if len(s.AnchorTx.FundedPsbt.Pkt.UnsignedTx.TxOut) > 1 {
		isAnchor := func(idx uint32) bool {
			for outIdx := range s.VirtualPacket.Outputs {
				vOut := s.VirtualPacket.Outputs[outIdx]
				if vOut.AnchorOutputIndex == idx {
					return true
				}
			}

			return false
		}

		err := proof.AddExclusionProofs(
			&passiveParams.BaseProofParams,
			s.AnchorTx.FundedPsbt.Pkt, isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion "+
				"proof for change output: %w", err)
		}
	}

	// Generate a proof of this new state transition.
	reAnchorProof, err := proof.CreateTransitionProof(
		passiveIn.PrevID.OutPoint, passiveParams,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating re-anchor proof: %w",
			err)
	}

	return reAnchorProof, nil
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
