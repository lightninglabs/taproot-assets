package tarofreighter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// SendState is an enum that describes the current state of a pending outbound
// parcel (asset transfer).
type SendState uint8

const (
	// SendStateVirtualCommitmentSelect is the state for performing input coin
	// selection to pick out which assets inputs should be spent.
	SendStateVirtualCommitmentSelect SendState = iota

	// SendStateVirtualSign is used to generate the Taro level witness data for
	// any inputs being spent.
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

	// dest returns the destination address for the parcel.
	dest() *address.Taro
}

// parcelKit is a struct that contains the channels that are used to deliver
// responses to the parcel creator.
type parcelKit struct {
	// respChan is the channel a response will be sent over.
	respChan chan *PendingParcel

	// errChan is the channel the error will be sent over.
	errChan chan error
}

// AddressParcel is the main request to issue an asset transfer. This packages a
// destination address, and also response context.
type AddressParcel struct {
	*parcelKit

	// destAddr is the address that should be used to satisfy the transfer.
	destAddr *address.Taro
}

// A compile-time assertion to ensure AddressParcel implements the parcel
// interface.
var _ Parcel = (*AddressParcel)(nil)

// NewAddressParcel creates a new AddressParcel.
func NewAddressParcel(destAddr *address.Taro) *AddressParcel {
	return &AddressParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *PendingParcel, 1),
			errChan:  make(chan error, 1),
		},
		destAddr: destAddr,
	}
}

// pkg returns the send package that should be delivered.
func (p *AddressParcel) pkg() *sendPackage {
	log.Infof("Received to send request to: %x:%x", p.destAddr.ID(),
		p.destAddr.ScriptKey.SerializeCompressed())

	// Initialize a package with the destination address.
	return &sendPackage{
		Parcel: p,
	}
}

// kit returns the parcel kit used for delivery.
func (p *AddressParcel) kit() *parcelKit {
	return p.parcelKit
}

// dest returns the destination address for the parcel.
func (p *AddressParcel) dest() *address.Taro {
	return p.destAddr
}

// PreSignedParcel is a request to issue an asset transfer of a pre-signed
// parcel. This packages a virtual transaction, the input commitment, and also
// the response context.
type PreSignedParcel struct {
	*parcelKit

	// vPkt is the virtual transaction that should be delivered.
	vPkt *taropsbt.VPacket

	// inputCommitment is the commitment for the input that is being spent
	// in the virtual transaction.
	inputCommitment *commitment.TaroCommitment
}

// A compile-time assertion to ensure AddressParcel implements the parcel
// interface.
var _ Parcel = (*PreSignedParcel)(nil)

// NewPreSignedParcel creates a new PreSignedParcel.
func NewPreSignedParcel(vPkt *taropsbt.VPacket,
	inputCommitment *commitment.TaroCommitment) *PreSignedParcel {

	return &PreSignedParcel{
		parcelKit: &parcelKit{
			respChan: make(chan *PendingParcel, 1),
			errChan:  make(chan error, 1),
		},
		vPkt:            vPkt,
		inputCommitment: inputCommitment,
	}
}

// pkg returns the send package that should be delivered.
func (p *PreSignedParcel) pkg() *sendPackage {
	log.Infof("New signed delivery request with %d outputs",
		len(p.vPkt.Outputs))

	// Initialize a package the signed virtual transaction and input
	// commitment.
	return &sendPackage{
		Parcel:          p,
		SendState:       SendStateAnchorSign,
		VirtualPacket:   p.vPkt,
		InputCommitment: p.inputCommitment,
	}
}

// kit returns the parcel kit used for delivery.
func (p *PreSignedParcel) kit() *parcelKit {
	return p.parcelKit
}

// dest returns the destination address for the parcel.
func (p *PreSignedParcel) dest() *address.Taro {
	// TODO(guggero): Fix for interactive full-value send.
	vIn := p.vPkt.Inputs[0]
	vOut := p.vPkt.Outputs[1]
	return &address.Taro{
		ChainParams: p.vPkt.ChainParams,
		Genesis:     vIn.Asset().Genesis,
		ScriptKey:   *vOut.ScriptKey.PubKey,
		InternalKey: *vOut.AnchorOutputInternalKey,
		Amount:      vOut.Amount,
	}
}

// AssetInput represents a previous asset input.
type AssetInput struct {
	// PrevID is the prev ID of the input.
	PrevID asset.PrevID

	// Amount is the amount stored in the target asset input.
	Amount btcutil.Amount
}

// AssetOutput represents a new asset output created as a result of a transfer.
type AssetOutput struct {
	AssetInput

	// NewBlob is the new proof blob of the asset.
	//
	// TODO(roasbeef): should just be the last transition, or mmap'd
	NewBlob proof.Blob

	// SplitCommitProof is an optional field of the split commitment proof.
	// If this is set, then this new asset was a split that resulted from a
	// send that needed change.
	SplitCommitProof *commitment.SplitCommitment
}

// PendingParcel is the response to a Parcel shipment request. This contains all
// the information of the pending transfer.
type PendingParcel struct {
	// OldTaroRoot is the Taro commitment root of the old anchor point.
	OldTaroRoot []byte

	// NewAnchorPoint is the new anchor point that commits to our new change
	// assets.
	NewAnchorPoint wire.OutPoint

	// NewTaroRoot is the Taro commitment root of the new anchor point.
	NewTaroRoot []byte

	// TransferTx is the transaction that completed the transfer.
	TransferTx *wire.MsgTx

	// AssetInputs are the set if inputs to the transfer transaction on the
	// Taro layer.
	AssetInputs []AssetInput

	// AssetOutputs is the set of newly produced outputs.
	AssetOutputs []AssetOutput

	// TotalFees is the amount of on chain fees that the transfer
	// transaction required.
	TotalFees btcutil.Amount
}

// sendPackage houses the information we need to complete a package transfer.
type sendPackage struct {
	// SendState is the current send state of this parcel.
	SendState SendState

	// VirtualPacket is the virtual packet that we'll use to construct the
	// virtual asset transition transaction.
	VirtualPacket *taropsbt.VPacket

	// PassiveAssets is the data used in re-anchoring passive assets.
	PassiveAssets []*PassiveAssetReAnchor

	// Parcel is the asset transfer request that kicked off this transfer.
	Parcel Parcel

	// InputCommitment is the full Taro tree of the asset being spent.
	InputCommitment *commitment.TaroCommitment

	// AnchorTx is the BTC level anchor transaction with all its information
	// as it was used when funding/signing it.
	AnchorTx *AnchorTransaction

	// OutboundPkg is the on-disk level information that tracks the pending
	// transfer.
	OutboundPkg *OutboundParcelDelta

	// TransferTxConfEvent contains transfer transaction on-chain
	// confirmation data.
	TransferTxConfEvent *chainntnfs.TxConfirmation
}

// prepareForStorage prepares the send package for storing to the database.
func (s *sendPackage) prepareForStorage(currentHeight uint32) error {
	// Now we'll grab our new commitment, and also the output index
	// to populate the log entry below.
	input := s.VirtualPacket.Inputs[0]
	senderOut := s.VirtualPacket.Outputs[0]
	anchorOutputIndex := senderOut.AnchorOutputIndex
	outputCommitments := s.AnchorTx.OutputCommitments
	newSenderCommitment := outputCommitments[anchorOutputIndex]

	var tapscriptSibling *chainhash.Hash
	if len(input.Anchor.TapscriptSibling) > 0 {
		h, err := chainhash.NewHash(
			input.Anchor.TapscriptSibling,
		)
		if err != nil {
			return err
		}

		tapscriptSibling = h
	}

	taroRoot := newSenderCommitment.TapscriptRoot(tapscriptSibling)

	senderProof, receiverProof, err := s.createProofs()
	if err != nil {
		return err
	}

	// Before we write to disk, we'll make the incomplete proofs
	// for the sender and the receiver.
	var senderProofBuf bytes.Buffer
	if err := senderProof.Encode(&senderProofBuf); err != nil {
		return err
	}

	var receiverProofBuf bytes.Buffer
	if err := receiverProof.Encode(&receiverProofBuf); err != nil {
		return err
	}

	// Gather newly generated data required for re-anchoring passive
	// assets.
	for _, passiveAsset := range s.PassiveAssets {
		// Generate passive asset re-anchoring proofs.
		newProof, err := s.createReAnchorProof(
			passiveAsset.VPacket,
		)
		if err != nil {
			return fmt.Errorf("failed to create re-anchor proof: "+
				"%w", err)
		}

		passiveAsset.NewProof = newProof

		vOut := passiveAsset.VPacket.Outputs[0]
		passiveAsset.NewWitnessData = vOut.Asset.PrevWitnesses
	}

	// Before we broadcast, we'll write to disk that we have a
	// pending outbound parcel. If we crash before this point,
	// we'll start all over. Otherwise, we'll come back to this
	// state to re-do the process.
	//
	// TODO(roasbeef); need to update proof file information,
	// ideally the db doesn't do this directly
	vIn := s.VirtualPacket.Inputs[0]
	inputAsset := vIn.Asset()
	newAsset := senderOut.Asset

	newInternalKeyDesc, err := senderOut.AnchorKeyToDesc()
	if err != nil {
		return fmt.Errorf("unable to get anchor key desc: %w", err)
	}

	s.OutboundPkg = &OutboundParcelDelta{
		OldAnchorPoint: vIn.PrevID.OutPoint,
		NewAnchorPoint: wire.OutPoint{
			Hash:  s.AnchorTx.FinalTx.TxHash(),
			Index: anchorOutputIndex,
		},
		NewInternalKey:     newInternalKeyDesc,
		TaroRoot:           taroRoot[:],
		AnchorTx:           s.AnchorTx.FinalTx,
		AnchorTxHeightHint: currentHeight,
		AssetSpendDeltas: []AssetSpendDelta{{
			OldScriptKey:        *inputAsset.ScriptKey.PubKey,
			NewAmt:              newAsset.Amount,
			NewScriptKey:        senderOut.ScriptKey,
			WitnessData:         newAsset.PrevWitnesses,
			SplitCommitmentRoot: newAsset.SplitCommitmentRoot,
			SenderAssetProof:    senderProofBuf.Bytes(),
			ReceiverAssetProof:  receiverProofBuf.Bytes(),
		}},
		TapscriptSibling: vIn.Anchor.TapscriptSibling,
		// TODO(bhandras): use clock.Clock instead.
		TransferTime:  time.Now(),
		ChainFees:     s.AnchorTx.ChainFees,
		PassiveAssets: s.PassiveAssets,
	}

	return nil
}

// createProofs creates the new set of proofs for the sender and the receiver.
// This is the final state transition that will be added to the proofs of both
// the sender and receiver. The proofs returned will have all the Taro level
// proof information, but contains dummy data for
func (s *sendPackage) createProofs() (*proof.Proof, *proof.Proof, error) {
	// dummyParams is used to create a set of dummy params for the final
	// state transition.
	dummyParams := func() proof.TransitionParams {
		return proof.TransitionParams{
			BaseProofParams: proof.BaseProofParams{
				Block: &wire.MsgBlock{
					Transactions: []*wire.MsgTx{
						s.AnchorTx.FinalTx,
					},
				},
				Tx:      s.AnchorTx.FinalTx,
				TxIndex: 0,
			},
		}
	}

	// First, we'll start by creating the dummy params with dummy chain
	// level proofs.
	senderParams := dummyParams()
	receiverParams := dummyParams()

	// We can now fetch the new Taro trees for the sender+receiver and also
	// the outputs indexes of each tree commitment.
	inputAsset := s.VirtualPacket.Inputs[0].Asset()
	inputPrevID := s.VirtualPacket.Inputs[0].PrevID
	outputCommitments := s.AnchorTx.OutputCommitments

	senderOut := s.VirtualPacket.Outputs[0]
	senderTaroTree := outputCommitments[senderOut.AnchorOutputIndex]
	senderAsset := senderOut.Asset
	senderIndex := senderOut.AnchorOutputIndex

	receiverOut := s.VirtualPacket.Outputs[1]
	receiverTaroTree := outputCommitments[receiverOut.AnchorOutputIndex]
	receiverAsset := receiverOut.Asset
	receiverIndex := receiverOut.AnchorOutputIndex

	// Next we'll compute the exclusion proofs for the sender and receiver.
	// This proves that the asset committed to isn't contained in any of
	// the other outputs in the transfer transaction.
	var (
		senderExclusionProof   *commitment.Proof
		receiverExclusionProof *commitment.Proof
		err                    error
	)

	isSplit, err := s.VirtualPacket.HasSplitCommitment()
	if err != nil {
		return nil, nil, err
	}

	// If we require a split, then we'll need to prove exclusion for both
	// parties.
	if isSplit {
		senderParams.NewAsset = senderAsset

		// First, we'll compute an exclusion proof that show that the
		// sender's asset isn't committed in the receiver's' tree.
		_, senderExclusionProof, err = receiverTaroTree.Proof(
			senderAsset.TaroCommitmentKey(),
			senderAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, nil, err
		}

		// With the proofs computed, we'll now place the receiver's new
		// asset in their proof, and also set the information that lets
		// us prove that their split is valid.
		receiverParams.NewAsset = receiverAsset
		receiverParams.RootOutputIndex = senderIndex
		receiverParams.RootInternalKey = senderOut.AnchorOutputInternalKey
		receiverParams.RootTaroTree = senderTaroTree
	} else {
		// Otherwise, if there's no split, then we can just compute a
		// simpler exclusion proof for the sender and receiver.
		//
		// TODO(jhb): NewAsset for sender proof can be empty?
		receiverParams.NewAsset = receiverAsset

		_, senderExclusionProof, err = receiverTaroTree.Proof(
			inputAsset.TaroCommitmentKey(),
			inputAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, nil, err
		}
	}

	// Next, we'll do the opposite for the receiver.
	_, receiverExclusionProof, err = senderTaroTree.Proof(
		receiverAsset.TaroCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, nil, err
	}

	// In a final phase, we'll fill out the remaining parameters for the
	// sender and receiver to generate a proof of this new state
	// transition.
	senderParams.OutputIndex = int(senderIndex)
	senderParams.InternalKey = senderOut.AnchorOutputInternalKey
	senderParams.TaroRoot = senderTaroTree
	senderParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: receiverIndex,
		InternalKey: receiverOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *senderExclusionProof,
		},
	}}

	receiverParams.OutputIndex = int(receiverIndex)
	receiverParams.InternalKey = receiverOut.AnchorOutputInternalKey
	receiverParams.TaroRoot = receiverTaroTree
	receiverParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: senderIndex,
		InternalKey: senderOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *receiverExclusionProof,
		},
	}}

	// We also need to account for any P2TR change outputs.
	if s.AnchorTx.FundedPsbt.ChangeOutputIndex > -1 {
		isAnchor := func(idx uint32) bool {
			// We exclude both sender and receiver
			// commitments because those get their own,
			// individually created exclusion proofs.
			return idx == senderIndex || idx == receiverIndex
		}

		err := proof.AddExclusionProofs(
			&senderParams.BaseProofParams,
			s.AnchorTx.FundedPsbt.Pkt, isAnchor,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding exclusion "+
				"proof for change output: %w", err)
		}

		err = proof.AddExclusionProofs(
			&receiverParams.BaseProofParams,
			s.AnchorTx.FundedPsbt.Pkt, isAnchor,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding exclusion "+
				"proof for change output: %w", err)
		}
	}

	senderProof, err := proof.CreateTransitionProof(
		inputPrevID.OutPoint, &senderParams,
	)
	if err != nil {
		return nil, nil, err
	}
	receiverProof, err := proof.CreateTransitionProof(
		inputPrevID.OutPoint, &receiverParams,
	)
	if err != nil {
		return nil, nil, err
	}

	return senderProof, receiverProof, nil
}

// createReAnchorProof creates the new proof for the re-anchoring of a passive
// asset.
func (s *sendPackage) createReAnchorProof(vPkt *taropsbt.VPacket) (*proof.Proof,
	error) {

	vIn := vPkt.Inputs[0]
	vOut := vPkt.Outputs[0]

	outputCommitments := s.AnchorTx.OutputCommitments

	// Create the exclusion proof for the receiver's tree.
	// TODO(ffranr): Remove static output index once PSBT work is complete.
	receiverOutputIndex := uint32(1)
	receiverTaroTree := outputCommitments[receiverOutputIndex]
	receiverOut := s.VirtualPacket.Outputs[receiverOutputIndex]

	_, receiverTreeExclusionProof, err := receiverTaroTree.Proof(
		vIn.Asset().TaroCommitmentKey(),
		vIn.Asset().AssetCommitmentKey(),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating exclusion proof for "+
			"re-anchor: %w", err)
	}

	receiverTaprootProof := proof.TaprootProof{
		OutputIndex: receiverOutputIndex,
		InternalKey: receiverOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *receiverTreeExclusionProof,
		},
	}

	// Fetch the new Taro tree for the passive asset.
	passiveAssetTaroTree := outputCommitments[vOut.AnchorOutputIndex]

	// Create the base proof parameters for the re-anchor.
	baseProofParams := proof.BaseProofParams{
		Block: &wire.MsgBlock{
			Transactions: []*wire.MsgTx{
				s.AnchorTx.FinalTx,
			},
		},
		Tx:              s.AnchorTx.FinalTx,
		OutputIndex:     int(vOut.AnchorOutputIndex),
		InternalKey:     vOut.AnchorOutputInternalKey,
		TaroRoot:        passiveAssetTaroTree,
		ExclusionProofs: []proof.TaprootProof{receiverTaprootProof},
	}

	// Add exclusion proof(s) for any P2TR change outputs.
	if s.AnchorTx.FundedPsbt.ChangeOutputIndex > -1 {
		isAnchor := func(idx uint32) bool {
			// We exclude both sender and receiver
			// commitments because those get their own,
			// individually created exclusion proofs.
			return idx == vOut.AnchorOutputIndex ||
				idx == receiverOutputIndex
		}

		err := proof.AddExclusionProofs(
			&baseProofParams, s.AnchorTx.FundedPsbt.Pkt, isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion "+
				"proof for change output: %w", err)
		}
	}

	// Generate a proof of this new state transition.
	transitionParams := proof.TransitionParams{
		BaseProofParams: baseProofParams,
		NewAsset:        vOut.Asset,
	}
	reAnchorProof, err := proof.CreateTransitionProof(
		vIn.PrevID.OutPoint, &transitionParams,
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

	oldRoot := s.InputCommitment.TapscriptRoot(nil)

	senderAsset := s.VirtualPacket.Outputs[0].Asset
	receiverAsset := s.VirtualPacket.Outputs[1].Asset
	log.Infof("Outbound parcel now pending for %x:%x, delivering "+
		"notification", receiverAsset.ID(),
		receiverAsset.ScriptKey.PubKey.SerializeCompressed())

	// Get the output index of the receiver from the spend locators.
	vIn := s.VirtualPacket.Inputs[0]
	receiverIndex := s.VirtualPacket.Outputs[1].AnchorOutputIndex

	s.Parcel.kit().respChan <- &PendingParcel{
		NewAnchorPoint: s.OutboundPkg.NewAnchorPoint,
		TransferTx:     s.OutboundPkg.AnchorTx,
		OldTaroRoot:    oldRoot[:],
		NewTaroRoot:    s.OutboundPkg.TaroRoot,
		AssetInputs: []AssetInput{
			{
				PrevID: vIn.PrevID,
				Amount: btcutil.Amount(vIn.Asset().Amount),
			},
		},
		AssetOutputs: []AssetOutput{{
			AssetInput: AssetInput{
				PrevID: asset.PrevID{
					OutPoint: s.OutboundPkg.NewAnchorPoint,
					ID:       senderAsset.ID(),
					ScriptKey: asset.ToSerialized(
						senderAsset.ScriptKey.PubKey,
					),
				},
				Amount: btcutil.Amount(senderAsset.Amount),
			},
		}, {
			AssetInput: AssetInput{
				PrevID: asset.PrevID{
					OutPoint: wire.OutPoint{
						Hash:  s.OutboundPkg.NewAnchorPoint.Hash,
						Index: receiverIndex,
					},
					ID: receiverAsset.ID(),
					ScriptKey: asset.ToSerialized(
						receiverAsset.ScriptKey.PubKey,
					),
				},
				Amount: btcutil.Amount(receiverAsset.Amount),
			},
		}},
		TotalFees: btcutil.Amount(s.OutboundPkg.ChainFees),
	}
}
