package tarofreighter

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
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

// createProofs creates the new set of proofs for the sender and the receiver.
// This is the final state transition that will be added to the proofs of both
// the sender and receiver. The proofs returned will have all the Taro level
// proof information, but contains dummy data for
func (s *sendPackage) createProofs() (*proof.Proof, *proof.Proof, error) {
	inputPrevID := s.VirtualPacket.Inputs[0].PrevID

	senderParams, receiverParams, err := proofParams(
		s.AnchorTx, s.VirtualPacket,
	)
	if err != nil {
		return nil, nil, err
	}

	// We also need to account for any P2TR change outputs.
	if s.AnchorTx.FundedPsbt.ChangeOutputIndex > -1 {
		isAnchor := func(idx uint32) bool {
			// We exclude both sender and receiver commitments
			// because those get their own, individually created
			// exclusion proofs.
			return idx == uint32(senderParams.OutputIndex) ||
				idx == uint32(receiverParams.OutputIndex)
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
		inputPrevID.OutPoint, senderParams,
	)
	if err != nil {
		return nil, nil, err
	}
	receiverProof, err := proof.CreateTransitionProof(
		inputPrevID.OutPoint, receiverParams,
	)
	if err != nil {
		return nil, nil, err
	}

	return senderProof, receiverProof, nil
}

// newParams is used to create a set of new params for the final state
// transition.
func newParams(anchorTx *AnchorTransaction, a *asset.Asset, outputIndex int,
	internalKey *btcec.PublicKey,
	taroRoot *commitment.TaroCommitment) *proof.TransitionParams {

	return &proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Transactions: []*wire.MsgTx{
					anchorTx.FinalTx,
				},
			},
			Tx:          anchorTx.FinalTx,
			TxIndex:     0,
			OutputIndex: outputIndex,
			InternalKey: internalKey,
			TaroRoot:    taroRoot,
		},
		NewAsset: a,
	}
}

// proofParams creates the set of parameters that will be used to create the
// proofs for the sender and receiver.
func proofParams(anchorTx *AnchorTransaction,
	vPkt *taropsbt.VPacket) (*proof.TransitionParams,
	*proof.TransitionParams, error) {

	outputCommitments := anchorTx.OutputCommitments

	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return nil, nil, err
	}

	// If there is no split, then the sender proof will only be an exclusion
	// proof of the input asset. But the BTC on-chain outputs will be the
	// same for both.
	if !isSplit {
		inputAsset := vPkt.Inputs[0].Asset()

		receiverOut := vPkt.Outputs[0]
		receiverIndex := receiverOut.AnchorOutputIndex
		receiverTaroTree := outputCommitments[receiverIndex]
		receiverAsset := receiverOut.Asset

		// Otherwise, if there's no split, then we can just compute a
		// simpler exclusion proof for the sender and receiver.
		_, senderExclusionProof, err := receiverTaroTree.Proof(
			inputAsset.TaroCommitmentKey(),
			inputAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, nil, err
		}

		senderParams := newParams(
			anchorTx, nil, int(receiverIndex),
			receiverOut.AnchorOutputInternalKey, receiverTaroTree,
		)
		senderParams.ExclusionProofs = []proof.TaprootProof{{
			OutputIndex: receiverIndex,
			InternalKey: receiverOut.AnchorOutputInternalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof: *senderExclusionProof,
			},
		}}

		receiverParams := newParams(
			anchorTx, receiverAsset, int(receiverIndex),
			receiverOut.AnchorOutputInternalKey, receiverTaroTree,
		)

		return senderParams, receiverParams, nil
	}

	senderOut := vPkt.Outputs[0]
	senderTaroTree := outputCommitments[senderOut.AnchorOutputIndex]
	senderAsset := senderOut.Asset
	senderIndex := senderOut.AnchorOutputIndex

	receiverOut := vPkt.Outputs[1]
	receiverTaroTree := outputCommitments[receiverOut.AnchorOutputIndex]
	receiverAsset := receiverOut.Asset
	receiverIndex := receiverOut.AnchorOutputIndex

	// First, we'll compute an exclusion proof that show that the
	// sender's asset isn't committed in the receiver's' tree.
	_, senderExclusionProof, err := receiverTaroTree.Proof(
		senderAsset.TaroCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, nil, err
	}

	// Next, we'll do the opposite for the receiver.
	_, receiverExclusionProof, err := senderTaroTree.Proof(
		receiverAsset.TaroCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, nil, err
	}

	// With the proofs computed, we'll now place the receiver's new
	// asset in their proof, and also set the information that lets
	// us prove that their split is valid.
	receiverParams := newParams(
		anchorTx, receiverAsset, int(receiverIndex),
		receiverOut.AnchorOutputInternalKey, receiverTaroTree,
	)
	receiverParams.RootOutputIndex = senderIndex
	receiverParams.RootInternalKey = senderOut.AnchorOutputInternalKey
	receiverParams.RootTaroTree = senderTaroTree
	receiverParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: senderIndex,
		InternalKey: senderOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *receiverExclusionProof,
		},
	}}

	// In a final phase, we'll fill out the remaining parameters for the
	// sender and receiver to generate a proof of this new state
	// transition.
	senderParams := newParams(
		anchorTx, senderAsset, int(senderIndex),
		senderOut.AnchorOutputInternalKey, senderTaroTree,
	)
	senderParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: receiverIndex,
		InternalKey: receiverOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *senderExclusionProof,
		},
	}}

	return senderParams, receiverParams, nil
}

// deliverTxBroadcastResp delivers a response for the parcel back to the
// receiver over the response channel.
func (s *sendPackage) deliverTxBroadcastResp() error {
	// Ensure that we have a response channel to deliver the response over.
	// We may not have one if the package send process was recommenced after
	// a restart.
	if s.Parcel == nil {
		log.Warnf("No response channel for resumed parcel, not " +
			"delivering notification")
		return nil
	}

	oldRoot := s.InputCommitment.TapscriptRoot(nil)

	// Prepare the output independent part of the pending parcel.
	vIn := s.VirtualPacket.Inputs[0]
	pending := &PendingParcel{
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
		TotalFees: btcutil.Amount(s.OutboundPkg.ChainFees),
	}

	isSplit, err := s.VirtualPacket.HasSplitCommitment()
	if err != nil {
		return fmt.Errorf("unable to determine if parcel has split")
	}

	if !isSplit {
		receiverOut := s.VirtualPacket.Outputs[0]
		receiverAsset := receiverOut.Asset
		log.Infof("Outbound parcel now pending for %x:%x, delivering "+
			"notification", receiverAsset.ID(),
			receiverOut.ScriptKey.PubKey.SerializeCompressed())

		pending.AssetOutputs = []AssetOutput{{
			AssetInput: AssetInput{
				PrevID: asset.PrevID{
					ScriptKey: asset.NUMSCompressedKey,
				},
				Amount: 0,
			},
		}, {
			AssetInput: AssetInput{
				PrevID: asset.PrevID{
					OutPoint: wire.OutPoint{
						Hash:  s.OutboundPkg.NewAnchorPoint.Hash,
						Index: receiverOut.AnchorOutputIndex,
					},
					ID: receiverAsset.ID(),
					ScriptKey: asset.ToSerialized(
						receiverAsset.ScriptKey.PubKey,
					),
				},
				Amount: btcutil.Amount(receiverAsset.Amount),
			},
		}}

		s.Parcel.kit().respChan <- pending
		return nil
	}

	senderAsset := s.VirtualPacket.Outputs[0].Asset
	receiverAsset := s.VirtualPacket.Outputs[1].Asset
	log.Infof("Outbound parcel now pending for %x:%x, delivering "+
		"notification", receiverAsset.ID(),
		receiverAsset.ScriptKey.PubKey.SerializeCompressed())

	// Get the output index of the receiver from the spend locators.
	receiverIndex := s.VirtualPacket.Outputs[1].AnchorOutputIndex

	pending.AssetOutputs = []AssetOutput{{
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
	}}

	s.Parcel.kit().respChan <- pending
	return nil
}
