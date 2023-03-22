package tarofreighter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
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
			respChan: make(chan *OutboundParcel, 1),
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
			respChan: make(chan *OutboundParcel, 1),
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

		var tapscriptSibling *chainhash.Hash
		// TODO(guggero): Actually store and retrieve the tapscript
		// sibling, verify with unit/integration test.
		outCommitment := outputCommitments[vOut.AnchorOutputIndex]
		taroRoot := outCommitment.TapscriptRoot(tapscriptSibling)

		proofSuffix, err := s.createProofSuffix(idx)
		if err != nil {
			return nil, fmt.Errorf("unable to create proof %d: %w",
				idx, err)
		}
		var proofSuffixBuf bytes.Buffer
		if err := proofSuffix.Encode(&proofSuffixBuf); err != nil {
			return nil, fmt.Errorf("unable to encode proof %d: %w",
				idx, err)
		}

		// The split root is where we commit the passive assets to.
		var numPassiveAssets uint32
		if vOut.IsSplitRoot {
			numPassiveAssets = uint32(len(s.PassiveAssets))
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
				MerkleRoot:       taroRoot[:],
				TapscriptSibling: nil,
				NumPassiveAssets: numPassiveAssets,
			},
			ScriptKey:           vOut.ScriptKey,
			Amount:              vOut.Amount,
			WitnessData:         vOut.Asset.PrevWitnesses,
			SplitCommitmentRoot: vOut.Asset.SplitCommitmentRoot,
			ProofSuffix:         proofSuffixBuf.Bytes(),
		}
	}

	return parcel, nil
}

// createProofSuffix creates the new proof for the given output. This is the
// final state transition that will be added to the proofs of the receiver. The
// proof returned will have all the Taro level proof information, but contains
// dummy data for the on-chain part.
func (s *sendPackage) createProofSuffix(outIndex int) (*proof.Proof, error) {
	inputPrevID := s.VirtualPacket.Inputs[0].PrevID

	params, err := proofParams(s.AnchorTx, s.VirtualPacket, outIndex)
	if err != nil {
		return nil, err
	}

	// We also need to account for any P2TR change outputs.
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
			&params.BaseProofParams, s.AnchorTx.FundedPsbt.Pkt,
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
func proofParams(anchorTx *AnchorTransaction, vPkt *taropsbt.VPacket,
	outIndex int) (*proof.TransitionParams, error) {

	outputCommitments := anchorTx.OutputCommitments

	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return nil, err
	}

	// Is this the split root? Then we need exclusion proofs from all the
	// split outputs. We can also use this path for interactive full value
	// send case, where we also just commit to an asset that has a TX
	// witness. We just need an inclusion proof and the exclusion proofs for
	// any other outputs.
	if vPkt.Outputs[outIndex].IsSplitRoot || !isSplit {
		rootOut := vPkt.Outputs[outIndex]
		rootIndex := rootOut.AnchorOutputIndex
		rootTaroTree := outputCommitments[rootIndex]

		rootParams := newParams(
			anchorTx, rootOut.Asset, int(rootIndex),
			rootOut.AnchorOutputInternalKey, rootTaroTree,
		)

		for idx := range vPkt.Outputs {
			if idx == outIndex {
				continue
			}

			splitOut := vPkt.Outputs[idx]
			splitIndex := splitOut.AnchorOutputIndex
			splitTaroTree := outputCommitments[splitIndex]

			_, splitExclusionProof, err := splitTaroTree.Proof(
				rootOut.Asset.TaroCommitmentKey(),
				rootOut.Asset.AssetCommitmentKey(),
			)
			if err != nil {
				return nil, err
			}

			exclusionProof := proof.TaprootProof{
				OutputIndex: splitIndex,
				InternalKey: splitOut.AnchorOutputInternalKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *splitExclusionProof,
				},
			}
			rootParams.ExclusionProofs = append(
				rootParams.ExclusionProofs, exclusionProof,
			)
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
	splitTaroTree := outputCommitments[splitIndex]

	_, splitRootExclusionProof, err := splitRootTree.Proof(
		splitOut.Asset.TaroCommitmentKey(),
		splitOut.Asset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, err
	}

	splitParams := newParams(
		anchorTx, splitOut.Asset, int(splitIndex),
		splitOut.AnchorOutputInternalKey, splitTaroTree,
	)
	splitParams.RootOutputIndex = splitRootIndex
	splitParams.RootInternalKey = splitRootOut.AnchorOutputInternalKey
	splitParams.RootTaroTree = splitRootTree
	splitParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: splitRootIndex,
		InternalKey: splitRootOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *splitRootExclusionProof,
		},
	}}

	return splitParams, nil
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

	txHash := s.OutboundPkg.AnchorTx.TxHash()
	log.Infof("Outbound parcel with txid %v now pending (num_inputs=%d, "+
		"num_outputs=%d), delivering notification", txHash,
		len(s.OutboundPkg.Inputs), len(s.OutboundPkg.Outputs))

	s.Parcel.kit().respChan <- s.OutboundPkg
}
