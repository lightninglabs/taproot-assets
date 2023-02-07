package tarofreighter

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// SendState is an enum that describes the current state of a pending outbound
// parcel (asset transfer).
type SendState uint8

const (
	// SendStateInitializing is that staring state of a transfer. In this
	// state, the initial context needed for a transfer is created.
	SendStateInitializing SendState = iota

	// SendStateCommitmentSelect is the state for performing input coin
	// selection to pick out which assets inputs should be spent.
	SendStateCommitmentSelect

	// SendStateValidatedInput validates the inputs to ensure that the set
	// of selected commitments can satisfy the transfer.
	SendStateValidatedInput

	// SendStatePreparedSplit prepares the splits (if needed) for a
	// transfer that will create a change output.
	SendStatePreparedSplit

	// SendStatePreparedComplete is the alternative to
	// SendStatePreparedSplit. We enter this state when a split isn't
	// required.
	SendStatePreparedComplete

	// SendStateSigned is used to generate the Taro level witness data for
	// any inputs being spent.
	SendStateSigned

	// SendStateCommitmentsUpdated is the state we enter to after we sign
	// each of the new Taro asset leaves. In this state, we'll construct
	// the final commitments that both sides will find in the chain.
	SendStateCommitmentsUpdated

	// SendStatePsbtFund is the state we enter after we have all the Taro
	// level witness data created. In this state, we'll ask the wallet to
	// fund a PSBT with enough fund for the transfer transaction at the
	// specified fee rate.
	SendStatePsbtFund

	// SendStatePsbtSign is the state we enter after the PSBT has been
	// funded. In this state, we'll ask the wallet to sign the PSBT and
	// then finalize to place the necessary signatures in the transaction.
	SendStatePsbtSign

	// SendStateLogCommit is the final in memory state. In this state,
	// we'll extract the signed transaction from the PSBT and log the
	// transfer information to disk. At this point, after a restart, the
	// transfer can be resumed.
	SendStateLogCommit

	// SendStateBroadcast broadcasts the transfer transaction to the
	// network, and imports the taproot output back into the wallet to
	// ensure it properly tracks the coins allocated to the anchor output.
	SendStateBroadcast

	// SendStateWaitingConf is the final terminal state. In this state,
	// we'll register for a confirmation request, and also handle the final
	// proof transfer.
	SendStateWaitingConf
)

// String returns a human readable version of SendState.
func (s SendState) String() string {
	switch s {
	case SendStateInitializing:
		return "SendStateInitializing"

	case SendStateCommitmentSelect:
		return "SendStateCommitmentSelect"

	case SendStateValidatedInput:
		return "SendStateValidatedInput"

	case SendStatePreparedSplit:
		return "SendStatePreparedSplit"

	case SendStatePreparedComplete:
		return "SendStatePreparedComplete"

	case SendStateSigned:
		return "SendStateSigned"

	case SendStateCommitmentsUpdated:
		return "SendStateCommitmentsUpdated"

	case SendStatePsbtFund:
		return "SendStatePsbtFund"

	case SendStatePsbtSign:
		return "SendStatePsbtSign"

	case SendStateLogCommit:
		return "SendStateLogCommit"

	case SendStateBroadcast:
		return "SendStateBroadcast"

	case SendStateWaitingConf:
		return "SendStateWaitingConf"

	default:
		return fmt.Sprintf("<unknown_state(%d)>", s)
	}
}

// AssetParcel is the main request to issue an asset transfer. This packages a
// destination address, and also response context.
type AssetParcel struct {
	// Dest is the address that should be used to satisfy the transfer.
	Dest *address.Taro

	// respChan is the channel a response will be sent over.
	respChan chan *PendingParcel

	// errChan is the channel the error will be sent over.
	errChan chan error
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

// PendingParcel is the response to an AssetParcel shipment request. This
// contains all the information of the pending transfer.
type PendingParcel struct {
	// OldTaroRoot is the Taro commitment root of the old anchor point.
	OldTaroRoot []byte

	// NewAnchorPoint is the new anchor point that commits to our new change assets.
	NewAnchorPoint wire.OutPoint

	// NewTaroRoot is the Taro commitment root of the new anchor point.
	NewTaroRoot []byte

	// TransferTx is the transaction that completed the transfer.
	TransferTx *wire.MsgTx

	// AssetInputs are the set if inputs to the transfer transfer
	// transaction on the Taro layer.
	AssetInputs []AssetInput

	// AssetOutputs is the set of newly produced outputs.
	AssetOutputs []AssetOutput

	// TotalFees is the amount of on chain fees that the transfer
	// transaction required.
	TotalFees btcutil.Amount
}

// sendPackage houses the information we need to complete a package transfer.
type sendPackage struct {
	// SendState is the current state state of this parcel.
	SendState SendState

	// SenderNewInternalKey is the new internal key for the sender. This is
	// where the change assets will be anchored at.
	SenderNewInternalKey keychain.KeyDescriptor

	// SenderScriptKey is the new script key of the sender. The input spent
	// will use this new script key.
	SenderScriptKey asset.ScriptKey

	// InputAssetPrevID is the input prev ID spent by the sender.
	InputAssetPrevID asset.PrevID

	// InputAsset contains the Taro and on chain information for the input
	// asset being spent.
	InputAsset *AnchoredCommitment

	// NeedsSplit is true if a change output is required during the
	// transfer.
	NeedsSplit bool

	// ReceiverAddr is the address of the receiver that kicked off the
	// transfer.
	ReceiverAddr *address.Taro

	// SendDelta contains the information needed to craft a final transfer
	// transaction.
	SendDelta *taroscript.SpendDelta

	// NewOutputCommitments is the set of new commitments that will be
	// anchored by each output on the transfer transaction.
	NewOutputCommitments taroscript.SpendCommitments

	// FundedPkt is the PSBT that was funded by the lnd internal wallet.
	// This will not be updated once the PSBT is signed and finalized in
	// order to keep the change output information around that is needed for
	// creating the exclusion proofs.
	FundedPkt *tarogarden.FundedPsbt

	// SendPkt is the PSBT that will complete the transfer. This will be
	// updated along the way from funded, signed to finalized.
	SendPkt *psbt.Packet

	// TransferTx is the final signed transfer transaction.
	TransferTx *wire.MsgTx

	// OutboundPkg is the on-disk level information that tracks the pending
	// transfer.
	OutboundPkg *OutboundParcelDelta

	// TargetFeeRate is the target fee rate for this send expressed in
	// sat/kw.
	TargetFeeRate chainfee.SatPerKWeight
}

// inputAnchorPkScript returns the top-level Taproot output script of the input
// anchor output as well as the Taro script root of the output (the Taproot
// tweak).
func (s *sendPackage) inputAnchorPkScript() ([]byte, []byte, error) {
	// If the input asset was received non-interactively, then the Taro tree
	// of the input anchor output was built with asset leaves that had empty
	// SplitCommitments. However, the SplitCommitment field was
	// populated when the transfer of the input asset was verified.
	// To recompute the correct output script, we need to build a Taro tree
	// from the input asset without any SplitCommitment.
	inputAssetCopy := s.InputAsset.Asset.Copy()
	inputAnchorCommitmentCopy, err := s.InputAsset.Commitment.Copy()
	if err != nil {
		return nil, nil, err
	}

	// Assets received via non-interactive split should have one witness,
	// with an empty PrevID and a SplitCommitment present.
	if inputAssetCopy.HasSplitCommitmentWitness() &&
		*inputAssetCopy.PrevWitnesses[0].PrevID == asset.ZeroPrevID {

		inputAssetCopy.PrevWitnesses[0].SplitCommitment = nil

		// Build the new Taro tree by first updating the asset
		// commitment tree with the new asset leaf, and then the
		// top-level Taro tree.
		inputCommitments := inputAnchorCommitmentCopy.Commitments()
		inputCommitmentKey := inputAssetCopy.TaroCommitmentKey()
		inputAssetTree := inputCommitments[inputCommitmentKey]
		err = inputAssetTree.Upsert(inputAssetCopy)
		if err != nil {
			return nil, nil, err
		}

		err = inputAnchorCommitmentCopy.Update(inputAssetTree, false)
		if err != nil {
			return nil, nil, err
		}
	}

	taroScriptRoot := inputAnchorCommitmentCopy.TapscriptRoot(nil)

	anchorPubKey := txscript.ComputeTaprootOutputKey(
		s.InputAsset.InternalKey.PubKey, taroScriptRoot[:],
	)

	pkScript, err := taroscript.PayToTaprootScript(anchorPubKey)
	return pkScript, taroScriptRoot[:], err
}

// addAnchorPsbtInput adds the input anchor information to the PSBT packet.
// This is called after the PSBT has been funded, but before signing.
func (s *sendPackage) addAnchorPsbtInput() error {
	// First, we'll need to fetch the input anchor pk script. This will be
	// used to create the prev out and also is the merkle root which is
	// needed for signing.
	anchorPkScript, merkleRoot, err := s.inputAnchorPkScript()
	if err != nil {
		return err
	}

	internalKey := s.InputAsset.InternalKey

	// Given the above information, we'll now construct the BIP 32
	// derivation information the wallet needs for signing.
	bip32Derivation := &psbt.Bip32Derivation{
		PubKey: internalKey.PubKey.SerializeCompressed(),
		Bip32Path: []uint32{
			keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
			s.ReceiverAddr.ChainParams.HDCoinType + hdkeychain.HardenedKeyStart,
			uint32(internalKey.Family) + uint32(hdkeychain.HardenedKeyStart),
			0,
			internalKey.Index,
		},
	}

	// With the BIP 32 information completed, we'll now add the information
	// as a partial input and also add the input to the unsigned
	// transaction.
	s.SendPkt.Inputs = append(s.SendPkt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    int64(s.InputAsset.AnchorOutputValue),
			PkScript: anchorPkScript,
		},
		SighashType:       txscript.SigHashDefault,
		Bip32Derivation:   []*psbt.Bip32Derivation{bip32Derivation},
		TaprootMerkleRoot: merkleRoot,
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          bip32Derivation.PubKey[1:],
			MasterKeyFingerprint: bip32Derivation.MasterKeyFingerprint,
			Bip32Path:            bip32Derivation.Bip32Path,
		}},
	})
	s.SendPkt.UnsignedTx.TxIn = append(
		s.SendPkt.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: s.InputAsset.AnchorPoint,
		},
	)

	// Now that we've added an extra input, we'll want to re-calculate the
	// total weight of the transaction, so we can ensure we're paying
	// enough in fees.
	var (
		weightEstimator     input.TxWeightEstimator
		inputAmt, outputAmt int64
	)
	for _, pIn := range s.SendPkt.Inputs {
		inputAmt += pIn.WitnessUtxo.Value

		inputPkScript := pIn.WitnessUtxo.PkScript
		switch {
		case txscript.IsPayToWitnessPubKeyHash(inputPkScript):
			weightEstimator.AddP2WKHInput()

		case txscript.IsPayToScriptHash(inputPkScript):
			weightEstimator.AddNestedP2WKHInput()

		case txscript.IsPayToTaproot(inputPkScript):
			weightEstimator.AddTaprootKeySpendInput(
				txscript.SigHashDefault,
			)
		default:
			return fmt.Errorf("unknown pkScript: %x",
				inputPkScript)
		}
	}
	for _, txOut := range s.SendPkt.UnsignedTx.TxOut {
		outputAmt += txOut.Value

		addrType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, s.ReceiverAddr.ChainParams.Params,
		)
		if err != nil {
			return err
		}

		switch addrType {
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHOutput()

		case txscript.WitnessV0ScriptHashTy:
			weightEstimator.AddP2WSHOutput()

		case txscript.WitnessV1TaprootTy:
			weightEstimator.AddP2TROutput()
		default:
			return fmt.Errorf("unknwon pkscript: %x",
				txOut.PkScript)
		}
	}

	// With this, we can now calculate the total fee we need to pay. We'll
	// also make sure to round up the required fee to the floor.
	totalWeight := int64(weightEstimator.Weight())
	requiredFee := s.TargetFeeRate.FeeForWeight(totalWeight)

	// Given the current fee (which doesn't account for our input) and the
	// total fee we want to pay, we'll adjust the wallet's change output
	// accordingly.
	//
	// Earlier in adjustFundedPsbt we set wallet's change output to be the
	// very last output in the transaction.
	lastIdx := len(s.SendPkt.UnsignedTx.TxOut) - 1
	currentFee := inputAmt - outputAmt
	feeDelta := int64(requiredFee) - currentFee
	s.SendPkt.UnsignedTx.TxOut[lastIdx].Value -= feeDelta

	log.Infof("Adjusting send pkt by delta of %v from %v sats to %v sats",
		feeDelta, int64(currentFee), int64(requiredFee))

	return nil
}

// spendProofs is a map of the script key of each party's assets to
// (incomplete) proof.
type spendProofs map[asset.SerializedKey]proof.Proof

// createProofs creates the new set of proofs for the sender and the receiver.
// This is the final state transition that will be added to the proofs of both
// the sender and receiver. The proofs returned will have all the Taro level
// proof information, but contains dummy data for
func (s *sendPackage) createProofs() (spendProofs, error) {
	// dummyParams is used to create a set of dummy params for the final
	// state transition.
	dummyParams := func() proof.TransitionParams {
		return proof.TransitionParams{
			BaseProofParams: proof.BaseProofParams{
				Block: &wire.MsgBlock{
					Transactions: []*wire.MsgTx{
						s.TransferTx,
					},
				},
				Tx:      s.TransferTx,
				TxIndex: 0,
			},
		}
	}

	isSplit := s.SendDelta.SplitCommitment != nil

	// First, we'll start by creating the dummy params with dummy chain
	// level proofs.
	senderParams := dummyParams()
	receiverParams := dummyParams()

	// Next, we'll re-derive the state keys for the sender and receiver so
	// we can look up their commitments.
	senderStateKey := asset.AssetCommitmentKey(
		s.InputAsset.Asset.ID(), s.SenderScriptKey.PubKey,
		s.InputAsset.Asset.GroupKey == nil,
	)
	receiverStateKey := s.ReceiverAddr.AssetCommitmentKey()

	// With the state key, we can fetch the new Taro trees for the
	// sender+receiver and also the outputs indexes of each tree
	// commitment.
	senderTaroTree := s.NewOutputCommitments[senderStateKey]
	senderIndex := s.SendDelta.Locators[senderStateKey].OutputIndex

	receiverTaroTree := s.NewOutputCommitments[receiverStateKey]
	receiverIndex := s.SendDelta.Locators[receiverStateKey].OutputIndex

	// Next we'll compute the exclusion proofs for the sender and receiver.
	// This proves that the asset committed to isn't contained in any of
	// the other outputs in the transfer transaction.
	var (
		senderExclusionProof   *commitment.Proof
		receiverExclusionProof *commitment.Proof
		err                    error
	)

	// If we require a split, then we'll need to prove exclusion for both
	// parties.
	if isSplit {
		senderParams.NewAsset = &s.SendDelta.NewAsset

		// First, we'll compute an exclusion proof that show that the
		// sender's asset isn't committed in the receiver's' tree.
		_, senderExclusionProof, err = receiverTaroTree.Proof(
			s.SendDelta.NewAsset.TaroCommitmentKey(),
			s.SendDelta.NewAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// Next, we'll do the opposite for the receiver.
		receiverLocator := s.SendDelta.Locators[receiverStateKey]
		receiverAsset := s.SendDelta.SplitCommitment.SplitAssets[receiverLocator].Asset
		_, receiverExclusionProof, err = senderTaroTree.Proof(
			receiverAsset.TaroCommitmentKey(),
			receiverAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// With the proofs computed, we'll now place the receiver's new
		// asset in their proof, and also set the information that lets
		// us prove that their split is valid.
		receiverParams.NewAsset = &receiverAsset
		receiverParams.RootOutputIndex = senderIndex
		receiverParams.RootInternalKey = s.SenderNewInternalKey.PubKey
		receiverParams.RootTaroTree = &senderTaroTree
	} else {
		// Otherwise, if there's no split, then we can just compute a
		// simpler exclusion proof for the sender and receiver.
		//
		// TODO(jhb): NewAsset for sender proof can be empty?
		receiverParams.NewAsset = &s.SendDelta.NewAsset

		_, senderExclusionProof, err = receiverTaroTree.Proof(
			s.InputAsset.Asset.TaroCommitmentKey(),
			s.InputAsset.Asset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		_, receiverExclusionProof, err = senderTaroTree.Proof(
			s.SendDelta.NewAsset.TaroCommitmentKey(),
			s.SendDelta.NewAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}
	}

	// In a final phase, we'll fill out the remaining parameters for the
	// sender and receiver to generate a proof of this new state
	// transition.
	senderParams.OutputIndex = int(senderIndex)
	senderParams.InternalKey = s.SenderNewInternalKey.PubKey
	senderParams.TaroRoot = &senderTaroTree
	senderParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: receiverIndex,
		InternalKey: &s.ReceiverAddr.InternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *senderExclusionProof,
		},
	}}

	receiverParams.OutputIndex = int(receiverIndex)
	receiverParams.InternalKey = &s.ReceiverAddr.InternalKey
	receiverParams.TaroRoot = &receiverTaroTree
	receiverParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: senderIndex,
		InternalKey: s.SenderNewInternalKey.PubKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof: *receiverExclusionProof,
		},
	}}

	// We also need to account for any P2TR change outputs.
	if s.FundedPkt.ChangeOutputIndex > -1 {
		isAnchor := func(idx uint32) bool {
			// We exclude both sender and receiver
			// commitments because those get their own,
			// individually created exclusion proofs.
			return idx == senderIndex || idx == receiverIndex
		}

		err := proof.AddExclusionProofs(
			&senderParams.BaseProofParams, s.FundedPkt.Pkt,
			isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion proof "+
				"for change output: %w", err)
		}

		err = proof.AddExclusionProofs(
			&receiverParams.BaseProofParams, s.FundedPkt.Pkt,
			isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion proof "+
				"for change output: %w", err)
		}
	}

	senderProof, err := proof.CreateTransitionProof(
		s.InputAsset.AnchorPoint, &senderParams,
	)
	if err != nil {
		return nil, err
	}
	receiverProof, err := proof.CreateTransitionProof(
		s.InputAsset.AnchorPoint, &receiverParams,
	)
	if err != nil {
		return nil, err
	}

	return spendProofs{
		asset.ToSerialized(s.SenderScriptKey.PubKey):  *senderProof,
		asset.ToSerialized(&s.ReceiverAddr.ScriptKey): *receiverProof,
	}, nil
}

// deliverResponse delivers a response for the parcel back to the receiver over
// the specified response channel.
func (s *sendPackage) deliverResponse(respChan chan<- *PendingParcel) {
	oldRoot := s.InputAsset.Commitment.TapscriptRoot(nil)

	log.Infof("Outbound parcel now pending for %x:%x, delivering "+
		"notification", s.ReceiverAddr.ID(),
		s.ReceiverAddr.ScriptKey.SerializeCompressed())

	// Get the output index of the receiver from the spend locators.
	receiverStateKey := s.ReceiverAddr.AssetCommitmentKey()
	receiverIndex := s.SendDelta.Locators[receiverStateKey].OutputIndex

	respChan <- &PendingParcel{
		NewAnchorPoint: s.OutboundPkg.NewAnchorPoint,
		TransferTx:     s.OutboundPkg.AnchorTx,
		OldTaroRoot:    oldRoot[:],
		NewTaroRoot:    s.OutboundPkg.TaroRoot,
		AssetInputs: []AssetInput{
			{
				PrevID: s.InputAssetPrevID,
				Amount: btcutil.Amount(
					s.InputAsset.Asset.Amount,
				),
			},
		},
		AssetOutputs: []AssetOutput{
			{
				AssetInput: AssetInput{
					PrevID: asset.PrevID{
						OutPoint: s.OutboundPkg.NewAnchorPoint,
						ID:       s.ReceiverAddr.ID(),
						ScriptKey: asset.ToSerialized(
							s.OutboundPkg.AssetSpendDeltas[0].NewScriptKey.PubKey,
						),
					},
					Amount: btcutil.Amount(
						s.OutboundPkg.AssetSpendDeltas[0].NewAmt,
					),
				},
			},
			{
				AssetInput: AssetInput{
					PrevID: asset.PrevID{
						OutPoint: wire.OutPoint{
							Hash:  s.OutboundPkg.NewAnchorPoint.Hash,
							Index: receiverIndex,
						},
						ID: s.ReceiverAddr.ID(),
						ScriptKey: asset.ToSerialized(
							&s.ReceiverAddr.ScriptKey,
						),
					},
					Amount: btcutil.Amount(
						s.ReceiverAddr.Amount,
					),
				},
			},
		},
		TotalFees: btcutil.Amount(s.OutboundPkg.ChainFees),
	}
}
