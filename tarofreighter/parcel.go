package tarofreighter

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/keychain"
)

// enum to define each stage of an asset send
type SendState uint8

// Start with one state per function
// State name signals the state change of the send, within the state
const (
	SendStateInitializing SendState = iota

	SendStateCommitmentSelect

	SendStateValidatedInput

	SendStatePreparedSplit

	SendStatePreparedComplete

	SendStateSigned

	SendStateCommitmentsUpdated

	SendStateValidatedLocators

	SendStatePsbtFund

	SendStatePsbtSign

	SendStateLogCommit

	SendStateBroadcast

	SendStateWaitingConf
)

// AssetParcel...
type AssetParcel struct {
	// Dest...
	Dest *address.Taro

	// resp...
	respChan chan *PendingParcel

	// errChan...
	errChan chan error
}

// AssetInput...
type AssetInput struct {
	// PrevID...
	PrevID asset.PrevID

	// Amount...
	Amount btcutil.Amount
}

// AssetOutput...
type AssetOutput struct {
	AssetInput

	// NewBlob
	NewBlob proof.Blob

	// SplitCommitProof...
	SplitCommitProof *commitment.SplitCommitment
}

// PendingParcel...
type PendingParcel struct {
	// NewAnchorPoint...
	NewAnchorPoint wire.OutPoint

	// OldTaroRoot...
	OldTaroRoot []byte

	// NewTaroRoot...
	NewTaroRoot []byte

	// TransferTx...
	TransferTx *wire.MsgTx

	// AssetInputs...
	AssetInputs []AssetInput

	// AssetOutputs...
	AssetOutputs []AssetOutput

	// TotalFees...
	TotalFees btcutil.Amount
}

// sendPackage...
type sendPackage struct {
	// SendState...
	SendState SendState

	// SenderNewInternalKey...
	SenderNewInternalKey keychain.KeyDescriptor

	// SenderScriptKey...
	SenderScriptKey asset.ScriptKey

	// TODO(jhb): optional SpendLocators
	// TODO(jhb): map sender state key to PrevID?
	// TODO(jhb): map sender state key to PrevTaroTree?
	// Includes PrevScriptKey

	// InputAssetPrevID...
	InputAssetPrevID asset.PrevID

	// InputAsset...
	InputAsset *AnchoredCommitment

	// NeedsSplit...
	// signal if we need a split
	NeedsSplit bool

	// ReceiverAddr..
	ReceiverAddr *address.Taro

	// SendDelta...
	SendDelta *taroscript.SpendDelta

	// NewOutputCommitments...
	NewOutputCommitments taroscript.SpendCommitments

	// SendPkt
	//
	// TODO(jhb): Wrap the PSBT with extra data?
	SendPkt *psbt.Packet

	// TransferTx...
	TransferTx *wire.MsgTx

	// OutboundPkg...
	OutboundPkg *OutboundParcelDelta
}

// inputAnchorPkScript...
func (s *sendPackage) inputAnchorPkScript() ([]byte, []byte, error) {
	s.InputAsset.Asset.PrevWitnesses = []asset.Witness{{
		PrevID: &asset.ZeroPrevID,
	}}

	newCommitment, err := commitment.NewAssetCommitment(s.InputAsset.Asset)
	if err != nil {
		return nil, nil, err
	}

	newTaroCommitment, err := commitment.NewTaroCommitment(newCommitment)
	if err != nil {
		return nil, nil, err
	}
	taroScriptRoot := newTaroCommitment.TapscriptRoot(nil)

	anchorPubKey := txscript.ComputeTaprootOutputKey(
		s.InputAsset.InternalKey.PubKey, taroScriptRoot[:],
	)

	pkScript, err := taroscript.PayToTaprootScript(anchorPubKey)
	return pkScript, taroScriptRoot[:], err
}

// addAnchorPsbtInput....
func (s *sendPackage) addAnchorPsbtInput() error {
	anchorPkScript, merkleRoot, err := s.inputAnchorPkScript()
	if err != nil {
		return err
	}

	internalKey := s.InputAsset.InternalKey
	bip32Derivation := &psbt.Bip32Derivation{
		PubKey: internalKey.PubKey.SerializeCompressed(),
		// Error from signer: lnd/lnwallet/btcwallet/signer.go#L91
		Bip32Path: []uint32{
			keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
			// Testnet gang?
			s.ReceiverAddr.ChainParams.HDCoinType + hdkeychain.HardenedKeyStart,
			// must be hardened
			uint32(internalKey.Family) + uint32(hdkeychain.HardenedKeyStart),
			0,
			internalKey.Index,
		},
	}

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

	// Add a corresponding input to the unsigned TX to match the mock PSBT input.
	s.SendPkt.UnsignedTx.TxIn = append(
		s.SendPkt.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: s.InputAsset.AnchorPoint,
		},
	)

	return err
}

// spendProofs is a map of the script key of each party's assets to
// (incomplete) proof.
type spendProofs map[asset.SerializedKey]proof.Proof

// helper for proof creation
func (s *sendPackage) createProofs() (spendProofs, error) {
	isSplit := s.SendDelta.SplitCommitment != nil

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

	// param objects to build proofs
	senderParams := dummyParams()
	receiverParams := dummyParams()

	// look up taro commitments and output indexes
	senderStateKey := asset.AssetCommitmentKey(
		s.InputAsset.Asset.ID(),
		s.SenderScriptKey.PubKey,
		s.InputAsset.Asset.FamilyKey == nil,
	)
	receiverStateKey := s.ReceiverAddr.AssetCommitmentKey()

	senderTaroTree := s.NewOutputCommitments[senderStateKey]
	receiverTaroTree := s.NewOutputCommitments[receiverStateKey]
	senderIndex := s.SendDelta.Locators[senderStateKey].OutputIndex
	receiverIndex := s.SendDelta.Locators[receiverStateKey].OutputIndex

	// compute exclusion proofs
	// senderProof = exluding sender asset from receiver tree, vice versa
	var (
		senderExclusionProof   *commitment.Proof
		receiverExclusionProof *commitment.Proof
		err                    error
	)

	// NewAsset is root asset for sender, have to
	// look up receiver split asset
	if isSplit {
		senderParams.NewAsset = &s.SendDelta.NewAsset

		_, senderExclusionProof, err = receiverTaroTree.Proof(
			s.SendDelta.NewAsset.TaroCommitmentKey(),
			s.SendDelta.NewAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		receiverLocator := s.SendDelta.Locators[receiverStateKey]
		receiverAsset := s.SendDelta.SplitCommitment.
			SplitAssets[receiverLocator].Asset
		_, receiverExclusionProof, err = senderTaroTree.Proof(
			receiverAsset.TaroCommitmentKey(),
			receiverAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		receiverParams.NewAsset = &receiverAsset
		// needed for root asset inclusion proof
		receiverParams.RootOutputIndex = senderIndex
		receiverParams.RootInternalKey = s.SenderNewInternalKey.PubKey
		receiverParams.RootTaroTree = &senderTaroTree

		// NewAsset is for receiver, need to exclude sender input asset
	} else {
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

	// fill out rest of params
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

	// create and store proofs
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

// deliverResponse...
func (s *sendPackage) deliverResponse(respChan chan<- *PendingParcel) {
	oldRoot := s.InputAsset.Commitment.TapscriptRoot(nil)

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
						OutPoint: s.OutboundPkg.NewAnchorPoint,
						ID:       s.ReceiverAddr.ID(),
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
		TotalFees: 0,
	}
}
