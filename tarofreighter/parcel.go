package tarofreighter

import (
	"github.com/btcsuite/btcd/btcec/v2"
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
// TODO(jhb): add state transition path for modifying locators
// State name signals the state change of the send, within the state
const (
	SendStateInitializing SendState = iota

	// TODO(jhb): Preceding states for input lookup given address input

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

	// TODO(jhb): Following states for finalization and broadcast
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

	// SenderScriptKeyDesc...
	SenderScriptKeyDesc keychain.KeyDescriptor

	// SenderScriptKey...
	SenderScriptKey *btcec.PublicKey

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
func (s *sendPackage) inputAnchorPkScript() ([]byte, error) {
	taroScriptRoot := s.InputAsset.Commitment.TapscriptRoot(nil)

	anchorPubKey := txscript.ComputeTaprootOutputKey(
		s.InputAsset.InternalKey.PubKey, taroScriptRoot[:],
	)

	return taroscript.PayToTaprootScript(anchorPubKey)
}

// addAnchorPsbtInput....
func (s *sendPackage) addAnchorPsbtInput() error {
	anchorPkScript, err := s.inputAnchorPkScript()
	if err != nil {
		return err
	}

	internalKey := s.InputAsset.InternalKey
	bip32Derivation := &psbt.Bip32Derivation{
		PubKey: internalKey.PubKey.SerializeCompressed(),
		Bip32Path: []uint32{
			keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
			keychain.CoinTypeBitcoin + hdkeychain.HardenedKeyStart,
			uint32(internalKey.Family),
			0,
			uint32(internalKey.Index + hdkeychain.HardenedKeyStart),
		},
	}

	s.SendPkt.Inputs = append(s.SendPkt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    int64(s.InputAsset.AnchorOutputValue),
			PkScript: anchorPkScript,
		},
		SighashType:     txscript.SigHashDefault,
		Bip32Derivation: []*psbt.Bip32Derivation{bip32Derivation},
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          bip32Derivation.PubKey[1:],
			MasterKeyFingerprint: bip32Derivation.MasterKeyFingerprint,
			Bip32Path:            bip32Derivation.Bip32Path,
		}},
	})

	return err

}
