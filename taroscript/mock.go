package taroscript

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/input"
)

type MockSigner struct {
	PrivKey *btcec.PrivateKey
}

func NewMockSigner(privKey *btcec.PrivateKey) *MockSigner {
	return &MockSigner{
		PrivKey: privKey,
	}
}

// Taken from lnd/lnwallet/btcwallet/signer:L344, SignOutputRaw
func (m *MockSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*schnorr.Signature, error) {

	witnessScript := signDesc.WitnessScript

	privKey := m.PrivKey
	var maybeTweakPrivKey *btcec.PrivateKey

	switch {
	case signDesc.SingleTweak != nil:
		maybeTweakPrivKey = input.TweakPrivKey(privKey,
			signDesc.SingleTweak)

	case signDesc.DoubleTweak != nil:
		maybeTweakPrivKey = input.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)

	default:
		maybeTweakPrivKey = privKey
	}

	privKey = maybeTweakPrivKey

	// In case of a taproot output any signature is always a Schnorr
	// signature, based on the new tapscript sighash algorithm.
	if !txscript.IsPayToTaproot(signDesc.Output.PkScript) {
		return nil, fmt.Errorf("mock signer: output script not taproot")
	}

	sigHashes := txscript.NewTxSigHashes(
		tx, signDesc.PrevOutputFetcher,
	)

	// Are we spending a script path or the key path? The API is
	// slightly different, so we need to account for that to get the
	// raw signature.
	var rawSig []byte
	var err error
	switch signDesc.SignMethod {
	case input.TaprootKeySpendBIP0086SignMethod,
		input.TaprootKeySpendSignMethod:

		// This function tweaks the private key using the tap
		// root key supplied as the tweak.
		rawSig, err = txscript.RawTxInTaprootSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			signDesc.TapTweak, signDesc.HashType,
			privKey,
		)
		if err != nil {
			return nil, err
		}

	case input.TaprootScriptSpendSignMethod:
		leaf := txscript.TapLeaf{
			LeafVersion: txscript.BaseLeafVersion,
			Script:      witnessScript,
		}
		rawSig, err = txscript.RawTxInTapscriptSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			leaf, signDesc.HashType, privKey,
		)
		if err != nil {
			return nil, err
		}
	}

	sig, err := schnorr.ParseSignature(rawSig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (m MockSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	fullSignDesc := input.SignDescriptor{
		KeyDesc:           signDesc.KeyDesc,
		SingleTweak:       signDesc.SingleTweak,
		DoubleTweak:       signDesc.DoubleTweak,
		TapTweak:          signDesc.TapTweak,
		WitnessScript:     signDesc.WitnessScript,
		SignMethod:        signDesc.SignMethod,
		Output:            signDesc.Output,
		HashType:          signDesc.HashType,
		SigHashes:         sigHashes,
		PrevOutputFetcher: prevOutFetcher,
		InputIndex:        signDesc.InputIndex,
	}

	sig, err := m.SignOutputRaw(tx, &fullSignDesc)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
