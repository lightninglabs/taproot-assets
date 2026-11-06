package tapsend_test

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

const (
	anchorInputIdx = 1
	anchorValue    = 1000
)

// anchorSignFixture is an anchor transaction whose first input belongs to the
// caller and whose second input spends an anchor owned by the wallet.
type anchorSignFixture struct {
	pkt     *psbt.Packet
	vPkt    *tappsbt.VPacket
	anchor  tapsend.OwnedAnchorInput
	privKey *btcec.PrivateKey
}

func newAnchorSignFixture(t *testing.T) *anchorSignFixture {
	privKey := test.RandPrivKey()
	anchor := tapsend.OwnedAnchorInput{
		Index: anchorInputIdx,
		InternalKey: keychain.KeyDescriptor{
			PubKey: privKey.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Family: asset.TaprootAssetsKeyFamily,
				Index:  7,
			},
		},
		MerkleRoot: test.RandBytes(32),
		Value:      anchorValue,
	}
	anchorPkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(
			privKey.PubKey(), anchor.MerkleRoot,
		),
	)
	require.NoError(t, err)

	anchorOp := test.RandOp(t)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: test.RandHash(),
	}, nil, nil))
	tx.AddTxIn(wire.NewTxIn(&anchorOp, nil, nil))
	tx.AddTxOut(wire.NewTxOut(50_000, anchorPkScript))

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	p2wpkh := append([]byte{0x00, 0x14}, test.RandBytes(20)...)
	pkt.Inputs[0] = psbt.PInput{
		WitnessUtxo:        wire.NewTxOut(60_000, p2wpkh),
		FinalScriptWitness: []byte{0x01, 0x01, 0x01},
		Bip32Derivation: []*psbt.Bip32Derivation{{
			PubKey: test.RandPubKey(t).SerializeCompressed(),
		}},
		Unknowns: []*psbt.Unknown{{
			Key: []byte{0xff}, Value: []byte{0x01},
		}},
	}
	pkt.Inputs[anchorInputIdx] = psbt.PInput{
		WitnessUtxo: wire.NewTxOut(anchorValue, anchorPkScript),
	}

	vPkt := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{OutPoint: anchorOp},
		}},
	}

	return &anchorSignFixture{
		pkt:     pkt,
		vPkt:    vPkt,
		anchor:  anchor,
		privKey: privKey,
	}
}

func prevOutFetcher(pkt *psbt.Packet) *txscript.MultiPrevOutFetcher {
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for idx, txIn := range pkt.UnsignedTx.TxIn {
		prevOuts[txIn.PreviousOutPoint] = pkt.Inputs[idx].WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevOuts)
}

// signer returns a PSBT signer that signs the anchor input with the
// fixture's key and asserts that no other input carries signing information.
func (f *anchorSignFixture) signer(t *testing.T) tapsend.PsbtSigner {
	return func(_ context.Context, p *psbt.Packet) (*psbt.Packet, error) {
		callerIn := p.Inputs[0]
		require.Empty(t, callerIn.Bip32Derivation)
		require.Empty(t, callerIn.TaprootBip32Derivation)
		require.Empty(t, callerIn.Unknowns)
		require.NotNil(t, callerIn.WitnessUtxo)

		anchorIn := p.Inputs[anchorInputIdx]
		require.Len(t, anchorIn.Bip32Derivation, 1)
		require.Len(t, anchorIn.TaprootBip32Derivation, 1)
		require.Equal(
			t, f.anchor.MerkleRoot, anchorIn.TaprootMerkleRoot,
		)

		sigHashes := txscript.NewTxSigHashes(
			p.UnsignedTx, prevOutFetcher(p),
		)
		sig, err := txscript.RawTxInTaprootSignature(
			p.UnsignedTx, sigHashes, anchorInputIdx, anchorValue,
			anchorIn.WitnessUtxo.PkScript,
			anchorIn.TaprootMerkleRoot, txscript.SigHashDefault,
			f.privKey,
		)
		require.NoError(t, err)

		p.Inputs[anchorInputIdx].TaprootKeySpendSig = sig

		return p, nil
	}
}

// TestUnsignedAnchorInputs checks which inputs are selected for signing.
func TestUnsignedAnchorInputs(t *testing.T) {
	t.Parallel()

	f := newAnchorSignFixture(t)
	vPkts := []*tappsbt.VPacket{f.vPkt}

	unsigned, err := tapsend.UnsignedAnchorInputs(f.pkt, vPkts)
	require.NoError(t, err)
	require.Equal(t, []int{anchorInputIdx}, unsigned)

	f.pkt.Inputs[anchorInputIdx].FinalScriptWitness = []byte{0x00}
	unsigned, err = tapsend.UnsignedAnchorInputs(f.pkt, vPkts)
	require.NoError(t, err)
	require.Empty(t, unsigned)

	f.pkt.Inputs[0].FinalScriptWitness = nil
	_, err = tapsend.UnsignedAnchorInputs(f.pkt, vPkts)
	require.ErrorContains(t, err, "input 0")
}

// TestSignAnchorInputs makes sure the anchor input is signed with a valid
// witness and that the signer only sees the anchor input's signing data.
func TestSignAnchorInputs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("valid", func(t *testing.T) {
		f := newAnchorSignFixture(t)
		callerIn := f.pkt.Inputs[0]

		err := tapsend.SignAnchorInputs(
			ctx, f.pkt, []tapsend.OwnedAnchorInput{f.anchor}, 0,
			f.signer(t),
		)
		require.NoError(t, err)
		require.Equal(t, callerIn, f.pkt.Inputs[0])

		finalTx, err := psbt.Extract(f.pkt)
		require.NoError(t, err)

		fetcher := prevOutFetcher(f.pkt)
		vm, err := txscript.NewEngine(
			f.pkt.Inputs[anchorInputIdx].WitnessUtxo.PkScript,
			finalTx, anchorInputIdx, txscript.StandardVerifyFlags,
			nil, txscript.NewTxSigHashes(finalTx, fetcher),
			anchorValue, fetcher,
		)
		require.NoError(t, err)
		require.NoError(t, vm.Execute())
	})

	t.Run("utxo mismatch", func(t *testing.T) {
		f := newAnchorSignFixture(t)
		f.pkt.Inputs[anchorInputIdx].WitnessUtxo.Value++

		err := tapsend.SignAnchorInputs(
			ctx, f.pkt, []tapsend.OwnedAnchorInput{f.anchor}, 0,
			f.signer(t),
		)
		require.ErrorContains(t, err, "does not match")
	})

	t.Run("merkle root mismatch", func(t *testing.T) {
		f := newAnchorSignFixture(t)
		f.anchor.MerkleRoot = test.RandBytes(32)

		err := tapsend.SignAnchorInputs(
			ctx, f.pkt, []tapsend.OwnedAnchorInput{f.anchor}, 0,
			f.signer(t),
		)
		require.ErrorContains(t, err, "does not match")
	})

	t.Run("not signed", func(t *testing.T) {
		f := newAnchorSignFixture(t)
		noSig := func(_ context.Context,
			p *psbt.Packet) (*psbt.Packet, error) {

			return p, nil
		}

		err := tapsend.SignAnchorInputs(
			ctx, f.pkt, []tapsend.OwnedAnchorInput{f.anchor}, 0,
			noSig,
		)
		require.ErrorContains(t, err, "did not sign anchor input 1")

		anchorIn := f.pkt.Inputs[anchorInputIdx]
		require.Empty(t, anchorIn.FinalScriptWitness)
	})

	t.Run("signer error", func(t *testing.T) {
		f := newAnchorSignFixture(t)
		errSign := errors.New("signer down")
		failing := func(context.Context, *psbt.Packet) (*psbt.Packet,
			error) {

			return nil, errSign
		}

		err := tapsend.SignAnchorInputs(
			ctx, f.pkt, []tapsend.OwnedAnchorInput{f.anchor}, 0,
			failing,
		)
		require.ErrorIs(t, err, errSign)
	})
}
