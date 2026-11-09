package tapsend

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/keychain"
)

// OwnedAnchorInput is an input of an anchor transaction that spends an anchor
// output the wallet can sign for.
type OwnedAnchorInput struct {
	// Index is the index of the input in the anchor transaction.
	Index int

	// InternalKey is the internal key of the spent anchor output.
	InternalKey keychain.KeyDescriptor

	// MerkleRoot is the Taproot merkle root of the spent anchor output.
	MerkleRoot []byte

	// Value is the value of the spent anchor output.
	Value btcutil.Amount
}

// PsbtSigner signs the inputs of a PSBT it has derivation info for.
type PsbtSigner func(context.Context, *psbt.Packet) (*psbt.Packet, error)

// UnsignedAnchorInputs returns the indexes of the anchor transaction inputs
// that spend an anchor of the given packets and have no final witness. It
// returns an error if any other input has no final witness.
func UnsignedAnchorInputs(pkt *psbt.Packet,
	vPackets []*tappsbt.VPacket) ([]int, error) {

	anchors := make(map[wire.OutPoint]struct{})
	for _, vPkt := range vPackets {
		for _, vIn := range vPkt.Inputs {
			anchors[vIn.PrevID.OutPoint] = struct{}{}
		}
	}

	var unsigned []int
	for idx, txIn := range pkt.UnsignedTx.TxIn {
		pIn := pkt.Inputs[idx]
		if len(pIn.FinalScriptWitness) > 0 ||
			len(pIn.FinalScriptSig) > 0 {

			continue
		}

		if _, ok := anchors[txIn.PreviousOutPoint]; !ok {
			return nil, fmt.Errorf("input %d (%v) has no final "+
				"witness and is not an anchor input of this "+
				"transfer", idx, txIn.PreviousOutPoint)
		}

		unsigned = append(unsigned, idx)
	}

	return unsigned, nil
}

// SignAnchorInputs signs and finalizes the given anchor inputs. The signer
// only sees a copy of the packet in which these inputs are the only ones that
// carry signing information, so it can't sign any other input.
func SignAnchorInputs(ctx context.Context, pkt *psbt.Packet,
	anchors []OwnedAnchorInput, coinType uint32, signer PsbtSigner) error {

	if len(anchors) == 0 {
		return nil
	}

	signPkt := &psbt.Packet{
		UnsignedTx: pkt.UnsignedTx.Copy(),
		Inputs:     make([]psbt.PInput, len(pkt.Inputs)),
		Outputs:    make([]psbt.POutput, len(pkt.Outputs)),
	}
	for idx := range pkt.Inputs {
		signPkt.Inputs[idx] = psbt.PInput{
			WitnessUtxo:    pkt.Inputs[idx].WitnessUtxo,
			NonWitnessUtxo: pkt.Inputs[idx].NonWitnessUtxo,
		}
	}

	for _, anchor := range anchors {
		if anchor.Index < 0 || anchor.Index >= len(pkt.Inputs) {
			return fmt.Errorf("anchor input %d out of range",
				anchor.Index)
		}

		err := matchAnchorUtxo(pkt.Inputs[anchor.Index], anchor)
		if err != nil {
			return fmt.Errorf("anchor input %d: %w", anchor.Index,
				err)
		}

		derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
			anchor.InternalKey, coinType,
		)

		in := &signPkt.Inputs[anchor.Index]
		in.SighashType = txscript.SigHashDefault
		in.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
		in.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trDerivation,
		}
		in.TaprootInternalKey = schnorr.SerializePubKey(
			anchor.InternalKey.PubKey,
		)
		in.TaprootMerkleRoot = anchor.MerkleRoot
	}

	signed, err := signer(ctx, signPkt)
	if err != nil {
		return fmt.Errorf("error signing anchor inputs: %w", err)
	}
	if len(signed.Inputs) != len(pkt.Inputs) {
		return fmt.Errorf("signed packet has %d inputs, expected %d",
			len(signed.Inputs), len(pkt.Inputs))
	}

	for _, anchor := range anchors {
		sig := signed.Inputs[anchor.Index].TaprootKeySpendSig
		if len(sig) != schnorr.SignatureSize {
			return fmt.Errorf("wallet did not sign anchor input %d",
				anchor.Index)
		}

		in := &pkt.Inputs[anchor.Index]
		in.TaprootKeySpendSig = sig
		in.SighashType = txscript.SigHashDefault
		if err := psbt.Finalize(pkt, anchor.Index); err != nil {
			return fmt.Errorf("error finalizing anchor input %d: "+
				"%w", anchor.Index, err)
		}
	}

	return nil
}

// matchAnchorUtxo makes sure the UTXO of the input is the given anchor output.
func matchAnchorUtxo(in psbt.PInput, anchor OwnedAnchorInput) error {
	if in.WitnessUtxo == nil {
		return fmt.Errorf("witness UTXO missing")
	}

	outputKey := txscript.ComputeTaprootOutputKey(
		anchor.InternalKey.PubKey, anchor.MerkleRoot,
	)
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		return err
	}

	if in.WitnessUtxo.Value != int64(anchor.Value) ||
		!bytes.Equal(in.WitnessUtxo.PkScript, pkScript) {

		return fmt.Errorf("witness UTXO does not match the anchor " +
			"output")
	}

	return nil
}
