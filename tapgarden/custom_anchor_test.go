package tapgarden

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/stretchr/testify/require"
)

func testCustomAnchorPacket(t *testing.T) *psbt.Packet {
	t.Helper()

	_, pub := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	pkScript, err := txscript.PayToTaprootScript(pub)
	require.NoError(t, err)
	var prevHash chainhash.Hash
	prevHash[0] = 1
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: prevHash, Index: 1,
	}})
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})
	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	pkt.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 2_000, PkScript: pkScript,
	}
	pkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(pub)
	pkt.Unknowns = []*psbt.Unknown{{Key: []byte{0x50}, Value: []byte("x")}}

	return pkt
}

func TestCustomGenesisPsbtValidation(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	funded, err := customGenesisPsbt(
		address.TestNet3Tap, nil, pkt, 0, -1, noneUint32(),
	)
	require.NoError(t, err)
	require.True(t, isCustomAnchorPsbt(funded.Pkt))
	require.True(t, funded.GenesisOutpoint().IsSome())

	bad := testCustomAnchorPacket(t)
	bad.Inputs = nil
	_, err = customGenesisPsbt(
		address.TestNet3Tap, nil, bad, 0, -1, noneUint32(),
	)
	require.ErrorContains(t, err, "input maps")

	underfunded := testCustomAnchorPacket(t)
	underfunded.Inputs[0].WitnessUtxo.Value = 500
	_, err = customGenesisPsbt(
		address.TestNet3Tap, nil, underfunded, 0, -1, noneUint32(),
	)
	require.ErrorContains(t, err, "outputs exceed")

	dust := testCustomAnchorPacket(t)
	dust.UnsignedTx.TxOut[0].Value = 1
	dust.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_RETURN}
	_, err = customGenesisPsbt(
		address.TestNet3Tap, nil, dust, 0, -1, noneUint32(),
	)
	require.ErrorContains(t, err, "anchor output is dust")

	for _, tapTree := range [][]byte{{}, {0x00}} {
		anchorTapTree := testCustomAnchorPacket(t)
		anchorTapTree.Outputs[0].TaprootTapTree = tapTree
		_, err = customGenesisPsbt(
			address.TestNet3Tap, nil, anchorTapTree, 0, -1,
			noneUint32(),
		)
		require.ErrorContains(t, err, "must not specify a PSBT tap tree")
	}

	// Every non-anchor P2TR output needs enough metadata to construct an
	// exclusion proof after the mint confirms.
	for _, testCase := range []struct {
		name        string
		output      psbt.POutput
		errContains string
	}{
		{
			name:        "missing internal key",
			errContains: "output 1 is a P2TR output but is missing",
		},
		{
			name: "invalid internal key",
			output: psbt.POutput{
				TaprootInternalKey: bytes.Repeat([]byte{0xff}, 32),
			},
			errContains: "internal key is invalid",
		},
		{
			name: "metadata mismatch",
			output: psbt.POutput{
				TaprootInternalKey: fn.CopySlice(
					testCustomAnchorPacket(t).Outputs[0].
						TaprootInternalKey,
				),
			},
			errContains: "metadata does not match",
		},
		{
			name: "malformed tap tree",
			output: psbt.POutput{
				TaprootInternalKey: fn.CopySlice(
					testCustomAnchorPacket(t).Outputs[0].
						TaprootInternalKey,
				),
				TaprootTapTree: []byte{0x00},
			},
			errContains: "invalid PSBT tap tree",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			invalid := testCustomAnchorPacket(t)
			invalid.UnsignedTx.AddTxOut(&wire.TxOut{
				Value: 1_000,
				PkScript: fn.CopySlice(
					invalid.UnsignedTx.TxOut[0].PkScript,
				),
			})
			invalid.Outputs = append(invalid.Outputs, testCase.output)
			_, err := customGenesisPsbt(
				address.TestNet3Tap, nil, invalid, 0, -1,
				noneUint32(),
			)
			require.ErrorContains(t, err, testCase.errContains)
		})
	}

	validMetadata := testCustomAnchorPacket(t)
	validInternalKey, err := schnorr.ParsePubKey(
		validMetadata.Outputs[0].TaprootInternalKey,
	)
	require.NoError(t, err)
	validOutputKey := txscript.ComputeTaprootKeyNoScript(validInternalKey)
	validOutputScript, err := txscript.PayToTaprootScript(validOutputKey)
	require.NoError(t, err)
	validMetadata.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: validOutputScript,
	})
	validMetadata.Outputs = append(validMetadata.Outputs, psbt.POutput{
		TaprootInternalKey: fn.CopySlice(
			validMetadata.Outputs[0].TaprootInternalKey,
		),
	})
	_, err = customGenesisPsbt(
		address.TestNet3Tap, nil, validMetadata, 0, -1, noneUint32(),
	)
	require.NoError(t, err)
}

func TestMergeSignedCustomPsbt(t *testing.T) {
	stored := testCustomAnchorPacket(t)
	markCustomAnchorPsbt(stored)
	signed := clonePsbt(t, stored)
	signed.Inputs[0].FinalScriptSig = []byte{}
	signed.Inputs[0].FinalScriptWitness = []byte{1, 0}
	signed.Inputs[0].TaprootInternalKey = nil

	merged, err := mergeSignedCustomPsbt(stored, signed)
	require.NoError(t, err)
	require.NotNil(t, merged.Inputs[0].FinalScriptSig)
	require.NotEmpty(t, merged.Inputs[0].FinalScriptWitness)
	require.Equal(t, stored.Inputs[0].WitnessUtxo,
		merged.Inputs[0].WitnessUtxo)

	mutated := clonePsbt(t, signed)
	mutated.Inputs[0].WitnessUtxo.Value++
	_, err = mergeSignedCustomPsbt(stored, mutated)
	require.ErrorContains(t, err, "changes input UTXO")
	require.Nil(t, stored.Inputs[0].FinalScriptSig)
}

func TestFundedMintAnchorPsbtCopyPreservesMetadata(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	pkt.Outputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x51}, Value: []byte("output"),
	}}
	pkt.Inputs[0].SighashType = txscript.SigHashSingle
	original := &FundedMintAnchorPsbt{FundedPsbt: fundedPsbt(pkt)}

	copyPkt := original.Copy().Pkt
	require.Equal(t, pkt.Unknowns, copyPkt.Unknowns)
	require.Equal(t, pkt.Outputs, copyPkt.Outputs)
	require.Equal(t, pkt.Inputs, copyPkt.Inputs)
	copyPkt.Unknowns[0].Value[0] ^= 1
	require.NotEqual(t, pkt.Unknowns, copyPkt.Unknowns)
}

func TestCustomGenesisPsbtSupplyPreCommitment(t *testing.T) {
	seedling := RandGroupAnchorSeedling(t, "supply-anchor", true)
	batch := &MintingBatch{
		Seedlings: map[string]*Seedling{
			seedling.AssetName: &seedling,
		},
		SupplyCommitments: true,
	}

	pkt := testCustomAnchorPacket(t)
	delegationKey, err := seedling.DelegationKey.UnwrapOrErr(
		errors.New("delegation key missing"),
	)
	require.NoError(t, err)
	preCommitOut, err := PreCommitTxOut(*delegationKey.PubKey)
	require.NoError(t, err)
	pkt.UnsignedTx.AddTxOut(&preCommitOut)
	pkt.Outputs = append(pkt.Outputs, psbt.POutput{})

	_, err = customGenesisPsbt(
		address.TestNet3Tap, batch, clonePsbt(t, pkt), 0, -1,
		noneUint32(),
	)
	require.ErrorContains(t, err, "requires a pre-commitment output index")

	wrong := clonePsbt(t, pkt)
	wrong.UnsignedTx.TxOut[1].PkScript[0] ^= 1
	_, err = customGenesisPsbt(
		address.TestNet3Tap, batch, wrong, 0, -1, fn.Some(uint32(1)),
	)
	require.ErrorContains(t, err, "doesn't match the batch delegation key")

	funded, err := customGenesisPsbt(
		address.TestNet3Tap, batch, clonePsbt(t, pkt), 0, -1,
		fn.Some(uint32(1)),
	)
	require.NoError(t, err)
	preCommit, err := funded.PreCommitmentOutput.UnwrapOrErr(
		errors.New("pre-commitment output missing"),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), preCommit.OutIdx)
	require.Equal(t, schnorr.SerializePubKey(delegationKey.PubKey),
		funded.Pkt.Outputs[1].TaprootInternalKey)
	require.Len(t, funded.Pkt.Outputs[1].Bip32Derivation, 1)
	require.Len(t, funded.Pkt.Outputs[1].TaprootBip32Derivation, 1)
}

func noneUint32() fn.Option[uint32] { return fn.None[uint32]() }

func fundedPsbt(pkt *psbt.Packet) tapsend.FundedPsbt {
	return tapsend.FundedPsbt{Pkt: pkt, ChangeOutputIndex: -1}
}

func clonePsbt(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	clone, err := psbt.NewFromRawBytes(&buf, false)
	require.NoError(t, err)
	return clone
}
