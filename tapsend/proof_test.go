package tapsend

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

var (
	testChainParams = &address.RegressionNetTap
)

// TestCreateProofSuffix tests the creation of suffix proofs for a given anchor
// transaction.
func TestCreateProofSuffix(t *testing.T) {
	testAssets := []*asset.Asset{
		asset.RandAsset(t, asset.RandAssetType(t)),
		asset.RandAsset(t, asset.RandAssetType(t)),
		asset.RandAsset(t, asset.RandAssetType(t)),
		asset.RandAsset(t, asset.RandAssetType(t)),
	}

	// We want to make sure the assets don't look like genesis assets.
	for idx, a := range testAssets {
		prevID := &asset.PrevID{
			ID:        a.ID(),
			ScriptKey: asset.ToSerialized(a.ScriptKey.PubKey),
		}
		if len(testAssets[idx].PrevWitnesses) > 0 {
			testAssets[idx].PrevWitnesses[0].PrevID = prevID
		} else {
			testAssets[idx].PrevWitnesses = []asset.Witness{{
				PrevID: prevID,
			}}
		}
	}

	// We create an anchor TX with 4 outputs:
	// 1. Commitment to asset 1 and asset 2 change (internal key 1).
	// 2. Commitment to asset 2 split and asset 3 (internal key 1).
	// 3. Commitment to asset 4 (internal key 2).
	// 4. BIP86 (change) output.
	internalKey1 := test.RandPubKey(t)
	internalKey2 := test.RandPubKey(t)
	testPackets := []*tappsbt.VPacket{
		createPacket(t, testAssets[0], false, internalKey1, 0),
		createPacket(t, testAssets[1], true, internalKey1, 1),
		createPacket(t, testAssets[2], false, internalKey1, 1),
		createPacket(t, testAssets[3], false, internalKey2, 2),
	}

	wireTx := wire.NewMsgTx(2)
	wireTx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: wire.OutPoint{},
	}}
	wireTx.TxOut = []*wire.TxOut{
		CreateDummyOutput(),
		CreateDummyOutput(),
		CreateDummyOutput(),
	}
	pkt, err := psbt.NewFromUnsignedTx(wireTx)
	require.NoError(t, err)
	anchorTx := &AnchorTransaction{
		FundedPsbt: &FundedPsbt{
			Pkt:               pkt,
			ChangeOutputIndex: 3,
		},
		FinalTx: pkt.UnsignedTx,
	}
	outputCommitments := make(map[uint32]*commitment.TapCommitment)

	addOutputCommitment(t, anchorTx, outputCommitments, testPackets...)
	addBip86Output(t, anchorTx.FundedPsbt.Pkt)

	// Create a proof suffix for all 4 packets now and validate it.
	for _, vPkt := range testPackets {
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := CreateProofSuffix(
				pkt.UnsignedTx, pkt.Outputs, vPkt,
				outputCommitments, outIdx, testPackets,
			)
			require.NoError(t, err)

			ctx := context.Background()
			prev := &proof.AssetSnapshot{
				Asset: vPkt.Inputs[0].Asset(),
			}

			_, err = proofSuffix.Verify(
				ctx, prev, proof.MockChainLookup,
				proof.MockVerifierCtx,
			)

			// Checking the transfer witness is the very last step
			// of the proof verification. Since we didn't properly
			// sign the transfer, we expect the witness to be
			// invalid. But if we get to that point, we know that
			// all inclusion and exclusion proofs are correct (which
			// is what this test is testing).
			invalidWitnessErr := vm.Error{
				Kind: vm.ErrInvalidTransferWitness,
				Inner: txscript.Error{
					ErrorCode: txscript.ErrTaprootSigInvalid,
				},
			}
			require.ErrorIs(t, err, invalidWitnessErr)
		}
	}
}

func createPacket(t *testing.T, a *asset.Asset, split bool,
	internalKey *btcec.PublicKey, anchorOutputIdx uint32) *tappsbt.VPacket {

	if split {
		amount := a.Amount / 2
		change := a.Amount - amount
		changeKey := asset.RandScriptKey(t)

		if a.Type == asset.Collectible {
			change = 0
			amount = 1
			changeKey = asset.NUMSScriptKey
		}

		outputs := []*tappsbt.VOutput{
			{
				Amount:                  change,
				AssetVersion:            a.Version,
				Type:                    tappsbt.TypeSplitRoot,
				ScriptKey:               changeKey,
				AnchorOutputIndex:       0,
				AnchorOutputInternalKey: internalKey,
			},
			{
				Amount:                  amount,
				AssetVersion:            a.Version,
				Type:                    tappsbt.TypeSimple,
				ScriptKey:               a.ScriptKey,
				AnchorOutputIndex:       anchorOutputIdx,
				AnchorOutputInternalKey: internalKey,
			},
		}
		vPkt := &tappsbt.VPacket{
			Inputs: []*tappsbt.VInput{{
				PrevID: asset.PrevID{
					ID: a.ID(),
				},
			}},
			Outputs:     outputs,
			ChainParams: testChainParams,
		}
		vPkt.SetInputAsset(0, a)

		ctx := context.Background()
		err := PrepareOutputAssets(ctx, vPkt)
		require.NoError(t, err)

		vPkt.Outputs[0].Asset.PrevWitnesses[0].TxWitness =
			a.PrevWitnesses[0].TxWitness
		vPkt.Outputs[1].Asset.PrevWitnesses[0].SplitCommitment.
			RootAsset.PrevWitnesses[0].TxWitness =
			a.PrevWitnesses[0].TxWitness

		return vPkt
	}

	// A non-split asset is just a single output.
	vPkt := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{
				ID: a.ID(),
			},
		}},
		Outputs: []*tappsbt.VOutput{
			{
				Amount:                  a.Amount,
				AssetVersion:            a.Version,
				Type:                    tappsbt.TypeSimple,
				Interactive:             true,
				Asset:                   a,
				ScriptKey:               a.ScriptKey,
				AnchorOutputIndex:       anchorOutputIdx,
				AnchorOutputInternalKey: internalKey,
			},
		},
		ChainParams: testChainParams,
	}
	vPkt.SetInputAsset(0, a)

	return vPkt
}

func addOutputCommitment(t *testing.T, anchorTx *AnchorTransaction,
	outputCommitments map[uint32]*commitment.TapCommitment,
	vPackets ...*tappsbt.VPacket) {

	packet := anchorTx.FundedPsbt.Pkt

	assetsByOutput := make(map[uint32][]*asset.Asset)
	keyByOutput := make(map[uint32]*btcec.PublicKey)
	for _, vPkt := range vPackets {
		for _, vOut := range vPkt.Outputs {
			idx := vOut.AnchorOutputIndex
			assetsByOutput[idx] = append(
				assetsByOutput[idx], vOut.Asset,
			)
			keyByOutput[idx] = vOut.AnchorOutputInternalKey
		}
	}

	for idx, assets := range assetsByOutput {
		for idx := range assets {
			if !assets[idx].HasSplitCommitmentWitness() {
				continue
			}
			assets[idx] = assets[idx].Copy()
			assets[idx].PrevWitnesses[0].SplitCommitment = nil
		}

		c, err := commitment.FromAssets(nil, assets...)
		require.NoError(t, err)

		internalKey := keyByOutput[idx]
		script, err := tapscript.PayToAddrScript(*internalKey, nil, *c)
		require.NoError(t, err)

		packet.UnsignedTx.TxOut[idx].PkScript = script
		packet.Outputs[idx].TaprootInternalKey = schnorr.SerializePubKey(
			internalKey,
		)
		outputCommitments[idx] = c
	}
}

func addBip86Output(t *testing.T, packet *psbt.Packet) {
	internalKey := test.RandPubKey(t)
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	script, err := txscript.PayToTaprootScript(taprootKey)
	require.NoError(t, err)

	txOut := &wire.TxOut{
		PkScript: script,
		Value:    1234,
	}
	pOut := psbt.POutput{
		TaprootInternalKey: schnorr.SerializePubKey(internalKey),
	}

	packet.UnsignedTx.AddTxOut(txOut)
	packet.Outputs = append(packet.Outputs, pOut)
}
