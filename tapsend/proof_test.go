package tapsend

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
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
	testCases := []struct {
		name        string
		stxoProof   bool
		expectedErr string
	}{
		{
			name:      "Correct inclusion and exclusion proofs",
			stxoProof: true,
		},
		{
			name:        "No stxo proof",
			stxoProof:   false,
			expectedErr: "no alt leaves for transfer root asset",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			createProofSuffix(t, tc.stxoProof, tc.expectedErr)
		})
	}
}

func createProofSuffix(t *testing.T, stxoProof bool, expectedErr string) {
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

	addOutputCommitment(
		t, anchorTx, outputCommitments, stxoProof,
		testPackets...,
	)
	addBip86Output(t, anchorTx.FundedPsbt.Pkt)

	// Change on outputCommitment to the legacy marker.
	outputCommitments[2], err = outputCommitments[2].Downgrade()
	require.NoError(t, err)

	// Create a proof suffix for all 4 packets now and validate it.
	for _, vPkt := range testPackets {
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := CreateProofSuffix(
				pkt.UnsignedTx, pkt.Outputs, vPkt,
				outputCommitments, outIdx, testPackets,
				proof.WithVersion(proof.TransitionV1),
			)
			switch {
			case err != nil:
				require.Nil(t, proofSuffix)
				require.ErrorContains(t, err, expectedErr)
				continue
			default:
				require.NoError(t, err)
			}

			ctx := context.Background()
			prev := &proof.AssetSnapshot{
				Asset: vPkt.Inputs[0].Asset(),
			}

			_, err = proofSuffix.Verify(
				ctx, prev, proof.MockChainLookup,
				proof.MockVerifierCtx,
			)

			// Checking the transfer witness is the very last step
			// of the proof verification. Since we don't properly
			// sign the transfer, we expect the witness to be
			// invalid. But if we get to that point, we know that
			// all inclusion and exclusion proofs are correct. So
			// for successful cases we still expect an error, namely
			// the invalid witness error.
			errCode := txscript.ErrTaprootSigInvalid
			invalidWitnessErr := vm.Error{
				Kind: vm.ErrInvalidTransferWitness,
				Inner: txscript.Error{
					ErrorCode: errCode,
				},
			}
			if expectedErr == "" {
				require.ErrorIs(t, err, invalidWitnessErr)

				continue
			}

			if vPkt.Outputs[outIdx].Asset.IsTransferRoot() {
				require.ErrorContains(
					t, err, expectedErr,
				)
			} else {
				require.ErrorIs(
					t, err, invalidWitnessErr,
				)
			}
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
	stxoProof bool, vPackets ...*tappsbt.VPacket) {

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

	stxoAssetsByOutput := make(map[uint32][]asset.AltLeaf[asset.Asset])
	for idx1, assets := range assetsByOutput {
		for idx2 := range assets {
			if assets[idx2].IsTransferRoot() {
				stxoAssets, err := asset.CollectSTXO(
					assets[idx2],
				)
				stxoAssetsByOutput[idx1] = append(
					stxoAssetsByOutput[idx1], stxoAssets...,
				)
				require.NoError(t, err)
			}

			if !assets[idx2].HasSplitCommitmentWitness() {
				continue
			}

			assets[idx2] = assets[idx2].Copy()
			assets[idx2].PrevWitnesses[0].SplitCommitment = nil
		}

		c, err := commitment.FromAssets(nil, assets...)
		require.NoError(t, err)
		if stxoProof {
			err = c.MergeAltLeaves(stxoAssetsByOutput[idx1])
			require.NoError(t, err)
		}

		internalKey := keyByOutput[idx1]
		script, err := tapscript.PayToAddrScript(*internalKey, nil, *c)
		require.NoError(t, err)

		packet.UnsignedTx.TxOut[idx1].PkScript = script
		packet.Outputs[idx1].TaprootInternalKey =
			schnorr.SerializePubKey(internalKey)
		outputCommitments[idx1] = c
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

// randTransferAsset returns a random asset of the given type that doesn't look
// like a genesis asset.
func randTransferAsset(t *testing.T, assetType asset.Type) *asset.Asset {
	a := asset.RandAsset(t, assetType)
	a.PrevWitnesses[0].PrevID = &asset.PrevID{
		ID:        a.ID(),
		ScriptKey: asset.ToSerialized(a.ScriptKey.PubKey),
	}

	return a
}

// anchorPackets commits the given packets to a fresh anchor transaction with
// the given number of asset outputs, followed by a BIP-86 output.
func anchorPackets(t *testing.T, numOutputs int,
	vPackets ...*tappsbt.VPacket) (*psbt.Packet,
	map[uint32]*commitment.TapCommitment) {

	wireTx := wire.NewMsgTx(2)
	wireTx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: wire.OutPoint{},
	}}
	for i := 0; i < numOutputs; i++ {
		wireTx.TxOut = append(wireTx.TxOut, CreateDummyOutput())
	}

	pkt, err := psbt.NewFromUnsignedTx(wireTx)
	require.NoError(t, err)
	anchorTx := &AnchorTransaction{
		FundedPsbt: &FundedPsbt{
			Pkt:               pkt,
			ChangeOutputIndex: int32(numOutputs),
		},
		FinalTx: pkt.UnsignedTx,
	}

	outputCommitments := make(map[uint32]*commitment.TapCommitment)
	addOutputCommitment(t, anchorTx, outputCommitments, true, vPackets...)
	addBip86Output(t, anchorTx.FundedPsbt.Pkt)

	return pkt, outputCommitments
}

// assertProofsValid asserts that the inclusion and exclusion proofs of the
// given proof suffix are valid. The test packets are not signed, so a proof
// that passes those checks fails on the transfer witness, which is verified
// last.
func assertProofsValid(t *testing.T, vPkt *tappsbt.VPacket,
	proofSuffix *proof.Proof) {

	_, err := proofSuffix.Verify(
		context.Background(), &proof.AssetSnapshot{
			Asset: vPkt.Inputs[0].Asset(),
		}, proof.MockChainLookup, proof.MockVerifierCtx,
	)
	require.ErrorIs(t, err, vm.Error{
		Kind: vm.ErrInvalidTransferWitness,
		Inner: txscript.Error{
			ErrorCode: txscript.ErrTaprootSigInvalid,
		},
	})
}

// TestCreateProofSuffixSharedOutput tests the creation of suffix proofs for a
// split whose root and split asset are committed to the same anchor output.
func TestCreateProofSuffixSharedOutput(t *testing.T) {
	vPkt := createPacket(
		t, randTransferAsset(t, asset.Normal), true,
		test.RandPubKey(t), 0,
	)
	pkt, outputCommitments := anchorPackets(t, 1, vPkt)

	for outIdx := range vPkt.Outputs {
		vOut := vPkt.Outputs[outIdx]
		require.Zero(t, vOut.AnchorOutputIndex)

		proofSuffix, err := CreateProofSuffix(
			pkt.UnsignedTx, pkt.Outputs, vPkt, outputCommitments,
			outIdx, []*tappsbt.VPacket{vPkt},
			proof.WithVersion(proof.TransitionV1),
		)
		require.NoError(t, err)

		// The only other output is the BIP-86 one. In particular, the
		// split asset needs no exclusion proof for the output it
		// shares with its root.
		require.Len(t, proofSuffix.ExclusionProofs, 1)
		exclusionProof := proofSuffix.ExclusionProofs[0]
		require.EqualValues(t, 1, exclusionProof.OutputIndex)
		require.NotNil(t, exclusionProof.TapscriptProof)

		assertProofsValid(t, vPkt, proofSuffix)

		// The shared output commits to the STXO, so either proof
		// carries its inclusion proof, and nothing else.
		inclusionProof := proofSuffix.InclusionProof.CommitmentProof
		if vOut.Type.IsSplitRoot() {
			require.Len(t, inclusionProof.STXOProofs, 1)
			continue
		}

		rootProof := proofSuffix.SplitRootProof.CommitmentProof
		require.Len(t, rootProof.STXOProofs, 1)
		require.Empty(t, inclusionProof.STXOProofs)
	}
}

// TestCreateProofSuffixMissingSplitWitness checks that a malformed receiver
// is rejected when another receiver makes the packet appear to be a split.
func TestCreateProofSuffixMissingSplitWitness(t *testing.T) {
	a := randTransferAsset(t, asset.Normal)
	a.Amount = 12
	internalKey := test.RandPubKey(t)
	vPkt := createPacket(t, a, true, internalKey, 1)
	vPkt.Outputs[0].Amount = 4
	vPkt.Outputs[1].Amount = 4
	vPkt.Outputs = append(vPkt.Outputs, &tappsbt.VOutput{
		Amount:                  4,
		AssetVersion:            a.Version,
		Type:                    tappsbt.TypeSimple,
		ScriptKey:               asset.RandScriptKey(t),
		AnchorOutputIndex:       2,
		AnchorOutputInternalKey: internalKey,
	})
	require.NoError(t, PrepareOutputAssets(context.Background(), vPkt))
	vPkt.Outputs[0].Asset.PrevWitnesses[0].TxWitness =
		a.PrevWitnesses[0].TxWitness
	for _, out := range vPkt.Outputs[1:] {
		splitCommitment := out.Asset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness =
			a.PrevWitnesses[0].TxWitness
	}

	// Keep the second receiver's amount and keys, but remove its split
	// witness. The first receiver still identifies the packet as a split.
	vPkt.Outputs[2].Asset.PrevWitnesses[0].SplitCommitment = nil
	encoded, err := tappsbt.Encode(vPkt)
	require.NoError(t, err)
	vPkt, err = tappsbt.Decode(encoded)
	require.NoError(t, err)

	packets := []*tappsbt.VPacket{vPkt}
	commitments, err := CreateOutputCommitments(packets)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: vPkt.Inputs[0].PrevID.OutPoint,
	})
	for range vPkt.Outputs {
		tx.AddTxOut(CreateDummyOutput())
	}
	anchor, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for i := range anchor.Outputs {
		anchor.Outputs[i].TaprootInternalKey =
			schnorr.SerializePubKey(internalKey)
	}
	require.NoError(t, UpdateTaprootOutputKeys(
		anchor, vPkt, commitments,
	))

	suffix, err := CreateProofSuffix(
		anchor.UnsignedTx, anchor.Outputs, vPkt, commitments, 2,
		packets,
	)
	require.Nil(t, suffix)
	require.ErrorContains(t, err,
		"split output 2 has no split commitment witness")
}

// TestCreateProofSuffixSplitSTXOProofs tests that the suffix proof of a split
// asset carries the STXO proofs for the input spent by its root asset.
func TestCreateProofSuffixSplitSTXOProofs(t *testing.T) {
	const (
		rootOutput = iota
		splitOutput
		otherOutput
		numOutputs
	)

	// Next to the split, we anchor an unrelated transfer.
	internalKey := test.RandPubKey(t)
	vPkt := createPacket(
		t, randTransferAsset(t, asset.Normal), true, internalKey,
		splitOutput,
	)
	otherPkt := createPacket(
		t, randTransferAsset(t, asset.Normal), false,
		test.RandPubKey(t), otherOutput,
	)
	vPackets := []*tappsbt.VPacket{vPkt, otherPkt}
	pkt, outputCommitments := anchorPackets(t, numOutputs, vPackets...)

	proofSuffix, err := CreateProofSuffix(
		pkt.UnsignedTx, pkt.Outputs, vPkt, outputCommitments, 1,
		vPackets, proof.WithVersion(proof.TransitionV1),
	)
	require.NoError(t, err)
	require.True(t, proofSuffix.Asset.HasSplitCommitmentWitness())

	assertProofsValid(t, vPkt, proofSuffix)

	// The STXO is included in the split root output, and excluded from
	// all the other asset outputs, including the one of the split asset.
	rootProof := proofSuffix.SplitRootProof.CommitmentProof
	require.EqualValues(
		t, rootOutput, proofSuffix.SplitRootProof.OutputIndex,
	)
	require.Len(t, rootProof.STXOProofs, 1)

	ownProof := proofSuffix.InclusionProof.CommitmentProof
	require.EqualValues(
		t, splitOutput, proofSuffix.InclusionProof.OutputIndex,
	)
	require.Len(t, ownProof.STXOProofs, 1)

	for _, exclusionProof := range proofSuffix.ExclusionProofs {
		switch exclusionProof.OutputIndex {
		case rootOutput:
			require.Empty(
				t, exclusionProof.CommitmentProof.STXOProofs,
			)

		case otherOutput:
			require.Len(
				t, exclusionProof.CommitmentProof.STXOProofs,
				1,
			)

		default:
			require.NotNil(t, exclusionProof.TapscriptProof)
		}
	}

	// Without STXO proofs, the proof carries none of them.
	outputCommitments[rootOutput], err = commitment.FromAssets(
		nil, vPkt.Outputs[0].Asset,
	)
	require.NoError(t, err)

	proofSuffix, err = CreateProofSuffix(
		pkt.UnsignedTx, pkt.Outputs, vPkt, outputCommitments, 1,
		vPackets, proof.WithNoSTXOProofs(),
	)
	require.NoError(t, err)
	require.Empty(t, proofSuffix.SplitRootProof.CommitmentProof.STXOProofs)
	require.Empty(t, proofSuffix.InclusionProof.CommitmentProof.STXOProofs)
	for _, exclusionProof := range proofSuffix.ExclusionProofs {
		if exclusionProof.CommitmentProof == nil {
			continue
		}

		require.Empty(t, exclusionProof.CommitmentProof.STXOProofs)
	}
}
