package itest

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/lndclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/stretchr/testify/require"
)

// testMultiSignature tests that we can use multi signature on all levels of the
// Taproot Assets Protocol. This includes the BTC level, the asset level and the
// group key level.
func testMultiSignature(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We mint some grouped assets to use in the test. These assets are
	// minted on the default tapd instance that is always created in the
	// integration test (connected to lnd "Alice").
	firstBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)[0]

	var (
		firstBatchGenesis = firstBatch.AssetGenesis
		aliceTapd         = t.tapd
		aliceLnd          = t.lndHarness.Alice
		bobLnd            = t.lndHarness.Bob
	)

	// We create a second tapd node that will be used to simulate a second
	// party in the test. This tapd node is connected to lnd "Bob".
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// And now we prepare the multisig addresses for both levels. On the
	// BTC level we are going to do a Tapscript based 2-of-2 multisig using
	// OP_CHECKSIGADD. On the asset level we are going to use a 2-of-2
	// MuSig2 scheme. The BTC level key is going to be called the "internal
	// key" and the asset level key is going to be called the "script key".
	aliceScriptKey, aliceInternalKey := deriveKeys(t.t, aliceTapd)
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bobTapd)

	// Create the BTC level multisig script, using OP_CHECKSIGADD.
	btcTapscript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(aliceInternalKey.PubKey)).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(bobInternalKey.PubKey)).
		AddOp(txscript.OP_CHECKSIGADD).
		AddInt64(2).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t.t, err)
	btcTapLeaf := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      btcTapscript,
	}

	// The actual internal key of the BTC level Taproot output will be the
	// provably un-spendable NUMS key.
	btcInternalKey := asset.NUMSPubKey
	btcControlBlock := &txscript.ControlBlock{
		LeafVersion: txscript.BaseLeafVersion,
		InternalKey: btcInternalKey,
	}
	siblingPreimage, err := commitment.NewPreimageFromLeaf(btcTapLeaf)
	require.NoError(t.t, err)
	siblingPreimageBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		siblingPreimage,
	)
	require.NoError(t.t, err)

	// Create the MuSig2 nonces and combined key.
	var (
		aliceFundingNonceOpt = musig2.WithPublicKey(
			aliceScriptKey.RawKey.PubKey,
		)
		bobFundingNonceOpt = musig2.WithPublicKey(
			bobScriptKey.RawKey.PubKey,
		)
		aliceNonces, _ = musig2.GenNonces(aliceFundingNonceOpt)
		bobNonces, _   = musig2.GenNonces(bobFundingNonceOpt)
	)
	muSig2Key, err := input.MuSig2CombineKeys(
		input.MuSig2Version100RC2, []*btcec.PublicKey{
			aliceScriptKey.RawKey.PubKey,
			bobScriptKey.RawKey.PubKey,
		}, true, &input.MuSig2Tweaks{TaprootBIP0086Tweak: true},
	)
	require.NoError(t.t, err)
	muSig2ScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: muSig2Key.PreTweakedKey,
	})

	// We now have everything we need to create the TAP address to receive
	// the multisig secured assets. The recipient of the assets is going to
	// be the Bob node, but the custody will be shared between Alice and Bob
	// on both levels.
	const assetsToSend = 1000
	muSig2Addr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:   firstBatchGenesis.AssetId,
		Amt:       assetsToSend,
		ScriptKey: tap.MarshalScriptKey(muSig2ScriptKey),
		InternalKey: &taprpc.KeyDescriptor{
			RawKeyBytes: pubKeyBytes(btcInternalKey),
		},
		TapscriptSibling: siblingPreimageBytes,
	})
	require.NoError(t.t, err)

	// Now we can create our virtual transaction and ask Alice's tapd to
	// fund it.
	sendResp, err := aliceTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{muSig2Addr.Encoded},
	})
	require.NoError(t.t, err)

	t.Logf("Initial transaction: %v", toJSON(t.t, sendResp))

	// By anchoring the virtual transaction, we can now learn the asset
	// commitment root which we'll need to include in the control block to
	// be able to spend the tapscript path later. The convention is that the
	// change output of a virtual transaction is always at index 0. So our
	// address output should be at index 1.
	multiSigOutAnchor := sendResp.Transfer.Outputs[1].Anchor
	btcControlBlock.InclusionProof = multiSigOutAnchor.TaprootAssetRoot

	// We also need to calculate the parity of the output key for the
	// control block.
	rootHash := btcControlBlock.RootHash(btcTapscript)
	tapKey := txscript.ComputeTaprootOutputKey(btcInternalKey, rootHash)

	if tapKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd {

		btcControlBlock.OutputKeyYIsOdd = true
	}
	require.Equal(t.t, rootHash[:], multiSigOutAnchor.MerkleRoot)

	// Let's mine a transaction to make sure the transfer completes.
	expectedAmounts := []uint64{
		firstBatch.Amount - assetsToSend, assetsToSend,
	}
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, aliceTapd,
		sendResp, firstBatchGenesis.AssetId, expectedAmounts,
		0, 1, len(expectedAmounts),
	)

	// And now the event should be completed on both sides.
	AssertAddrEvent(t.t, bobTapd, muSig2Addr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertBalanceByID(
		t.t, bobTapd, firstBatchGenesis.AssetId, assetsToSend,
	)

	// We have now stored our assets in a double-multisig protected TAP
	// address. Let's now try to spend them back to Alice. Let's create a
	// virtual transaction that sends half of the assets back to Alice.
	withdrawAddr, err := aliceTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: firstBatchGenesis.AssetId,
		Amt:     assetsToSend / 2,
	})
	require.NoError(t.t, err)

	// We fund this withdrawal transaction from Bob's tapd which only has
	// the multisig locked assets currently.
	withdrawRecipients := map[string]uint64{
		withdrawAddr.Encoded: withdrawAddr.Amount,
	}
	withdrawFundResp, err := bobTapd.FundVirtualPsbt(
		ctxt, &wrpc.FundVirtualPsbtRequest{
			Template: &wrpc.FundVirtualPsbtRequest_Raw{
				Raw: &wrpc.TxTemplate{
					Recipients: withdrawRecipients,
				},
			},
		},
	)
	require.NoError(t.t, err)

	fundedWithdrawPkt := deserializeVPacket(
		t.t, withdrawFundResp.FundedPsbt,
	)

	// With the virtual transaction funded, we can simply use lnd's MuSig2
	// RPC methods to sign the virtual packet. We only need to keep Alice's
	// session ID and Bob's partial signature since we'll use Alice's lnd to
	// combine the signatures (which is a stateful operation, so the signing
	// session remembers its own partial signature).
	_, aliceSessID := tapCreatePartialSig(
		t.t, aliceTapd, fundedWithdrawPkt, aliceScriptKey.RawKey,
		aliceNonces, bobScriptKey.RawKey.PubKey, bobNonces.PubNonce,
	)
	bobPartialSig, _ := tapCreatePartialSig(
		t.t, bobTapd, fundedWithdrawPkt, bobScriptKey.RawKey, bobNonces,
		aliceScriptKey.RawKey.PubKey, aliceNonces.PubNonce,
	)

	// With the two partial signatures obtained, we can now combine them to
	// create the final.
	finalTapWitness := combineSigs(
		t.t, aliceLnd, aliceSessID, bobPartialSig,
	)

	// We've now replaced the call to SignVirtualTransaction with a manual
	// MuSig2 signing process. The next step is to add the combined
	// signature as the witness to the virtual transaction, then commit it
	// into a BTC level transaction.
	for idx := range fundedWithdrawPkt.Outputs {
		updateWitness(
			fundedWithdrawPkt.Outputs[idx].Asset, finalTapWitness,
		)
	}

	vPackets := []*tappsbt.VPacket{fundedWithdrawPkt}
	withdrawBtcPkt, err := tapsend.PrepareAnchoringTemplate(vPackets)
	require.NoError(t.t, err)

	// By committing the virtual transaction to the BTC template we created,
	// Bob's lnd node will fund the BTC level transaction with an input to
	// pay for the fees (and it will also add a change output).
	btcWithdrawPkt, finalizedWithdrawPackets, _, commitResp := commitVirtualPsbts(
		t.t, bobTapd, withdrawBtcPkt, vPackets, nil, -1,
	)

	// Now all we have to do is to sign the BTC level transaction and
	// publish it.
	assetInputIdx := uint32(0)
	btcControlBlockBytes, err := btcControlBlock.ToBytes()
	require.NoError(t.t, err)

	aliceBtcPartialSig := partialSignWithKey(
		t.t, aliceLnd, btcWithdrawPkt, assetInputIdx, aliceInternalKey,
		btcControlBlockBytes, btcTapLeaf,
	)
	bobBtcPartialSig := partialSignWithKey(
		t.t, bobLnd, btcWithdrawPkt, assetInputIdx, bobInternalKey,
		btcControlBlockBytes, btcTapLeaf,
	)

	// Combine the two signatures into a witness stack, together with the
	// script and control block, and serialize that to the wire binary
	// format.
	txWitness := wire.TxWitness{
		bobBtcPartialSig,
		aliceBtcPartialSig,
		btcTapscript,
		btcControlBlockBytes,
	}
	var buf bytes.Buffer
	err = psbt.WriteTxWitness(&buf, txWitness)
	require.NoError(t.t, err)

	btcWithdrawPkt.Inputs[assetInputIdx].FinalScriptWitness = buf.Bytes()

	// We should now be able to finalize and publish the BTC level
	// transaction.
	signedPkt := finalizePacket(t.t, bobLnd, btcWithdrawPkt)

	logResp := logAndPublish(
		t.t, bobTapd, signedPkt, finalizedWithdrawPackets, nil,
		commitResp,
	)

	t.Logf("Logged transaction: %v", toJSON(t.t, logResp))

	// Mine a block to confirm the transfer.
	MineBlocks(t.t, t.lndHarness.Miner.Client, 1, 1)

	// Alice minted 5000, sent out 1000, and received 500 back. So she
	// should have 4500 left.
	AssertAddrEvent(t.t, aliceTapd, withdrawAddr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, aliceTapd, 1)
	AssertBalanceByID(
		t.t, aliceTapd, firstBatchGenesis.AssetId,
		firstBatch.Amount-assetsToSend/2,
	)

	// Bob should have 500 left.
	AssertBalanceByID(
		t.t, bobTapd, firstBatchGenesis.AssetId, assetsToSend/2,
	)
}

func fetchProofFile(t *testing.T, src *tapdHarness, assetID,
	scriptKey []byte) []byte {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := src.ExportProof(ctxt, &taprpc.ExportProofRequest{
		AssetId:   assetID,
		ScriptKey: scriptKey,
	})
	require.NoError(t, err)

	return resp.RawProofFile
}

func deserializeVPacket(t *testing.T, packetBytes []byte) *tappsbt.VPacket {
	p, err := tappsbt.NewFromRawBytes(bytes.NewReader(packetBytes), false)
	require.NoError(t, err)

	return p
}

func pubKeyBytes(k *btcec.PublicKey) []byte {
	return k.SerializeCompressed()
}

func tapCreatePartialSig(t *testing.T, tapd *tapdHarness, vPkt *tappsbt.VPacket,
	localKey keychain.KeyDescriptor, localNonces *musig2.Nonces,
	otherKey *btcec.PublicKey,
	otherNonces [musig2.PubNonceSize]byte) ([]byte, []byte) {

	lnd := tapd.cfg.LndNode
	sessID := tapMuSig2Session(
		t, lnd, localKey, otherKey.SerializeCompressed(), *localNonces,
		[][]byte{otherNonces[:]},
	)

	partialSigner := &muSig2PartialSigner{
		sessID: sessID,
		lnd:    lnd,
	}

	// The signing code requires us to specify the BIP-0032 derivation info
	// for the key we want to sign with. We can't do that because it's a
	// combined key. But since our integration test partial signer will just
	// ignore the key anyway, we simply provide a fake key to bypass the
	// check.
	// TODO(guggero): Make this nicer by implementing the proposed MuSig2
	// fields for PSBT.
	vIn := vPkt.Inputs[0]
	derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
		keychain.KeyDescriptor{
			PubKey: localKey.PubKey,
		}, tapd.cfg.NetParams.HDCoinType,
	)
	vIn.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trDerivation,
	}

	err := tapsend.SignVirtualTransaction(
		vPkt, partialSigner, partialSigner,
	)
	require.NoError(t, err)

	isSplit, err := vPkt.HasSplitCommitment()
	require.NoError(t, err)

	// Identify new output asset. For splits, the new asset that received
	// the signature is the one with the split root set to true.
	newAsset := vPkt.Outputs[0].Asset
	if isSplit {
		splitOut, err := vPkt.SplitRootOutput()
		require.NoError(t, err)

		newAsset = splitOut.Asset
	}

	// The first part of the witness is just a fake R value, which we can
	// ignore.
	partialSig := newAsset.PrevWitnesses[0].TxWitness[0][32:]

	return partialSig, sessID
}

type muSig2PartialSigner struct {
	sessID []byte
	lnd    *node.HarnessNode
}

func (m *muSig2PartialSigner) ValidateWitnesses(*asset.Asset,
	[]*commitment.SplitAsset, commitment.InputSet) error {

	return nil
}

func (m *muSig2PartialSigner) SignVirtualTx(_ *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	prevOutputFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sighashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)

	sigHash, err := txscript.CalcTaprootSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutputFetcher,
	)
	if err != nil {
		return nil, err
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	sign, err := m.lnd.RPC.Signer.MuSig2Sign(
		ctxt, &signrpc.MuSig2SignRequest{
			SessionId:     m.sessID,
			MessageDigest: sigHash,
			Cleanup:       false,
		},
	)
	if err != nil {
		return nil, err
	}

	// We only get the 32-byte partial signature (just the s value).
	// So we just use an all-zero value for R, since the parsing mechanism
	// doesn't validate R to be a valid point on the curve.
	var sig [schnorr.SignatureSize]byte
	copy(sig[32:], sign.LocalPartialSignature)

	return schnorr.ParseSignature(sig[:])
}

func (m *muSig2PartialSigner) Execute(*asset.Asset, []*commitment.SplitAsset,
	commitment.InputSet) error {

	return nil
}

func tapMuSig2Session(t *testing.T, lnd *node.HarnessNode,
	localKey keychain.KeyDescriptor, otherKey []byte,
	localNonces musig2.Nonces, otherNonces [][]byte) []byte {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	version := signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2
	sess, err := lnd.RPC.Signer.MuSig2CreateSession(
		ctxt, &signrpc.MuSig2SessionRequest{
			KeyLoc: &signrpc.KeyLocator{
				KeyFamily: int32(localKey.Family),
				KeyIndex:  int32(localKey.Index),
			},
			AllSignerPubkeys: [][]byte{
				localKey.PubKey.SerializeCompressed(),
				otherKey,
			},
			OtherSignerPublicNonces: otherNonces,
			TaprootTweak: &signrpc.TaprootTweakDesc{
				KeySpendOnly: true,
			},
			Version:                version,
			PregeneratedLocalNonce: localNonces.SecNonce[:],
		},
	)
	require.NoError(t, err)

	return sess.SessionId
}

func partialSignWithKey(t *testing.T, lnd *node.HarnessNode, pkt *psbt.Packet,
	inputIndex uint32, key keychain.KeyDescriptor, controlBlockBytes []byte,
	tapLeaf txscript.TapLeaf) []byte {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	leafToSign := []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBlockBytes,
		Script:       tapLeaf.Script,
		LeafVersion:  tapLeaf.LeafVersion,
	}}

	// The lnd SignPsbt RPC doesn't really understand multi-sig yet, we
	// cannot specify multiple keys that need to sign. So what we do here
	// is just replace the derivation path info for the input we want to
	// sign to the key we want to sign with. If we do this for every signing
	// participant, we'll get the correct signatures for OP_CHECKSIGADD.
	signInput := &pkt.Inputs[inputIndex]
	derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
		key, lnd.Cfg.NetParams.HDCoinType,
	)
	trDerivation.LeafHashes = [][]byte{fn.ByteSlice(tapLeaf.TapHash())}
	signInput.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	signInput.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trDerivation,
	}
	signInput.TaprootLeafScript = leafToSign
	signInput.SighashType = txscript.SigHashDefault

	var buf bytes.Buffer
	err := pkt.Serialize(&buf)
	require.NoError(t, err)

	resp, err := lnd.RPC.WalletKit.SignPsbt(
		ctxt, &walletrpc.SignPsbtRequest{
			FundedPsbt: buf.Bytes(),
		},
	)
	require.NoError(t, err)

	result, err := psbt.NewFromRawBytes(
		bytes.NewReader(resp.SignedPsbt), false,
	)
	require.NoError(t, err)

	// Make sure the input we wanted to sign for was actually signed.
	require.Contains(t, resp.SignedInputs, inputIndex)

	return result.Inputs[inputIndex].TaprootScriptSpendSig[0].Signature
}

func combineSigs(t *testing.T, lnd *node.HarnessNode, sessID,
	otherPartialSig []byte) wire.TxWitness {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := lnd.RPC.Signer.MuSig2CombineSig(
		ctxt, &signrpc.MuSig2CombineSigRequest{
			SessionId:              sessID,
			OtherPartialSignatures: [][]byte{otherPartialSig},
		},
	)
	require.NoError(t, err)
	require.True(t, resp.HaveAllSignatures)

	commitmentWitness := make(wire.TxWitness, 1)
	commitmentWitness[0] = resp.FinalSignature

	return commitmentWitness
}

func updateWitness(a *asset.Asset, witness wire.TxWitness) {
	firstPrevWitness := &a.PrevWitnesses[0]
	if a.HasSplitCommitmentWitness() {
		rootAsset := firstPrevWitness.SplitCommitment.RootAsset
		firstPrevWitness = &rootAsset.PrevWitnesses[0]
	}
	firstPrevWitness.TxWitness = witness
}

func combineProofs(t *testing.T, rawFile []byte,
	proofs ...*proof.Proof) []byte {

	f := &proof.File{}
	err := f.Decode(bytes.NewReader(rawFile))
	require.NoError(t, err)

	for _, p := range proofs {
		err := f.AppendProof(*p)
		require.NoError(t, err)
	}

	var buf bytes.Buffer
	err = f.Encode(&buf)
	require.NoError(t, err)

	return buf.Bytes()
}

func ignoreHeaderVerifier(wire.BlockHeader, uint32) error {
	return nil
}

func ignoreGroupVerifier(*btcec.PublicKey) error {
	return nil
}
