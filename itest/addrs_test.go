package itest

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

var (
	statusDetected  = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusConfirmed = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED
)

func testAddresses(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	//
	// TODO(guggero): Update this test once we support pocket universes with
	// virtual TX outpoints in prevID so we don't have to sign for every
	// asset within a commitment if we only move one of them.
	var rpcAssets []*tarorpc.Asset
	rpcAssets = append(rpcAssets, mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)...)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	var (
		addresses []*tarorpc.Addr
		newAssets []*asset.Asset
		events    []*tarorpc.AddrEvent
	)
	for _, a := range rpcAssets {
		var familyKey []byte
		if a.AssetFamily != nil {
			familyKey = a.AssetFamily.TweakedFamilyKey
		}

		// We send the full amount of assets.
		//
		// TODO(guggero): Add test that sends with asset split.
		addr, err := t.tarod.NewAddr(ctxt, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: a.AssetGenesis.GenesisBootstrapInfo,
			FamKey:               familyKey,
			Amt:                  a.Amount,
			AssetType:            a.AssetType,
		})
		require.NoError(t.t, err)
		addresses = append(addresses, addr)

		assertAddrCreated(t.t, t.tarod, a, addr)

		// Create an asset transfer now.
		newAssets = append(newAssets, sendAssetsToAddr(t, a, addr))

		// Make sure that eventually we see a single event for the
		// address.
		err = wait.NoError(func() error {
			resp, err := t.tarod.AddrReceives(
				ctxt, &tarorpc.AddrReceivesRequest{
					FilterAddr: addr.Encoded,
				},
			)
			if err != nil {
				return err
			}

			if len(resp.Events) != 1 {
				return fmt.Errorf("got %d events, wanted 1",
					len(resp.Events))
			}

			if resp.Events[0].Status != statusDetected {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusDetected)
			}

			eventJSON, err := formatProtoJSON(resp.Events[0])
			require.NoError(t.t, err)
			t.Logf("Got address event %s", eventJSON)
			events = append(events, resp.Events[0])

			return nil
		}, defaultWaitTimeout/2)
		require.NoError(t.t, err)
	}

	// Mine a block to make sure the events are marked as confirmed.
	block := mineBlocks(t, t.lndHarness, 1, len(rpcAssets))[0]

	// Eventually the events should be marked as confirmed.
	err := wait.NoError(func() error {
		resp, err := t.tarod.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Events, len(rpcAssets))

		for _, event := range resp.Events {
			if event.Status != statusConfirmed {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusConfirmed)
			}
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, err)

	// We now append a proof for each new asset.
	for idx := range newAssets {
		addr := addresses[idx]
		newAsset := newAssets[idx]
		event := events[idx]

		internalKey, err := btcec.ParsePubKey(addr.InternalKey)
		require.NoError(t.t, err)

		newAsset.PrevWitnesses = nil

		assetCommitment, err := commitment.NewAssetCommitment(newAsset)
		require.NoError(t.t, err)
		taroCommitment, err := commitment.NewTaroCommitment(
			assetCommitment,
		)
		require.NoError(t.t, err)

		proofParams := proof.BaseProofParams{
			Block:       block,
			OutputIndex: 0,
			InternalKey: internalKey,
			TaroRoot:    taroCommitment,
		}

		// Find the transaction that sent to this particular asset.
		outpoint, err := parseOutPoint(event.Outpoint)
		require.NoError(t.t, err)
		for idx := range block.Transactions {
			tx := block.Transactions[idx]
			if tx.TxHash() == outpoint.Hash {
				proofParams.Tx = tx
				proofParams.TxIndex = idx
				break
			}
		}
		require.NotNil(t.t, proofParams.Tx)

		lastProof := assertAssetProofs(t.t, t.tarod, rpcAssets[idx])
		newBlob, _, err := proof.AppendTransition(
			lastProof, &proof.TransitionParams{
				BaseProofParams: proofParams,
				NewAsset:        newAssets[idx],
			},
		)
		require.NoError(t.t, err)

		_, snapshot := verifyProofBlob(t.t, t.tarod, newBlob)
		require.Equal(
			t.t, commitmentKey(t.t, rpcAssets[idx]),
			snapshot.Asset.AssetCommitmentKey(),
		)
	}
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
//
// TODO(guggero): Replace this manual send with a call to the send RPC once that
// is fully implemented.
func sendAssetsToAddr(t *harnessTest, rpcInputAsset *tarorpc.Asset,
	rpcAddr *tarorpc.Addr) *asset.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	genesisOutpoint, err := parseOutPoint(
		rpcInputAsset.AssetGenesis.GenesisPoint,
	)
	require.NoError(t.t, err)
	genesis := asset.Genesis{
		FirstPrevOut: *genesisOutpoint,
		Tag:          rpcInputAsset.AssetGenesis.Name,
		Metadata:     rpcInputAsset.AssetGenesis.Meta,
		OutputIndex:  rpcInputAsset.AssetGenesis.OutputIndex,
		Type:         asset.Type(rpcInputAsset.AssetType),
	}

	senderScriptKey, err := btcec.ParsePubKey(rpcInputAsset.ScriptKey)
	require.NoError(t.t, err)

	recipientScriptKey, err := btcec.ParsePubKey(rpcAddr.ScriptKey)
	require.NoError(t.t, err)

	senderInternalKey, err := btcec.ParsePubKey(
		rpcInputAsset.ChainAnchor.InternalKey,
	)
	require.NoError(t.t, err)

	recipientInternalKey, err := btcec.ParsePubKey(rpcAddr.InternalKey)
	require.NoError(t.t, err)

	var (
		familyKey, familyKeyNoSig *asset.FamilyKey
	)
	if rpcInputAsset.AssetFamily != nil {
		rpcFamKey := rpcInputAsset.AssetFamily
		rawKey, err := btcec.ParsePubKey(rpcFamKey.RawFamilyKey)
		require.NoError(t.t, err)
		famKey, err := btcec.ParsePubKey(rpcFamKey.TweakedFamilyKey)
		require.NoError(t.t, err)
		famSig, err := schnorr.ParseSignature(rpcFamKey.AssetIdSig)
		require.NoError(t.t, err)

		familyKey = &asset.FamilyKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: rawKey,
			},
			FamKey: *famKey,
			Sig:    *famSig,
		}
		familyKeyNoSig = &asset.FamilyKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: rawKey,
			},
			FamKey: *famKey,
		}
	}

	inputAsset, err := asset.New(
		genesis, uint64(rpcAddr.Amount), uint64(rpcInputAsset.LockTime),
		uint64(rpcInputAsset.RelativeLockTime),
		asset.NewScriptKey(senderScriptKey), familyKey,
	)
	require.NoError(t.t, err)

	prevOutpoint, err := parseOutPoint(
		rpcInputAsset.ChainAnchor.AnchorOutpoint,
	)
	require.NoError(t.t, err)

	newAsset, err := asset.New(
		genesis, uint64(rpcAddr.Amount), 0, 0,
		asset.NewScriptKey(recipientScriptKey), familyKeyNoSig,
	)
	require.NoError(t.t, err)

	lndServices, err := t.newLndClient(t.lndHarness.Alice)
	require.NoError(t.t, err)

	// Add the witness to the asset, authorizing the asset level transfer.
	signAssetTransfer(
		t.t, *prevOutpoint, recipientInternalKey, inputAsset, newAsset,
		taro.NewLndRpcVirtualTxSigner(&lndServices.LndServices),
	)

	// Now create the Bitcoin level TX and sign for that as well. Before we
	// can do that, we need to create our commitments in order to tweak the
	// internal keys.
	inputCommitment, err := commitment.NewAssetCommitment(inputAsset)
	require.NoError(t.t, err)
	inputTaroCommitment, err := commitment.NewTaroCommitment(
		inputCommitment,
	)
	require.NoError(t.t, err)

	inputTapscriptRoot := inputTaroCommitment.TapscriptRoot(nil)
	inputTaprootKey := txscript.ComputeTaprootOutputKey(
		senderInternalKey, inputTapscriptRoot[:],
	)

	inputPkScript, err := taroscript.PayToTaprootScript(inputTaprootKey)
	require.NoError(t.t, err)

	outputTaprootKey, err := schnorr.ParsePubKey(rpcAddr.TaprootOutputKey)
	require.NoError(t.t, err)
	outputPkScript, err := taroscript.PayToTaprootScript(outputTaprootKey)
	require.NoError(t.t, err)

	utxo := &wire.TxOut{
		PkScript: inputPkScript,
		Value:    int64(tarogarden.GenesisAmtSats),
	}
	sendTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: *prevOutpoint,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: outputPkScript,
			// All assets are minted with 1k sats, 200 sat should be
			// plenty to pay a 1-input-1-output P2TR-to-P2TR TX.
			Value: int64(tarogarden.GenesisAmtSats) - 200,
		}},
	}

	sigs, err := lndServices.Signer.SignOutputRaw(
		ctxt, sendTx, []*lndclient.SignDescriptor{{
			KeyDesc: keychain.KeyDescriptor{
				PubKey: senderInternalKey,
			},
			TapTweak:   inputTapscriptRoot[:],
			SignMethod: input.TaprootKeySpendSignMethod,
			Output:     utxo,
			HashType:   txscript.SigHashDefault,
			InputIndex: 0,
		}},
		[]*wire.TxOut{utxo},
	)
	require.NoError(t.t, err)
	require.Len(t.t, sigs, 1)

	sendTx.TxIn[0].Witness = sigs
	var buf bytes.Buffer
	require.NoError(t.t, sendTx.Serialize(&buf))

	// Publish the second transaction and then mine it.
	_, err = t.lndHarness.Alice.WalletKitClient.PublishTransaction(
		ctxt, &walletrpc.Transaction{
			TxHex: buf.Bytes(),
		},
	)
	require.NoError(t.t, err)

	return newAsset
}

// signAssetTransfer creates a virtual transaction for an asset transfer and
// signs it with the given sender private key. Then we add the generated witness
// to the root asset and all split asset's root asset references.
func signAssetTransfer(t *testing.T, prevOutpoint wire.OutPoint,
	internalKey *btcec.PublicKey, inputAsset *asset.Asset,
	newAsset *asset.Asset, signer taroscript.Signer) {

	prevID := &asset.PrevID{
		OutPoint: prevOutpoint,
		ID:       inputAsset.ID(),
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID: prevID,
	}}
	inputs := commitment.InputSet{
		*prevID: inputAsset,
	}

	virtualTx, _, err := taroscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)

	txWitness, err := taroscript.SignTaprootKeySpend(
		*internalKey, virtualTx, inputAsset, 0, signer,
	)
	require.NoError(t, err)

	newAsset.PrevWitnesses[0].TxWitness = *txWitness
}

func parseOutPoint(s string) (*wire.OutPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("expecting outpoint to be in format of: " +
			"txid:index")
	}

	index, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %v", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %v", err)
	}

	return &wire.OutPoint{
		Hash:  *txid,
		Index: uint32(index),
	}, nil
}
