package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/rpc"
	"github.com/stretchr/testify/require"
)

// testMintFundSealAssets tests that we're able to mint assets with custom
// script keys, group keys, and group key tapscript roots. Once minted, we
// also want to reissue assets with a custom asset group witness, and spend
// an asset with a custom script key witness. An asset group with a tapscript
// root should also be imported into a new node correctly.
func testMintFundSealAssets(t *harnessTest) {
	// We create a second tapd node that will be used to simulate a second
	// party in the test. This tapd node is connected to lnd "Bob".
	var (
		aliceTapd = t.tapd
		aliceLnd  = t.lndHarness.Alice
		bobLnd    = t.lndHarness.Bob
		bobTapd   = setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	)

	aliceLndClient, err := t.newLndClient(aliceLnd)
	require.NoError(t.t, err)

	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	aliceLndKeyRing := taprootassets.NewLndRpcKeyRing(
		&aliceLndClient.LndServices,
	)

	// Let's derive the keys and tapscript trees we'll use.
	// tweakedScript will have an internal key not managed by a tapd, and
	// a tapscript root with a hashlock and a single sig script.
	tweakedScriptDesc := deriveRandomKey(t.t, ctxt, aliceLndKeyRing)
	tweakedScriptSigLock := test.ScriptSchnorrSig(
		t.t, tweakedScriptDesc.PubKey,
	)

	tweakedScript, tweakedScriptTapTree := buildTweakedScriptKey(
		t.t, &tweakedScriptDesc, test.DefaultHashLockWitness,
		tweakedScriptDesc.PubKey,
	)

	// managedGroupInternal will be an internal key we generate via a tapd
	// RPC call, and then set for a specific asset group.
	_, managedGroupInternal := DeriveKeys(t.t, aliceTapd)

	// groupInternalSigLockKey will be an internal key used only for the
	// signature locking script of an asset group.
	_, groupInternalSigLockKey := DeriveKeys(t.t, aliceTapd)
	groupInternalTweak, groupInternalHashLock, groupInternalTapTree :=
		computeGroupKeyTweak(t.t, groupInternalSigLockKey.PubKey, true)

	// groupExternal will be a group internal key not managed by a tapd,
	// that will also have a tapscript tweak.
	groupExternalDesc := deriveRandomKey(t.t, ctxt, aliceLndKeyRing)

	// groupExternalTweak will be the tapscript tweak we apply to
	// groupExternal. We'll use random bytes as we don't intend to use the
	// script spend path at all.
	groupExternalTweak := test.RandBytes(32)

	// firstAnchorInternal and secondAnchorInternal will be the two keys
	// used in the multisig for the genesis output.
	_, firstAnchorInternal := DeriveKeys(t.t, aliceTapd)
	_, secondAnchorInternal := DeriveKeys(t.t, aliceTapd)

	// The tapscript sibling of the anchor will be a 2-of-2 multisig script.
	anchorMultisigScript, siblingReq := buildMultisigTapLeaf(
		t.t, firstAnchorInternal.PubKey, secondAnchorInternal.PubKey,
	)

	// Now, let's build our asset requests. We'll modify each of the
	// standard asset requests used across the itests.
	// Asset 0 will have no asset group, and an external script key with a
	// tapscript root.
	assetReqWithScriptKey := CopyRequest(simpleAssets[0])
	assetReqWithScriptKey.Asset.ScriptKey = taprpc.MarshalScriptKey(
		tweakedScript,
	)

	// Asset 1 will have a specific internal group key with a tapscript
	// root. This asset will be a group anchor.
	assetReqGroupedInternalTweaked := CopyRequest(simpleAssets[1])
	assetReqGroupedInternalTweaked.Asset.NewGroupedAsset = true
	assetReqGroupedInternalTweaked.Asset.GroupInternalKey = taprpc.
		MarshalKeyDescriptor(managedGroupInternal)
	assetReqGroupedInternalTweaked.Asset.
		GroupTapscriptRoot = groupInternalTweak

	// Asset 2 will have an external group key with a tapscript root.
	assetReqGroupedExternal := CopyRequest(issuableAssets[0])
	assetReqGroupedExternal.Asset.GroupInternalKey = taprpc.
		MarshalKeyDescriptor(groupExternalDesc)
	assetReqGroupedExternal.Asset.GroupTapscriptRoot = groupExternalTweak[:]

	// Asset 3 will be a member of the asset group created by Asset 1.
	assetReqGroupMember := CopyRequest(issuableAssets[1])
	assetReqGroupMember.Asset.NewGroupedAsset = false
	assetReqGroupMember.Asset.GroupedAsset = true
	assetReqGroupMember.Asset.GroupAnchor = assetReqGroupedInternalTweaked.
		Asset.Name

	assetReqs := []*mintrpc.MintAssetRequest{
		assetReqWithScriptKey, assetReqGroupedInternalTweaked,
		assetReqGroupedExternal, assetReqGroupMember,
	}

	// Let's fund a batch, adding the multisig tapscript sibling we
	// constructed earlier.
	fundReq := &mintrpc.FundBatchRequest{
		BatchSibling: &siblingReq,
	}
	fundResp, err := aliceTapd.FundBatch(ctxt, fundReq)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, fundResp.Batch)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_PENDING,
		fundResp.Batch.State,
	)
	require.NotEmpty(t.t, fundResp.Batch.BatchPsbt)

	// Now we can add all the asset requests created above.
	BuildMintingBatch(t.t, aliceTapd, assetReqs)

	// If we request a verbose list of batches, we should receive asset
	// group information for exactly 3 assets.
	listBatchResp, err := aliceTapd.ListBatches(
		ctxt, &mintrpc.ListBatchRequest{
			Verbose: true,
		})
	require.NoError(t.t, err)
	require.Len(t.t, listBatchResp.Batches, 1)

	unsealedAssets := listBatchResp.Batches[0].UnsealedAssets
	unsealedAssetCount := fn.Count(
		unsealedAssets, func(a *mintrpc.UnsealedAsset) bool {
			return a.GroupKeyRequest != nil &&
				a.GroupVirtualTx != nil
		},
	)
	require.Equal(t.t, 3, unsealedAssetCount)

	findUnsealedAsset := func(name string,
		assets []*mintrpc.UnsealedAsset) *mintrpc.UnsealedAsset {

		targetAsset, err := fn.First(
			assets, func(a *mintrpc.UnsealedAsset) bool {
				return a.Asset.Name == name
			},
		)
		require.NoError(t.t, err)

		return targetAsset
	}

	// Fetch the responses that match the three grouped asset requests.
	assetGroupedInternalTweaked := findUnsealedAsset(
		assetReqGroupedInternalTweaked.Asset.Name, unsealedAssets,
	)
	assetGroupedExternal := findUnsealedAsset(
		assetReqGroupedExternal.Asset.Name, unsealedAssets,
	)
	assetGroupMember := findUnsealedAsset(
		assetReqGroupMember.Asset.Name, unsealedAssets,
	)

	// Since Asset 3 set Asset 1 as its group anchor, their group key
	// requests should overlap. The internal group key and anchor genesis
	// should match, but the new asset should differ.
	AssertAssetGenesis(
		t.t, assetGroupedInternalTweaked.GroupKeyRequest.AnchorGenesis,
		assetGroupMember.GroupKeyRequest.AnchorGenesis,
	)
	require.Equal(
		t.t, assetGroupedInternalTweaked.GroupKeyRequest.RawKey,
		assetGroupMember.GroupKeyRequest.RawKey,
	)
	require.NotEqual(
		t.t, assetGroupedInternalTweaked.GroupKeyRequest.NewAsset,
		assetGroupMember.GroupKeyRequest.NewAsset,
	)

	// Now we can construct any asset group witnesses needed. Before
	// performing any signing, we'll create a GenesisSigner backed by
	// Alice's LND node, which also derived all keypairs so far.
	aliceLndSigner := taprootassets.NewLndRpcVirtualTxSigner(
		&aliceLndClient.LndServices,
	)

	// For Asset 2, we'll derive a standard signature (key spend path).
	groupedExternalGroupKeyRequest, groupedExternalVirtualTx :=
		unmarshalPendingAssetGroup(t.t, assetGroupedExternal)
	groupedExternalAssetID, groupedExternalProtoAsset :=
		fetchProtoAssetInfo(groupedExternalGroupKeyRequest)

	groupedExternalGroupKey, err := asset.DeriveGroupKey(
		aliceLndSigner, groupedExternalVirtualTx,
		groupedExternalGroupKeyRequest, nil,
	)
	require.NoError(t.t, err)

	validateGroupWitness(
		t.t, groupedExternalProtoAsset, groupedExternalGroupKey,
	)

	groupedExternalWitness := taprpc.GroupWitness{
		GenesisId: groupedExternalAssetID[:],
		Witness:   groupedExternalGroupKey.Witness,
	}

	// For Asset 3, we'll use a hash preimage as the asset group witness.
	groupMemberGroupKeyRequest, groupMemberVirtualTx :=
		unmarshalPendingAssetGroup(t.t, assetGroupMember)
	groupMemberAssetID, groupMemberProtoAsset :=
		fetchProtoAssetInfo(groupMemberGroupKeyRequest)

	// To build the control block for the hash lock, we first need to
	// derive the singly tweaked group key. From there we can build the
	// partial reveal of the hash lock script, and then finally the control
	// block.
	groupMemberAnchorID := groupMemberGroupKeyRequest.AnchorGen.ID()
	groupMemberGroupInternalKey := groupMemberGroupKeyRequest.RawKey
	groupMemberSinglyTweakedKey := input.TweakPubKeyWithTweak(
		groupMemberGroupInternalKey.PubKey, groupMemberAnchorID[:],
	)
	hashLockControlBlock, err := buildScriptSpendControlBlock(
		groupMemberSinglyTweakedKey, groupInternalHashLock,
		groupInternalTapTree,
	)
	require.NoError(t.t, err)

	// With the control block, we can construct the full asset group
	// witness, apply it to the asset, and verify it before submitting it
	// to tapd.
	hashLockWitness := wire.TxWitness{
		test.DefaultHashLockWitness, groupInternalHashLock.Script,
		hashLockControlBlock,
	}
	groupMemberWitness := taprpc.GroupWitness{
		GenesisId: groupMemberAssetID[:],
		Witness:   hashLockWitness,
	}
	groupMemberGroupKey := &asset.GroupKey{
		RawKey:        groupMemberGroupInternalKey,
		GroupPubKey:   groupMemberVirtualTx.TweakedKey,
		TapscriptRoot: groupMemberGroupKeyRequest.TapscriptRoot,
		Witness:       hashLockWitness,
	}

	validateGroupWitness(
		t.t, groupMemberProtoAsset, groupMemberGroupKey,
	)
	t.Logf("Asset 3 group witness:\n%v", toJSON(t.t, &groupMemberWitness))

	// With the two group witnesses, we can seal the batch. This will
	// validate the witnesses given, generate a witness for Asset 1, and
	// persist these witnesses to be used during batch finalization.
	sealReq := mintrpc.SealBatchRequest{
		GroupWitnesses: []*taprpc.GroupWitness{
			&groupMemberWitness, &groupedExternalWitness,
		},
	}
	sealResp, err := aliceTapd.SealBatch(ctxt, &sealReq)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, sealResp.Batch)

	// With the batch sealed successfully, we can now finalize it and
	// broadcast the anchor TX.
	ctxc, streamCancel := context.WithCancel(context.Background())
	stream, err := aliceTapd.SubscribeMintEvents(
		ctxc, &mintrpc.SubscribeMintEventsRequest{},
	)
	require.NoError(t.t, err)
	sub := &EventSubscription[*mintrpc.MintEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	batchTXID, batchKey := FinalizeBatchUnconfirmed(
		t.t, t.lndHarness.Miner().Client, aliceTapd, assetReqs,
	)
	batchAssets := ConfirmBatch(
		t.t, t.lndHarness.Miner().Client, aliceTapd, assetReqs, sub,
		batchTXID, batchKey,
	)
	assetTweakedScriptKey, err := fn.First(
		batchAssets, func(a *taprpc.Asset) bool {
			return assetReqWithScriptKey.Asset.Name ==
				a.AssetGenesis.Name
		})
	require.NoError(t.t, err)

	// We should have one group with two assets and a balance of 2. The
	// other should have one asset with a balance of 5000.
	collectibleGroupKey := groupMemberVirtualTx.TweakedKey
	collectibleGroupKeyHex := hex.EncodeToString(
		collectibleGroupKey.SerializeCompressed(),
	)
	normalGroupKey := assetGroupedExternal.GroupVirtualTx.TweakedKey
	groupCount := 2
	AssertNumGroups(t.t, aliceTapd, groupCount)
	AssertBalanceByGroup(t.t, aliceTapd, collectibleGroupKeyHex, 2)
	AssertBalanceByGroup(
		t.t, aliceTapd, hex.EncodeToString(normalGroupKey), 5000,
	)

	// Let's make sure Bob receives minting proofs for this batch, and
	// verify that he syncs the assets correctly.
	SyncUniverses(
		ctxt, t.t, bobTapd, aliceTapd, aliceTapd.rpcHost(),
		defaultTimeout,
	)

	// If we fetch issuance leaves for the collectible asset group, we
	// should have synced the asset group witnesses for each asset.
	collectibleGroupUniID := universe.Identifier{
		GroupKey:  &collectibleGroupKey,
		ProofType: universe.ProofTypeIssuance,
	}
	rpcCollectibleGroupUniID, err := taprootassets.MarshalUniID(
		collectibleGroupUniID,
	)
	require.NoError(t.t, err)
	collectibleGroupLeaves, err := bobTapd.AssetLeaves(
		ctxt, rpcCollectibleGroupUniID,
	)
	require.NoError(t.t, err)
	require.Len(t.t, collectibleGroupLeaves.Leaves, 2)

	// We can then assert that Bob received and verified the hash lock asset
	// group witness we created earlier.
	matchingLeaf := false
	for _, leaf := range collectibleGroupLeaves.Leaves {
		leafGroupWitness := leaf.Asset.PrevWitnesses[0].TxWitness
		for i, witElem := range hashLockWitness {
			if !bytes.Equal(leafGroupWitness[i], witElem) {
				break
			}
		}

		matchingLeaf = true
		break
	}
	require.True(t.t, matchingLeaf)

	// Now, let's try to transfer the ungrouped asset minted with a tweaked
	// script key to Bob. We'll use the PSBT flow to add witnesses for the
	// asset script key and minting anchor output.
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: assetTweakedScriptKey.AssetGenesis.AssetId,
		Amt:     assetTweakedScriptKey.Amount / 2,
	})
	require.NoError(t.t, err)

	// We only have script encumbered assets now, so selecting BIP-086 only
	// assets should result in an error.
	const bip86Only = wrpc.CoinSelectType_COIN_SELECT_BIP86_ONLY
	_, err = aliceTapd.FundVirtualPsbt(
		ctxt, &wrpc.FundVirtualPsbtRequest{
			Template: &wrpc.FundVirtualPsbtRequest_Raw{
				Raw: &wrpc.TxTemplate{
					Recipients: map[string]uint64{
						bobAddr.Encoded: 1,
					},
				},
			},
			CoinSelectType: bip86Only,
		},
	)
	require.ErrorContains(
		t.t, err, "failed to find coin(s) that satisfy given "+
			"constraints",
	)

	signedAddrPsbt, signedPassivePsbts := signTransferWithTweakedScriptKey(
		t, ctxt, aliceTapd, bobAddr, &tweakedScript, 2,
		tweakedScriptSigLock, tweakedScriptTapTree,
	)

	// With all assets signed, we can now create the anchor PSBT for the
	// transfer. We'll make a template PSBT first, and then Alice's tapd
	// will commit all virtual transactions to that PSBT. If needed, an
	// input and change output will be added to cover chain fees.
	allSignedPsbts := append(signedAddrPsbt, signedPassivePsbts...)
	transferTemplatePkt, err := tapsend.PrepareAnchoringTemplate(
		allSignedPsbts,
	)
	require.NoError(t.t, err)

	transferPkt, bobVpsbt, passiveVpsbts, commitResp := CommitVirtualPsbts(
		t.t, aliceTapd, transferTemplatePkt, signedAddrPsbt,
		signedPassivePsbts, -1,
	)

	// The last step is constructing a witness for the transfer anchor
	// input, which is the genesis output from the minting batch. We'll
	// satisfy the 2-of-2 multisig script we specified when funding the
	// batch.
	// To build the control block, we need the internal key from that
	// output, and the Taproot Asset root hash used for that batch. This
	// output is currently leased for the transfer we're constructing.
	assetInputIdx := uint32(0)
	aliceUtxoResp, err := aliceTapd.ListUtxos(
		ctxt, &taprpc.ListUtxosRequest{
			IncludeLeased: true,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, aliceUtxoResp.ManagedUtxos, 1)
	anchorOutpoint := wire.OutPoint{
		Hash:  batchTXID,
		Index: 0,
	}
	anchorUTXO, ok := aliceUtxoResp.ManagedUtxos[anchorOutpoint.String()]
	require.True(t.t, ok)

	anchorInputWitness := signMultisigAnchorScript(
		t.t, aliceLnd.RPC, regtestParams, transferPkt, assetInputIdx,
		firstAnchorInternal, secondAnchorInternal, anchorUTXO,
		anchorMultisigScript,
	)

	var witBuf bytes.Buffer
	err = psbt.WriteTxWitness(&witBuf, anchorInputWitness)
	require.NoError(t.t, err)

	transferPkt.Inputs[assetInputIdx].FinalScriptWitness = witBuf.Bytes()

	// Finalize and publish the transfer anchor TX.
	signedPkt := FinalizePacket(t.t, aliceLnd.RPC, transferPkt)
	logResp := LogAndPublish(
		t.t, aliceTapd, signedPkt, bobVpsbt, passiveVpsbts,
		commitResp,
	)
	t.Logf("Logged transaction: %v", toJSON(t.t, logResp))

	// Mine a block and confirm that Alice registers the transfer correctly.
	transferAmount := assetTweakedScriptKey.Amount / 2
	numOutputs := 2
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, aliceTapd, logResp,
		assetTweakedScriptKey.AssetGenesis.AssetId,
		[]uint64{transferAmount, transferAmount}, 0, 1, numOutputs,
	)

	// Bob should have detected the transfer, and now own half of the total
	// asset supply.
	AssertAddrEvent(t.t, bobTapd, bobAddr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertBalanceByID(
		t.t, bobTapd, assetTweakedScriptKey.AssetGenesis.AssetId,
		assetTweakedScriptKey.Amount/2,
	)

	// Alice's balance for the passive assets should be the same.
	AssertNumGroups(t.t, aliceTapd, groupCount)
	AssertBalanceByGroup(t.t, aliceTapd, collectibleGroupKeyHex, 2)
	AssertBalanceByGroup(
		t.t, aliceTapd, hex.EncodeToString(normalGroupKey), 5000,
	)

	// None of the anchor outputs should have a tapscript sibling.
	fn.All(logResp.Transfer.Outputs, func(out *taprpc.TransferOutput) bool {
		anchor := out.Anchor
		return bytes.Equal(anchor.TaprootAssetRoot, anchor.MerkleRoot)
	})
}

// Derive a random key on an LND node, with a key family not matching the
// Taproot Assets key family.
func deriveRandomKey(t *testing.T, ctxt context.Context,
	keyRing *taprootassets.LndRpcKeyRing) keychain.KeyDescriptor {

	var (
		randFam = test.RandInt31n(math.MaxInt32)
		randInd = test.RandInt31n(255)
		desc    keychain.KeyDescriptor
		err     error
	)

	// Ensure that we use a different key family from tapd.
	for randFam == asset.TaprootAssetsKeyFamily {
		randFam = test.RandInt31n(math.MaxInt32)
	}

	desc, err = keyRing.DeriveNextKey(
		ctxt, keychain.KeyFamily(randFam),
	)
	require.NoError(t, err)

	// Set the desired key index to always be beyond the current
	// index.
	randInd += int32(desc.KeyLocator.Index)
	for i := int32(0); i < randInd; i++ {
		desc, err = keyRing.DeriveNextKey(
			ctxt, keychain.KeyFamily(randFam),
		)
		require.NoError(t, err)
	}

	return desc
}

func buildTweakedScriptKey(t *testing.T, internalKey *keychain.KeyDescriptor,
	hashLockWitness []byte, sigLockKey *btcec.PublicKey) (asset.ScriptKey,
	*txscript.IndexedTapScriptTree) {

	tweakedScriptHashLock := test.ScriptHashLock(
		t, bytes.Clone(hashLockWitness),
	)
	tweakedScriptSigLock := test.ScriptSchnorrSig(t, sigLockKey)
	tapTree := txscript.AssembleTaprootScriptTree(
		tweakedScriptHashLock, tweakedScriptSigLock,
	)
	scriptTweak := tapTree.RootNode.TapHash()
	tweakedPubKey := txscript.ComputeTaprootOutputKey(
		internalKey.PubKey, scriptTweak[:],
	)

	tweakedScriptKey := asset.ScriptKey{
		PubKey: tweakedPubKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: *internalKey,
			Tweak:  scriptTweak[:],
		},
	}

	return tweakedScriptKey, tapTree
}

func computeGroupKeyTweak(t *testing.T, sigLockKey *btcec.PublicKey,
	useHashLock bool) ([]byte, txscript.TapLeaf,
	*txscript.IndexedTapScriptTree) {

	hashLock := test.ScriptHashLock(
		t, bytes.Clone(test.DefaultHashLockWitness),
	)
	sigLock := test.ScriptSchnorrSig(t, sigLockKey)
	tapTree := txscript.AssembleTaprootScriptTree(hashLock, sigLock)
	tapTweak := tapTree.RootNode.TapHash()

	if useHashLock {
		return tapTweak[:], hashLock, tapTree
	}

	return tapTweak[:], sigLock, tapTree
}

func buildMultisigTapLeaf(t *testing.T,
	pubkey1, pubkey2 *btcec.PublicKey) ([]byte,
	mintrpc.FundBatchRequest_FullTree) {

	multisigScript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(pubkey1)).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(pubkey2)).
		AddOp(txscript.OP_CHECKSIGADD).
		AddInt64(2).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	multisigLeaf := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      multisigScript,
	}
	rpcLeaf := taprpc.TapLeaf{
		Script: multisigLeaf.Script,
	}
	siblingReq := mintrpc.FundBatchRequest_FullTree{
		FullTree: &taprpc.TapscriptFullTree{
			AllLeaves: []*taprpc.TapLeaf{&rpcLeaf},
		},
	}

	return multisigScript, siblingReq
}

func unmarshalPendingAssetGroup(t *testing.T,
	a *mintrpc.UnsealedAsset) (asset.GroupKeyRequest,
	asset.GroupVirtualTx) {

	require.NotNil(t, a.GroupVirtualTx)
	virtualTx, err := taprpc.UnmarshalGroupVirtualTx(a.GroupVirtualTx)
	require.NoError(t, err)

	require.NotNil(t, a.GroupKeyRequest)
	keyReq, err := taprpc.UnmarshalGroupKeyRequest(a.GroupKeyRequest)
	require.NoError(t, err)

	return *keyReq, *virtualTx
}

func buildScriptSpendControlBlock(singlyTweakedKey *btcec.PublicKey,
	usedLeaf txscript.TapLeaf,
	tapTree *txscript.IndexedTapScriptTree) ([]byte, error) {

	leafTapHash := usedLeaf.TapHash()
	tapscriptProofIdx := tapTree.LeafProofIndex[leafTapHash]
	tapscriptProof := tapTree.LeafMerkleProofs[tapscriptProofIdx]
	partialReveal := input.TapscriptPartialReveal(
		singlyTweakedKey, usedLeaf, tapscriptProof.InclusionProof,
	)

	return partialReveal.ControlBlock.ToBytes()
}

func signTransferWithTweakedScriptKey(t *harnessTest, ctxt context.Context,
	sender *tapdHarness, addr *taprpc.Addr, scriptKey *asset.ScriptKey,
	passiveAssetCount int, sigLockLeaf txscript.TapLeaf,
	tapTree *txscript.IndexedTapScriptTree) ([]*tappsbt.VPacket,
	[]*tappsbt.VPacket) {

	encodeVpsbt := func(psbt *tappsbt.VPacket) []byte {
		var b bytes.Buffer
		require.NoError(t.t, psbt.Serialize(&b))
		return b.Bytes()
	}
	decodeVpsbt := func(psbt []byte) *tappsbt.VPacket {
		vpsbt, err := tappsbt.NewFromRawBytes(
			bytes.NewReader(psbt), false,
		)
		require.NoError(t.t, err)
		return vpsbt
	}

	// The sender will build a set of vPSBTs representing the transfer and
	// moving the other assets from the same minting batch.
	fundAddrResp := fundAddressSendPacket(t, sender, addr)
	fundedPacket := decodeVpsbt(fundAddrResp.FundedPsbt)
	require.Len(t.t, fundAddrResp.PassiveAssetPsbts, passiveAssetCount+1)

	// We'll use the sig lock of the tweaked script key to build our
	// asset transfer witness.
	tweakedScriptControlBlock, err := buildScriptSpendControlBlock(
		scriptKey.RawKey.PubKey, sigLockLeaf, tapTree,
	)
	require.NoError(t.t, err)

	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: tweakedScriptControlBlock,
			Script:       sigLockLeaf.Script,
			LeafVersion:  sigLockLeaf.LeafVersion,
		},
	}
	sigLockLeafHash := sigLockLeaf.TapHash()
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		sigLockLeafHash[:],
	}

	// With the sig lock information added, the sender's tapd can create the
	// sig lock witness.
	signedAddrResp, err := sender.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: encodeVpsbt(fundedPacket),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedAddrResp.SignedInputs, uint32(0))

	// We also need to sign a transfer for the other assets of the minting
	// batch.
	signedAddrPsbt := []*tappsbt.VPacket{
		decodeVpsbt(signedAddrResp.SignedPsbt),
	}
	signedPassivePsbts := []*tappsbt.VPacket{}
	for i := range fundAddrResp.PassiveAssetPsbts {
		passiveResp, err := sender.SignVirtualPsbt(
			ctxt, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundAddrResp.PassiveAssetPsbts[i],
			},
		)
		require.NoError(t.t, err)

		signedPassivePsbts = append(
			signedPassivePsbts, decodeVpsbt(passiveResp.SignedPsbt),
		)
	}

	return signedAddrPsbt, signedPassivePsbts
}

func signMultisigAnchorScript(t *testing.T, lnd *rpc.HarnessRPC,
	params *chaincfg.Params, pkt *psbt.Packet, inputIndex uint32,
	key1, key2 keychain.KeyDescriptor, utxo *taprpc.ManagedUtxo,
	multisigScript []byte) wire.TxWitness {

	anchorInputInternalKey, err := btcec.ParsePubKey(utxo.InternalKey)
	require.NoError(t, err)

	anchorInputOutputKey := txscript.ComputeTaprootOutputKey(
		anchorInputInternalKey, utxo.MerkleRoot,
	)
	anchorKeyYIsOdd := anchorInputOutputKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd

	anchorInputControlBlock := txscript.ControlBlock{
		InternalKey:     anchorInputInternalKey,
		OutputKeyYIsOdd: anchorKeyYIsOdd,
		LeafVersion:     txscript.BaseLeafVersion,
		InclusionProof:  utxo.TaprootAssetRoot,
	}
	anchorInputControlBlockBytes, err := anchorInputControlBlock.ToBytes()
	require.NoError(t, err)

	// With our control block, we can generate the two needed signatures
	// and construct the anchor witness.
	anchorMultisigLeaf := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      multisigScript,
	}
	firstKeyPartialSig := partialSignWithKey(
		t, lnd, params, pkt, inputIndex, key1,
		anchorInputControlBlockBytes, anchorMultisigLeaf,
	)
	secondKeyPartialSig := partialSignWithKey(
		t, lnd, params, pkt, inputIndex, key2,
		anchorInputControlBlockBytes, anchorMultisigLeaf,
	)

	anchorInputWitness := wire.TxWitness{
		secondKeyPartialSig,
		firstKeyPartialSig,
		multisigScript,
		anchorInputControlBlockBytes,
	}

	return anchorInputWitness
}

func fetchProtoAssetInfo(groupReq asset.GroupKeyRequest) (asset.ID,
	*asset.Asset) {

	return groupReq.NewAsset.ID(), groupReq.NewAsset
}

func validateGroupWitness(t *testing.T, protoAsset *asset.Asset,
	newGroup *asset.GroupKey) {

	assetWithGroup := protoAsset.Copy()
	assetWithGroup.GroupKey = newGroup
	assetWithGroup.PrevWitnesses[0].TxWitness = newGroup.Witness

	witnessValidator := taprootassets.ValidatorV0{}
	err := witnessValidator.Execute(
		assetWithGroup, nil, nil, proof.MockChainLookup,
	)
	require.NoError(t, err)
}
