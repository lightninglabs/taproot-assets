package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/lndclient"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
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

	displayGroupWitness := func(wit *taprpc.GroupWitness) string {
		return fmt.Sprintf(
			"genID: %x\nWitness: %x\n",
			wit.GenesisId, wit.Witness,
		)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Derive a random key on an LND node, with a key family not matching
	// the Taproot Assets key family.
	deriveRandomKey := func(lnd *node.HarnessNode) keychain.KeyDescriptor {
		randFam := test.RandInt31n(math.MaxInt32)
		for randFam == asset.TaprootAssetsKeyFamily {
			randFam = test.RandInt31n(math.MaxInt32)
		}

		descResp := lnd.RPC.DeriveKey(&signrpc.KeyLocator{
			KeyFamily: randFam,
			KeyIndex:  test.RandInt31n(math.MaxInt32),
		})
		loc := keychain.KeyLocator{
			Family: keychain.KeyFamily(
				descResp.KeyLoc.KeyFamily,
			),
			Index: uint32(descResp.KeyLoc.KeyIndex),
		}
		pubkey, err := btcec.ParsePubKey(
			descResp.RawKeyBytes,
		)
		require.NoError(t.t, err)

		return keychain.KeyDescriptor{
			KeyLocator: loc,
			PubKey:     pubkey,
		}
	}
	_ = deriveRandomKey(aliceLnd)

	// Let's derive the keys and tapscript trees we'll use.
	// tweakedScript will have an internal key not managed by a tapd, and
	// a tapscript root with a hashlock and a single sig script.
	// TODO(jhb): Use a fully external key
	// tweakedScriptDesc := deriveRandomKey(aliceLnd)
	_, tweakedScriptDesc := DeriveKeys(t.t, aliceTapd)
	tweakedScriptHashLock := test.ScriptHashLock(
		t.t, bytes.Clone(test.DefaultHashLockWitness),
	)
	tweakedScriptSigLock := test.ScriptSchnorrSig(
		t.t, tweakedScriptDesc.PubKey,
	)
	tweakedScriptTapTree := txscript.AssembleTaprootScriptTree(
		tweakedScriptHashLock, tweakedScriptSigLock,
	)
	tweakedScriptTweak := txscript.NewTapBranch(
		tweakedScriptTapTree.RootNode.Left(),
		tweakedScriptTapTree.RootNode.Right(),
	).TapHash()
	tweakedScriptPubkey := txscript.ComputeTaprootOutputKey(
		tweakedScriptDesc.PubKey, tweakedScriptTweak[:],
	)

	tweakedScript := asset.ScriptKey{
		PubKey: tweakedScriptPubkey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: tweakedScriptDesc,
			Tweak:  tweakedScriptTweak[:],
		},
	}

	// managedGroupInternal will be an internal key we generate via a tapd
	// RPC call, and then set for a specific asset group.
	_, managedGroupInternal := DeriveKeys(t.t, aliceTapd)

	// groupInternalSigLockKey will be an internal key used only for the
	// signature locking script of an asset group.
	_, groupInternalSigLockKey := DeriveKeys(t.t, aliceTapd)
	groupInternalHashLock := test.ScriptHashLock(
		t.t, bytes.Clone(test.DefaultHashLockWitness),
	)
	groupInternalSigLock := test.ScriptSchnorrSig(
		t.t, groupInternalSigLockKey.PubKey,
	)
	groupInternalTapTree := txscript.AssembleTaprootScriptTree(
		groupInternalHashLock, groupInternalSigLock,
	)

	// groupInternalTweak will be the tapscript tweak we apply to
	// managedGroupInternal.
	groupInternalTweak := txscript.NewTapBranch(
		groupInternalTapTree.RootNode.Left(),
		groupInternalTapTree.RootNode.Right(),
	).TapHash()

	// groupExternal will be a group internal key not managed by a tapd,
	// that will also have a tapscript tweak.
	// TODO(jhb): Use a fully external key
	_, groupExternalDesc := DeriveKeys(t.t, aliceTapd)

	// groupExternalTweak will be the tapscript tweak we apply to
	// groupExternal. We'll use random bytes as we don't intend to use the
	// script spend path at all.
	groupExternalTweak := test.RandBytes(32)

	// firstAnchorInternal and secondAnchorInternal will be the two keys
	// used in the multisig for the genesis output.
	_, firstAnchorInternal := DeriveKeys(t.t, aliceTapd)
	_, secondAnchorInternal := DeriveKeys(t.t, aliceTapd)

	// anchorTapTree will be a tapscript tree with a hashlock and a 2-of-2
	// multisig script.
	anchorMultisigScript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(firstAnchorInternal.PubKey)).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(secondAnchorInternal.PubKey)).
		AddOp(txscript.OP_CHECKSIGADD).
		AddInt64(2).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t.t, err)

	anchorMultisigLeaf := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      anchorMultisigScript,
	}
	rpcAnchorLeaf := taprpc.TapLeaf{
		Script: anchorMultisigLeaf.Script,
	}
	siblingReq := mintrpc.FundBatchRequest_FullTree{
		FullTree: &taprpc.TapscriptFullTree{
			AllLeaves: []*taprpc.TapLeaf{&rpcAnchorLeaf},
		},
	}

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
		GroupTapscriptRoot = groupInternalTweak[:]

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
		assetReqGroupedExternal,
		assetReqGroupMember,
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

	// Fetch the responses that match the three grouped asset requests.
	assetGroupedInternalTweaked, err := fn.First(
		unsealedAssets, func(a *mintrpc.UnsealedAsset) bool {
			return a.Asset.Name ==
				assetReqGroupedInternalTweaked.Asset.Name
		})
	require.NoError(t.t, err)
	assetGroupedExternal, err := fn.First(
		unsealedAssets, func(a *mintrpc.UnsealedAsset) bool {
			return a.Asset.Name ==
				assetReqGroupedExternal.Asset.Name
		})
	require.NoError(t.t, err)
	assetGroupMember, err := fn.First(
		unsealedAssets, func(a *mintrpc.UnsealedAsset) bool {
			return a.Asset.Name == assetReqGroupMember.Asset.Name
		})
	require.NoError(t.t, err)

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

	// For Asset 1, the group anchor for Asset 3, we'll use the signature
	// locking script spend path.
	internalTweakedVirtualTx, err := taprpc.UnmarshalGroupVirtualTx(
		assetGroupedInternalTweaked.GroupVirtualTx,
	)
	require.NoError(t.t, err)
	internalTweakedGroupKeyRequest, err := taprpc.UnmarshalGroupKeyRequest(
		assetGroupedInternalTweaked.GroupKeyRequest,
	)
	require.NoError(t.t, err)

	// To build the control block for the sig lock, we first need to
	// derive the singly tweaked group key. From there we can build the
	// partial reveal of the sig lock script, and then finally the control
	// block.
	internalTweakedAnchorID := internalTweakedGroupKeyRequest.AnchorGen.ID()
	internalTweakedSinglyTweakedKey := input.TweakPubKeyWithTweak(
		managedGroupInternal.PubKey, internalTweakedAnchorID[:],
	)
	sigLockControlBlock, err := BuildScriptSpendControlBlock(
		internalTweakedSinglyTweakedKey, groupInternalSigLock,
		groupInternalTapTree,
	)
	require.NoError(t.t, err)

	// To produce the correct signature, we need to use the key used to
	// build the signature lock, and without any tweaks.
	signDesc := lndclient.SignDescriptor{
		KeyDesc:       groupInternalSigLockKey,
		Output:        &internalTweakedVirtualTx.PrevOut,
		HashType:      txscript.SigHashDefault,
		InputIndex:    0,
		SignMethod:    input.TaprootScriptSpendSignMethod,
		WitnessScript: groupInternalSigLock.Script,
	}
	sig, err := aliceLndSigner.SignVirtualTx(
		&signDesc, &internalTweakedVirtualTx.Tx,
		&internalTweakedVirtualTx.PrevOut,
	)
	require.NoError(t.t, err)

	// After we have the signature, we can construct the full asset group
	// witness, apply it to the asset, and verify it before submitting it
	// to tapd.
	internalTweakedGroupWitness := wire.TxWitness{
		sig.Serialize(), signDesc.WitnessScript, sigLockControlBlock,
	}
	internalTweakedGroupKey := &asset.GroupKey{
		RawKey:        internalTweakedGroupKeyRequest.RawKey,
		GroupPubKey:   internalTweakedVirtualTx.TweakedKey,
		TapscriptRoot: internalTweakedGroupKeyRequest.TapscriptRoot,
		Witness:       internalTweakedGroupWitness,
	}
	internalTweakedAsset := ApplyGroupWitness(
		internalTweakedGroupKeyRequest.NewAsset,
		internalTweakedGroupKey,
	)

	groupWitnessValidator := taprootassets.ValidatorV0{}
	err = groupWitnessValidator.Execute(internalTweakedAsset, nil, nil)
	require.NoError(t.t, err)

	internalTweakedWitness := taprpc.GroupWitness{
		GenesisId: internalTweakedAnchorID[:],
		Witness:   internalTweakedGroupKey.Witness,
	}
	t.Logf(
		"Asset 1 group witness:\n%v",
		displayGroupWitness(&internalTweakedWitness),
	)

	// For Asset 3, we'll use a hash preimage as the asset group witness.
	groupMemberVirtualTx, err := taprpc.UnmarshalGroupVirtualTx(
		assetGroupMember.GroupVirtualTx,
	)
	require.NoError(t.t, err)
	groupMemberGroupKeyRequest, err := taprpc.UnmarshalGroupKeyRequest(
		assetGroupMember.GroupKeyRequest,
	)
	require.NoError(t.t, err)

	// To build the control block for the hash lock, we first need to
	// derive the singly tweaked group key. From there we can build the
	// partial reveal of the hash lock script, and then finally the control
	// block.
	groupMemberAnchorID := groupMemberGroupKeyRequest.AnchorGen.ID()
	groupMemberGroupInternalKey := groupMemberGroupKeyRequest.RawKey
	groupMemberSinglyTweakedKey := input.TweakPubKeyWithTweak(
		groupMemberGroupInternalKey.PubKey, groupMemberAnchorID[:],
	)
	hashLockControlBlock, err := BuildScriptSpendControlBlock(
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
	groupMemberAssetID := groupMemberGroupKeyRequest.NewAsset.ID()
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
	groupMemberAsset := ApplyGroupWitness(
		groupMemberGroupKeyRequest.NewAsset,
		groupMemberGroupKey,
	)

	err = groupWitnessValidator.Execute(groupMemberAsset, nil, nil)
	require.NoError(t.t, err)
	t.Logf(
		"Asset 3 group witness:\n%v",
		displayGroupWitness(&groupMemberWitness),
	)

	// With the two group witnesses, we can seal the batch. This will
	// validate the witnesses given, generate a witness for Asset 1, and
	// persist these witnesses to be used during batch finalization.
	sealReq := mintrpc.SealBatchRequest{
		GroupWitnesses: []*taprpc.GroupWitness{
			&groupMemberWitness, &internalTweakedWitness,
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
		t.t, t.lndHarness.Miner.Client, aliceTapd, assetReqs,
	)
	batchAssets := ConfirmBatch(
		t.t, t.lndHarness.Miner.Client, aliceTapd, assetReqs, sub,
		batchTXID, batchKey,
	)
	assetTweakedScriptKey, err := fn.First(
		batchAssets, func(a *taprpc.Asset) bool {
			return assetReqWithScriptKey.Asset.Name ==
				a.AssetGenesis.Name
		})
	require.NoError(t.t, err)

	// We should have one group with two assets and a balance of 2. The
	// The other should have one asset with a balance of 5000.
	collectibleGroupKey := internalTweakedVirtualTx.TweakedKey
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

	uniLeafMatchingWitness := func(leaf *universerpc.AssetLeaf,
		wit *wire.TxWitness) bool {

		leafGroupWitness := leaf.Asset.PrevWitnesses[0].TxWitness
		for i, witElem := range *wit {
			if !bytes.Equal(leafGroupWitness[i], witElem) {
				return false
			}
		}

		return true
	}

	// We can then assert that Bob received and verified the custom asset
	// group witnesses we created earlier.
	require.True(t.t, fn.Any(
		collectibleGroupLeaves.Leaves,
		func(leaf *universerpc.AssetLeaf) bool {
			return uniLeafMatchingWitness(leaf, &hashLockWitness)
		},
	))
	require.True(t.t, fn.Any(
		collectibleGroupLeaves.Leaves,
		func(leaf *universerpc.AssetLeaf) bool {
			return uniLeafMatchingWitness(
				leaf, &internalTweakedGroupWitness,
			)
		},
	))

	// Now, let's try to transfer the ungrouped asset minted with a tweaked
	// script key to Bob. We'll use the PSBT flow to add witnesses for the
	// asset script key and minting anchor output.
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: assetTweakedScriptKey.AssetGenesis.AssetId,
		Amt:     assetTweakedScriptKey.Amount / 2,
	})
	require.NoError(t.t, err)

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

	// Alice will build a set of vPSBTs representing the transfer and
	// moving the other 3 assets from the same minting batch.
	fundBobResp := fundAddressSendPacket(t, aliceTapd, bobAddr)
	fundedPacket := decodeVpsbt(fundBobResp.FundedPsbt)
	require.Len(t.t, fundBobResp.PassiveAssetPsbts, 3)

	// We'll use the sig lock of the tweaked script key to build our
	// asset transfer witness.
	tweakedScriptControlBlock, err := BuildScriptSpendControlBlock(
		tweakedScriptDesc.PubKey, tweakedScriptSigLock,
		tweakedScriptTapTree,
	)
	require.NoError(t.t, err)

	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: tweakedScriptControlBlock,
			Script:       tweakedScriptSigLock.Script,
			LeafVersion:  tweakedScriptSigLock.LeafVersion,
		},
	}
	sigLockLeafHash := tweakedScriptSigLock.TapHash()
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		sigLockLeafHash[:],
	}

	// With the sig lock information added, Alice's tapd can create the
	// sig lock witness.
	signedBobResp, err := aliceTapd.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: encodeVpsbt(fundedPacket),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedBobResp.SignedInputs, uint32(0))

	// We also need to sign a transfer for the other assets of the minting
	// batch.
	signedBobPsbt := []*tappsbt.VPacket{
		decodeVpsbt(signedBobResp.SignedPsbt),
	}
	signedPassivePsbts := []*tappsbt.VPacket{}
	for i := range fundBobResp.PassiveAssetPsbts {
		passiveResp, err := aliceTapd.SignVirtualPsbt(
			ctxt, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundBobResp.PassiveAssetPsbts[i],
			},
		)
		require.NoError(t.t, err)

		signedPassivePsbts = append(
			signedPassivePsbts, decodeVpsbt(passiveResp.SignedPsbt),
		)
	}

	// With all assets signed, we can now create the anchor PSBT for the
	// transfer. We'll make a template PSBT first, and then Alice's tapd
	// will commit all virtual transactions to that PSBT. If needed, an
	// input and change output will be added to cover chain fees.
	allSignedPsbts := append(signedBobPsbt, signedPassivePsbts...)
	transferTemplatePkt, err := tapsend.PrepareAnchoringTemplate(
		allSignedPsbts,
	)
	require.NoError(t.t, err)

	transferPkt, bobVpsbt, passiveVpsbts, commitResp := CommitVirtualPsbts(
		t.t, aliceTapd, transferTemplatePkt, signedBobPsbt,
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

	anchorInputInternalKey, err := btcec.ParsePubKey(anchorUTXO.InternalKey)
	require.NoError(t.t, err)

	anchorInputOutputKey := txscript.ComputeTaprootOutputKey(
		anchorInputInternalKey, anchorUTXO.MerkleRoot,
	)
	anchorKeyYIsOdd := anchorInputOutputKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd

	anchorInputControlBlock := txscript.ControlBlock{
		InternalKey:     anchorInputInternalKey,
		OutputKeyYIsOdd: anchorKeyYIsOdd,
		LeafVersion:     txscript.BaseLeafVersion,
		InclusionProof:  anchorUTXO.TaprootAssetRoot,
	}
	anchorInputControlBlockBytes, err := anchorInputControlBlock.ToBytes()
	require.NoError(t.t, err)

	// With our control block, we can generate the two needed signatures
	// and construct the anchor witness.
	firstKeyPartialSig := partialSignWithKey(
		t.t, aliceLnd.RPC, regtestParams, transferPkt, assetInputIdx,
		firstAnchorInternal, anchorInputControlBlockBytes,
		anchorMultisigLeaf,
	)
	secondKeyPartialSig := partialSignWithKey(
		t.t, aliceLnd.RPC, regtestParams, transferPkt, assetInputIdx,
		secondAnchorInternal, anchorInputControlBlockBytes,
		anchorMultisigLeaf,
	)

	anchorInputWitness := wire.TxWitness{
		secondKeyPartialSig,
		firstKeyPartialSig,
		anchorMultisigScript,
		anchorInputControlBlockBytes,
	}
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

	// Mine a block to confirm the transfer.
	MineBlocks(t.t, t.lndHarness.Miner.Client, 1, 1)

	// Bob should have detected the transfer, and now own half of the total
	// asset supply.
	AssertAddrEvent(t.t, bobTapd, bobAddr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertBalanceByID(
		t.t, bobTapd, assetTweakedScriptKey.AssetGenesis.AssetId,
		assetTweakedScriptKey.Amount/2,
	)

	time.Sleep(time.Second)
	AssertBalanceByID(
		t.t, aliceTapd, assetTweakedScriptKey.AssetGenesis.AssetId,
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

func BuildScriptSpendControlBlock(singlyTweakedKey *btcec.PublicKey,
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

func ApplyGroupWitness(protoAsset *asset.Asset,
	newGroup *asset.GroupKey) *asset.Asset {

	assetWithGroup := protoAsset.Copy()
	assetWithGroup.GroupKey = newGroup
	assetWithGroup.PrevWitnesses[0].TxWitness = newGroup.Witness

	return assetWithGroup
}
