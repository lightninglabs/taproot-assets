package tarodb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/rand"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type assetGenOptions struct {
	assetGen asset.Genesis

	customGroup bool

	noGroupKey bool

	groupKeyPriv *btcec.PrivateKey

	amt uint64

	genesisPoint wire.OutPoint

	scriptKey asset.ScriptKey
}

func defaultAssetGenOpts(t *testing.T) *assetGenOptions {
	gen := asset.RandGenesis(t, asset.Normal)

	return &assetGenOptions{
		assetGen:     gen,
		groupKeyPriv: test.RandPrivKey(t),
		amt:          uint64(test.RandInt[uint32]()),
		genesisPoint: test.RandOp(t),
		scriptKey: asset.NewScriptKeyBIP0086(keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: test.RandInt[keychain.KeyFamily](),
				Index:  uint32(test.RandInt[int32]()),
			},
		}),
	}
}

type assetGenOpt func(*assetGenOptions)

func withAssetGenAmt(amt uint64) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.amt = amt
	}
}

func withAssetGenKeyGroup(key *btcec.PrivateKey) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.customGroup = true
		opt.groupKeyPriv = key
	}
}

func withAssetGenPoint(op wire.OutPoint) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.genesisPoint = op
	}
}

func withAssetGen(g asset.Genesis) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.assetGen = g
	}
}

func withScriptKey(k asset.ScriptKey) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.scriptKey = k
	}
}

func withNoGroupKey() assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.noGroupKey = true
	}
}

func randAsset(t *testing.T, genOpts ...assetGenOpt) *asset.Asset {
	opts := defaultAssetGenOpts(t)
	for _, optFunc := range genOpts {
		optFunc(opts)
	}

	genesis := opts.assetGen
	genesis.FirstPrevOut = opts.genesisPoint

	groupPriv := *opts.groupKeyPriv

	genSigner := asset.NewRawKeyGenesisSigner(&groupPriv)

	groupKey, sig, err := genSigner.SignGenesis(
		keychain.KeyDescriptor{
			PubKey: groupPriv.PubKey(),
		}, genesis, nil,
	)
	require.NoError(t, err)

	newAsset := &asset.Asset{
		Genesis:          genesis,
		Amount:           opts.amt,
		LockTime:         uint64(test.RandInt[int32]()),
		RelativeLockTime: uint64(test.RandInt[int32]()),
		ScriptKey:        opts.scriptKey,
	}

	// 50/50 chance that we'll actually have a group key. Or we'll always
	// use it if a custom group key was specified.
	switch {
	case opts.noGroupKey:
		break

	case opts.customGroup || test.RandInt[int]()%2 == 0:
		newAsset.GroupKey = &asset.GroupKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: groupKey,
			},
			GroupPubKey: *groupKey,
			Sig:         *sig,
		}
	}

	// Go with an even amount to make the splits always work nicely.
	if newAsset.Amount%2 != 0 {
		newAsset.Amount++
	}

	// For the witnesses, we'll flip a coin: we'll either make a genesis
	// witness, or a set of actual witnesses.
	var witnesses []asset.Witness
	if test.RandInt[int]()%2 == 0 {
		witnesses = append(witnesses, asset.Witness{
			PrevID:          &asset.PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		})
	} else {
		numWitness := test.RandInt[int]() % 10
		if numWitness == 0 {
			numWitness++
		}
		witnesses = make([]asset.Witness, numWitness)
		for i := 0; i < numWitness; i++ {
			scriptKey := asset.NewScriptKeyBIP0086(
				keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
				},
			)
			witnesses[i] = asset.Witness{
				PrevID: &asset.PrevID{
					OutPoint: test.RandOp(t),
					ID:       asset.RandID(t),
					ScriptKey: asset.ToSerialized(
						scriptKey.PubKey,
					),
				},
				TxWitness: test.RandTxWitnesses(t),
				// For simplicity, we just use the base asset
				// itself as the "anchor" asset in the split
				// commitment.
				SplitCommitment: commitment.RandSplitCommit(
					t, *newAsset,
				),
			}
		}
	}

	newAsset.PrevWitnesses = witnesses

	return newAsset
}

func assertAssetEqual(t *testing.T, a, b *asset.Asset) {
	if equal := a.DeepEqual(b); !equal {
		// Print a nice diff if the native equality check fails.
		require.Equal(t, b, a)

		// Make sure we fail in any case, even if the above equality
		// check succeeds (which shouldn't be the case).
		t.Fatalf("asset equality failed!")
	}
}

// TestImportAssetProof tests that given a valid asset proof (mainly the final
// snapshot information), we're able to properly import all the components on
// disk, then retrieve the asset as if it were ours.
func TestImportAssetProof(t *testing.T) {
	t.Parallel()

	// First, we'll create a new instance of the database.
	_, assetStore, db := newAssetStore(t)

	// Next, we'll make a new random asset that also has a few inputs with
	// dummy witness information.
	testAsset := randAsset(t)

	assetRoot, err := commitment.NewAssetCommitment(testAsset)
	require.NoError(t, err)

	taroRoot, err := commitment.NewTaroCommitment(assetRoot)
	require.NoError(t, err)

	// With our asset created, we can now create the AnnotatedProof we use
	// to import assets into the database.
	var blockHash chainhash.Hash
	_, err = rand.Read(blockHash[:])
	require.NoError(t, err)

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    10,
	})

	assetID := testAsset.ID()
	anchorPoint := wire.OutPoint{
		Hash:  anchorTx.TxHash(),
		Index: 0,
	}
	testProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *testAsset.ScriptKey.PubKey,
		},
		Blob: bytes.Repeat([]byte{0x0}, 100),
		AssetSnapshot: &proof.AssetSnapshot{
			Asset:             testAsset,
			OutPoint:          anchorPoint,
			AnchorBlockHash:   blockHash,
			AnchorBlockHeight: test.RandInt[uint32](),
			AnchorTxIndex:     test.RandInt[uint32](),
			AnchorTx:          anchorTx,
			OutputIndex:       0,
			InternalKey:       test.RandPubKey(t),
			ScriptRoot:        taroRoot,
		},
	}
	if testAsset.GroupKey != nil {
		testProof.GroupKey = &testAsset.GroupKey.GroupPubKey
	}

	// We'll now insert the internal key information as well as the script
	// key ahead of time to reflect the address creation that happens
	// elsewhere.
	ctx := context.Background()
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testProof.InternalKey.SerializeCompressed(),
		KeyFamily: test.RandInt[int32](),
		KeyIndex:  test.RandInt[int32](),
	})
	require.NoError(t, err)
	rawScriptKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testAsset.ScriptKey.RawKey.PubKey.SerializeCompressed(),
		KeyFamily: int32(testAsset.ScriptKey.RawKey.Family),
		KeyIndex:  int32(testAsset.ScriptKey.RawKey.Index),
	})
	require.NoError(t, err)
	_, err = db.UpsertScriptKey(ctx, NewScriptKey{
		InternalKeyID:    rawScriptKeyID,
		TweakedScriptKey: testAsset.ScriptKey.PubKey.SerializeCompressed(),
		Tweak:            nil,
	})
	require.NoError(t, err)

	// We'll add the chain transaction of the proof now to simulate a
	// batched transfer on a higher layer.
	var anchorTxBuf bytes.Buffer
	err = testProof.AnchorTx.Serialize(&anchorTxBuf)
	require.NoError(t, err)
	anchorTXID := testProof.AnchorTx.TxHash()
	_, err = db.UpsertChainTx(ctx, ChainTx{
		Txid:        anchorTXID[:],
		RawTx:       anchorTxBuf.Bytes(),
		BlockHeight: sqlInt32(testProof.AnchorBlockHeight),
		BlockHash:   testProof.AnchorBlockHash[:],
		TxIndex:     sqlInt32(testProof.AnchorTxIndex),
	})
	require.NoError(t, err, "unable to insert chain tx: %w", err)

	// With all our test data constructed, we'll now attempt to import the
	// asset into the database.
	require.NoError(
		t, assetStore.ImportProofs(
			context.Background(), proof.MockHeaderVerifier, testProof,
		),
	)

	// We should now be able to retrieve the set of all assets inserted on
	// disk.
	assets, err := assetStore.FetchAllAssets(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The DB asset should match the asset we inserted exactly.
	dbAsset := assets[0]

	assertAssetEqual(t, testAsset, dbAsset.Asset)

	// Finally, we'll verify all the anchor information that was inserted
	// on disk.
	require.Equal(t, testProof.AnchorBlockHash, dbAsset.AnchorBlockHash)
	require.Equal(t, testProof.OutPoint, dbAsset.AnchorOutpoint)
	require.Equal(t, testProof.AnchorTx.TxHash(), dbAsset.AnchorTx.TxHash())

	// We should also be able to fetch the proof we just inserted using the
	// script key of the new asset.
	_, err = assetStore.FetchProof(ctx, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
	})
	require.NoError(t, err)

	// We should also be able to fetch the created asset above based on
	// either the asset ID, or key group via the main coin selection
	// routine.
	var assetConstraints tarofreighter.CommitmentConstraints
	if testAsset.GroupKey != nil {
		assetConstraints.GroupKey = &testAsset.GroupKey.GroupPubKey
	} else {
		assetConstraints.AssetID = &assetID
	}
	selectedAssets, err := assetStore.SelectCommitment(
		ctx, assetConstraints,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, 1)
	assertAssetEqual(t, testAsset, selectedAssets[0].Asset)
}

// TestInternalKeyUpsert tests that if we insert an internal key that's a
// duplicate, it works and we get the primary key of the key that was already
// inserted.
func TestInternalKeyUpsert(t *testing.T) {
	t.Parallel()

	// First, we'll create a new instance of the database.
	_, _, db := newAssetStore(t)

	testKey := test.RandPubKey(t)

	// Now we'll insert two internal keys that are the same. We should get
	// the same response back (the primary key) for both of them.
	ctx := context.Background()
	k1, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testKey.SerializeCompressed(),
		KeyFamily: 1,
		KeyIndex:  2,
	})
	require.NoError(t, err)

	k2, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testKey.SerializeCompressed(),
		KeyFamily: 1,
		KeyIndex:  2,
	})
	require.NoError(t, err)

	require.Equal(t, k1, k2)
}

type assetDesc struct {
	assetGen    asset.Genesis
	anchorPoint wire.OutPoint

	keyGroup *btcec.PrivateKey

	noGroupKey bool

	scriptKey *asset.ScriptKey

	amt uint64
}

type assetGenerator struct {
	assetGens []asset.Genesis

	anchorTxs []*wire.MsgTx

	anchorPoints     []wire.OutPoint
	anchorPointsToTx map[wire.OutPoint]*wire.MsgTx

	groupKeys []*btcec.PrivateKey
}

func newAssetGenerator(t *testing.T,
	numAssetIDs, numGroupKeys int) *assetGenerator {

	anchorTxs := make([]*wire.MsgTx, numAssetIDs)
	for i := 0; i < numAssetIDs; i++ {
		pkScript := bytes.Repeat([]byte{byte(i)}, 34)
		anchorTxs[i] = &wire.MsgTx{
			TxIn: []*wire.TxIn{
				{},
			},
			TxOut: []*wire.TxOut{
				{
					PkScript: pkScript,
					Value:    10 * 8,
				},
			},
		}
	}

	anchorPoints := make([]wire.OutPoint, numAssetIDs)
	anchorPointsToTx := make(map[wire.OutPoint]*wire.MsgTx, numAssetIDs)
	for i, tx := range anchorTxs {
		tx := tx

		anchorPoint := wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}

		anchorPoints[i] = anchorPoint
		anchorPointsToTx[anchorPoint] = tx
	}

	assetGens := make([]asset.Genesis, numAssetIDs)
	for i := 0; i < numAssetIDs; i++ {
		assetGens[i] = asset.RandGenesis(t, asset.Normal)
	}

	groupKeys := make([]*btcec.PrivateKey, numGroupKeys)
	for i := 0; i < numGroupKeys; i++ {
		groupKeys[i] = test.RandPrivKey(t)
	}

	return &assetGenerator{
		groupKeys:        groupKeys,
		assetGens:        assetGens,
		anchorPoints:     anchorPoints,
		anchorPointsToTx: anchorPointsToTx,
		anchorTxs:        anchorTxs,
	}
}

func (a *assetGenerator) genAssets(t *testing.T, assetStore *AssetStore,
	assetDescs []assetDesc) {

	ctx := context.Background()
	for _, desc := range assetDescs {
		desc := desc

		opts := []assetGenOpt{
			withAssetGenAmt(desc.amt), withAssetGenPoint(desc.anchorPoint),
			withAssetGen(desc.assetGen),
		}

		if desc.keyGroup != nil {
			opts = append(opts, withAssetGenKeyGroup(desc.keyGroup))
		}
		if desc.noGroupKey {
			opts = append(opts, withNoGroupKey())
		}
		if desc.scriptKey != nil {
			opts = append(opts, withScriptKey(*desc.scriptKey))
		}

		if desc.amt == 0 {
			opts = append(opts, withScriptKey(asset.NUMSScriptKey))
		}
		asset := randAsset(t, opts...)

		// TODO(roasbeef): should actually group them all together?
		assetCommitment, err := commitment.NewAssetCommitment(asset)
		require.NoError(t, err)
		taroCommitment, err := commitment.NewTaroCommitment(assetCommitment)
		require.NoError(t, err)

		anchorPoint := a.anchorPointsToTx[desc.anchorPoint]

		err = assetStore.importAssetFromProof(
			ctx, assetStore.db, &proof.AnnotatedProof{
				AssetSnapshot: &proof.AssetSnapshot{
					AnchorTx:    anchorPoint,
					InternalKey: test.RandPubKey(t),
					Asset:       asset,
					ScriptRoot:  taroCommitment,
				},
				Blob: bytes.Repeat([]byte{1}, 100),
			},
		)
		require.NoError(t, err)
	}
}

func (a *assetGenerator) bindAssetID(i int, op wire.OutPoint) *asset.ID {
	gen := a.assetGens[i]
	gen.FirstPrevOut = op

	id := gen.ID()

	return &id
}

func (a *assetGenerator) bindKeyGroup(i int, op wire.OutPoint) *btcec.PublicKey {
	gen := a.assetGens[i]
	gen.FirstPrevOut = op

	groupPriv := *a.groupKeys[i]

	tweakedPriv := txscript.TweakTaprootPrivKey(
		groupPriv, gen.GroupKeyTweak(),
	)

	return tweakedPriv.PubKey()
}

// TestSelectCommitment tests that the coin selection logic can properly select
// assets from a canned set that meet the specified set of constraints.
func TestSelectCommitment(t *testing.T) {
	t.Parallel()

	const (
		numAssetIDs  = 10
		numGroupKeys = 2
	)

	assetGen := newAssetGenerator(t, numAssetIDs, numGroupKeys)

	testCases := []struct {
		name string

		assets []assetDesc

		constraints tarofreighter.CommitmentConstraints

		numAssets int

		err error
	}{
		// Only one asset that matches the constraints, should be the
		// only one returned.
		{
			name: "single asset exact match",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      5,

					anchorPoint: assetGen.anchorPoints[0],
				},
			},
			constraints: tarofreighter.CommitmentConstraints{
				AssetID: assetGen.bindAssetID(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 2,
			},
			numAssets: 1,
		},

		// Asset matches all the params, but too small of a UTXO.  only
		// one returned.
		{
			name: "single asset no match min amt",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      5,

					anchorPoint: assetGen.anchorPoints[0],
				},
			},
			constraints: tarofreighter.CommitmentConstraints{
				AssetID: assetGen.bindAssetID(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 10,
			},
			numAssets: 0,
			err:       tarofreighter.ErrNoPossibleAssetInputs,
		},

		// Asset ID not found on disk, no matches should be returned.
		{
			name: "no match wrong asset ID",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      5,

					anchorPoint: assetGen.anchorPoints[0],
				},
			},
			constraints: tarofreighter.CommitmentConstraints{
				AssetID: assetGen.bindAssetID(
					1, assetGen.anchorPoints[1],
				),
				MinAmt: 10,
			},
			numAssets: 0,
			err:       tarofreighter.ErrNoPossibleAssetInputs,
		},

		// Create two assets, one has a key group the other doesn't.
		// We should only get one asset back.
		{
			name: "asset with key group",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      10,

					anchorPoint: assetGen.anchorPoints[0],

					keyGroup: assetGen.groupKeys[0],
				},
				{
					assetGen: assetGen.assetGens[1],
					amt:      10,

					anchorPoint: assetGen.anchorPoints[1],
					noGroupKey:  true,
				},
			},
			constraints: tarofreighter.CommitmentConstraints{
				GroupKey: assetGen.bindKeyGroup(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 1,
			},
			numAssets: 1,
		},
	}

	ctx := context.Background()
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// First, we'll create a new assets store and then
			// insert the set of assets described by the asset
			// descriptions.
			_, assetsStore, _ := newAssetStore(t)

			assetGen.genAssets(t, assetsStore, tc.assets)

			// With the assets inserted, we'll now attempt to query
			// for the set of matching assets based on the
			// constraints.
			selectedAssets, err := assetsStore.SelectCommitment(
				ctx, tc.constraints,
			)
			require.ErrorIs(t, tc.err, err)

			// The number of selected assets should match up
			// properly.
			require.Equal(t, tc.numAssets, len(selectedAssets))

			// If the expectation is to get a single asset, let's
			// make sure we can fetch the same asset commitment with
			// the FetchCommitment method.
			if tc.numAssets != 1 {
				return
			}

			sa := selectedAssets[0]
			assetCommitment, err := assetsStore.FetchCommitment(
				ctx, sa.Asset.ID(), sa.AnchorPoint,
				sa.Asset.GroupKey, &sa.Asset.ScriptKey,
			)
			require.NoError(t, err)

			assertAssetEqual(t, sa.Asset, assetCommitment.Asset)
			assertAssetsEqual(
				t, sa.Commitment, assetCommitment.Commitment,
			)

			// And make sure we get a proper error if we try to
			// fetch an asset with an invalid asset ID.
			wrongID := sa.Asset.ID()
			wrongID[0] ^= 0x01
			assetCommitment, err = assetsStore.FetchCommitment(
				ctx, wrongID, sa.AnchorPoint,
				sa.Asset.GroupKey, &sa.Asset.ScriptKey,
			)
			require.ErrorIs(
				t, err, tarofreighter.ErrNoPossibleAssetInputs,
			)
		})
	}
}

// TestAssetExportLog tests that were able to properly spend/transfer assets on
// disk. This ensures we can properly commit the end result of an asset
// transfer initiated at a higher level.
func TestAssetExportLog(t *testing.T) {
	t.Parallel()

	_, assetsStore, db := newAssetStore(t)
	ctx := context.Background()

	targetScriptKey := asset.NewScriptKeyBIP0086(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	// First, we'll generate 3 assets, each all sharing the same anchor
	// transaction, but having distinct asset IDs.
	const numAssets = 3
	assetGen := newAssetGenerator(t, numAssets, 3)
	assetGen.genAssets(t, assetsStore, []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],

			// This is the script key of the asset we'll be
			// modifying.
			scriptKey: &targetScriptKey,

			amt: 16,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[0],

			amt: 10,
		},
		{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[0],

			amt: 6,
		},
	})

	// We should see a single UTXO at this point, since the assets all had
	// the same anchor point.
	utxos, err := assetsStore.FetchManagedUTXOs(ctx)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, assetGen.anchorPoints[0], utxos[0].OutPoint)

	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{})
	newAnchorTx.TxIn[0].SignatureScript = []byte{}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	const heightHint = 1450

	newScriptKey := asset.NewScriptKeyBIP0086(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	newAmt := 9

	newRootHash := sha256.Sum256([]byte("kek"))
	newRootValue := uint64(100)

	senderBlob := bytes.Repeat([]byte{0x01}, 100)
	receiverBlob := bytes.Repeat([]byte{0x02}, 100)

	newWitness := asset.Witness{
		PrevID:          &asset.PrevID{},
		TxWitness:       [][]byte{{0x01}, {0x02}},
		SplitCommitment: nil,
	}

	chainFees := int64(100)

	// With the assets inserted, we'll now construct the struct we'll used
	// to commit a new spend on disk.
	anchorTxHash := newAnchorTx.TxHash()
	spendDelta := &tarofreighter.OutboundParcelDelta{
		OldAnchorPoint: wire.OutPoint{
			Hash:  assetGen.anchorTxs[0].TxHash(),
			Index: 0,
		},
		NewAnchorPoint: wire.OutPoint{
			Hash:  anchorTxHash,
			Index: 0,
		},
		NewInternalKey: keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(rand.Int31()),
				Index:  uint32(test.RandInt[int32]()),
			},
		},
		// This can be anything since we assume the application sets it
		// properly.
		TaroRoot:           bytes.Repeat([]byte{0x01}, 100),
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: heightHint,
		// We'll actually modify only one of the assets. This simulates
		// us create a split of the asset to send to another party.
		AssetSpendDeltas: []tarofreighter.AssetSpendDelta{
			{
				OldScriptKey: *targetScriptKey.PubKey,
				NewAmt:       uint64(newAmt),
				NewScriptKey: newScriptKey,
				SplitCommitmentRoot: mssmt.NewComputedNode(
					newRootHash, newRootValue,
				),
				WitnessData:        []asset.Witness{newWitness},
				SenderAssetProof:   senderBlob,
				ReceiverAssetProof: receiverBlob,
			},
		},
		ChainFees: int64(chainFees),
	}
	require.NoError(t, assetsStore.LogPendingParcel(ctx, spendDelta))

	// At this point, we should be able to query for the log parcel, by
	// looking for all unconfirmed transfers.
	assetTransfers, err := db.QueryAssetTransfers(ctx, TransferQuery{})
	require.NoError(t, err)
	require.Equal(t, 1, len(assetTransfers))

	// We should also be able to find it based on its outpoint.
	anchorPointBytes, err := encodeOutpoint(spendDelta.NewAnchorPoint)
	require.NoError(t, err)
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		NewAnchorPoint: anchorPointBytes,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(assetTransfers))

	// Check that the new UTXO is found among our managed UTXOs.
	utxos, err = assetsStore.FetchManagedUTXOs(ctx)
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	// First UTXO should remain unchanged.
	require.Equal(t, assetGen.anchorPoints[0], utxos[0].OutPoint)

	// Second UTXO will be our new one.
	newUtxo := utxos[1]
	require.Equal(t, spendDelta.NewAnchorPoint, newUtxo.OutPoint)
	require.Equal(t, spendDelta.NewInternalKey, newUtxo.InternalKey)
	require.Equal(t, spendDelta.AnchorTx.TxOut[0].Value,
		int64(newUtxo.OutputValue))
	require.Equal(t, spendDelta.TaroRoot, newUtxo.TaroRoot)
	require.Equal(t, spendDelta.TapscriptSibling, newUtxo.TapscriptSibling)

	// Finally, if we look for the set of confirmed transfers, nothing
	// should be returned.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		UnconfOnly: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(assetTransfers))

	// This should also show up in the set of pending parcels. It should
	// also match exactly the inbound parcel we used to make the delta.
	parcels, err := assetsStore.PendingParcels(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(parcels))
	require.Equal(t, spendDelta, parcels[0])

	// With the asset delta committed and verified, we'll now mark the
	// delta as being confirmed on chain.
	fakeBlockHash := chainhash.Hash(sha256.Sum256([]byte("fake")))
	blockHeight := int32(100)
	txIndex := int32(10)
	finalSenderBlob := bytes.Repeat([]byte{0x03}, 100)
	err = assetsStore.ConfirmParcelDelivery(ctx, &tarofreighter.AssetConfirmEvent{
		AnchorPoint:      spendDelta.NewAnchorPoint,
		TxIndex:          txIndex,
		BlockHeight:      blockHeight,
		BlockHash:        fakeBlockHash,
		FinalSenderProof: finalSenderBlob,
	})
	require.NoError(t, err)

	// We'll now fetch all the assets to verify that they were updated
	// properly on disk.
	chainAssets, err := assetsStore.FetchAllAssets(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, numAssets, len(chainAssets))

	var mutationFound bool
	for _, chainAsset := range chainAssets {
		require.Equal(
			t, spendDelta.NewAnchorPoint, chainAsset.AnchorOutpoint,
		)

		// We should find the mutated asset with its _new_ script key
		// and amount.
		if chainAsset.ScriptKey.PubKey.IsEqual(newScriptKey.PubKey) {
			require.True(t, chainAsset.Amount == uint64(newAmt))
			require.True(
				t, mssmt.IsEqualNode(
					chainAsset.SplitCommitmentRoot,
					spendDelta.AssetSpendDeltas[0].SplitCommitmentRoot,
				), "split roots don't match",
			)
			mutationFound = true
		}
	}
	require.True(t, mutationFound)

	// As a final check for the asset, we'll fetch its blob to ensure it's
	// been updated on disk.
	diskSenderBlob, err := db.FetchAssetProof(
		ctx, newScriptKey.PubKey.SerializeCompressed(),
	)
	require.NoError(t, err)
	require.Equal(t, finalSenderBlob, diskSenderBlob.ProofFile)

	// If we fetch the chain transaction again, then it should have the
	// conf information populated.
	anchorTx, err := db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Equal(t, fakeBlockHash[:], anchorTx.BlockHash[:])
	require.Equal(
		t, uint32(blockHeight), extractSqlInt32[uint32](anchorTx.BlockHeight),
	)
	require.Equal(t, uint32(txIndex), extractSqlInt32[uint32](anchorTx.TxIndex))
	require.Equal(t, chainFees, anchorTx.ChainFees)

	// At this point, there should be no more pending parcels.
	parcels, err = assetsStore.PendingParcels(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(parcels))
}

// TestAssetGroupSigUpsert tests that if you try to insert another asset
// group sig with the same asset_gen_id, then only one is actually created.
func TestAssetGroupSigUpsert(t *testing.T) {
	t.Parallel()

	_, _, db := newAssetStore(t)
	ctx := context.Background()

	internalKey := test.RandPubKey(t)

	// First, we'll insert all the required rows we need to satisfy the
	// foreign key constraints needed to insert a new genesis sig.
	keyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey: internalKey.SerializeCompressed(),
	})
	require.NoError(t, err)

	genesisPointID, err := upsertGenesisPoint(ctx, db, test.RandOp(t))
	require.NoError(t, err)

	genAssetID, err := upsertGenesis(
		ctx, db, genesisPointID, asset.RandGenesis(t, asset.Normal),
	)
	require.NoError(t, err)

	groupID, err := db.UpsertAssetGroupKey(ctx, AssetGroupKey{
		TweakedGroupKey: internalKey.SerializeCompressed(),
		InternalKeyID:   keyID,
		GenesisPointID:  genesisPointID,
	})
	require.NoError(t, err)

	// With all the other items inserted, we'll now insert an asset group
	// sig.
	groupSigID, err := db.UpsertAssetGroupSig(ctx, AssetGroupSig{
		GenesisSig: []byte{0x01},
		GenAssetID: genAssetID,
		GroupKeyID: groupID,
	})
	require.NoError(t, err)

	// If we insert the very same sig, then we should get the same group sig
	// ID back.
	groupSigID2, err := db.UpsertAssetGroupSig(ctx, AssetGroupSig{
		GenesisSig: []byte{0x01},
		GenAssetID: genAssetID,
		GroupKeyID: groupID,
	})
	require.NoError(t, err)

	require.Equal(t, groupSigID, groupSigID2)
}

// TestFetchGroupedAssets tests that the FetchGroupedAssets query corectly
// excludes assets with nil group keys, groups assets with matching group
// keys, and returns other asset fields accurately.
func TestFetchGroupedAssets(t *testing.T) {
	t.Parallel()

	_, assetsStore, _ := newAssetStore(t)
	ctx := context.Background()

	// Make four assets and create only two group keys. We want one asset
	// with no group, one group with only one asset, and two assets to be
	// in the same group.
	const numAssets = 4
	assetGen := newAssetGenerator(t, numAssets, 2)
	// Need to add type variation also
	assetDescs := []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],
			noGroupKey:  true,
			amt:         88,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[1],
			keyGroup:    assetGen.groupKeys[0],
			amt:         44,
		},
		{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[2],
			keyGroup:    assetGen.groupKeys[1],
			amt:         22,
		},
		{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[3],
			keyGroup:    assetGen.groupKeys[1],
			amt:         2,
		},
	}

	assetGen.genAssets(t, assetsStore, assetDescs)

	groupedAssets, err := assetsStore.FetchGroupedAssets(ctx)
	require.Nil(t, err)

	// The one asset with no group should not be returned.
	require.Equal(t, numAssets-1, len(groupedAssets))

	// Sort the assets to match the order of the asset descriptors, for
	// easier comparison.
	sort.Slice(groupedAssets, func(i, j int) bool {
		return groupedAssets[i].Amount > groupedAssets[j].Amount
	})

	// Group keys should not match between assets 1 and 2, and match for
	// assets 2 and 3.
	require.NotEqual(
		t, groupedAssets[0].GroupKey.SerializeCompressed(),
		groupedAssets[1].GroupKey.SerializeCompressed(),
	)
	require.Equal(
		t, groupedAssets[1].GroupKey.SerializeCompressed(),
		groupedAssets[2].GroupKey.SerializeCompressed(),
	)

	// Fetch all assets to check the accuracy of other asset fields.
	allAssets, err := assetsStore.FetchAllAssets(ctx, nil)
	require.NoError(t, err)

	// Sort assets to match the order of the asset descriptors.
	sort.Slice(allAssets, func(i, j int) bool {
		return allAssets[i].Amount > allAssets[j].Amount
	})

	// Check for equality of all asset fields.
	equalityCheck := func(a *asset.Asset, b *AssetHumanReadable) {
		require.Equal(t, a.ID(), b.ID)
		require.Equal(t, a.Amount, b.Amount)
		require.Equal(t, a.LockTime, b.LockTime)
		require.Equal(t, a.RelativeLockTime, b.RelativeLockTime)
		require.Equal(t, a.Tag, b.Tag)
		require.Equal(t, a.Metadata, b.Metadata)
		require.Equal(t, a.Type, b.Type)
	}

	equalityCheck(allAssets[1].Asset, groupedAssets[0])
	equalityCheck(allAssets[2].Asset, groupedAssets[1])
	equalityCheck(allAssets[3].Asset, groupedAssets[2])
}
