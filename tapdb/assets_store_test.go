package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type assetGenOptions struct {
	version asset.Version

	assetGen asset.Genesis

	customGroup bool

	groupAnchorGen *asset.Genesis

	groupAnchorGenPoint *wire.OutPoint

	noGroupKey bool

	groupKeyPriv *btcec.PrivateKey

	amt uint64

	genesisPoint wire.OutPoint

	scriptKey asset.ScriptKey
}

func defaultAssetGenOpts(t *testing.T) *assetGenOptions {
	gen := asset.RandGenesis(t, asset.Normal)

	return &assetGenOptions{
		version:      asset.Version(rand.Int31n(2)),
		assetGen:     gen,
		groupKeyPriv: test.RandPrivKey(),
		amt:          uint64(test.RandInt[uint32]()),
		genesisPoint: test.RandOp(t),
		scriptKey: asset.NewScriptKeyBip86(keychain.KeyDescriptor{
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

func withGroupAnchorGen(g *asset.Genesis) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.groupAnchorGen = g
	}
}

func withGroupAnchorGenPoint(op wire.OutPoint) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.groupAnchorGenPoint = &op
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

func withAssetVersionGen(v *asset.Version) assetGenOpt {
	return func(opt *assetGenOptions) {
		opt.version = *v
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

	genSigner := asset.NewMockGenesisSigner(&groupPriv)
	genTxBuilder := tapscript.GroupTxBuilder{}

	var (
		groupKeyDesc = keychain.KeyDescriptor{
			PubKey: groupPriv.PubKey(),
		}
		assetGroupKey    *asset.GroupKey
		err              error
		initialGen       = genesis
		protoAsset       *asset.Asset
		lockTime         = uint64(test.RandInt[int32]())
		relativeLockTime = uint64(test.RandInt[int32]())
	)

	protoAsset = asset.NewAssetNoErr(
		t, genesis, opts.amt, lockTime, relativeLockTime,
		opts.scriptKey, nil, asset.WithAssetVersion(opts.version),
	)

	if opts.groupAnchorGen != nil {
		initialGen = *opts.groupAnchorGen
	}
	if opts.groupAnchorGenPoint != nil {
		initialGen.FirstPrevOut = *opts.groupAnchorGenPoint
	}

	groupReq := asset.NewGroupKeyRequestNoErr(
		t, groupKeyDesc, fn.None[asset.ExternalKey](), initialGen,
		protoAsset, nil, fn.None[chainhash.Hash](),
	)
	genTx, err := groupReq.BuildGroupVirtualTx(&genTxBuilder)
	require.NoError(t, err)

	assetGroupKey, err = asset.DeriveGroupKey(
		genSigner, *genTx, *groupReq, nil,
	)

	require.NoError(t, err)

	newAsset := &asset.Asset{
		Version:          opts.version,
		Genesis:          genesis,
		Amount:           opts.amt,
		LockTime:         lockTime,
		RelativeLockTime: relativeLockTime,
		ScriptKey:        opts.scriptKey,
	}

	// Go with an even amount to make the splits always work nicely.
	if newAsset.Amount%2 != 0 {
		newAsset.Amount++
	}

	// 50/50 chance that we'll actually have a group key. Or we'll always
	// use it if a custom group key was specified.
	switch {
	case opts.noGroupKey:
		break

	case opts.customGroup || test.RandInt[int]()%2 == 0:
		// If we're using a group key, we want to leave the asset with
		// the group witness and not a random witness.
		assetWithGroup := asset.NewAssetNoErr(
			t, genesis, newAsset.Amount, newAsset.LockTime,
			newAsset.RelativeLockTime, newAsset.ScriptKey,
			assetGroupKey, asset.WithAssetVersion(opts.version),
		)

		return assetWithGroup
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
			scriptKey := asset.NewScriptKeyBip86(
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
	t.Helper()

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

	var (
		ctxb = context.Background()

		dbHandle   = NewDbHandle(t)
		assetStore = dbHandle.AssetStore
	)

	// Add a random asset and corresponding proof into the database.
	testAsset, testProof := dbHandle.AddRandomAssetProof(t)
	initialBlob := testProof.Blob

	// We should now be able to retrieve the set of all assets inserted on
	// disk.
	assets, err := assetStore.FetchAllAssets(ctxb, false, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The DB asset should match the asset we inserted exactly.
	dbAsset := assets[0]

	assertAssetEqual(t, testAsset, dbAsset.Asset)

	// Finally, we'll verify all the anchor information that was inserted
	// on disk.
	require.Equal(t, testProof.AnchorBlockHash, dbAsset.AnchorBlockHash)
	require.Equal(
		t, testProof.AssetSnapshot.OutPoint, dbAsset.AnchorOutpoint,
	)
	require.Equal(t, testProof.AnchorTx.TxHash(), dbAsset.AnchorTx.TxHash())
	require.NotZero(t, dbAsset.AnchorBlockHeight)

	// We should also be able to fetch the proof we just inserted using the
	// script key of the new asset.
	currentBlob, err := assetStore.FetchProof(ctxb, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
	})
	require.NoError(t, err)
	require.Equal(t, initialBlob, currentBlob)

	// We should also be able to fetch the created asset above based on
	// either the asset ID, or key group via the main coin selection
	// routine.
	assetConstraints := tapfreighter.CommitmentConstraints{
		AssetSpecifier: testAsset.Specifier(),
	}
	selectedAssets, err := assetStore.ListEligibleCoins(
		ctxb, assetConstraints,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, 1)
	assertAssetEqual(t, testAsset, selectedAssets[0].Asset)

	// We'll now attempt to overwrite the proof with one that has different
	// block information (simulating a re-org).
	updatedBlob := bytes.Repeat([]byte{0x77}, 100)

	testProof.AnchorBlockHash = chainhash.Hash{12, 34, 56}
	testProof.AnchorBlockHeight = 1234
	testProof.AnchorTxIndex = 5678
	testProof.Blob = updatedBlob
	require.NoError(t, assetStore.ImportProofs(
		ctxb, proof.MockVerifierCtx, true, testProof,
	))

	currentBlob, err = assetStore.FetchProof(ctxb, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
	})
	require.NoError(t, err)
	require.Equal(t, updatedBlob, []byte(currentBlob))

	// Make sure we get the same result if we also query by proof outpoint.
	currentBlob, err = assetStore.FetchProof(ctxb, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
		OutPoint:  &testProof.AssetSnapshot.OutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, updatedBlob, []byte(currentBlob))

	// Make sure the chain TX was updated as well.
	assets, err = assetStore.FetchAllAssets(ctxb, false, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The DB asset should match the asset we inserted exactly.
	dbAsset = assets[0]

	assertAssetEqual(t, testAsset, dbAsset.Asset)

	// Finally, we'll verify all the anchor information that was inserted
	// on disk.
	require.Equal(t, testProof.AnchorBlockHash, dbAsset.AnchorBlockHash)
	require.Equal(
		t, testProof.AssetSnapshot.OutPoint, dbAsset.AnchorOutpoint,
	)
	require.Equal(t, testProof.AnchorTx.TxHash(), dbAsset.AnchorTx.TxHash())

	// We now add a second proof for the same script key but a different
	// outpoint and expect that to be stored and retrieved correctly.
	oldOutpoint := testProof.AssetSnapshot.OutPoint
	newChainTx := wire.NewMsgTx(2)
	newChainTx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: test.RandOp(t),
	}}
	newChainTx.TxOut = []*wire.TxOut{{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
	}}
	newOutpoint := wire.OutPoint{
		Hash:  newChainTx.TxHash(),
		Index: 0,
	}
	testProof.AssetSnapshot.AnchorTx = newChainTx
	testProof.AssetSnapshot.OutPoint = newOutpoint
	testProof.Blob = []byte("new proof")

	require.NoError(t, assetStore.ImportProofs(
		ctxb, proof.MockVerifierCtx, false, testProof,
	))

	// We should still be able to fetch the old proof.
	dbBlob, err := assetStore.FetchProof(ctxb, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
		OutPoint:  &oldOutpoint,
	})
	require.NoError(t, err)
	require.Equal(t, updatedBlob, []byte(dbBlob))

	// But also the new one.
	dbBlob, err = assetStore.FetchProof(ctxb, proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
		OutPoint:  &newOutpoint,
	})
	require.NoError(t, err)
	require.EqualValues(t, testProof.Blob, []byte(dbBlob))
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
	assetGen asset.Genesis

	groupAnchorGen *asset.Genesis

	groupAnchorGenPoint *wire.OutPoint

	anchorPoint wire.OutPoint

	keyGroup *btcec.PrivateKey

	noGroupKey bool

	scriptKey *asset.ScriptKey

	amt uint64

	spent bool

	leasedUntil time.Time

	assetVersion *asset.Version
}

type assetGenerator struct {
	assetGens []asset.Genesis

	anchorTxs []*wire.MsgTx

	anchorPoints          []wire.OutPoint
	anchorPointsToTx      map[wire.OutPoint]*wire.MsgTx
	anchorPointsToHeights map[wire.OutPoint]uint32

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
	anchorPointsToHeights := make(map[wire.OutPoint]uint32, numAssetIDs)
	for i, tx := range anchorTxs {
		tx := tx

		anchorPoint := wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: 0,
		}

		anchorPoints[i] = anchorPoint
		anchorPointsToTx[anchorPoint] = tx
		anchorPointsToHeights[anchorPoint] = uint32(i + 500)
	}

	assetGens := make([]asset.Genesis, numAssetIDs)
	for i := 0; i < numAssetIDs; i++ {
		assetGens[i] = asset.RandGenesis(t, asset.Normal)
	}

	groupKeys := make([]*btcec.PrivateKey, numGroupKeys)
	for i := 0; i < numGroupKeys; i++ {
		groupKeys[i] = test.RandPrivKey()
	}

	return &assetGenerator{
		groupKeys:             groupKeys,
		assetGens:             assetGens,
		anchorPoints:          anchorPoints,
		anchorPointsToTx:      anchorPointsToTx,
		anchorPointsToHeights: anchorPointsToHeights,
		anchorTxs:             anchorTxs,
	}
}

func (a *assetGenerator) genAssets(t *testing.T, assetStore *AssetStore,
	assetDescs []assetDesc) ([]*asset.Asset, []proof.Proof) {

	ctx := context.Background()

	anchorPointsToAssetCommitments := make(
		map[wire.OutPoint][]*commitment.AssetCommitment,
	)
	newAssets := make([]*asset.Asset, len(assetDescs))
	for idx, desc := range assetDescs {
		desc := desc

		opts := []assetGenOpt{
			withAssetGenAmt(desc.amt),
			withAssetGenPoint(desc.anchorPoint),
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
		if desc.groupAnchorGen != nil {
			opts = append(opts, withGroupAnchorGen(
				desc.groupAnchorGen,
			))
		}
		if desc.groupAnchorGenPoint != nil {
			opts = append(opts, withGroupAnchorGenPoint(
				*desc.groupAnchorGenPoint,
			))
		}
		if desc.assetVersion != nil {
			opts = append(opts, withAssetVersionGen(
				desc.assetVersion,
			))
		}
		newAssets[idx] = randAsset(t, opts...)

		// Group assets by anchor point before building tap commitments.
		assetCommitment, err := commitment.NewAssetCommitment(
			newAssets[idx],
		)
		require.NoError(t, err)

		_, ok := anchorPointsToAssetCommitments[desc.anchorPoint]
		if !ok {
			anchorPointsToAssetCommitments[desc.anchorPoint] =
				[]*commitment.AssetCommitment{}
		}

		anchorPointsToAssetCommitments[desc.anchorPoint] = append(
			anchorPointsToAssetCommitments[desc.anchorPoint],
			assetCommitment,
		)
	}

	anchorPointsToTapCommitments := make(
		map[wire.OutPoint]*commitment.TapCommitment,
	)

	for anchorPoint, commitments := range anchorPointsToAssetCommitments {
		tapCommitment, err := commitment.NewTapCommitment(
			nil, commitments...,
		)
		require.NoError(t, err)

		anchorPointsToTapCommitments[anchorPoint] = tapCommitment
	}

	assetProofs := make([]proof.Proof, len(newAssets))
	for i, newAsset := range newAssets {
		desc := assetDescs[i]
		anchorPoint := a.anchorPointsToTx[desc.anchorPoint]
		height := a.anchorPointsToHeights[desc.anchorPoint]
		tapCommitment := anchorPointsToTapCommitments[desc.anchorPoint]

		// Encode a minimal proof so we have a valid proof blob to
		// store.
		assetProof := proof.Proof{}
		assetProof.AnchorTx = *anchorPoint
		assetProof.BlockHeight = height

		txMerkleProof, err := proof.NewTxMerkleProof(
			[]*wire.MsgTx{anchorPoint}, 0,
		)
		require.NoError(t, err)

		assetProof.TxMerkleProof = *txMerkleProof
		assetProof.Asset = *newAsset
		assetProof.InclusionProof = proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: test.RandPubKey(t),
		}
		assetProofs[i] = assetProof

		proofBlob, err := proof.EncodeAsProofFile(&assetProof)
		require.NoError(t, err)

		err = assetStore.importAssetFromProof(
			ctx, assetStore.db, &proof.AnnotatedProof{
				AssetSnapshot: &proof.AssetSnapshot{
					AnchorTx:          anchorPoint,
					InternalKey:       test.RandPubKey(t),
					Asset:             newAsset,
					ScriptRoot:        tapCommitment,
					AnchorBlockHeight: height,
				},
				Blob: proofBlob,
			},
		)
		require.NoError(t, err)

		if desc.spent {
			opBytes, err := encodeOutpoint(desc.anchorPoint)
			require.NoError(t, err)

			var (
				scriptKey = newAsset.ScriptKey.PubKey
				id        = newAsset.ID()
			)
			params := SetAssetSpentParams{
				ScriptKey:   scriptKey.SerializeCompressed(),
				GenAssetID:  id[:],
				AnchorPoint: opBytes,
			}
			_, err = assetStore.db.SetAssetSpent(ctx, params)
			require.NoError(t, err)
		}

		if !desc.leasedUntil.IsZero() {
			owner := newAsset.ID()
			err = assetStore.LeaseCoins(
				ctx, owner, desc.leasedUntil, desc.anchorPoint,
			)
			require.NoError(t, err)
		}
	}

	return newAssets, assetProofs
}

func (a *assetGenerator) assetSpecifierAssetID(i int,
	op wire.OutPoint) asset.Specifier {

	gen := a.assetGens[i]
	gen.FirstPrevOut = op

	id := gen.ID()

	return asset.NewSpecifierFromId(id)
}

func (a *assetGenerator) assetSpecifierGroupKey(i int,
	op wire.OutPoint) asset.Specifier {

	gen := a.assetGens[i]
	gen.FirstPrevOut = op
	genTweak := gen.ID()

	groupPriv := *a.groupKeys[i]

	internalPriv := input.TweakPrivKey(&groupPriv, genTweak[:])
	tweakedPriv := txscript.TweakTaprootPrivKey(*internalPriv, nil)
	groupPubKey := tweakedPriv.PubKey()

	return asset.NewSpecifierFromGroupKey(*groupPubKey)
}

type filterOpt func(f *AssetQueryFilters)

func filterSpecifier(s asset.Specifier) filterOpt {
	return func(f *AssetQueryFilters) {
		f.AssetSpecifier = s
	}
}

func filterMinAmt(amt uint64) filterOpt {
	return func(f *AssetQueryFilters) {
		f.MinAmt = amt
	}
}

func filterMaxAmt(amt uint64) filterOpt {
	return func(f *AssetQueryFilters) {
		f.MaxAmt = amt
	}
}

func filterDistinctSpecifier() filterOpt {
	return func(f *AssetQueryFilters) {
		f.DistinctSpecifier = true
	}
}

func filterAnchorHeight(height int32) filterOpt {
	return func(f *AssetQueryFilters) {
		f.MinAnchorHeight = height
	}
}

func filterAnchorPoint(point *wire.OutPoint) filterOpt {
	return func(f *AssetQueryFilters) {
		f.AnchorPoint = point
	}
}

func filterScriptKey(key *asset.ScriptKey) filterOpt {
	return func(f *AssetQueryFilters) {
		f.ScriptKey = key
	}
}

func filterScriptKeyType(keyType asset.ScriptKeyType) filterOpt {
	return func(f *AssetQueryFilters) {
		f.ScriptKeyType = fn.Some(keyType)
	}
}

// TestFetchAllAssets tests that the different AssetQueryFilters work as
// expected.
func TestFetchAllAssets(t *testing.T) {
	t.Parallel()

	const (
		numAssetIDs  = 12
		numGroupKeys = 2
	)

	internalKey := test.RandPubKey(t)
	tweak := test.RandBytes(32)
	scriptPubKey := txscript.ComputeTaprootOutputKey(internalKey, tweak)

	scriptKeyWithScript := &asset.ScriptKey{
		PubKey: scriptPubKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: internalKey,
			},
			Tweak: tweak,
		},
	}

	ctx := context.Background()
	assetGen := newAssetGenerator(t, numAssetIDs, numGroupKeys)
	availableAssets := []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         5,
	}, {
		assetGen:    assetGen.assetGens[1],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         1,
	}, {
		assetGen:    assetGen.assetGens[2],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         34,
		scriptKey:   scriptKeyWithScript,
	}, {
		assetGen:    assetGen.assetGens[3],
		anchorPoint: assetGen.anchorPoints[1],
		amt:         99,
		spent:       true,
	}, {
		assetGen:    assetGen.assetGens[4],
		anchorPoint: assetGen.anchorPoints[1],
		amt:         12,
	}, {
		assetGen:    assetGen.assetGens[5],
		anchorPoint: assetGen.anchorPoints[2],
		amt:         666,
		spent:       true,
	}, {
		assetGen:    assetGen.assetGens[6],
		anchorPoint: assetGen.anchorPoints[3],
		amt:         22,
		leasedUntil: time.Now().Add(time.Hour),
	}, {
		assetGen:    assetGen.assetGens[7],
		anchorPoint: assetGen.anchorPoints[3],
		amt:         666,
		spent:       true,
	}, {
		assetGen:    assetGen.assetGens[8],
		anchorPoint: assetGen.anchorPoints[4],
		amt:         34,
		leasedUntil: time.Now().Add(time.Hour),
	}, {
		assetGen:    assetGen.assetGens[9],
		anchorPoint: assetGen.anchorPoints[4],
		amt:         777,
		scriptKey:   scriptKeyWithScript,
	}, {
		assetGen:    assetGen.assetGens[10],
		anchorPoint: assetGen.anchorPoints[10],
		amt:         10,
		keyGroup:    assetGen.groupKeys[0],
	}, {
		assetGen:            assetGen.assetGens[11],
		anchorPoint:         assetGen.anchorPoints[11],
		amt:                 8,
		groupAnchorGen:      &assetGen.assetGens[10],
		groupAnchorGenPoint: &assetGen.anchorPoints[10],
		keyGroup:            assetGen.groupKeys[0],
	}}
	makeFilter := func(opts ...filterOpt) *AssetQueryFilters {
		var filter AssetQueryFilters
		for _, opt := range opts {
			opt(&filter)
		}

		return &filter
	}

	// First, we'll create a new assets store and then insert the set of
	// assets described by the asset descriptions.
	_, assetsStore, _ := newAssetStore(t)
	genAssets, _ := assetGen.genAssets(t, assetsStore, availableAssets)
	numGenAssets := len(genAssets)
	lastAsset := genAssets[numGenAssets-1]

	testCases := []struct {
		name          string
		includeSpent  bool
		includeLeased bool
		filter        *AssetQueryFilters
		numAssets     int
		err           error
	}{{
		name:      "no constraints",
		numAssets: 6,
	}, {
		name:          "no constraints, include leased",
		includeLeased: true,
		numAssets:     9,
	}, {
		name:         "no constraints, include spent",
		includeSpent: true,
		numAssets:    8,
	}, {
		name:          "no constraints, include leased, include spent",
		includeLeased: true,
		includeSpent:  true,
		numAssets:     12,
	}, {
		name: "min amount",
		filter: makeFilter(
			filterMinAmt(12),
		),
		numAssets: 2,
	}, {
		name: "min amount, include spent",
		filter: makeFilter(
			filterMinAmt(12),
		),
		includeSpent: true,
		numAssets:    4,
	}, {
		name: "min amount, include leased",
		filter: makeFilter(
			filterMinAmt(12),
		),
		includeLeased: true,
		numAssets:     5,
	}, {
		name: "min amount, include leased, include spent",
		filter: makeFilter(
			filterMinAmt(12),
		),
		includeLeased: true,
		includeSpent:  true,
		numAssets:     8,
	}, {
		name: "max amount",
		filter: makeFilter(
			filterMaxAmt(100),
		),
		numAssets: 6,
	}, {
		name: "max amount, include spent",
		filter: makeFilter(
			filterMaxAmt(100),
		),
		includeSpent: true,
		numAssets:    7,
	}, {
		name: "max amount, include leased",
		filter: makeFilter(
			filterMaxAmt(100),
		),
		includeLeased: true,
		numAssets:     8,
	}, {
		name: "max amount, include leased, include spent",
		filter: makeFilter(
			filterMaxAmt(100),
		),
		includeLeased: true,
		includeSpent:  true,
		numAssets:     9,
	}, {
		name: "default min height, include spent",
		filter: makeFilter(
			filterAnchorHeight(500),
		),
		includeSpent: true,
		numAssets:    8,
	}, {
		name: "specific height",
		filter: makeFilter(
			filterAnchorHeight(512),
		),
		numAssets: 0,
	}, {
		name: "specific height, include spent",
		filter: makeFilter(
			filterAnchorHeight(502),
		),
		includeSpent: true,
		numAssets:    3,
	}, {
		name: "script key with tapscript",
		filter: makeFilter(
			filterMinAmt(100),
			filterScriptKeyType(asset.ScriptKeyBip86),
		),
		numAssets: 0,
	}, {
		name: "query by script key",
		filter: makeFilter(
			filterScriptKey(scriptKeyWithScript),
		),
		numAssets: 1,
	}, {
		name: "query by script key, include leased",
		filter: makeFilter(
			filterScriptKey(scriptKeyWithScript),
		),
		includeLeased: true,
		numAssets:     2,
	}, {
		name: "query by group key only",
		filter: makeFilter(
			filterSpecifier(asset.NewSpecifierFromGroupKey(
				lastAsset.GroupKey.GroupPubKey,
			)),
		),
		numAssets: 2,
	}, {
		name: "query by group key and asset ID",
		filter: makeFilter(
			filterSpecifier(asset.NewSpecifierOptionalGroupPubKey(
				lastAsset.ID(), &lastAsset.GroupKey.GroupPubKey,
			)),
		),
		numAssets: 1,
	}, {
		name: "query by group key and asset ID but distinct",
		filter: makeFilter(
			filterSpecifier(asset.NewSpecifierOptionalGroupPubKey(
				lastAsset.ID(), &lastAsset.GroupKey.GroupPubKey,
			)), filterDistinctSpecifier(),
		),
		numAssets: 2,
	}, {
		name: "query by anchor point",
		filter: makeFilter(
			filterAnchorPoint(&assetGen.anchorPoints[0]),
		),
		numAssets: 3,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// With the assets inserted, we'll now attempt to query
			// for the set of matching assets based on the filter.
			selectedAssets, err := assetsStore.FetchAllAssets(
				ctx, tc.includeSpent, tc.includeLeased,
				tc.filter,
			)
			require.ErrorIs(t, tc.err, err)

			require.Len(t, selectedAssets, tc.numAssets)
		})
	}
}

// TestFetchProof tests that proofs can be fetched for different assets.
func TestFetchProof(t *testing.T) {
	t.Parallel()

	const (
		numAssetIDs  = 10
		numGroupKeys = 2
	)

	assetGen := newAssetGenerator(t, numAssetIDs, numGroupKeys)
	scriptKey := asset.RandScriptKey(t)
	anchorPoint1 := assetGen.anchorPoints[0]
	anchorPoint2 := assetGen.anchorPoints[1]

	ctx := context.Background()
	availableAssets := []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: anchorPoint1,
		amt:         777,
		scriptKey:   &scriptKey,
	}, {
		assetGen:    assetGen.assetGens[8],
		anchorPoint: anchorPoint2,
		amt:         10,
		keyGroup:    assetGen.groupKeys[0],
		scriptKey:   &scriptKey,
	}, {
		assetGen:            assetGen.assetGens[9],
		anchorPoint:         anchorPoint2,
		amt:                 8,
		groupAnchorGen:      &assetGen.assetGens[8],
		groupAnchorGenPoint: &anchorPoint2,
		keyGroup:            assetGen.groupKeys[0],
		scriptKey:           &scriptKey,
	}}

	// First, we'll create a new assets store and then insert the set of
	// assets described by the asset descriptions.
	_, assetsStore, _ := newAssetStore(t)
	genAssets, genProofs := assetGen.genAssets(
		t, assetsStore, availableAssets,
	)

	testCases := []struct {
		name          string
		locator       proof.Locator
		expectProofID int
		err           error
	}{{
		name: "script key only",
		locator: proof.Locator{
			ScriptKey: *scriptKey.PubKey,
		},
		err: proof.ErrMultipleProofs,
	}, {
		name: "script key and anchor point",
		locator: proof.Locator{
			ScriptKey: *scriptKey.PubKey,
			OutPoint:  &anchorPoint2,
		},
		err: proof.ErrMultipleProofs,
	}, {
		name: "script key, anchor point and group key",
		locator: proof.Locator{
			ScriptKey: *scriptKey.PubKey,
			OutPoint:  &anchorPoint2,
			GroupKey:  &genAssets[1].GroupKey.GroupPubKey,
		},
		err: proof.ErrMultipleProofs,
	}, {
		name: "script key, anchor point and asset ID",
		locator: proof.Locator{
			ScriptKey: *scriptKey.PubKey,
			OutPoint:  &anchorPoint2,
			AssetID:   fn.Ptr(genAssets[1].ID()),
		},
		expectProofID: 1,
	}, {
		name: "script key, anchor point, group key and asset ID",
		locator: proof.Locator{
			ScriptKey: *scriptKey.PubKey,
			OutPoint:  &anchorPoint2,
			GroupKey:  &genAssets[1].GroupKey.GroupPubKey,
			AssetID:   fn.Ptr(genAssets[2].ID()),
		},
		expectProofID: 2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := assetsStore.FetchProof(
				ctx, tc.locator,
			)
			if tc.err != nil {
				require.ErrorIs(t, tc.err, err)

				return
			}

			require.NoError(t, err)

			expectedFile, err := proof.NewFile(
				proof.V0, genProofs[tc.expectProofID],
			)
			require.NoError(t, err)

			var expectedBuf bytes.Buffer
			err = expectedFile.Encode(&expectedBuf)
			require.NoError(t, err)

			require.Equal(t, expectedBuf.Bytes(), []byte(blob))
		})
	}
}

// TestUTXOLeases tests that we're able to properly lease UTXOs in the DB,
// update and then remove them again.
func TestUTXOLeases(t *testing.T) {
	t.Parallel()

	_, assetsStore, _ := newAssetStore(t)
	ctx := context.Background()

	// First, we'll generate 3 assets, two of them sharing the same anchor
	// transaction, but all having distinct asset IDs.
	const numAssets = 3
	assetGen := newAssetGenerator(t, numAssets, 3)
	assetGen.genAssets(t, assetsStore, []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],

			amt: 16,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[0],

			amt: 10,
		},
		{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[1],

			amt: 6,
		},
	})

	// At first, none of the assets should be leased.
	selectedAssets, err := assetsStore.FetchAllAssets(
		ctx, false, false, nil,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, numAssets)

	// Now we lease the first asset for 1 hour. This will cause the second
	// one also to be leased, since it's on the same anchor transaction.
	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)
	err = assetsStore.LeaseCoins(
		ctx, leaseOwner, leaseExpiry, assetGen.anchorPoints[0],
	)
	require.NoError(t, err)

	// Only one asset should be returned that is not leased.
	selectedAssets, err = assetsStore.FetchAllAssets(
		ctx, false, false, nil,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, 1)

	// Let's now update the lease.
	leaseExpiry = time.Now().Add(2 * time.Hour)
	err = assetsStore.LeaseCoins(
		ctx, leaseOwner, leaseExpiry, assetGen.anchorPoints[0],
	)
	require.NoError(t, err)

	// Fetch all assets, including the leased ones, and make sure the leased
	// ones have the updated lease time.
	selectedAssets, err = assetsStore.FetchAllAssets(
		ctx, false, true, nil,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, numAssets)

	for idx := range selectedAssets {
		a := selectedAssets[idx]
		if a.AnchorOutpoint == assetGen.anchorPoints[0] {
			require.NotNil(t, a.AnchorLeaseExpiry)
			require.Equal(
				t, leaseExpiry.Unix(),
				a.AnchorLeaseExpiry.Unix(),
			)
			require.Equal(t, leaseOwner, a.AnchorLeaseOwner)
		}
	}

	// Update the lease again, but into the past, so that it should be
	// removed upon cleanup.
	leaseExpiry = time.Now().Add(-time.Hour)
	err = assetsStore.LeaseCoins(
		ctx, leaseOwner, leaseExpiry, assetGen.anchorPoints[0],
	)
	require.NoError(t, err)

	// Trigger the cleanup now.
	err = assetsStore.DeleteExpiredLeases(ctx)
	require.NoError(t, err)

	// All assets should be returned again as non-leased.
	selectedAssets, err = assetsStore.FetchAllAssets(
		ctx, false, false, nil,
	)
	require.NoError(t, err)
	require.Len(t, selectedAssets, numAssets)

	for idx := range selectedAssets {
		a := selectedAssets[idx]
		if a.AnchorOutpoint == assetGen.anchorPoints[0] {
			require.Nil(t, a.AnchorLeaseExpiry)
			require.Equal(t, [32]byte{}, a.AnchorLeaseOwner)
		}
	}
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
	inOneHour := time.Now().Add(time.Hour)

	testCases := []struct {
		name string

		assets []assetDesc

		constraints tapfreighter.CommitmentConstraints

		numAssets int
		sum       int64

		err error
	}{
		// Only one asset that matches the constraints, should be the
		// only one returned.
		{
			name: "single asset exact match",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      6,

					anchorPoint: assetGen.anchorPoints[0],
				},
			},
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierAssetID(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 2,
			},
			numAssets: 1,
			sum:       6,
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
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierAssetID(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 10,
			},
			numAssets: 0,
			err:       tapfreighter.ErrMatchingAssetsNotFound,
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
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierAssetID(
					1, assetGen.anchorPoints[1],
				),
				MinAmt: 10,
			},
			numAssets: 0,
			err:       tapfreighter.ErrMatchingAssetsNotFound,
		},

		// Create two assets, one has a group key the other doesn't.
		// We should only get one asset back.
		{
			name: "asset with group key",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      10,

					anchorPoint: assetGen.anchorPoints[0],

					keyGroup: assetGen.groupKeys[0],
				},
				{
					assetGen: assetGen.assetGens[1],
					amt:      12,

					anchorPoint: assetGen.anchorPoints[1],
					noGroupKey:  true,
				},
			},
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierGroupKey(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 1,
			},
			numAssets: 1,
			sum:       10,
		},

		// Leased assets shouldn't be returned, and neither should other
		// assets on the same anchor transaction.
		{
			name: "multiple assets, one leased",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      5,

					anchorPoint: assetGen.anchorPoints[0],

					leasedUntil: inOneHour,
				},
				{
					assetGen: assetGen.assetGens[0],
					amt:      5,

					anchorPoint: assetGen.anchorPoints[0],
				},
			},
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierAssetID(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 2,
			},
			numAssets: 0,
			err:       tapfreighter.ErrMatchingAssetsNotFound,
		},

		// Create three assets, the first two have a group key but
		// different asset IDs, the other doesn't have a group key.
		// We should only get the first two assets back.
		{
			name: "multiple different assets with same group key",
			assets: []assetDesc{
				{
					assetGen: assetGen.assetGens[0],
					amt:      10,

					anchorPoint: assetGen.anchorPoints[0],

					keyGroup: assetGen.groupKeys[0],
				},
				{
					assetGen: assetGen.assetGens[1],
					amt:      20,

					anchorPoint: assetGen.anchorPoints[0],

					keyGroup:            assetGen.groupKeys[0],
					groupAnchorGen:      &assetGen.assetGens[0],
					groupAnchorGenPoint: &assetGen.anchorPoints[0],
				},
				{
					assetGen: assetGen.assetGens[1],
					amt:      15,

					anchorPoint: assetGen.anchorPoints[1],
					noGroupKey:  true,
				},
			},
			constraints: tapfreighter.CommitmentConstraints{
				AssetSpecifier: assetGen.assetSpecifierGroupKey(
					0, assetGen.anchorPoints[0],
				),
				MinAmt: 1,
			},
			numAssets: 2,
			sum:       30,
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
			selectedAssets, err := assetsStore.ListEligibleCoins(
				ctx, tc.constraints,
			)
			require.ErrorIs(t, err, tc.err)

			// The number of selected assets should match up
			// properly.
			require.Equal(t, tc.numAssets, len(selectedAssets))

			// Also verify the expected sum of asset amounts
			// selected.
			var sum int64
			for _, a := range selectedAssets {
				sum += int64(a.Asset.Amount)
			}
			require.Equal(t, tc.sum, sum)

			// If the expectation is to get a single asset, let's
			// make sure we can fetch the same asset commitment with
			// the FetchCommitment method.
			if tc.numAssets != 1 {
				return
			}

			sa := selectedAssets[0]
			assetCommitment, err := assetsStore.FetchCommitment(
				ctx, sa.Asset.ID(), sa.AnchorPoint,
				sa.Asset.GroupKey, &sa.Asset.ScriptKey, false,
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
				sa.Asset.GroupKey, &sa.Asset.ScriptKey, false,
			)
			require.ErrorIs(
				t, err, tapfreighter.ErrMatchingAssetsNotFound,
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

	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetVersionV0 := asset.V0
	assetVersionV1 := asset.V1

	// First, we'll generate 3 assets, each all sharing the same anchor
	// transaction, but having distinct asset IDs. Two of them will have a
	// V1 asset version.
	const numAssets = 3
	assetGen := newAssetGenerator(t, numAssets, 3)
	assetGen.genAssets(t, assetsStore, []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],

			// This is the script key of the asset we'll be
			// modifying.
			scriptKey: &targetScriptKey,

			amt:          16,
			assetVersion: &assetVersionV1,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[0],

			amt:          10,
			assetVersion: &assetVersionV1,
		},
		{
			assetGen:    assetGen.assetGens[2],
			anchorPoint: assetGen.anchorPoints[0],

			amt:          6,
			assetVersion: &assetVersionV0,
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
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    1000,
	})

	const heightHint = 1450

	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	newScriptKey2 := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	newAmt := 9

	newRootHash := sha256.Sum256([]byte("kek"))
	newRootValue := uint64(100)

	newWitness := asset.Witness{
		PrevID:          &asset.PrevID{},
		TxWitness:       [][]byte{{0x01}, {0x02}},
		SplitCommitment: nil,
	}

	chainFees := int64(100)

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, numAssets)

	inputAsset := allAssets[0]
	senderAsset := inputAsset.Copy()
	senderAsset.ScriptKey = newScriptKey
	senderProof := randProof(t, senderAsset)
	receiverAsset := inputAsset.Copy()
	receiverAsset.ScriptKey = newScriptKey2
	receiverProof := randProof(t, receiverAsset)

	senderProofBytes, err := senderProof.Bytes()
	require.NoError(t, err)

	receiverProofBytes, err := receiverProof.Bytes()
	require.NoError(t, err)

	// With the assets inserted, we'll now construct the struct that will be
	// used to commit a new spend on disk.
	anchorTxHash := newAnchorTx.TxHash()
	spendDelta := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: heightHint,
		ChainFees:          chainFees,
		// We'll actually modify only one of the assets. This simulates
		// us create a split of the asset to send to another party.
		Inputs: []tapfreighter.TransferInput{{
			PrevID: asset.PrevID{
				OutPoint: wire.OutPoint{
					Hash:  assetGen.anchorTxs[0].TxHash(),
					Index: 0,
				},
				ID: inputAsset.ID(),
				ScriptKey: asset.ToSerialized(
					inputAsset.ScriptKey.PubKey,
				),
			},
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 0,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				// This can be anything since we assume the
				// application sets it properly.
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
				PkScript:         bytes.Repeat([]byte{0x1}, 34),
			},
			ScriptKey:        newScriptKey,
			ScriptKeyLocal:   true,
			Amount:           uint64(newAmt),
			LockTime:         1337,
			RelativeLockTime: 31337,
			WitnessData:      []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				newRootHash, newRootValue,
			),
			// The receiver wants a V0 asset version.
			AssetVersion: asset.V0,
			ProofSuffix:  receiverProofBytes,
			Position:     0,
		}, {
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 1,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				// This can be anything since we assume the
				// application sets it properly.
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
				PkScript:         bytes.Repeat([]byte{0x2}, 34),
			},
			ScriptKey:      newScriptKey2,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount - uint64(newAmt),
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				newRootHash, newRootValue,
			),
			// As the sender, we'll send our change back to a V1
			// asset version.
			AssetVersion: asset.V1,
			ProofSuffix:  senderProofBytes,
			Position:     1,
		}},
	}
	require.NoError(t, assetsStore.LogPendingParcel(
		ctx, spendDelta, leaseOwner, leaseExpiry,
	))

	assetID := inputAsset.ID()
	receiverIdentifier := tapfreighter.NewOutputIdentifier(
		assetID, 0, *newScriptKey.PubKey,
	)
	senderIdentifier := tapfreighter.NewOutputIdentifier(
		assetID, 0, *newScriptKey2.PubKey,
	)
	proofs := map[tapfreighter.OutputIdentifier]*proof.AnnotatedProof{
		receiverIdentifier: {
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *newScriptKey.PubKey,
			},
			Blob: receiverProofBytes,
		},
		senderIdentifier: {
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *newScriptKey2.PubKey,
			},
			Blob: senderProofBytes,
		},
	}

	// At this point, we should be able to query for the log parcel, by
	// looking for all unconfirmed transfers.
	assetTransfers, err := db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// This transfer's anchor transaction is unconfirmed. Therefore, the
	// anchor transaction block hash field of the transfer should be unset.
	require.Empty(t, assetTransfers[0].AnchorTxBlockHash)

	// We should also be able to find it based on its outpoint.
	firstOutput := spendDelta.Outputs[0]
	firstOutputAnchor := firstOutput.Anchor
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: firstOutputAnchor.OutPoint.Hash[:],
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// Check that the new UTXO is found among our managed UTXOs.
	utxos, err = assetsStore.FetchManagedUTXOs(ctx)
	require.NoError(t, err)
	require.Len(t, utxos, 3)

	// First UTXO should remain unchanged. It should now have a lease
	// expiry and owner set.
	require.Equal(t, assetGen.anchorPoints[0], utxos[0].OutPoint)
	require.Equal(t, leaseOwner[:], utxos[0].LeaseOwner[:])
	require.NotZero(t, utxos[0].LeaseExpiry)

	// Second UTXO will be our new one.
	newUtxo := utxos[1]
	require.Equal(t, firstOutputAnchor.OutPoint, newUtxo.OutPoint)
	require.Equal(t, firstOutputAnchor.InternalKey, newUtxo.InternalKey)
	require.Equal(
		t, spendDelta.AnchorTx.TxOut[0].Value,
		int64(newUtxo.OutputValue),
	)
	require.Equal(
		t, firstOutputAnchor.TaprootAssetRoot, newUtxo.TaprootAssetRoot,
	)
	require.Equal(t, firstOutputAnchor.MerkleRoot, newUtxo.MerkleRoot)
	require.Equal(
		t, firstOutputAnchor.TapscriptSibling, newUtxo.TapscriptSibling,
	)

	// Finally, if we look for the set of confirmed transfers, nothing
	// should be returned.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// This should also show up in the set of pending parcels. It should
	// also match exactly the inbound parcel we used to make the delta.
	parcels, err := assetsStore.PendingParcels(ctx)
	require.NoError(t, err)
	require.Len(t, parcels, 1)
	require.Equal(t, spendDelta, parcels[0])

	// We should also be able to query for the parcel when filtering on its
	// anchor transaction hash.
	parcels, err = assetsStore.QueryParcels(ctx, &anchorTxHash, true)
	require.NoError(t, err)
	require.Len(t, parcels, 1)
	require.Equal(t, spendDelta, parcels[0])

	// With the asset delta committed and verified, we'll now mark the
	// delta as being confirmed on chain.
	fakeBlockHash := chainhash.Hash(sha256.Sum256([]byte("fake")))
	blockHeight := int32(100)
	txIndex := int32(10)
	err = assetsStore.LogAnchorTxConfirm(
		ctx, &tapfreighter.AssetConfirmEvent{
			AnchorTXID:  firstOutputAnchor.OutPoint.Hash,
			TxIndex:     txIndex,
			BlockHeight: blockHeight,
			BlockHash:   fakeBlockHash,
			FinalProofs: proofs,
		}, nil,
	)
	require.NoError(t, err)

	// Make sure that if we query for the asset transfer again, we now have
	// the block hash and height set.
	parcels, err = assetsStore.QueryParcels(ctx, &anchorTxHash, false)
	require.NoError(t, err)
	require.Len(t, parcels, 1)
	spendDelta.AnchorTxBlockHash = fn.Some(fakeBlockHash)
	spendDelta.AnchorTxBlockHeight = uint32(blockHeight)
	require.Equal(t, spendDelta, parcels[0])

	// We'll now fetch all the assets to verify that they were updated
	// properly on disk.
	chainAssets, err := assetsStore.FetchAllAssets(ctx, false, true, nil)
	require.NoError(t, err)

	// We split one asset into two UTXOs, so there's now one more than
	// before.
	require.Equal(t, numAssets+1, len(chainAssets))

	var (
		mutationFound bool
		inputLeased   bool
	)
	for _, chainAsset := range chainAssets {
		switch {
		// We should find the mutated asset with its _new_ script key
		// and amount.
		case chainAsset.ScriptKey.PubKey.IsEqual(newScriptKey.PubKey):
			require.Equal(
				t, firstOutputAnchor.OutPoint,
				chainAsset.AnchorOutpoint,
			)
			require.True(t, chainAsset.Amount == uint64(newAmt))
			require.True(
				t, mssmt.IsEqualNode(
					chainAsset.SplitCommitmentRoot,
					firstOutput.SplitCommitmentRoot,
				), "split roots don't match",
			)

			// The version of the new asset should be V0, even
			// though it was initially a V1 asset.
			require.Equal(t, asset.V0, chainAsset.Version)

			mutationFound = true

		// Our two other assets should have their asset version
		// unchanged. These were passive assets in the transfer.
		case chainAsset.Genesis.Tag == assetGen.assetGens[1].Tag:
			require.Equal(t, asset.V1, chainAsset.Version)
		case chainAsset.Genesis.Tag == assetGen.assetGens[2].Tag:
			require.Equal(t, asset.V0, chainAsset.Version)

		// The newly created asset should have an asset version of V1.
		case chainAsset.ScriptKey.PubKey.IsEqual(newScriptKey2.PubKey):
			require.Equal(t, asset.V1, chainAsset.Version)

		default:
			t.Fatalf("unknown asset version not asserted: %v",
				spew.Sdump(chainAsset.Genesis))
		}

		// The single UTXO we had at the beginning should now be leased
		// for an hour.
		if chainAsset.AnchorOutpoint == utxos[0].OutPoint {
			require.Equal(
				t, leaseOwner, chainAsset.AnchorLeaseOwner,
			)
			require.NotNil(t, chainAsset.AnchorLeaseExpiry)
			require.Equal(
				t, leaseExpiry.Unix(),
				chainAsset.AnchorLeaseExpiry.Unix(),
			)
			inputLeased = true
		}
	}
	require.True(t, mutationFound)
	require.True(t, inputLeased)

	// As a final check for the asset, we'll fetch its blob to ensure it's
	// been updated on disk.
	diskSenderBlob, err := db.FetchAssetProof(ctx, FetchAssetProof{
		TweakedScriptKey: newScriptKey.PubKey.SerializeCompressed(),
	})
	require.NoError(t, err)
	require.Equal(t, receiverProofBytes, diskSenderBlob[0].ProofFile)

	// If we fetch the chain transaction again, then it should have the
	// conf information populated.
	anchorTx, err := db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Equal(t, fakeBlockHash[:], anchorTx.BlockHash[:])
	require.Equal(
		t, uint32(blockHeight),
		extractSqlInt32[uint32](anchorTx.BlockHeight),
	)
	require.Equal(
		t, uint32(txIndex), extractSqlInt32[uint32](anchorTx.TxIndex),
	)
	require.Equal(t, chainFees, anchorTx.ChainFees)

	// At this point, there should be no more pending parcels.
	parcels, err = assetsStore.PendingParcels(ctx)
	require.NoError(t, err)
	require.Len(t, parcels, 0)
}

// TestAssetGroupWitnessUpsert tests that if you try to insert another asset
// group witness with the same asset_gen_id, then only one is actually created.
func TestAssetGroupWitnessUpsert(t *testing.T) {
	t.Parallel()

	_, _, db := newAssetStore(t)
	ctx := context.Background()

	internalKey := test.RandPubKey(t)

	// First, we'll insert all the required rows we need to satisfy the
	// foreign key constraints needed to insert a new genesis witness.
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
	// witness.
	groupWitnessID, err := db.UpsertAssetGroupWitness(
		ctx, AssetGroupWitness{
			WitnessStack: []byte{0x01},
			GenAssetID:   genAssetID,
			GroupKeyID:   groupID,
		})
	require.NoError(t, err)

	// If we insert the very same sig, then we should get the same group sig
	// ID back.
	groupWitnessID2, err := db.UpsertAssetGroupWitness(
		ctx, AssetGroupWitness{
			WitnessStack: []byte{0x01},
			GenAssetID:   genAssetID,
			GroupKeyID:   groupID,
		})
	require.NoError(t, err)

	require.Equal(t, groupWitnessID, groupWitnessID2)
}

// TestAssetGroupComplexWitness tests that we can store and load an asset group
// witness of multiple elements.
func TestAssetGroupComplexWitness(t *testing.T) {
	t.Parallel()

	mintingStore, assetStore, db := newAssetStore(t)
	ctx := context.Background()

	internalKey := test.RandPubKey(t)
	groupAnchorGen := asset.RandGenesis(t, asset.RandAssetType(t))
	groupAnchorGen.MetaHash = [32]byte{}
	tapscriptRoot := test.RandBytes(32)
	groupSig := test.RandBytes(64)

	// First, we'll insert all the required rows we need to satisfy the
	// foreign key constraints needed to insert a new genesis witness.
	genesisPointID, err := upsertGenesisPoint(
		ctx, db, groupAnchorGen.FirstPrevOut,
	)
	require.NoError(t, err)

	genAssetID, err := upsertGenesis(ctx, db, genesisPointID, groupAnchorGen)
	require.NoError(t, err)

	groupKey := asset.GroupKey{
		RawKey: keychain.KeyDescriptor{
			PubKey: internalKey,
		},
		GroupPubKey:   *internalKey,
		TapscriptRoot: tapscriptRoot,
		Witness:       fn.MakeSlice(tapscriptRoot, groupSig),
	}

	_, err = upsertGroupKey(
		ctx, &groupKey, assetStore.db, genesisPointID, genAssetID,
	)
	require.NoError(t, err)

	// If we fetch the group, it should have all the fields correctly
	// populated.

	storedGroup, err := mintingStore.FetchGroupByGroupKey(ctx, internalKey)
	require.NoError(t, err)

	require.Equal(t, groupAnchorGen, *storedGroup.Genesis)
	require.True(t, groupKey.IsEqual(storedGroup.GroupKey))
}

// TestAssetGroupV1 tests that we can store and fetch an asset group version 1.
func TestAssetGroupV1(t *testing.T) {
	t.Parallel()

	mintingStore, assetStore, db := newAssetStore(t)
	ctx := context.Background()

	internalKey := test.RandPubKey(t)
	groupAnchorGen := asset.RandGenesis(t, asset.RandAssetType(t))
	groupAnchorGen.MetaHash = [32]byte{}
	tapscriptRoot := test.RandBytes(32)
	customTapscriptRoot := test.RandHash()
	groupSig := test.RandBytes(64)

	// First, we'll insert all the required rows we need to satisfy the
	// foreign key constraints needed to insert a new genesis witness.
	genesisPointID, err := upsertGenesisPoint(
		ctx, db, groupAnchorGen.FirstPrevOut,
	)
	require.NoError(t, err)

	genAssetID, err := upsertGenesis(
		ctx, db, genesisPointID, groupAnchorGen,
	)
	require.NoError(t, err)

	groupKey := asset.GroupKey{
		Version: asset.GroupKeyV1,
		RawKey: keychain.KeyDescriptor{
			PubKey: internalKey,
		},
		GroupPubKey:   *internalKey,
		TapscriptRoot: tapscriptRoot,
		CustomTapscriptRoot: fn.Some[chainhash.Hash](
			customTapscriptRoot,
		),
		Witness: fn.MakeSlice(tapscriptRoot, groupSig),
	}

	// Upsert, fetch, and check the group key.
	_, err = upsertGroupKey(
		ctx, &groupKey, assetStore.db, genesisPointID, genAssetID,
	)
	require.NoError(t, err)

	storedGroup, err := mintingStore.FetchGroupByGroupKey(ctx, internalKey)
	require.NoError(t, err)

	require.Equal(t, groupAnchorGen, *storedGroup.Genesis)
	require.True(t, groupKey.IsEqual(storedGroup.GroupKey))

	// Formulate a new group key where the custom tapscript root is None.
	// Check that we can insert and fetch the group key.
	groupKeyCustomRootNone := asset.GroupKey{
		Version: asset.GroupKeyV1,
		RawKey: keychain.KeyDescriptor{
			PubKey: internalKey,
		},
		GroupPubKey:         *internalKey,
		TapscriptRoot:       tapscriptRoot,
		CustomTapscriptRoot: fn.None[chainhash.Hash](),
		Witness:             fn.MakeSlice(tapscriptRoot, groupSig),
	}

	// Upsert, fetch, and check the group key.
	_, err = upsertGroupKey(
		ctx, &groupKeyCustomRootNone, assetStore.db, genesisPointID,
		genAssetID,
	)
	require.NoError(t, err)

	storedGroup2, err := mintingStore.FetchGroupByGroupKey(ctx, internalKey)
	require.NoError(t, err)

	require.Equal(t, groupAnchorGen, *storedGroup2.Genesis)
	require.True(t, groupKeyCustomRootNone.IsEqual(storedGroup2.GroupKey))
}

// TestAssetGroupKeyUpsert tests that if you try to insert another asset group
// key with the same tweaked_group_key, then only one is actually created.
func TestAssetGroupKeyUpsert(t *testing.T) {
	t.Parallel()

	_, _, db := newAssetStore(t)
	ctx := context.Background()

	internalKey := test.RandPubKey(t)
	groupKey := internalKey.SerializeCompressed()
	keyIndex := test.RandInt[int32]()
	scriptRoot := test.RandBytes(32)
	witness := test.RandBytes(64)

	// First, we'll insert all the required rows we need to satisfy the
	// foreign key constraints needed to insert a new genesis sig.
	keyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    groupKey,
		KeyFamily: asset.TaprootAssetsKeyFamily,
		KeyIndex:  keyIndex,
	})
	require.NoError(t, err)

	genesisPointID, err := upsertGenesisPoint(ctx, db, test.RandOp(t))
	require.NoError(t, err)

	// Now we'll insert an asset group key. We use a non-empty tapscript
	// root to test that we can fetch the tapscript root after the upsert,
	// even though we only store empty tapscript roots currently.
	groupID, err := db.UpsertAssetGroupKey(ctx, AssetGroupKey{
		TweakedGroupKey: groupKey,
		TapscriptRoot:   scriptRoot,
		InternalKeyID:   keyID,
		GenesisPointID:  genesisPointID,
	})
	require.NoError(t, err)

	// If we insert the very same group key, then we should get the same
	// group ID back.
	groupID2, err := db.UpsertAssetGroupKey(ctx, AssetGroupKey{
		TweakedGroupKey: groupKey,
		TapscriptRoot:   scriptRoot,
		InternalKeyID:   keyID,
		GenesisPointID:  genesisPointID,
	})
	require.NoError(t, err)

	require.Equal(t, groupID, groupID2)

	// Insert a genesis and group sig to fill out the group key view.
	genAssetID, err := upsertGenesis(
		ctx, db, genesisPointID, asset.RandGenesis(t, asset.Normal),
	)
	require.NoError(t, err)

	_, err = db.UpsertAssetGroupWitness(ctx, AssetGroupWitness{
		WitnessStack: witness,
		GenAssetID:   genAssetID,
		GroupKeyID:   groupID,
	})
	require.NoError(t, err)

	// If we fetch the group key, it should match the inserted fields.
	groupInfo, err := db.FetchGroupByGroupKey(ctx, groupKey[:])
	require.NoError(t, err)

	require.Equal(t, genAssetID, groupInfo.GenAssetID)
	require.Equal(t, groupKey, groupInfo.RawKey)
	require.EqualValues(
		t, asset.TaprootAssetsKeyFamily, groupInfo.KeyFamily,
	)
	require.Equal(t, keyIndex, groupInfo.KeyIndex)
	require.Equal(t, scriptRoot, groupInfo.TapscriptRoot)
	require.Equal(t, witness, groupInfo.WitnessStack)
}

// TestFetchGroupedAssets tests that the FetchGroupedAssets query correctly
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

	// Record the genesis information and anchor point of the third asset,
	// which is needed for reissuance into the same group.
	reissueGen := assetGen.assetGens[2]
	reissueGen.FirstPrevOut = assetGen.anchorPoints[2]

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
			assetGen:       assetGen.assetGens[3],
			groupAnchorGen: &reissueGen,
			anchorPoint:    assetGen.anchorPoints[3],
			keyGroup:       assetGen.groupKeys[1],
			amt:            2,
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
	allAssets, err := assetsStore.FetchAllAssets(ctx, false, false, nil)
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
		require.Equal(t, a.MetaHash, b.MetaHash)
		require.Equal(t, a.Type, b.Type)
	}

	equalityCheck(allAssets[1].Asset, groupedAssets[0])
	equalityCheck(allAssets[2].Asset, groupedAssets[1])
	equalityCheck(allAssets[3].Asset, groupedAssets[2])
}

// TestTransferOutputProofDeliveryStatus tests that we can properly set the
// proof delivery status of a transfer output.
func TestTransferOutputProofDeliveryStatus(t *testing.T) {
	t.Parallel()

	// First, we'll create a new assets store. We'll use this to store the
	// asset and the outbound parcel in the database.
	_, assetsStore, db := newAssetStore(t)
	ctx := context.Background()

	// Generate a single asset.
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetVersionV0 := asset.V0

	const numAssets = 1
	assetGen := newAssetGenerator(t, numAssets, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],

			// This is the script key of the asset we'll be
			// modifying.
			scriptKey: &targetScriptKey,

			amt:          16,
			assetVersion: &assetVersionV0,
		},
	})

	// Formulate a spend delta outbound parcel. This parcel will be stored
	// in the database. We will then manipulate the proof delivery status
	// of the first transfer output.
	//
	// First, we'll generate a new anchor transaction for use in the parcel.
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{})
	newAnchorTx.TxIn[0].SignatureScript = []byte{}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	// Next, we'll generate script keys for the two transfer outputs.
	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	newScriptKey2 := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	// The outbound parcel will split the asset into two outputs. The first
	// will have an amount of 9, and the second will have the remainder of
	// the asset amount.
	newAmt := 9

	senderBlob := bytes.Repeat([]byte{0x01}, 100)
	receiverBlob := bytes.Repeat([]byte{0x02}, 100)

	newWitness := asset.Witness{
		PrevID:          &asset.PrevID{},
		TxWitness:       [][]byte{{0x01}, {0x02}},
		SplitCommitment: nil,
	}

	// Mock proof courier address.
	proofCourierAddrBytes := []byte("universerpc://localhost:10009")

	// Fetch the asset that was previously generated.
	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, numAssets)

	inputAsset := allAssets[0]

	// Construct the outbound parcel that will be stored in the database.
	spendDelta := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		ChainFees:          int64(100),
		Inputs: []tapfreighter.TransferInput{{
			PrevID: asset.PrevID{
				OutPoint: wire.OutPoint{
					Hash:  assetGen.anchorTxs[0].TxHash(),
					Index: 0,
				},
				ID: inputAsset.ID(),
				ScriptKey: asset.ToSerialized(
					inputAsset.ScriptKey.PubKey,
				),
			},
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 0,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			},
			ScriptKey:             newScriptKey,
			ScriptKeyLocal:        false,
			Amount:                uint64(newAmt),
			LockTime:              1337,
			RelativeLockTime:      31337,
			WitnessData:           []asset.Witness{newWitness},
			SplitCommitmentRoot:   nil,
			AssetVersion:          asset.V0,
			ProofSuffix:           receiverBlob,
			ProofCourierAddr:      proofCourierAddrBytes,
			ProofDeliveryComplete: fn.Some[bool](false),
			Position:              0,
		}, {
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 1,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			},
			ScriptKey:           newScriptKey2,
			ScriptKeyLocal:      true,
			Amount:              inputAsset.Amount - uint64(newAmt),
			WitnessData:         []asset.Witness{newWitness},
			SplitCommitmentRoot: nil,
			AssetVersion:        asset.V1,
			ProofSuffix:         senderBlob,
			Position:            1,
		}},
	}

	// Store the outbound parcel in the database.
	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)
	require.NoError(t, assetsStore.LogPendingParcel(
		ctx, spendDelta, leaseOwner, leaseExpiry,
	))

	// At this point, we should be able to query for the log parcel, by
	// looking for all unconfirmed transfers.
	assetTransfers, err := db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// This transfer's anchor transaction is unconfirmed. Therefore, the
	// anchor transaction block hash field of the transfer should be unset.
	require.Empty(t, assetTransfers[0].AnchorTxBlockHash)

	// At this point we will confirm the anchor tx on-chain.
	assetTransfer := assetTransfers[0]
	randBlockHash := test.RandHash()

	err = db.ConfirmChainAnchorTx(ctx, AnchorTxConf{
		Txid:        assetTransfer.Txid,
		BlockHash:   randBlockHash[:],
		BlockHeight: sqlInt32(441),
		TxIndex:     sqlInt32(1),
	})
	require.NoError(t, err)

	// Ensure that parcel is still pending. It should be pending due to the
	// incomplete proof delivery status of some transfer outputs.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// We should also be able to find the transfer outputs.
	transferOutputs, err := db.FetchTransferOutputs(
		ctx, assetTransfers[0].ID,
	)
	require.NoError(t, err)
	require.Len(t, transferOutputs, 2)

	// Let's confirm that the proof has not been delivered for the first
	// transfer output and that the proof delivery status for the second
	// transfer output is still unset.
	require.Equal(
		t, sqlBool(false), transferOutputs[0].ProofDeliveryComplete,
	)
	require.Equal(
		t, sql.NullBool{}, transferOutputs[1].ProofDeliveryComplete,
	)

	// We will now set the status of the transfer output proof to
	// "delivered".
	//
	// nolint: lll
	err = db.SetTransferOutputProofDeliveryStatus(
		ctx, OutputProofDeliveryStatus{
			DeliveryComplete:         sqlBool(true),
			SerializedAnchorOutpoint: transferOutputs[0].AnchorOutpoint,
			Position:                 transferOutputs[0].Position,
		},
	)
	require.NoError(t, err)

	// We will check to ensure that the transfer output proof delivery
	// status has been updated correctly.
	transferOutputs, err = db.FetchTransferOutputs(
		ctx, assetTransfers[0].ID,
	)
	require.NoError(t, err)
	require.Len(t, transferOutputs, 2)

	// The proof delivery status of the first output should be set to
	// delivered (true).
	require.Equal(
		t, sqlBool(true), transferOutputs[0].ProofDeliveryComplete,
	)

	// The proof delivery status of the second output should be unset.
	require.Equal(
		t, sql.NullBool{}, transferOutputs[1].ProofDeliveryComplete,
	)

	// At this point the anchoring transaction has been confirmed on-chain
	// and the proof delivery status shows complete for all applicable
	// transfer outputs. Therefore, we should not be able to find any
	// pending transfers.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 0)

	// Given that the asset transfer is completely finalised, we should be
	// able to find it among the confirmed transfers. We will test this by
	// retrieving the transfer by not specifying the pending transfers only
	// flag and, in another attempt, by setting the flag to false.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(false),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// Ensure that the anchor transaction is confirmed on-chain by verifying
	// that the anchor transaction block hash field on the transfer is
	// correctly set.
	require.Equal(
		t, randBlockHash[:], assetTransfers[0].AnchorTxBlockHash,
	)
}

func TestQueryAssetBurns(t *testing.T) {
	t.Parallel()

	// First, we'll create a new assets store. We'll use this to store the
	// asset and the outbound parcel in the database.
	_, assetsStore, db := newAssetStore(t)
	ctx := context.Background()

	// Generate a single asset.
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetVersionV0 := asset.V0

	const numAssets = 1
	assetGen := newAssetGenerator(t, numAssets, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],

			// This is the script key of the asset we'll be
			// modifying.
			scriptKey: &targetScriptKey,

			amt:          16,
			assetVersion: &assetVersionV0,
		},
	})

	// Formulate a spend delta outbound parcel. This parcel will be stored
	// in the database. We will then manipulate the proof delivery status
	// of the first transfer output.
	//
	// First, we'll generate a new anchor transaction for use in the parcel.
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{})
	newAnchorTx.TxIn[0].SignatureScript = []byte{}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	// Next, we'll generate script keys for the two transfer outputs.
	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	newScriptKey2 := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})

	// The outbound parcel will split the asset into two outputs. The first
	// will have an amount of 9, and the second will have the remainder of
	// the asset amount.
	newAmt := 9

	senderBlob := bytes.Repeat([]byte{0x01}, 100)
	receiverBlob := bytes.Repeat([]byte{0x02}, 100)

	newWitness := asset.Witness{
		PrevID:          &asset.PrevID{},
		TxWitness:       [][]byte{{0x01}, {0x02}},
		SplitCommitment: nil,
	}

	// Mock proof courier address.
	proofCourierAddrBytes := []byte("universerpc://localhost:10009")

	// Fetch the asset that was previously generated.
	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, numAssets)

	inputAsset := allAssets[0]

	// Construct the outbound parcel that will be stored in the database.
	spendDelta := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		ChainFees:          int64(100),
		Inputs: []tapfreighter.TransferInput{{
			PrevID: asset.PrevID{
				OutPoint: wire.OutPoint{
					Hash:  assetGen.anchorTxs[0].TxHash(),
					Index: 0,
				},
				ID: inputAsset.ID(),
				ScriptKey: asset.ToSerialized(
					inputAsset.ScriptKey.PubKey,
				),
			},
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 0,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			},
			ScriptKey:             newScriptKey,
			ScriptKeyLocal:        false,
			Amount:                uint64(newAmt),
			LockTime:              1337,
			RelativeLockTime:      31337,
			WitnessData:           []asset.Witness{newWitness},
			SplitCommitmentRoot:   nil,
			AssetVersion:          asset.V0,
			ProofSuffix:           receiverBlob,
			ProofCourierAddr:      proofCourierAddrBytes,
			ProofDeliveryComplete: fn.Some[bool](false),
			Position:              0,
		}, {
			Anchor: tapfreighter.Anchor{
				Value: 1000,
				OutPoint: wire.OutPoint{
					Hash:  anchorTxHash,
					Index: 1,
				},
				InternalKey: keychain.KeyDescriptor{
					PubKey: test.RandPubKey(t),
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							rand.Int31(),
						),
						Index: uint32(
							test.RandInt[int32](),
						),
					},
				},
				TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
				MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			},
			ScriptKey:           newScriptKey2,
			ScriptKeyLocal:      true,
			Amount:              inputAsset.Amount - uint64(newAmt),
			WitnessData:         []asset.Witness{newWitness},
			SplitCommitmentRoot: nil,
			AssetVersion:        asset.V1,
			ProofSuffix:         senderBlob,
			Position:            1,
		}},
	}

	// Store the outbound parcel in the database.
	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)
	require.NoError(t, assetsStore.LogPendingParcel(
		ctx, spendDelta, leaseOwner, leaseExpiry,
	))

	// At this point, we should be able to query for the log parcel, by
	// looking for all unconfirmed transfers.
	assetTransfers, err := db.QueryAssetTransfers(ctx, TransferQuery{
		PendingTransfersOnly: sqlBool(true),
	})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// This transfer's anchor transaction is unconfirmed. Therefore, the
	// anchor transaction block hash field of the transfer should be unset.
	require.Empty(t, assetTransfers[0].AnchorTxBlockHash)

	// At this point we will confirm the anchor tx on-chain.
	assetTransfer := assetTransfers[0]
	randBlockHash := test.RandHash()

	err = db.ConfirmChainAnchorTx(ctx, AnchorTxConf{
		Txid:        assetTransfer.Txid,
		BlockHash:   randBlockHash[:],
		BlockHeight: sqlInt32(441),
		TxIndex:     sqlInt32(1),
	})
	require.NoError(t, err)

	// We should also be able to find the transfer outputs.
	transferOutputs, err := db.FetchTransferOutputs(
		ctx, assetTransfers[0].ID,
	)
	require.NoError(t, err)
	require.Len(t, transferOutputs, 2)

	// We will now set the status of the transfer output proof to
	// "delivered".
	//
	// nolint: lll
	err = db.SetTransferOutputProofDeliveryStatus(
		ctx, OutputProofDeliveryStatus{
			DeliveryComplete:         sqlBool(true),
			SerializedAnchorOutpoint: transferOutputs[0].AnchorOutpoint,
			Position:                 transferOutputs[0].Position,
		},
	)
	require.NoError(t, err)

	// Given that the asset transfer is completely finalised, we should be
	// able to find it among the confirmed transfers. We will test this by
	// retrieving the transfer by not specifying the pending transfers only
	// flag and, in another attempt, by setting the flag to false.
	assetTransfers, err = db.QueryAssetTransfers(ctx, TransferQuery{})
	require.NoError(t, err)
	require.Len(t, assetTransfers, 1)

	// Let's insert a burn.
	assetID := inputAsset.ID()

	_, err = assetsStore.db.InsertBurn(ctx, sqlc.InsertBurnParams{
		TransferID: int32(assetTransfers[0].ID),
		Note: sql.NullString{
			String: "burn",
			Valid:  true,
		},
		AssetID:  assetID[:],
		GroupKey: nil,
		Amount:   424242,
	})
	require.NoError(t, err)

	burns, err := assetsStore.QueryBurns(ctx, sqlc.QueryBurnsParams{})

	// We should have one burn.
	require.NoError(t, err)
	require.Len(t, burns, 1)

	_, err = assetsStore.db.InsertBurn(ctx, sqlc.InsertBurnParams{
		TransferID: int32(assetTransfers[0].ID),
		Note: sql.NullString{
			String: "burn",
			Valid:  true,
		},
		AssetID:  assetID[:],
		GroupKey: nil,
		Amount:   424242,
	})
	require.NoError(t, err)

	// If we filter burns by the asset ID we should have 2 burns.
	burns, err = assetsStore.QueryBurns(ctx, sqlc.QueryBurnsParams{
		AssetID: assetID[:],
	})
	require.NoError(t, err)
	require.Len(t, burns, 2)
}

func TestQueryAssetBalances(t *testing.T) {
	t.Parallel()

	_, assetsStore, _ := newAssetStore(t)
	ctx := context.Background()

	// First, we'll generate 3 assets, two of them sharing the same anchor
	// transaction, but all having distinct asset IDs.
	const numAssets = 4
	const numGroups = 2
	assetGen := newAssetGenerator(t, numAssets, numGroups)
	assetDesc := []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],
			keyGroup:    assetGen.groupKeys[0],
			amt:         16,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[0],
			keyGroup:    assetGen.groupKeys[1],
			amt:         10,
		},
		{
			assetGen:            assetGen.assetGens[2],
			anchorPoint:         assetGen.anchorPoints[1],
			keyGroup:            assetGen.groupKeys[0],
			groupAnchorGen:      &assetGen.assetGens[0],
			groupAnchorGenPoint: &assetGen.anchorPoints[0],
			amt:                 6,
		},
		{
			assetGen:    assetGen.assetGens[3],
			anchorPoint: assetGen.anchorPoints[3],
			noGroupKey:  true,
			amt:         4,
		},
	}
	assetGen.genAssets(t, assetsStore, assetDesc)

	// Loop through assetDesc and sum the amt values
	totalBalances := uint64(0)
	for _, desc := range assetDesc {
		totalBalances += desc.amt
	}
	totalGroupedBalances := totalBalances - assetDesc[3].amt

	// At first, none of the assets should be leased.
	includeLeased := false
	balances, err := assetsStore.QueryBalancesByAsset(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	balancesByGroup, err := assetsStore.QueryAssetBalancesByGroup(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, balances, numAssets)
	require.Len(t, balancesByGroup, len(assetGen.groupKeys))

	balanceSum := uint64(0)
	for _, balance := range balances {
		balanceSum += balance.Balance
	}
	require.Equal(t, totalBalances, balanceSum)

	balanceByGroupSum := uint64(0)
	for _, balance := range balancesByGroup {
		balanceByGroupSum += balance.Balance
	}
	require.Equal(t, totalGroupedBalances, balanceByGroupSum)

	// Now we lease the first asset for 1 hour. This will cause the second
	// one also to be leased, since it's on the same anchor transaction. The
	// second asset is in its own group, so when leased, the entire group is
	// leased.
	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)
	err = assetsStore.LeaseCoins(
		ctx, leaseOwner, leaseExpiry, assetGen.anchorPoints[0],
	)
	require.NoError(t, err)
	// With the first two assets leased, the total balance of unleased
	// assets is the sum of the third and fourth asset.
	totalUnleasedBalances := assetDesc[2].amt + assetDesc[3].amt
	// The total of unleased grouped assets is only the third asset.
	totalUnleasedGroupedBalances := assetDesc[2].amt

	// Only two assets should be returned that is not leased.
	unleasedBalances, err := assetsStore.QueryBalancesByAsset(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, unleasedBalances, numAssets-2)

	// Only one group should be returned that is not leased.
	unleasedBalancesByGroup, err := assetsStore.QueryAssetBalancesByGroup(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, unleasedBalancesByGroup, numGroups-1)

	unleasedBalanceSum := uint64(0)
	for _, balance := range unleasedBalances {
		unleasedBalanceSum += balance.Balance
	}
	require.Equal(t, totalUnleasedBalances, unleasedBalanceSum)

	unleasedBalanceByGroupSum := uint64(0)
	for _, balance := range unleasedBalancesByGroup {
		unleasedBalanceByGroupSum += balance.Balance
	}
	require.Equal(
		t, totalUnleasedGroupedBalances, unleasedBalanceByGroupSum,
	)

	// Now we'll query with the leased assets included. This should return
	// the same results as when the assets where unleased.
	includeLeased = true
	includeLeasedBalances, err := assetsStore.QueryBalancesByAsset(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, includeLeasedBalances, numAssets)
	includeLeasedBalByGroup, err := assetsStore.QueryAssetBalancesByGroup(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, includeLeasedBalByGroup, len(assetGen.groupKeys))

	leasedBalanceSum := uint64(0)
	for _, balance := range includeLeasedBalances {
		leasedBalanceSum += balance.Balance
	}
	require.Equal(t, totalBalances, leasedBalanceSum)

	leasedBalanceByGroupSum := uint64(0)
	for _, balance := range includeLeasedBalByGroup {
		leasedBalanceByGroupSum += balance.Balance
	}
	require.Equal(t, totalGroupedBalances, leasedBalanceByGroupSum)
}

func TestQueryAssetBalancesCustomChannelFunding(t *testing.T) {
	t.Parallel()

	_, assetsStore, _ := newAssetStore(t)
	ctx := context.Background()

	// First, we'll generate 2 assets, one of them having a script key that
	// is the typical funding script key.
	const numAssets = 2
	const numGroups = 1
	assetGen := newAssetGenerator(t, numAssets, numGroups)

	fundingKey := tapscript.NewChannelFundingScriptTree()
	xOnlyKey, _ := schnorr.ParsePubKey(
		schnorr.SerializePubKey(fundingKey.TaprootKey),
	)
	fundingScriptKey := asset.ScriptKey{
		PubKey: xOnlyKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: fundingKey.InternalKey,
			},
			Type: asset.ScriptKeyScriptPathChannel,
		},
	}

	assetDesc := []assetDesc{
		{
			assetGen:    assetGen.assetGens[0],
			anchorPoint: assetGen.anchorPoints[0],
			keyGroup:    assetGen.groupKeys[0],
			amt:         8,
			scriptKey:   &fundingScriptKey,
		},
		{
			assetGen:    assetGen.assetGens[1],
			anchorPoint: assetGen.anchorPoints[1],
			keyGroup:    assetGen.groupKeys[0],
			amt:         12,
		},
	}
	assetGen.genAssets(t, assetsStore, assetDesc)

	// Hit both balance queries, they should return the same result.
	includeLeased := false
	balances, err := assetsStore.QueryBalancesByAsset(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	balancesByGroup, err := assetsStore.QueryAssetBalancesByGroup(
		ctx, nil, includeLeased, fn.None[asset.ScriptKeyType](),
	)
	require.NoError(t, err)
	require.Len(t, balances, numAssets-1)
	require.Len(t, balancesByGroup, numAssets-1)

	// Both sums should be equal to the amount of the second asset; the
	// asset that is not part of a custom channel funding tx.
	balanceSum := uint64(0)
	for _, balance := range balances {
		balanceSum += balance.Balance
	}
	require.Equal(t, assetDesc[1].amt, balanceSum)

	balanceByGroupSum := uint64(0)
	for _, balance := range balancesByGroup {
		balanceByGroupSum += balance.Balance
	}
	require.Equal(t, assetDesc[1].amt, balanceByGroupSum)

	// If we explicitly query for channel related script keys, we should get
	// just those assets.
	balances, err = assetsStore.QueryBalancesByAsset(
		ctx, nil, includeLeased,
		fn.Some(asset.ScriptKeyScriptPathChannel),
	)
	require.NoError(t, err)
	balancesByGroup, err = assetsStore.QueryAssetBalancesByGroup(
		ctx, nil, includeLeased,
		fn.Some(asset.ScriptKeyScriptPathChannel),
	)
	require.NoError(t, err)
	require.Len(t, balances, numAssets-1)
	require.Len(t, balancesByGroup, numAssets-1)

	balanceSum = uint64(0)
	for _, balance := range balances {
		balanceSum += balance.Balance
	}
	require.Equal(t, assetDesc[0].amt, balanceSum)

	balanceByGroupSum = uint64(0)
	for _, balance := range balancesByGroup {
		balanceByGroupSum += balance.Balance
	}
	require.Equal(t, assetDesc[0].amt, balanceByGroupSum)
}
