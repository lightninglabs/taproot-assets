package universe

import (
	"context"
	"errors"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// mockMultiverse implements MultiverseArchive, returning
// ErrNoUniverseRoot for any unknown universe.
type mockMultiverse struct {
	knownRoots map[IdentifierKey]Root
}

func (m *mockMultiverse) UniverseRootNode(_ context.Context,
	id Identifier) (Root, error) {

	root, ok := m.knownRoots[id.Key()]
	if !ok {
		return Root{}, ErrNoUniverseRoot
	}

	return root, nil
}

func (m *mockMultiverse) RootNodes(context.Context,
	RootNodesQuery) ([]Root, error) {

	return nil, nil
}

func (m *mockMultiverse) UpsertProofLeaf(context.Context,
	Identifier, LeafKey, *Leaf,
	*proof.MetaReveal) (*Proof, error) {

	return nil, nil
}

func (m *mockMultiverse) UpsertProofLeafBatch(context.Context,
	[]*Item) error {

	return nil
}

func (m *mockMultiverse) FetchProofLeaf(context.Context,
	Identifier, LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (m *mockMultiverse) DeleteUniverse(context.Context,
	Identifier) (string, error) {

	return "", nil
}

func (m *mockMultiverse) DeleteProofLeaf(context.Context,
	Identifier, LeafKey) (string, error) {

	return "", nil
}

func (m *mockMultiverse) UniverseLeafKeys(context.Context,
	UniverseLeafKeysQuery) ([]LeafKey, error) {

	return nil, nil
}

func (m *mockMultiverse) FetchLeaves(context.Context,
	[]MultiverseLeafDesc, ProofType) ([]MultiverseLeaf, error) {

	return nil, nil
}

func (m *mockMultiverse) MultiverseRootNode(context.Context,
	ProofType) (fn.Option[MultiverseRoot], error) {

	return fn.None[MultiverseRoot](), nil
}

// mockStorageBackend implements StorageBackend as a no-op.
type mockStorageBackend struct{}

func (m *mockStorageBackend) RootNode(
	context.Context) (mssmt.Node, string, error) {

	return nil, "", nil
}

func (m *mockStorageBackend) UpsertProofLeaf(context.Context,
	LeafKey, *Leaf, *proof.MetaReveal) (*Proof, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchProof(context.Context,
	LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchKeys(context.Context,
	UniverseLeafKeysQuery) ([]LeafKey, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchLeaves(
	context.Context, FetchLeavesQuery) ([]Leaf, error) {

	return nil, nil
}

func (m *mockStorageBackend) DeleteUniverse(
	context.Context) (string, error) {

	return "", nil
}

func (m *mockStorageBackend) DeleteProofLeaf(context.Context,
	LeafKey) (string, error) {

	return "", nil
}

// newTestArchive creates an Archive with a mock multiverse and a
// NewBaseTree that tracks how many times it's been called.
func newTestArchive(
	mv *mockMultiverse) (*Archive, *int) {

	var newTreeCalls int
	a := NewArchive(ArchiveConfig{
		NewBaseTree: func(id Identifier) StorageBackend {
			newTreeCalls++
			return &mockStorageBackend{}
		},
		Multiverse: mv,
	})

	return a, &newTreeCalls
}

func randIdentifier() Identifier {
	var id asset.ID
	//nolint:gosec
	_, _ = rand.Read(id[:])
	return Identifier{
		AssetID:   id,
		ProofType: ProofTypeIssuance,
	}
}

// TestFetchLeavesNonExistentUniverse verifies that FetchLeaves for
// a nonexistent universe returns empty results and does not allocate
// a cached backend.
func TestFetchLeavesNonExistentUniverse(t *testing.T) {
	t.Parallel()

	mv := &mockMultiverse{
		knownRoots: make(map[IdentifierKey]Root),
	}
	archive, newTreeCalls := newTestArchive(mv)

	ctx := context.Background()

	// Request leaves for many random (nonexistent) universes.
	for i := 0; i < 100; i++ {
		leaves, err := archive.FetchLeaves(
			ctx, randIdentifier(), FetchLeavesQuery{},
		)
		require.NoError(t, err)
		require.Nil(t, leaves)
	}

	// NewBaseTree should never have been called.
	require.Equal(t, 0, *newTreeCalls)
}

// TestFetchLeavesExistingUniverse verifies that FetchLeaves for a
// known universe does allocate a cached backend.
func TestFetchLeavesExistingUniverse(t *testing.T) {
	t.Parallel()

	id := randIdentifier()
	mv := &mockMultiverse{
		knownRoots: map[IdentifierKey]Root{
			id.Key(): {ID: id},
		},
	}
	archive, newTreeCalls := newTestArchive(mv)

	ctx := context.Background()

	leaves, err := archive.FetchLeaves(
		ctx, id, FetchLeavesQuery{},
	)
	require.NoError(t, err)
	require.Nil(t, leaves) // mock returns nil

	require.Equal(t, 1, *newTreeCalls)

	// Second call should hit the cache, not allocate again.
	_, err = archive.FetchLeaves(ctx, id, FetchLeavesQuery{})
	require.NoError(t, err)
	require.Equal(t, 1, *newTreeCalls)
}
func mintTestAsset(t *testing.T, grouped bool) *Item {
	t.Helper()

	genesisPrivKey := test.RandPrivKey()
	genesisScriptKey := test.PubToKeyDesc(genesisPrivKey.PubKey())

	var metaBlob [100]byte
	//nolint:gosec
	_, err := rand.Read(metaBlob[:])
	require.NoError(t, err)
	metaReveal := &proof.MetaReveal{
		Data: metaBlob[:],
	}

	assetGenesis := asset.RandGenesis(t, asset.Collectible)
	assetGenesis.MetaHash = metaReveal.MetaHash()
	assetGenesis.OutputIndex = 0

	// A group anchor carries a group key reveal in its proof, which is what
	// the archive partitions the batch on.
	var groupKey *asset.GroupKey
	if grouped {
		protoAsset := asset.NewAssetNoErr(
			t, assetGenesis, 1, 0, 0,
			asset.NewScriptKeyBip86(genesisScriptKey), nil,
		)
		groupKey = asset.RandGroupKey(t, assetGenesis, protoAsset)
	}

	tapCommitment, mintedAssets, err := commitment.Mint(
		nil, assetGenesis, groupKey, &commitment.AssetDetails{
			Type:      asset.Collectible,
			ScriptKey: genesisScriptKey,
		},
	)
	require.NoError(t, err)
	require.Len(t, mintedAssets, 1)

	internalKey := test.SchnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)

	changeInternalKey := test.RandPrivKey().PubKey()
	changeTaprootKey := txscript.ComputeTaprootKeyNoScript(
		changeInternalKey,
	)

	genesisTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: assetGenesis.FirstPrevOut,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, taprootKey),
			Value:    330,
		}, {
			PkScript: test.ComputeTaprootScript(
				t, changeTaprootKey,
			),
			Value: 333,
		}},
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(genesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)

	scriptKeyForMeta := asset.NewScriptKeyBip86(genesisScriptKey)
	metaReveals := map[asset.SerializedKey]*proof.MetaReveal{
		asset.ToSerialized(scriptKeyForMeta.PubKey): metaReveal,
	}

	// NewMintingBlobs verifies the proofs it builds, so a proof coming out
	// of here is one the archive will accept.
	proofs, err := proof.NewMintingBlobs(&proof.MintParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{genesisTx},
			},
			Tx:               genesisTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      internalKey,
			TaprootAssetRoot: tapCommitment,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 1,
				InternalKey: changeInternalKey,
				TapscriptProof: &proof.TapscriptProof{
					Bip86: true,
				},
			}},
		},
		GenesisPoint: genesisTx.TxIn[0].PreviousOutPoint,
	}, proof.MockVerifierCtx, proof.WithAssetMetaReveals(metaReveals))
	require.NoError(t, err)
	require.Len(t, proofs, 1)

	mintedAsset := mintedAssets[0]
	assetProof, ok := proofs[asset.ToSerialized(
		mintedAsset.ScriptKey.PubKey,
	)]
	require.True(t, ok)

	rawProof, err := assetProof.Bytes()
	require.NoError(t, err)

	scriptKey := asset.NewScriptKey(mintedAsset.ScriptKey.PubKey)

	return &Item{
		ID: Identifier{
			AssetID:   assetGenesis.ID(),
			ProofType: ProofTypeIssuance,
		},
		Key: BaseLeafKey{
			OutPoint:  assetProof.OutPoint(),
			ScriptKey: &scriptKey,
		},
		Leaf: &Leaf{
			GenesisWithGroup: GenesisWithGroup{
				Genesis:  assetGenesis,
				GroupKey: assetProof.Asset.GroupKey,
			},
			RawProof: rawProof,
			Asset:    &assetProof.Asset,
			Amt:      mintedAsset.Amount,
		},
	}
}

// newProofTestArchive creates an archive configured with proof verifier mocks.
func newProofTestArchive(mv *mockMultiverse) *Archive {
	vCtx := proof.MockVerifierCtx

	return NewArchive(ArchiveConfig{
		NewBaseTree: func(Identifier) StorageBackend {
			return &mockStorageBackend{}
		},
		HeaderVerifier:       vCtx.HeaderVerifier,
		MerkleVerifier:       vCtx.MerkleVerifier,
		GroupVerifier:        vCtx.GroupVerifier,
		Multiverse:           mv,
		ChainLookupGenerator: vCtx.ChainLookupGen,
		IgnoreChecker:        vCtx.IgnoreChecker,
	})
}

// TestUpsertProofLeafOutPointMismatch tests that a proof is rejected under a
// leaf key whose outpoint differs from the anchor outpoint of the proof.
func TestUpsertProofLeafOutPointMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	newItem := func(t *testing.T) *Item {
		item := mintTestAsset(t, false)
		key, ok := item.Key.(BaseLeafKey)
		require.True(t, ok)
		key.OutPoint.Index++
		item.Key = key

		return item
	}
	newArchive := func() *Archive {
		return newProofTestArchive(&mockMultiverse{
			knownRoots: make(map[IdentifierKey]Root),
		})
	}

	t.Run("single", func(t *testing.T) {
		t.Parallel()

		item := newItem(t)
		_, err := newArchive().UpsertProofLeaf(
			ctx, item.ID, item.Key, item.Leaf,
		)
		require.ErrorContains(t, err, "outpoint mismatch")
	})

	t.Run("batch", func(t *testing.T) {
		t.Parallel()

		err := newArchive().UpsertProofLeafBatch(
			ctx, []*Item{newItem(t)},
		)
		require.ErrorContains(t, err, "outpoint mismatch")
	})
}

// TestUpsertProofLeafRejectsUngroupedInGroupUniverse tests that an issuance
// proof for an ungrouped asset is rejected under a group key universe ID.
func TestUpsertProofLeafRejectsUngroupedInGroupUniverse(t *testing.T) {
	t.Parallel()

	item := mintTestAsset(t, false)
	require.Nil(t, item.Leaf.Asset.GroupKey)

	archive := newProofTestArchive(&mockMultiverse{
		knownRoots: make(map[IdentifierKey]Root),
	})
	id := item.ID
	id.GroupKey = test.RandPrivKey().PubKey()

	_, err := archive.UpsertProofLeaf(
		context.Background(), id, item.Key, item.Leaf,
	)
	require.ErrorContains(t, err, "group key mismatch")
}

type fallbackChainLookup struct {
	err   error
	calls atomic.Int32
}

func (l *fallbackChainLookup) TxBlockHeight(_ context.Context,
	_ chainhash.Hash) (uint32, error) {

	l.calls.Add(1)
	return 0, l.err
}

func (l *fallbackChainLookup) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return time.Time{}, nil
}

func (l *fallbackChainLookup) CurrentHeight(context.Context) (uint32, error) {
	return 0, nil
}

// TestBatchPreviousProofContext verifies that batch predecessor selection is
// scoped by both asset ID and leaf key, and carries the decoded proof height.
func TestBatchPreviousProofContext(t *testing.T) {
	t.Parallel()

	const prevBlockHeight = 950_239
	amount := uint64(100)
	prevProof, _ := proof.RandGenesisProofWithKey(
		t, asset.Normal, &amount, nil, true, nil, nil, nil, nil,
		asset.V0,
	)
	prevProof.BlockHeight = prevBlockHeight
	prevRawProof, err := prevProof.Bytes()
	require.NoError(t, err)

	prevScriptKey := asset.NewScriptKey(prevProof.Asset.ScriptKey.PubKey)
	prevLeafKey := BaseLeafKey{
		OutPoint:  prevProof.OutPoint(),
		ScriptKey: &prevScriptKey,
	}
	assetID := prevProof.Asset.ID()
	prevItem := &Item{
		ID: Identifier{
			AssetID:   assetID,
			ProofType: ProofTypeIssuance,
		},
		Key: prevLeafKey,
		Leaf: &Leaf{
			RawProof: prevRawProof,
			Asset:    &prevProof.Asset,
		},
	}

	// Use the same leaf key in another asset namespace. A leaf-only map
	// would overwrite the predecessor's proof context here.
	distractorProof, _ := proof.RandGenesisProofWithKey(
		t, asset.Normal, &amount, nil, true, nil, nil, nil, nil,
		asset.V0,
	)
	distractorItem := &Item{
		ID: Identifier{
			AssetID:   distractorProof.Asset.ID(),
			ProofType: ProofTypeIssuance,
		},
		Key: prevLeafKey,
		Leaf: &Leaf{
			Asset: &distractorProof.Asset,
		},
	}

	newAsset := prevProof.Asset.Copy()
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &asset.PrevID{
			OutPoint: prevProof.OutPoint(),
			ID:       assetID,
			ScriptKey: asset.ToSerialized(
				prevProof.Asset.ScriptKey.PubKey,
			),
		},
	}}
	batchProofs := map[*Item]*proof.Proof{
		prevItem:       &prevProof,
		distractorItem: &distractorProof,
	}
	deps := extractBatchDeps(
		[]*Item{prevItem, distractorItem}, batchProofs,
	)
	prevSnapshot, err := (&Archive{}).getPrevAssetSnapshot(
		context.Background(), Identifier{
			AssetID:   assetID,
			ProofType: ProofTypeTransfer,
		}, newAsset, deps,
	)
	require.NoError(t, err)
	require.Equal(t, assetID, prevSnapshot.Asset.ID())
	require.EqualValues(
		t, prevBlockHeight, prevSnapshot.AnchorBlockHeight,
	)
}

// TestPredecessorChainLookup tests predecessor lookup and fallback delegation.
func TestPredecessorChainLookup(t *testing.T) {
	t.Parallel()

	fallbackErr := errors.New("missing transaction")
	fallback := &fallbackChainLookup{err: fallbackErr}
	lookup := &predecessorChainLookup{
		ChainLookup: fallback,
		txID:        chainhash.Hash{1},
		height:      123,
	}
	ctx := context.Background()
	height, err := lookup.TxBlockHeight(ctx, lookup.txID)
	require.NoError(t, err)
	require.EqualValues(t, 123, height)
	require.Zero(t, fallback.calls.Load())

	_, err = lookup.TxBlockHeight(ctx, chainhash.Hash{2})
	require.ErrorIs(t, err, fallbackErr)
	require.EqualValues(t, 1, fallback.calls.Load())
	_, err = lookup.MeanBlockTimestamp(ctx, 123)
	require.NoError(t, err)
	_, err = lookup.CurrentHeight(ctx)
	require.NoError(t, err)
}
