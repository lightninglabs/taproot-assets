package universe

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
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

	// newItems is what UpsertProofLeafBatch reports as newly inserted. If
	// nil, every item handed in is reported as new.
	newItems []*Item

	// leafInserted is what UpsertProofLeaf reports for the single-leaf
	// path, and upsertProof the receipt it hands back.
	leafInserted bool
	upsertProof  *Proof
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
	*proof.MetaReveal) (*Proof, bool, error) {

	return m.upsertProof, m.leafInserted, nil
}

func (m *mockMultiverse) UpsertProofLeafBatch(_ context.Context,
	items []*Item) ([]*Item, error) {

	if m.newItems == nil {
		return items, nil
	}

	// Report back only those configured items that are in this sub-batch,
	// the way the real store reports per call.
	return fn.Filter(m.newItems, func(n *Item) bool {
		return fn.Any(items, func(i *Item) bool {
			return i == n
		})
	}), nil
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
	UniverseLeafKeysQuery) ([]LeafEntry, error) {

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

func (m *mockMultiverse) FetchDeltaPage(_ context.Context,
	sinceSeq uint64, _ int32) (*DeltaPage, error) {

	return &DeltaPage{
		Roots:     make(map[IdentifierKey]Root),
		LatestSeq: sinceSeq,
	}, nil
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
	UniverseLeafKeysQuery) ([]LeafEntry, error) {

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

// newTestArchiveWithStats creates an Archive wired to the given multiverse and
// telemetry, with the mock verifiers that RandProof-free minted proofs expect.
func newTestArchiveWithStats(mv *mockMultiverse,
	stats Telemetry) *Archive {

	return NewArchive(ArchiveConfig{
		NewBaseTree: func(Identifier) StorageBackend {
			return &mockStorageBackend{}
		},
		Multiverse:           mv,
		UniverseStats:        stats,
		HeaderVerifier:       proof.MockHeaderVerifier,
		MerkleVerifier:       proof.MockMerkleVerifier,
		GroupVerifier:        proof.MockGroupVerifier,
		ChainLookupGenerator: proof.MockChainLookup,
	})
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

// mockTelemetry implements Telemetry, recording the universe ids handed to the
// new-proof logging calls.
type mockTelemetry struct {
	mu sync.Mutex

	loggedProofs []Identifier
}

func (m *mockTelemetry) AggregateSyncStats(
	context.Context) (AggregateStats, error) {

	return AggregateStats{}, nil
}

func (m *mockTelemetry) LogSyncEvent(context.Context, Identifier,
	LeafKey) error {

	return nil
}

func (m *mockTelemetry) LogSyncEvents(context.Context, ...Identifier) error {
	return nil
}

func (m *mockTelemetry) LogNewProofEvent(_ context.Context, uniID Identifier,
	_ LeafKey) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.loggedProofs = append(m.loggedProofs, uniID)

	return nil
}

func (m *mockTelemetry) LogNewProofEvents(_ context.Context,
	uniIDs ...Identifier) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.loggedProofs = append(m.loggedProofs, uniIDs...)

	return nil
}

func (m *mockTelemetry) QuerySyncStats(context.Context,
	SyncStatsQuery) (*AssetSyncStats, error) {

	return nil, nil
}

func (m *mockTelemetry) QueryAssetStatsPerDay(context.Context,
	GroupedStatsQuery) ([]*GroupedStats, error) {

	return nil, nil
}

// logged returns the ids logged so far.
func (m *mockTelemetry) logged() []Identifier {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]Identifier(nil), m.loggedProofs...)
}

// mintTestAsset builds a genesis proof that passes full proof verification, so
// that a test can drive the archive's real ingest path rather than stopping at
// the verify step. It returns the universe item the proof belongs in.
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
			OutPoint:  assetGenesis.FirstPrevOut,
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

// TestUpsertProofLeafBatchLogsOnlyNewLeaves tests that the archive logs a new
// proof event for exactly the leaves the multiverse reported as new, and none
// of the ones it already held.
func TestUpsertProofLeafBatchLogsOnlyNewLeaves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	const numItems = 4
	// A mix of group anchors and plain issuances, so the batch is split
	// across both of the archive's sub-batches.
	items := make([]*Item, numItems)
	for idx := range items {
		items[idx] = mintTestAsset(t, idx%2 == 0)
	}

	// The multiverse reports one anchor and one non-anchor item as new,
	// standing in for a peer re-pushing the other two.
	newItems := []*Item{items[0], items[1]}
	mv := &mockMultiverse{
		knownRoots: make(map[IdentifierKey]Root),
		newItems:   newItems,
	}
	stats := &mockTelemetry{}
	archive := newTestArchiveWithStats(mv, stats)

	err := archive.UpsertProofLeafBatch(ctx, items)
	require.NoError(t, err)

	expectedIDs := fn.Map(newItems, func(i *Item) Identifier {
		return i.ID
	})
	require.Eventually(t, func() bool {
		return len(stats.logged()) == len(expectedIDs)
	}, time.Second, 10*time.Millisecond)
	require.ElementsMatch(t, expectedIDs, stats.logged())
}

// TestUpsertProofLeafBatchNoNewLeaves tests that a batch consisting entirely of
// leaves we already hold logs no new proof events at all.
func TestUpsertProofLeafBatchNoNewLeaves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	items := []*Item{mintTestAsset(t, true), mintTestAsset(t, false)}

	mv := &mockMultiverse{
		knownRoots: make(map[IdentifierKey]Root),
		newItems:   []*Item{},
	}
	stats := &mockTelemetry{}
	archive := newTestArchiveWithStats(mv, stats)

	err := archive.UpsertProofLeafBatch(ctx, items)
	require.NoError(t, err)

	// Nothing was new, so nothing may be logged. Give the async logging
	// goroutine a chance to run before concluding that.
	require.Never(t, func() bool {
		return len(stats.logged()) > 0
	}, 200*time.Millisecond, 20*time.Millisecond)
}

// TestUpsertProofLeafLogsOnlyNewLeaf tests that the single-leaf path takes the
// new/existing answer from the multiverse's write transaction rather than
// re-deriving it, so a leaf the multiverse reports as already held logs no
// event even when the archive's earlier read didn't see it.
func TestUpsertProofLeafLogsOnlyNewLeaf(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := []struct {
		name        string
		multiverse  bool
		expectEvent bool
	}{{
		name:        "new leaf is logged",
		multiverse:  true,
		expectEvent: true,
	}, {
		// This is the race the read-then-write derivation used to get
		// wrong: our own FetchProofLeaf missed, so we verified and
		// wrote, but a concurrent insert of the same leaf won and ours
		// was a no-op upsert.
		name:        "leaf lost the insert race is not logged",
		multiverse:  false,
		expectEvent: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			item := mintTestAsset(t, false)
			mv := &mockMultiverse{
				knownRoots:   make(map[IdentifierKey]Root),
				leafInserted: tc.multiverse,
				upsertProof:  &Proof{Leaf: item.Leaf},
			}
			stats := &mockTelemetry{}
			archive := newTestArchiveWithStats(mv, stats)

			_, err := archive.UpsertProofLeaf(
				ctx, item.ID, item.Key, item.Leaf,
			)
			require.NoError(t, err)

			if tc.expectEvent {
				require.Eventually(t, func() bool {
					return len(stats.logged()) == 1
				}, time.Second, 10*time.Millisecond)
				require.Equal(
					t, []Identifier{item.ID},
					stats.logged(),
				)

				return
			}

			require.Never(t, func() bool {
				return len(stats.logged()) > 0
			}, 200*time.Millisecond, 20*time.Millisecond)
		})
	}
}
