package universe

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// memUniverse is a single in-memory universe backed by a real MS-SMT
// tree, so roots and inclusion proofs are genuine.
type memUniverse struct {
	id     Identifier
	tree   mssmt.Tree
	keys   []LeafKey
	leaves map[[32]byte]*Leaf
}

// memUniverseSet implements DiffEngine, DeltaEngine and BatchRegistrar
// over a set of in-memory universes plus an insertion journal. It
// stands in for either side of a sync: the remote (diff/delta engine)
// or the local (diff engine and registrar).
type memUniverseSet struct {
	mu      sync.Mutex
	unis    map[IdentifierKey]*memUniverse
	uniIDs  []Identifier
	nextSeq uint64
	journal []DeltaLeafItem
}

func newMemUniverseSet() *memUniverseSet {
	return &memUniverseSet{
		unis: make(map[IdentifierKey]*memUniverse),
	}
}

// insert upserts a leaf. Re-inserting an existing (key, same content)
// pair is a no-op that produces no new journal entry, mirroring the
// production ON CONFLICT semantics.
func (m *memUniverseSet) insert(id Identifier, key LeafKey,
	leaf *Leaf) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	idKey := id.Key()
	uni, ok := m.unis[idKey]
	if !ok {
		uni = &memUniverse{
			id:     id,
			tree:   mssmt.NewCompactedTree(mssmt.NewDefaultStore()),
			leaves: make(map[[32]byte]*Leaf),
		}
		m.unis[idKey] = uni
		m.uniIDs = append(m.uniIDs, id)
	}

	uniKey := key.UniverseKey()
	if existing, ok := uni.leaves[uniKey]; ok {
		if bytes.Equal(existing.RawProof, leaf.RawProof) {
			return nil
		}
	} else {
		uni.keys = append(uni.keys, key)
	}
	uni.leaves[uniKey] = leaf

	_, err := uni.tree.Insert(
		context.Background(), uniKey, leaf.SmtLeafNode(),
	)
	if err != nil {
		return err
	}

	m.nextSeq++
	m.journal = append(m.journal, DeltaLeafItem{
		Seq:  m.nextSeq,
		ID:   id,
		Key:  key,
		Leaf: leaf,
	})

	return nil
}

// rootLocked returns the universe root as a computed branch node,
// mirroring the RPC boundary (which transports only hash and sum).
// Handing out the tree's real linked root node would also make
// spew.Sdump trace statements in the syncer walk the entire empty
// subtree lattice.
func (m *memUniverseSet) rootLocked(uni *memUniverse) (mssmt.Node, error) {
	root, err := uni.tree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	return mssmt.NewComputedBranch(root.NodeHash(), root.NodeSum()), nil
}

// RootNode returns the root of the given universe.
//
// NOTE: part of the DiffEngine interface.
func (m *memUniverseSet) RootNode(_ context.Context,
	id Identifier) (Root, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	uni, ok := m.unis[id.Key()]
	if !ok {
		return Root{}, ErrNoUniverseRoot
	}

	root, err := m.rootLocked(uni)
	if err != nil {
		return Root{}, err
	}

	return Root{ID: id, Node: root}, nil
}

// RootNodes returns a page of all universe roots.
//
// NOTE: part of the DiffEngine interface.
func (m *memUniverseSet) RootNodes(_ context.Context,
	q RootNodesQuery) ([]Root, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	var roots []Root
	for i := int(q.Offset); i < len(m.uniIDs); i++ {
		if q.Limit > 0 && len(roots) >= int(q.Limit) {
			break
		}

		id := m.uniIDs[i]
		uni := m.unis[id.Key()]
		root, err := m.rootLocked(uni)
		if err != nil {
			return nil, err
		}
		roots = append(roots, Root{ID: id, Node: root})
	}

	return roots, nil
}

// UniverseLeafKeys returns a page of the leaf entries of one universe,
// each carrying its canonical leaf node hash.
//
// NOTE: part of the DiffEngine interface.
func (m *memUniverseSet) UniverseLeafKeys(_ context.Context,
	q UniverseLeafKeysQuery) ([]LeafEntry, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	uni, ok := m.unis[q.Id.Key()]
	if !ok {
		return nil, nil
	}

	var entries []LeafEntry
	for i := int(q.Offset); i < len(uni.keys); i++ {
		if q.Limit > 0 && len(entries) >= int(q.Limit) {
			break
		}

		key := uni.keys[i]
		leaf := uni.leaves[key.UniverseKey()]
		entries = append(entries, LeafEntry{
			Key: key,
			NodeHash: fn.Some(
				leaf.SmtLeafNode().NodeHash(),
			),
		})
	}

	return entries, nil
}

// FetchProofLeaf returns the leaf at the given key together with its
// inclusion proof and the universe root.
//
// NOTE: part of the DiffEngine interface.
func (m *memUniverseSet) FetchProofLeaf(_ context.Context, id Identifier,
	key LeafKey) ([]*Proof, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	uni, ok := m.unis[id.Key()]
	if !ok {
		return nil, fmt.Errorf("%w: unknown universe",
			ErrNoUniverseProofFound)
	}

	leaf, ok := uni.leaves[key.UniverseKey()]
	if !ok {
		return nil, fmt.Errorf("%w: unknown leaf",
			ErrNoUniverseProofFound)
	}

	ctx := context.Background()
	root, err := m.rootLocked(uni)
	if err != nil {
		return nil, err
	}
	inclusionProof, err := uni.tree.MerkleProof(ctx, key.UniverseKey())
	if err != nil {
		return nil, err
	}

	return []*Proof{{
		LeafKey:                key,
		UniverseRoot:           root,
		UniverseInclusionProof: inclusionProof,
		Leaf:                   leaf,
	}}, nil
}

// SyncDelta returns the journal entries after sinceSeq with fresh
// inclusion proofs, plus the roots of the universes they touch.
//
// NOTE: part of the DeltaEngine interface.
func (m *memUniverseSet) SyncDelta(_ context.Context, sinceSeq uint64,
	pageSize int32) (*DeltaPage, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	page := &DeltaPage{
		Roots:     make(map[IdentifierKey]Root),
		LatestSeq: sinceSeq,
	}

	ctx := context.Background()
	for _, entry := range m.journal {
		if entry.Seq <= sinceSeq {
			continue
		}
		if pageSize > 0 && len(page.Items) >= int(pageSize) {
			break
		}

		uni := m.unis[entry.ID.Key()]
		inclusionProof, err := uni.tree.MerkleProof(
			ctx, entry.Key.UniverseKey(),
		)
		if err != nil {
			return nil, err
		}

		item := entry
		item.InclusionProof = inclusionProof
		page.Items = append(page.Items, item)
		page.LatestSeq = entry.Seq

		idKey := entry.ID.Key()
		if _, ok := page.Roots[idKey]; !ok {
			root, err := m.rootLocked(uni)
			if err != nil {
				return nil, err
			}
			page.Roots[idKey] = Root{ID: entry.ID, Node: root}
		}
	}

	return page, nil
}

// UpsertProofLeaf inserts a single leaf.
//
// NOTE: part of the BatchRegistrar interface.
func (m *memUniverseSet) UpsertProofLeaf(_ context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	if err := m.insert(id, key, leaf); err != nil {
		return nil, err
	}

	return nil, nil
}

// UpsertProofLeafBatch inserts a batch of leaves in order.
//
// NOTE: part of the BatchRegistrar interface.
func (m *memUniverseSet) UpsertProofLeafBatch(_ context.Context,
	items []*Item) error {

	for _, item := range items {
		if err := m.insert(item.ID, item.Key, item.Leaf); err != nil {
			return err
		}
	}

	return nil
}

func (m *memUniverseSet) Close() error { return nil }

var (
	_ DiffEngine     = (*memUniverseSet)(nil)
	_ DeltaEngine    = (*memUniverseSet)(nil)
	_ BatchRegistrar = (*memUniverseSet)(nil)
)

// maxSeq returns the current journal high-water mark.
func (m *memUniverseSet) maxSeq() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextSeq
}

// diffOnlyEngine hides the DeltaEngine implementation of the wrapped
// engine, modeling a remote that predates delta sync.
type diffOnlyEngine struct {
	inner DiffEngine
}

func (d *diffOnlyEngine) RootNode(ctx context.Context,
	id Identifier) (Root, error) {

	return d.inner.RootNode(ctx, id)
}

func (d *diffOnlyEngine) RootNodes(ctx context.Context,
	q RootNodesQuery) ([]Root, error) {

	return d.inner.RootNodes(ctx, q)
}

func (d *diffOnlyEngine) UniverseLeafKeys(ctx context.Context,
	q UniverseLeafKeysQuery) ([]LeafEntry, error) {

	return d.inner.UniverseLeafKeys(ctx, q)
}

func (d *diffOnlyEngine) FetchProofLeaf(ctx context.Context,
	id Identifier, key LeafKey) ([]*Proof, error) {

	return d.inner.FetchProofLeaf(ctx, id, key)
}

func (d *diffOnlyEngine) Close() error { return d.inner.Close() }

// corruptDeltaEngine passes everything through but strips the
// inclusion proofs from delta items of one target universe, modeling a
// remote whose delta cannot be verified for that universe.
type corruptDeltaEngine struct {
	*memUniverseSet

	target IdentifierKey
}

func (c *corruptDeltaEngine) SyncDelta(ctx context.Context,
	sinceSeq uint64, pageSize int32) (*DeltaPage, error) {

	page, err := c.memUniverseSet.SyncDelta(ctx, sinceSeq, pageSize)
	if err != nil {
		return nil, err
	}

	for i := range page.Items {
		if page.Items[i].ID.Key() == c.target {
			page.Items[i].InclusionProof = nil
		}
	}

	return page, nil
}

// deltaLeafGen generates a random universe leaf.
var deltaLeafGen = rapid.Custom(func(t *rapid.T) *Leaf {
	gen := asset.GenesisGen.Draw(t, "genesis")
	a := asset.AssetGen.Draw(t, "asset")
	rawProof := rapid.SliceOfN(
		rapid.Byte(), 8, 32,
	).Draw(t, "raw_proof")

	return &Leaf{
		GenesisWithGroup: GenesisWithGroup{Genesis: gen},
		RawProof:         rawProof,
		Asset:            &a,
		Amt:              rapid.Uint64Range(1, 1_000).Draw(t, "amt"),
	}
})

// deltaUniIDGen generates a random issuance- or transfer-typed
// universe identifier.
var deltaUniIDGen = rapid.Custom(func(t *rapid.T) Identifier {
	return Identifier{
		AssetID: asset.AssetIDGen.Draw(t, "asset_id"),
		ProofType: rapid.SampledFrom([]ProofType{
			ProofTypeIssuance, ProofTypeTransfer,
		}).Draw(t, "proof_type"),
	}
})

// allowAllConfigs enables global insert and export for both proof
// types.
func allowAllConfigs() SyncConfigs {
	return SyncConfigs{
		GlobalSyncConfigs: []*FedGlobalSyncConfig{
			{
				ProofType:       ProofTypeIssuance,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
			{
				ProofType:       ProofTypeTransfer,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
		},
	}
}

// newMemSyncer builds a SimpleSyncer whose local side is the given
// universe set and whose remote diff engine is served by remoteFn.
func newMemSyncer(local *memUniverseSet,
	remoteFn func() DiffEngine, batchSize int) *SimpleSyncer {

	return NewSimpleSyncer(SimpleSyncCfg{
		LocalDiffEngine: local,
		LocalRegistrar:  local,
		NewRemoteDiffEngine: func(_ ServerAddr) (DiffEngine, error) {
			return remoteFn(), nil
		},
		SyncBatchSize:       batchSize,
		SyncRootConcurrency: 2,
	})
}

// requireConverged asserts that the local set holds exactly the same
// universes with exactly the same roots as the remote set.
func requireConverged(t require.TestingT, local, remote *memUniverseSet) {
	ctx := context.Background()

	remoteRoots, err := remote.RootNodes(ctx, RootNodesQuery{})
	require.NoError(t, err)

	for _, remoteRoot := range remoteRoots {
		localRoot, err := local.RootNode(ctx, remoteRoot.ID)
		require.NoError(t, err)
		require.True(
			t, mssmt.IsEqualNode(localRoot.Node, remoteRoot.Node),
			"universe %v diverged", remoteRoot.ID.String(),
		)
	}
}

// TestSyncUniverseDeltaEquivalence is the core invariant of delta sync:
// for any remote population and any honest cursor position (the local
// side holds everything at or below the cursor, and possibly more),
// delta sync with root-check fallback converges the local side to
// exactly the same state as full enumeration sync, and advances the
// cursor to the remote's high-water mark.
func TestSyncUniverseDeltaEquivalence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := allowAllConfigs()

	rapid.Check(t, func(rt *rapid.T) {
		remote := newMemUniverseSet()

		// Populate 1-3 universes with 1-6 leaves each.
		numUnis := rapid.IntRange(1, 3).Draw(rt, "num_unis")
		for u := 0; u < numUnis; u++ {
			id := deltaUniIDGen.Draw(rt, fmt.Sprintf("uni_%d", u))
			numLeaves := rapid.IntRange(1, 6).Draw(
				rt, fmt.Sprintf("num_leaves_%d", u),
			)
			for l := 0; l < numLeaves; l++ {
				key := baseLeafKeyGen.Draw(
					rt, fmt.Sprintf("key_%d_%d", u, l),
				)
				leaf := deltaLeafGen.Draw(
					rt, fmt.Sprintf("leaf_%d_%d", u, l),
				)
				require.NoError(rt, remote.insert(
					id, key, leaf,
				))
			}
		}

		// Pick an honest cursor: both locals hold every journal
		// entry at or below it, plus a random subset of the later
		// ones (modeling re-delivery tolerance).
		cursor := rapid.Uint64Range(0, remote.maxSeq()).Draw(
			rt, "cursor",
		)

		localDelta := newMemUniverseSet()
		localEnum := newMemUniverseSet()
		for _, entry := range remote.journal {
			have := entry.Seq <= cursor || rapid.Bool().Draw(
				rt, fmt.Sprintf("have_%d", entry.Seq),
			)
			if !have {
				continue
			}

			require.NoError(rt, localDelta.insert(
				entry.ID, entry.Key, entry.Leaf,
			))
			require.NoError(rt, localEnum.insert(
				entry.ID, entry.Key, entry.Leaf,
			))
		}

		batchSize := rapid.SampledFrom([]int{1, 3, 50}).Draw(
			rt, "batch_size",
		)

		// Delta sync one local; enumeration sync the other.
		deltaSyncer := newMemSyncer(
			localDelta, func() DiffEngine { return remote },
			batchSize,
		)
		res, err := deltaSyncer.SyncUniverseDelta(
			ctx, ServerAddr{}, cursor, cfg,
		)
		require.NoError(rt, err)
		require.Equal(rt, remote.maxSeq(), res.NewCursor)

		enumSyncer := newMemSyncer(
			localEnum, func() DiffEngine { return remote },
			batchSize,
		)
		_, err = enumSyncer.SyncUniverse(
			ctx, ServerAddr{}, SyncFull, cfg,
		)
		require.NoError(rt, err)

		// Both must converge to the remote state exactly.
		requireConverged(rt, localDelta, remote)
		requireConverged(rt, localEnum, remote)
	})
}

// TestSyncUniverseDeltaUnsupported pins the fallback signal: a remote
// engine that does not implement DeltaEngine yields
// ErrDeltaUnsupported.
func TestSyncUniverseDeltaUnsupported(t *testing.T) {
	t.Parallel()

	remote := newMemUniverseSet()
	local := newMemUniverseSet()

	syncer := newMemSyncer(local, func() DiffEngine {
		return &diffOnlyEngine{inner: remote}
	}, 50)

	_, err := syncer.SyncUniverseDelta(
		context.Background(), ServerAddr{}, 0, allowAllConfigs(),
	)
	require.ErrorIs(t, err, ErrDeltaUnsupported)
}

// TestSyncUniverseDeltaInsertFilter pins that universes with insert
// disabled are skipped without blocking cursor advancement.
func TestSyncUniverseDeltaInsertFilter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := newMemUniverseSet()

	allowedID := Identifier{ProofType: ProofTypeIssuance}
	allowedID.AssetID[0] = 1
	blockedID := Identifier{ProofType: ProofTypeIssuance}
	blockedID.AssetID[0] = 2

	insertRandomLeaves := func(id Identifier, n int) {
		for i := 0; i < n; i++ {
			key := randomTestLeafKey(t)
			leaf := randomTestLeaf(t)
			require.NoError(t, remote.insert(id, key, leaf))
		}
	}
	insertRandomLeaves(allowedID, 3)
	insertRandomLeaves(blockedID, 2)
	insertRandomLeaves(allowedID, 1)

	// Insert is enabled globally for issuance, but disabled
	// specifically for the blocked universe.
	cfg := allowAllConfigs()
	cfg.UniSyncConfigs = []*FedUniSyncConfig{{
		UniverseID:      blockedID,
		AllowSyncInsert: false,
		AllowSyncExport: true,
	}}

	local := newMemUniverseSet()
	syncer := newMemSyncer(
		local, func() DiffEngine { return remote }, 50,
	)

	res, err := syncer.SyncUniverseDelta(ctx, ServerAddr{}, 0, cfg)
	require.NoError(t, err)

	// The cursor covers the blocked universe's entries too.
	require.Equal(t, remote.maxSeq(), res.NewCursor)

	// The allowed universe converged; the blocked one was never
	// created locally.
	allowedRoot, err := local.RootNode(ctx, allowedID)
	require.NoError(t, err)
	remoteRoot, err := remote.RootNode(ctx, allowedID)
	require.NoError(t, err)
	require.True(t, mssmt.IsEqualNode(allowedRoot.Node, remoteRoot.Node))

	_, err = local.RootNode(ctx, blockedID)
	require.ErrorIs(t, err, ErrNoUniverseRoot)
}

// TestSyncUniverseDeltaTaintFallback pins the demotion path: when a
// universe's delta items fail inclusion-proof verification, the
// universe is synced via enumeration instead, and the run still
// converges and advances the cursor.
func TestSyncUniverseDeltaTaintFallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := newMemUniverseSet()

	goodID := Identifier{ProofType: ProofTypeIssuance}
	goodID.AssetID[0] = 1
	badID := Identifier{ProofType: ProofTypeTransfer}
	badID.AssetID[0] = 2

	for i := 0; i < 3; i++ {
		require.NoError(t, remote.insert(
			goodID, randomTestLeafKey(t), randomTestLeaf(t),
		))
		require.NoError(t, remote.insert(
			badID, randomTestLeafKey(t), randomTestLeaf(t),
		))
	}

	local := newMemUniverseSet()
	syncer := newMemSyncer(local, func() DiffEngine {
		return &corruptDeltaEngine{
			memUniverseSet: remote,
			target:         badID.Key(),
		}
	}, 50)

	res, err := syncer.SyncUniverseDelta(
		ctx, ServerAddr{}, 0, allowAllConfigs(),
	)
	require.NoError(t, err)
	require.Equal(t, remote.maxSeq(), res.NewCursor)

	// Both universes converged: the good one via the delta, the bad
	// one via fallback enumeration.
	requireConverged(t, local, remote)
}

// randomTestLeafKey returns a random leaf key outside a rapid context.
func randomTestLeafKey(t *testing.T) LeafKey {
	t.Helper()

	return BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}
}

// randomTestLeaf returns a random leaf outside a rapid context.
func randomTestLeaf(t *testing.T) *Leaf {
	t.Helper()

	a := asset.RandAsset(t, asset.Normal)
	return &Leaf{
		GenesisWithGroup: GenesisWithGroup{Genesis: a.Genesis},
		RawProof:         test.RandBytes(24),
		Asset:            a,
		Amt:              a.Amount,
	}
}
