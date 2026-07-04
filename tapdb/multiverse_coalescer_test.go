package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genUniverseItems generates n universe items that all target the same
// universe of a random proof type, each carrying a distinct leaf.
func genUniverseItems(t *testing.T, n int) []*universe.Item {
	proofType := universe.ProofTypeIssuance
	if test.RandBool() {
		proofType = universe.ProofTypeTransfer
	}

	return genUniverseItemsWithType(t, proofType, n)
}

// genUniverseItemsWithType generates n universe items that all target
// the same universe of the given proof type, each carrying a distinct
// leaf.
func genUniverseItemsWithType(t *testing.T, proofType universe.ProofType,
	n int) []*universe.Item {

	assetGen := asset.RandGenesis(t, asset.Normal)
	id := randUniverseID(t, test.RandBool(), withProofType(proofType))

	items := make([]*universe.Item, n)
	for i := range items {
		leaf := randMintingLeaf(t, assetGen, id.GroupKey)
		id.AssetID = leaf.Asset.ID()

		// For transfer proofs, the witness must look like a
		// transfer rather than a genesis witness.
		if proofType == universe.ProofTypeTransfer {
			prevWitnesses := leaf.Asset.PrevWitnesses
			prevWitnesses[0].TxWitness = [][]byte{
				{1}, {1}, {1},
			}
			prevID := prevWitnesses[0].PrevID
			prevID.OutPoint.Hash = [32]byte{1}
		}

		items[i] = &universe.Item{
			ID:   id,
			Key:  randLeafKey(t),
			Leaf: &leaf,
		}
	}

	return items
}

// insertUniverseLeafOnly commits a proof leaf into its universe tree
// without updating the shared multiverse tree, returning the universe
// root after the insert. This is the committed-but-not-yet-flushed
// state the coalescer's callers are in when they submit an update.
func insertUniverseLeafOnly(ctx context.Context,
	multiverse *MultiverseStore, item *universe.Item) (mssmt.Node, error) {

	var (
		writeTx BaseMultiverseOptions
		root    mssmt.Node
	)
	err := multiverse.db.ExecTx(
		ctx, &writeTx, func(store BaseMultiverseStore) error {
			uniProof, _, err := universeUpsertProofLeaf(
				ctx, store, item.ID.String(),
				item.ID.ProofType, item.ID.GroupKey, item.Key,
				item.Leaf, item.MetaReveal, lfn.None[uint32](),
			)
			if err != nil {
				return err
			}
			root = uniProof.UniverseRoot

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return root, nil
}

// multiverseLeafForRoot builds the multiverse leaf that must commit to
// the given universe root, mirroring the sum rule of the production
// insert path: issuance leaves carry a sum of one, transfer leaves
// carry the universe root's sum.
func multiverseLeafForRoot(id universe.Identifier,
	root mssmt.Node) *mssmt.LeafNode {

	rootHash := root.NodeHash()
	sum := root.NodeSum()
	if id.ProofType == universe.ProofTypeIssuance {
		sum = 1
	}

	return mssmt.NewLeafNode(rootHash[:], sum)
}

// assertReceiptComposes asserts that an upsert or fetch receipt is
// internally consistent: its leaf is included in its universe root, and
// the multiverse leaf committing to that universe root is included in
// its multiverse root.
func assertReceiptComposes(t require.TestingT, id universe.Identifier,
	p *universe.Proof) {

	require.True(t, p.VerifyRoot(p.UniverseRoot))
	require.True(t, mssmt.VerifyMerkleProof(
		id.Bytes(), multiverseLeafNode(id, p.UniverseRoot),
		p.MultiverseInclusionProof, p.MultiverseRoot,
	))
}

// assertOracleRoot asserts that the multiverse root stored for the
// given proof type matches the root of the given in-memory oracle
// tree.
func assertOracleRoot(t require.TestingT, ctx context.Context,
	multiverse *MultiverseStore, oracle *mssmt.CompactedTree,
	proofType universe.ProofType) {

	oracleRoot, err := oracle.Root(ctx)
	require.NoError(t, err)

	storeRoot, err := multiverse.MultiverseRootNode(ctx, proofType)
	require.NoError(t, err)
	require.True(t, storeRoot.IsSome())

	storeRoot.WhenSome(func(r universe.MultiverseRoot) {
		require.Equal(
			t, oracleRoot.NodeHash(), r.Node.NodeHash(),
			"proof type %v: root hash mismatch", proofType,
		)
		require.Equal(
			t, oracleRoot.NodeSum(), r.Node.NodeSum(),
			"proof type %v: root sum mismatch", proofType,
		)
	})
}

// TestMultiverseRootCoalescer asserts that concurrent root updates for
// distinct universes all succeed, return self-verifying inclusion
// proofs, and leave the multiverse trees identical to inserting the
// same leaves directly.
func TestMultiverseRootCoalescer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	const numUniverses = 16

	items := make([]*universe.Item, numUniverses)
	roots := make([]mssmt.Node, numUniverses)
	for i := range items {
		items[i] = genRandomAsset(t)

		var err error
		roots[i], err = insertUniverseLeafOnly(
			ctx, multiverse, items[i],
		)
		require.NoError(t, err)
	}

	var (
		wg      sync.WaitGroup
		results = make([]multiverseRootUpdate, numUniverses)
		errs    = make([]error, numUniverses)
	)
	for i := range items {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			coalescer := multiverse.rootCoalescer
			results[i], errs[i] = coalescer.updateRoot(
				ctx, items[i].ID,
			)
		}(i)
	}
	wg.Wait()

	// Every update must have succeeded and returned an inclusion
	// proof for the leaf committing to the universe's root, valid
	// against the returned multiverse root.
	for i := range items {
		require.NoError(t, errs[i])

		// The flush must have derived exactly the root committed
		// for the universe; nothing else wrote to it.
		require.True(t, mssmt.IsEqualNode(
			roots[i], results[i].universeRoot,
		))

		leaf := multiverseLeafForRoot(items[i].ID, roots[i])
		require.True(t, mssmt.VerifyMerkleProof(
			items[i].ID.Bytes(), leaf, results[i].inclusionProof,
			results[i].multiverseRoot,
		))
	}

	// The final multiverse roots must equal those of oracle trees
	// built directly from the expected leaves.
	oracles := map[universe.ProofType]*mssmt.CompactedTree{
		universe.ProofTypeIssuance: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
		universe.ProofTypeTransfer: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
	}
	touched := make(map[universe.ProofType]bool)
	for i := range items {
		id := items[i].ID
		leaf := multiverseLeafForRoot(id, roots[i])
		_, err := oracles[id.ProofType].Insert(ctx, id.Bytes(), leaf)
		require.NoError(t, err)
		touched[id.ProofType] = true
	}
	for proofType, oracle := range oracles {
		if !touched[proofType] {
			continue
		}

		assertOracleRoot(t, ctx, multiverse, oracle, proofType)
	}
}

// TestMultiverseRootCoalescerProps property-tests the coalescer against
// an in-memory oracle: for any schedule of concurrent per-universe
// insert sequences, the flushed multiverse roots must equal the oracle
// trees holding each universe's final root, and every returned
// inclusion proof must verify. The store and oracles persist across
// property iterations, so the comparison also covers cumulative state.
func TestMultiverseRootCoalescerProps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	oracles := map[universe.ProofType]*mssmt.CompactedTree{
		universe.ProofTypeIssuance: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
		universe.ProofTypeTransfer: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
	}
	touched := make(map[universe.ProofType]bool)

	rapid.Check(t, func(rt *rapid.T) {
		// Draw a set of universes, each with a sequence of leaf
		// inserts. A universe's inserts are applied in order by a
		// single goroutine, which is what entitles each update to
		// a proof of the root it just committed below. Concurrent
		// same-universe traffic is exercised elsewhere, not here.
		numUniverses := rapid.IntRange(1, 4).Draw(rt, "num_universes")
		universeItems := make([][]*universe.Item, numUniverses)
		for i := range universeItems {
			numInserts := rapid.IntRange(
				1, 3,
			).Draw(rt, "num_inserts")
			universeItems[i] = genUniverseItems(t, numInserts)
		}

		// Run each universe's insert-then-update sequence in its
		// own goroutine, all universes concurrently.
		type outcome struct {
			// root is the universe root right after the
			// insert this update was submitted for.
			root   mssmt.Node
			update multiverseRootUpdate
			err    error
		}
		outcomes := make([][]outcome, numUniverses)
		var wg sync.WaitGroup
		for i := range universeItems {
			outcomes[i] = make([]outcome, len(universeItems[i]))

			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				coalescer := multiverse.rootCoalescer
				for j, item := range universeItems[i] {
					root, err := insertUniverseLeafOnly(
						ctx, multiverse, item,
					)
					if err != nil {
						outcomes[i][j] = outcome{
							err: err,
						}
						return
					}

					update, err := coalescer.updateRoot(
						ctx, item.ID,
					)
					outcomes[i][j] = outcome{
						root:   root,
						update: update,
						err:    err,
					}
				}
			}(i)
		}
		wg.Wait()

		// Every update must succeed with a proof of the leaf
		// committing to the universe root its caller had just
		// committed.
		for i := range universeItems {
			id := universeItems[i][0].ID
			for j := range universeItems[i] {
				out := outcomes[i][j]
				require.NoError(rt, out.err)

				// Only this goroutine writes the universe,
				// so the flush must have derived exactly
				// the root committed by this insert.
				require.True(rt, mssmt.IsEqualNode(
					out.root, out.update.universeRoot,
				))

				leaf := multiverseLeafForRoot(id, out.root)
				require.True(rt, mssmt.VerifyMerkleProof(
					id.Bytes(), leaf,
					out.update.inclusionProof,
					out.update.multiverseRoot,
				))
			}
		}

		// Feed each universe's final root to the oracle and
		// compare full roots per touched proof type.
		for i := range universeItems {
			id := universeItems[i][0].ID
			final := outcomes[i][len(outcomes[i])-1].root
			_, err := oracles[id.ProofType].Insert(
				ctx, id.Bytes(),
				multiverseLeafForRoot(id, final),
			)
			require.NoError(rt, err)
			touched[id.ProofType] = true
		}

		for proofType, oracle := range oracles {
			if !touched[proofType] {
				continue
			}

			assertOracleRoot(
				rt, ctx, multiverse, oracle, proofType,
			)
		}
	})
}

// panicFlushDB is a BatchedMultiverse whose write transactions always
// panic, simulating an unexpected failure inside a flush.
type panicFlushDB struct {
	BatchedMultiverse
}

func (panicFlushDB) ExecTx(context.Context, TxOptions,
	func(BaseMultiverseStore) error) error {

	panic("flush boom")
}

// TestMultiverseRootCoalescerFlushPanic asserts that a panic during a
// flush is contained: every waiter of the round receives an error, the
// flusher role is surrendered and no pending state leaks, so the
// coalescer keeps functioning for future updates.
func TestMultiverseRootCoalescerFlushPanic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	coalescer := newMultiverseRootCoalescer(panicFlushDB{})

	newID := func() universe.Identifier {
		var id universe.Identifier
		id.ProofType = universe.ProofTypeIssuance
		copy(id.AssetID[:], test.RandBytes(32))
		return id
	}

	// Enqueue a waiter by hand, so the panicking flush has a waiter
	// beyond the leading caller itself.
	waiterChan := make(chan flushResult, 1)
	waiterID := newID()
	coalescer.mu.Lock()
	coalescer.pending[waiterID.String()] = &pendingRootUpdate{
		id:      waiterID,
		waiters: []chan flushResult{waiterChan},
	}
	coalescer.order = append(coalescer.order, waiterID.String())
	coalescer.mu.Unlock()

	// The leading caller must receive the panic as an error, not a
	// stuck call or an unwound stack.
	_, err := coalescer.updateRoot(ctx, newID())
	require.ErrorContains(t, err, "panic")

	// The bystander waiter must have been failed as well.
	select {
	case res := <-waiterChan:
		require.ErrorContains(t, res.err, "panic")
	default:
		t.Fatal("waiter was not notified of the failed flush")
	}

	// The flusher role and the pending queue must be clean, so
	// future updates are not blocked.
	coalescer.mu.Lock()
	require.False(t, coalescer.flushing)
	require.Empty(t, coalescer.pending)
	require.Empty(t, coalescer.order)
	coalescer.mu.Unlock()
}

// TestMultiverseRootCoalescerMissingUniverse asserts that an update for
// a universe with no committed root — the state left behind by a
// concurrent universe deletion — fails with a typed error rather than
// delivering an exclusion proof as though it were an inclusion proof.
func TestMultiverseRootCoalescerMissingUniverse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	var id universe.Identifier
	id.ProofType = universe.ProofTypeIssuance
	copy(id.AssetID[:], test.RandBytes(32))

	_, err := multiverse.rootCoalescer.updateRoot(ctx, id)
	require.ErrorIs(t, err, errUniverseDeleted)

	// The failed refresh must not have created a multiverse leaf: the
	// multiverse tree must still be missing entirely.
	_, err = multiverse.MultiverseRootNode(
		ctx, universe.ProofTypeIssuance,
	)
	require.ErrorIs(t, err, ErrNoMultiverseRoot)
}

// TestUpsertProofLeafSameUniverseConcurrent asserts that concurrent
// inserts into the same universe leave the multiverse leaf committing
// to the universe's current root. Submission order to the coalescer
// does not track universe commit order, so this holds only because the
// flush derives the root itself rather than trusting submitted values.
func TestUpsertProofLeafSameUniverseConcurrent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	const numLeaves = 8
	items := genUniverseItems(t, numLeaves)
	id := items[0].ID

	var (
		wg       sync.WaitGroup
		receipts = make([]*universe.Proof, numLeaves)
		errs     = make([]error, numLeaves)
	)
	for i := range items {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			receipts[i], errs[i] = multiverse.UpsertProofLeaf(
				ctx, items[i].ID, items[i].Key,
				items[i].Leaf, items[i].MetaReveal,
			)
		}(i)
	}
	wg.Wait()

	// Every returned receipt must compose, whichever flush round
	// served it and whether or not it was superseded by a concurrent
	// insert.
	for i, err := range errs {
		require.NoError(t, err)
		assertReceiptComposes(t, id, receipts[i])
	}

	// The multiverse leaf must commit to the universe's current root,
	// not to whichever root happened to be submitted last.
	var (
		uniRoot mssmt.Node
		mvRoot  mssmt.Node
		mvProof *mssmt.Proof
	)
	readTx := NewBaseMultiverseReadTx()
	err := multiverse.db.ExecTx(
		ctx, &readTx, func(db BaseMultiverseStore) error {
			dbRoot, err := db.FetchUniverseRoot(ctx, id.String())
			if err != nil {
				return err
			}

			var rootHash mssmt.NodeHash
			copy(rootHash[:], dbRoot.RootHash[:])
			uniRoot = mssmt.NewComputedNode(
				rootHash, uint64(dbRoot.RootSum),
			)

			mvRoot, mvProof, err = multiverseRootAndProof(
				ctx, db, id,
			)
			return err
		},
	)
	require.NoError(t, err)

	require.True(t, mssmt.VerifyMerkleProof(
		id.Bytes(), multiverseLeafForRoot(id, uniRoot), mvProof, mvRoot,
	))
}

// TestFetchProofLeafHealsMultiverse asserts that fetching a proof in
// the window between a universe commit and its multiverse flush returns
// a consistent composite: the read path detects the missing or stale
// multiverse leaf, waits for a healing flush, and reads again.
func TestFetchProofLeafHealsMultiverse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	items := genUniverseItems(t, 2)
	id := items[0].ID

	// A committed universe leaf with no multiverse update is exactly
	// the state a fetcher observes in the gap, with the multiverse
	// leaf missing entirely.
	_, err := insertUniverseLeafOnly(ctx, multiverse, items[0])
	require.NoError(t, err)

	proofs, err := multiverse.FetchProofLeaf(ctx, id, items[0].Key)
	require.NoError(t, err)
	require.Len(t, proofs, 1)
	assertReceiptComposes(t, id, proofs[0])

	// The heal above flushed the multiverse leaf; a second universe
	// commit without its multiverse update now leaves the leaf
	// present but stale.
	_, err = insertUniverseLeafOnly(ctx, multiverse, items[1])
	require.NoError(t, err)

	proofs, err = multiverse.FetchProofLeaf(ctx, id, items[1].Key)
	require.NoError(t, err)
	require.Len(t, proofs, 1)
	assertReceiptComposes(t, id, proofs[0])
}

// TestUpsertProofLeafConcurrentDelete asserts that inserts racing a
// deletion of their universe either succeed with a composing receipt or
// fail outright, and that the persisted multiverse state is consistent
// with the universe state whatever the interleaving.
func TestUpsertProofLeafConcurrentDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	const numLeaves = 8
	items := genUniverseItems(t, numLeaves)
	id := items[0].ID

	// Seed the universe so the deletion has something to delete.
	_, err := multiverse.UpsertProofLeaf(
		ctx, items[0].ID, items[0].Key, items[0].Leaf,
		items[0].MetaReveal,
	)
	require.NoError(t, err)

	var (
		wg       sync.WaitGroup
		receipts = make([]*universe.Proof, numLeaves)
		errs     = make([]error, numLeaves)
		delErr   error
	)
	for i := 1; i < numLeaves; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			receipts[i], errs[i] = multiverse.UpsertProofLeaf(
				ctx, items[i].ID, items[i].Key,
				items[i].Leaf, items[i].MetaReveal,
			)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()

		_, delErr = multiverse.DeleteUniverse(ctx, id)
	}()
	wg.Wait()

	require.NoError(t, delErr)

	// An insert that reported success must have returned a composing
	// receipt; failures (universe deleted under the insert's
	// multiverse update or receipt fetch) are acceptable.
	for i := 1; i < numLeaves; i++ {
		if errs[i] != nil {
			continue
		}

		assertReceiptComposes(t, id, receipts[i])
	}

	// Whatever the interleaving, the persisted multiverse leaf must
	// agree with the persisted universe state: absent if the universe
	// is gone, committing to its current root otherwise.
	var (
		exists  bool
		uniRoot mssmt.Node
		mvRoot  mssmt.Node
		mvProof *mssmt.Proof
	)
	readTx := NewBaseMultiverseReadTx()
	err = multiverse.db.ExecTx(
		ctx, &readTx, func(db BaseMultiverseStore) error {
			dbRoot, err := db.FetchUniverseRoot(ctx, id.String())
			switch {
			case errors.Is(err, sql.ErrNoRows):

			case err != nil:
				return err

			default:
				exists = true
				var rootHash mssmt.NodeHash
				copy(rootHash[:], dbRoot.RootHash[:])
				uniRoot = mssmt.NewComputedNode(
					rootHash, uint64(dbRoot.RootSum),
				)
			}

			mvRoot, mvProof, err = multiverseRootAndProof(
				ctx, db, id,
			)
			return err
		},
	)
	require.NoError(t, err)

	expected := mssmt.EmptyLeafNode
	if exists {
		expected = multiverseLeafNode(id, uniRoot)
	}
	require.True(t, mssmt.VerifyMerkleProof(
		id.Bytes(), expected, mvProof, mvRoot,
	))
}
