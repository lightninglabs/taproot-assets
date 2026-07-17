package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
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

// TestMultiverseRootCoalescerBatch asserts that batch root updates,
// interleaved with concurrent single updates, leave the multiverse
// trees identical to inserting the same leaves directly.
func TestMultiverseRootCoalescerBatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// A pending universe holds one committed leaf, awaiting its
	// multiverse update.
	type pendingUniverse struct {
		id   universe.Identifier
		root mssmt.Node
	}
	newBatch := func(n int) ([]pendingUniverse, []universe.Identifier) {
		pending := make([]pendingUniverse, n)
		ids := make([]universe.Identifier, n)
		for i := range pending {
			item := genRandomAsset(t)
			root, err := insertUniverseLeafOnly(
				ctx, multiverse, item,
			)
			require.NoError(t, err)

			pending[i] = pendingUniverse{
				id:   item.ID,
				root: root,
			}
			ids[i] = item.ID
		}

		return pending, ids
	}

	// Two batches and a handful of single updates, all submitted
	// concurrently.
	batchA, idsA := newBatch(8)
	batchB, idsB := newBatch(8)
	singles, _ := newBatch(4)

	var (
		wg         sync.WaitGroup
		batchErrs  = make([]error, 2)
		singleErrs = make([]error, len(singles))
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		batchErrs[0] = multiverse.rootCoalescer.updateRoots(ctx, idsA)
	}()
	go func() {
		defer wg.Done()
		batchErrs[1] = multiverse.rootCoalescer.updateRoots(ctx, idsB)
	}()
	for i := range singles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, singleErrs[i] = multiverse.rootCoalescer.updateRoot(
				ctx, singles[i].id,
			)
		}(i)
	}
	wg.Wait()

	for _, err := range batchErrs {
		require.NoError(t, err)
	}
	for _, err := range singleErrs {
		require.NoError(t, err)
	}

	oracles := map[universe.ProofType]*mssmt.CompactedTree{
		universe.ProofTypeIssuance: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
		universe.ProofTypeTransfer: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
	}
	touched := make(map[universe.ProofType]bool)
	allUpdates := append(append(batchA, batchB...), singles...)
	for _, update := range allUpdates {
		_, err := oracles[update.id.ProofType].Insert(
			ctx, update.id.Bytes(),
			multiverseLeafForRoot(update.id, update.root),
		)
		require.NoError(t, err)
		touched[update.id.ProofType] = true
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

	var writeMu sync.Mutex
	coalescer := newMultiverseRootCoalescer(panicFlushDB{}, &writeMu)

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
		id: waiterID,
		waiters: []flushWaiter{{
			result:    waiterChan,
			wantProof: true,
		}},
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

	// The multiverse write lock must have been released on the way
	// out, or the deletion paths would deadlock.
	require.True(t, writeMu.TryLock())
	writeMu.Unlock()
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

// countTxDB is a BatchedMultiverse that counts the transactions
// executed through it.
type countTxDB struct {
	BatchedMultiverse

	count atomic.Int32
}

func (c *countTxDB) ExecTx(ctx context.Context, opts TxOptions,
	txBody func(BaseMultiverseStore) error) error {

	c.count.Add(1)

	return c.BatchedMultiverse.ExecTx(ctx, opts, txBody)
}

// TestMultiverseRootCoalescerRollover asserts that a submission larger
// than the flush batch size is applied across several bounded rounds
// of one transaction each: every waiter is served, a refresh callback
// arrives for every universe in submission order, and the multiverse
// state matches the oracle.
func TestMultiverseRootCoalescerRollover(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// Shrink the per-round cap so a small submission spans several
	// rounds, and capture the refresh callbacks.
	multiverse.rootCoalescer.flushBatchSize = 4

	var (
		refreshMu sync.Mutex
		refreshed []universe.Root
	)
	multiverse.rootCoalescer.onRefresh = func(root universe.Root) {
		refreshMu.Lock()
		defer refreshMu.Unlock()

		refreshed = append(refreshed, root)
	}

	const numUniverses = 9

	ids := make([]universe.Identifier, numUniverses)
	roots := make([]mssmt.Node, numUniverses)
	for i := 0; i < numUniverses; i++ {
		item := genRandomAsset(t)

		root, err := insertUniverseLeafOnly(ctx, multiverse, item)
		require.NoError(t, err)

		ids[i] = item.ID
		roots[i] = root
	}

	// Count the flush transactions from here on: the coalescer's
	// handle only ever executes flushes, so wrapping it counts exactly
	// those.
	counter := &countTxDB{
		BatchedMultiverse: multiverse.rootCoalescer.db,
	}
	multiverse.rootCoalescer.db = counter

	require.NoError(t, multiverse.rootCoalescer.updateRoots(ctx, ids))

	// Nine universes at a cap of four must have flushed in exactly
	// three rounds, one transaction each. An implementation that
	// ignored the cap would apply them in a single transaction.
	require.EqualValues(t, 3, counter.count.Load())

	// Every universe must have been refreshed exactly once, in
	// submission order: rounds are taken from the front of the
	// pending queue, which preserves first-submission order.
	require.Len(t, refreshed, numUniverses)
	for i, root := range refreshed {
		require.Equal(t, ids[i].Bytes(), root.ID.Bytes())
		require.True(t, mssmt.IsEqualNode(roots[i], root.Node))
	}

	// The multiverse trees must match oracles fed the same roots.
	oracles := map[universe.ProofType]*mssmt.CompactedTree{
		universe.ProofTypeIssuance: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
		universe.ProofTypeTransfer: mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		),
	}
	touched := make(map[universe.ProofType]bool)
	for i, id := range ids {
		_, err := oracles[id.ProofType].Insert(
			ctx, id.Bytes(), multiverseLeafForRoot(id, roots[i]),
		)
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

// TestMultiverseRootCoalescerMixedDeleted asserts that a flush round
// containing both a missing universe and a healthy one commits the
// healthy refresh while failing only the missing universe's waiters
// with the typed error.
func TestMultiverseRootCoalescerMixedDeleted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// One healthy universe with a committed leaf, and one universe
	// identifier with no committed state, as left behind by a
	// concurrent deletion.
	item := genRandomAsset(t)
	rootX, err := insertUniverseLeafOnly(ctx, multiverse, item)
	require.NoError(t, err)

	var missing universe.Identifier
	missing.ProofType = item.ID.ProofType
	copy(missing.AssetID[:], test.RandBytes(32))

	// Both universes are submitted together, so they land in the same
	// flush round and transaction.
	err = multiverse.rootCoalescer.updateRoots(
		ctx, []universe.Identifier{missing, item.ID},
	)
	require.ErrorIs(t, err, errUniverseDeleted)

	// The healthy universe's refresh must have committed in that same
	// round regardless.
	var (
		mvRoot  mssmt.Node
		mvProof *mssmt.Proof
	)
	readTx := NewBaseMultiverseReadTx()
	err = multiverse.db.ExecTx(
		ctx, &readTx, func(db BaseMultiverseStore) error {
			var err error
			mvRoot, mvProof, err = multiverseRootAndProof(
				ctx, db, item.ID,
			)
			return err
		},
	)
	require.NoError(t, err)

	require.True(t, mssmt.VerifyMerkleProof(
		item.ID.Bytes(), multiverseLeafForRoot(item.ID, rootX),
		mvProof, mvRoot,
	))
}

// failFlushDB is a BatchedMultiverse that fails coalescer flush
// transactions — recognized by their isolation override — while letting
// every other transaction through, simulating a database that becomes
// unavailable between a universe commit and its multiverse flush.
type failFlushDB struct {
	BatchedMultiverse

	failing atomic.Bool
}

func (f *failFlushDB) ExecTx(ctx context.Context, opts TxOptions,
	txBody func(BaseMultiverseStore) error) error {

	if _, isFlush := opts.(TxIsolationOverrider); isFlush &&
		f.failing.Load() {

		return fmt.Errorf("flush unavailable")
	}

	return f.BatchedMultiverse.ExecTx(ctx, opts, txBody)
}

// TestUpsertProofLeafFlushFailure asserts that when the multiverse
// flush fails after the universe transaction has committed, the
// commit-tied bookkeeping has still run: stale cached proofs are
// evicted and the custodian notification for the stored transfer proof
// is emitted, even though the call reports the flush error.
func TestUpsertProofLeafFlushFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	db := NewTestDB(t)
	failDB := &failFlushDB{
		BatchedMultiverse: NewTransactionExecutor(
			db, func(tx *sql.Tx) BaseMultiverseStore {
				return db.WithTx(tx)
			},
		),
	}
	cfg := DefaultMultiverseStoreConfig()
	cfg.Caches.SyncerCacheEnabled = true
	multiverse, err := NewMultiverseStore(failDB, cfg)
	require.NoError(t, err)

	items := genUniverseItemsWithType(t, universe.ProofTypeTransfer, 2)
	id := items[0].ID

	// Insert a first leaf and fetch it, so the proof cache holds an
	// entry that the failing insert below must evict.
	_, err = multiverse.UpsertProofLeaf(
		ctx, items[0].ID, items[0].Key, items[0].Leaf,
		items[0].MetaReveal,
	)
	require.NoError(t, err)

	proofs, err := multiverse.FetchProofLeaf(ctx, id, items[0].Key)
	require.NoError(t, err)
	require.Len(t, proofs, 1)
	require.NotEmpty(t, multiverse.proofCache.fetchProof(
		id, items[0].Key,
	))

	// Initialize the syncer cache and pin the universe root it now
	// serves.
	rootsQuery := universe.RootNodesQuery{
		SortDirection: universe.SortAscending,
		Limit:         universe.RequestPageSize,
	}
	roots, err := multiverse.RootNodes(ctx, rootsQuery)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	staleRoot := roots[0].Node

	receiver := fn.NewEventReceiver[proof.Blob](fn.DefaultQueueSize)
	require.NoError(t, multiverse.RegisterSubscriber(
		receiver, false, nil,
	))

	// Insert a second leaf with the flush failing: the call must
	// report the error, as the multiverse update did not commit.
	failDB.failing.Store(true)
	_, err = multiverse.UpsertProofLeaf(
		ctx, items[1].ID, items[1].Key, items[1].Leaf,
		items[1].MetaReveal,
	)
	require.ErrorContains(t, err, "flush unavailable")

	// The universe commit went through, so the bookkeeping tied to it
	// must have run regardless: the previously cached proof, stale as
	// of the new leaf, is gone, and the stored transfer proof was
	// delivered to subscribers.
	require.Empty(t, multiverse.proofCache.fetchProof(id, items[0].Key))

	select {
	case blob := <-receiver.NewItemCreated.ChanOut():
		require.Equal(
			t, []byte(items[1].Leaf.RawProof), []byte(blob),
		)

	case <-time.After(time.Second):
		t.Fatal("no transfer proof notification received")
	}

	// The failed flush must have invalidated the syncer cache: the
	// next syncer query repopulates from the database and serves the
	// universe root committed by the failed call, not the stale one
	// installed before it.
	roots, err = multiverse.RootNodes(ctx, rootsQuery)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.False(t, mssmt.IsEqualNode(staleRoot, roots[0].Node))

	// Once the database recovers, the read path heals the multiverse
	// on the next fetch.
	failDB.failing.Store(false)
	proofs, err = multiverse.FetchProofLeaf(ctx, id, items[1].Key)
	require.NoError(t, err)
	require.Len(t, proofs, 1)
	assertReceiptComposes(t, id, proofs[0])
}

// hookFlushDB is a BatchedMultiverse that recognizes coalescer flush
// transactions by their isolation override, letting tests act
// deterministically at the boundary between a universe commit and its
// multiverse flush: it counts flushes, runs a one-shot hook right
// before a flush executes, and can fail flushes from a given ordinal
// onwards.
type hookFlushDB struct {
	BatchedMultiverse

	// beforeFlush, if armed, runs exactly once, right before the next
	// flush transaction executes. The flusher holds the multiverse
	// write lock at that point, so work done here is already
	// serialized against the flush itself.
	beforeFlush atomic.Pointer[func()]

	// flushCount is the number of flush transactions attempted.
	flushCount atomic.Int32

	// failFrom, if positive, fails every flush whose ordinal (from
	// one) is greater than or equal to it.
	failFrom atomic.Int32
}

func (h *hookFlushDB) ExecTx(ctx context.Context, opts TxOptions,
	txBody func(BaseMultiverseStore) error) error {

	if _, isFlush := opts.(TxIsolationOverrider); isFlush {
		n := h.flushCount.Add(1)

		if hook := h.beforeFlush.Swap(nil); hook != nil {
			(*hook)()
		}

		if from := h.failFrom.Load(); from > 0 && n >= from {
			return fmt.Errorf("flush unavailable")
		}
	}

	return h.BatchedMultiverse.ExecTx(ctx, opts, txBody)
}

// newHookedMultiverse creates a multiverse store whose flush
// transactions pass through a hookFlushDB.
func newHookedMultiverse(t *testing.T) (*MultiverseStore, *hookFlushDB) {
	db := NewTestDB(t)
	hookDB := &hookFlushDB{
		BatchedMultiverse: NewTransactionExecutor(
			db, func(tx *sql.Tx) BaseMultiverseStore {
				return db.WithTx(tx)
			},
		),
	}
	multiverse, err := NewMultiverseStore(
		hookDB, DefaultMultiverseStoreConfig(),
	)
	require.NoError(t, err)

	return multiverse, hookDB
}

// TestUpsertProofLeafSuperseded deterministically forces the
// superseded-receipt path: a second leaf commits into the universe
// after the first caller's transaction but before its flush, so the
// flush derives the newer root and the first caller's receipt must be
// rebuilt against it.
func TestUpsertProofLeafSuperseded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, hookDB := newHookedMultiverse(t)

	items := genUniverseItems(t, 2)
	id := items[0].ID

	// Arm the hook: right before the first insert's flush runs, a
	// second leaf commits into the same universe.
	var (
		superseding mssmt.Node
		hookErr     error
	)
	hook := func() {
		superseding, hookErr = insertUniverseLeafOnly(
			ctx, multiverse, items[1],
		)
	}
	hookDB.beforeFlush.Store(&hook)

	receipt, err := multiverse.UpsertProofLeaf(
		ctx, items[0].ID, items[0].Key, items[0].Leaf,
		items[0].MetaReveal,
	)
	require.NoError(t, err)
	require.NoError(t, hookErr)
	require.NotNil(t, superseding)

	// The receipt must compose, and it must commit to the superseding
	// root rather than the root of the caller's own transaction.
	assertReceiptComposes(t, id, receipt)
	require.True(t, mssmt.IsEqualNode(superseding, receipt.UniverseRoot))
}

// TestUpsertProofLeafDeletedInGap deterministically forces a universe
// deletion into the gap between a caller's universe commit and its
// multiverse flush: the flush finds the universe gone, the caller
// receives the typed error, and no multiverse leaf is resurrected.
func TestUpsertProofLeafDeletedInGap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, hookDB := newHookedMultiverse(t)

	items := genUniverseItems(t, 1)
	id := items[0].ID

	// Arm the hook: right before the insert's flush runs, the
	// universe is deleted. The flusher holds the multiverse write
	// lock here, so the deletion is already serialized with the
	// flush.
	var hookErr error
	hook := func() {
		var writeTx BaseMultiverseOptions
		hookErr = multiverse.db.ExecTx(
			ctx, &writeTx,
			func(store BaseMultiverseStore) error {
				multiverseNS, err := namespaceForProof(
					id.ProofType,
				)
				if err != nil {
					return err
				}

				multiverseTree := mssmt.NewCompactedTree(
					newTreeStoreWrapperTx(
						store, multiverseNS,
					),
				)
				_, err = multiverseTree.Delete(
					ctx, id.Bytes(),
				)
				if err != nil {
					return err
				}

				return deleteUniverseTree(ctx, store, id)
			},
		)
	}
	hookDB.beforeFlush.Store(&hook)

	_, err := multiverse.UpsertProofLeaf(
		ctx, items[0].ID, items[0].Key, items[0].Leaf,
		items[0].MetaReveal,
	)
	require.ErrorIs(t, err, errUniverseDeleted)
	require.NoError(t, hookErr)

	// The skipped flush must not have resurrected any multiverse
	// state for the deleted universe.
	_, err = multiverse.MultiverseRootNode(ctx, id.ProofType)
	require.ErrorIs(t, err, ErrNoMultiverseRoot)
}

// TestMultiverseRootCoalescerCoalesces proves that updates enqueued
// while a flush is in flight are applied together: with the first flush
// blocked, several universes are submitted, and releasing the flush
// must drain all of them in exactly one further flush transaction.
func TestMultiverseRootCoalescerCoalesces(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, hookDB := newHookedMultiverse(t)

	const numQueued = 4

	leader := genRandomAsset(t)
	_, err := insertUniverseLeafOnly(ctx, multiverse, leader)
	require.NoError(t, err)

	queued := make([]*universe.Item, numQueued)
	for i := range queued {
		queued[i] = genRandomAsset(t)
		_, err := insertUniverseLeafOnly(ctx, multiverse, queued[i])
		require.NoError(t, err)
	}

	// Block the leader's flush until the queued universes are
	// pending.
	inFlush := make(chan struct{})
	release := make(chan struct{})
	hook := func() {
		close(inFlush)
		<-release
	}
	hookDB.beforeFlush.Store(&hook)

	var (
		wg        sync.WaitGroup
		leaderErr error
		queueErrs = make([]error, numQueued)
	)
	wg.Add(1)
	go func() {
		defer wg.Done()

		_, leaderErr = multiverse.rootCoalescer.updateRoot(
			ctx, leader.ID,
		)
	}()
	<-inFlush

	for i := range queued {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			_, queueErrs[i] = multiverse.rootCoalescer.updateRoot(
				ctx, queued[i].ID,
			)
		}(i)
	}

	// Wait until all queued universes are registered as pending, then
	// let the blocked flush proceed.
	coalescer := multiverse.rootCoalescer
	require.Eventually(t, func() bool {
		coalescer.mu.Lock()
		defer coalescer.mu.Unlock()

		return len(coalescer.order) == numQueued
	}, time.Second, time.Millisecond)
	close(release)

	wg.Wait()
	require.NoError(t, leaderErr)
	for _, err := range queueErrs {
		require.NoError(t, err)
	}

	// The leader's round plus exactly one coalesced round for the
	// queued universes.
	require.EqualValues(t, 2, hookDB.flushCount.Load())
}

// TestReconcileMultiverseChunkFailure asserts that chunked startup
// repairs make durable forward progress: a failure in the second chunk
// leaves the first chunk's repairs committed, and a subsequent
// reconcile completes from the remaining divergence.
func TestReconcileMultiverseChunkFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, hookDB := newHookedMultiverse(t)

	// Repair three universes per chunk, with seven diverged: chunks
	// of 3, 3 and 1.
	multiverse.reconcileBatchSize = 3

	const numDiverged = 7
	for i := 0; i < numDiverged; i++ {
		_, err := insertUniverseLeafOnly(
			ctx, multiverse, genRandomAsset(t),
		)
		require.NoError(t, err)
	}

	// The first chunk's flush succeeds, everything after fails.
	hookDB.failFrom.Store(2)

	err := multiverse.ReconcileMultiverse(ctx)
	require.ErrorContains(t, err, "flush unavailable")

	// The first chunk must have committed: only the remaining four
	// universes still diverge.
	diverged, err := multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Len(t, diverged, numDiverged-3)

	// Once the database recovers, reconciliation completes from where
	// it left off.
	hookDB.failFrom.Store(0)
	require.NoError(t, multiverse.ReconcileMultiverse(ctx))

	diverged, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, diverged)
}
