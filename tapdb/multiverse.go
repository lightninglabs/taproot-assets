package tapdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnutils"
)

const (
	// issuanceMultiverseNS is the namespace used for the multiverse
	// transfer proofs.
	issuanceMultiverseNS = "multiverse-issuance"

	// transferMultiverseNS is the namespace used for the multiverse
	// issuance proofs.
	transferMultiverseNS = "multiverse-transfer"
)

type (
	BaseUniverseRoot = sqlc.UniverseRootsRow

	UniverseRootsParams = sqlc.UniverseRootsParams
)

// BaseMultiverseStore is used to interact with a set of base universe
// roots, also known as a multiverse.
type BaseMultiverseStore interface {
	BaseUniverseStore

	UniverseRoots(ctx context.Context,
		params UniverseRootsParams) ([]BaseUniverseRoot, error)
}

// BaseMultiverseOptions is the set of options for multiverse queries.
type BaseMultiverseOptions struct {
	readOnly bool
}

// ReadOnly returns true if the transaction is read-only.
func (b *BaseMultiverseOptions) ReadOnly() bool {
	return b.readOnly
}

// NewBaseMultiverseReadTx creates a new read-only transaction for the
// multiverse.
func NewBaseMultiverseReadTx() BaseMultiverseOptions {
	return BaseMultiverseOptions{
		readOnly: true,
	}
}

// BatchedMultiverse is a wrapper around the base multiverse that allows us to
// perform batch transactional database queries with all the relevant query
// interfaces.
type BatchedMultiverse interface {
	BaseMultiverseStore

	BatchedTx[BaseMultiverseStore]
}

// ProofKey is used to uniquely identify a proof within a universe. This is
// used for the LRU cache for the proofs themselves, which are considered to be
// immutable.
type ProofKey [32]byte

// NewProofKey takes a universe identifier and leaf key, and returns a proof
// key.
func NewProofKey(id universe.Identifier, key universe.LeafKey) ProofKey {
	idBytes := id.Bytes()
	leafKeyBytes := key.UniverseKey()

	// The proof key maps down the ID and the leaf key into a single
	// 32-byte value: sha256(id || leaf_key)..
	h := sha256.New()
	h.Write(idBytes[:])
	h.Write(leafKeyBytes[:])

	return fn.ToArray[ProofKey](h.Sum(nil))
}

// numCachedProofs is the number of universe proofs we'll cache.
const numCachedProofs = 25_000

// cachedProof is a single cached proof.
type cachedProof []*universe.Proof

// Size just returns 1 as we're limiting based on the total number of proofs.
func (c *cachedProof) Size() (uint64, error) {
	return 1, nil
}

// leafProofCache is used to cache proofs for issuance leaves for assets w/o a
// group key.
type leafProofCache = *lru.Cache[ProofKey, *cachedProof]

// newLeafCache creates a new leaf proof cache.
func newLeafCache() leafProofCache {
	return lru.NewCache[ProofKey, *cachedProof](
		numCachedProofs,
	)
}

// treeID is used to uniquely identify a multiverse tree.
type treeID string

// proofCache a map of proof caches for each proof type.
type proofCache lnutils.SyncMap[treeID, leafProofCache]

// newProofCache creates a new proof cache.
func newProofCache() *proofCache {
	return &proofCache{}
}

// fetchProof reads the cached proof for the given ID and leaf key.
func (p *proofCache) fetchProof(id universe.Identifier,
	leafKey universe.LeafKey) []*universe.Proof {

	// First, get the sub-cache for this universe ID from the map of
	// caches.
	idStr := treeID(id.String())
	proofCache, _ := p.LoadOrStore(idStr, newLeafCache())
	assetProofCache := proofCache.(leafProofCache)

	// With that lower level cache obtained, we can check to see if we have
	// a hit or not.
	proofKey := NewProofKey(id, leafKey)
	proof, err := assetProofCache.Get(proofKey)
	if err == nil {
		log.Debugf("read proof for %v+%v from cache, key=%v",
			id.StringForLog(), leafKey, proofKey[:])
		return *proof
	}

	return nil
}

// insertProof inserts the given proof into the cache.
func (p *proofCache) insertProof(id universe.Identifier, leafKey universe.LeafKey,
	proof []*universe.Proof) {

	idStr := treeID(id.String())

	proofCache, _ := p.LoadOrStore(idStr, newLeafCache())
	assetProofCache := proofCache.(leafProofCache)

	proofKey := NewProofKey(id, leafKey)

	log.Debugf("storing proof for %v+%v in cache, key=%x",
		id.StringForLog(), leafKey, proofKey[:])

	proofVal := cachedProof(proof)
	assetProofCache.Put(proofKey, &proofVal)
}

// delProofsForAsset deletes all the proofs for the given asset.
func (p *proofCache) delProofsForAsset(id universe.Identifier) {
	log.Debugf("wiping proofs for %v from cache", id)

	idStr := treeID(id.String())
	p.Delete(idStr)
}

// cachedRoots is used to store the latest root for each known universe tree.
type cachedRoots []universe.Root

// atomicRootCache is an atomic pointer to a root cache.
type atomicRootCache = atomic.Pointer[cachedRoots]

// newAtomicRootCache creates a new atomic root cache.
func newAtomicRootCache() atomicRootCache {
	treeCache := &cachedRoots{}

	var a atomicRootCache
	a.Store(treeCache)

	return a
}

// rootIndex maps a tree ID to a universe root.
type rootIndex = lnutils.SyncMap[treeID, *universe.Root]

// atomicRootIndex is an atomic pointer to a root index.
type atomicRootIndex = atomic.Pointer[rootIndex]

// newAtomicRootIndex creates a new atomic root index.
func newAtomicRootIndex() atomicRootIndex {
	var a atomicRootIndex
	a.Store(&rootIndex{})

	return a
}

// rootNodeCache is used to cache the set of active root nodes for the
// multiverse tree.
type rootNodeCache struct {
	sync.RWMutex

	rootIndex atomicRootIndex

	allRoots atomicRootCache

	// TODO(roasbeef): cache for issuance vs transfer roots?
}

// newRootNodeCache creates a new root node cache.
func newRootNodeCache() *rootNodeCache {
	return &rootNodeCache{
		rootIndex: newAtomicRootIndex(),
		allRoots:  newAtomicRootCache(),
	}
}

// fetchRoots reads the cached roots for the given proof type. If the amounts
// are needed, then we return nothing so we go to the database to fetch the
// information.
func (r *rootNodeCache) fetchRoots(withAmts, haveWriteLock bool,
) []universe.Root {

	// We don't cache roots with amounts, so if the caller wants the
	// amounts, they'll go to disk.
	if withAmts {
		return nil
	}

	// If we have the write lock already, no need to fetch it.
	if !haveWriteLock {
		r.RLock()
		defer r.RUnlock()
	}

	log.Infof("checking cache for roots")

	// Attempt to read directly from the root node cache.
	rootNodeCache := r.allRoots.Load()
	rootNodes := *rootNodeCache

	return rootNodes
}

// fetchRoot reads the cached root for the given ID.
func (r *rootNodeCache) fetchRoot(id universe.Identifier) *universe.Root {
	rootIndex := r.rootIndex.Load()

	root, ok := rootIndex.Load(treeID(id.String()))
	if ok {
		return root
	}

	return nil
}

// cacheRoots stores the given roots in the cache.
func (r *rootNodeCache) cacheRoots(rootNodes []universe.Root) {
	log.Debugf("caching num_roots=%v", len(rootNodes))

	// Store the main root pointer, then update the root index.
	newRoots := cachedRoots(rootNodes)
	r.allRoots.Store(&newRoots)

	rootIndex := r.rootIndex.Load()
	for _, rootNode := range rootNodes {
		idStr := treeID(rootNode.ID.String())
		rootIndex.Store(idStr, &rootNode)
	}
}

// wipeCache wipes all the cached roots.
func (r *rootNodeCache) wipeCache() {
	log.Debugf("wiping universe cache")

	r.allRoots.Store(&cachedRoots{})
}

// MultiverseStore implements the persistent storage for a multiverse.
//
// NOTE: This implements the universe.MultiverseArchive interface.
type MultiverseStore struct {
	db BatchedMultiverse

	rootNodeCache *rootNodeCache

	proofCache proofCache
}

// NewMultiverseStore creates a new multiverse DB store handle.
func NewMultiverseStore(db BatchedMultiverse) *MultiverseStore {
	return &MultiverseStore{
		db:            db,
		rootNodeCache: newRootNodeCache(),
		proofCache:    newProofCache(),
	}
}

// namespaceForProof returns the multiverse namespace used for the given proof
// type.
func namespaceForProof(proofType universe.ProofType) (string, error) {
	switch proofType {
	case universe.ProofTypeIssuance:
		return issuanceMultiverseNS, nil

	case universe.ProofTypeTransfer:
		return transferMultiverseNS, nil

	default:
		return "", fmt.Errorf("unknown proof type: %v", int(proofType))
	}
}

// RootNode returns the root multiverse node for the given proof type.
func (b *MultiverseStore) RootNode(ctx context.Context,
	proofType universe.ProofType) (*universe.MultiverseRoot, error) {

	var rootNode *universe.MultiverseRoot

	multiverseNS, err := namespaceForProof(proofType)
	if err != nil {
		return nil, err
	}

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, multiverseNS),
		)

		multiverseRoot, err := multiverseTree.Root(ctx)
		if err != nil {
			return err
		}

		rootNode = &universe.MultiverseRoot{
			Node:      multiverseRoot,
			ProofType: proofType,
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return rootNode, nil
}

// RootNodes returns the complete set of known base universe root nodes for the
// set of base universes tracked in the multiverse.
func (b *MultiverseStore) RootNodes(ctx context.Context,
	q universe.RootNodesQuery) ([]universe.Root, error) {

	// Attempt to read directly from the root node cache.
	rootNodes := b.rootNodeCache.fetchRoots(withAmountsById, false)
	if len(rootNodes) > 0 {
		log.Debugf("read %d root nodes from cache", len(rootNodes))
		return rootNodes, nil
	}

	b.rootNodeCache.Lock()
	defer b.rootNodeCache.Unlock()

	// Check to see if the cache was populated while we were waiting for
	// the mutex.
	rootNodes = b.rootNodeCache.fetchRoots(withAmountsById, true)
	if len(rootNodes) > 0 {
		log.Debugf("read %d root nodes from cache", len(rootNodes))
		return rootNodes, nil
	}

	now := time.Now()
	log.Infof("populating root cache...")

	var (
		uniRoots []universe.Root
		readTx   = NewBaseMultiverseReadTx()
	)

	params := sqlc.UniverseRootsParams{
		SortDirection: sqlInt16(q.SortDirection),
		NumOffset:     int32(q.Offset),
		NumLimit: func() int32 {
			if q.Limit == 0 {
				return universe.MaxPageSize
			}

			return int32(q.Limit)
		}(),
	}

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		dbRoots, err := db.UniverseRoots(ctx, params)
		if err != nil {
			return err
		}

		for _, dbRoot := range dbRoots {
			var (
				id            universe.Identifier
				groupedAssets map[asset.ID]uint64
			)

			// Parse universe proof type and populate the universe
			// ID.
			id.ProofType, err = universe.ParseStrProofType(
				dbRoot.ProofType,
			)
			if err != nil {
				return err
			}

			if dbRoot.AssetID != nil {
				copy(id.AssetID[:], dbRoot.AssetID)
			}

			if dbRoot.GroupKey != nil {
				id.GroupKey, err = schnorr.ParsePubKey(
					dbRoot.GroupKey,
				)
				if err != nil {
					return err
				}
			}

			// We skip the grouped assets if that wasn't explicitly
			// requested by the user, saves us some calls for
			// grouped assets.
			if dbRoot.GroupKey != nil && q.WithAmountsById {
				groupLeaves, err := db.QueryUniverseLeaves(
					ctx, UniverseLeafQuery{
						Namespace: id.String(),
					},
				)
				if err != nil {
					return err
				}

				groupedAssets = make(
					map[asset.ID]uint64, len(groupLeaves),
				)
				for _, leaf := range groupLeaves {
					var id asset.ID
					copy(id[:], leaf.AssetID)
					groupedAssets[id] = uint64(leaf.SumAmt)
				}
			} else if q.WithAmountsById {
				// For non-grouped assets, there's exactly one
				// member, the asset itself.
				groupedAssets = map[asset.ID]uint64{
					id.AssetID: uint64(dbRoot.RootSum),
				}
			}

			var nodeHash mssmt.NodeHash
			copy(nodeHash[:], dbRoot.RootHash)
			uniRoot := universe.Root{
				ID: id,
				Node: mssmt.NewComputedBranch(
					nodeHash, uint64(dbRoot.RootSum),
				),
				AssetName:     dbRoot.AssetName,
				GroupedAssets: groupedAssets,
			}

			uniRoots = append(uniRoots, uniRoot)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	log.Debugf("Populating %v root nodes into cache, took=%v",
		len(uniRoots), time.Since(now))

	// Cache all the root nodes we just read from the database.
	b.rootNodeCache.cacheRoots(uniRoots)

	return uniRoots, nil
}

// FetchProofLeaf returns a proof leaf for the target key. If the key doesn't
// have a script key specified, then all the proof leafs for the minting
// outpoint will be returned. If neither are specified, then all inserted proof
// leafs will be returned.
func (b *MultiverseStore) FetchProofLeaf(ctx context.Context,
	id universe.Identifier,
	universeKey universe.LeafKey) ([]*universe.Proof, error) {

	// First, check the cached to see if we already have this proof.
	proof := b.proofCache.fetchProof(id, universeKey)
	if len(proof) > 0 {
		return proof, nil
	}

	var (
		readTx = NewBaseUniverseReadTx()
		proofs []*universe.Proof
	)

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	dbErr := b.db.ExecTx(ctx, &readTx, func(dbTx BaseMultiverseStore) error {
		var err error
		proofs, err = universeFetchProofLeaf(
			ctx, id, universeKey, dbTx,
		)
		if err != nil {
			return err
		}

		// Populate multiverse specific fields of proofs.
		//
		// Retrieve a handle to the multiverse MS-SMT tree.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		multiverseRoot, err := multiverseTree.Root(ctx)
		if err != nil {
			return err
		}

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := id.Bytes()

		// Retrieve the multiverse inclusion proof for the asset
		// specific universe.
		multiverseInclusionProof, err := multiverseTree.MerkleProof(
			ctx, leafNodeKey,
		)
		if err != nil {
			return err
		}

		for i := range proofs {
			proofs[i].MultiverseRoot = multiverseRoot
			proofs[i].MultiverseInclusionProof = multiverseInclusionProof
		}

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// Insert the proof we just read up into the main cache.
	b.proofCache.insertProof(id, universeKey, proofs)

	return proofs, nil
}

// UpsertProofLeaf upserts a proof leaf within the multiverse tree and the
// universe tree that corresponds to the given key.
func (b *MultiverseStore) UpsertProofLeaf(ctx context.Context,
	id universe.Identifier, key universe.LeafKey,
	leaf *universe.Leaf,
	metaReveal *proof.MetaReveal) (*universe.Proof, error) {

	var (
		writeTx       BaseMultiverseOptions
		issuanceProof *universe.Proof
	)

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	execTxFunc := func(dbTx BaseMultiverseStore) error {
		// Register issuance in the asset (group) specific universe
		// tree.
		var (
			universeRoot mssmt.Node
			err          error
		)
		issuanceProof, universeRoot, err = universeUpsertProofLeaf(
			ctx, dbTx, id, key, leaf, metaReveal,
		)
		if err != nil {
			return err
		}

		// Retrieve a handle to the multiverse tree so that we can
		// update the tree by inserting a new issuance.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		// Construct a leaf node for insertion into the multiverse tree.
		// The leaf node includes a reference to the lower tree via the
		// lower tree root hash.
		universeRootHash := universeRoot.NodeHash()
		assetGroupSum := universeRoot.NodeSum()

		if id.ProofType == universe.ProofTypeIssuance {
			assetGroupSum = 1
		}

		leafNode := mssmt.NewLeafNode(
			universeRootHash[:], assetGroupSum,
		)

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := id.Bytes()

		_, err = multiverseTree.Insert(
			ctx, leafNodeKey, leafNode,
		)
		if err != nil {
			return err
		}

		// Retrieve the multiverse root and asset specific inclusion
		// proof for the leaf node.
		multiverseRoot, err := multiverseTree.Root(ctx)
		if err != nil {
			return err
		}

		multiverseInclusionProof, err := multiverseTree.MerkleProof(
			ctx, leafNodeKey,
		)
		if err != nil {
			return err
		}

		// Add multiverse specific fields to the issuance proof.
		issuanceProof.MultiverseRoot = multiverseRoot
		issuanceProof.MultiverseInclusionProof = multiverseInclusionProof

		return err
	}
	dbErr := b.db.ExecTx(ctx, &writeTx, execTxFunc)
	if dbErr != nil {
		return nil, dbErr
	}

	// Invalidate the cache since we just updated the root.
	b.rootNodeCache.wipeCache()
	b.proofCache.delProofsForAsset(id)

	return issuanceProof, nil
}

// UpsertProofLeafBatch upserts a proof leaf batch within the multiverse tree
// and the universe tree that corresponds to the given key(s).
func (b *MultiverseStore) UpsertProofLeafBatch(ctx context.Context,
	items []*universe.Item) error {

	insertProof := func(item *universe.Item,
		dbTx BaseMultiverseStore) error {

		// Upsert proof leaf into the asset (group) specific universe
		// tree.
		_, universeRoot, err := universeUpsertProofLeaf(
			ctx, dbTx, item.ID, item.Key, item.Leaf,
			item.MetaReveal,
		)
		if err != nil {
			return err
		}

		multiverseNS, err := namespaceForProof(item.ID.ProofType)
		if err != nil {
			return err
		}

		// Retrieve a handle to the multiverse tree so that we can
		// update the tree by inserting/updating a proof leaf.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		// Construct a leaf node for insertion into the multiverse tree.
		// The leaf node includes a reference to the lower tree via the
		// lower tree root hash.
		universeRootHash := universeRoot.NodeHash()
		assetGroupSum := universeRoot.NodeSum()

		if item.ID.ProofType == universe.ProofTypeIssuance {
			assetGroupSum = 1
		}

		leafNode := mssmt.NewLeafNode(
			universeRootHash[:], assetGroupSum,
		)

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := item.ID.Bytes()

		_, err = multiverseTree.Insert(ctx, leafNodeKey, leafNode)
		if err != nil {
			return err
		}

		return nil
	}

	var writeTx BaseMultiverseOptions
	dbErr := b.db.ExecTx(
		ctx, &writeTx, func(store BaseMultiverseStore) error {
			for idx := range items {
				item := items[idx]
				err := insertProof(item, store)
				if err != nil {
					return err
				}
			}

			return nil
		},
	)
	if dbErr != nil {
		return dbErr
	}

	// TODO(roasbeef): want to write thru but then need db query again?

	b.rootNodeCache.wipeCache()

	// Invalidate the root node cache for all the assets we just inserted.
	idsToDelete := fn.NewSet(fn.Map(items, func(item *universe.Item) treeID {
		return treeID(item.ID.String())
	})...)

	for id := range idsToDelete {
		b.proofCache.Delete(id)
	}

	return nil
}

// DeleteUniverse delete an entire universe sub-tre.
func (b *MultiverseStore) DeleteUniverse(ctx context.Context,
	id universe.Identifier) (string, error) {

	var writeTx BaseUniverseStoreOptions

	dbErr := b.db.ExecTx(ctx, &writeTx, func(dbTx BaseMultiverseStore) error {
		multiverseNS, err := namespaceForProof(id.ProofType)
		if err != nil {
			return err
		}

		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		multiverseLeafKey := id.Bytes()
		_, err = multiverseTree.Delete(ctx, multiverseLeafKey)
		if err != nil {
			return err
		}

		return deleteUniverseTree(ctx, dbTx, id)
	})
	if dbErr != nil {
		return "", dbErr
	}

	// Wipe the cache items from this node.
	b.rootNodeCache.wipeCache()

	idStr := treeID(id.String())
	b.proofCache.Delete(idStr)

	return id.String(), dbErr
}
