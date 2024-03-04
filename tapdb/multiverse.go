package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
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

var (
	// ErrNoMultiverseRoot is returned when no universe root is found for
	// the target proof type.
	ErrNoMultiverseRoot = errors.New("no multiverse root found")
)

type (
	BaseUniverseRoot = sqlc.UniverseRootsRow

	UniverseRootsParams = sqlc.UniverseRootsParams

	// MultiverseRoot is the root of a multiverse tree. Two trees exist:
	// issuance and transfers.
	MultiverseRoot = sqlc.FetchMultiverseRootRow

	// MultiverseLeaf is a leaf in a multiverse.
	MultiverseLeaf = sqlc.QueryMultiverseLeavesRow

	// QueryMultiverseLeaves is used to query for a set of leaves based on
	// the proof type and asset ID (or group key)
	QueryMultiverseLeaves = sqlc.QueryMultiverseLeavesParams
)

// BaseMultiverseStore is used to interact with a set of base universe
// roots, also known as a multiverse.
type BaseMultiverseStore interface {
	BaseUniverseStore

	// UniverseRoots returns the set of active universe roots for a given
	// Multiverse type.
	UniverseRoots(ctx context.Context,
		params UniverseRootsParams) ([]BaseUniverseRoot, error)

	// QueryMultiverseLeaves is used to query for the set of leaves that
	// reside in a multiverse tree.
	QueryMultiverseLeaves(ctx context.Context,
		arg QueryMultiverseLeaves) ([]MultiverseLeaf, error)

	// FetchMultiverseRoot returns the root of the multiverse tree for a
	// given target namespace (proof type in this case).
	FetchMultiverseRoot(ctx context.Context,
		proofNamespace string) (MultiverseRoot, error)
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
const numCachedProofs = 50_000

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
type proofCache struct {
	lnutils.SyncMap[treeID, leafProofCache]

	*cacheLogger
}

// newProofCache creates a new proof cache.
func newProofCache() *proofCache {
	return &proofCache{
		SyncMap:     lnutils.SyncMap[treeID, leafProofCache]{},
		cacheLogger: newCacheLogger("universe_proofs"),
	}
}

// fetchProof reads the cached proof for the given ID and leaf key.
func (p *proofCache) fetchProof(id universe.Identifier,
	leafKey universe.LeafKey) []*universe.Proof {

	// First, get the sub-cache for this universe ID from the map of
	// caches.
	idStr := treeID(id.String())
	assetProofCache, _ := p.LoadOrStore(idStr, newLeafCache())

	// With that lower level cache obtained, we can check to see if we have
	// a hit or not.
	proofKey := NewProofKey(id, leafKey)
	proof, err := assetProofCache.Get(proofKey)
	if err == nil {
		p.Hit()
		return *proof
	}

	p.Miss()

	return nil
}

// insertProof inserts the given proof into the cache.
func (p *proofCache) insertProof(id universe.Identifier,
	leafKey universe.LeafKey, proof []*universe.Proof) {

	idStr := treeID(id.String())

	assetProofCache, _ := p.LoadOrStore(idStr, newLeafCache())

	proofKey := NewProofKey(id, leafKey)

	log.Debugf("storing proof for %v+%v in cache, key=%x",
		id.StringForLog(), leafKey, proofKey[:])

	proofVal := cachedProof(proof)
	_, _ = assetProofCache.Put(proofKey, &proofVal)
}

// delProofsForAsset deletes all the proofs for the given asset.
func (p *proofCache) delProofsForAsset(id universe.Identifier) {
	log.Debugf("wiping proofs for %v from cache", id)

	idStr := treeID(id.String())
	p.Delete(idStr)
}

// rootPageQuery is a wrapper around a query to fetch all the roots, but with
// pagination parameters.
type rootPageQuery struct {
	withAmountsById bool
	leafQuery
}

// newRootPageQuery creates a new root page query.
func newRootPageQuery(q universe.RootNodesQuery) rootPageQuery {
	return rootPageQuery{
		withAmountsById: q.WithAmountsById,
		leafQuery: leafQuery{
			sortDirection: q.SortDirection,
			offset:        q.Offset,
			limit:         q.Limit,
		},
	}
}

// universeRootPage is a single page of roots.
type universeRootPage []universe.Root

// Size is the amount of roots in the page.
func (u universeRootPage) Size() (uint64, error) {
	return uint64(len(u)), nil
}

// rootPageCache is used to store the latest root pages for a given treeID.
type rootPageCache = lru.Cache[rootPageQuery, universeRootPage]

// atomicRootCache is an atomic pointer to a root cache.
type atomicRootCache = atomic.Pointer[rootPageCache]

// newAtomicRootCache creates a new atomic root cache.
func newAtomicRootCache() *atomicRootCache {
	rootCache := lru.NewCache[rootPageQuery, universeRootPage](
		numCachedProofs,
	)

	var a atomicRootCache
	a.Store(rootCache)

	return &a
}

// rootIndex maps a tree ID to a universe root.
type rootIndex = lnutils.SyncMap[treeID, *universe.Root]

// atomicRootIndex is an atomic pointer to a root index.
type atomicRootIndex = atomic.Pointer[rootIndex]

// newAtomicRootIndex creates a new atomic root index.
func newAtomicRootIndex() *atomicRootIndex {
	var a atomicRootIndex
	a.Store(&rootIndex{})

	return &a
}

// rootNodeCache is used to cache the set of active root nodes for the
// multiverse tree.
type rootNodeCache struct {
	sync.RWMutex

	rootIndex *atomicRootIndex

	allRoots *atomicRootCache

	*cacheLogger

	// TODO(roasbeef): cache for issuance vs transfer roots?
}

// newRootNodeCache creates a new root node cache.
func newRootNodeCache() *rootNodeCache {
	return &rootNodeCache{
		rootIndex:   newAtomicRootIndex(),
		allRoots:    newAtomicRootCache(),
		cacheLogger: newCacheLogger("universe_roots"),
	}
}

// fetchRoots reads the cached roots for the given proof type. If the amounts
// are needed, then we return nothing so we go to the database to fetch the
// information.
func (r *rootNodeCache) fetchRoots(q universe.RootNodesQuery,
	haveWriteLock bool) []universe.Root {

	// If we have the write lock already, no need to fetch it.
	if !haveWriteLock {
		r.RLock()
		defer r.RUnlock()
	}

	// Attempt to read directly from the root node cache.
	rootNodeCache := r.allRoots.Load()
	rootNodes, _ := rootNodeCache.Get(newRootPageQuery(q))

	if len(rootNodes) > 0 {
		r.Hit()
	} else {
		r.Miss()
	}

	return rootNodes
}

// fetchRoot reads the cached root for the given ID.
func (r *rootNodeCache) fetchRoot(id universe.Identifier) *universe.Root {
	rootIndex := r.rootIndex.Load()

	root, ok := rootIndex.Load(treeID(id.String()))
	if ok {
		r.Hit()
		return root
	}

	r.Miss()

	return nil
}

// cacheRoot stores the given root in the cache.
func (r *rootNodeCache) cacheRoot(id universe.Identifier,
	root universe.Root) {

	rootIndex := r.rootIndex.Load()
	rootIndex.Store(treeID(id.String()), &root)
}

// cacheRoots stores the given roots in the cache.
func (r *rootNodeCache) cacheRoots(q universe.RootNodesQuery,
	rootNodes []universe.Root) {

	log.Debugf("caching num_roots=%v", len(rootNodes))

	// Store the main root pointer, then update the root index.
	rootPageCache := r.allRoots.Load()
	_, _ = rootPageCache.Put(newRootPageQuery(q), rootNodes)

	rootIndex := r.rootIndex.Load()
	for _, rootNode := range rootNodes {
		rootNode := rootNode

		idStr := treeID(rootNode.ID.String())
		rootIndex.Store(idStr, &rootNode)
	}
}

// wipeCache wipes all the cached roots.
func (r *rootNodeCache) wipeCache() {
	log.Debugf("wiping universe cache")

	rootCache := lru.NewCache[rootPageQuery, universeRootPage](
		numCachedProofs,
	)
	r.allRoots.Store(rootCache)

	r.rootIndex.Store(&rootIndex{})
}

// cachedLeafKeys is used to cache the set of leaf keys for a given universe.
//
// TODO(roasbeef); cacheable[T]
type cachedLeafKeys []universe.LeafKey

// Size just returns 1, as we cache based on the total number of assets, but
// not the sum of their leaves.
func (c cachedLeafKeys) Size() (uint64, error) {
	return uint64(1), nil
}

// numMaxCachedPages is the maximum number of pages we'll cache for a given
// page cache. Each page is 512 items, so we'll cache 10 of them, up to 5,120
// for a given namespace.
const numMaxCachedPages = 1000

// leafQuery is a wrapper around the existing UniverseLeafKeysQuery struct that
// doesn't include a pointer so it can be safely used as a map key.
type leafQuery struct {
	sortDirection universe.SortDirection
	offset        int32
	limit         int32
}

// newLeafQuery creates a new leaf query.
func newLeafQuery(q universe.UniverseLeafKeysQuery) leafQuery {
	return leafQuery{
		sortDirection: q.SortDirection,
		offset:        q.Offset,
		limit:         q.Limit,
	}
}

// leafPageCache caches the various paginated responses for a given treeID.
type leafPageCache struct {
	*lru.Cache[leafQuery, *cachedLeafKeys]
}

// Size returns the number of elements in the leaf page cache.
func (l *leafPageCache) Size() (uint64, error) {
	return uint64(l.Len()), nil
}

// leafKeysCache is used to cache the set of leaf keys for a given universe.
// For each treeID we store an inner cache for the paginated responses.
type leafKeysCache = lru.Cache[treeID, *leafPageCache]

// universeLeafCaches is used to cache the set of leaf keys for a given
// universe.
type universeLeafCache struct {
	sync.Mutex

	leafCache *leafKeysCache

	*cacheLogger
}

// newUniverseLeafCache creates a new universe leaf cache.
func newUniverseLeafCache() *universeLeafCache {
	return &universeLeafCache{
		leafCache: lru.NewCache[treeID, *leafPageCache](
			numCachedProofs,
		),
		cacheLogger: newCacheLogger("universe_leaf_keys"),
	}
}

// fetchLeafKeys reads the cached leaf keys for the given ID.
func (u *universeLeafCache) fetchLeafKeys(q universe.UniverseLeafKeysQuery,
) []universe.LeafKey {

	idStr := treeID(q.Id.String())

	leafPageCache, err := u.leafCache.Get(idStr)
	if err == nil {
		leafKeys, err := leafPageCache.Get(newLeafQuery(q))
		if err == nil {
			u.Hit()
			log.Tracef("read leaf keys for %v from cache",
				q.Id.StringForLog())
			return *leafKeys
		}
	}

	u.Miss()

	return nil
}

// cacheLeafKeys stores the given leaf keys in the cache.
func (u *universeLeafCache) cacheLeafKeys(q universe.UniverseLeafKeysQuery,
	keys []universe.LeafKey) {

	cachedKeys := cachedLeafKeys(keys)

	idStr := treeID(q.Id.String())

	log.Debugf("storing leaf keys for %v in cache", q.Id.StringForLog())

	pageCache, err := u.leafCache.Get(idStr)
	if err != nil {
		// No page cache yet, so we'll create one now.
		pageCache = &leafPageCache{
			Cache: lru.NewCache[leafQuery, *cachedLeafKeys](
				numMaxCachedPages,
			),
		}

		// Store the cache in the top level cache.
		_, _ = u.leafCache.Put(idStr, pageCache)
	}

	// Add the to the page cache.
	_, _ = pageCache.Put(newLeafQuery(q), &cachedKeys)
}

// wipeCache wipes the cache of leaf keys for a given universe ID.
func (u *universeLeafCache) wipeCache(id treeID) {
	log.Debugf("wiping leaf keys for %x in cache", id)

	u.leafCache.Delete(id)
}

// MultiverseStore implements the persistent storage for a multiverse.
//
// NOTE: This implements the universe.MultiverseArchive interface.
type MultiverseStore struct {
	db BatchedMultiverse

	rootNodeCache *rootNodeCache

	proofCache *proofCache

	leafKeysCache *universeLeafCache

	// transferProofDistributor is an event distributor that will be used to
	// notify subscribers about new proof leaves that are added to the
	// multiverse. This is used to notify the custodian about new incoming
	// proofs. And since the custodian is only interested in transfer
	// proofs, we only signal on transfer proofs.
	transferProofDistributor *fn.EventDistributor[proof.Blob]
}

// NewMultiverseStore creates a new multiverse DB store handle.
func NewMultiverseStore(db BatchedMultiverse) *MultiverseStore {
	return &MultiverseStore{
		db:                       db,
		rootNodeCache:            newRootNodeCache(),
		proofCache:               newProofCache(),
		leafKeysCache:            newUniverseLeafCache(),
		transferProofDistributor: fn.NewEventDistributor[proof.Blob](),
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
		return "", fmt.Errorf("unknown proof type: %d", int(proofType))
	}
}

// MultiverseRootNode returns the root multiverse node for the given proof
// type.
func (b *MultiverseStore) MultiverseRootNode(ctx context.Context,
	proofType universe.ProofType) (fn.Option[universe.MultiverseRoot],
	error) {

	none := fn.None[universe.MultiverseRoot]()

	multiverseNS, err := namespaceForProof(proofType)
	if err != nil {
		return none, err
	}

	var rootNode universe.MultiverseRoot

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		multiverseRoot, err := db.FetchMultiverseRoot(ctx, multiverseNS)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNoMultiverseRoot

		case err != nil:
			return err
		}

		nodeHash, err := newKey(multiverseRoot.MultiverseRootHash[:])
		if err != nil {
			return err
		}

		smtRoot := mssmt.NewComputedBranch(
			nodeHash, uint64(multiverseRoot.MultiverseRootSum),
		)

		rootNode = universe.MultiverseRoot{
			Node:      smtRoot,
			ProofType: proofType,
		}

		return nil
	})
	if dbErr != nil {
		return none, dbErr
	}

	return fn.Some(rootNode), nil
}

// UniverseRootNode returns the Universe root node for the given asset ID.
func (b *MultiverseStore) UniverseRootNode(ctx context.Context,
	id universe.Identifier) (universe.Root, error) {

	// First, we'll check the root node cache to see if we already have it.
	rootNode := b.rootNodeCache.fetchRoot(id)
	if rootNode != nil {
		return *rootNode, nil
	}

	b.rootNodeCache.Lock()
	defer b.rootNodeCache.Unlock()

	// Check to see if the cache was populated while we were waiting for
	// the lock.
	rootNode = b.rootNodeCache.fetchRoot(id)
	if rootNode != nil {
		return *rootNode, nil
	}

	var universeRoot UniverseRoot

	universeNamespace := id.String()

	readTx := NewBaseUniverseReadTx()

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		dbRoot, err := db.FetchUniverseRoot(ctx, universeNamespace)
		if err != nil {
			return err
		}

		universeRoot = dbRoot
		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return universe.Root{}, universe.ErrNoUniverseRoot
	case dbErr != nil:
		return universe.Root{}, dbErr
	}

	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], universeRoot.RootHash[:])
	smtNode := mssmt.NewComputedNode(
		nodeHash, uint64(universeRoot.RootSum),
	)

	dbRoot := universe.Root{
		ID:        id,
		Node:      smtNode,
		AssetName: universeRoot.AssetName,
	}

	b.rootNodeCache.cacheRoot(id, dbRoot)

	return dbRoot, nil
}

// UniverseLeafKeys returns the set of leaf keys for the given universe.
func (b *MultiverseStore) UniverseLeafKeys(ctx context.Context,
	q universe.UniverseLeafKeysQuery) ([]universe.LeafKey, error) {

	// First, check to see if we have the leaf keys cached.
	leafKeys := b.leafKeysCache.fetchLeafKeys(q)
	if len(leafKeys) > 0 {
		return leafKeys, nil
	}

	// The leaves wasn't populated, so we'll go to disk to fetch it.
	b.leafKeysCache.Lock()
	defer b.leafKeysCache.Unlock()

	// While we were waiting for the lock, the cache might have been
	// populated, so we'll check that now.
	leafKeys = b.leafKeysCache.fetchLeafKeys(q)
	if len(leafKeys) > 0 {
		return leafKeys, nil
	}

	// Otherwise, we'll read it from disk, then add it to our cache.
	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		dbLeaves, err := mintingKeys(ctx, db, q, q.Id.String())
		if err != nil {
			return err
		}

		leafKeys = dbLeaves

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	b.leafKeysCache.cacheLeafKeys(q, leafKeys)

	return leafKeys, nil
}

// RootNodes returns the complete set of known base universe root nodes for the
// set of base universes tracked in the multiverse.
func (b *MultiverseStore) RootNodes(ctx context.Context,
	q universe.RootNodesQuery) ([]universe.Root, error) {

	// Attempt to read directly from the root node cache.
	rootNodes := b.rootNodeCache.fetchRoots(q, false)
	if len(rootNodes) > 0 {
		log.Tracef("read %d root nodes from cache", len(rootNodes))
		return rootNodes, nil
	}

	b.rootNodeCache.Lock()
	defer b.rootNodeCache.Unlock()

	// Check to see if the cache was populated while we were waiting for
	// the mutex.
	rootNodes = b.rootNodeCache.fetchRoots(q, true)
	if len(rootNodes) > 0 {
		log.Tracef("read %d root nodes from cache", len(rootNodes))
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
		NumOffset:     q.Offset,
		NumLimit: func() int32 {
			if q.Limit == 0 {
				return universe.MaxPageSize
			}

			return q.Limit
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
	b.rootNodeCache.cacheRoots(q, uniRoots)

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

// FetchProof fetches a proof for an asset uniquely identified by the passed
// Locator. The returned blob contains the encoded full proof file, representing
// the complete provenance of the asset.
//
// If a proof cannot be found, then ErrProofNotFound is returned.
//
// NOTE: This is part of the proof.NotifyArchiver interface.
func (b *MultiverseStore) FetchProof(ctx context.Context,
	originLocator proof.Locator) (proof.Blob, error) {

	// The universe only delivers a single proof at a time, so we need a
	// callback that we can feed into proof.FetchProofProvenance to assemble
	// the full proof file.
	fetchProof := func(ctx context.Context, loc proof.Locator) (proof.Blob,
		error) {

		uniID := universe.Identifier{
			AssetID:   *loc.AssetID,
			GroupKey:  loc.GroupKey,
			ProofType: universe.ProofTypeTransfer,
		}
		scriptKey := asset.NewScriptKey(&loc.ScriptKey)
		leafKey := universe.LeafKey{
			ScriptKey: &scriptKey,
		}
		if loc.OutPoint != nil {
			leafKey.OutPoint = *loc.OutPoint
		}

		proofs, err := b.FetchProofLeaf(ctx, uniID, leafKey)
		if errors.Is(err, universe.ErrNoUniverseProofFound) {
			// If we didn't find a proof, maybe we arrived at the
			// issuance proof, in which case we need to adjust the
			// proof type.
			uniID.ProofType = universe.ProofTypeIssuance
			proofs, err = b.FetchProofLeaf(ctx, uniID, leafKey)

			// If we still didn't find a proof, then we'll return
			// the proof not found error, but the one from the proof
			// package, not the universe package, as the Godoc for
			// this method in the proof.NotifyArchiver states.
			if errors.Is(err, universe.ErrNoUniverseProofFound) {
				return nil, proof.ErrProofNotFound
			}
		}
		if err != nil {
			return nil, fmt.Errorf("error fetching proof from "+
				"archive: %w", err)
		}

		if len(proofs) > 1 {
			return nil, fmt.Errorf("expected only one proof, "+
				"got %d", len(proofs))
		}

		return proofs[0].Leaf.RawProof, nil
	}

	file, err := proof.FetchProofProvenance(
		ctx, nil, originLocator, fetchProof,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching proof from archive: %w",
			err)
	}

	var buf bytes.Buffer
	if err := file.Encode(&buf); err != nil {
		return nil, fmt.Errorf("error encoding proof file: %w", err)
	}

	return buf.Bytes(), nil
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

	execTxFunc := func(dbTx BaseMultiverseStore) error {
		// Register issuance in the asset (group) specific universe
		// tree.
		var err error
		issuanceProof, err = universeUpsertProofLeaf(
			ctx, dbTx, id, key, leaf, metaReveal,
		)
		if err != nil {
			return err
		}

		return nil
	}
	dbErr := b.db.ExecTx(ctx, &writeTx, execTxFunc)
	if dbErr != nil {
		return nil, dbErr
	}

	idStr := treeID(id.String())

	// Invalidate the cache since we just updated the root.
	b.rootNodeCache.wipeCache()
	b.proofCache.delProofsForAsset(id)
	b.leafKeysCache.wipeCache(idStr)

	// Notify subscribers about the new proof leaf, now that we're sure we
	// have written it to the database. But we only care about transfer
	// proofs, as the events are received by the custodian to finalize
	// inbound transfers.
	if id.ProofType == universe.ProofTypeTransfer {
		b.transferProofDistributor.NotifySubscribers(leaf.RawProof)
	}

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
		_, err := universeUpsertProofLeaf(
			ctx, dbTx, item.ID, item.Key, item.Leaf,
			item.MetaReveal,
		)
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

	// Notify subscribers about the new proof leaves, now that we're sure we
	// have written them to the database. But we only care about transfer
	// proofs, as the events are received by the custodian to finalize
	// inbound transfers.
	for idx := range items {
		if items[idx].ID.ProofType == universe.ProofTypeTransfer {
			b.transferProofDistributor.NotifySubscribers(
				items[idx].Leaf.RawProof,
			)
		}
	}

	// Invalidate the root node cache for all the assets we just inserted.
	idsToDelete := fn.NewSet(fn.Map(items, func(item *universe.Item) treeID {
		return treeID(item.ID.String())
	})...)

	for id := range idsToDelete {
		b.proofCache.Delete(id)
		b.leafKeysCache.wipeCache(id)
	}

	return nil
}

// DeleteUniverse delete an entire universe sub-tree.
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
	b.leafKeysCache.wipeCache(idStr)

	return id.String(), dbErr
}

// FetchLeaves returns the set of multiverse leaves for the given proof type,
// asset ID, and group key. If both asset ID and group key is nil, all leaves
// for the given proof type will be returned.
func (b *MultiverseStore) FetchLeaves(ctx context.Context,
	universeTargets []universe.MultiverseLeafDesc,
	proofType universe.ProofType) ([]universe.MultiverseLeaf, error) {

	queries := make([]QueryMultiverseLeaves, 0, len(universeTargets))
	switch len(universeTargets) {
	// If we don't have any targets, then we'll have just a single query to
	// return all universe leaves for the proof type.
	case 0:
		queries = append(queries, QueryMultiverseLeaves{
			ProofType: proofType.String(),
		})

	// Otherwise, we'll do a query for each universe target specified.
	default:
		for _, uniTarget := range universeTargets {
			var assetIDBytes, groupKeyBytes []byte

			uniTarget.WhenLeft(func(a asset.ID) {
				assetIDBytes = a[:]
			})
			uniTarget.WhenRight(func(g btcec.PublicKey) {
				groupKeyBytes = schnorr.SerializePubKey(&g)
			})

			queries = append(queries, QueryMultiverseLeaves{
				ProofType: proofType.String(),
				AssetID:   assetIDBytes,
				GroupKey:  groupKeyBytes,
			})
		}
	}

	var (
		readTx = NewBaseUniverseReadTx()
		leaves []universe.MultiverseLeaf
	)
	dbErr := b.db.ExecTx(ctx, &readTx, func(q BaseMultiverseStore) error {
		leaves = nil

		for _, query := range queries {
			dbLeaves, err := q.QueryMultiverseLeaves(ctx, query)
			if err != nil {
				return err
			}

			for _, leaf := range dbLeaves {
				var id universe.Identifier

				id.ProofType = proofType
				if len(leaf.AssetID) > 0 {
					copy(id.AssetID[:], leaf.AssetID)
				}
				if len(leaf.GroupKey) > 0 {
					id.GroupKey, err = schnorr.ParsePubKey(
						leaf.GroupKey,
					)
					if err != nil {
						return err
					}
				}

				leaves = append(leaves, universe.MultiverseLeaf{
					ID: id,
					LeafNode: mssmt.NewLeafNode(
						leaf.UniverseRootHash,
						uint64(leaf.UniverseRootSum),
					),
				})
			}
		}
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return leaves, nil
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (b *MultiverseStore) RegisterSubscriber(
	receiver *fn.EventReceiver[proof.Blob], deliverExisting bool,
	deliverFrom []*proof.Locator) error {

	b.transferProofDistributor.RegisterSubscriber(receiver)

	// No delivery of existing items requested, we're done here.
	if !deliverExisting {
		return nil
	}

	ctx := context.Background()
	for _, loc := range deliverFrom {
		if loc.AssetID == nil {
			return fmt.Errorf("missing asset ID")
		}

		id := universe.Identifier{
			AssetID:   *loc.AssetID,
			GroupKey:  loc.GroupKey,
			ProofType: universe.ProofTypeTransfer,
		}
		scriptKey := asset.NewScriptKey(&loc.ScriptKey)
		key := universe.LeafKey{
			ScriptKey: &scriptKey,
		}

		if loc.OutPoint != nil {
			key.OutPoint = *loc.OutPoint
		}

		leaves, err := b.FetchProofLeaf(ctx, id, key)
		if err != nil {
			return err
		}

		// Deliver the found leaves to the new item queue of the
		// subscriber.
		for idx := range leaves {
			rawProof := leaves[idx].Leaf.RawProof
			receiver.NewItemCreated.ChanIn() <- rawProof
		}
	}

	return nil
}

// RemoveSubscriber removes the given subscriber and also stops it from
// processing events.
func (b *MultiverseStore) RemoveSubscriber(
	subscriber *fn.EventReceiver[proof.Blob]) error {

	return b.transferProofDistributor.RemoveSubscriber(subscriber)
}

// A compile-time interface to ensure MultiverseStore meets the
// proof.NotifyArchiver interface.
var _ proof.NotifyArchiver = (*MultiverseStore)(nil)
