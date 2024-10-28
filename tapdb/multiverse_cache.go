package tapdb

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"

	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnutils"
)

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
	proofFromCache, err := assetProofCache.Get(proofKey)
	if err == nil {
		p.Hit()
		return *proofFromCache
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
	if _, err := assetProofCache.Put(proofKey, &proofVal); err != nil {
		log.Errorf("unable to insert into proof cache: %v", err)
	}
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
	_, err := rootPageCache.Put(newRootPageQuery(q), rootNodes)
	if err != nil {
		log.Errorf("unable to insert into root cache: %v", err)
	}

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
func (u *universeLeafCache) fetchLeafKeys(
	q universe.UniverseLeafKeysQuery) []universe.LeafKey {

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
		if _, err := u.leafCache.Put(idStr, pageCache); err != nil {
			// If we encounter an error here, we'll exit to avoid a
			// panic below.
			log.Errorf("unable to store entry in page cache: %v",
				err)
			return
		}
	}

	// Add the to the page cache.
	if _, err := pageCache.Put(newLeafQuery(q), &cachedKeys); err != nil {
		log.Errorf("unable to store leaf resp: %v", err)
	}
}

// wipeCache wipes the cache of leaf keys for a given universe ID.
func (u *universeLeafCache) wipeCache(id treeID) {
	log.Debugf("wiping leaf keys for %x in cache", id)

	u.leafCache.Delete(id)
}
