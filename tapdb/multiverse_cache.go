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

// cachedProofs is a list of cached proof leaves.
type cachedProofs []*universe.Proof

// Size just returns 1 as we're limiting based on the total number different
// leaf keys we query by. So we might store more than one proof per cache entry
// if the universe key's script key isn't set. But we only want a certain number
// of different keys stored in the cache.
func (c *cachedProofs) Size() (uint64, error) {
	return 1, nil
}

// newProofCache creates a new leaf proof cache.
func newProofCache() *lru.Cache[ProofKey, *cachedProofs] {
	return lru.NewCache[ProofKey, *cachedProofs](
		numCachedProofs,
	)
}

// universeIDKey is a cache key that is used to uniquely identify a universe
// within a multiverse tree cache.
type universeIDKey = string

// universeProofCache a map of proof caches for each proof type.
type universeProofCache struct {
	lnutils.SyncMap[universeIDKey, *lru.Cache[ProofKey, *cachedProofs]]

	*cacheLogger
}

// newUniverseProofCache creates a new proof cache.
func newUniverseProofCache() *universeProofCache {
	return &universeProofCache{
		SyncMap: lnutils.SyncMap[
			universeIDKey, *lru.Cache[ProofKey, *cachedProofs],
		]{},
		cacheLogger: newCacheLogger("universe_proofs"),
	}
}

// fetchProof reads the cached proof for the given ID and leaf key.
func (p *universeProofCache) fetchProof(id universe.Identifier,
	leafKey universe.LeafKey) []*universe.Proof {

	// First, get the sub-cache for this universe ID from the map of
	// caches.
	assetProofCache, _ := p.LoadOrStore(id.String(), newProofCache())

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

// insertProofs inserts the given proofs into the cache.
func (p *universeProofCache) insertProofs(id universe.Identifier,
	leafKey universe.LeafKey, proof []*universe.Proof) {

	assetProofCache, _ := p.LoadOrStore(id.String(), newProofCache())

	proofKey := NewProofKey(id, leafKey)

	log.Debugf("storing proof for %v+%v in cache, key=%x",
		id.StringForLog(), leafKey, proofKey[:])

	proofVal := cachedProofs(proof)
	if _, err := assetProofCache.Put(proofKey, &proofVal); err != nil {
		log.Errorf("unable to insert into proof cache: %v", err)
	}
}

// delProofsForAsset deletes all the proofs for the given asset.
func (p *universeProofCache) delProofsForAsset(id universe.Identifier) {
	log.Debugf("wiping proofs for %v from cache", id)

	p.Delete(id.String())
}

// rootPageQueryKey is a cache key that wraps around a query to fetch all the
// roots, but with pagination parameters.
type rootPageQueryKey struct {
	withAmountsById bool
	leafQueryKey
}

// newRootPageQuery creates a new root page query.
func newRootPageQuery(q universe.RootNodesQuery) rootPageQueryKey {
	return rootPageQueryKey{
		withAmountsById: q.WithAmountsById,
		leafQueryKey: leafQueryKey{
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

// rootPageCache is used to store the latest root pages for a given
// universeIDKey.
type rootPageCache struct {
	atomic.Pointer[lru.Cache[rootPageQueryKey, universeRootPage]]
}

// newRootPageCache creates a new atomic root cache.
func newRootPageCache() *rootPageCache {
	var cache rootPageCache
	cache.wipe()

	return &cache
}

// wipe wipes the cache.
func (r *rootPageCache) wipe() {
	rootCache := lru.NewCache[rootPageQueryKey, universeRootPage](
		numCachedProofs,
	)
	r.Store(rootCache)
}

// rootIndex maps a tree ID to a universe root.
type rootIndex struct {
	atomic.Pointer[lnutils.SyncMap[universeIDKey, *universe.Root]]
}

// newRootIndex creates a new atomic root index.
func newRootIndex() *rootIndex {
	var a rootIndex
	a.wipe()

	return &a
}

// wipe wipes the cache.
func (r *rootIndex) wipe() {
	var idx lnutils.SyncMap[universeIDKey, *universe.Root]
	r.Store(&idx)
}

// rootNodeCache is used to cache the set of active root nodes for the
// multiverse tree.
type rootNodeCache struct {
	sync.RWMutex

	rootIndex *rootIndex

	allRoots *rootPageCache

	*cacheLogger

	// TODO(roasbeef): cache for issuance vs transfer roots?
}

// newRootNodeCache creates a new root node cache.
func newRootNodeCache() *rootNodeCache {
	return &rootNodeCache{
		rootIndex:   newRootIndex(),
		allRoots:    newRootPageCache(),
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

	root, ok := rootIndex.Load(id.String())
	if ok {
		r.Hit()
		return root
	}

	r.Miss()

	return nil
}

// cacheRoot stores the given root in the cache.
func (r *rootNodeCache) cacheRoot(id universe.Identifier, root universe.Root) {
	rootIndex := r.rootIndex.Load()
	rootIndex.Store(id.String(), &root)
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
		rootIndex.Store(rootNode.ID.String(), &rootNode)
	}
}

// wipeCache wipes all the cached roots.
func (r *rootNodeCache) wipeCache() {
	log.Debugf("wiping universe cache")

	r.allRoots.wipe()
	r.rootIndex.wipe()
}

// cachedLeafKeys is used to cache the set of leaf keys for a given universe.
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

// leafQueryKey is a wrapper around the existing UniverseLeafKeysQuery struct that
// doesn't include a pointer so it can be safely used as a map key.
type leafQueryKey struct {
	sortDirection universe.SortDirection
	offset        int32
	limit         int32
}

// newLeafQuery creates a new leaf query.
func newLeafQuery(q universe.UniverseLeafKeysQuery) leafQueryKey {
	return leafQueryKey{
		sortDirection: q.SortDirection,
		offset:        q.Offset,
		limit:         q.Limit,
	}
}

// leafPageCache caches the various paginated responses for a given
// universeIDKey.
type leafPageCache struct {
	*lru.Cache[leafQueryKey, *cachedLeafKeys]
}

// Size returns the number of elements in the leaf page cache.
func (l *leafPageCache) Size() (uint64, error) {
	return uint64(l.Len()), nil
}

// universeLeafCaches is used to cache the set of leaf keys for a given
// universe.
type universeLeafPageCache struct {
	sync.Mutex

	leafCache *lru.Cache[universeIDKey, *leafPageCache]

	*cacheLogger
}

// newUniverseLeafPageCache creates a new universe leaf cache.
func newUniverseLeafPageCache() *universeLeafPageCache {
	return &universeLeafPageCache{
		leafCache: lru.NewCache[universeIDKey, *leafPageCache](
			numCachedProofs,
		),
		cacheLogger: newCacheLogger("universe_leaf_keys"),
	}
}

// fetchLeafKeys reads the cached leaf keys for the given ID.
func (u *universeLeafPageCache) fetchLeafKeys(
	q universe.UniverseLeafKeysQuery) []universe.LeafKey {

	leafPageCache, err := u.leafCache.Get(q.Id.String())
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
func (u *universeLeafPageCache) cacheLeafKeys(q universe.UniverseLeafKeysQuery,
	keys []universe.LeafKey) {

	cachedKeys := cachedLeafKeys(keys)

	idStr := q.Id.String()

	log.Debugf("storing leaf keys for %v in cache", q.Id.StringForLog())

	pageCache, err := u.leafCache.Get(idStr)
	if err != nil {
		// No page cache yet, so we'll create one now.
		pageCache = &leafPageCache{
			Cache: lru.NewCache[leafQueryKey, *cachedLeafKeys](
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
func (u *universeLeafPageCache) wipeCache(id universeIDKey) {
	log.Debugf("wiping leaf keys for %x in cache", id)

	u.leafCache.Delete(id)
}
