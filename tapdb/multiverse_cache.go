package tapdb

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnutils"
)

// MultiverseCacheConfig is the configuration for the different multiverse
// caches that exist.
//
//nolint:lll
type MultiverseCacheConfig struct {
	// ProofsPerUniverse is the number of proofs that are cached per
	// universe. This number needs to be multiplied by the total number of
	// universes to get the total number of proofs that are cached. There is
	// no limit to the number of universes that can hold cached keys, so a
	// cache is created for each universe that receives a request.
	ProofsPerUniverse uint64 `long:"proofs-per-universe" description:"The number of proofs that are cached per universe."`

	// LeavesNumCachedUniverses is the number of universes that can have a
	// cache of leaf keys. Each cached universe can have up to
	// LeavesPerUniverse keys cached. The total number of cached keys is
	// therefore LeavesNumCachedUniverses * LeavesPerUniverse.
	LeavesNumCachedUniverses uint64 `long:"leaves-num-cached-universes" description:"The number of universes that can have a cache of leaf keys."`

	// LeavesPerUniverse is the number of leaf keys that are cached per
	// universe. This number needs to be multiplied by
	// LeavesNumCachedUniverses to get the total number of leaf keys that
	// are cached.
	LeavesPerUniverse uint64 `long:"leaves-per-universe" description:"The number of leaf keys that are cached per cached universe."`

	// SyncerCacheEnabled is a flag that indicates if the syncer cache is
	// enabled. The syncer cache is used to cache the set of active root
	// nodes for the multiverse tree, which is specifically kept for the
	// universe sync.
	SyncerCacheEnabled bool `long:"syncer-cache-enabled" description:"If the syncer cache is enabled."`

	// SyncerCachePreAllocSize is the pre-allocated size of the syncer
	// cache.
	SyncerCachePreAllocSize uint64 `long:"syncer-cache-pre-alloc-size" description:"The pre-allocated size of the syncer cache."`

	// RootNodePageCacheSize is the size of the root node page cache that
	// serves all paginated queries for root nodes that use different
	// parameters than the syncer cache.
	RootNodePageCacheSize uint64 `long:"root-node-page-cache-size" description:"The size of the root node page cache for all requests that aren't served by the syncer cache."`
}

// DefaultMultiverseCacheConfig returns the default configuration for the
// multiverse cache.
func DefaultMultiverseCacheConfig() MultiverseCacheConfig {
	return MultiverseCacheConfig{
		ProofsPerUniverse:        5,
		LeavesNumCachedUniverses: 2_000,
		LeavesPerUniverse:        50,
		SyncerCacheEnabled:       false,
		SyncerCachePreAllocSize:  100_000,
		RootNodePageCacheSize:    20 * universe.RequestPageSize,
	}
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
func newProofCache(proofCacheSize uint64) *lru.Cache[ProofKey, *cachedProofs] {
	return lru.NewCache[ProofKey, *cachedProofs](proofCacheSize)
}

// universeIDKey is a cache key that is used to uniquely identify a universe
// within a multiverse tree cache.
type universeIDKey = string

// universeProofCache a map of proof caches for each proof type.
type universeProofCache struct {
	proofsPerUniverse uint64

	lnutils.SyncMap[universeIDKey, *lru.Cache[ProofKey, *cachedProofs]]

	*cacheLogger
}

// newUniverseProofCache creates a new proof cache.
func newUniverseProofCache(proofsPerUniverse uint64) *universeProofCache {
	return &universeProofCache{
		proofsPerUniverse: proofsPerUniverse,
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
	assetProofCache, _ := p.LoadOrStore(
		id.String(), newProofCache(p.proofsPerUniverse),
	)

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

	assetProofCache, _ := p.LoadOrStore(
		id.String(), newProofCache(p.proofsPerUniverse),
	)

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
func newRootPageCache(cacheSize uint64) *rootPageCache {
	var cache rootPageCache
	cache.wipe(cacheSize)

	return &cache
}

// wipe wipes the cache.
func (r *rootPageCache) wipe(cacheSize uint64) {
	rootCache := lru.NewCache[rootPageQueryKey, universeRootPage](cacheSize)
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

// syncerRootNodeCache is used to cache the set of active root nodes for the
// multiverse tree, which is specifically kept for the universe sync.
type syncerRootNodeCache struct {
	sync.RWMutex

	// enabled is a flag that indicates if the cache is enabled.
	enabled bool

	// preAllocSize is the pre-allocated size of the cache.
	preAllocSize uint64

	// universeKeyList is the list of all keys of the universes that are
	// currently known in this multiverse. This slice is sorted by the key
	// (which might differ from the database ordering) and can be used to
	// paginate through the universes efficiently. The universe identifier
	// key also contains the proof type, so there will be two entries
	// per asset ID or group key, one for issuance and one for transfer
	// universes. The universe roots map below will contain a root for each
	// of these universes. The stable sort order allows us to add and remove
	// entries without needing to fetch the entire list from the database,
	// as remove can be done by binary search and add can be done by
	// inserting and then sorting again.
	universeKeyList []universe.IdentifierKey

	// universeRoots is a map of universe ID key to the root of the
	// universe. This map is needed to look up the root of an individual
	// universe quickly, or to look up the roots of all the universes when
	// paging through them. This map never needs to be cleared, as universe
	// roots are only added (new issuance or transfer events) or modified
	// (re-issuance into grouped asset or new transfer) but rarely deleted.
	// Therefore, we never need to do a full wipe of the cache.
	universeRoots map[universe.IdentifierKey]universe.Root

	*cacheLogger
}

// newSyncerRootNodeCache creates a new root node cache.
func newSyncerRootNodeCache(enabled bool,
	preAllocSize uint64) *syncerRootNodeCache {

	rootsMap := make(map[universe.IdentifierKey]universe.Root)
	if enabled {
		rootsMap = make(
			map[universe.IdentifierKey]universe.Root, preAllocSize,
		)
	}

	return &syncerRootNodeCache{
		preAllocSize:  preAllocSize,
		universeRoots: rootsMap,
		cacheLogger:   newCacheLogger("syncer_universe_roots"),
		enabled:       enabled,
	}
}

// isQueryForSyncerCache returns true if the given query can be served from the
// syncer cache. We explicitly only cache the syncer queries in the syncer
// cache, which _always_ queries with sort direction "ascending" and no amounts
// by ID. For any other query, we'll go to the LRU based secondary cache or the
// database.
func isQueryForSyncerCache(q universe.RootNodesQuery) bool {
	if q.WithAmountsById || q.SortDirection != universe.SortAscending {
		return false
	}

	return true
}

// fetchRoots reads the cached roots for the given proof type. If the amounts
// are needed, then we return nothing so we go to the database to fetch the
// information. The boolean indicates if there are more roots available because
// the caller has reached the end of the list with the given offset.
func (r *syncerRootNodeCache) fetchRoots(q universe.RootNodesQuery,
	haveWriteLock bool) ([]universe.Root, bool) {

	// We shouldn't be called for a query that can't be served from the
	// cache. But in case we are, we'll just short-cut here.
	if !isQueryForSyncerCache(q) || !r.enabled {
		return nil, false
	}

	// If we've acquired the write lock because we're doing a last lookup
	// before potentially populating the cache, we don't need to acquire the
	// read lock. If we're just normally reading from the cache, we'll need
	// to acquire the read lock.
	if !haveWriteLock {
		r.RLock()
		defer r.RUnlock()
	}

	// If the cache is empty, we'll short-cut as well.
	if len(r.universeRoots) == 0 {
		// This is a miss, but we'll return nil to indicate that we
		// don't have any roots.
		r.Miss()

		return nil, false
	}

	offset := q.Offset
	limit := q.Limit

	// Is the page valid?
	if offset < 0 || limit <= 0 {
		log.Warnf("Invalid page query for syncer cache: offset=%v, "+
			"limit=%v", offset, limit)

		return nil, false
	}

	// Because the cache is not empty, and we know it should contain all
	// roots, we know the caller has reached the end of the list when their
	// offset is larger than the number of roots. Since this is a "legal"
	// query (how else would they know they're at the end?), we'll return
	// an empty list and a boolean to indicate that there are no more roots.
	if offset >= int32(len(r.universeRoots)) {
		return nil, true
	}

	endIndex := offset + limit
	if endIndex > int32(len(r.universeRoots)) {
		endIndex = int32(len(r.universeRoots))
	}

	rootNodeIDs := r.universeKeyList[offset:endIndex]
	rootNodes := make([]universe.Root, len(rootNodeIDs))
	for idx, id := range rootNodeIDs {
		root, ok := r.universeRoots[id]
		if !ok {
			// This should never happen, the two maps should be in
			// sync.
			log.Errorf("Root key %x found in cache list but not "+
				"in map", id[:])
			r.Miss()

			return nil, false
		}

		rootNodes[idx] = root
	}

	// This was a cache hit.
	r.Hit()

	return rootNodes, false
}

// fetchRoot reads the cached root for the given ID.
func (r *syncerRootNodeCache) fetchRoot(id universe.Identifier,
	haveWriteLock bool) *universe.Root {

	if !r.enabled {
		return nil
	}

	// If we've acquired the write lock because we're doing a last lookup
	// before potentially populating the cache, we don't need to acquire the
	// read lock. If we're just normally reading from the cache, we'll need
	// to acquire the read lock.
	if !haveWriteLock {
		r.RLock()
		defer r.RUnlock()
	}

	root, ok := r.universeRoots[id.Key()]
	if !ok {
		r.Miss()

		return nil
	}

	r.Hit()
	return &root
}

// sortKeys sorts the universe key list.
//
// NOTE: This method must be called while holding the syncer cache lock.
func (r *syncerRootNodeCache) sortKeys() {
	// To make sure we can easily add and remove entries, we sort the
	// universe list by the key. This order will be different from the
	// database order, but that's fine.
	sort.Slice(r.universeKeyList, func(i, j int) bool {
		return bytes.Compare(
			r.universeKeyList[i][:], r.universeKeyList[j][:],
		) < 0
	})
}

// replaceCache replaces the cache with the given roots.
//
// NOTE: This method must be called while holding the syncer cache lock.
func (r *syncerRootNodeCache) replaceCache(newRoots []universe.Root) {
	if !r.enabled {
		return
	}

	r.universeKeyList = make([]universe.IdentifierKey, len(newRoots))
	for idx, root := range newRoots {
		r.universeKeyList[idx] = root.ID.Key()
		r.universeRoots[root.ID.Key()] = root
	}

	r.sortKeys()
}

// addOrReplace adds a single root to the cache if it isn't already present or
// replaces the existing value if it is.
func (r *syncerRootNodeCache) addOrReplace(root universe.Root) {
	if !r.enabled {
		return
	}

	r.Lock()
	defer r.Unlock()

	if _, ok := r.universeRoots[root.ID.Key()]; ok {
		// If the root is already in the cache, we'll just replace it in
		// the map. The key list doesn't need to be updated, as the key
		// never changes.
		r.universeRoots[root.ID.Key()] = root

		return
	}

	r.universeKeyList = append(r.universeKeyList, root.ID.Key())
	r.universeRoots[root.ID.Key()] = root

	r.sortKeys()
}

// remove removes a single root from the cache.
func (r *syncerRootNodeCache) remove(key universe.IdentifierKey) {
	if !r.enabled {
		return
	}

	r.Lock()
	defer r.Unlock()

	idx := sort.Search(len(r.universeKeyList), func(i int) bool {
		return bytes.Compare(r.universeKeyList[i][:], key[:]) >= 0
	})
	if idx < len(r.universeKeyList) && r.universeKeyList[idx] == key {
		// Remove the entry from the list.
		r.universeKeyList = slices.Delete(r.universeKeyList, idx, idx+1)

		// Remove the entry from the map.
		delete(r.universeRoots, key)
	}
}

// isEmpty returns true if the cache is empty.
func (r *syncerRootNodeCache) isEmpty() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.universeKeyList) == 0
}

// rootNodeCache is used to cache the set of active root nodes for the
// multiverse tree.
type rootNodeCache struct {
	sync.RWMutex

	cacheSize uint64

	rootIndex *rootIndex

	allRoots *rootPageCache

	*cacheLogger

	// TODO(roasbeef): cache for issuance vs transfer roots?
}

// newRootNodeCache creates a new root node cache.
func newRootNodeCache(cacheSize uint64) *rootNodeCache {
	return &rootNodeCache{
		cacheSize:   cacheSize,
		rootIndex:   newRootIndex(),
		allRoots:    newRootPageCache(cacheSize),
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
		rootIndex.Store(rootNode.ID.String(), &rootNode)
	}
}

// wipeCache wipes all the cached roots.
func (r *rootNodeCache) wipeCache() {
	log.Debugf("wiping universe cache")

	r.allRoots.wipe(r.cacheSize)
	r.rootIndex.wipe()
}

// cachedLeafKeys is used to cache the set of leaf keys for a given universe.
type cachedLeafKeys []universe.LeafKey

// Size just returns 1, as we cache based on the total number of assets, but
// not the sum of their leaves.
func (c cachedLeafKeys) Size() (uint64, error) {
	return uint64(1), nil
}

// leafQueryKey is a wrapper around the existing UniverseLeafKeysQuery struct
// that doesn't include a pointer so it can be safely used as a map key.
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

	leavesPerUniverse uint64

	leafCache *lru.Cache[universeIDKey, *leafPageCache]

	*cacheLogger
}

// newUniverseLeafPageCache creates a new universe leaf cache.
func newUniverseLeafPageCache(numCachedUniverses,
	leavesPerUniverse uint64) *universeLeafPageCache {

	return &universeLeafPageCache{
		leavesPerUniverse: leavesPerUniverse,
		leafCache: lru.NewCache[universeIDKey, *leafPageCache](
			numCachedUniverses,
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
				u.leavesPerUniverse,
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
	log.Debugf("wiping leaf keys for %s in cache", id)

	u.leafCache.Delete(id)
}
