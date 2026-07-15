package tapdb

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/dustin/go-humanize"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/universe"
)

const (
	// defaultMaxProofCacheSize is the default maximum size of the proof
	// cache expressed as a human-readable string type so that we can
	// present it directly to CLI users.
	defaultMaxProofCacheSize = "32MB"
)

// MultiverseCacheConfig is the configuration for the different multiverse
// caches that exist.
//
//nolint:lll
type MultiverseCacheConfig struct {
	// MaxProofCacheSize is the maximum size of the proof cache expressed
	// as a human-readable string, for example, "32MB" or "1GB".
	MaxProofCacheSize string `long:"max-proof-cache-size" description:"The maximum total size of the cached proofs. Accepts human readable values such as 32MB or 1GB."`

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
		MaxProofCacheSize:        defaultMaxProofCacheSize,
		LeavesNumCachedUniverses: 2_000,
		LeavesPerUniverse:        50,
		SyncerCacheEnabled:       false,
		SyncerCachePreAllocSize:  100_000,
		RootNodePageCacheSize:    20 * universe.RequestPageSize,
	}
}

// maxProofCacheSizeBytes returns the parsed byte representation of the proof
// cache size limit.
func (c MultiverseCacheConfig) maxProofCacheSizeBytes() (uint64, error) {
	sizeStr := c.MaxProofCacheSize
	if sizeStr == "" {
		sizeStr = defaultMaxProofCacheSize
	}

	sizeBytes, err := humanize.ParseBytes(sizeStr)
	if err != nil {
		return 0, fmt.Errorf("parse max proof cache size: %w", err)
	}

	return sizeBytes, nil
}

// cachedProofs is a list of cached proof leaves.
type cachedProofs struct {
	// proofs is the list of cached proofs.
	proofs []*universe.Proof

	// proofSizeCache is a map of proof universe key to the size of the
	// proof in bytes.
	proofSizeCache map[[32]byte]uint64
}

// newCachedProofs creates a new cached proofs list.
func newCachedProofs(proofs []*universe.Proof) cachedProofs {
	return cachedProofs{
		proofs:         proofs,
		proofSizeCache: make(map[[32]byte]uint64, len(proofs)),
	}
}

// Size returns the total byte size of all cached proofs.
func (c *cachedProofs) Size() (uint64, error) {
	if c == nil {
		return 0, nil
	}

	totalBytes := uint64(0)
	for _, proof := range c.proofs {
		if proof == nil {
			continue
		}

		// Look up the cached size for this proof. If absent, compute
		// the lower-bound size and cache it under the proof’s universe
		// key.
		universeKey := proof.LeafKey.UniverseKey()
		size, ok := c.proofSizeCache[universeKey]
		if !ok {
			size = proof.LowerBoundByteSize()
			c.proofSizeCache[universeKey] = size
		}

		totalBytes += size
	}

	return totalBytes, nil
}

// newProofCache creates a new leaf proof cache.
//
// nolint: lll
func newProofCache(totalCacheBytesSize uint64,
	onDelete lru.OnDeleteCallback[UniverseProofKey, *cachedProofs],
) *lru.Cache[UniverseProofKey, *cachedProofs] {

	return lru.NewCache[UniverseProofKey, *cachedProofs](
		totalCacheBytesSize,
		lru.WithDeleteCallback(onDelete),
	)
}

// universeIDKey is a cache key used to uniquely identify a universe within a
// multiverse tree cache.
type universeIDKey = string

// UniverseProofKey houses the components of a universe proof key. All fields
// must be comparable.
type UniverseProofKey struct {
	// uniIDKey is the universe ID key to which the proof belongs.
	uniIDKey universe.IdentifierKey

	// leafKey is the leaf key of the proof.
	leafKeyBytes [32]byte
}

// NewUniverseProofKey creates a new universe proof key.
func NewUniverseProofKey(uniID universe.Identifier,
	leafKey universe.LeafKey) UniverseProofKey {

	return UniverseProofKey{
		uniIDKey:     uniID.Key(),
		leafKeyBytes: leafKey.UniverseKey(),
	}
}

// universeProofCache a map of proof caches for each proof type.
type universeProofCache struct {
	// maxCacheByteSize is the maximum size of the cache in bytes.
	maxCacheByteSize uint64

	// writeMu serializes all write paths (insertProofs,
	// RemoveLeafKeyProofs, RemoveUniverseProofs) so that the LRU and
	// the byID secondary index stay coherent. The LRU's delete
	// callback runs synchronously during the cache op that triggered
	// it, on the same goroutine, so the callback inherits this lock
	// and can mutate byID without taking it itself. Read paths
	// (fetchProof) do not take writeMu.
	writeMu sync.Mutex

	// byID maps a universe id key to the set of leaf-key suffixes
	// that are currently cached under that id. It is the secondary
	// index that makes RemoveUniverseProofs O(k) in the number of
	// cached leaves for the affected universe rather than O(N) in
	// the total cache size.
	byID map[universe.IdentifierKey]map[[32]byte]struct{}

	// cache is the LRU cache for the proofs themselves.
	cache *lru.Cache[UniverseProofKey, *cachedProofs]

	*cacheLogger
}

// newUniverseProofCache creates a new proof cache.
func newUniverseProofCache(maxCacheByteSize uint64) *universeProofCache {
	p := &universeProofCache{
		maxCacheByteSize: maxCacheByteSize,
		byID: make(
			map[universe.IdentifierKey]map[[32]byte]struct{},
		),
	}

	// onDelete keeps the byID secondary index in sync with the LRU.
	// It is invoked by the LRU for both explicit deletes and
	// capacity evictions, synchronously on the caller's goroutine.
	// Every write path holds writeMu before calling cache.Put or
	// cache.Delete, so this callback never needs to lock byID
	// itself.
	onDelete := func(key UniverseProofKey, _ *cachedProofs) {
		set, ok := p.byID[key.uniIDKey]
		if !ok {
			return
		}

		delete(set, key.leafKeyBytes)
		if len(set) == 0 {
			delete(p.byID, key.uniIDKey)
		}
	}

	p.cache = newProofCache(maxCacheByteSize, onDelete)

	// Formulate a callback function that returns the cache size in a
	// human-readable format. This will be called by the cache logger to get
	// the current cache size.
	cacheSizeLogStr := func() string {
		return humanize.Bytes(p.cache.Size())
	}
	p.cacheLogger = newCacheLogger(
		"universe_proofs", withCacheSizeFunc(cacheSizeLogStr),
	)

	return p
}

// fetchProof reads the cached proof for the given ID and leaf key.
func (p *universeProofCache) fetchProof(id universe.Identifier,
	leafKey universe.LeafKey) []*universe.Proof {

	uniProofKey := NewUniverseProofKey(id, leafKey)
	proofFromCache, err := p.cache.Get(uniProofKey)
	if err == nil {
		p.Hit()
		return proofFromCache.proofs
	}

	p.Miss()

	return nil
}

// insertProofs inserts the given proofs into the cache.
func (p *universeProofCache) insertProofs(id universe.Identifier,
	leafKey universe.LeafKey, proofs []*universe.Proof) {

	uniProofKey := NewUniverseProofKey(id, leafKey)

	log.Debugf("Storing proof(s) in cache (universe_id=%v, leaf_key=%v, "+
		"count=%d)", id.StringForLog(), leafKey, len(proofs))

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	proofVal := newCachedProofs(proofs)
	if _, err := p.cache.Put(uniProofKey, &proofVal); err != nil {
		log.Errorf("Unable to insert proof into universe proof "+
			"cache: %v", err)
		return
	}

	// Record the new entry in the secondary index. cache.Put above
	// may have evicted older entries to make room; their onDelete
	// callbacks ran synchronously under writeMu and already pruned
	// byID, so the only mutation we need to make here is for the
	// key we just inserted.
	set, ok := p.byID[uniProofKey.uniIDKey]
	if !ok {
		set = make(map[[32]byte]struct{})
		p.byID[uniProofKey.uniIDKey] = set
	}
	set[uniProofKey.leafKeyBytes] = struct{}{}
}

// RemoveUniverseProofs deletes all the proofs for the given universe ID.
func (p *universeProofCache) RemoveUniverseProofs(id universe.Identifier) {
	log.Debugf("Removing universe proofs (universe_id=%s)",
		id.StringForLog())

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	targetIDKey := id.Key()
	set, ok := p.byID[targetIDKey]
	if !ok {
		return
	}

	// Snapshot the leaf keys before deleting, since each cache.Delete
	// fires the onDelete callback which mutates byID[targetIDKey];
	// iterating the map directly while it's being modified would be
	// unsafe.
	leafKeys := make([][32]byte, 0, len(set))
	for lk := range set {
		leafKeys = append(leafKeys, lk)
	}

	for _, lk := range leafKeys {
		p.cache.Delete(UniverseProofKey{
			uniIDKey:     targetIDKey,
			leafKeyBytes: lk,
		})
	}
}

// RemoveLeafKeyProofs deletes all the proofs for the given universe ID and leaf
// key.
func (p *universeProofCache) RemoveLeafKeyProofs(id universe.Identifier,
	leafKey universe.LeafKey) {

	log.Debugf("Removing leaf key proofs (universe_id=%s, leaf_key=%v)",
		id.StringForLog(), leafKey)

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	targetCacheKey := NewUniverseProofKey(id, leafKey)
	p.cache.Delete(targetCacheKey)
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
			log.Errorf("Root key found in cache list but not "+
				"in map (key=%x)", id[:])
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

	allRoots *rootPageCache

	*cacheLogger

	// TODO(roasbeef): cache for issuance vs transfer roots?
}

// newRootNodeCache creates a new root node cache.
func newRootNodeCache(cacheSize uint64) *rootNodeCache {
	return &rootNodeCache{
		cacheSize:   cacheSize,
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
//
// NOTE: This method must be called while holding the rootNodeCache lock, so
// that the page installed here can't be made stale by a concurrent wipe or
// eviction running between the caller's database read and this call.
func (r *rootNodeCache) cacheRoots(q universe.RootNodesQuery,
	rootNodes []universe.Root) {

	log.Debugf("Caching root node (count=%v)", len(rootNodes))

	rootPageCache := r.allRoots.Load()
	_, err := rootPageCache.Put(newRootPageQuery(q), rootNodes)
	if err != nil {
		log.Errorf("unable to insert into root cache: %v", err)
	}
}

// wipeCache wipes all the cached roots.
func (r *rootNodeCache) wipeCache() {
	log.Debugf("Wiping universe root node cache")

	// The lock serializes us with the cache fill in RootNodes, which
	// holds it across both its database read and cacheRoots. Without it
	// we could wipe between the two, and the fill would then install a
	// page into the fresh cache that was read before the write that
	// triggered this wipe committed.
	r.Lock()
	defer r.Unlock()

	r.allRoots.wipe(r.cacheSize)
}

// handleRootUpdate updates the cached roots after a proof leaf was inserted
// into the universe identified by root.ID. Creating a new universe changes
// which roots appear on which page of paginated root queries, so the whole
// page cache is invalidated. Updating an existing universe only changes the
// value of a single, already placed root, so only the cached pages
// containing that root are evicted and all other pages stay warm.
func (r *rootNodeCache) handleRootUpdate(root universe.Root,
	status universeRootStatus) {

	switch status {
	case universeRootCreated:
		r.wipeCache()

	case universeRootUpdated:
		r.evictRoots([]universe.Root{root})
	}
}

// evictRoots removes all cached pages that contain any of the given universe
// roots. Pages are keyed by pagination parameters only and the backing query
// orders by the stable universe_roots.id column, so updating an existing
// universe never changes which page its root appears on. Cached pages that
// don't contain any of the roots therefore remain valid, and absence of a
// root from all cached pages means there is nothing to invalidate for it.
//
// The affected pages are evicted rather than patched with the new root
// value: eviction is idempotent, so concurrent updates of the same universe
// can apply in any order without ever leaving a value in the cache that is
// older than the database state. It also keeps query-derived fields honest:
// a grouped universe's asset name, for example, is frozen to its first
// member by the backing query and would diverge if we patched in the latest
// leaf's tag.
func (r *rootNodeCache) evictRoots(roots []universe.Root) {
	// The lock serializes us with the cache fill in RootNodes, which
	// holds it across both its database read and cacheRoots. Without it
	// we could evict between the two, and the fill would then install a
	// page that was read before our root update committed.
	r.Lock()
	defer r.Unlock()

	keys := make(map[universe.IdentifierKey]struct{}, len(roots))
	for _, root := range roots {
		keys[root.ID.Key()] = struct{}{}
	}

	rootPages := r.allRoots.Load()

	// We first collect the affected pages, as mutating the cache while
	// iterating over it isn't safe.
	var evicted []rootPageQueryKey
	rootPages.Range(func(key rootPageQueryKey,
		page universeRootPage) bool {

		stale := slices.ContainsFunc(
			page, func(cached universe.Root) bool {
				_, ok := keys[cached.ID.Key()]
				return ok
			},
		)
		if stale {
			evicted = append(evicted, key)
		}

		return true
	})

	for _, key := range evicted {
		rootPages.Delete(key)
	}
}

// cachedLeafKeys is used to cache the set of leaf entries for a
// given universe.
type cachedLeafKeys []universe.LeafEntry

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

// fetchLeafKeys reads the cached leaf entries for the given ID.
func (u *universeLeafPageCache) fetchLeafKeys(
	q universe.UniverseLeafKeysQuery) []universe.LeafEntry {

	leafPageCache, err := u.leafCache.Get(q.Id.String())
	if err == nil {
		leafKeys, err := leafPageCache.Get(newLeafQuery(q))
		if err == nil {
			u.Hit()
			log.Tracef("Read leaf keys from page cache "+
				"(universe_id=%v)", q.Id.StringForLog())
			return *leafKeys
		}
	}

	u.Miss()

	return nil
}

// cacheLeafKeys stores the given leaf entries in the cache.
func (u *universeLeafPageCache) cacheLeafKeys(q universe.UniverseLeafKeysQuery,
	keys []universe.LeafEntry) {

	cachedKeys := cachedLeafKeys(keys)

	idStr := q.Id.String()

	log.Debugf("Storing leaf key(s) in cache (universe_id=%v)",
		q.Id.StringForLog())

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
			log.Errorf("Unable to store entry in page cache: %v",
				err)
			return
		}
	}

	// Add the cached keys to the page cache.
	if _, err := pageCache.Put(newLeafQuery(q), &cachedKeys); err != nil {
		log.Errorf("Unable to store leaf resp: %v", err)
	}
}

// wipeCache wipes the cache of leaf keys for a given universe ID.
func (u *universeLeafPageCache) wipeCache(id universeIDKey) {
	log.Debugf("Wiping leaf keys from page cache (universe_id=%s)", id)

	u.leafCache.Delete(id)
}
