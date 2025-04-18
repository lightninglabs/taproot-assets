package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
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
	// BaseUniverseRoot is the type returned from the UniverseRoots query.
	BaseUniverseRoot = sqlc.UniverseRootsRow

	// UniverseRootsParams are the parameters for the UniverseRoots query.
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

// MultiverseStoreConfig is the set of configuration options for the multiverse
// store.
type MultiverseStoreConfig struct {
	// Caches is the set of cache configurations for the multiverse store.
	Caches MultiverseCacheConfig
}

// DefaultMultiverseStoreConfig returns the default configuration for the
// multiverse store.
func DefaultMultiverseStoreConfig() *MultiverseStoreConfig {
	return &MultiverseStoreConfig{
		Caches: DefaultMultiverseCacheConfig(),
	}
}

// MultiverseStore implements the persistent storage for a multiverse.
//
// NOTE: This implements the universe.MultiverseArchive interface.
type MultiverseStore struct {
	db BatchedMultiverse

	cfg *MultiverseStoreConfig

	syncerCache *syncerRootNodeCache

	rootNodeCache *rootNodeCache

	proofCache *universeProofCache

	leafKeysCache *universeLeafPageCache

	// transferProofDistributor is an event distributor that will be used to
	// notify subscribers about new proof leaves that are added to the
	// multiverse. This is used to notify the custodian about new incoming
	// proofs. And since the custodian is only interested in transfer
	// proofs, we only signal on transfer proofs.
	transferProofDistributor *fn.EventDistributor[proof.Blob]
}

// NewMultiverseStore creates a new multiverse DB store handle.
func NewMultiverseStore(db BatchedMultiverse,
	cfg *MultiverseStoreConfig) *MultiverseStore {

	return &MultiverseStore{
		db:  db,
		cfg: cfg,
		syncerCache: newSyncerRootNodeCache(
			cfg.Caches.SyncerCacheEnabled,
			cfg.Caches.SyncerCachePreAllocSize,
		),
		rootNodeCache: newRootNodeCache(
			cfg.Caches.RootNodePageCacheSize,
		),
		proofCache: newUniverseProofCache(
			cfg.Caches.ProofsPerUniverse,
		),
		leafKeysCache: newUniverseLeafPageCache(
			cfg.Caches.LeavesNumCachedUniverses,
			cfg.Caches.LeavesPerUniverse,
		),
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

	// For an individual universe root node, we always fetch it from the
	// syncer cache, as that should have all root nodes that are currently
	// known. We never update the syncer cache on a cache miss of a single
	// root node, as that shouldn't happen (unless the cache is empty).
	// This will always return nil if the cache is disabled, so we don't
	// need an extra indentation for that check here.
	rootNode := b.syncerCache.fetchRoot(id, false)
	if rootNode != nil {
		return *rootNode, nil
	}

	// If the cache is still empty, we'll populate it now, given it is
	// enabled.
	if b.syncerCache.isEmpty() && b.cfg.Caches.SyncerCacheEnabled {
		// We attempt to acquire the write lock to fill the cache. If
		// another goroutine is already filling the cache, we'll wait
		// for it to finish that way.
		b.syncerCache.Lock()
		defer b.syncerCache.Unlock()

		// Because another goroutine might have filled the cache while
		// we were waiting for the lock, we'll check again if the item
		// is now in the cache.
		rootNode = b.syncerCache.fetchRoot(id, true)
		if rootNode != nil {
			return *rootNode, nil
		}

		// Populate the cache with all the root nodes.
		err := b.fillSyncerCache(ctx)
		if err != nil {
			return universe.Root{}, fmt.Errorf("error filling "+
				"syncer cache: %w", err)
		}

		// We now try again to fetch the root node from the cache.
		rootNode = b.syncerCache.fetchRoot(id, true)
		if rootNode != nil {
			return *rootNode, nil
		}

		// Still no luck with the cache (this should really never
		// happen), so we'll go to the secondary cache or the disk to
		// fetch it.
		log.Warnf("Fetching root node from disk for id %v, cache miss "+
			"even after filling the cache", id)
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

	// The leaves weren't populated, so we'll go to disk to fetch it.
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

	// Is this a query for the syncer cache (ascending and
	// WithAmountsById=false)? This cache is complete (all root nodes) and
	// can be directly sliced into, but it doesn't have any amounts by ID
	// and doesn't support descending order.
	if isQueryForSyncerCache(q) && b.cfg.Caches.SyncerCacheEnabled {
		// First, check to see if we have the root nodes cached in the
		// syncer cache.
		rootNodes, emptyPage := b.syncerCache.fetchRoots(q, false)
		if len(rootNodes) > 0 || emptyPage {
			return rootNodes, nil
		}

		// If the cache is still empty, we'll populate it now.
		if b.syncerCache.isEmpty() {
			// We attempt to acquire the write lock to fill the
			// cache. If another goroutine is already filling the
			// cache, we'll wait for it to finish that way.
			b.syncerCache.Lock()
			defer b.syncerCache.Unlock()

			// Because another goroutine might have filled the cache
			// while we were waiting for the lock, we'll check again
			// if the item is now in the cache.
			rootNodes, emptyPage = b.syncerCache.fetchRoots(q, true)
			if len(rootNodes) > 0 || emptyPage {
				return rootNodes, nil
			}

			// Populate the cache with all the root nodes.
			err := b.fillSyncerCache(ctx)
			if err != nil {
				return nil, fmt.Errorf("error filling syncer "+
					"cache: %w", err)
			}

			// We now try again to fetch the root nodes page from
			// the cache.
			rootNodes, emptyPage = b.syncerCache.fetchRoots(q, true)
			if len(rootNodes) > 0 || emptyPage {
				return rootNodes, nil
			}

			// Still no luck with the cache (this should really
			// never happen), so we'll go to the secondary cache or
			// disk to fetch it.
			log.Warnf("Fetching root nodes page from disk for "+
				"query %v, cache miss even after filling the "+
				"cache", q)
		}
	}

	// Attempt to read directly from the root node cache next. This
	// secondary cache only contains the last few pages of root nodes that
	// were queried with parameters the syncer doesn't use. This might serve
	// some UI requests where the first few pages are queried multiple
	// times, so an LRU based cache that's smaller makes sense..
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

	params := sqlc.UniverseRootsParams{
		SortDirection: sqlInt16(q.SortDirection),
		NumOffset:     q.Offset,
		NumLimit: func() int32 {
			if q.Limit == 0 {
				return universe.RequestPageSize
			}

			return q.Limit
		}(),
	}
	uniRoots, err := b.queryRootNodes(ctx, params, q.WithAmountsById)
	if err != nil {
		return nil, err
	}

	log.Debugf("Populating %v root nodes into cache, took=%v",
		len(uniRoots), time.Since(now))

	// Cache all the root nodes we just read from the database.
	b.rootNodeCache.cacheRoots(q, uniRoots)

	return uniRoots, nil
}

// queryRootNodes returns the set of root nodes for the given query parameters.
func (b *MultiverseStore) queryRootNodes(ctx context.Context,
	params sqlc.UniverseRootsParams,
	withAmountsByID bool) ([]universe.Root, error) {

	var (
		uniRoots []universe.Root
		readTx   = NewBaseMultiverseReadTx()
	)
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
				dbRoot.ProofType.String,
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
			if dbRoot.GroupKey != nil && withAmountsByID {
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
			} else if withAmountsByID {
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

	return uniRoots, nil
}

// fillSyncerCache populates the syncer cache with all the root nodes that are
// currently known. This is used to quickly serve the syncer with the root nodes
// it needs to sync the multiverse.
//
// NOTE: This method must be called while holding the syncer cache lock.
func (b *MultiverseStore) fillSyncerCache(ctx context.Context) error {
	now := time.Now()
	log.Infof("Populating syncer root cache...")

	params := sqlc.UniverseRootsParams{
		SortDirection: sqlInt16(universe.SortAscending),
		NumOffset:     0,
		NumLimit:      universe.RequestPageSize,
	}

	allRoots := make(
		[]universe.Root, 0, b.cfg.Caches.SyncerCachePreAllocSize,
	)
	for {
		newRoots, err := b.queryRootNodes(ctx, params, false)
		if err != nil {
			return err
		}

		allRoots = append(allRoots, newRoots...)
		params.NumOffset += universe.RequestPageSize

		if len(newRoots) < universe.RequestPageSize {
			break
		}
	}

	log.Debugf("Populating %v root nodes into syncer cache, took=%v",
		len(allRoots), time.Since(now))

	b.syncerCache.replaceCache(allRoots)

	return nil
}

// FetchProofLeaf returns a proof leaf for the target key. If the key doesn't
// have a script key specified, then all the proof leafs for the outpoint will
// be returned. If neither are specified, then all inserted proof
// leafs will be returned.
func (b *MultiverseStore) FetchProofLeaf(ctx context.Context,
	id universe.Identifier,
	universeKey universe.LeafKey) ([]*universe.Proof, error) {

	// First, check the cached to see if we already have this proof.
	proofsFromCache := b.proofCache.fetchProof(id, universeKey)
	if len(proofsFromCache) > 0 {
		return proofsFromCache, nil
	}

	var (
		readTx = NewBaseUniverseReadTx()
		proofs []*universe.Proof
	)

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	dbErr := b.db.ExecTx(ctx, &readTx, func(tx BaseMultiverseStore) error {
		var err error
		proofs, err = universeFetchProofLeaf(ctx, id, universeKey, tx)
		if err != nil {
			return err
		}

		// Populate multiverse specific fields of proofs.
		//
		// Retrieve a handle to the multiverse MS-SMT tree.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(tx, multiverseNS),
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

			//nolint:lll
			proofs[i].MultiverseInclusionProof = multiverseInclusionProof
		}

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// Insert the proofs we just read up into the main cache.
	b.proofCache.insertProofs(id, universeKey, proofs)

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
		leafKey := universe.BaseLeafKey{
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
	id universe.Identifier, key universe.LeafKey, leaf *universe.Leaf,
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
			ctx, dbTx, id, key, leaf, metaReveal, false,
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

	// Invalidate the cache since we just updated the root.
	b.rootNodeCache.wipeCache()
	b.proofCache.delProofsForAsset(id)
	b.leafKeysCache.wipeCache(id.String())
	b.syncerCache.addOrReplace(universe.Root{
		ID:        id,
		AssetName: leaf.Asset.Tag,
		Node:      issuanceProof.UniverseRoot,
	})

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
		dbTx BaseMultiverseStore) (*universe.Proof, error) {

		// Upsert proof leaf into the asset (group) specific universe
		// tree.
		return universeUpsertProofLeaf(
			ctx, dbTx, item.ID, item.Key, item.Leaf,
			item.MetaReveal, false,
		)
	}

	var (
		writeTx   BaseMultiverseOptions
		uniProofs []*universe.Proof
	)
	dbErr := b.db.ExecTx(
		ctx, &writeTx, func(store BaseMultiverseStore) error {
			uniProofs = make([]*universe.Proof, len(items))
			for idx := range items {
				item := items[idx]
				uniProof, err := insertProof(item, store)
				if err != nil {
					return err
				}

				uniProofs[idx] = uniProof
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

		// Update the syncer cache with the new root node.
		b.syncerCache.addOrReplace(universe.Root{
			ID:        items[idx].ID,
			AssetName: items[idx].Leaf.Asset.Tag,
			Node:      uniProofs[idx].UniverseRoot,
		})
	}

	// Invalidate the root node cache for all the assets we just inserted.
	idsToDelete := fn.NewSet(
		fn.Map(items, func(item *universe.Item) universeIDKey {
			return item.ID.String()
		})...,
	)

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

	dbErr := b.db.ExecTx(ctx, &writeTx, func(tx BaseMultiverseStore) error {
		multiverseNS, err := namespaceForProof(id.ProofType)
		if err != nil {
			return err
		}

		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(tx, multiverseNS),
		)

		multiverseLeafKey := id.Bytes()
		_, err = multiverseTree.Delete(ctx, multiverseLeafKey)
		if err != nil {
			return err
		}

		return deleteUniverseTree(ctx, tx, id)
	})
	if dbErr != nil {
		return "", dbErr
	}

	// Wipe the cache items from this node.
	b.rootNodeCache.wipeCache()

	b.proofCache.Delete(id.String())
	b.leafKeysCache.wipeCache(id.String())
	b.syncerCache.remove(id.Key())

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
		key := universe.BaseLeafKey{
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
