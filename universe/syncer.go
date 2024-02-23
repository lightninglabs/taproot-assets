package universe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"golang.org/x/sync/errgroup"
)

const (
	defaultPageSize = int32(MaxPageSize)
)

var (
	// ErrUnsupportedSync is returned when a syncer is asked to async in a
	// way that it does not support.
	ErrUnsupportedSync = fmt.Errorf("unsupported sync type")
)

// SimpleSyncCfg contains all the configuration needed to create a new
// SimpleSyncer.
type SimpleSyncCfg struct {
	// LocalDiffEngine is the diff engine tied to a local Universe
	// instance.
	LocalDiffEngine DiffEngine

	// NewRemoteDiffEngine is a function that returns a new diff engine
	// tied to the remote Universe instance we want to sync with.
	NewRemoteDiffEngine func(ServerAddr) (DiffEngine, error)

	// LocalRegistrar is the registrar tied to a local Universe instance.
	// This is used to insert new proof into the local DB as a result of
	// the diff operation.
	LocalRegistrar BatchRegistrar

	// SyncBatchSize is the number of items to sync in a single batch.
	SyncBatchSize int
}

// SimpleSyncer is a simple implementation of the Syncer interface. It's based
// on a set difference operation between the local and remote Universe.
type SimpleSyncer struct {
	cfg SimpleSyncCfg

	// isSyncing keeps track of whether we're currently syncing the local
	// Universe with a remote Universe. This is used to prevent concurrent
	// syncs.
	isSyncing atomic.Bool
}

// NewSimpleSyncer creates a new SimpleSyncer instance.
func NewSimpleSyncer(cfg SimpleSyncCfg) *SimpleSyncer {
	return &SimpleSyncer{
		cfg: cfg,
	}
}

// executeSync attempts to sync the local Universe with the remote diff engine.
// A simple approach where a set difference is used to find the set of assets
// that need to be synced is used.
func (s *SimpleSyncer) executeSync(ctx context.Context, diffEngine DiffEngine,
	syncType SyncType, syncConfigs SyncConfigs,
	idsToSync []Identifier) ([]AssetSyncDiff, error) {

	// Prevent the syncer from running twice.
	if !s.isSyncing.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("sync is already in progress, please " +
			"wait for it to finish")
	}

	defer func() {
		s.isSyncing.Store(false)
	}()

	// Examine config to ascertain whether global insertion for either proof
	// type is allowed.
	globalInsertEnabled := fn.Any(
		syncConfigs.GlobalSyncConfigs,
		func(config *FedGlobalSyncConfig) bool {
			return config.AllowSyncInsert
		},
	)

	// Define a custom filter function that will be used to filter for
	// Universes that we want to sync. This filter makes use of the
	// given syncType.
	uniIdSyncFilter := func(id Identifier) bool {
		// If we're syncing issuance proofs, then the universe must
		// relate to issuance proofs.
		if syncType == SyncIssuance &&
			id.ProofType != ProofTypeIssuance {

			return false
		}

		return syncConfigs.IsSyncInsertEnabled(id)
	}

	var (
		targetRoots []Root
		err         error
	)
	switch {
	// If we have been given a specific set of Universes to sync, then we'll
	// only fetch roots for those universes. We wont filter out any
	// Universes here as we assume that the caller has already done so.
	case len(idsToSync) != 0:
		targetRoots, err = fetchRootsForIDs(ctx, idsToSync, diffEngine)
		if err != nil {
			return nil, err
		}

	// If global insert is enabled we'll just fetch all the roots from the
	// remote servers.
	case globalInsertEnabled:
		log.Infof("Fetching all roots for remote Universe server...")

		targetRoots, err = s.fetchAllRoots(ctx, diffEngine)
		if err != nil {
			return nil, err
		}

		// Examine universe IDs of returned roots and filter out
		// universes that we don't want to sync.
		targetRoots = fn.Filter(
			targetRoots, func(r Root) bool {
				return uniIdSyncFilter(r.ID)
			},
		)

	// At this point, we know that global insert is disabled, and we don't
	// have any specific Universes to sync. We will therefore fetch roots
	// for all universes which have corresponding and enabled specific sync
	// configs.
	default:
		var uniIDs []Identifier

		for _, uniSyncCfg := range syncConfigs.UniSyncConfigs {
			// Check with the filter to ensure that the universe is
			// applicable for syncing. If not, we would have
			// retrieved the corresponding root in vain.
			if uniIdSyncFilter(uniSyncCfg.UniverseID) {
				uniIDs = append(
					uniIDs, uniSyncCfg.UniverseID,
				)
			}
		}

		// Retrieve roots for the gathered set of universes.
		targetRoots, err = fetchRootsForIDs(ctx, uniIDs, diffEngine)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("Obtained %v roots from remote Universe server",
		len(targetRoots))

	// Now that we know the set of Universes we need to sync, we'll execute
	// the diff operation for each of them.
	syncDiffs := make(chan AssetSyncDiff, len(targetRoots))
	err = fn.ParSlice(
		ctx, targetRoots, func(ctx context.Context, r Root) error {
			return s.syncRoot(ctx, r, diffEngine, syncDiffs)
		},
	)
	if err != nil {
		return nil, err
	}

	// Finally, we'll collect all the diffs and return them to the caller.
	return fn.Collect(syncDiffs), nil
}

// fetchRootsForIDs fetches the roots for a specific set of universe IDs.
func fetchRootsForIDs(ctx context.Context, idsToSync []Identifier,
	diffEngine DiffEngine) ([]Root, error) {

	log.Infof("Fetching %v roots", len(idsToSync))
	log.Tracef("Fetching %v roots for IDs: %v", len(idsToSync),
		spew.Sdump(idsToSync))

	// We'll use an error group to fetch each Universe root we need
	// as a series of parallel requests backed by a worker pool.
	rootsToSync := make(chan Root, len(idsToSync))
	err := fn.ParSlice(
		ctx, idsToSync,
		func(ctx context.Context, id Identifier) error {
			root, err := diffEngine.RootNode(ctx, id)
			if err != nil {
				return err
			}

			rootsToSync <- root
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch roots for "+
			"universe sync: %w", err)
	}

	return fn.Collect(rootsToSync), nil
}

// syncRoot attempts to sync the local Universe with the remote diff engine for
// a specific base root.
func (s *SimpleSyncer) syncRoot(ctx context.Context, remoteRoot Root,
	diffEngine DiffEngine, result chan<- AssetSyncDiff) error {

	// First, we'll compare the remote root against the local root.
	uniID := remoteRoot.ID
	localRoot, err := s.cfg.LocalDiffEngine.RootNode(ctx, uniID)
	switch {
	// If we don't have this root, then we don't have anything to compare
	// to, so we'll proceed as normal.
	case errors.Is(err, ErrNoUniverseRoot):
		// TODO(roasbeef): abstraction leak, error should be in
		// universe package

	// If the local root matches the remote root, then we're done here.
	case err == nil && mssmt.IsEqualNode(localRoot, remoteRoot):
		log.Debugf("Root for %v matches, no sync needed",
			uniID.String())

		return nil

	case err != nil:
		return fmt.Errorf("unable to fetch local root: %w", err)
	}

	log.Infof("UniverseRoot(%v) diverges, performing leaf diff...",
		uniID.String())

	// Otherwise, we'll need to perform a diff operation to find the set of
	// keys we need to fetch. We'll start by fetching the set of keys from
	// both the local and remote Universe.
	var (
		remoteUniKeys []LeafKey
		localUniKeys  []LeafKey
	)

	remoteUniKeys, err = s.fetchAllLeafKeys(ctx, diffEngine, uniID)
	if err != nil {
		return err
	}

	localUniKeys, err = s.fetchAllLeafKeys(ctx, s.cfg.LocalDiffEngine, uniID)
	if err != nil {
		return err
	}

	// With the set of keys fetched, we can now find the set of keys that
	// need to be synced.
	keysToFetch := fn.SetDiff(remoteUniKeys, localUniKeys)

	log.Infof("UniverseRoot(%v): diff_size=%v", uniID.String(),
		len(keysToFetch))
	log.Tracef("UniverseRoot(%v): diff_size=%v, diff=%v", uniID.String(),
		len(keysToFetch), spew.Sdump(keysToFetch))

	// Before we start fetching leaves, we already start our batch stream
	// for the new leaves. This allows us to stream the new leaves to the
	// local registrar as they're fetched.
	var (
		fetchedLeaves = make(chan *Item, len(keysToFetch))
		newLeafProofs []*Leaf
		batchSyncEG   errgroup.Group
	)

	// We use an error group to simply the error handling of a goroutine.
	// This goroutine will handle reading in batches of new leaves to
	// insert into the DB. We'll fee the output of the goroutines below
	// into the input fetchedLeaves channel.
	batchSyncEG.Go(func() error {
		newLeafProofs, err = s.batchStreamNewItems(
			ctx, uniID, fetchedLeaves, len(keysToFetch),
		)
		return err
	})

	// If this is a transfer tree, then we'll use these channels to sort
	// the contents before sending to the batch writer.
	isIssuanceTree := remoteRoot.ID.ProofType == ProofTypeIssuance
	transferLeafProofs := make(chan *Item, len(keysToFetch))

	// Now that we know where the divergence is, we can fetch the issuance
	// proofs from the remote party.
	err = fn.ParSlice(
		ctx, keysToFetch, func(ctx context.Context, key LeafKey) error {
			newProof, err := diffEngine.FetchProofLeaf(
				ctx, uniID, key,
			)
			if err != nil {
				return err
			}

			leafProof := newProof[0]

			// Now that we have this leaf proof, we want to ensure
			// that it's actually part of the remote root we were
			// given.
			validRoot := leafProof.VerifyRoot(remoteRoot)
			if !validRoot {
				return fmt.Errorf("proof for key=%v is "+
					"invalid", spew.Sdump(key))
			}

			// If this is an issuance proof, then we can send
			// things directly to the batch insertion goroutine.
			// Otherwise, we'll another step to the pipeline below
			// for sorting.
			if isIssuanceTree {
				fetchedLeaves <- &Item{
					ID:   uniID,
					Key:  key,
					Leaf: leafProof.Leaf,
				}
			} else {
				transferLeafProofs <- &Item{
					ID:   uniID,
					Key:  key,
					Leaf: leafProof.Leaf,
				}
			}

			return nil
		})
	if err != nil {
		return err
	}

	// If this is a transfer tree, then we'll collect all the items as we
	// need to sort them to ensure we can validate them in dep order.
	if !isIssuanceTree {
		transferLeaves := fn.Collect(transferLeafProofs)
		sort.Slice(transferLeaves, func(i, j int) bool {
			// We'll need to decode the block heights from the
			// proof, so we'll make a record to do so.
			var iBlockHeight, jBlockHeight uint32

			iRecord := proof.BlockHeightRecord(&iBlockHeight)
			jRecord := proof.BlockHeightRecord(&jBlockHeight)

			_ = proof.SparseDecode(
				//nolint:lll
				bytes.NewReader(transferLeaves[i].Leaf.RawProof),
				iRecord,
			)

			_ = proof.SparseDecode(
				//nolint:lll
				bytes.NewReader(transferLeaves[j].Leaf.RawProof),
				jRecord,
			)

			return iBlockHeight < jBlockHeight
		})

		fn.SendAll(fetchedLeaves, transferLeaves...)
	}

	// And now we wait for the batch streamer to finish as well.
	close(fetchedLeaves)
	err = batchSyncEG.Wait()
	if err != nil {
		return err
	}

	log.Infof("Universe sync for UniverseRoot(%v) complete, %d "+
		"new leaves inserted", uniID.String(), len(keysToFetch))

	// TODO(roabseef): sanity check local and remote roots match now?

	// To wrap up, we'll collect the set of leaves then convert them into a
	// final sync diff.
	result <- AssetSyncDiff{
		OldUniverseRoot: localRoot,
		NewUniverseRoot: remoteRoot,
		NewLeafProofs:   newLeafProofs,
	}

	log.Infof("Sync for UniverseRoot(%v) complete!", uniID.String())
	log.Tracef("Sync for UniverseRoot(%v) complete! New "+
		"universe_root=%v", uniID.String(), spew.Sdump(remoteRoot))

	return nil
}

// batchStreamNewItems streams the set of new items to the local registrar in
// batches and returns the new leaf proofs.
func (s *SimpleSyncer) batchStreamNewItems(ctx context.Context,
	uniID Identifier, fetchedLeaves chan *Item,
	numTotal int) ([]*Leaf, error) {

	var (
		numItems      int
		newLeafProofs []*Leaf
	)
	err := fn.CollectBatch(
		ctx, fetchedLeaves, s.cfg.SyncBatchSize,
		func(ctx context.Context, batch []*Item) error {
			numItems += len(batch)

			log.Debugf("UniverseRoot(%v): Inserting %d new leaves "+
				"(%d of %d)", uniID.String(), len(batch),
				numItems, numTotal)

			err := s.cfg.LocalRegistrar.UpsertProofLeafBatch(
				ctx, batch,
			)
			if err != nil {
				return fmt.Errorf("unable to register "+
					"proofs: %w", err)
			}

			if len(batch) > 0 {
				log.Infof("UniverseRoot(%v): Inserted %d new "+
					"leaves (%d of %d)", uniID.String(),
					len(batch), numItems, numTotal)
			}

			newLeaves := fn.Map(
				batch, func(i *Item) *Leaf {
					return i.Leaf
				},
			)
			newLeafProofs = append(newLeafProofs, newLeaves...)

			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register proofs: %w", err)
	}

	return newLeafProofs, nil
}

// SyncUniverse attempts to synchronize the local universe with the remote
// universe, governed by the sync type and the set of universe IDs to sync.
func (s *SimpleSyncer) SyncUniverse(ctx context.Context, host ServerAddr,
	syncType SyncType, syncConfigs SyncConfigs,
	idsToSync ...Identifier) ([]AssetSyncDiff, error) {

	log.Infof("Attempting to sync universe: host=%v, sync_type=%v, ids=%v",
		host.HostStr(), syncType, spew.Sdump(idsToSync))

	// Next, we'll attempt to create a new diff engine for the remote
	// Universe.
	diffEngine, err := s.cfg.NewRemoteDiffEngine(host)
	if err != nil {
		return nil, fmt.Errorf("unable to create remote diff "+
			"engine: %w", err)
	}
	defer diffEngine.Close()

	// With the engine created, we can now sync the local Universe with the
	// remote instance.
	return s.executeSync(ctx, diffEngine, syncType, syncConfigs, idsToSync)
}

// fetchAllRoots fetches all the roots from the remote Universe. This function
// is used in order to isolate any logic related to the specifics of how we
// fetch the data from the universe server.
func (s *SimpleSyncer) fetchAllRoots(ctx context.Context, diffEngine DiffEngine) ([]Root, error) {
	offset := int32(0)
	pageSize := defaultPageSize
	roots := make([]Root, 0)

	for {
		log.Debugf("Fetching roots in range: %v to %v", offset,
			offset+pageSize)
		tempRoots, err := diffEngine.RootNodes(
			ctx, RootNodesQuery{
				WithAmountsById: false,
				SortDirection:   SortAscending,
				Offset:          offset,
				Limit:           pageSize,
			},
		)

		if err != nil {
			return nil, err
		}

		if len(tempRoots) == 0 {
			break
		}

		roots = append(roots, tempRoots...)
		offset += pageSize
	}

	return roots, nil
}

// fetchAllLeafKeys fetches all the leaf keys from the remote Universe. This
// function is used in order to isolate any logic related to the specifics of
// how we fetch the data from the universe server.
func (s *SimpleSyncer) fetchAllLeafKeys(ctx context.Context,
	diffEngine DiffEngine, uniID Identifier) ([]LeafKey, error) {

	// Initialize the offset to be used for the pages.
	offset := int32(0)
	pageSize := defaultPageSize
	leafKeys := make([]LeafKey, 0)

	for {
		tempRemoteKeys, err := diffEngine.UniverseLeafKeys(
			ctx, UniverseLeafKeysQuery{
				Id:            uniID,
				Offset:        offset,
				Limit:         pageSize,
				SortDirection: SortAscending,
			},
		)
		if err != nil {
			return nil, err
		}

		if len(tempRemoteKeys) == 0 {
			break
		}

		leafKeys = append(leafKeys, tempRemoteKeys...)
		offset += pageSize
	}

	return leafKeys, nil
}
