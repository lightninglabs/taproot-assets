package universe

import (
	"context"
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
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
	LocalRegistrar Registrar
}

// SimpleSyncer is a simple implementation of the Syncer interface. It's based
// on a set difference operation between the local and remote Universe.
type SimpleSyncer struct {
	cfg SimpleSyncCfg
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
	syncType SyncType, idsToSync []Identifier) ([]AssetSyncDiff, error) {

	var (
		rootsToSync = make(chan BaseRoot, len(idsToSync))
		err         error
	)
	switch {
	// If we have a specific set of Universes to sync, then we'll fetch the
	// roots for each of them.
	case len(idsToSync) != 0:
		log.Infof("Fetching %v roots", len(idsToSync))
		log.Tracef("Fetching %v roots for IDs: %v", len(idsToSync),
			spew.Sdump(idsToSync))

		// We'll use an error group to fetch each Universe root we need
		// as a series of parallel requests backed by a worker pool.
		//
		// TODO(roasbeef): can actually make non-blocking..
		err = fn.ParSlice(ctx, idsToSync,
			func(ctx context.Context, id Identifier) error {
				root, err := diffEngine.RootNode(ctx, id)
				if err != nil {
					return err
				}

				rootsToSync <- root
				return nil
			},
		)

	// Otherwise, we'll just fetch all the roots from the remote universe.
	default:
		log.Infof("Fetching all roots for remote Universe server...")
		roots, err := diffEngine.RootNodes(ctx)
		if err != nil {
			return nil, err
		}

		rootsToSync = make(chan BaseRoot, len(roots))

		// TODO(roasbeef): can make non-blocking w/ goroutine
		fn.SendAll(rootsToSync, roots...)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to fetch roots for "+
			"universe sync: %w", err)
	}

	targetRoots := fn.Collect(rootsToSync)

	log.Infof("Obtained %v roots from remote Universe server",
		len(targetRoots))
	log.Tracef("Obtained %v roots from remote Universe server: %v",
		len(targetRoots), spew.Sdump(targetRoots))

	// Now that we know the set of Universes we need to sync, we'll execute
	// the diff operation for each of them.
	syncDiffs := make(chan AssetSyncDiff, len(targetRoots))
	err = fn.ParSlice(ctx, targetRoots, func(ctx context.Context, remoteRoot BaseRoot) error {
		// First, we'll compare the remote root against the local root.
		uniID := remoteRoot.ID
		localRoot, err := s.cfg.LocalDiffEngine.RootNode(ctx, uniID)
		switch {
		// If we don't have this root, then we don't have anything to
		// compare to so we'll proceed as normal.
		case errors.Is(err, ErrNoUniverseRoot):
			// TODO(roasbeef): abstraction leak, error should be in
			// universe package

		// If the local root matches the remote root, then we're done
		// here.
		case err == nil && mssmt.IsEqualNode(localRoot, remoteRoot):
			log.Infof("Root for %v matches, no sync needed",
				uniID.String())

			return nil

		case err != nil:
			return fmt.Errorf("unable to fetch local root: %v", err)
		}

		log.Infof("UniverseRoot(%v) diverges, performing leaf diff...",
			uniID.String())

		// Otherwise, we'll need to perform a diff operation to find
		// the set of keys we need to fetch.
		remoteUnikeys, err := diffEngine.MintingKeys(ctx, uniID)
		if err != nil {
			return err
		}
		localUnikeys, err := s.cfg.LocalDiffEngine.MintingKeys(
			ctx, uniID,
		)
		if err != nil {
			return err
		}

		// With the set of keys fetched, we can now find the set of
		// keys that need to be synced.
		keysToFetch := fn.SetDiff(remoteUnikeys, localUnikeys)

		log.Infof("UniverseRoot(%v): diff_size=%v", uniID.String(),
			len(keysToFetch))
		log.Tracef("UniverseRoot(%v): diff_size=%v, diff=%v",
			uniID.String(), len(keysToFetch),
			spew.Sdump(keysToFetch))

		// Now that we know where the divergence is, we can fetch the
		// issuance proofs from the remote party.
		newLeaves := make(chan *MintingLeaf, len(keysToFetch))
		err = fn.ParSlice(ctx, keysToFetch, func(ctx context.Context, key BaseKey) error {
			newProof, err := diffEngine.FetchIssuanceProof(ctx, uniID, key)
			if err != nil {
				return err
			}

			leafProof := newProof[0]

			// Now that we have this leaf proof, we want to ensure
			// that it's actually part of the remote root we were
			// given.
			if !leafProof.VerifyRoot(remoteRoot) {
				return fmt.Errorf("proof for key=%v is "+
					"invalid", spew.Sdump(key))
			}

			// TODO(roasbeef): inclusion w/ root here, also that
			// it's the expected asset ID

			log.Infof("UniverseRoot(%v): inserting new leaf",
				uniID.String())
			log.Tracef("UniverseRoot(%v): inserting new leaf for "+
				"key=%v", uniID.String(), spew.Sdump(key))

			// TODO(roasbeef): this is actually giving a lagging
			// proof for each of them
			_, err = s.cfg.LocalRegistrar.RegisterIssuance(
				ctx, uniID, key, leafProof.Leaf,
			)
			if err != nil {
				return fmt.Errorf("unable to register "+
					"issuance proof: %w", err)
			}

			newLeaves <- leafProof.Leaf
			return nil
		})
		if err != nil {
			return err
		}

		log.Infof("Universe sync for UniverseRoot(%v) complete, %d "+
			"new leaves inserted", uniID.String(), len(keysToFetch))

		// TODO(roabseef): sanity check local and remote roots match
		// now?

		// To wrap up, we'll collect the set of leaves then convert
		// them into a final sync diff.
		syncDiffs <- AssetSyncDiff{
			OldUniverseRoot: localRoot,
			NewUniverseRoot: remoteRoot,
			NewLeafProofs:   fn.Collect(newLeaves),
		}

		log.Infof("Sync for UniverseRoot(%v) complete!", uniID.String())
		log.Tracef("Sync for UniverseRoot(%v) complete! New "+
			"universe_root=%v", uniID.String(),
			spew.Sdump(remoteRoot))

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Finally, we'll collect all the diffs and return them to the caller.
	return fn.Collect(syncDiffs), nil
}

// SyncUniverse attempts to synchronize the local universe with the remote
// universe, governed by the sync type and the set of universe IDs to sync.
func (s *SimpleSyncer) SyncUniverse(ctx context.Context, host ServerAddr,
	syncType SyncType, idsToSync ...Identifier) ([]AssetSyncDiff, error) {

	// First, we'll make sure that the user requested a sync with the set
	// of supported sync types.
	switch syncType {
	case SyncIssuance:
		break

	// For now, we only support issuance syncs.
	case SyncFull:
		fallthrough

	default:
		return nil, ErrUnsupportedSync
	}

	log.Infof("Attempting to sync universe: host=%v, sync_type=%v, ids=%v",
		host.HostStr(), syncType, spew.Sdump(idsToSync))

	// Next, we'll attempt to create a new diff engine for the remote
	// Universe.
	diffEngine, err := s.cfg.NewRemoteDiffEngine(host)
	if err != nil {
		return nil, fmt.Errorf("unable to create remote diff "+
			"engine: %w", err)
	}

	// With the engine created, we can now sync the local Universe with the
	// remote instance.
	return s.executeSync(ctx, diffEngine, syncType, idsToSync)
}

// SyncType is an enum that describes the type of sync that should be performed
// between a local and remote universe.
type SyncType uint8

const (
	// SyncIssuance is a sync that will only sync new asset issuance events.
	SyncIssuance SyncType = iota

	// SyncFull is a sync that will sync all the assets in the universe.
	SyncFull
)

// String returns a human-readable string representation of the sync type.
func (s SyncType) String() string {
	switch s {
	case SyncIssuance:
		return "issuance"
	case SyncFull:
		return "full"
	default:
		return fmt.Sprintf("unknown(%v)", int(s))
	}
}

// AssetSyncStats is the response to a SyncStatsQuery request. It contains the
// original query, and the set of sync stats generated by the query.
type AssetSyncStats struct {
	// Query is the original query that was used to generate the stats.
	Query SyncStatsQuery

	// SyncStats is the set of sync stats generated by the query.
	SyncStats []AssetSyncSnapshot
}

// AssetSyncSnapshot is a snapshot of the sync activity for a given asset.
type AssetSyncSnapshot struct {
	// AssetID is the ID of the asset.
	AssetID asset.ID

	// AssetName is the name of the asset.
	AssetName string

	// AssetType is the type of the asset.
	AssetType asset.Type

	// TotalSupply is the total supply of the asset.
	TotalSupply uint64

	// GenesisHeight is the height of the block that the asset was created
	// in.
	GenesisHeight uint32

	// TotalSyncs is the total number of syncs that have been performed for
	// the target asset.
	TotalSyncs uint64

	// TotalProofs is the total number of proofs that have been inserted
	// for the asset.
	TotalProofs uint64

	// TODO(roasbeef): add last sync?
}

// AssetSyncDiff is the result of a success Universe sync. The diff contains the
// Universe root, and the set of assets that were added to the Universe.
type AssetSyncDiff struct {
	// OldUniverseRoot is the root of the universe before the sync.
	OldUniverseRoot BaseRoot

	// NewUniverseRoot is the new root of the Universe after the sync.
	NewUniverseRoot BaseRoot

	// NewAssetLeaves is the set of new leaf proofs that were added to the
	// Universe.
	NewLeafProofs []*MintingLeaf

	// TODO(roasbeef): ability to return if things failed?
	//  * can used a sealed interface to return the error
}

// SyncStatsSort is an enum used to specify the sort order of the returned sync
// stats.
type SyncStatsSort uint8

const (
	// SortByNone is a sentinel value that indicates that no sorting should
	// be done.
	SortByNone SyncStatsSort = iota

	// SortByAssetName sorts the returned stats by the asset name.
	SortByAssetName

	// SortByAssetType sorts the returned stats by the asset type.
	SortByAssetType

	// SortByAssetID sorts the returned stats by the asset ID.
	SortByAssetID
)

// SyncStatsQuery packages a set of query parameters to retrieve stats related
// to the sync activity of a given Universe. Any of the filters can be
// specified, however only a single sort by value should be specified. The
// offset and limit fields can be used to implement pagination.
type SyncStatsQuery struct {
	// AssetNameFilter can be used to filter for stats for a given asset name.
	AssetNameFilter string

	// AssetIDFilter can be used to filter for stats for a given asset ID.
	AssetIDFilter asset.ID

	// AssetTypeFilter can be used to filter for stats for a given asset
	// type.
	AssetTypeFilter *asset.Type

	// SortBy is the sort order to use when returning the stats.
	SortBy SyncStatsSort

	// Offset is the offset to use when returning the stats. This can be
	// used to paginate the response.
	Offset int

	// Limit is the maximum number of stats to return. This can be used to
	// paginate the response.
	Limit int
}
