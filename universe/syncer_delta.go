package universe

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
)

// DeltaSyncResult summarizes a successful delta sync run against a
// single remote server.
type DeltaSyncResult struct {
	// NewCursor is the cursor value the caller should persist for the
	// server. A successful run implies every universe the delta touched
	// ended the run verified — either directly, or via fallback
	// enumeration — so the cursor always reflects the final page.
	NewCursor uint64

	// Diffs describes the per-universe changes applied during the run.
	Diffs []AssetSyncDiff
}

// SyncUniverseDelta attempts a cursor-based delta sync against the given
// host: fetch the leaves inserted on the remote after sinceSeq, verify
// each against the remote's claimed universe roots, insert them locally
// in remote insertion order, and then verify convergence per universe by
// comparing the recomputed local root against the remote root. Universes
// that fail verification are demoted to the enumeration-based syncRoot
// path. If the remote does not support delta sync, ErrDeltaUnsupported
// is returned and the caller should use SyncUniverse instead.
//
// The delta is an optimization of enumeration sync, never a semantic
// change: the cursor is an unauthenticated hint, and every acceptance
// decision rests on the same inclusion-proof, chain-verification, and
// root-equality checks the enumeration path uses.
//
// One caveat follows from only examining universes the delta touches: a
// universe with no post-cursor activity is not root-checked, so local
// divergence in a quiet universe (e.g. an administrative delete, or a
// leaf missed under a stale cursor) heals only when that universe next
// gains a leaf, or when a full enumeration sync runs. Callers that need
// a hard bound on divergence should schedule occasional full syncs as
// an audit.
func (s *SimpleSyncer) SyncUniverseDelta(ctx context.Context,
	host ServerAddr, sinceSeq uint64,
	syncConfigs SyncConfigs) (*DeltaSyncResult, error) {

	log.Infof("Attempting delta sync: host=%v, since_seq=%v",
		host.HostStr(), sinceSeq)

	diffEngine, err := s.cfg.NewRemoteDiffEngine(host)
	if err != nil {
		return nil, fmt.Errorf("unable to create remote diff "+
			"engine: %w", err)
	}
	defer diffEngine.Close()

	deltaEngine, ok := diffEngine.(DeltaEngine)
	if !ok {
		return nil, ErrDeltaUnsupported
	}

	// Prevent concurrent syncs, mirroring executeSync. The flag also
	// acts as the global write-pressure throttle: at most one sync run
	// feeds the local registrar at a time.
	if !s.isSyncing.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("sync is already in progress, please " +
			"wait for it to finish")
	}
	defer func() {
		s.isSyncing.Store(false)
	}()

	// insertFilter mirrors executeSync's uniIdSyncFilter for a full
	// sync: only issuance and transfer universes with insert enabled
	// are accepted.
	insertFilter := func(id Identifier) bool {
		switch id.ProofType {
		case ProofTypeIssuance, ProofTypeTransfer:

		case ProofTypeUnspecified, ProofTypeIgnore, ProofTypeBurn,
			ProofTypeMintSupply:

			return false
		}

		return syncConfigs.IsSyncInsertEnabled(id)
	}

	var (
		cursor        = sinceSeq
		remoteRoots   = make(map[IdentifierKey]Root)
		tainted       = make(map[IdentifierKey]struct{})
		touched       = make(map[IdentifierKey]Identifier)
		oldLocalRoots = make(map[IdentifierKey]Root)
		newLeaves     = make(map[IdentifierKey][]*Leaf)
	)

	for {
		page, err := deltaEngine.SyncDelta(ctx, cursor, defaultPageSize)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch delta page "+
				"(since_seq=%d): %w", cursor, err)
		}

		// Merge the page roots: later pages carry fresher roots for
		// universes that keep growing while we page.
		for key, root := range page.Roots {
			remoteRoots[key] = root
		}

		accepted := make([]*Item, 0, len(page.Items))
		for i := range page.Items {
			item := page.Items[i]
			idKey := item.ID.Key()

			if !insertFilter(item.ID) {
				continue
			}
			if _, isTainted := tainted[idKey]; isTainted {
				continue
			}

			// Record the universe's pre-sync local root the first
			// time the delta touches it, so the final diff reports
			// the actual transition.
			if _, seen := touched[idKey]; !seen {
				local := s.cfg.LocalDiffEngine
				localRoot, err := local.RootNode(
					ctx, item.ID,
				)
				switch {
				// This universe is new to us.
				case errors.Is(err, ErrNoUniverseRoot):

				case err != nil:
					return nil, fmt.Errorf("unable to "+
						"fetch local root: %w", err)

				default:
					oldLocalRoots[idKey] = localRoot
				}

				touched[idKey] = item.ID
			}

			// Verify the item's inclusion proof against the
			// remote's claimed root for its universe. A failure
			// taints the universe: its remaining items are
			// dropped and it is queued for fallback enumeration.
			root, haveRoot := remoteRoots[idKey]
			leafProof := &Proof{
				LeafKey:                item.Key,
				UniverseRoot:           root.Node,
				UniverseInclusionProof: item.InclusionProof,
				Leaf:                   item.Leaf,
			}
			if !haveRoot || item.InclusionProof == nil ||
				!leafProof.VerifyRoot(root.Node) {

				log.Warnf("Delta item (seq=%d) failed "+
					"universe root verification, "+
					"demoting UniverseRoot(%v) to "+
					"enumeration sync", item.Seq,
					item.ID.String())

				tainted[idKey] = struct{}{}
				continue
			}

			accepted = append(accepted, &Item{
				ID:   item.ID,
				Key:  item.Key,
				Leaf: item.Leaf,
			})
		}

		// Insert the accepted items in remote insertion order. That
		// order respects proof dependencies by construction: the
		// remote could only have inserted a leaf after the leaves it
		// depends on, so no re-sorting or proof-type partitioning is
		// needed here.
		err = s.insertDeltaItems(ctx, accepted)
		if err != nil {
			return nil, err
		}

		for _, item := range accepted {
			idKey := item.ID.Key()
			newLeaves[idKey] = append(newLeaves[idKey], item.Leaf)
		}

		// The cursor no longer advancing means the remote has nothing
		// further for us. This also covers byte-budget-shortened
		// pages, which advance the cursor and simply require another
		// round trip.
		if page.LatestSeq == cursor {
			break
		}
		cursor = page.LatestSeq
	}

	// With the delta applied, verify convergence per touched universe:
	// the recomputed local root must equal the freshest remote root the
	// pages reported. Mismatches (tainted universes, in-place re-org
	// rewrites, journal anomalies) are demoted to enumeration sync.
	var (
		diffs   []AssetSyncDiff
		demoted []Root
	)
	for idKey, id := range touched {
		remoteRoot, haveRoot := remoteRoots[idKey]
		if !haveRoot {
			return nil, fmt.Errorf("no remote root reported for "+
				"universe %v", id.String())
		}

		localRoot, err := s.cfg.LocalDiffEngine.RootNode(ctx, id)
		if err == nil && mssmt.IsEqualNode(localRoot, remoteRoot) {
			// The diff reports the measured local root, so the
			// completion report is adequate to what was actually
			// attained.
			diffs = append(diffs, AssetSyncDiff{
				OldUniverseRoot: oldLocalRoots[idKey],
				NewUniverseRoot: localRoot,
				NewLeafProofs:   newLeaves[idKey],
			})
			continue
		}
		if err != nil && !errors.Is(err, ErrNoUniverseRoot) {
			return nil, fmt.Errorf("unable to fetch local "+
				"root: %w", err)
		}

		demoted = append(demoted, remoteRoot)
	}

	// Fallback: enumeration sync for the demoted universes, issuance
	// first, bounded by the usual root concurrency. Any failure here
	// fails the whole run, so a successful return always implies every
	// touched universe converged.
	if len(demoted) > 0 {
		log.Infof("Delta sync demoting %d universes to enumeration "+
			"sync", len(demoted))

		syncDiffs := make(chan AssetSyncDiff, len(demoted))
		sorted := partitionByProofType(demoted)
		for _, roots := range [][]Root{
			sorted.Issuance, sorted.Transfer, sorted.Other,
		} {
			err := s.syncRoots(ctx, roots, diffEngine, syncDiffs)
			if err != nil {
				return nil, fmt.Errorf("delta fallback "+
					"sync failed: %w", err)
			}
		}

		diffs = append(diffs, fn.Collect(syncDiffs)...)
	}

	result := &DeltaSyncResult{
		NewCursor: cursor,
		Diffs:     diffs,
	}

	// Notify subscribers of the universes whose roots changed.
	var events []fn.Event
	for idx := range diffs {
		diff := diffs[idx]

		rootChange, err := diff.HasRootChanged()
		if err != nil {
			return nil, fmt.Errorf("unable to determine if root "+
				"has changed: %w", err)
		}

		if rootChange {
			events = append(events, &SyncDiffEvent{
				timestamp: time.Now().UTC(),
				SyncDiff:  diff,
			})
		}
	}
	s.eventDistributor.NotifySubscribers(events...)

	log.Infof("Delta sync complete: host=%v, new_cursor=%v, "+
		"universes_synced=%d (%d via fallback)", host.HostStr(),
		cursor, len(touched), len(demoted))

	return result, nil
}

// insertDeltaItems feeds the given items to the local registrar in
// SyncBatchSize chunks, preserving their order.
func (s *SimpleSyncer) insertDeltaItems(ctx context.Context,
	items []*Item) error {

	batchSize := s.cfg.SyncBatchSize
	if batchSize <= 0 {
		batchSize = 200
	}

	for start := 0; start < len(items); start += batchSize {
		end := start + batchSize
		if end > len(items) {
			end = len(items)
		}

		err := s.cfg.LocalRegistrar.UpsertProofLeafBatch(
			ctx, items[start:end],
		)
		if err != nil {
			return fmt.Errorf("unable to register proofs: %w",
				err)
		}
	}

	return nil
}
