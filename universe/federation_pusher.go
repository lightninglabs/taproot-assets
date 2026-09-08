package universe

import (
	"context"
	"fmt"
	"time"
)

// fifoFederationProofSyncLog is implemented by federation stores that can
// return pending pushes in their durable insertion order.
type fifoFederationProofSyncLog interface {
	FetchPendingProofsSyncLogFIFO(context.Context,
		*SyncDirection) ([]*ProofSyncLogEntry, error)
}

// signalPusher wakes the federation pusher without coupling callers to the
// pusher's current progress. The durable proof sync log is the work queue, so
// this channel only needs to carry an edge-triggered wakeup.
func (f *FederationEnvoy) signalPusher() {
	select {
	case f.pushWake <- struct{}{}:
	default:
	}
}

// pusher serially drains pending federation proof pushes. Keeping this work in
// a dedicated goroutine prevents a slow remote federation member from blocking
// the periodic federation sync loop.
func (f *FederationEnvoy) pusher() {
	defer f.Wg.Done()

	retryInterval := f.cfg.SyncInterval
	if retryInterval <= 0 {
		retryInterval = DefaultTimeout
	}

	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

	for {
		select {
		case <-f.pushWake:
		case <-retryTicker.C:
		case <-f.Quit:
			return
		}

		if err := f.handlePendingProofPushes(); err != nil {
			log.Warnf("Unable to handle pending federation push: %v",
				err)
		}
	}
}

// pendingProofPushes fetches pending work in durable FIFO order when the
// backing store supports it. Alternate FederationDB implementations retain the
// existing method contract, which is useful for lightweight test stores.
func (f *FederationEnvoy) pendingProofPushes(ctx context.Context,
	syncDirection *SyncDirection) ([]*ProofSyncLogEntry, error) {

	fifoLog, ok := f.cfg.FederationDB.(fifoFederationProofSyncLog)
	if ok {
		return fifoLog.FetchPendingProofsSyncLogFIFO(
			ctx, syncDirection,
		)
	}

	return f.cfg.FederationDB.FetchPendingProofsSyncLog(
		ctx, syncDirection,
	)
}

// handlePendingProofPushes drains the durable push log in FIFO order. A
// failed push blocks only later entries for that same federation member during
// this pass. This prevents a reissuance from overtaking its anchor while still
// allowing healthy members to make progress.
func (f *FederationEnvoy) handlePendingProofPushes() error {
	ctx, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	syncDirection := SyncDirectionPush
	logEntries, err := f.pendingProofPushes(ctx, &syncDirection)
	if err != nil {
		return fmt.Errorf("unable to query pending push sync log: %w",
			err)
	}

	if len(logEntries) > 0 {
		log.Debugf("Handling pending proof sync log entries "+
			"(entries_count=%d)", len(logEntries))
	}

	blockedServers := make(map[string]struct{})
	for idx := range logEntries {
		entry := logEntries[idx]
		serverHost := entry.ServerAddr.HostStr()

		if _, blocked := blockedServers[serverHost]; blocked {
			continue
		}

		err := f.pushProofToServerLogged(
			ctx, entry.UniID, entry.LeafKey, &entry.Leaf,
			entry.ServerAddr,
		)
		if err != nil {
			// Keep the remaining FIFO entries for this server pending
			// until the next pass, but do not stall unrelated members.
			blockedServers[serverHost] = struct{}{}
			log.Warnf("Cannot push queued proof to federation "+
				"server(%v): %v", serverHost, err)
		}
	}

	return nil
}

// filterProofSyncPendingCtx filters out federation servers that already have a
// completed push log entry for the given proof leaf.
func (f *FederationEnvoy) filterProofSyncPendingCtx(ctx context.Context,
	fedServers []ServerAddr, uniID Identifier,
	key LeafKey) ([]ServerAddr, error) {

	if len(fedServers) == 0 {
		return nil, nil
	}

	logs, err := f.cfg.FederationDB.QueryFederationProofSyncLog(
		ctx, uniID, key, SyncDirectionPush,
		ProofSyncStatusComplete,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query federation sync log: %w",
			err)
	}

	syncedServers := make(map[string]struct{}, len(logs))
	for idx := range logs {
		logEntry := logs[idx]
		syncedServers[logEntry.ServerAddr.HostStr()] = struct{}{}
	}

	filteredFedServers := make([]ServerAddr, 0, len(fedServers))
	for idx := range fedServers {
		server := fedServers[idx]
		if _, ok := syncedServers[server.HostStr()]; ok {
			continue
		}

		filteredFedServers = append(filteredFedServers, server)
	}

	return filteredFedServers, nil
}

// queueProofPushes records durable push work before returning to the caller.
// Federation delivery is best effort from the caller's point of view, matching
// the existing envoy contract: failures to enumerate members or write the push
// log are reported through logs and retried only when durable work exists.
// Items that explicitly opt out of the proof sync log keep their existing
// best-effort behavior and are pushed outside the sync loop.
func (f *FederationEnvoy) queueProofPushes(ctx context.Context,
	items []*Item) error {

	fedServers, err := f.cfg.FederationDB.UniverseServers(ctx)
	if err != nil {
		log.Warnf("Unable to fetch federation servers while queuing "+
			"proof push: %v", err)
		return nil
	}
	if len(fedServers) == 0 {
		log.Warnf("could not find any federation servers")
		return nil
	}

	var (
		loggedWork bool
		bestEffort = make([]*Item, 0, len(items))
	)

	for idx := range items {
		item := items[idx]
		if !item.LogProofSync {
			bestEffort = append(bestEffort, item)
			continue
		}

		pendingServers, err := f.filterProofSyncPendingCtx(
			ctx, fedServers, item.ID, item.Key,
		)
		if err != nil {
			log.Warnf("Unable to filter pending federation pushes: %v",
				err)
			continue
		}

		for serverIdx := range pendingServers {
			server := pendingServers[serverIdx]
			_, err := f.cfg.FederationDB.UpsertFederationProofSyncLog(
				ctx, item.ID, item.Key, server,
				SyncDirectionPush, ProofSyncStatusPending, false,
			)
			if err != nil {
				log.Warnf("Unable to queue federation push to "+
					"server=%v: %v", server.HostStr(), err)
				continue
			}

			loggedWork = true
		}
	}

	if loggedWork {
		f.signalPusher()
	}

	if len(bestEffort) > 0 {
		f.pushBestEffort(bestEffort, fedServers)
	}

	return nil
}

// pushBestEffort preserves the existing behavior for proof updates that are
// intentionally not written to the durable federation push log. The work is
// detached from the caller and from the federation sync loop.
func (f *FederationEnvoy) pushBestEffort(items []*Item,
	fedServers []ServerAddr) {

	f.Wg.Add(1)
	go func() {
		defer f.Wg.Done()

		ctx, cancel := f.WithCtxQuitNoTimeout()
		defer cancel()

		for idx := range items {
			item := items[idx]
			f.pushProofToFederation(
				ctx, item.ID, item.Key, item.Leaf, fedServers,
				false,
			)
		}
	}()
}
