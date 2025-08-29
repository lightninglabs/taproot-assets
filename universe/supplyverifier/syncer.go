package supplyverifier

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

const (
	// defaultPullTimeout is the default timeout for a supply commitment
	defaultPullTimeout = 30 * time.Second
)

// UniverseClient is an interface that represents a client connection to a
// remote universe server.
type UniverseClient interface {
	// InsertSupplyCommit inserts a supply commitment for a specific
	// asset group into the remote universe server.
	InsertSupplyCommit(ctx context.Context, assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment,
		updateLeaves supplycommit.SupplyLeaves,
		chainProof supplycommit.ChainProof) error

	// FetchSupplyCommit fetches a supply commitment for a specific
	// asset group from the remote universe server.
	FetchSupplyCommit(ctx context.Context, assetSpec asset.Specifier,
		spentCommitOutpoint fn.Option[wire.OutPoint]) (
		supplycommit.FetchSupplyCommitResult, error)

	// Close closes the fetcher and cleans up any resources.
	Close() error
}

// UniverseClientFactory is a function type that creates UniverseClient
// instances for a given universe server address.
type UniverseClientFactory func(serverAddr universe.ServerAddr) (UniverseClient,
	error)

// SupplySyncerStore is an interface for storing synced leaves and state.
type SupplySyncerStore interface {
	// LogSupplyCommitPush logs that a supply commitment and its leaves
	// have been successfully pushed to a remote universe server.
	LogSupplyCommitPush(ctx context.Context, serverAddr universe.ServerAddr,
		assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment,
		leaves supplycommit.SupplyLeaves) error
}

// UniverseFederationView is an interface that provides a view of the
// federation of universe servers.
type UniverseFederationView interface {
	// UniverseServers returns a list of all known universe servers in
	// the federation.
	UniverseServers(ctx context.Context) ([]universe.ServerAddr, error)
}

// SupplySyncerConfig is a configuration struct for creating a new
// SupplySyncer instance.
type SupplySyncerConfig struct {
	// ClientFactory is a factory function that creates UniverseClient
	// instances for specific universe server addresses.
	ClientFactory UniverseClientFactory

	// Store is used to persist supply leaves to the local database.
	Store SupplySyncerStore

	// UniverseFederationView is used to fetch the list of known
	// universe servers in the federation.
	UniverseFederationView UniverseFederationView
}

// SupplySyncer is a struct that is responsible for retrieving supply leaves
// from a universe.
type SupplySyncer struct {
	// cfg is the configuration for the SupplySyncer.
	cfg SupplySyncerConfig
}

// NewSupplySyncer creates a new SupplySyncer with a factory function for
// creating UniverseClient instances and a store for persisting leaves.
func NewSupplySyncer(cfg SupplySyncerConfig) SupplySyncer {
	return SupplySyncer{
		cfg: cfg,
	}
}

// pushUniServer pushes the supply commitment to a specific universe server.
func (s *SupplySyncer) pushUniServer(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof,
	serverAddr universe.ServerAddr) error {

	// Create a client for the specific universe server address.
	client, err := s.cfg.ClientFactory(serverAddr)
	if err != nil {
		return fmt.Errorf("unable to create universe client: %w", err)
	}

	// Ensure the client is properly closed when we're done.
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Errorf("unable to close universe client: %v",
				closeErr)
		}
	}()

	err = client.InsertSupplyCommit(
		ctx, assetSpec, commitment, updateLeaves, chainProof,
	)
	if err != nil {
		return fmt.Errorf("unable to insert supply leaves: %w", err)
	}

	// Log the successful insertion to the remote universe.
	err = s.cfg.Store.LogSupplyCommitPush(
		ctx, serverAddr, assetSpec, commitment, updateLeaves,
	)
	if err != nil {
		return fmt.Errorf("unable to log supply commit push: %w", err)
	}

	return nil
}

// fetchServerAddrs retrieves the list of universe server addresses that
// the syncer uses to interact with remote servers.
func (s *SupplySyncer) fetchServerAddrs(ctx context.Context,
	canonicalUniverses []url.URL) ([]universe.ServerAddr, error) {

	var zero []universe.ServerAddr

	// Fetch latest set of universe federation server addresses.
	fedAddrs, err := s.cfg.UniverseFederationView.UniverseServers(ctx)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch universe servers: %w",
			err)
	}

	// Formulate final unique list of universe server addresses to push to.
	uniqueAddrs := make(map[string]universe.ServerAddr)
	for idx := range canonicalUniverses {
		addrUrl := canonicalUniverses[idx]
		serverAddr := universe.NewServerAddrFromStr(addrUrl.String())
		uniqueAddrs[serverAddr.HostStr()] = serverAddr
	}

	for idx := range fedAddrs {
		serverAddr := fedAddrs[idx]
		uniqueAddrs[serverAddr.HostStr()] = serverAddr
	}

	targetAddrs := make([]universe.ServerAddr, 0, len(uniqueAddrs))
	for _, serverAddr := range uniqueAddrs {
		targetAddrs = append(targetAddrs, serverAddr)
	}

	return targetAddrs, nil
}

// PushSupplyCommitment pushes a supply commitment to the remote universe
// server. This function should block until the sync insertion is complete.
//
// Returns a map of per-server errors keyed by server host string and
// an internal error. If all pushes succeed, both return values are nil.
// If some pushes fail, the map contains only the failed servers and
// their corresponding errors. If there's an internal/system error that
// prevents the operation from proceeding, it's returned as the second
// value.
//
// NOTE: This function must be thread safe.
func (s *SupplySyncer) PushSupplyCommitment(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof,
	canonicalUniverses []url.URL) (map[string]error, error) {

	targetAddrs, err := s.fetchServerAddrs(ctx, canonicalUniverses)
	if err != nil {
		// This is an internal error that prevents the operation from
		// proceeding.
		return nil, fmt.Errorf("unable to fetch target universe "+
			"server addresses: %w", err)
	}

	// Push the supply commitment to all target universe servers in
	// parallel. Any error for a specific server will be captured in the
	// pushErrs map and will not abort the entire operation.
	pushErrs, err := fn.ParSliceErrCollect(
		ctx, targetAddrs, func(ctx context.Context,
			serverAddr universe.ServerAddr) error {

			// Push the supply commitment to the universe server.
			err := s.pushUniServer(
				ctx, assetSpec, commitment, updateLeaves,
				chainProof, serverAddr,
			)
			if err != nil {
				return fmt.Errorf("unable to push supply "+
					"commitment (server_addr_id=%d, "+
					"server_addr_host_str=%s): %w",
					serverAddr.ID, serverAddr.HostStr(),
					err)
			}

			return nil
		},
	)
	if err != nil {
		// This should not happen with ParSliceErrCollect, but handle it
		// as an internal error.
		return nil, fmt.Errorf("unable to push supply commitment: %w",
			err)
	}

	// Build a map of errors encountered while pushing to each server.
	// If there were no errors, return nil for both values.
	if len(pushErrs) == 0 {
		return nil, nil
	}

	errorMap := make(map[string]error)
	for idx, pushErr := range pushErrs {
		serverAddr := targetAddrs[idx]
		hostStr := serverAddr.HostStr()
		errorMap[hostStr] = pushErr
	}

	return errorMap, nil
}

// pullUniServer fetches the supply commitment from a specific universe server.
func (s *SupplySyncer) pullUniServer(ctx context.Context,
	assetSpec asset.Specifier, spentCommitOutpoint fn.Option[wire.OutPoint],
	serverAddr universe.ServerAddr) (supplycommit.FetchSupplyCommitResult,
	error) {

	var zero supplycommit.FetchSupplyCommitResult

	// Create a client for the specific universe server address.
	client, err := s.cfg.ClientFactory(serverAddr)
	if err != nil {
		return zero, fmt.Errorf("unable to create universe client: %w",
			err)
	}

	// Ensure the client is properly closed when we're done.
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Errorf("Unable to close supply syncer pull "+
				"universe client: %v", closeErr)
		}
	}()

	result, err := client.FetchSupplyCommit(
		ctx, assetSpec, spentCommitOutpoint,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply commitment: %w",
			err)
	}

	return result, nil
}

// SupplyCommitPullResult represents the result of a supply commitment pull
// operation across multiple universe servers.
type SupplyCommitPullResult struct {
	// FetchResult contains the complete fetched supply commitment data.
	FetchResult fn.Option[supplycommit.FetchSupplyCommitResult]

	// ErrorMap contains errors encountered while pulling from each server,
	// keyed by server host string. If empty, all pulls succeeded.
	ErrorMap map[string]error
}

// PullSupplyCommitment fetches a supply commitment from remote universe
// servers. This function attempts to fetch from all servers in parallel.
//
// Returns a SupplyCommitPullResult containing the fetched data and a map of
// per-server errors, plus an internal error. If at least one server succeeds,
// the result will contain the commitment data. If all servers fail, the
// ErrorMap will contain all the errors and the commitment data will be nil.
//
// NOTE: This function must be thread safe.
func (s *SupplySyncer) PullSupplyCommitment(ctx context.Context,
	assetSpec asset.Specifier, spentCommitOutpoint fn.Option[wire.OutPoint],
	canonicalUniverses []url.URL) (SupplyCommitPullResult, error) {

	var zero SupplyCommitPullResult

	targetAddrs, err := s.fetchServerAddrs(ctx, canonicalUniverses)
	if err != nil {
		// This is an internal error that prevents the operation from
		// proceeding.
		return zero, fmt.Errorf("unable to fetch target universe "+
			"server addresses: %w", err)
	}

	// Pull the supply commitment from all target universe servers in
	// parallel. Store both errors and successful results.
	var muResults sync.Mutex
	results := make(map[string]supplycommit.FetchSupplyCommitResult)

	// Specify context timeout for the entire pull operation.
	ctxPull, cancel := context.WithTimeout(ctx, defaultPullTimeout)
	defer cancel()

	pullErrs, err := fn.ParSliceErrCollect(
		ctxPull, targetAddrs, func(ctx context.Context,
			serverAddr universe.ServerAddr) error {

			// Pull the supply commitment from the universe server.
			result, err := s.pullUniServer(
				ctx, assetSpec, spentCommitOutpoint, serverAddr,
			)
			if err != nil {
				return fmt.Errorf("unable to pull supply "+
					"commitment (server_addr_id=%d, "+
					"server_addr_host_str=%s): %w",
					serverAddr.ID, serverAddr.HostStr(),
					err)
			}

			muResults.Lock()
			results[serverAddr.HostStr()] = result
			muResults.Unlock()

			return nil
		},
	)
	if err != nil {
		// This should not happen with ParSliceErrCollect, but handle it
		// as an internal error.
		return zero, fmt.Errorf("unable to pull supply commitment: %w",
			err)
	}

	// Report results: log server address and supply tree root.
	//
	// If the supply commitment that was pulled fails verification later,
	// we can use this log to trace back to the server it came from.
	for serverAddr, res := range results {
		// Format the spent outpoint if present, otherwise empty string.
		spentOutpointStr := fn.MapOptionZ(
			spentCommitOutpoint, func(op wire.OutPoint) string {
				return op.String()
			},
		)

		log.Infof("Pulled supply commitment from server "+
			"(server_addr=%s, asset=%s, supply_tree_root=%s, "+
			"spent_outpoint=%s)", serverAddr, assetSpec.String(),
			res.RootCommitment.SupplyRoot.NodeHash().String(),
			spentOutpointStr)
	}

	// Return one successful result, if available, as the final outcome.
	var finalResult *supplycommit.FetchSupplyCommitResult
	for _, res := range results {
		finalResult = &res
		break
	}

	// Build a map from server addresses to their corresponding errors.
	errorMap := make(map[string]error)
	for idx, pullErr := range pullErrs {
		serverAddr := targetAddrs[idx]
		hostStr := serverAddr.HostStr()
		if pullErr != nil {
			errorMap[hostStr] = pullErr
		}
	}

	return SupplyCommitPullResult{
		FetchResult: fn.MaybeSome(finalResult),
		ErrorMap:    errorMap,
	}, nil
}
