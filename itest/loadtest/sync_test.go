package loadtest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// syncTest checks that the universe server can handle multiple requests to its
// public universe endpoints. The number of clients is configurable.
func syncTest(t *testing.T, ctx context.Context, cfg *Config) {
	alice := initAlice(t, ctx, cfg)

	// Let's start by logging the aggregate universe stats.
	res, err := alice.UniverseStats(ctx, &universerpc.StatsRequest{})
	require.NoError(t, err)

	t.Logf("Universe Aggregate Stats: %+v", res)

	// We'll use this wait group to block until all clients are done.
	var wg sync.WaitGroup

	// We dispatch a client sync for the configured number of clients.
	for i := range cfg.SyncNumClients {
		switch cfg.SyncType {
		case "simplesyncer":
			wg.Add(1)
			go simpleSyncer(t, ctx, cfg, i, &wg)

		case "rest":
			wg.Add(1)
			go syncAssetRootsREST(t, ctx, cfg, i, &wg)
		}
	}

	wg.Wait()
}

// simpleSyncer creates a simple syncer instance and uses Alice as the remote
// diff engine. It always triggers a full sync as the local diff engine returns
// an empty leaf node.
func simpleSyncer(t *testing.T, ctx context.Context, cfg *Config, id int,
	wg *sync.WaitGroup) {

	defer wg.Done()

	// Alice is always serving as the universe server.
	uniURL := fmt.Sprintf("%s:%v", cfg.Alice.Tapd.Host, cfg.Alice.Tapd.Port)

	syncer := universe.NewSimpleSyncer(
		universe.SimpleSyncCfg{
			LocalDiffEngine:     noopBaseUni{},
			NewRemoteDiffEngine: tap.NewRpcUniverseDiff,
			LocalRegistrar:      noopBaseUni{},
			SyncBatchSize:       512,
		},
	)

	t.Logf("SimpleSyncer-%02d: Starting full universe sync", id)

	// We don't care about the diff, so we only check if an error occurred,
	// otherwise the sync completed.
	_, err := syncer.SyncUniverse(
		ctx, universe.NewServerAddrFromStr(uniURL),
		universe.SyncFull, universe.SyncConfigs{
			GlobalSyncConfigs: []*universe.FedGlobalSyncConfig{
				{
					// nolint:lll
					ProofType:       universe.ProofTypeIssuance,
					AllowSyncInsert: true,
				},
			},
		},
	)
	require.NoError(t, err)

	t.Logf("SimpleSyncer-%02d: Completed full universe sync", id)
}

// syncAssetRootsREST performs a series of requests to the AssetRoots endpoint
// of the universe server. It automatically progresses the requested page until
// the whole data is read.
func syncAssetRootsREST(t *testing.T, ctx context.Context, cfg *Config,
	id int, wg *sync.WaitGroup) {

	defer wg.Done()
	var (
		limit  = cfg.SyncPageSize
		offset = 0
	)

	for {
		// This is the URL of the universe server, in our case that's
		// always Alice.
		baseURL := fmt.Sprintf(
			"https://%s:%v/v1/taproot-assets/universe/roots",
			cfg.Alice.Tapd.Host, cfg.Alice.Tapd.RestPort,
		)

		// We inject the pagination GET params.
		fullURL := fmt.Sprintf(
			"%s?offset=%v&limit=%v", baseURL, offset, limit,
		)

		t.Logf("Syncer%02d: Fetching AssetRoots offset=%v, limit=%v",
			id, offset, limit)

		res := getAssetRoots(t, ctx, fullURL)

		// In order to count the length of the response without doing
		// JSON parsing, we simply count the occurences of a top-level
		// field name that repeats for all entries in the array.
		len := strings.Count(res, "mssmt_root")

		// Break if we reached the end. This is signalled by retrieving
		// less entities than what was defined as the max limit,
		// meaning that there's nothing left to consume.
		if len < limit {
			break
		}

		offset += limit
	}
}

// getAssetRoots performs a GET request to the AssetRoots REST endpoint of the
// universe server. We don't care about handling the response, we just hit the
// endpoint and return the text of the body.
func getAssetRoots(t *testing.T, ctx context.Context, fullURL string) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(body)
}
