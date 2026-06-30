package rpc

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
)

// Universe benches that fit Storage today exercise the empty-archive
// fast paths. Populated-universe variants live in the scenario suite.

// BenchmarkUniverseInfo covers Info — a trivial getter on the archive.
//
// bench:rpc=universerpc.Universe.Info
func BenchmarkUniverseInfo(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.Info, &unirpc.InfoRequest{})
}

// BenchmarkUniverseStats covers UniverseStats against an empty stats
// collector — measures aggregation overhead with no rows.
//
// bench:rpc=universerpc.Universe.UniverseStats
func BenchmarkUniverseStats(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.UniverseStats, &unirpc.StatsRequest{})
}

// BenchmarkQueryAssetStats covers QueryAssetStats against an empty stats
// store.
//
// bench:rpc=universerpc.Universe.QueryAssetStats
func BenchmarkQueryAssetStats(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.QueryAssetStats,
		&unirpc.AssetStatsQuery{})
}

// BenchmarkQueryEvents covers QueryEvents against an empty event log.
//
// bench:rpc=universerpc.Universe.QueryEvents
func BenchmarkQueryEvents(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.QueryEvents,
		&unirpc.QueryEventsRequest{})
}

// BenchmarkListFederationServers covers ListFederationServers against an
// empty federation store.
//
// bench:rpc=universerpc.Universe.ListFederationServers
func BenchmarkListFederationServers(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListFederationServers,
		&unirpc.ListFederationServersRequest{})
}

// BenchmarkQueryFederationSyncConfig covers QueryFederationSyncConfig
// against an empty config store.
//
// bench:rpc=universerpc.Universe.QueryFederationSyncConfig
func BenchmarkQueryFederationSyncConfig(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.QueryFederationSyncConfig,
		&unirpc.QueryFederationSyncConfigRequest{})
}

// BenchmarkAssetRoots covers AssetRoots against an empty universe.
// Exercises FederationEnvoy.QuerySyncConfigs + pagination.
//
// bench:rpc=universerpc.Universe.AssetRoots
func BenchmarkAssetRoots(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.AssetRoots, &unirpc.AssetRootRequest{
		Limit: 100,
	})
}

// BenchmarkDeleteFederationServer covers DeleteFederationServer with an
// empty server list. Exercises the proof-sync-log delete + RemoveServers
// fast paths even though both end up touching zero rows.
//
// bench:rpc=universerpc.Universe.DeleteFederationServer
func BenchmarkDeleteFederationServer(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.CommandBench(b, f.Server.DeleteFederationServer,
		&unirpc.DeleteFederationServerRequest{})
}

// BenchmarkSetFederationSyncConfig covers SetFederationSyncConfig with
// an empty config update.
//
// bench:rpc=universerpc.Universe.SetFederationSyncConfig
func BenchmarkSetFederationSyncConfig(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.CommandBench(b, f.Server.SetFederationSyncConfig,
		&unirpc.SetFederationSyncConfigRequest{})
}
