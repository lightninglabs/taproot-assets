// Package rpc contains per-RPC benchmarks for the taprootassets daemon. Each
// .proto service has its own file; methods are bound to a graduated fixture
// from bench/fixture per the dependency surface their handlers require.
//
// This file is the first per-RPC bench file: it covers the methods that the
// Minimal fixture is sufficient for. Methods requiring populated db state
// (List*, Query*, Decode-with-marshal) wait for the Storage fixture; methods
// requiring active subsystems wait for Mint/Send/UniverseSync.
package rpc

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// loadProofFileBlob loads the canonical test proof file from the proof
// package's testdata directory and returns its raw bytes.
func loadProofFileBlob(b *testing.B) []byte {
	b.Helper()
	const path = "../../proof/testdata/proof-file.hex"

	raw, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("read proof file: %v", err)
	}
	blob, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		b.Fatalf("decode proof file hex: %v", err)
	}
	return blob
}

// BenchmarkDebugLevel covers the DebugLevel RPC. It reads only LogMgr off
// the config and serves as the smallest end-to-end proof of the fixture +
// shape-template wiring.
//
// bench:rpc=taprpc.TaprootAssets.DebugLevel
func BenchmarkDebugLevel(b *testing.B) {
	f := fixture.NewMinimal(b)
	fixture.QueryBench(b, f.Server.DebugLevel, &taprpc.DebugLevelRequest{
		Show: true,
	})
}

// BenchmarkUnpackProofFile covers UnpackProofFile, which decodes a proof
// file blob and returns its constituent raw proofs. It has no subsystem
// dependencies — pure parser + memory copy.
//
// bench:rpc=taprpc.TaprootAssets.UnpackProofFile
func BenchmarkUnpackProofFile(b *testing.B) {
	f := fixture.NewMinimal(b)
	blob := loadProofFileBlob(b)
	fixture.QueryBench(b, f.Server.UnpackProofFile,
		&taprpc.UnpackProofFileRequest{
			RawProofFile: blob,
		})
}

// BenchmarkListAssets covers ListAssets against an empty AssetStore. The
// empty-store path is the relevant baseline for query overhead; populated-
// store variants are added as scenarios.
//
// bench:rpc=taprpc.TaprootAssets.ListAssets
func BenchmarkListAssets(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListAssets, &taprpc.ListAssetRequest{})
}

// BenchmarkListUtxos covers ListUtxos against an empty AssetStore.
//
// bench:rpc=taprpc.TaprootAssets.ListUtxos
func BenchmarkListUtxos(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListUtxos, &taprpc.ListUtxosRequest{})
}

// BenchmarkListGroups covers ListGroups against an empty AssetStore.
//
// bench:rpc=taprpc.TaprootAssets.ListGroups
func BenchmarkListGroups(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListGroups, &taprpc.ListGroupsRequest{})
}

// BenchmarkListBalances covers ListBalances grouped by asset.
//
// bench:rpc=taprpc.TaprootAssets.ListBalances
func BenchmarkListBalances(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListBalances,
		&taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_AssetId{
				AssetId: true,
			},
		})
}

// BenchmarkListTransfers covers ListTransfers against an empty AssetStore.
//
// bench:rpc=taprpc.TaprootAssets.ListTransfers
func BenchmarkListTransfers(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListTransfers,
		&taprpc.ListTransfersRequest{})
}

// BenchmarkListBurns covers ListBurns against an empty AssetStore.
//
// bench:rpc=taprpc.TaprootAssets.ListBurns
func BenchmarkListBurns(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.ListBurns, &taprpc.ListBurnsRequest{})
}

// BenchmarkQueryAddrs covers QueryAddrs against an empty TapAddrBook.
//
// bench:rpc=taprpc.TaprootAssets.QueryAddrs
func BenchmarkQueryAddrs(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.QueryAddrs, &taprpc.QueryAddrRequest{})
}

// BenchmarkDecodeAddr covers DecodeAddr — bech32m parse + marshal. Exercises
// TapAddrBook on the marshal path even though the address isn't found.
//
// bench:rpc=taprpc.TaprootAssets.DecodeAddr
func BenchmarkDecodeAddr(b *testing.B) {
	f := fixture.NewStorage(b)

	addr, _, _ := address.RandAddrWithVersion(
		b, &address.RegressionNetTap,
		address.RandProofCourierAddr(b), address.V1,
	)
	encoded, err := addr.Tap.EncodeAddress()
	require.NoError(b, err)

	fixture.QueryBench(b, f.Server.DecodeAddr,
		&taprpc.DecodeAddrRequest{Addr: encoded})
}

// BenchmarkAddrReceives covers AddrReceives against an empty event log.
//
// bench:rpc=taprpc.TaprootAssets.AddrReceives
func BenchmarkAddrReceives(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.QueryBench(b, f.Server.AddrReceives,
		&taprpc.AddrReceivesRequest{})
}
