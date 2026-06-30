package rpc

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
)

// keyFamily is the Taproot Assets key family. The MockKeyRing only has a
// derivation rule installed for this family, so other values panic.
const keyFamily = 212

// BenchmarkNextInternalKey covers NextInternalKey. Requires AddrBook +
// MockKeyRing — both populated by the Storage fixture.
//
// bench:rpc=assetwalletrpc.AssetWallet.NextInternalKey
func BenchmarkNextInternalKey(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.CommandBench(b, f.Server.NextInternalKey,
		&wrpc.NextInternalKeyRequest{KeyFamily: keyFamily})
}

// BenchmarkNextScriptKey covers NextScriptKey.
//
// bench:rpc=assetwalletrpc.AssetWallet.NextScriptKey
func BenchmarkNextScriptKey(b *testing.B) {
	f := fixture.NewStorage(b)
	fixture.CommandBench(b, f.Server.NextScriptKey,
		&wrpc.NextScriptKeyRequest{KeyFamily: keyFamily})
}

// BenchmarkRemoveUTXOLease covers RemoveUTXOLease — exercises the
// CoinSelect release path against the AssetStore. The synthetic outpoint
// is not actually leased; ReleaseCoins issues a DELETE that matches no
// rows but still runs the full transaction (marshal + open txn + delete
// + commit). That measures the dominant per-call cost and matches what
// callers pay for any release request, leased or not.
//
// bench:rpc=assetwalletrpc.AssetWallet.RemoveUTXOLease
func BenchmarkRemoveUTXOLease(b *testing.B) {
	f := fixture.NewSend(b)

	txid := make([]byte, 32)
	for i := range txid {
		txid[i] = byte(i + 1)
	}
	req := &wrpc.RemoveUTXOLeaseRequest{
		Outpoint: &taprpc.OutPoint{
			Txid:        txid,
			OutputIndex: 0,
		},
	}

	fixture.CommandBench(b, f.Server.RemoveUTXOLease, req)
}
