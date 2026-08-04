package rpcserver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// syncDeltaHarness bundles a minimally wired RPCServer whose universe
// archive is seeded with random leaves, together with the federation DB
// that controls export gating.
type syncDeltaHarness struct {
	rpc   *RPCServer
	fedDB *tapdb.UniverseFederationDB
	arch  *universe.Archive
}

// loadOddBlock loads the shared odd-transaction-count block fixture
// that proof.RandProof anchors its proofs in.
func loadOddBlock(t *testing.T) wire.MsgBlock {
	t.Helper()

	oddTxBlockHex, err := os.ReadFile(
		"../proof/testdata/odd-block.hex",
	)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	return oddTxBlock
}

// seedUniverse inserts n random leaves into the given universe of the
// harness archive's multiverse store.
func seedUniverse(t *testing.T, mv *tapdb.MultiverseStore,
	id universe.Identifier, assetGen asset.Genesis, block wire.MsgBlock,
	n int) {

	t.Helper()

	ctx := context.Background()
	for i := 0; i < n; i++ {
		scriptKey := test.RandPubKey(t)
		p := proof.RandProof(t, assetGen, scriptKey, block, 0, 1)

		proofBytes, err := p.Bytes()
		require.NoError(t, err)

		leaf := &universe.Leaf{
			GenesisWithGroup: universe.GenesisWithGroup{
				Genesis: assetGen,
			},
			RawProof: proofBytes,
			Asset:    &p.Asset,
			Amt:      p.Asset.Amount,
		}
		key := universe.BaseLeafKey{
			OutPoint: test.RandOp(t),
			ScriptKey: fn.Ptr(
				asset.NewScriptKey(scriptKey),
			),
		}

		_, err = mv.UpsertProofLeaf(ctx, id, key, leaf, nil)
		require.NoError(t, err)
	}
}

// newSyncDeltaHarness wires the minimal RPCServer dependencies the
// SyncDelta handler touches: the universe archive, the federation sync
// config DB, and the address book (for asset leaf marshaling). The
// archive is seeded with 3 issuance universes of 4 leaves each and 2
// transfer universes of 3 leaves each.
func newSyncDeltaHarness(t *testing.T) *syncDeltaHarness {
	t.Helper()

	clk := clock.NewTestClock(time.Unix(1_700_000_000, 0))
	db := tapdb.NewTestDB(t)

	multiverseTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	mv, err := tapdb.NewMultiverseStore(
		multiverseTx, tapdb.DefaultMultiverseStoreConfig(),
	)
	require.NoError(t, err)

	uniTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
	statsTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.UniverseStatsStore {
			return db.WithTx(tx)
		},
	)

	arch := universe.NewArchive(universe.ArchiveConfig{
		NewBaseTree: func(
			id universe.Identifier) universe.StorageBackend {

			return tapdb.NewBaseUniverseTree(uniTx, id)
		},
		HeaderVerifier:       proof.MockHeaderVerifier,
		MerkleVerifier:       proof.DefaultMerkleVerifier,
		GroupVerifier:        proof.MockGroupVerifier,
		ChainLookupGenerator: proof.MockChainLookup,
		Multiverse:           mv,
		UniverseStats:        tapdb.NewUniverseStats(statsTx, clk),
		IgnoreChecker:        lfn.None[proof.IgnoreChecker](),
	})

	// Seed: 3 issuance universes x 4 leaves, 2 transfer universes x 3
	// leaves. Universe IDs derive from each universe's asset genesis,
	// matching production.
	oddBlock := loadOddBlock(t)
	for i := 0; i < 3; i++ {
		assetGen := asset.RandGenesis(t, asset.Normal)
		seedUniverse(t, mv, universe.Identifier{
			AssetID:   assetGen.ID(),
			ProofType: universe.ProofTypeIssuance,
		}, assetGen, oddBlock, 4)
	}
	for i := 0; i < 2; i++ {
		assetGen := asset.RandGenesis(t, asset.Normal)
		seedUniverse(t, mv, universe.Identifier{
			AssetID:   assetGen.ID(),
			ProofType: universe.ProofTypeTransfer,
		}, assetGen, oddBlock, 3)
	}

	fedTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.UniverseServerStore {
			return db.WithTx(tx)
		},
	)
	fedDB := tapdb.NewUniverseFederationDB(fedTx, clk)

	addrTx := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.AddrBook {
			return db.WithTx(tx)
		},
	)
	tapAddrBook := tapdb.NewTapAddressBook(
		addrTx, &address.RegressionNetTap, clk,
	)
	addrBook := address.NewBook(address.BookConfig{
		Store: tapAddrBook,
		Chain: address.RegressionNetTap,
	})

	r := NewRPCServer()
	r.cfg = &tapconfig.Config{
		DatabaseConfig: &tapconfig.DatabaseConfig{
			FederationDB: fedDB,
		},
		UniverseArchive: arch,
		AddrBook:        addrBook,
	}
	r.proofQueryRateLimiter = rate.NewLimiter(rate.Inf, 1)

	// Enable export globally for both proof types, matching a fresh
	// tapd's default.
	ctx := context.Background()
	err = fedDB.UpsertFederationSyncConfig(
		ctx, []*universe.FedGlobalSyncConfig{
			{
				ProofType:       universe.ProofTypeIssuance,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
			{
				ProofType:       universe.ProofTypeTransfer,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
		}, nil,
	)
	require.NoError(t, err)

	return &syncDeltaHarness{
		rpc:   r,
		fedDB: fedDB,
		arch:  arch,
	}
}

// serverRoots enumerates the universe roots of the harness archive.
func (h *syncDeltaHarness) serverRoots(t *testing.T) []universe.Root {
	t.Helper()

	roots, err := h.arch.RootNodes(
		context.Background(), universe.RootNodesQuery{Limit: 500},
	)
	require.NoError(t, err)
	return roots
}

// TestSyncDelta exercises the SyncDelta handler: full fetch, export
// gating, paging via the cursor, and inclusion proof validity.
func TestSyncDelta(t *testing.T) {
	ctx := context.Background()
	h := newSyncDeltaHarness(t)

	// The fixture seeds 3 issuance universes with 4 leaves each and 2
	// transfer universes with 3 leaves each.
	const totalLeaves = 3*4 + 2*3

	roots := h.serverRoots(t)
	require.Len(t, roots, 5)

	// Disable export for one issuance universe; its leaves must be
	// omitted from every response while still advancing the cursor.
	var disabled universe.Identifier
	for _, root := range roots {
		if root.ID.ProofType == universe.ProofTypeIssuance {
			disabled = root.ID
			break
		}
	}
	err := h.fedDB.UpsertFederationSyncConfig(
		ctx, nil, []*universe.FedUniSyncConfig{{
			UniverseID:      disabled,
			AllowSyncInsert: true,
			AllowSyncExport: false,
		}},
	)
	require.NoError(t, err)

	// A single large page returns every exportable leaf.
	full, err := h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		SinceSeq: 0,
		PageSize: 100,
	})
	require.NoError(t, err)
	require.Len(t, full.Items, totalLeaves-4)

	// Sequence numbers are strictly increasing and the disabled
	// universe never appears.
	rootsByUni := make(map[universe.IdentifierKey]*unirpc.UniverseRoot)
	for _, rpcRoot := range full.UniverseRoots {
		id, err := UnmarshalUniID(rpcRoot.Id)
		require.NoError(t, err)
		rootsByUni[id.Key()] = rpcRoot
	}
	require.Len(t, rootsByUni, 4)
	require.NotContains(t, rootsByUni, disabled.Key())

	var lastSeq uint64
	for _, item := range full.Items {
		require.Greater(t, item.Seq, lastSeq)
		lastSeq = item.Seq

		id, err := UnmarshalUniID(item.UniverseId)
		require.NoError(t, err)
		require.False(t, id.IsEqual(disabled))

		// Every item's inclusion proof must bind its leaf to the
		// universe root reported in the same response.
		rpcRoot, ok := rootsByUni[id.Key()]
		require.True(t, ok)

		leafKey, err := unmarshalLeafKey(item.Key)
		require.NoError(t, err)

		leaf, err := unmarshalAssetLeaf(item.Leaf)
		require.NoError(t, err)

		var compressedProof mssmt.CompressedProof
		require.NoError(t, compressedProof.Decode(
			bytes.NewReader(item.UniverseInclusionProof),
		))
		inclusionProof, err := compressedProof.Decompress()
		require.NoError(t, err)

		uniRoot, err := unmarshalUniverseRoot(rpcRoot)
		require.NoError(t, err)

		uniProof := &universe.Proof{
			LeafKey:                leafKey,
			UniverseRoot:           uniRoot,
			UniverseInclusionProof: inclusionProof,
			Leaf:                   leaf,
		}
		require.True(t, uniProof.VerifyRoot(uniRoot))
	}

	// The cursor is a position in the insertion log: filtered leaves
	// advance it too, so resuming from latest_seq yields nothing new.
	require.GreaterOrEqual(t, full.LatestSeq, lastSeq)
	empty, err := h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		SinceSeq: full.LatestSeq,
	})
	require.NoError(t, err)
	require.Empty(t, empty.Items)
	require.Equal(t, full.LatestSeq, empty.LatestSeq)

	// Paging with a small page size walks the same item sequence.
	var (
		paged  []*unirpc.SyncDeltaItem
		cursor uint64
	)
	for {
		page, err := h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
			SinceSeq: cursor,
			PageSize: 5,
		})
		require.NoError(t, err)

		paged = append(paged, page.Items...)
		if page.LatestSeq == cursor {
			break
		}
		cursor = page.LatestSeq
	}
	require.Len(t, paged, len(full.Items))
	for i := range paged {
		require.Equal(t, full.Items[i].Seq, paged[i].Seq)
	}

	// Invalid page sizes are rejected.
	_, err = h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		PageSize: -1,
	})
	require.ErrorContains(t, err, "invalid page size")

	_, err = h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		PageSize: universe.MaxPageSize + 1,
	})
	require.ErrorContains(t, err, "exceeds maximum")
}

// TestSyncDeltaByteBudget pins that a page is cut short once the
// response byte budget is exhausted, while always admitting at least
// one item so the caller can make progress.
func TestSyncDeltaByteBudget(t *testing.T) {
	ctx := context.Background()
	h := newSyncDeltaHarness(t)

	// Shrink the budget so any single item exceeds it.
	oldBudget := syncDeltaByteBudget
	syncDeltaByteBudget = 1
	t.Cleanup(func() {
		syncDeltaByteBudget = oldBudget
	})

	// Every page must carry exactly one item: the first item is always
	// admitted, and any further item would exceed the budget.
	page, err := h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		SinceSeq: 0,
		PageSize: 100,
	})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)

	// The cursor points at the single included item, so the next page
	// resumes right after it.
	next, err := h.rpc.SyncDelta(ctx, &unirpc.SyncDeltaRequest{
		SinceSeq: page.LatestSeq,
		PageSize: 100,
	})
	require.NoError(t, err)
	require.Len(t, next.Items, 1)
	require.Greater(t, next.Items[0].Seq, page.Items[0].Seq)
}
