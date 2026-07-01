package universe

import (
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// leafEntries wraps a slice of LeafKey into a slice of LeafEntry
// with no node hash. This exercises diffLeafEntries in its key-only
// fallback mode — the semantics the legacy keyset-only diff pinned.
func leafEntries(keys ...LeafKey) []LeafEntry {
	entries := make([]LeafEntry, len(keys))
	for i, k := range keys {
		entries[i] = LeafEntry{
			Key:      k,
			NodeHash: fn.None[mssmt.NodeHash](),
		}
	}
	return entries
}

// leafEntriesWithHash wraps a slice of LeafKey into a slice of
// LeafEntry, deriving each entry's node hash deterministically from
// its universe key so that identical keys yield identical hashes.
// Exercises diffLeafEntries in its content-aware mode.
func leafEntriesWithHash(keys ...LeafKey) []LeafEntry {
	entries := make([]LeafEntry, len(keys))
	for i, k := range keys {
		hash := mssmt.NodeHash(k.UniverseKey())
		entries[i] = LeafEntry{
			Key:      k,
			NodeHash: fn.Some(hash),
		}
	}
	return entries
}

// TestDiffLeafEntries_PointerInvariance is the direct regression for
// issue #2026's diff bug: two BaseLeafKey values with identical
// outpoint + script pubkey but freshly-allocated ScriptKey pointers
// must be treated as equal by the diff, so that a mostly-synced node
// stops re-fetching every remote leaf on each sync.
func TestDiffLeafEntries_PointerInvariance(t *testing.T) {
	t.Parallel()

	outpoint := test.RandOp(t)
	pubKey := test.RandPubKey(t)

	// Same content, distinct pointer addresses.
	a := BaseLeafKey{
		OutPoint:  outpoint,
		ScriptKey: fn.Ptr(asset.NewScriptKey(pubKey)),
	}
	b := BaseLeafKey{
		OutPoint:  outpoint,
		ScriptKey: fn.Ptr(asset.NewScriptKey(pubKey)),
	}

	require.NotSame(t, a.ScriptKey, b.ScriptKey,
		"test presupposes distinct pointer addresses")

	require.Empty(t, diffLeafEntries(
		leafEntries(a), leafEntries(b),
	))
}

// TestDiffLeafEntries_ReturnsMissing checks the positive case: a leaf
// present only in remote is returned.
func TestDiffLeafEntries_ReturnsMissing(t *testing.T) {
	t.Parallel()

	shared := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}
	only := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}

	diff := diffLeafEntries(
		leafEntries(shared, only), leafEntries(shared),
	)
	require.Len(t, diff, 1)
	require.Equal(t, only.UniverseKey(), diff[0].UniverseKey())
}

// TestDiffLeafEntries_PreservesRemoteOrder pins the subsequence
// invariant: survivors appear in the same order as they did in
// remote. Downstream error attribution indexes into the returned
// slice.
func TestDiffLeafEntries_PreservesRemoteOrder(t *testing.T) {
	t.Parallel()

	// Build a run of remote keys and remove the middle one from local.
	remote := make([]LeafKey, 5)
	for i := range remote {
		remote[i] = BaseLeafKey{
			OutPoint: wire.OutPoint{
				Hash: [32]byte{byte(i)}, Index: uint32(i),
			},
			ScriptKey: fn.Ptr(asset.NewScriptKey(
				test.RandPubKey(t),
			)),
		}
	}

	// Local has everything except remote[2].
	local := append([]LeafKey{}, remote[:2]...)
	local = append(local, remote[3:]...)

	diff := diffLeafEntries(leafEntries(remote...), leafEntries(local...))
	require.Len(t, diff, 1)
	require.Equal(t, remote[2].UniverseKey(), diff[0].UniverseKey())
}

// TestDiffLeafEntries_SharedKeyContentMismatch pins the content-aware
// case that motivated the wire change: same universe key on both
// sides, disagreeing leaf node hashes, must be surfaced for refetch.
// Under the legacy keyset-only diff this shared key would never
// appear in the result.
func TestDiffLeafEntries_SharedKeyContentMismatch(t *testing.T) {
	t.Parallel()

	shared := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}

	remote := []LeafEntry{{
		Key:      shared,
		NodeHash: fn.Some(mssmt.NodeHash{0x01}),
	}}
	local := []LeafEntry{{
		Key:      shared,
		NodeHash: fn.Some(mssmt.NodeHash{0x02}),
	}}

	diff := diffLeafEntries(remote, local)
	require.Len(t, diff, 1)
	require.Equal(t, shared.UniverseKey(), diff[0].UniverseKey())
}

// TestDiffLeafEntries_SharedKeyContentMatch pins the converse: same
// key, same hash on both sides is a no-op.
func TestDiffLeafEntries_SharedKeyContentMatch(t *testing.T) {
	t.Parallel()

	shared := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}

	diff := diffLeafEntries(
		leafEntriesWithHash(shared), leafEntriesWithHash(shared),
	)
	require.Empty(t, diff)
}

// TestDiffLeafEntries_RemoteSubsetIsNoop pins the peer-is-behind
// case: when every remote key is also in local, no leaf is fetched.
// The legacy diff's empty-diff-with-diverging-roots fallback used
// to spend a full refetch here; the entry-based diff makes it a
// no-op by construction.
func TestDiffLeafEntries_RemoteSubsetIsNoop(t *testing.T) {
	t.Parallel()

	shared := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}
	localExtra := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}

	diff := diffLeafEntries(
		leafEntriesWithHash(shared),
		leafEntriesWithHash(shared, localExtra),
	)
	require.Empty(t, diff)
}
