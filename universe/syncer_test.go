package universe

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestDiffLeafKeys_PointerInvariance is the direct regression for
// issue #2026's diff bug: two BaseLeafKey values with identical
// outpoint + script pubkey but freshly-allocated ScriptKey pointers
// must be treated as equal by the diff, so that a mostly-synced node
// stops re-fetching every remote leaf on each sync.
func TestDiffLeafKeys_PointerInvariance(t *testing.T) {
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

	require.Empty(t, diffLeafKeys(
		[]LeafKey{a}, []LeafKey{b},
	))
}

// TestDiffLeafKeys_ReturnsMissing checks the positive case: a leaf
// present only in remote is returned.
func TestDiffLeafKeys_ReturnsMissing(t *testing.T) {
	t.Parallel()

	shared := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}
	only := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}

	diff := diffLeafKeys(
		[]LeafKey{shared, only}, []LeafKey{shared},
	)
	require.Len(t, diff, 1)
	require.Equal(t, only.UniverseKey(), diff[0].UniverseKey())
}

// TestDiffLeafKeys_PreservesRemoteOrder pins the subsequence invariant:
// survivors appear in the same order as they did in remote. Downstream
// error attribution indexes into the returned slice, so the property
// matters at the call site.
func TestDiffLeafKeys_PreservesRemoteOrder(t *testing.T) {
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

	diff := diffLeafKeys(remote, local)
	require.Len(t, diff, 1)
	require.Equal(t, remote[2].UniverseKey(), diff[0].UniverseKey())
}
