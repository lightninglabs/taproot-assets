package tapchannel

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestWarnMissingSpenderLeaves tests that a channel whose commitment carries
// no spender leaves is warned about once, and only while a proof activation
// height is set. The test changes the default activation height, so it must
// not run in parallel with other tests.
func TestWarnMissingSpenderLeaves(t *testing.T) {
	defer proof.SetDefaultActivationHeight(proof.DefaultActivationHeight())

	chanPoint := func(idx uint32) wire.OutPoint {
		return wire.OutPoint{
			Hash:  chainhash.Hash{0x7a, 0x9e},
			Index: idx,
		}
	}
	legacy := STXOFeatures{STXO: true}
	spender := STXOFeatures{STXO: true, Spender: true}

	// Without an activation height, nothing is warned about.
	proof.SetDefaultActivationHeight(lfn.None[uint32]())
	require.False(t, warnMissingSpenderLeaves(chanPoint(0), legacy))

	proof.SetDefaultActivationHeight(lfn.Some(uint32(100)))

	// A commitment with spender leaves is not warned about.
	require.False(t, warnMissingSpenderLeaves(chanPoint(1), spender))

	// A channel whose commitment lacks them is warned about once.
	require.True(t, warnMissingSpenderLeaves(chanPoint(2), legacy))
	require.False(t, warnMissingSpenderLeaves(chanPoint(2), legacy))

	// So is a channel without STXOs at all.
	require.True(t, warnMissingSpenderLeaves(chanPoint(3), STXOFeatures{}))
}

// TestWarnSplitTreeV0 tests that a channel whose commitment has BranchV0 split
// trees is warned about once, and only while a split tree activation height is
// set. The test changes the default split tree activation height, so it must
// not run in parallel with other tests.
func TestWarnSplitTreeV0(t *testing.T) {
	defer proof.SetDefaultSplitTreeActivationHeight(
		proof.DefaultSplitTreeActivationHeight(),
	)

	chanPoint := func(idx uint32) wire.OutPoint {
		return wire.OutPoint{
			Hash:  chainhash.Hash{0x5b, 0x71},
			Index: idx,
		}
	}
	v0 := STXOFeatures{STXO: true, Spender: true}
	v1 := STXOFeatures{STXO: true, Spender: true, SplitTreeV1: true}

	// Without a split tree activation height, nothing is warned about.
	proof.SetDefaultSplitTreeActivationHeight(lfn.None[uint32]())
	require.False(t, warnSplitTreeV0(chanPoint(0), v0))

	proof.SetDefaultSplitTreeActivationHeight(lfn.Some(uint32(100)))

	// A commitment with BranchV1 split trees is not warned about.
	require.False(t, warnSplitTreeV0(chanPoint(1), v1))

	// A channel whose commitment has BranchV0 split trees is warned
	// about once.
	require.True(t, warnSplitTreeV0(chanPoint(2), v0))
	require.False(t, warnSplitTreeV0(chanPoint(2), v0))
}
