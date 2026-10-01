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
