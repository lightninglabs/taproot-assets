package proof

import (
	"context"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/vm"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

const (
	// MainNetSplitTreeActivationHeight is the block height from which
	// split commitment trees must have BranchV1 branches on mainnet.
	MainNetSplitTreeActivationHeight uint32 = 978_493

	// SigNetSplitTreeActivationHeight is the block height from which
	// split commitment trees must have BranchV1 branches on the default
	// signet.
	SigNetSplitTreeActivationHeight uint32 = 331_000

	// TestNet3SplitTreeActivationHeight is the block height from which
	// split commitment trees must have BranchV1 branches on testnet3.
	TestNet3SplitTreeActivationHeight uint32 = 5_360_000

	// TestNet4SplitTreeActivationHeight is the block height from which
	// split commitment trees must have BranchV1 branches on testnet4.
	TestNet4SplitTreeActivationHeight uint32 = 164_500
)

// NetworkSplitTreeActivationHeight returns the split tree activation height of
// the network with the given name, if it has one.
func NetworkSplitTreeActivationHeight(network string) lfn.Option[uint32] {
	switch network {
	case chaincfg.MainNetParams.Name:
		return lfn.Some(MainNetSplitTreeActivationHeight)

	case chaincfg.SigNetParams.Name:
		return lfn.Some(SigNetSplitTreeActivationHeight)

	case chaincfg.TestNet3Params.Name:
		return lfn.Some(TestNet3SplitTreeActivationHeight)

	case chaincfg.TestNet4Params.Name:
		return lfn.Some(TestNet4SplitTreeActivationHeight)

	default:
		return lfn.None[uint32]()
	}
}

// defaultSplitTreeActivationHeight is the split tree activation height used
// by a verifier context that sets none of its own. A daemon sets it once, at
// startup, for the network it runs on.
var defaultSplitTreeActivationHeight atomic.Pointer[uint32]

// SetDefaultSplitTreeActivationHeight sets the split tree activation height
// used by every verifier context that sets none of its own.
func SetDefaultSplitTreeActivationHeight(height lfn.Option[uint32]) {
	var h *uint32
	height.WhenSome(func(v uint32) {
		h = &v
	})
	defaultSplitTreeActivationHeight.Store(h)
}

// DefaultSplitTreeActivationHeight returns the split tree activation height
// used by every verifier context that sets none of its own.
func DefaultSplitTreeActivationHeight() lfn.Option[uint32] {
	height := defaultSplitTreeActivationHeight.Load()
	if height == nil {
		return lfn.None[uint32]()
	}

	return lfn.Some(*height)
}

// splitTreeActivationHeight returns the split tree activation height that
// applies to the verifier context: its own, or else the default.
func (v VerifierCtx) splitTreeActivationHeight() lfn.Option[uint32] {
	if v.SplitTreeActivationHeight.IsSome() {
		return v.SplitTreeActivationHeight
	}

	return DefaultSplitTreeActivationHeight()
}

// SplitTreeVersionsAt returns the branch versions that a split commitment tree
// anchored at the given height may have under the default split tree
// activation height.
func SplitTreeVersionsAt(height uint32) []mssmt.BranchVersion {
	activationHeight := DefaultSplitTreeActivationHeight()
	v1Required := lfn.MapOptionZ(activationHeight, func(h uint32) bool {
		return height >= h
	})

	return vm.SplitTreeVersions(v1Required)
}

// splitTreeVersions returns the branch versions that the split commitment
// tree of the proof's state transition may have. A proof is held to BranchV1
// on the terms activationRequired describes, with the split tree activation
// height. The chain tip is only consulted for a split transition.
func (p *Proof) splitTreeVersions(ctx context.Context, vCtx VerifierCtx,
	skipChainVerification bool) ([]mssmt.BranchVersion, error) {

	isSplit := p.Asset.SplitCommitmentRoot != nil ||
		p.Asset.HasSplitCommitmentWitness()
	if !isSplit {
		return vm.SplitTreeVersions(false), nil
	}

	v1Required, err := heightReached(
		ctx, p, vCtx, vCtx.splitTreeActivationHeight(),
		skipChainVerification,
	)
	if err != nil {
		return nil, err
	}

	return vm.SplitTreeVersions(v1Required), nil
}
