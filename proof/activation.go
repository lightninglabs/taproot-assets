package proof

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

const (
	// MainNetActivationHeight is the block height from which the
	// activation rules apply to transition proofs on mainnet.
	MainNetActivationHeight uint32 = 971_750

	// SigNetActivationHeight is the block height from which the
	// activation rules apply to transition proofs on the default signet.
	SigNetActivationHeight uint32 = 326_200
)

var (
	// ErrTransitionV1Required is returned when a V0 transition proof is
	// subject to the activation rules.
	ErrTransitionV1Required = errors.New(
		"transition proof version 1 required",
	)

	// ErrMissingRootLocatorProof is returned when a split transition
	// proof that is subject to the activation rules omits the root
	// locator proof.
	ErrMissingRootLocatorProof = errors.New("missing root locator proof")

	// ErrMissingSplitSTXOProofs is returned when the proof of a split
	// asset that is subject to the activation rules omits the STXO
	// proofs of its root asset.
	ErrMissingSplitSTXOProofs = errors.New(
		"missing STXO proofs of split root",
	)

	// ErrMissingSpenderProofs is returned when a transition proof that is
	// subject to the activation rules omits the spender proofs of its
	// transfer root.
	ErrMissingSpenderProofs = errors.New("missing spender proofs")
)

// NetworkActivationHeight returns the activation height of the network with
// the given name, if it has one.
func NetworkActivationHeight(network string) lfn.Option[uint32] {
	switch network {
	case chaincfg.MainNetParams.Name:
		return lfn.Some(MainNetActivationHeight)

	case chaincfg.SigNetParams.Name:
		return lfn.Some(SigNetActivationHeight)

	default:
		return lfn.None[uint32]()
	}
}

// defaultActivationHeight is the activation height used by a verifier
// context that sets none of its own. A daemon sets it once, at startup, for
// the network it runs on.
var defaultActivationHeight atomic.Pointer[uint32]

// SetDefaultActivationHeight sets the activation height used by every
// verifier context that sets none of its own.
func SetDefaultActivationHeight(height lfn.Option[uint32]) {
	var h *uint32
	height.WhenSome(func(v uint32) {
		h = &v
	})
	defaultActivationHeight.Store(h)
}

// DefaultActivationHeight returns the activation height used by every
// verifier context that sets none of its own.
func DefaultActivationHeight() lfn.Option[uint32] {
	height := defaultActivationHeight.Load()
	if height == nil {
		return lfn.None[uint32]()
	}

	return lfn.Some(*height)
}

// activationHeight returns the activation height that applies to the
// verifier context: its own, or else the default.
func (v VerifierCtx) activationHeight() lfn.Option[uint32] {
	if v.ActivationHeight.IsSome() {
		return v.ActivationHeight
	}

	return DefaultActivationHeight()
}

// activationRequired reports whether a proof must satisfy the activation
// rules. A confirmed proof is exempt only if chain verification authenticates
// a non-zero claimed height below the activation height; a zero height is not
// bound to the anchor block by the production header verifier. An unconfirmed
// proof has no authenticated height, so the verifier's chain tip stands in for
// it: the proof cannot confirm before the next block, and it is exempt only
// while that block lies below the activation height.
func activationRequired(ctx context.Context, p *Proof, vCtx VerifierCtx,
	skipChainVerification bool) (bool, error) {

	height := vCtx.activationHeight()
	if height.IsNone() {
		return false, nil
	}
	activationHeight := height.UnwrapOr(0)

	if !skipChainVerification {
		required := p.BlockHeight == 0 ||
			p.BlockHeight >= activationHeight

		return required, nil
	}

	if vCtx.ChainLookupGen == nil {
		return false, fmt.Errorf("no chain lookup to resolve the " +
			"activation height for an unconfirmed proof")
	}

	chainLookup, err := vCtx.ChainLookupGen.GenProofChainLookup(p)
	if err != nil {
		return false, err
	}

	tip, err := chainLookup.CurrentHeight(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to fetch chain tip: %w", err)
	}

	return uint64(tip)+1 >= uint64(activationHeight), nil
}

// hasSpenderProofs returns true if the proof carries the spender proofs of its
// transfer root: on its inclusion proof for a root asset, or on its split root
// proof for a split asset.
func (p *Proof) hasSpenderProofs() bool {
	rootProof := &p.InclusionProof
	if p.Asset.HasSplitCommitmentWitness() {
		rootProof = p.SplitRootProof
	}

	return rootProof != nil && rootProof.CommitmentProof != nil &&
		len(rootProof.CommitmentProof.SpenderProofs) > 0
}

// missingActivationEvidence returns the first activation rule that the proof
// does not satisfy, or nil if it satisfies them all. The rules require
// transition version 1, the root locator proof of a split transition, the STXO
// proofs of the root of a split asset, and the spender proofs of the transfer
// root. An issuance spends no inputs, so none of them apply to it.
func (p *Proof) missingActivationEvidence() error {
	if p.Asset.IsGenesisAsset() {
		return nil
	}

	isSplit := p.Asset.SplitCommitmentRoot != nil ||
		p.Asset.HasSplitCommitmentWitness()

	switch {
	case p.Version == TransitionV0:
		return ErrTransitionV1Required

	case isSplit && p.RootLocatorProof == nil:
		return ErrMissingRootLocatorProof

	case p.Asset.HasSplitCommitmentWitness() &&
		!p.hasSplitRootSTXOProofs():

		return ErrMissingSplitSTXOProofs

	case !p.hasSpenderProofs():
		return ErrMissingSpenderProofs
	}

	return nil
}

// verifyActivation enforces the activation rules on a proof. The activation
// rules, and with them the chain tip, are only consulted for a proof that
// would fail one of them.
func (p *Proof) verifyActivation(ctx context.Context, vCtx VerifierCtx,
	skipChainVerification bool) error {

	missing := p.missingActivationEvidence()
	if missing == nil {
		return nil
	}

	required, err := activationRequired(
		ctx, p, vCtx, skipChainVerification,
	)
	if err != nil {
		return err
	}
	if !required {
		return nil
	}

	return fmt.Errorf("%w: proof at height %d", missing, p.BlockHeight)
}
