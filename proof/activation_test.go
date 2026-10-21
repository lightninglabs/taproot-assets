package proof

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// tipChainLookup is a mock chain lookup whose chain tip is fixed by the test.
type tipChainLookup struct {
	*mockChainLookup

	tip uint32
}

// CurrentHeight returns the fixed chain tip.
func (t *tipChainLookup) CurrentHeight(context.Context) (uint32, error) {
	return t.tip, nil
}

// GenFileChainLookup returns the lookup itself.
func (t *tipChainLookup) GenFileChainLookup(*File) asset.ChainLookup {
	return t
}

// GenProofChainLookup returns the lookup itself.
func (t *tipChainLookup) GenProofChainLookup(*Proof) (asset.ChainLookup,
	error) {

	return t, nil
}

// withChainTip returns a copy of the verifier context whose chain tip is
// fixed at the given height.
func withChainTip(vCtx VerifierCtx, tip uint32) VerifierCtx {
	vCtx.ChainLookupGen = &tipChainLookup{
		mockChainLookup: MockChainLookup,
		tip:             tip,
	}

	return vCtx
}

// TestActivationRequired tests when a proof is subject to the activation
// rules: a confirmed proof unless its chain-bound height is non-zero and
// below the activation height, an unconfirmed proof unless the block after
// the verifier's chain tip is below it.
func TestActivationRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		blockHeight      uint32
		activationHeight lfn.Option[uint32]
		skipChain        bool
		chainTip         uint32
		wantRequired     bool
	}{{
		name:         "activation unset",
		blockHeight:  150,
		wantRequired: false,
	}, {
		name:             "confirmed before activation",
		blockHeight:      99,
		activationHeight: lfn.Some(uint32(100)),
		wantRequired:     false,
	}, {
		name:             "confirmed at activation",
		blockHeight:      100,
		activationHeight: lfn.Some(uint32(100)),
		wantRequired:     true,
	}, {
		name:             "zero height",
		activationHeight: lfn.Some(uint32(100)),
		wantRequired:     true,
	}, {
		name:             "unconfirmed below activation",
		blockHeight:      99,
		activationHeight: lfn.Some(uint32(100)),
		skipChain:        true,
		chainTip:         98,
		wantRequired:     false,
	}, {
		name:             "unconfirmed at activation",
		blockHeight:      99,
		activationHeight: lfn.Some(uint32(100)),
		skipChain:        true,
		chainTip:         99,
		wantRequired:     true,
	}, {
		name:             "unconfirmed past activation",
		activationHeight: lfn.Some(uint32(100)),
		skipChain:        true,
		chainTip:         150,
		wantRequired:     true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &Proof{BlockHeight: tc.blockHeight}
			vCtx := withChainTip(MockVerifierCtx, tc.chainTip)
			vCtx.ActivationHeight = tc.activationHeight

			required, err := activationRequired(
				context.Background(), p, vCtx, tc.skipChain,
			)
			require.NoError(t, err)
			require.Equal(t, tc.wantRequired, required)
		})
	}
}

// TestActivationTransitionProofs tests that, once subject to the activation
// rules, the proofs of a split require transition version 1, the root locator
// proof, the STXO proofs of the split root and the spender proofs, while an
// exempt proof, and the issuance it descends from, verify without them.
func TestActivationTransitionProofs(t *testing.T) {
	t.Parallel()

	const (
		rootOutput = iota
		splitOutput
		btcOutput
		numOutputs
	)

	genesis := newSplitGenesis(t)
	split := &testSplit{
		rootOutput:   rootOutput,
		splitOutputs: []uint32{splitOutput},
		spenders:     true,
	}
	anchor := newTestSplitAnchor(
		t, genesis.inputs, numOutputs, genesis.sign, split,
	)

	rootProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.rootParams(t, split),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	splitProof, err := CreateTransitionProof(
		genesis.outPoint, anchor.splitParams(t, split, 0),
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	vCtx := MockVerifierCtx
	vCtx.ActivationHeight = lfn.Some(uint32(100))

	verify := func(p *Proof, vCtx VerifierCtx,
		opts ...VerifyOption) error {

		f, err := NewFile(V0, genesis.proof, *p)
		require.NoError(t, err)

		_, err = f.Verify(context.Background(), vCtx, opts...)

		return err
	}

	tests := []struct {
		name    string
		proof   *Proof
		mutate  func(p *Proof)
		wantErr error
	}{{
		name:   "root",
		proof:  rootProof,
		mutate: func(p *Proof) {},
	}, {
		name:   "split",
		proof:  splitProof,
		mutate: func(p *Proof) {},
	}, {
		name:  "root without spender proofs",
		proof: rootProof,
		mutate: func(p *Proof) {
			p.InclusionProof.CommitmentProof.SpenderProofs = nil
		},
		wantErr: ErrMissingSpenderProofs,
	}, {
		name:  "root without root locator proof",
		proof: rootProof,
		mutate: func(p *Proof) {
			p.RootLocatorProof = nil
		},
		wantErr: ErrMissingRootLocatorProof,
	}, {
		name:  "root of version 0",
		proof: rootProof,
		mutate: func(p *Proof) {
			p.Version = TransitionV0
		},
		wantErr: ErrTransitionV1Required,
	}, {
		name:  "split without split root STXO proofs",
		proof: splitProof,
		mutate: func(p *Proof) {
			p.SplitRootProof.CommitmentProof.STXOProofs = nil
		},
		wantErr: ErrMissingSplitSTXOProofs,
	}, {
		name:  "split without spender proofs",
		proof: splitProof,
		mutate: func(p *Proof) {
			p.SplitRootProof.CommitmentProof.SpenderProofs = nil
		},
		wantErr: ErrMissingSpenderProofs,
	}, {
		name:  "split without root locator proof",
		proof: splitProof,
		mutate: func(p *Proof) {
			p.RootLocatorProof = nil
		},
		wantErr: ErrMissingRootLocatorProof,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := copyProof(t, tc.proof)
			tc.mutate(p)

			// Anchored before the activation height, the proof
			// is exempt.
			p.BlockHeight = 99
			require.NoError(t, verify(p, vCtx))

			// Anchored at it, or claiming no height at all, the
			// proof must satisfy the activation rules.
			for _, height := range []uint32{100, 0} {
				p.BlockHeight = height
				err := verify(p, vCtx)
				if tc.wantErr == nil {
					require.NoError(t, err)
					continue
				}

				require.ErrorIs(t, err, tc.wantErr)
			}

			// Unconfirmed, the proof is exempt only while the
			// block after the chain tip is below the activation
			// height.
			skipFinal := WithSkipChainVerificationForFinalProof()
			p.BlockHeight = 99
			require.NoError(
				t, verify(p, withChainTip(vCtx, 98), skipFinal),
			)

			err := verify(p, withChainTip(vCtx, 99), skipFinal)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestNetworkActivationHeight tests the activation heights of the networks.
func TestNetworkActivationHeight(t *testing.T) {
	t.Parallel()

	require.Equal(
		t, lfn.Some(MainNetActivationHeight),
		NetworkActivationHeight(chaincfg.MainNetParams.Name),
	)
	require.Equal(
		t, lfn.Some(SigNetActivationHeight),
		NetworkActivationHeight(chaincfg.SigNetParams.Name),
	)
	require.Equal(
		t, lfn.Some(TestNet3ActivationHeight),
		NetworkActivationHeight(chaincfg.TestNet3Params.Name),
	)
	require.Equal(
		t, lfn.Some(TestNet4ActivationHeight),
		NetworkActivationHeight(chaincfg.TestNet4Params.Name),
	)

	for _, params := range []chaincfg.Params{
		chaincfg.RegressionNetParams, chaincfg.SimNetParams,
	} {
		require.True(t, NetworkActivationHeight(params.Name).IsNone())
	}
}

// TestDefaultActivationHeight tests that a verifier context without an
// activation height of its own applies the default. The test changes the
// default, so it must not run in parallel with other tests.
func TestDefaultActivationHeight(t *testing.T) {
	defer SetDefaultActivationHeight(DefaultActivationHeight())

	SetDefaultActivationHeight(lfn.None[uint32]())
	require.True(t, MockVerifierCtx.activationHeight().IsNone())

	SetDefaultActivationHeight(lfn.Some(uint32(100)))
	require.Equal(
		t, lfn.Some(uint32(100)), MockVerifierCtx.activationHeight(),
	)

	vCtx := MockVerifierCtx
	vCtx.ActivationHeight = lfn.Some(uint32(200))
	require.Equal(t, lfn.Some(uint32(200)), vCtx.activationHeight())

	// A V0 proof anchored past the default activation height is rejected
	// by a verifier context that sets no height of its own.
	p := &Proof{BlockHeight: 150}
	err := p.verifyActivation(
		context.Background(), MockVerifierCtx, false,
	)
	require.ErrorIs(t, err, ErrTransitionV1Required)
}
