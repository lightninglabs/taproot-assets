package supplyverifier

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// newTestVerifierCfg returns a VerifierCfg with all required fields populated
// with minimal non-nil stubs.
func newTestVerifierCfg(t *testing.T) VerifierCfg {
	t.Helper()

	return VerifierCfg{
		AssetSpec:        createTestAssetSpec(t),
		ChainBridge:      tapgarden.NewMockChainBridge(),
		AssetLookup:      &supplycommit.MockAssetLookup{},
		Lnd:              &lndclient.LndServices{},
		GroupFetcher:     &MockGroupFetcher{},
		SupplyCommitView: &MockSupplyCommitView{},
		SupplyTreeView:   &MockSupplyTreeView{},
	}
}

// TestVerifierCfgValidate tests that VerifierCfg.Validate returns an error
// when any required field is nil, and succeeds when all fields are present.
func TestVerifierCfgValidate(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*VerifierCfg)
		expectError bool
	}{
		{
			name:        "valid config",
			mutate:      func(_ *VerifierCfg) {},
			expectError: false,
		},
		{
			name: "nil chain bridge",
			mutate: func(cfg *VerifierCfg) {
				cfg.ChainBridge = nil
			},
			expectError: true,
		},
		{
			name: "nil asset lookup",
			mutate: func(cfg *VerifierCfg) {
				cfg.AssetLookup = nil
			},
			expectError: true,
		},
		{
			name: "nil lnd services",
			mutate: func(cfg *VerifierCfg) {
				cfg.Lnd = nil
			},
			expectError: true,
		},
		{
			name: "nil group fetcher",
			mutate: func(cfg *VerifierCfg) {
				cfg.GroupFetcher = nil
			},
			expectError: true,
		},
		{
			name: "nil supply commit view",
			mutate: func(cfg *VerifierCfg) {
				cfg.SupplyCommitView = nil
			},
			expectError: true,
		},
		{
			name: "nil supply tree view",
			mutate: func(cfg *VerifierCfg) {
				cfg.SupplyTreeView = nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestVerifierCfg(t)
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestNewVerifier tests that NewVerifier rejects invalid configs and returns
// a properly initialised Verifier for valid ones.
func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(*VerifierCfg)
		expectError   bool
		checkVerifier func(*testing.T, Verifier, VerifierCfg)
	}{
		{
			name: "invalid config rejected",
			mutate: func(cfg *VerifierCfg) {
				cfg.ChainBridge = nil
			},
			expectError:   true,
			checkVerifier: nil,
		},
		{
			name:   "valid config accepted",
			mutate: func(_ *VerifierCfg) {},
			checkVerifier: func(
				t *testing.T,
				v Verifier,
				cfg VerifierCfg,
			) {

				require.Equal(t, cfg, v.cfg)
				require.NotNil(t, v.assetLog)
				v.assetLog.Debugf(
					"test log message from TestNewVerifier",
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestVerifierCfg(t)
			tt.mutate(&cfg)

			v, err := NewVerifier(cfg)
			if tt.expectError {
				require.Error(t, err)
				require.ErrorContains(
					t, err, "invalid verifier config",
				)
				return
			}

			require.NoError(t, err)
			if tt.checkVerifier != nil {
				tt.checkVerifier(t, v, cfg)
			}
		})
	}
}

// TestIsEquivalentPubKeys tests BIP340-based public key equivalence.
// Three cases are covered:
//
//   - Same key is equivalent to itself.
//   - Two distinct keys are not equivalent.
//   - A key and its parity-negated counterpart (same x-coordinate, opposite
//     y) are equivalent under BIP340 x-only serialization.
func TestIsEquivalentPubKeys(t *testing.T) {
	privKeyA, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privKeyB, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name     string
		a        *btcec.PublicKey
		b        *btcec.PublicKey
		expected bool
	}{
		{
			name:     "same key is equivalent",
			a:        privKeyA.PubKey(),
			b:        privKeyA.PubKey(),
			expected: true,
		},
		{
			name:     "distinct keys are not equivalent",
			a:        privKeyA.PubKey(),
			b:        privKeyB.PubKey(),
			expected: false,
		},
		{
			name: "parity-negated key is equivalent under BIP340",
			a:    privKeyA.PubKey(),
			b: func() *btcec.PublicKey {
				// Flip the parity byte.
				raw := privKeyA.PubKey().
					SerializeCompressed()
				if raw[0] == 0x02 {
					raw[0] = 0x03
				} else {
					raw[0] = 0x02
				}
				neg, err := btcec.ParsePubKey(raw)
				require.NoError(t, err)
				return neg
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEquivalentPubKeys(tt.a, tt.b)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestVerifyPrecommitsSpent covers:
//  1. Pre-commits above the commitment block height are excluded from the
//     required-spend set.
//  2. Pre-commits at or below commitment height that are not spent by the
//     commitment transaction produce an error.
//
// Plus boundary cases: happy path, initial commitment with no pre-commits,
// and missing commitment block.
func TestVerifyPrecommitsSpent(t *testing.T) {
	v := Verifier{assetLog: log}

	makeCommitSpending := func(t *testing.T, blockHeight uint32,
		spent []wire.OutPoint) supplycommit.RootCommitment {

		t.Helper()
		txIn := make([]*wire.TxIn, len(spent))
		for i, op := range spent {
			txIn[i] = &wire.TxIn{PreviousOutPoint: op}
		}
		commit := createTestRootCommitment(t, blockHeight)
		commit.Txn = &wire.MsgTx{
			Version: 2,
			TxIn:    txIn,
			TxOut: []*wire.TxOut{{
				Value:    1000,
				PkScript: []byte{0x51},
			}},
		}
		return commit
	}

	pc0 := createTestPreCommitment(t, 100, 0, 0)
	pc1 := createTestPreCommitment(t, 150, 1, 1)
	pc2 := createTestPreCommitment(t, 250, 1, 1)
	pc3 := createTestPreCommitment(t, 150, 1, 1)

	tests := []struct {
		name        string
		commitment  supplycommit.RootCommitment
		preCommits  supplycommit.PreCommits
		expectError bool
		errContains string
	}{
		{
			name: "all pre-commits at or below height are spent",
			commitment: makeCommitSpending(t, 200, []wire.OutPoint{
				pc0.OutPoint(), pc1.OutPoint(),
			}),
			preCommits: supplycommit.PreCommits{pc0, pc1},
		},
		{
			name: "pre-commit above commitment height excluded " +
				"from spend check",
			commitment: makeCommitSpending(
				t, 200, []wire.OutPoint{pc0.OutPoint()},
			),
			preCommits: supplycommit.PreCommits{pc0, pc2},
		},
		{
			name: "pre-commit below height not spent " +
				"returns error",
			commitment: makeCommitSpending(
				t, 200, []wire.OutPoint{pc0.OutPoint()},
			),
			preCommits:  supplycommit.PreCommits{pc0, pc3},
			expectError: true,
			errContains: "does not spend all known",
		},
		{
			name: "initial commitment with no pre-commits fails",
			commitment: func() supplycommit.RootCommitment {
				c := createTestRootCommitment(t, 200)
				c.SpentCommitment =
					fn.None[wire.OutPoint]()
				return c
			}(),
			preCommits:  supplycommit.PreCommits{},
			expectError: true,
			errContains: "no unspent supply pre-commitment",
		},
		{
			name: "missing commitment block returns error",
			commitment: func() supplycommit.RootCommitment {
				c := createTestRootCommitment(t, 200)
				c.CommitmentBlock =
					fn.None[supplycommit.CommitmentBlock]()
				return c
			}(),
			preCommits: supplycommit.PreCommits{
				createTestPreCommitment(t, 100, 0, 0),
			},
			expectError: true,
			errContains: "missing commitment block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.verifyPrecommitsSpent(
				tt.commitment, tt.preCommits,
			)
			if tt.expectError {
				require.Error(t, err)
				require.ErrorContains(
					t, err, tt.errContains,
				)
				return
			}
			require.NoError(t, err)
		})
	}
}
