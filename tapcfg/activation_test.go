package tapcfg

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestProofActivationHeight tests the activation height that a daemon applies
// on each network: the configured override, or else the network's own, which
// a custom signet does not share with the default signet.
func TestProofActivationHeight(t *testing.T) {
	t.Parallel()

	defaultChallenge := hex.EncodeToString(chaincfg.DefaultSignetChallenge)

	tests := []struct {
		name      string
		network   chaincfg.Params
		challenge string
		override  uint32
		want      lfn.Option[uint32]
	}{{
		name:    "mainnet",
		network: chaincfg.MainNetParams,
		want:    lfn.Some(proof.MainNetActivationHeight),
	}, {
		name:    "signet",
		network: chaincfg.SigNetParams,
		want:    lfn.Some(proof.SigNetActivationHeight),
	}, {
		name:      "signet with the default challenge",
		network:   chaincfg.SigNetParams,
		challenge: defaultChallenge,
		want:      lfn.Some(proof.SigNetActivationHeight),
	}, {
		name:      "custom signet",
		network:   chaincfg.SigNetParams,
		challenge: "5121",
		want:      lfn.None[uint32](),
	}, {
		name:    "testnet3",
		network: chaincfg.TestNet3Params,
		want:    lfn.Some(proof.TestNet3ActivationHeight),
	}, {
		name:    "testnet4",
		network: chaincfg.TestNet4Params,
		want:    lfn.Some(proof.TestNet4ActivationHeight),
	}, {
		name:    "regtest",
		network: chaincfg.RegressionNetParams,
		want:    lfn.None[uint32](),
	}, {
		name:     "regtest with override",
		network:  chaincfg.RegressionNetParams,
		override: 200,
		want:     lfn.Some(uint32(200)),
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			network := tc.network.Name
			if network == chaincfg.SigNetParams.Name {
				network = "signet"
			}

			cfg := &Config{
				ChainConf: &ChainConfig{
					Network:         network,
					SigNetChallenge: tc.challenge,
				},
				ActiveNetParams:       tc.network,
				ProofActivationHeight: tc.override,
			}

			require.Equal(t, tc.want, proofActivationHeight(cfg))
		})
	}
}
