package tapchannel

import (
	"bytes"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

// TestSettledOutputKept asserts that a party's settled BTC output is kept on
// its own exactly when lnd keeps it on the co-op close transaction, around
// the dust limit, with and without an asset output, for either party.
func TestSettledOutputKept(t *testing.T) {
	t.Parallel()

	const (
		dustLimit btcutil.Amount = 354
		anchorAmt btcutil.Amount = 1_000
	)

	// randScript returns a BIP 86 P2TR script of a random key.
	randScript := func() []byte {
		taprootKey := txscript.ComputeTaprootKeyNoScript(
			test.RandPubKey(t),
		)
		pkScript, err := txscript.PayToTaprootScript(taprootKey)
		require.NoError(t, err)

		return pkScript
	}

	ourScript := randScript()
	theirScript := randScript()
	assetScript := randScript()

	tests := []struct {
		name           string
		btcAmt         btcutil.Amount
		hasAssetOutput bool
		want           bool
	}{
		{
			name:   "no asset output, below dust",
			btcAmt: dustLimit - 1,
			want:   false,
		},
		{
			name:   "no asset output, at dust",
			btcAmt: dustLimit,
			want:   true,
		},
		{
			name:   "no asset output, above dust",
			btcAmt: dustLimit + 1,
			want:   true,
		},
		{
			name:           "asset output, remainder below dust",
			btcAmt:         anchorAmt + dustLimit - 1,
			hasAssetOutput: true,
			want:           false,
		},
		{
			name:           "asset output, remainder at dust",
			btcAmt:         anchorAmt + dustLimit,
			hasAssetOutput: true,
			want:           false,
		},
		{
			name:           "asset output, remainder above dust",
			btcAmt:         anchorAmt + dustLimit + 1,
			hasAssetOutput: true,
			want:           true,
		},
	}

	// lndKeeps returns true if lnd keeps the settled output of the given
	// party on its own on the co-op close transaction.
	lndKeeps := func(t *testing.T, btcAmt btcutil.Amount,
		hasAssetOutput, isLocal bool) bool {

		var opts []lnwallet.CloseTxOpt
		if hasAssetOutput {
			opts = append(opts, lnwallet.WithExtraTxCloseOutputs(
				[]lnwallet.CloseOutput{{
					TxOut: wire.TxOut{
						PkScript: assetScript,
						Value:    int64(anchorAmt),
					},
					IsLocal: isLocal,
				}},
			))
		}

		ourBalance, theirBalance := btcAmt, btcutil.Amount(0)
		settledScript := ourScript
		if !isLocal {
			ourBalance, theirBalance = theirBalance, ourBalance
			settledScript = theirScript
		}

		closeTx, err := lnwallet.CreateCooperativeCloseTx(
			wire.TxIn{}, dustLimit, dustLimit, ourBalance,
			theirBalance, ourScript, theirScript, opts...,
		)
		require.NoError(t, err)

		isSettled := func(o *wire.TxOut) bool {
			return bytes.Equal(o.PkScript, settledScript)
		}

		return slices.ContainsFunc(closeTx.TxOut, isSettled)
	}

	for _, tc := range tests {
		for _, isLocal := range []bool{true, false} {
			name := tc.name + ", local"
			if !isLocal {
				name = tc.name + ", remote"
			}

			t.Run(name, func(t *testing.T) {
				var assetAmt btcutil.Amount
				if tc.hasAssetOutput {
					assetAmt = anchorAmt
				}

				lndKept := lndKeeps(
					t, tc.btcAmt, tc.hasAssetOutput,
					isLocal,
				)
				require.Equal(t, tc.want, lndKept)

				require.Equal(t, tc.want, settledOutputKept(
					tc.btcAmt, assetAmt, dustLimit,
					tc.hasAssetOutput,
				))
			})
		}
	}
}
