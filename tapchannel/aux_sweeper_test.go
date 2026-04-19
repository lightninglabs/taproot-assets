package tapchannel

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

// TestRevocationSweepDescSignVerify tests that the revocation sweep descriptor
// functions produce taproot output keys consistent with the signing key derived
// from the same base material. For each revocation type (offered, accepted,
// second-level), it performs a full sign+verify round-trip using the same
// routines used in production to create the scripts and derive the keys.
func TestRevocationSweepDescSignVerify(t *testing.T) {
	t.Parallel()

	// Generate base key material. In production, revokeBasePriv is our
	// revocation base point secret, and commitSecret is the per-commitment
	// secret revealed when the remote party broadcasts a revoked
	// commitment.
	revokeBasePriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	commitSecret, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Generate HTLC keys and delay key for the commitment keyring.
	localHtlcPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	remoteHtlcPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	toLocalPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Derive the revocation public key using the standard LND routine.
	// This key becomes the internal key of all HTLC taproot outputs.
	revocationKey := input.DeriveRevocationPubkey(
		revokeBasePriv.PubKey(), commitSecret.PubKey(),
	)

	keyRing := &lnwallet.CommitmentKeyRing{
		RevocationKey: revocationKey,
		LocalHtlcKey:  localHtlcPriv.PubKey(),
		RemoteHtlcKey: remoteHtlcPriv.PubKey(),
		ToLocalKey:    toLocalPriv.PubKey(),
	}

	payHash := sha256.Sum256([]byte("test preimage"))
	htlcIndex := input.HtlcIndex(42)
	csvDelay := uint32(144)
	htlcExpiry := uint32(800_000)

	// Derive the signing private key that the LND signer computes when
	// processing a breach sweep:
	// 1. DeriveRevocationPrivKey (DoubleTweak) — recovers the revocation
	//    private key from our base secret and the revealed commit secret.
	// 2. TweakPrivKey with HTLC index (SingleTweak) — applies the
	//    asset-level HTLC index tweak.
	revocationPriv := input.DeriveRevocationPrivKey(
		revokeBasePriv, commitSecret,
	)

	tweakScalar := ScriptKeyTweakFromHtlcIndex(htlcIndex)
	var singleTweak [32]byte
	tweakScalar.PutBytesUnchecked(singleTweak[:])
	signingPriv := input.TweakPrivKey(revocationPriv, singleTweak[:])

	// Verify that the private key tweak path is consistent with the public
	// key tweak path. This confirms that TweakPrivKey + SingleTweak on the
	// private side produces the same result as TweakPubKeyWithTweak on the
	// public side.
	derivedInternalKey := input.TweakPubKeyWithTweak(
		revocationKey, singleTweak[:],
	)
	require.Equal(
		t, derivedInternalKey.SerializeCompressed(),
		signingPriv.PubKey().SerializeCompressed(),
		"private key tweak path should match public key tweak path",
	)

	testCases := []struct {
		name          string
		getSweepDescs func() lfn.Result[tapscriptSweepDescs]
	}{
		{
			name: "offered HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcOfferedRevokeSweepDesc(
					keyRing, payHash[:], htlcExpiry,
					htlcIndex,
				)
			},
		},
		{
			name: "accepted HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcAcceptedRevokeSweepDesc(
					keyRing, payHash[:], htlcIndex,
				)
			},
		},
		{
			name: "second-level HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcSecondLevelRevokeSweepDesc(
					keyRing, csvDelay, htlcIndex,
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the sweep descriptor.
			descs := tc.getSweepDescs().UnwrapOrFail(t)
			desc := descs.firstLevel

			// Revocation sweeps use keyspend (no control block).
			require.Empty(t, desc.ctrlBlockBytes,
				"revocation sweep should use keyspend")

			// Verify the descriptor's internal key matches what
			// we derived from applying both tweaks to the base
			// keys on the public key side.
			tree := desc.scriptTree.Tree()
			require.Equal(
				t,
				derivedInternalKey.SerializeCompressed(),
				tree.InternalKey.SerializeCompressed(),
				"descriptor internal key should match "+
					"derived key",
			)

			// Apply the taproot tweak for keyspend signing.
			// This mirrors what RawTxInTaprootSignature does
			// internally.
			tapTweak := desc.scriptTree.TapTweak()
			taprootPriv := txscript.TweakTaprootPrivKey(
				*signingPriv, tapTweak,
			)

			// Sign a test message.
			testMsg := sha256.Sum256([]byte(tc.name))
			sig, err := schnorr.Sign(taprootPriv, testMsg[:])
			require.NoError(t, err)

			// Verify the signature against the taproot output
			// key from the descriptor. This is the key that the
			// UTXO is locked to on-chain.
			require.True(
				t, sig.Verify(testMsg[:], tree.TaprootKey),
				"signature should verify against taproot "+
					"output key",
			)
		})
	}
}
