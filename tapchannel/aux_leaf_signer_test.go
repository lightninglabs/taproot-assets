package tapchannel

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// Some of these test values and functions are from lnd's lnwire/lnwire_test.go.
// We just need them to have some realistically sized values for the BTC-level
// Schnorr signatures. The actual values are not important for the test.
var (
	testSchnorrSigStr, _ = hex.DecodeString(
		"04e7f9037658a92afeb4f25bae5339e3ddca81a353493827d26f16d92308" +
			"e49e2a25e92208678a2df86970da91b03a8af8815a8a60498b35" +
			"8daf560b347aa557",
	)
	testSchnorrSig, _ = lnwire.NewSigFromSchnorrRawSignature(
		testSchnorrSigStr,
	)
)

func randPartialSigWithNonce() (*lnwire.PartialSigWithNonce, error) {
	var sigBytes [32]byte
	if _, err := rand.Read(sigBytes[:]); err != nil {
		return nil, fmt.Errorf("unable to generate sig: %w", err)
	}

	var s btcec.ModNScalar
	s.SetByteSlice(sigBytes[:])

	var nonce lnwire.Musig2Nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}

	return &lnwire.PartialSigWithNonce{
		PartialSig: lnwire.NewPartialSig(s),
		Nonce:      nonce,
	}, nil
}

func somePartialSigWithNonce(t *testing.T) lnwire.OptPartialSigWithNonceTLV {
	sig, err := randPartialSigWithNonce()
	if err != nil {
		t.Fatal(err)
	}

	return tlv.SomeRecordT(tlv.NewRecordT[
		lnwire.PartialSigWithNonceType,
		lnwire.PartialSigWithNonce,
	](*sig))
}

// TestMaxCommitSigMsgSize attempts to find values for the max number of asset
// IDs we want to allow per channel and the resulting maximum number of HTLCs
// that channel can allow. The maximum number of different asset IDs that can be
// committed to a channel directly impacts the number of HTLCs that can be
// created on that channel, because we have a limited message size to exchange
// the second-stage HTLC signatures. The goal of this test is to find the right
// number of asset IDs we should allow per channel to still give us a reasonable
// amount of HTLCs.
func TestMaxCommitSigMsgSize(t *testing.T) {
	// This test is only relevant once, to find the values we want to use
	// for the maximum number of asset IDs and the resulting maximum number
	// of HTLCs. We only need to re-run this if any of the parameters
	// change.
	t.Skip("Test for manual execution only")

	const (
		maxNumAssetIDs = 10
		startNumHTLCs  = 5
		endNumHTLCs    = input.MaxHTLCNumber
	)

	var buf bytes.Buffer
	for numID := 0; numID <= maxNumAssetIDs; numID++ {
		for htlcs := startNumHTLCs; htlcs <= endNumHTLCs; htlcs++ {
			buf.Reset()

			msg := makeCommitSig(t, numID, htlcs)
			err := msg.Encode(&buf, 0)
			require.NoError(t, err)

			if buf.Len() > lnwire.MaxMsgBody {
				t.Logf("Last valid commit sig msg size with: "+
					"numAssetIDs=%d, numHTLCs=%d",
					numID, htlcs-1)

				break
			}

			if htlcs == endNumHTLCs {
				t.Logf("Last valid commit sig msg size with: "+
					"numAssetIDs=%d, numHTLCs=%d",
					numID, htlcs)
			}
		}
	}
}

func makeCommitSig(t *testing.T, numAssetIDs, numHTLCs int) *lnwire.CommitSig {
	var (
		msg = &lnwire.CommitSig{
			HtlcSigs: make([]lnwire.Sig, numHTLCs),
		}
		err error
	)

	// Static values that are always set for custom channels (which are
	// Taproot channels, so have an all-zero legacy commit signature and a
	// partial MuSig2 signature).
	msg.PartialSig = somePartialSigWithNonce(t)
	msg.CommitSig, err = lnwire.NewSigFromWireECDSA(
		bytes.Repeat([]byte{0}, 64),
	)
	require.NoError(t, err)

	assetSigs := make([][]*cmsg.AssetSig, numHTLCs)
	for i := range numHTLCs {
		msg.HtlcSigs[i] = testSchnorrSig

		assetSigs[i] = make([]*cmsg.AssetSig, numAssetIDs)
		for j := range numAssetIDs {
			var assetID asset.ID

			_, err := rand.Read(assetID[:])
			require.NoError(t, err)

			assetSigs[i][j] = cmsg.NewAssetSig(
				assetID, testSchnorrSig, txscript.SigHashAll,
			)
		}
	}

	if numAssetIDs == 0 {
		return msg
	}

	commitSig := cmsg.NewCommitSig(assetSigs)

	var buf bytes.Buffer
	err = commitSig.Encode(&buf)
	require.NoError(t, err)

	msg.CustomRecords = lnwire.CustomRecords{
		// The actual record type is not important for this test, it
		// just needs to be in the correct range to be encoded with the
		// correct number of bytes in the compact size encoding.
		lnwire.MinCustomRecordsTlvType + 123: buf.Bytes(),
	}

	return msg
}
