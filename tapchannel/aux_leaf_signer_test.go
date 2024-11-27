package tapchannel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
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

func pubKeyFromUint64(num uint64) *btcec.PublicKey {
	var (
		buf    = make([]byte, 8)
		scalar = new(secp256k1.ModNScalar)
	)
	binary.BigEndian.PutUint64(buf, num)
	_ = scalar.SetByteSlice(buf)
	return secp256k1.NewPrivateKey(scalar).PubKey()
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

// TestHtlcIndexAsScriptKeyTweak tests the ScriptKeyTweakFromHtlcIndex function.
func TestHtlcIndexAsScriptKeyTweak(t *testing.T) {
	var (
		buf               = make([]byte, 8)
		maxUint64MinusOne = new(secp256k1.ModNScalar)
		maxUint64         = new(secp256k1.ModNScalar)
	)
	binary.BigEndian.PutUint64(buf, math.MaxUint64-1)
	_ = maxUint64MinusOne.SetByteSlice(buf)

	binary.BigEndian.PutUint64(buf, math.MaxUint64)
	_ = maxUint64.SetByteSlice(buf)

	testCases := []struct {
		name   string
		index  uint64
		result *secp256k1.ModNScalar
	}{
		{
			name:   "index 0",
			index:  0,
			result: new(secp256k1.ModNScalar).SetInt(1),
		},
		{
			name:  "index math.MaxUint32-1",
			index: math.MaxUint32 - 1,
			result: new(secp256k1.ModNScalar).SetInt(
				math.MaxUint32,
			),
		},
		{
			name:   "index math.MaxUint64-2",
			index:  math.MaxUint64 - 2,
			result: maxUint64MinusOne,
		},
		{
			name:   "index math.MaxUint64-1",
			index:  math.MaxUint64 - 1,
			result: maxUint64,
		},
		{
			name:   "index math.MaxUint64, wraps around to 1",
			index:  math.MaxUint64,
			result: new(secp256k1.ModNScalar).SetInt(1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tweak := ScriptKeyTweakFromHtlcIndex(tc.index)
			require.Equal(t, tc.result, tweak)
		})
	}
}

// TestTweakPubKeyWithIndex tests the TweakPubKeyWithIndex function.
func TestTweakPubKeyWithIndex(t *testing.T) {
	// We want a random number in the range of uint32 but will need it as
	// an uint64 for the test cases.
	randNum := uint64(test.RandInt[uint32]())
	startKey := pubKeyFromUint64(randNum)

	testCases := []struct {
		name   string
		pubKey *btcec.PublicKey
		index  uint64
		result *btcec.PublicKey
	}{
		{
			name:   "index 0",
			pubKey: startKey,
			index:  0,
			result: pubKeyFromUint64(randNum + 1),
		},
		{
			name:   "index 1",
			pubKey: startKey,
			index:  1,
			result: pubKeyFromUint64(randNum + 2),
		},
		{
			name:   "index 99",
			pubKey: startKey,
			index:  99,
			result: pubKeyFromUint64(randNum + 100),
		},
		{
			name:   "index math.MaxUint32-1",
			pubKey: startKey,
			index:  math.MaxUint32 - 1,
			result: pubKeyFromUint64(randNum + math.MaxUint32),
		},
		{
			// Because we always increment by 1, there is a
			// "collision" at 0 and math.MaxUint64. For the purpose
			// of tweaking channel related keys with the HTLC index,
			// that is okay, as there isn't expected to ever be that
			// many HTLCs during the lifetime of a channel.
			name:   "index math.MaxUint64, wrap around",
			pubKey: startKey,
			index:  math.MaxUint64,
			result: pubKeyFromUint64(randNum + 1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tweakedKey := TweakPubKeyWithIndex(tc.pubKey, tc.index)
			require.Equal(
				t, tc.result.SerializeCompressed(),
				tweakedKey.SerializeCompressed(),
			)
		})
	}
}

// TestTweakHtlcTree tests the TweakHtlcTree function.
func TestTweakHtlcTree(t *testing.T) {
	randTree := txscript.AssembleTaprootScriptTree(
		test.RandTapLeaf(nil), test.RandTapLeaf(nil),
		test.RandTapLeaf(nil),
	)
	randRoot := randTree.RootNode.TapHash()

	// We want a random number in the range of uint32 but will need it as
	// an uint64 for the test cases.
	randNum := uint64(test.RandInt[uint32]())

	makeTaprootKey := func(num uint64) *btcec.PublicKey {
		return txscript.ComputeTaprootOutputKey(
			pubKeyFromUint64(num), randRoot[:],
		)
	}
	startKey := pubKeyFromUint64(randNum)
	startTaprootKey := makeTaprootKey(randNum)
	startTree := input.ScriptTree{
		InternalKey:   startKey,
		TaprootKey:    startTaprootKey,
		TapscriptTree: randTree,
		TapscriptRoot: randRoot[:],
	}

	testCases := []struct {
		name   string
		tree   input.ScriptTree
		index  uint64
		result input.ScriptTree
	}{
		{
			name:  "index 0",
			tree:  startTree,
			index: 0,
			result: input.ScriptTree{
				InternalKey:   pubKeyFromUint64(randNum + 1),
				TaprootKey:    makeTaprootKey(randNum + 1),
				TapscriptTree: randTree,
				TapscriptRoot: randRoot[:],
			},
		},
		{
			name:  "index 1",
			tree:  startTree,
			index: 1,
			result: input.ScriptTree{
				InternalKey:   pubKeyFromUint64(randNum + 2),
				TaprootKey:    makeTaprootKey(randNum + 2),
				TapscriptTree: randTree,
				TapscriptRoot: randRoot[:],
			},
		},
		{
			name:  "index 99",
			tree:  startTree,
			index: 99,
			result: input.ScriptTree{
				InternalKey:   pubKeyFromUint64(randNum + 100),
				TaprootKey:    makeTaprootKey(randNum + 100),
				TapscriptTree: randTree,
				TapscriptRoot: randRoot[:],
			},
		},
		{
			name:  "index math.MaxUint32-1",
			tree:  startTree,
			index: math.MaxUint32 - 1,
			result: input.ScriptTree{
				InternalKey: pubKeyFromUint64(
					randNum + math.MaxUint32,
				),
				TaprootKey: makeTaprootKey(
					randNum + math.MaxUint32,
				),
				TapscriptTree: randTree,
				TapscriptRoot: randRoot[:],
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tweakedTree := TweakHtlcTree(tc.tree, tc.index)
			require.Equal(
				t, tc.result.InternalKey.SerializeCompressed(),
				tweakedTree.InternalKey.SerializeCompressed(),
			)
			require.Equal(
				t, tc.result.TaprootKey.SerializeCompressed(),
				tweakedTree.TaprootKey.SerializeCompressed(),
			)
			require.Equal(t, tc.result, tweakedTree)
		})
	}
}

// TestAddTweakWithIndex tests the AddTweakWithIndex function.
func TestAddTweakWithIndex(t *testing.T) {
	var (
		bufMaxUint64 = make([]byte, 8)
		maxUint64    = new(secp256k1.ModNScalar)
	)
	binary.BigEndian.PutUint64(bufMaxUint64, math.MaxUint64)
	_ = maxUint64.SetByteSlice(bufMaxUint64)
	maxUint64Double := new(secp256k1.ModNScalar).
		Set(maxUint64).Add(maxUint64)

	testCases := []struct {
		name   string
		tweak  []byte
		index  uint64
		result *secp256k1.ModNScalar
	}{
		{
			name:   "empty tweak, index 0",
			index:  0,
			result: new(secp256k1.ModNScalar).SetInt(1),
		},
		{
			name:   "five as tweak, index 123",
			tweak:  []byte{0x05},
			index:  123,
			result: new(secp256k1.ModNScalar).SetInt(129),
		},
		{
			name:   "all zero tweak, index 123",
			tweak:  bytes.Repeat([]byte{0}, 32),
			index:  123,
			result: new(secp256k1.ModNScalar).SetInt(124),
		},
		{
			name:   "tweak math.MaxUint64, index math.MaxUint64-1",
			tweak:  fn.ByteSlice(maxUint64.Bytes()),
			index:  math.MaxUint64 - 1,
			result: maxUint64Double,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tweak := AddTweakWithIndex(tc.tweak, tc.index)
			resultBytes := tc.result.Bytes()
			resultBigInt := new(big.Int).SetBytes(resultBytes[:])
			tweakBigInt := new(big.Int).SetBytes(tweak)

			require.Equalf(t, resultBytes[:], tweak, "expected: "+
				"%s, got: %s", resultBigInt.String(),
				tweakBigInt.String())
		})
	}
}
