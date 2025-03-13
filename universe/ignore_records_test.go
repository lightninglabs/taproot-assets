package universe

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// IgnoreSigGen is a custom generator for generating valid IgnoreSig objects.
var IgnoreSigGen = rapid.Custom(func(t *rapid.T) IgnoreSig {
	privKey := asset.PrivKeyInnerGen(t)

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = rapid.Uint8().Draw(t, "msg_byte"+string(rune(i)))
	}

	sig, err := schnorr.Sign(privKey, msg)
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}

	return IgnoreSig{Signature: *sig}
})

// IgnoreTupleGen is a custom generator for generating valid IgnoreTuple
// (PrevID) objects. It reuses the NonGenesisPrevIDGen from the asset package.
var IgnoreTupleGen = rapid.Custom(func(t *rapid.T) IgnoreTuple {
	return IgnoreTuple{
		PrevID: asset.NonGenesisPrevIDGen.Draw(t, "ignore_tuple"),
		Amount: rapid.Uint64().Draw(t, "amount"),
	}
})

// SignedIgnoreTupleGen is a custom generator for generating valid
// SignedIgnoreTuple objects.
var SignedIgnoreTupleGen = rapid.Custom(func(t *rapid.T) SignedIgnoreTuple {
	tuple := IgnoreTupleGen.Draw(t, "tuple")
	sig := IgnoreSigGen.Draw(t, "sig")

	return NewSignedIgnoreTuple(tuple, sig)
})

// TestIgnoreSigRecordRoundTrip tests the IgnoreSig's Record method for
// round-trip serialization.
func TestIgnoreSigRecordRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random signature
		origSig := IgnoreSigGen.Draw(t, "orig_sig")

		var buf bytes.Buffer
		err := origSig.Encode(&buf)
		require.NoError(t, err)

		var decodedSig IgnoreSig
		err = decodedSig.Decode(&buf)
		require.NoError(t, err)

		// Ensure the signatures are equal by comparing serialized form
		require.Equal(t, origSig, decodedSig)
	})
}

// TestSignedIgnoreTupleRoundTrip tests the encode/decode round-trip for
// SignedIgnoreTuple.
func TestSignedIgnoreTupleRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		origTuple := SignedIgnoreTupleGen.Draw(t, "orig_tuple")

		// Encode the tuple to bytes.
		tupleBytes, err := origTuple.Bytes()
		require.NoError(t, err)

		// Decode the tuple from bytes.
		decodedTuple, err := DecodeSignedIgnoreTuple(tupleBytes)
		require.NoError(t, err)

		// Check if the decoded tuple matches the original For the
		// PrevID
		require.Equal(t, origTuple, decodedTuple)
	})
}

// TestSignedIgnoreTupleEncodeDecode tests encode/decode operations directly for
// SignedIgnoreTuple.
func TestSignedIgnoreTupleEncodeDecode(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random SignedIgnoreTuple
		origTuple := SignedIgnoreTupleGen.Draw(t, "orig_tuple")

		// Create a buffer and encode the tuple
		var buf bytes.Buffer
		err := origTuple.Encode(&buf)
		require.NoError(t, err)

		// Create a new SignedIgnoreTuple to decode into
		var decodedTuple SignedIgnoreTuple

		// Decode the tuple from the buffer
		err = decodedTuple.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Check if the decoded tuple matches the original
		require.Equal(t, origTuple, decodedTuple)
	})
}
