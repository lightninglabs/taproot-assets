package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// testFragmentPayload is the auth mailbox message payload of testFragment,
// encrypted to testFragmentReceiver. A fixed payload makes sure that messages
// of existing senders remain readable.
const testFragmentPayload = "" +
	"012103504f7b23c899837771fedda9fba59c30048411754ec35e5eaf2c0ddc76" +
	"8ce2dc2f12cdda49da73da88ff894c568f9f8648dc3f4f655cad54e147bda639" +
	"8a9a2bbd4648f7cc0d6644da9ba2bf19866c2caab007cd3e2bbbbb238437013a" +
	"9d94f3d086a1f8e42f06c4eb86c2bdf8d26a5cba75a2d2e51d97daf1056152ff" +
	"706493bd9db5c81bf23feafa609200d8e20033be0b6a9c300b597bb91a34a2fe" +
	"31986f5df0551ba2b0381bc312d322321ebc173f228b8c47253384bac2b49750" +
	"fdb6ad17f66aafdcb6d63087f0f9964cbfa10984dc9fe967fad45874f600cc93" +
	"ab2d3c7da917142a45f1b8fa9c6ca3c21275c0f09ada6a376deb77284e697e9c" +
	"104e538ddc26fe565948ad0180dfa97d3a3114a6cb371cf4d1111b565773a220" +
	"e3dc0e64d4345201b76eba8762b2a80c0304fe4ba9bac468e4765b6e"

// testFragmentReceiver is the private key testFragmentPayload is encrypted to.
var testFragmentReceiver, _ = btcec.PrivKeyFromBytes(
	bytes.Repeat([]byte{0x01}, 32),
)

// testFragment returns the send fragment contained in testFragmentPayload.
func testFragment() SendFragment {
	return SendFragment{
		Version: SendFragmentV1,
		BlockHeader: wire.BlockHeader{
			Version:    1,
			PrevBlock:  [32]byte{0x01},
			MerkleRoot: [32]byte{0x02},
			Timestamp:  time.Unix(1234567890, 0),
			Bits:       0x1d00ffff,
		},
		BlockHeight: 1234,
		OutPoint: wire.OutPoint{
			Hash:  [32]byte{0x03},
			Index: 1,
		},
		Outputs: map[asset.ID]SendOutput{
			{0x01}: {
				AssetVersion: asset.V1,
				Amount:       100,
				DerivationMethod: asset.
					ScriptKeyDerivationUniquePedersen,
				ScriptKey: asset.SerializedKey{0x02, 0x04},
			},
		},
		TaprootAssetRoot: [32]byte{0x04, 0x05, 0x06},
	}
}

// lndSharedKeyDeriver returns a shared key deriver for the given private key
// that uses lnd's ECDH implementation.
func lndSharedKeyDeriver(privKey *btcec.PrivateKey) SharedKeyDeriver {
	ecdh := &keychain.PrivKeyECDH{PrivKey: privKey}

	return func(_ context.Context,
		pubKey *btcec.PublicKey) ([sha256.Size]byte, error) {

		return ecdh.ECDH(pubKey)
	}
}

// TestSendFragmentEncodeDecode tests the encoding and decoding of SendFragment
// structs.
func TestSendFragmentEncodeDecode(t *testing.T) {
	output1 := SendOutput{
		AssetVersion:     asset.Version(1),
		Amount:           100,
		DerivationMethod: asset.ScriptKeyDerivationUniquePedersen,
		ScriptKey:        asset.SerializedKey{0x04},
	}
	output2 := SendOutput{
		AssetVersion:     asset.Version(2),
		Amount:           200,
		DerivationMethod: asset.ScriptKeyDerivationUniquePedersen,
		ScriptKey:        asset.SerializedKey{0x05, 0x06},
	}

	tests := []struct {
		name     string
		fragment SendFragment
	}{
		{
			name: "basic fragment",
			fragment: SendFragment{
				Version: SendFragmentV1,
				BlockHeader: wire.BlockHeader{
					Version:    1,
					PrevBlock:  [32]byte{0x01},
					MerkleRoot: [32]byte{0x02},
					Timestamp:  time.Unix(1234567890, 0),
					Bits:       0x1d00ffff,
					Nonce:      0,
				},
				BlockHeight: 1234,
				OutPoint: wire.OutPoint{
					Hash:  [32]byte{0x03},
					Index: 1,
				},
				Outputs: map[asset.ID]SendOutput{
					{0x01}: output1,
					{0x02}: output2,
				},
				TaprootAssetRoot: [32]byte{
					0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
				},
				UnknownOddTypes: tlv.TypeMap{
					0x1001: []byte{0x05, 0x06},
				},
			},
		},
		{
			name: "empty fragment",
			fragment: SendFragment{
				Version: SendFragmentV1,
				BlockHeader: wire.BlockHeader{
					Timestamp: time.Unix(1234567890, 0),
				},
				Outputs: map[asset.ID]SendOutput{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the fragment.
			var buf bytes.Buffer
			err := tt.fragment.Encode(&buf)
			require.NoError(t, err)

			// Decode the fragment.
			var decodedFragment SendFragment
			err = decodedFragment.Decode(&buf)
			require.NoError(t, err)

			// Verify the decoded fragment matches the original.
			require.Equal(t, tt.fragment, decodedFragment)
		})
	}
}

// TestSendOutputsEncoderKeyOrder tests that the outputs of a send fragment are
// encoded sorted by their asset ID, whatever the iteration order of the map.
func TestSendOutputsEncoderKeyOrder(t *testing.T) {
	t.Parallel()

	const numOutputs = 4
	outputs := make(map[asset.ID]SendOutput, numOutputs)
	for i := range numOutputs {
		outputs[asset.RandID(t)] = SendOutput{
			AssetVersion: asset.V1,
			Amount:       uint64(i + 1),
			ScriptKey:    asset.SerializedKey{0x02, byte(i)},
		}
	}

	byID := func(a, b asset.ID) int {
		return bytes.Compare(a[:], b[:])
	}

	// A single encoding may be sorted by chance, so we encode the outputs
	// several times.
	var buf [8]byte
	for range 10 {
		var b bytes.Buffer
		err := SendOutputsEncoder(&b, &outputs, &buf)
		require.NoError(t, err)

		numIDs, err := tlv.ReadVarInt(&b, &buf)
		require.NoError(t, err)
		require.EqualValues(t, numOutputs, numIDs)

		ids := make([]asset.ID, numIDs)
		for i := range ids {
			_, err := io.ReadFull(&b, ids[i][:])
			require.NoError(t, err)

			var output SendOutput
			err = SendOutputDecoder(&b, &output, &buf)
			require.NoError(t, err)
			require.Equal(t, outputs[ids[i]], output)
		}
		require.Zero(t, b.Len())

		require.True(t, slices.IsSortedFunc(ids, byID))
	}
}

// TestEncryptSendFragment tests that an encrypted send fragment has the
// expected layout and can be decrypted by the receiver.
func TestEncryptSendFragment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fragment := testFragment()
	fragmentBytes, err := fn.Encode(&fragment)
	require.NoError(t, err)

	receiver, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	payload, err := EncryptSendFragment(&fragment, receiver.PubKey())
	require.NoError(t, err)

	// The payload starts with the version and the length-prefixed sender
	// key, followed by the nonce and the ciphertext with its 16 byte tag.
	const (
		keyLen    = btcec.PubKeyBytesLenCompressed
		headerLen = 2 + keyLen
		nonceLen  = 24
		tagLen    = 16
	)
	require.Len(t, payload, headerLen+nonceLen+len(fragmentBytes)+tagLen)
	require.EqualValues(t, 1, payload[0])
	require.EqualValues(t, keyLen, payload[1])

	_, err = btcec.ParsePubKey(payload[2:headerLen])
	require.NoError(t, err)
	require.NotContains(t, string(payload), string(fragmentBytes))

	decrypted, err := DecryptSendFragment(
		ctx, payload, lndSharedKeyDeriver(receiver),
	)
	require.NoError(t, err)
	require.Equal(t, fragment, *decrypted)

	// Each message uses its own sender key.
	payload2, err := EncryptSendFragment(&fragment, receiver.PubKey())
	require.NoError(t, err)
	require.NotEqual(t, payload[2:headerLen], payload2[2:headerLen])
}

// TestDecryptSendFragment tests the decryption of a send fragment with a fixed
// payload, and that payloads the receiver can't read are rejected.
func TestDecryptSendFragment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deriver := lndSharedKeyDeriver(testFragmentReceiver)

	validPayload, err := hex.DecodeString(testFragmentPayload)
	require.NoError(t, err)

	fragment, err := DecryptSendFragment(ctx, validPayload, deriver)
	require.NoError(t, err)
	require.Equal(t, testFragment(), *fragment)

	otherKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	invalidKeyPayload := bytes.Clone(validPayload)
	invalidKeyPayload[2] = 0x05

	tamperedPayload := bytes.Clone(validPayload)
	tamperedPayload[len(tamperedPayload)-1] ^= 0x01

	emptyFragment := testFragment()
	emptyFragment.Outputs = nil
	emptyPayload, err := EncryptSendFragment(
		&emptyFragment, testFragmentReceiver.PubKey(),
	)
	require.NoError(t, err)

	errDerive := errors.New("derive error")
	failingDeriver := func(context.Context,
		*btcec.PublicKey) ([sha256.Size]byte, error) {

		return [sha256.Size]byte{}, errDerive
	}

	_, err = DecryptSendFragment(ctx, validPayload, failingDeriver)
	require.ErrorIs(t, err, errDerive)

	tests := []struct {
		name    string
		payload []byte
		deriver SharedKeyDeriver
		err     string
	}{
		{
			name:    "truncated payload",
			payload: validPayload[:20],
			deriver: deriver,
			err:     "unable to extract sender key",
		},
		{
			name:    "invalid sender key",
			payload: invalidKeyPayload,
			deriver: deriver,
			err:     "unable to parse sender key",
		},
		{
			name:    "wrong receiver key",
			payload: validPayload,
			deriver: lndSharedKeyDeriver(otherKey),
			err:     "unable to decrypt send fragment",
		},
		{
			name:    "tampered ciphertext",
			payload: tamperedPayload,
			deriver: deriver,
			err:     "unable to decrypt send fragment",
		},
		{
			name:    "fragment without outputs",
			payload: emptyPayload,
			deriver: deriver,
			err:     "invalid send fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptSendFragment(
				ctx, tt.payload, tt.deriver,
			)
			require.ErrorContains(t, err, tt.err)
		})
	}
}
