package address

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/address/v2/bech32"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// produce an address that later panics during output key derivation.
func TestAddressDecodeRequiresKeys(t *testing.T) {
	v1 := V1
	addr, err := randAddress(
		t, &TestNet3Tap, &v1, false, false, nil, asset.Normal, nil,
	)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		omitScript   bool
		omitInternal bool
		wantErr      string
	}{
		{name: "complete"},
		{
			name:       "missing script key",
			omitScript: true,
			wantErr:    "missing script key",
		},
		{
			name:         "missing internal key",
			omitInternal: true,
			wantErr:      "missing internal key",
		},
		{
			name:         "missing both keys",
			omitScript:   true,
			omitInternal: true,
			wantErr:      "missing script key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var records []tlv.Record
			for _, record := range addr.EncodeRecords() {
				if tc.omitScript &&
					record.Type() == addrScriptKeyType {

					continue
				}
				if tc.omitInternal &&
					record.Type() == addrInternalKeyType {

					continue
				}
				records = append(records, record)
			}

			stream, err := tlv.NewStream(records...)
			require.NoError(t, err)
			var raw bytes.Buffer
			require.NoError(t, stream.Encode(&raw))

			var decoded Tap
			err = decoded.Decode(bytes.NewReader(raw.Bytes()))
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}

			converted, err := bech32.ConvertBits(
				raw.Bytes(), 8, 5, true,
			)
			require.NoError(t, err)
			encoded, err := bech32.EncodeM(
				TestNet3Tap.TapHRP, converted,
			)
			require.NoError(t, err)
			_, err = DecodeAddress(encoded, &TestNet3Tap)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

// key is refused.
func TestCompressedPubKeyDecoderZeroKey(t *testing.T) {
	t.Parallel()

	var (
		key btcec.PublicKey
		buf [8]byte
	)
	zeroKey := make([]byte, btcec.PubKeyBytesLenCompressed)
	err := compressedPubKeyDecoder(
		bytes.NewReader(zeroKey), &key, &buf, uint64(len(zeroKey)),
	)
	require.Error(t, err)
}
