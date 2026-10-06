package backup

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestGroupBackupRecordLimits checks the group fields added since the
// original decoder hardening, including the enclosing asset backup record.
func TestGroupBackupRecordLimits(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		typ   tlv.Type
		limit uint64
		asset bool
	}{
		{"group backup", AssetBackupGroupKeyType, maxTLVSize, true},
		{
			"tapscript root", GroupKeyTapscriptRootType,
			maxTLVSize, false,
		},
		{
			"custom root", GroupKeyCustomRootType,
			chainhash.HashSize, false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			var scratch [8]byte
			require.NoError(t, tlv.WriteVarInt(
				&encoded, uint64(test.typ), &scratch,
			))
			require.NoError(t, tlv.WriteVarInt(
				&encoded, test.limit+1, &scratch,
			))

			var err error
			if test.asset {
				var wrapped bytes.Buffer
				require.NoError(t, tlv.WriteVarInt(
					&wrapped, uint64(encoded.Len()),
					&scratch,
				))
				_, err = wrapped.Write(encoded.Bytes())
				require.NoError(t, err)
				var decoded AssetBackup
				err = decoded.Decode(&wrapped)
			} else {
				var decoded GroupKeyBackup
				err = decoded.Decode(&encoded)
			}
			require.ErrorIs(t, err, tlv.ErrRecordTooLarge)
		})
	}
}
