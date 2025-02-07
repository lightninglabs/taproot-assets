package proof

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

type mockSigner struct {
	lndclient.SignerClient

	privKey *btcec.PrivateKey
}

func (r *mockSigner) SignMessage(_ context.Context, msg []byte,
	_ keychain.KeyLocator, _ ...lndclient.SignMessageOption) ([]byte,
	error) {

	sig, err := schnorr.Sign(r.privKey, msg)
	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

// TestUniCommitmentParams tests encoding and decoding of the
// UniCommitmentParams struct.
func TestUniCommitmentParams(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		params *UniCommitmentParams
	}{
		{
			name:   "empty params",
			params: &UniCommitmentParams{},
		},
		{
			name:   "params with values",
			params: NewUniCommitmentParams(1, 31337),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the params and then deserialize them again.
			var b bytes.Buffer
			err := tc.params.Encode(&b)
			require.NoError(t, err)

			deserializedParams := &UniCommitmentParams{}
			err = deserializedParams.Decode(&b)
			require.NoError(t, err)

			require.Equal(t, tc.params, deserializedParams)
		})
	}
}

// TestUniCommitments tests encoding and decoding of the UniCommitments struct.
func TestUniCommitments(t *testing.T) {
	t.Parallel()

	randSig := func() lnwire.Sig {
		sig, err := lnwire.NewSigFromSchnorrRawSignature(
			test.RandBytes(64),
		)
		require.NoError(t, err)

		return sig
	}

	testCases := []struct {
		name        string
		commitments *UniCommitments
	}{
		{
			name:        "empty commitments",
			commitments: &UniCommitments{},
		},
		{
			name:        "commitments with no params",
			commitments: NewUniCommitments(nil, randSig()),
		},
		{
			name: "commitments with params",
			commitments: NewUniCommitments(NewUniCommitmentParams(
				123, 768,
			), randSig()),
		},
	}

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	var (
		ctx    = context.Background()
		signer = &mockSigner{
			privKey: privKey,
		}
		loc       keychain.KeyLocator
		mintPoint = wire.OutPoint{
			Hash:  test.RandHash(),
			Index: 123,
		}
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the commitments and then deserialize them
			// again.
			var b bytes.Buffer
			err := tc.commitments.Encode(&b)
			require.NoError(t, err)

			deserializedCommitments := &UniCommitments{}
			err = deserializedCommitments.Decode(&b)
			require.NoError(t, err)

			require.Equal(
				t, tc.commitments, deserializedCommitments,
			)

			err = deserializedCommitments.Sign(
				ctx, signer, loc, mintPoint,
			)
			require.NoError(t, err)

			err = deserializedCommitments.Verify(
				mintPoint, privKey.PubKey(),
			)
			require.NoError(t, err)
		})
	}
}
