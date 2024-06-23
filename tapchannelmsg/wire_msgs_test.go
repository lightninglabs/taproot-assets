package tapchannelmsg

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	proofmock "github.com/lightninglabs/taproot-assets/internal/mock/proof"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestAssetFundingMsg tests encoding and decoding of the AssetFundingMsg
// structs.
func TestAssetFundingMsg(t *testing.T) {
	t.Parallel()

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	randGen := assetmock.RandGenesis(t, asset.Normal)
	scriptKey1 := test.RandPubKey(t)
	originalRandProof := proofmock.RandProof(
		t, randGen, scriptKey1, oddTxBlock, 0, 1,
	)

	// Proofs don't Encode everything, so we need to do a quick Encode/
	// Decode cycle to make sure we can compare it afterward.
	proofBytes, err := proof.Encode(&originalRandProof)
	require.NoError(t, err)
	randProof, err := proof.Decode(proofBytes)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		msg   AssetFundingMsg
		empty func() AssetFundingMsg
	}{
		{
			name: "TxAssetInputProof",
			msg: NewTxAssetInputProof(
				[32]byte{1}, *randProof,
			),
			empty: func() AssetFundingMsg {
				return &TxAssetInputProof{}
			},
		},
		{
			name: "TxAssetOutputProof",
			msg: NewTxAssetOutputProof(
				[32]byte{1}, randProof.Asset, true,
			),
			empty: func() AssetFundingMsg {
				return &TxAssetOutputProof{}
			},
		},
		{
			name: "AssetFundingCreated",
			msg: NewAssetFundingCreated(
				[32]byte{1}, []*AssetOutput{
					NewAssetOutput(
						[32]byte{2}, 1, *randProof,
					),
				},
			),
			empty: func() AssetFundingMsg {
				return &AssetFundingCreated{}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the message and then deserialize it again.
			var b bytes.Buffer
			err := tc.msg.Encode(&b, 0)
			require.NoError(t, err)

			deserializedMsg := tc.empty()
			err = deserializedMsg.Decode(&b, 0)
			require.NoError(t, err)

			require.Equal(t, tc.msg, deserializedMsg)
		})
	}
}
