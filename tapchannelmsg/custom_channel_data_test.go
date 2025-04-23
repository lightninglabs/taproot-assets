package tapchannelmsg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

var (
	hexStr       = hex.EncodeToString
	pubKeyHexStr = func(pubKey *btcec.PublicKey) string {
		return hex.EncodeToString(pubKey.SerializeCompressed())
	}
)

// TestReadChannelCustomData tests that we can read the custom data from a
// channel state response and format it as JSON.
func TestReadChannelCustomData(t *testing.T) {
	proof1 := randProof(t)
	proof2 := randProof(t)
	proof3 := randProof(t)
	proof4 := randProof(t)
	assetID1 := proof1.Asset.ID()
	assetID2 := proof2.Asset.ID()
	assetID3 := proof3.Asset.ID()
	assetID4 := proof4.Asset.ID()
	output1 := NewAssetOutput(assetID1, 1000, proof1)
	output2 := NewAssetOutput(assetID2, 2000, proof2)
	output3 := NewAssetOutput(assetID3, 3000, proof3)
	output4 := NewAssetOutput(assetID4, 4000, proof4)

	fundingState := NewOpenChannel(
		[]*AssetOutput{output1, output2}, 11, nil,
	)
	commitState := NewCommitment(
		[]*AssetOutput{output1}, []*AssetOutput{output2},
		map[input.HtlcIndex][]*AssetOutput{
			1: {output3},
		}, map[input.HtlcIndex][]*AssetOutput{
			2: {output4},
		}, lnwallet.CommitAuxLeaves{},
	)

	fundingBlob := fundingState.Bytes()
	commitBlob := commitState.Bytes()

	var customChannelData bytes.Buffer
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, fundingBlob,
	))
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, commitBlob,
	))

	channelJSON, err := jsonFormatChannelCustomData(
		customChannelData.Bytes(),
	)
	require.NoError(t, err)

	var formattedJSON bytes.Buffer
	err = json.Indent(&formattedJSON, channelJSON, "", "  ")
	require.NoError(t, err)

	expected := `{
  "funding_assets": [
    {
      "version": 0,
      "asset_genesis": {
        "genesis_point": "` + proof1.Asset.FirstPrevOut.String() + `",
        "name": "` + proof1.Asset.Tag + `",
        "meta_hash": "` + hexStr(proof1.Asset.MetaHash[:]) + `",
        "asset_id": "` + hexStr(assetID1[:]) + `"
      },
      "amount": 1,
      "script_key": "` + pubKeyHexStr(proof1.Asset.ScriptKey.PubKey) + `",
      "decimal_display": 11
    },
    {
      "version": 0,
      "asset_genesis": {
        "genesis_point": "` + proof2.Asset.FirstPrevOut.String() + `",
        "name": "` + proof2.Asset.Tag + `",
        "meta_hash": "` + hexStr(proof2.Asset.MetaHash[:]) + `",
        "asset_id": "` + hexStr(assetID2[:]) + `"
      },
      "amount": 1,
      "script_key": "` + pubKeyHexStr(proof2.Asset.ScriptKey.PubKey) + `",
      "decimal_display": 11
    }
  ],
  "local_assets": [
    {
      "asset_id": "` + hexStr(assetID1[:]) + `",
      "amount": 1000
    }
  ],
  "remote_assets": [
    {
      "asset_id": "` + hexStr(assetID2[:]) + `",
      "amount": 2000
    }
  ],
  "outgoing_htlcs": [
    {
      "asset_id": "` + hexStr(assetID3[:]) + `",
      "amount": 3000
    }
  ],
  "incoming_htlcs": [
    {
      "asset_id": "` + hexStr(assetID4[:]) + `",
      "amount": 4000
    }
  ],
  "capacity": 3000,
  "local_balance": 1000,
  "remote_balance": 2000,
  "outgoing_htlc_balance": 3000,
  "incoming_htlc_balance": 4000
}`
	require.Equal(t, expected, formattedJSON.String())
}

// TestReadBalanceCustomData tests that we can read the custom data from a
// channel balance response and format it as JSON.
func TestReadBalanceCustomData(t *testing.T) {
	proof1 := randProof(t)
	proof2 := randProof(t)
	proof3 := randProof(t)
	assetID1 := proof1.Asset.ID()
	assetID2 := proof2.Asset.ID()
	assetID3 := proof3.Asset.ID()
	output1 := NewAssetOutput(assetID1, 1000, proof1)
	output2 := NewAssetOutput(assetID2, 2000, proof2)
	output3 := NewAssetOutput(assetID3, 3000, proof3)

	openChannel1 := NewCommitment(
		[]*AssetOutput{output1}, []*AssetOutput{output2}, nil, nil,
		lnwallet.CommitAuxLeaves{},
	)
	openChannel2 := NewCommitment(
		[]*AssetOutput{output2}, []*AssetOutput{output3}, nil, nil,
		lnwallet.CommitAuxLeaves{},
	)
	pendingChannel1 := NewCommitment(
		[]*AssetOutput{output3}, nil, nil, nil,
		lnwallet.CommitAuxLeaves{},
	)
	pendingChannel2 := NewCommitment(
		nil, []*AssetOutput{output1}, nil, nil,
		lnwallet.CommitAuxLeaves{},
	)

	var customChannelData bytes.Buffer
	require.NoError(t, wire.WriteVarInt(&customChannelData, 0, 2))
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, openChannel1.Bytes(),
	))
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, openChannel2.Bytes(),
	))
	require.NoError(t, wire.WriteVarInt(&customChannelData, 0, 2))
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, pendingChannel1.Bytes(),
	))
	require.NoError(t, wire.WriteVarBytes(
		&customChannelData, 0, pendingChannel2.Bytes(),
	))

	channelJSON, err := jsonFormatBalanceCustomData(
		customChannelData.Bytes(),
	)
	require.NoError(t, err)

	var formattedJSON bytes.Buffer
	err = json.Indent(&formattedJSON, channelJSON, "", "  ")
	require.NoError(t, err)

	// The results are in a map, so the order can't be predicted. But we
	// have distinct balances, so we can just make sure the expected values
	// appear in the JSON.
	expectedOpen1 := `"` + hexStr(assetID1[:]) + `": {
      "asset_id": "` + hexStr(assetID1[:]) + `",
      "name": "` + proof1.Asset.Tag + `",
      "local_balance": 1000,
      "remote_balance": 0
    }`
	expectedOpen2 := `"` + hexStr(assetID2[:]) + `": {
      "asset_id": "` + hexStr(assetID2[:]) + `",
      "name": "` + proof2.Asset.Tag + `",
      "local_balance": 2000,
      "remote_balance": 2000
    }`
	expectedOpen3 := `"` + hexStr(assetID3[:]) + `": {
      "asset_id": "` + hexStr(assetID3[:]) + `",
      "name": "` + proof3.Asset.Tag + `",
      "local_balance": 0,
      "remote_balance": 3000
    }`

	expectedPending1 := `"` + hexStr(assetID1[:]) + `": {
      "asset_id": "` + hexStr(assetID1[:]) + `",
      "name": "` + proof1.Asset.Tag + `",
      "local_balance": 0,
      "remote_balance": 1000
    }`
	expectedPending2 := `"` + hexStr(assetID3[:]) + `": {
      "asset_id": "` + hexStr(assetID3[:]) + `",
      "name": "` + proof3.Asset.Tag + `",
      "local_balance": 3000,
      "remote_balance": 0
    }`

	require.Contains(t, formattedJSON.String(), expectedOpen1)
	require.Contains(t, formattedJSON.String(), expectedOpen2)
	require.Contains(t, formattedJSON.String(), expectedOpen3)
	require.Contains(t, formattedJSON.String(), expectedPending1)
	require.Contains(t, formattedJSON.String(), expectedPending2)
}

// TestCloseOutCustomData tests that we can read the custom data from a channel
// close response and format it as JSON.
func TestCloseOutCustomData(t *testing.T) {
	testAssetInternalKey := test.RandPubKey(t)
	testBtcInternalKey := test.RandPubKey(t)

	testScriptKeys := make(ScriptKeyMap)

	const numScriptKeys = 10
	for i := 0; i < numScriptKeys; i++ {
		testScriptKeys[[32]byte{byte(i)}] = *test.RandPubKey(t)
	}

	shutdownMsg := NewAuxShutdownMsg(
		testBtcInternalKey, testAssetInternalKey,
		testScriptKeys, nil,
	)

	var customChannelData bytes.Buffer
	require.NoError(t, shutdownMsg.Encode(&customChannelData))

	channelJSON, err := jsonFormatCloseOutCustomData(
		customChannelData.Bytes(),
	)
	require.NoError(t, err)

	var formattedJSON bytes.Buffer
	err = json.Indent(&formattedJSON, channelJSON, "", "  ")
	require.NoError(t, err)

	expectedStart := `{
  "btc_internal_key": "` + pubKeyHexStr(testBtcInternalKey) + `",
  "asset_internal_key": "` + pubKeyHexStr(testAssetInternalKey) + `",
  "script_keys": {`
	require.Contains(t, formattedJSON.String(), expectedStart)

	for id, key := range testScriptKeys {
		expected := `"` + hexStr(id[:]) + `": "` +
			pubKeyHexStr(&key) + `"`
		require.Contains(t, formattedJSON.String(), expected)
	}
}

// TestHtlcCustomData tests that we can read the custom data from a HTLC
// response and format it as JSON.
func TestHtlcCustomData(t *testing.T) {
	assetID1 := [32]byte{1}
	assetID2 := [32]byte{2}
	assetID3 := [32]byte{3}
	rfqID := rfqmsg.ID{0, 1, 2, 3, 4, 5, 6, 7}
	htlc := rfqmsg.NewHtlc([]*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(assetID1, 1000),
		rfqmsg.NewAssetBalance(assetID2, 2000),
		rfqmsg.NewAssetBalance(assetID3, 5000),
	}, fn.Some(rfqID))

	var customChannelData bytes.Buffer
	require.NoError(t, htlc.Encode(&customChannelData))

	channelJSON, err := jsonFormatHtlcCustomData(customChannelData.Bytes())
	require.NoError(t, err)

	var formattedJSON bytes.Buffer
	err = json.Indent(&formattedJSON, channelJSON, "", "  ")
	require.NoError(t, err)

	expected := `{
  "balances": [
    {
      "asset_id": "` + hexStr(assetID1[:]) + `",
      "amount": 1000
    },
    {
      "asset_id": "` + hexStr(assetID2[:]) + `",
      "amount": 2000
    },
    {
      "asset_id": "` + hexStr(assetID3[:]) + `",
      "amount": 5000
    }
  ],
  "rfq_id": "` + hexStr(rfqID[:]) + `"
}`
	require.Equal(t, expected, formattedJSON.String())
}
