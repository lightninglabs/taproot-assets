package rpcserver

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

func TestScriptKeyTypeAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		skt     asset.ScriptKeyType
		allowed []asset.ScriptKeyType
		want    bool
	}{
		{
			name: "present",
			skt:  asset.ScriptKeyBip86,
			allowed: []asset.ScriptKeyType{
				asset.ScriptKeyBip86,
				asset.ScriptKeyScriptPathExternal,
			},
			want: true,
		},
		{
			name: "absent",
			skt:  asset.ScriptKeyScriptPathChannel,
			allowed: []asset.ScriptKeyType{
				asset.ScriptKeyBip86,
			},
			want: false,
		},
		{
			name:    "empty set",
			skt:     asset.ScriptKeyBip86,
			allowed: nil,
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scriptKeyTypeAllowed(tc.skt, tc.allowed)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAppendChannelScriptKeyType(t *testing.T) {
	t.Parallel()

	ch := asset.ScriptKeyScriptPathChannel

	// Appends when absent.
	out := appendChannelScriptKeyType([]asset.ScriptKeyType{
		asset.ScriptKeyBip86,
	})
	require.Contains(t, out, ch)
	require.Len(t, out, 2)

	// Idempotent when already present.
	out2 := appendChannelScriptKeyType(out)
	require.Equal(t, out, out2)

	// Works on nil input.
	out3 := appendChannelScriptKeyType(nil)
	require.Equal(t, []asset.ScriptKeyType{ch}, out3)
}

func TestJsonToChannelBalances(t *testing.T) {
	t.Parallel()

	idHex := "aabbccdd"
	idBytes, _ := hex.DecodeString(idHex)

	src := map[string]*rfqmsg.JsonAssetBalance{
		"key1": {
			AssetID:       idHex,
			Name:          "test-asset",
			LocalBalance:  100,
			RemoteBalance: 200,
		},
		"key2": {
			AssetID:       "11223344",
			Name:          "other",
			LocalBalance:  50,
			RemoteBalance: 60,
		},
	}

	// No filter returns all entries.
	out := jsonToChannelBalances(src, "")
	require.Len(t, out, 2)
	require.Equal(t, idBytes, out["key1"].AssetId)
	require.Equal(t, "test-asset", out["key1"].Name)
	require.Equal(t, uint64(100), out["key1"].LocalBalance)
	require.Equal(t, uint64(200), out["key1"].RemoteBalance)

	// Filter returns only matching entry.
	out = jsonToChannelBalances(src, "key1")
	require.Len(t, out, 1)
	require.Contains(t, out, "key1")

	// Empty input returns empty output.
	out = jsonToChannelBalances(nil, "")
	require.Empty(t, out)
}

// encodeProofSuffix creates a minimal proof suffix that can be
// sparse-decoded to recover the given asset's leaf data.
func encodeProofSuffix(
	t *testing.T, a *asset.Asset) []byte {

	t.Helper()

	var buf bytes.Buffer
	_, err := buf.Write(proof.PrefixMagicBytes[:])
	require.NoError(t, err)

	rec := proof.AssetLeafRecord(a)
	stream, err := tlv.NewStream(rec)
	require.NoError(t, err)
	require.NoError(t, stream.Encode(&buf))

	return buf.Bytes()
}

// testGroupKey builds a minimal GroupKey from a private key.
func testGroupKey(priv *btcec.PrivateKey) *asset.GroupKey {
	return &asset.GroupKey{
		GroupPubKey: *priv.PubKey(),
	}
}

// testScriptKey builds a ScriptKey with the given type.
func testScriptKey(
	t *testing.T, skt asset.ScriptKeyType) asset.ScriptKey {

	t.Helper()

	priv := test.RandPrivKey()
	return asset.ScriptKey{
		PubKey: priv.PubKey(),
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: priv.PubKey(),
			},
			Type: skt,
		},
	}
}

func TestPendingBalancesByGroup(t *testing.T) {
	t.Parallel()

	groupPriv1 := test.RandPrivKey()
	groupPriv2 := test.RandPrivKey()

	gen := asset.RandGenesis(t, asset.Normal)

	// Build test assets with group keys.
	mkAsset := func(gk *asset.GroupKey) *asset.Asset {
		return &asset.Asset{
			Genesis:  gen,
			Amount:   1, // doesn't matter for proof
			GroupKey: gk,
			ScriptKey: asset.NewScriptKeyBip86(
				keychain.KeyDescriptor{
					PubKey: test.RandPrivKey().PubKey(),
				},
			),
		}
	}

	assetWithGroup1 := mkAsset(testGroupKey(groupPriv1))
	assetWithGroup2 := mkAsset(testGroupKey(groupPriv2))
	assetNoGroup := mkAsset(nil)

	proofGroup1 := encodeProofSuffix(t, assetWithGroup1)
	proofGroup2 := encodeProofSuffix(t, assetWithGroup2)
	proofNoGroup := encodeProofSuffix(t, assetNoGroup)

	bip86Key := testScriptKey(t, asset.ScriptKeyBip86)
	chanKey := testScriptKey(
		t, asset.ScriptKeyScriptPathChannel,
	)

	allTypes := []asset.ScriptKeyType{
		asset.ScriptKeyBip86,
		asset.ScriptKeyScriptPathExternal,
	}

	t.Run("aggregates same group", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{
				{
					ScriptKeyLocal: true,
					Amount:         10,
					ProofSuffix:    proofGroup1,
					ScriptKey:      bip86Key,
				},
				{
					ScriptKeyLocal: true,
					Amount:         5,
					ProofSuffix:    proofGroup1,
					ScriptKey:      bip86Key,
				},
			},
		}}

		result, err := pendingBalancesByGroup(
			parcels, nil, allTypes,
		)
		require.NoError(t, err)
		require.Len(t, result, 1)

		gkHex := hex.EncodeToString(
			groupPriv1.PubKey().SerializeCompressed(),
		)
		require.Equal(t, uint64(15), result[gkHex].Balance)
	})

	t.Run("skips remote outputs", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{{
				ScriptKeyLocal: false,
				Amount:         10,
				ProofSuffix:    proofGroup1,
				ScriptKey:      bip86Key,
			}},
		}}

		result, err := pendingBalancesByGroup(
			parcels, nil, allTypes,
		)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("skips ungrouped assets", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{{
				ScriptKeyLocal: true,
				Amount:         10,
				ProofSuffix:    proofNoGroup,
				ScriptKey:      bip86Key,
			}},
		}}

		result, err := pendingBalancesByGroup(
			parcels, nil, allTypes,
		)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("skips empty proof suffix", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{{
				ScriptKeyLocal: true,
				Amount:         10,
				ScriptKey:      bip86Key,
			}},
		}}

		result, err := pendingBalancesByGroup(
			parcels, nil, allTypes,
		)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("filters by group key", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{
				{
					ScriptKeyLocal: true,
					Amount:         10,
					ProofSuffix:    proofGroup1,
					ScriptKey:      bip86Key,
				},
				{
					ScriptKeyLocal: true,
					Amount:         20,
					ProofSuffix:    proofGroup2,
					ScriptKey:      bip86Key,
				},
			},
		}}

		result, err := pendingBalancesByGroup(
			parcels, groupPriv1.PubKey(), allTypes,
		)
		require.NoError(t, err)
		require.Len(t, result, 1)

		gkHex := hex.EncodeToString(
			groupPriv1.PubKey().SerializeCompressed(),
		)
		require.Equal(t, uint64(10), result[gkHex].Balance)
	})

	t.Run("filters by script key type", func(t *testing.T) {
		parcels := []*tapfreighter.OutboundParcel{{
			Outputs: []tapfreighter.TransferOutput{{
				ScriptKeyLocal: true,
				Amount:         10,
				ProofSuffix:    proofGroup1,
				ScriptKey:      chanKey,
			}},
		}}

		result, err := pendingBalancesByGroup(
			parcels, nil, allTypes,
		)
		require.NoError(t, err)
		require.Empty(t, result)
	})
}
