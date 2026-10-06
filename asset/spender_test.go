package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// randPrevID returns a random previous ID.
func randPrevID(t *testing.T) PrevID {
	return PrevID{
		OutPoint: wire.OutPoint{
			Hash:  test.RandHash(),
			Index: test.RandInt[uint32](),
		},
		ID:        RandID(t),
		ScriptKey: ToSerialized(test.RandPubKey(t)),
	}
}

// TestDeriveSpenderKey tests the derivation of the script key of a spender
// leaf. The key is committed to on chain, so its derivation must not change.
func TestDeriveSpenderKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		prevID      PrevID
		expectedKey string
	}{{
		name:   "empty prev ID",
		prevID: PrevID{},
		expectedKey: "05e57c33df19e0e78cf6ede1198aec52e64b190c" +
			"9624eb9ab9ee06cf8fb9aaca",
	}, {
		name: "dummy value ID",
		prevID: PrevID{
			OutPoint: wire.OutPoint{
				Hash: chainhash.Hash{
					0x77, 0x88, 0x99, 0xaa,
				},
				Index: 123,
			},
			ID: ID{
				0x01, 0x02, 0x03, 0x04,
			},
			ScriptKey: SerializedKey{
				0x02, 0x03, 0x04, 0x05,
			},
		},
		expectedKey: "5f3863d541fc850271a192c25c890219f80c7032" +
			"b485cff127fce6d2bb48ca24",
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spenderKey := DeriveSpenderKey(tc.prevID)
			require.Equal(t, tc.expectedKey, hex.EncodeToString(
				schnorr.SerializePubKey(spenderKey),
			))

			// The parity of the key is dropped.
			require.Equal(
				t, byte(0x02),
				spenderKey.SerializeCompressed()[0],
			)

			// The key is set apart from the burn key of the input,
			// which is the script key of its STXO.
			burnKey := DeriveBurnKey(tc.prevID)
			require.False(t, spenderKey.IsEqual(burnKey))
		})
	}
}

// TestMakeSpenderAsset tests that a spender leaf is located by the input alone,
// while its content names the spender.
func TestMakeSpenderAsset(t *testing.T) {
	t.Parallel()

	prevID := randPrevID(t)
	witness := Witness{
		PrevID: &prevID,
	}

	spender := RandAsset(t, Normal)
	spenderLeaf, err := MakeSpenderAsset(witness, spender)
	require.NoError(t, err)
	require.NoError(t, spenderLeaf.ValidateAltLeaf())
	require.True(t, spenderLeaf.IsAltLeaf())
	require.True(
		t, spenderLeaf.ScriptKey.PubKey.IsEqual(
			DeriveSpenderKey(prevID),
		),
	)

	// The leaf carries the hash of the commitment keys of the spender.
	tapKey := spender.TapCommitmentKey()
	assetKey := spender.AssetCommitmentKey()
	slot := sha256.Sum256(append(tapKey[:], assetKey[:]...))
	require.Equal(t, []Witness{{
		TxWitness: wire.TxWitness{slot[:]},
	}}, spenderLeaf.PrevWitnesses)

	// The leaf is committed to next to the STXO of the input.
	stxoLeaf, err := MakeSpentAsset(witness)
	require.NoError(t, err)
	require.NotEqual(
		t, stxoLeaf.AssetCommitmentKey(),
		spenderLeaf.AssetCommitmentKey(),
	)
	require.NoError(
		t, ValidAltLeaves(ToAltLeaves([]*Asset{stxoLeaf, spenderLeaf})),
	)

	// Another spender of the same input claims the same place with a
	// different leaf, whether it differs from the first by its script key
	// or by its asset ID.
	otherScriptKey := spender.Copy()
	otherScriptKey.ScriptKey = RandScriptKey(t)

	otherID := spender.Copy()
	otherID.Genesis = RandGenesis(t, Normal)

	leaf, err := spenderLeaf.Leaf()
	require.NoError(t, err)

	for _, otherSpender := range []*Asset{otherScriptKey, otherID} {
		otherLeaf, err := MakeSpenderAsset(witness, otherSpender)
		require.NoError(t, err)
		require.Equal(
			t, spenderLeaf.AssetCommitmentKey(),
			otherLeaf.AssetCommitmentKey(),
		)
		require.ErrorIs(
			t, ValidAltLeaves(
				ToAltLeaves([]*Asset{spenderLeaf, otherLeaf}),
			), ErrDuplicateAltLeafKey,
		)

		otherNode, err := otherLeaf.Leaf()
		require.NoError(t, err)
		require.False(t, mssmt.IsEqualNode(leaf, otherNode))
	}

	// The same spender of another input claims another place.
	otherPrevID := randPrevID(t)
	otherInputLeaf, err := MakeSpenderAsset(Witness{
		PrevID: &otherPrevID,
	}, spender)
	require.NoError(t, err)
	require.NotEqual(
		t, spenderLeaf.AssetCommitmentKey(),
		otherInputLeaf.AssetCommitmentKey(),
	)

	// The leaf is committed to as it is encoded.
	var buf bytes.Buffer
	require.NoError(t, spenderLeaf.EncodeAltLeaf(&buf))

	var decoded Asset
	require.NoError(t, decoded.DecodeAltLeaf(&buf))
	require.NoError(t, decoded.ValidateAltLeaf())

	decodedLeaf, err := decoded.Leaf()
	require.NoError(t, err)
	require.True(t, mssmt.IsEqualNode(leaf, decodedLeaf))

	// A witness without a prev ID references no input.
	_, err = MakeSpenderAsset(Witness{}, spender)
	require.ErrorContains(t, err, "witness has no prevID")
}

// TestCollectSpenders tests that only the root asset of a transfer is named as
// the spender of its inputs.
func TestCollectSpenders(t *testing.T) {
	t.Parallel()

	prevIDs := []PrevID{randPrevID(t), randPrevID(t)}

	root := RandAsset(t, Normal)
	root.PrevWitnesses = []Witness{{
		PrevID:    &prevIDs[0],
		TxWitness: wire.TxWitness{{0x01}},
	}, {
		PrevID:    &prevIDs[1],
		TxWitness: wire.TxWitness{{0x02}},
	}}
	require.True(t, root.IsTransferRoot())

	spenders, err := CollectSpenders(root)
	require.NoError(t, err)
	require.Len(t, spenders, len(prevIDs))

	stxos, err := CollectSTXO(root)
	require.NoError(t, err)
	require.Len(t, stxos, len(prevIDs))

	for idx := range prevIDs {
		spender := spenders[idx].(*Asset)
		require.True(
			t, spender.ScriptKey.PubKey.IsEqual(
				DeriveSpenderKey(prevIDs[idx]),
			),
		)
	}
	require.NoError(t, ValidAltLeaves(append(stxos, spenders...)))

	// A genesis asset spends no inputs.
	genesis := RandAsset(t, Normal)
	genesis.PrevWitnesses = []Witness{{
		PrevID: &ZeroPrevID,
	}}
	require.True(t, genesis.IsGenesisAsset())

	spenders, err = CollectSpenders(genesis)
	require.NoError(t, err)
	require.Empty(t, spenders)

	// A split asset takes part in the transfer of its root asset.
	split := RandAsset(t, Normal)
	split.PrevWitnesses = []Witness{{
		PrevID: &ZeroPrevID,
		SplitCommitment: &SplitCommitment{
			RootAsset: *root,
		},
	}}
	require.True(t, split.HasSplitCommitmentWitness())

	spenders, err = CollectSpenders(split)
	require.NoError(t, err)
	require.Empty(t, spenders)
}
