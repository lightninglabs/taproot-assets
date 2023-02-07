package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	hashBytes1     = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	hashBytes2     = [32]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	pubKeyBytes, _ = hex.DecodeString(
		"03a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f",
	)
	pubKey, _   = btcec.ParsePubKey(pubKeyBytes)
	sigBytes, _ = hex.DecodeString(
		"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
	)
	sig, _ = schnorr.ParseSignature(sigBytes)
)

// TestGroupKeyIsEqual tests that GroupKey.IsEqual is correct.
func TestGroupKeyIsEqual(t *testing.T) {
	t.Parallel()

	testKey := &GroupKey{
		RawKey: keychain.KeyDescriptor{
			// Fill in some non-defaults.
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyMultiSig,
				Index:  1,
			},
			PubKey: pubKey,
		},
		GroupPubKey: *pubKey,
		Sig:         *sig,
	}

	pubKeyCopy := *pubKey

	tests := []struct {
		a, b  *GroupKey
		equal bool
	}{
		{
			a:     nil,
			b:     nil,
			equal: true,
		},
		{
			a:     &GroupKey{},
			b:     &GroupKey{},
			equal: true,
		},
		{
			a:     nil,
			b:     &GroupKey{},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				GroupPubKey: *pubKey,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
					PubKey:     nil,
				},

				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: &pubKeyCopy,
				},

				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
					PubKey:     &pubKeyCopy,
				},

				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: true,
		},
		{
			a: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			b: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: true,
		},
		{
			a: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
				},
				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
				},
				GroupPubKey: testKey.GroupPubKey,
				Sig:         testKey.Sig,
			},
			equal: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		require.Equal(t, testCase.equal, testCase.a.IsEqual(testCase.b))
		require.Equal(t, testCase.equal, testCase.b.IsEqual(testCase.a))
	}
}

// TestAssetEncoding asserts that we can properly encode and decode assets
// through their TLV serialization.
func TestAssetEncoding(t *testing.T) {
	t.Parallel()

	assertAssetEncoding := func(a *Asset) {
		t.Helper()

		require.True(t, a.DeepEqual(a.Copy()))

		var buf bytes.Buffer
		require.NoError(t, a.Encode(&buf))

		var b Asset
		require.NoError(t, b.Decode(&buf))

		require.True(t, a.DeepEqual(&b))
	}

	split := &Asset{
		Version: 1,
		Genesis: Genesis{
			FirstPrevOut: wire.OutPoint{
				Hash:  hashBytes1,
				Index: 1,
			},
			Tag:         "asset",
			Metadata:    []byte{1, 2, 3},
			OutputIndex: 1,
			Type:        1,
		},
		Amount:           1,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes1,
					Index: 1,
				},
				ID:        hashBytes1,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       nil,
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       1,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey: &GroupKey{
			GroupPubKey: *pubKey,
			Sig:         *sig,
		},
	}
	root := &Asset{
		Version:          1,
		Genesis:          split.Genesis,
		Amount:           1,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes2,
					Index: 2,
				},
				ID:        hashBytes2,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       wire.TxWitness{{2}, {2}},
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: mssmt.NewComputedNode(hashBytes1, 1337),
		ScriptVersion:       1,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey: &GroupKey{
			GroupPubKey: *pubKey,
			Sig:         *sig,
		},
	}
	split.PrevWitnesses[0].SplitCommitment = &SplitCommitment{
		Proof:     *mssmt.NewProof(mssmt.EmptyTree[:mssmt.MaxTreeLevels]),
		RootAsset: *root,
	}
	assertAssetEncoding(split)

	assertAssetEncoding(&Asset{
		Version: 2,
		Genesis: Genesis{
			FirstPrevOut: wire.OutPoint{
				Hash:  hashBytes2,
				Index: 2,
			},
			Tag:         "asset",
			Metadata:    []byte{1, 2, 3},
			OutputIndex: 2,
			Type:        2,
		},
		Amount:           2,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID:          nil,
			TxWitness:       nil,
			SplitCommitment: nil,
		}, {
			PrevID:          &PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		}, {
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes2,
					Index: 2,
				},
				ID:        hashBytes2,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       wire.TxWitness{{2}, {2}},
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       2,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey:            nil,
	})
}

// TestAssetType asserts that the number of issued assets is set according to
// the genesis type when creating a new asset.
func TestAssetType(t *testing.T) {
	t.Parallel()

	normalGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "normal asset",
		Metadata:    []byte{1, 2, 3},
		OutputIndex: 1,
		Type:        Normal,
	}
	collectibleGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "collectible asset",
		Metadata:    []byte{1, 2, 3},
		OutputIndex: 2,
		Type:        Collectible,
	}
	scriptKey := NewScriptKey(pubKey)

	normal, err := New(normalGen, 741, 0, 0, scriptKey, nil)
	require.NoError(t, err)
	require.EqualValues(t, 741, normal.Amount)

	_, err = New(collectibleGen, 741, 0, 0, scriptKey, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "amount must be 1 for asset")

	collectible, err := New(collectibleGen, 1, 0, 0, scriptKey, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, collectible.Amount)
}

// TestAssetID makes sure that the asset ID is derived correctly.
func TestAssetID(t *testing.T) {
	t.Parallel()

	g := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "collectible asset 1",
		Metadata:    []byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Collectible,
	}
	tagHash := sha256.Sum256([]byte(g.Tag))
	metadataHash := sha256.Sum256(g.Metadata)

	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &g.FirstPrevOut)
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(metadataHash[:])
	_, _ = h.Write([]byte{0, 0, 0, 21, 1})
	result := h.Sum(nil)

	id := g.ID()
	require.Equal(t, result, id[:])

	// Make sure we get a different asset ID even if everything is the same
	// except for the type.
	normalWithDifferentType := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "collectible asset 1",
		Metadata:    []byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Normal,
	}
	differentID := normalWithDifferentType.ID()
	require.NotEqual(t, id[:], differentID[:])
}

// TestAssetGroupKey tests that the asset key group is derived correctly.
func TestAssetGroupKey(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKeyCopy := btcec.PrivKeyFromScalar(&privKey.Key)
	genSigner := NewRawKeyGenesisSigner(privKeyCopy)
	fakeKeyDesc := keychain.KeyDescriptor{
		PubKey: privKeyCopy.PubKey(),
	}

	g := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "normal asset 1",
		Metadata:    []byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Collectible,
	}

	var groupBytes bytes.Buffer
	_ = wire.WriteOutPoint(&groupBytes, 0, 0, &g.FirstPrevOut)
	_, _ = groupBytes.Write([]byte{0, 0, 0, 21, 1})

	tweakedKey := txscript.TweakTaprootPrivKey(*privKey, groupBytes.Bytes())

	// TweakTaprootPrivKey modifies the private key that is passed in! We
	// need to provide a copy to arrive at the same result.
	keyGroup, err := DeriveGroupKey(genSigner, fakeKeyDesc, g, nil)
	require.NoError(t, err)

	require.Equal(
		t, schnorr.SerializePubKey(tweakedKey.PubKey()),
		schnorr.SerializePubKey(&keyGroup.GroupPubKey),
	)
}

func FuzzAssetDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		a := &Asset{}
		if err := a.Decode(r); err != nil {
			return
		}
	})
}
