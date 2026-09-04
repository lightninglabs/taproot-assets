package backup

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestScriptKeyTypeForImport asserts how restored script keys are classified.
// The important case is a unique Pedersen key from a V2 address receive: it
// carries a tweak, so a tweak based guess would file it as an external script
// path key and hide the asset from default listings and coin selection.
func TestScriptKeyTypeForImport(t *testing.T) {
	t.Parallel()

	rawKey := keychain.KeyDescriptor{
		PubKey:     test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{Family: 212, Index: 3},
	}
	untyped := func(sk asset.ScriptKey) asset.ScriptKey {
		sk.TweakedScriptKey.Type = asset.ScriptKeyUnknown
		return sk
	}

	// The classifier only reads the ID and the first witness from the
	// asset.
	testAsset := newTestAsset(t)
	assetID := testAsset.ID()

	t.Run("declared type wins", func(t *testing.T) {
		sk := asset.NewScriptKeyBip86(rawKey)
		sk.TweakedScriptKey.Type = asset.ScriptKeyScriptPathChannel
		require.Equal(t, asset.ScriptKeyScriptPathChannel,
			scriptKeyTypeForImport(sk, testAsset))
	})

	t.Run("bip86 derived", func(t *testing.T) {
		sk := untyped(asset.NewScriptKeyBip86(rawKey))
		require.Equal(t, asset.ScriptKeyBip86,
			scriptKeyTypeForImport(sk, testAsset))
	})

	t.Run("tombstone by NUMS key", func(t *testing.T) {
		sk := asset.ScriptKey{
			PubKey:           asset.NUMSPubKey,
			TweakedScriptKey: &asset.TweakedScriptKey{},
		}
		require.Equal(t, asset.ScriptKeyTombstone,
			scriptKeyTypeForImport(sk, testAsset))

		// Even with a raw key attached, NUMS is a tombstone, never
		// BIP-86. All tombstones share one script key row, so a
		// wrong classification would leak into every tombstone.
		sk.TweakedScriptKey.RawKey = rawKey
		require.Equal(t, asset.ScriptKeyTombstone,
			scriptKeyTypeForImport(sk, testAsset))
	})

	t.Run("burn key from first witness", func(t *testing.T) {
		burnAsset := *testAsset
		prevID := asset.PrevID{
			OutPoint:  wire.OutPoint{Index: 7},
			ID:        asset.ID{3},
			ScriptKey: asset.ToSerialized(test.RandPubKey(t)),
		}
		burnAsset.PrevWitnesses = []asset.Witness{{PrevID: &prevID}}
		sk := asset.ScriptKey{
			PubKey:           asset.DeriveBurnKey(prevID),
			TweakedScriptKey: &asset.TweakedScriptKey{},
		}
		require.Equal(t, asset.ScriptKeyBurn,
			scriptKeyTypeForImport(sk, &burnAsset))
	})

	t.Run("unique pedersen derived", func(t *testing.T) {
		sk, err := asset.DeriveUniqueScriptKey(
			*rawKey.PubKey, assetID,
			asset.ScriptKeyDerivationUniquePedersen,
		)
		require.NoError(t, err)
		require.NotEmpty(t, sk.TweakedScriptKey.Tweak)
		sk.TweakedScriptKey.RawKey = rawKey

		require.Equal(t, asset.ScriptKeyUniquePedersen,
			scriptKeyTypeForImport(untyped(sk), testAsset))

		// A different asset does not derive the same key, so it
		// falls through to the tweaked classification.
		other := newTestAsset(t)
		other.Genesis.Tag = "other"
		require.NotEqual(t, assetID, other.ID())
		require.Equal(t, asset.ScriptKeyScriptPathExternal,
			scriptKeyTypeForImport(untyped(sk), other))
	})

	t.Run("other tweak is external script path", func(t *testing.T) {
		sk := asset.ScriptKey{
			PubKey: test.RandPubKey(t),
			TweakedScriptKey: &asset.TweakedScriptKey{
				RawKey: rawKey,
				Tweak:  []byte("some tapscript root"),
			},
		}
		require.Equal(t, asset.ScriptKeyScriptPathExternal,
			scriptKeyTypeForImport(sk, testAsset))
	})

	t.Run("no raw key and no tweak", func(t *testing.T) {
		sk := asset.ScriptKey{
			PubKey:           test.RandPubKey(t),
			TweakedScriptKey: &asset.TweakedScriptKey{},
		}
		require.Equal(t, asset.ScriptKeyBip86,
			scriptKeyTypeForImport(sk, testAsset))
	})

	t.Run("missing material", func(t *testing.T) {
		require.Equal(t, asset.ScriptKeyUnknown,
			scriptKeyTypeForImport(asset.ScriptKey{}, testAsset))
		require.Equal(t, asset.ScriptKeyUnknown,
			scriptKeyTypeForImport(
				asset.NewScriptKeyBip86(rawKey), nil,
			))
	})
}

// TestKeyMaterialComplete asserts that entries missing the public keys they
// describe are recognised, so the import skips them instead of crashing.
func TestKeyMaterialComplete(t *testing.T) {
	t.Parallel()

	complete := newTestAssetBackupV2(t)
	require.True(t, keyMaterialComplete(complete))

	noKeys := newTestAssetBackupV2(t)
	noKeys.ScriptKeyInfo = nil
	noKeys.AnchorInternalKeyInfo = nil
	require.True(t, keyMaterialComplete(noKeys))

	noScriptPub := newTestAssetBackupV2(t)
	noScriptPub.ScriptKeyInfo.PubKey = nil
	require.False(t, keyMaterialComplete(noScriptPub))

	noRawPub := newTestAssetBackupV2(t)
	noRawPub.ScriptKeyInfo.RawKey.PubKey = nil
	require.False(t, keyMaterialComplete(noRawPub))

	noAnchorPub := newTestAssetBackupV2(t)
	noAnchorPub.AnchorInternalKeyInfo.PubKey = nil
	require.False(t, keyMaterialComplete(noAnchorPub))
}

// TestCreateAssetBackupRecordsType asserts the export records the script key
// type, taking the stored type and otherwise deriving it.
func TestCreateAssetBackupRecordsType(t *testing.T) {
	t.Parallel()

	rawKey := keychain.KeyDescriptor{
		PubKey:     test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{Family: 212, Index: 1},
	}

	// Stored type wins.
	a := newTestAsset(t)
	a.ScriptKey = asset.NewScriptKeyBip86(rawKey)
	a.ScriptKey.TweakedScriptKey.Type = asset.ScriptKeyUniquePedersen
	ab, err := createAssetBackup(
		context.Background(), &asset.ChainAsset{Asset: a}, nil, nil,
	)
	require.NoError(t, err)
	require.Equal(t, asset.ScriptKeyUniquePedersen, ab.ScriptKeyInfo.Type)

	// Unknown stored type is derived from the key material.
	a.ScriptKey.TweakedScriptKey.Type = asset.ScriptKeyUnknown
	ab, err = createAssetBackup(
		context.Background(), &asset.ChainAsset{Asset: a}, nil, nil,
	)
	require.NoError(t, err)
	require.Equal(t, asset.ScriptKeyBip86, ab.ScriptKeyInfo.Type)
}

// TestScriptKeyBackupTypeEncoding asserts the type round trips and that a
// backup written without it decodes to an unknown type.
func TestScriptKeyBackupTypeEncoding(t *testing.T) {
	t.Parallel()

	sk := newTestScriptKeyBackup(t)
	sk.Type = asset.ScriptKeyUniquePedersen

	var buf bytes.Buffer
	require.NoError(t, sk.Encode(&buf))

	var decoded ScriptKeyBackup
	require.NoError(t, decoded.Decode(&buf))
	require.Equal(t, asset.ScriptKeyUniquePedersen, decoded.Type)

	// A type this decoder does not know reads back as unknown, so the
	// importer classifies from the key material instead of registering
	// a type no filter matches.
	sk.Type = asset.ScriptKeyType(200)
	buf.Reset()
	require.NoError(t, sk.Encode(&buf))
	var future ScriptKeyBackup
	require.NoError(t, future.Decode(&buf))
	require.Equal(t, asset.ScriptKeyUnknown, future.Type)

	// Without a type nothing is written for it and it reads back as
	// unknown, which the import then classifies from the key material.
	sk.Type = asset.ScriptKeyUnknown
	buf.Reset()
	require.NoError(t, sk.Encode(&buf))

	var legacy ScriptKeyBackup
	require.NoError(t, legacy.Decode(&buf))
	require.Equal(t, asset.ScriptKeyUnknown, legacy.Type)
}

// staticExporter is a proof.Exporter that answers every lookup the same way.
type staticExporter struct {
	err error
}

func (s *staticExporter) FetchProof(context.Context,
	proof.Locator) (proof.Blob, error) {

	if s.err != nil {
		return nil, s.err
	}

	return proof.Blob("found"), nil
}

// TestAssetExists asserts that the existence check consults the wallet
// database store when one is configured, and only falls back to the full
// archive without it. A proof file left on disk must not make an asset look
// like it is already part of a wiped wallet.
func TestAssetExists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	found := &staticExporter{}
	missing := &staticExporter{err: proof.ErrProofNotFound}
	broken := &staticExporter{err: errors.New("db locked")}

	t.Run("wallet store wins over archive", func(t *testing.T) {
		exists, err := assetExists(ctx, &ImportConfig{
			ProofArchive: proof.NewMockProofArchive(),
			WalletProofs: missing,
		}, proof.Locator{})
		require.NoError(t, err)
		require.False(t, exists)

		exists, err = assetExists(ctx, &ImportConfig{
			ProofArchive: proof.NewMockProofArchive(),
			WalletProofs: found,
		}, proof.Locator{})
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("archive fallback", func(t *testing.T) {
		exists, err := assetExists(ctx, &ImportConfig{
			ProofArchive: proof.NewMockProofArchive(),
		}, proof.Locator{})
		require.NoError(t, err)
		require.False(t, exists)
	})

	t.Run("store error is fatal", func(t *testing.T) {
		_, err := assetExists(ctx, &ImportConfig{
			ProofArchive: proof.NewMockProofArchive(),
			WalletProofs: broken,
		}, proof.Locator{})
		require.ErrorContains(t, err, "db locked")
	})
}

// TestImportBackupEncrypted covers the decryption gate at the start of
// ImportBackup. The config deliberately carries only a key deriver: any path
// that reaches the chain or archive would dereference nil and panic, which
// proves the encrypted cases are decided before any other dependency is used.
func TestImportBackupEncrypted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deriver := newMockKeyDeriver(t)
	encrypter := newTestEncrypter(t, deriver)

	// An empty wallet backup needs no chain access to import, so the
	// happy path can run end to end with an otherwise empty config.
	plaintext, err := EncodeWalletBackup(&WalletBackup{
		Version: BackupVersionStripped,
	})
	require.NoError(t, err)

	packed, err := EncryptBackup(encrypter, plaintext)
	require.NoError(t, err)

	t.Run("no key deriver", func(t *testing.T) {
		_, _, err := ImportBackup(ctx, packed, &ImportConfig{})
		require.ErrorIs(t, err, ErrNoKeyDeriver)
	})

	t.Run("wrong key", func(t *testing.T) {
		_, _, err := ImportBackup(ctx, packed, &ImportConfig{
			KeyDeriver: newMockKeyDeriver(t),
		})
		require.ErrorContains(t, err, "unable to decrypt")
	})

	t.Run("key derivation fails", func(t *testing.T) {
		bad := newMockKeyDeriver(t)
		bad.err = context.DeadlineExceeded

		_, _, err := ImportBackup(ctx, packed, &ImportConfig{
			KeyDeriver: bad,
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("correct key", func(t *testing.T) {
		imported, skipped, err := ImportBackup(ctx, packed,
			&ImportConfig{KeyDeriver: deriver})
		require.NoError(t, err)
		require.Zero(t, imported)
		require.Zero(t, skipped)
	})

	t.Run("encrypted v1 and v3 payloads", func(t *testing.T) {
		for _, version := range []uint32{
			BackupVersionOriginal, BackupVersionOptimistic,
		} {
			wb := &WalletBackup{Version: version}
			if version == BackupVersionOptimistic {
				wb.FederationURLs = []string{"u:1"}
			}
			plain, err := EncodeWalletBackup(wb)
			require.NoError(t, err)
			enc, err := EncryptBackup(encrypter, plain)
			require.NoError(t, err)

			imported, skipped, err := ImportBackup(ctx, enc,
				&ImportConfig{KeyDeriver: deriver})
			require.NoError(t, err)
			require.Zero(t, imported)
			require.Zero(t, skipped)
		}
	})

	t.Run("garbage plaintext", func(t *testing.T) {
		enc, err := EncryptBackup(encrypter, []byte("not a backup"))
		require.NoError(t, err)

		_, _, err = ImportBackup(ctx, enc, &ImportConfig{
			KeyDeriver: deriver,
		})
		require.ErrorContains(t, err, "failed to decode backup")
	})

	t.Run("plaintext still accepted", func(t *testing.T) {
		imported, skipped, err := ImportBackup(
			ctx, plaintext, &ImportConfig{},
		)
		require.NoError(t, err)
		require.Zero(t, imported)
		require.Zero(t, skipped)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		tampered := append([]byte{}, packed...)
		tampered[len(tampered)-1] ^= 0x01

		_, _, err := ImportBackup(ctx, tampered, &ImportConfig{
			KeyDeriver: deriver,
		})
		require.ErrorContains(t, err, "unable to decrypt")
	})
}
