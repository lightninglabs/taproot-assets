package backup

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/stretchr/testify/require"
)

// mockKeyDeriver is a KeyDeriver that always returns the public key of a
// fixed private key, regardless of the requested locator. It records the
// locators it was asked for.
type mockKeyDeriver struct {
	privKey  *btcec.PrivateKey
	err      error
	locators []keychain.KeyLocator
	nilDesc  bool
}

func newMockKeyDeriver(t *testing.T) *mockKeyDeriver {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return &mockKeyDeriver{privKey: privKey}
}

func (m *mockKeyDeriver) DeriveKey(_ context.Context,
	locator *keychain.KeyLocator) (*keychain.KeyDescriptor, error) {

	m.locators = append(m.locators, *locator)

	if m.err != nil {
		return nil, m.err
	}
	if m.nilDesc {
		return &keychain.KeyDescriptor{}, nil
	}

	return &keychain.KeyDescriptor{
		KeyLocator: *locator,
		PubKey:     m.privKey.PubKey(),
	}, nil
}

// newTestEncrypter returns an encrypter derived from the given mock deriver.
func newTestEncrypter(t *testing.T,
	deriver KeyDeriver) lnencrypt.EncrypterDecrypter {

	encrypter, err := NewKeyRingEncrypter(context.Background(), deriver)
	require.NoError(t, err)

	return encrypter
}

// TestNewKeyRingEncrypter asserts the key derivation contract: the key is
// derived from the base encryption family, and deriver failures propagate.
func TestNewKeyRingEncrypter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("nil deriver", func(t *testing.T) {
		_, err := NewKeyRingEncrypter(ctx, nil)
		require.ErrorIs(t, err, ErrNoKeyDeriver)
	})

	t.Run("uses base encryption key locator", func(t *testing.T) {
		deriver := newMockKeyDeriver(t)
		_, err := NewKeyRingEncrypter(ctx, deriver)
		require.NoError(t, err)

		require.Len(t, deriver.locators, 1)
		require.Equal(t, keychain.KeyLocator{
			Family: keychain.KeyFamilyBaseEncryption,
			Index:  0,
		}, deriver.locators[0])
	})

	t.Run("deriver error propagates", func(t *testing.T) {
		deriver := newMockKeyDeriver(t)
		deriver.err = errors.New("lnd unavailable")

		_, err := NewKeyRingEncrypter(ctx, deriver)
		require.ErrorContains(t, err, "lnd unavailable")
	})

	t.Run("empty descriptor rejected", func(t *testing.T) {
		deriver := newMockKeyDeriver(t)
		deriver.nilDesc = true

		_, err := NewKeyRingEncrypter(ctx, deriver)
		require.ErrorContains(t, err, "empty")
	})

	t.Run("adapter rejects DeriveNextKey", func(t *testing.T) {
		adapter := &keyRingAdapter{
			ctx:     ctx,
			deriver: newMockKeyDeriver(t),
		}
		_, err := adapter.DeriveNextKey(
			keychain.KeyFamilyBaseEncryption,
		)
		require.ErrorIs(t, err, errDeriveNextKeyUnsupported)
	})
}

// TestEncryptDecryptBackup covers the encrypted container round trip and the
// ways decryption must fail.
func TestEncryptDecryptBackup(t *testing.T) {
	t.Parallel()

	deriver := newMockKeyDeriver(t)
	encrypter := newTestEncrypter(t, deriver)

	plaintext, err := EncodeWalletBackup(&WalletBackup{
		Version: BackupVersionStripped,
		Assets:  []*AssetBackup{newTestAssetBackupV2(t)},
	})
	require.NoError(t, err)
	require.False(t, IsEncryptedBackup(plaintext))

	packed, err := EncryptBackup(encrypter, plaintext)
	require.NoError(t, err)
	require.True(t, IsEncryptedBackup(packed))
	require.NotEqual(t, plaintext, packed)

	t.Run("round trip", func(t *testing.T) {
		got, err := DecryptBackup(encrypter, packed)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)

		// The decrypted payload is a regular backup.
		decoded, err := DecodeWalletBackup(got)
		require.NoError(t, err)
		require.Len(t, decoded.Assets, 1)
	})

	t.Run("fresh nonce per encryption", func(t *testing.T) {
		packed2, err := EncryptBackup(encrypter, plaintext)
		require.NoError(t, err)
		require.NotEqual(t, packed, packed2)
	})

	t.Run("wrong key", func(t *testing.T) {
		other := newTestEncrypter(t, newMockKeyDeriver(t))
		_, err := DecryptBackup(other, packed)
		require.ErrorContains(t, err, "unable to decrypt")
	})

	t.Run("same seed decrypts", func(t *testing.T) {
		// A second encrypter derived from the same wallet key must
		// be able to read the file, this is the restore scenario.
		same := newTestEncrypter(t, &mockKeyDeriver{
			privKey: deriver.privKey,
		})
		got, err := DecryptBackup(same, packed)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		tampered := append([]byte{}, packed...)
		tampered[len(tampered)-1] ^= 0xff

		_, err := DecryptBackup(encrypter, tampered)
		require.ErrorContains(t, err, "unable to decrypt")
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		truncated := packed[:encryptedHeaderSize+5]
		_, err := DecryptBackup(encrypter, truncated)
		require.Error(t, err)
	})

	t.Run("unsupported version", func(t *testing.T) {
		bad := append([]byte{}, packed...)
		binary.BigEndian.PutUint32(
			bad[len(encryptedMagicBytes):encryptedHeaderSize], 99,
		)

		_, err := DecryptBackup(encrypter, bad)
		require.ErrorContains(t, err, "unsupported encrypted backup "+
			"version 99")
	})

	t.Run("plaintext is not encrypted", func(t *testing.T) {
		_, err := DecryptBackup(encrypter, plaintext)
		require.ErrorIs(t, err, ErrNotEncrypted)
	})

	t.Run("nil encrypter", func(t *testing.T) {
		_, err := DecryptBackup(nil, packed)
		require.ErrorIs(t, err, ErrNoKeyDeriver)

		_, err = EncryptBackup(nil, plaintext)
		require.ErrorIs(t, err, ErrNoKeyDeriver)
	})

	t.Run("empty plaintext", func(t *testing.T) {
		_, err := EncryptBackup(encrypter, nil)
		require.ErrorContains(t, err, "empty")
	})
}

// TestIsEncryptedBackup checks the header detection edge cases.
func TestIsEncryptedBackup(t *testing.T) {
	t.Parallel()

	require.False(t, IsEncryptedBackup(nil))
	require.False(t, IsEncryptedBackup([]byte(encryptedMagicBytes)))
	require.False(t, IsEncryptedBackup([]byte(backupMagicBytes+"0000")))

	header := append([]byte(encryptedMagicBytes), 0, 0, 0, 1)
	require.True(t, IsEncryptedBackup(header))
}
