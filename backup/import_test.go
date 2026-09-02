package backup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

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
