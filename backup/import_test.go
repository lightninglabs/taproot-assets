package backup

import (
	"context"
	"errors"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

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
