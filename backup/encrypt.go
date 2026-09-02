package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnencrypt"
)

const (
	// encryptedMagicBytes are the magic bytes that identify an encrypted
	// backup blob. They are distinct from the plaintext magic so a decoder
	// can tell the two apart before attempting to decrypt.
	encryptedMagicBytes = "TAPENC"

	// EncryptedBackupVersion is the current version of the encrypted
	// backup container format.
	EncryptedBackupVersion uint32 = 1

	// encryptedHeaderSize is the size of the encrypted container header:
	// magic bytes followed by a big endian uint32 version.
	encryptedHeaderSize = len(encryptedMagicBytes) + 4
)

var (
	// ErrNotEncrypted is returned when a blob does not carry the encrypted
	// container header.
	ErrNotEncrypted = errors.New("backup is not encrypted")

	// ErrNoKeyDeriver is returned when an encrypted backup is presented
	// but no key deriver is available to decrypt it.
	ErrNoKeyDeriver = errors.New("encrypted backup but no key deriver " +
		"configured")

	// errDeriveNextKeyUnsupported is returned by the key ring adapter for
	// the DeriveNextKey method, which the encrypter never calls.
	errDeriveNextKeyUnsupported = errors.New("DeriveNextKey is not " +
		"supported by the backup key ring adapter")
)

// KeyDeriver is the minimal interface needed to derive the backup encryption
// key from the lnd wallet. It is satisfied by lndclient's WalletKitClient.
type KeyDeriver interface {
	// DeriveKey derives the key described by the given locator.
	DeriveKey(ctx context.Context,
		locator *keychain.KeyLocator) (*keychain.KeyDescriptor, error)
}

// keyRingAdapter adapts a context aware KeyDeriver to lnd's keychain.KeyRing
// interface so that lnencrypt.KeyRingEncrypter can be reused as is.
type keyRingAdapter struct {
	ctx     context.Context //nolint:containedctx
	deriver KeyDeriver
}

// DeriveNextKey is part of the keychain.KeyRing interface. The encrypter
// never calls it, so it is not supported.
func (k *keyRingAdapter) DeriveNextKey(
	keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	return keychain.KeyDescriptor{}, errDeriveNextKeyUnsupported
}

// DeriveKey derives the key described by the given locator through the
// wrapped KeyDeriver.
func (k *keyRingAdapter) DeriveKey(
	keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {

	desc, err := k.deriver.DeriveKey(k.ctx, &keyLoc)
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}
	if desc == nil || desc.PubKey == nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("derived key " +
			"descriptor is empty")
	}

	return *desc, nil
}

// A compile time assertion to ensure keyRingAdapter meets the
// keychain.KeyRing interface.
var _ keychain.KeyRing = (*keyRingAdapter)(nil)

// NewKeyRingEncrypter derives the backup encryption key from the lnd wallet
// and returns an encrypter/decrypter that uses it. The key is derived the
// same way lnd derives the key for its static channel backup file, so a
// backup encrypted by tapd can be decrypted by any tapd connected to an lnd
// with the same seed.
func NewKeyRingEncrypter(ctx context.Context,
	deriver KeyDeriver) (lnencrypt.EncrypterDecrypter, error) {

	if deriver == nil {
		return nil, ErrNoKeyDeriver
	}

	encrypter, err := lnencrypt.KeyRingEncrypter(&keyRingAdapter{
		ctx:     ctx,
		deriver: deriver,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to derive backup encryption "+
			"key: %w", err)
	}

	return encrypter, nil
}

// IsEncryptedBackup returns true if the given blob carries the encrypted
// backup container header.
func IsEncryptedBackup(data []byte) bool {
	if len(data) < encryptedHeaderSize {
		return false
	}

	return bytes.Equal(
		data[:len(encryptedMagicBytes)], []byte(encryptedMagicBytes),
	)
}

// EncryptBackup wraps an encoded (plaintext) wallet backup into the encrypted
// container format: magic bytes, a version and the AEAD sealed payload.
func EncryptBackup(encrypter lnencrypt.EncrypterDecrypter,
	plaintext []byte) ([]byte, error) {

	if encrypter == nil {
		return nil, ErrNoKeyDeriver
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("backup data is empty")
	}

	var buf bytes.Buffer
	buf.WriteString(encryptedMagicBytes)

	var versionBuf [4]byte
	binary.BigEndian.PutUint32(versionBuf[:], EncryptedBackupVersion)
	buf.Write(versionBuf[:])

	err := encrypter.EncryptPayloadToWriter(plaintext, &buf)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt backup: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptBackup unwraps an encrypted backup container and returns the encoded
// plaintext wallet backup. ErrNotEncrypted is returned if the blob does not
// carry the encrypted header.
func DecryptBackup(encrypter lnencrypt.EncrypterDecrypter,
	data []byte) ([]byte, error) {

	if !IsEncryptedBackup(data) {
		return nil, ErrNotEncrypted
	}
	if encrypter == nil {
		return nil, ErrNoKeyDeriver
	}

	version := binary.BigEndian.Uint32(
		data[len(encryptedMagicBytes):encryptedHeaderSize],
	)
	if version != EncryptedBackupVersion {
		return nil, fmt.Errorf("unsupported encrypted backup "+
			"version %d", version)
	}

	plaintext, err := encrypter.DecryptPayloadFromReader(
		bytes.NewReader(data[encryptedHeaderSize:]),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt backup: %w", err)
	}

	return plaintext, nil
}
