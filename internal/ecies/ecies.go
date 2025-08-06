// This package implements an ECIES (Elliptic Curve Integrated Encryption
// Scheme) encryption. It uses ChaCha20Poly1305 for encryption and HKDF with
// SHA256 for key derivation. The package provides functions to encrypt and
// decrypt messages using a shared secret derived between two parties using ECDH
// (Elliptic Curve Diffie-Hellman).

package ecies

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// protocolName is the name of the protocol used for encryption and
	// decryption. This is used to salt the HKDF key derivation.
	protocolName = "ECIES-HKDF-SHA256-XCHA20POLY1305"
)

// Version represents the version of the ECIES encoding format.
type Version uint8

const (
	// VersionUndefined is the undefined version of the ECIES encoding
	// format. It is used to indicate that the version is not set or
	// that the version is unknown.
	VersionUndefined Version = 0

	// VersionV1 represents the initial version of the ECIES encoding
	// format.
	VersionV1 Version = 1

	// LatestVersion is the latest supported protocol version.
	latestVersion = VersionV1
)

// String returns the string representation of the version.
func (v Version) String() string {
	switch v {
	case VersionUndefined:
		return "Undefined"
	case VersionV1:
		return "V1"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// EncryptSha256ChaCha20Poly1305 encrypts the given message using
// ChaCha20Poly1305 with a shared secret (usually derived using ECDH between the
// sender's ephemeral key and the receiver's public key) that is hardened using
// HKDF with SHA256. The cipher also authenticates the additional data and
// prepends it to the returned encrypted message. The additional data is limited
// to at most 255 bytes. The output is a byte slice containing:
//
// <1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
// <* bytes ciphertext>
func EncryptSha256ChaCha20Poly1305(sharedSecret [32]byte, msg []byte,
	additionalData []byte) ([]byte, error) {

	if len(additionalData) > math.MaxUint8 {
		return nil, fmt.Errorf("additional data too long: %d bytes "+
			"given, 255 bytes maximum", len(additionalData))
	}

	// Select a random nonce.
	nonceSize := chacha20poly1305.NonceSizeX
	nonce := make([]byte, nonceSize)

	if _, err := crand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random nonce: %w", err)
	}

	// Derive a strong session key from the shared secret using HKDF-SHA256.
	// The nonce is used as the salt, and the protocol name as the info
	// label. This mitigates risks from weak shared secrets.
	stretchedKey, err := HkdfSha256(
		sharedSecret[:], nonce, []byte(protocolName),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// We can now create a new XChaCha20Poly1305 AEAD cipher using the
	// stretched key.
	aead, err := chacha20poly1305.NewX(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new chacha20poly1305 "+
			"cipher: %w", err)
	}

	// Sanity check the nonce size used.
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length")
	}

	// Construct an extended nonce which has additional capacity for the
	// ciphertext.
	extendedNonce := make(
		[]byte, aead.NonceSize(),
		aead.NonceSize()+len(msg)+aead.Overhead(),
	)
	copy(extendedNonce, nonce)

	ciphertext := aead.Seal(
		extendedNonce, extendedNonce, msg, additionalData,
	)

	var result bytes.Buffer
	result.WriteByte(byte(latestVersion))
	result.WriteByte(byte(len(additionalData)))
	result.Write(additionalData)
	result.Write(ciphertext)

	return result.Bytes(), nil
}

// ExtractAdditionalData extracts the version, additional data, and the
// ciphertext from the given message. The message must be in the format:
//
// <1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
// <* bytes ciphertext>
func ExtractAdditionalData(msg []byte) (Version, []byte, []byte, error) {
	// We need at least 2 bytes for the version and additional data length.
	if len(msg) < 2 {
		return VersionUndefined, nil, nil, fmt.Errorf("ciphertext "+
			"too short: %d bytes given, 2 bytes minimum", len(msg))
	}

	// Extract the version from the first byte of the ciphertext.
	version := Version(msg[0])

	// Check if the version is supported. We currently only support the
	// latest version. Return an error early if the version is not supported
	// as the encoding format may be incompatible with the current
	// implementation.
	if version != latestVersion {
		return VersionUndefined, nil, nil, fmt.Errorf("unsupported "+
			"version: %s", version)
	}

	// Extract the additional data length from the second byte of the
	// ciphertext.
	additionalDataLen := int(msg[1])

	// Before we start, we check that the ciphertext is at least
	// 2+adLength+24+16 bytes long. This is the minimum size for a valid
	// ciphertext, as it contains the version (1 byte), additional data
	// length (1 byte), the additional data (additionalDataLen bytes), the
	// nonce (24 bytes) and the overhead (16 bytes).
	minLength := 2 + additionalDataLen + chacha20poly1305.NonceSizeX +
		chacha20poly1305.Overhead
	if len(msg) < minLength {
		return VersionUndefined, nil, nil, fmt.Errorf("ciphertext "+
			"too short: %d bytes given, %d bytes minimum", len(msg),
			minLength)
	}

	additionalData := msg[2 : 2+additionalDataLen]
	msg = msg[2+additionalDataLen:]

	return version, additionalData, msg, nil
}

// DecryptSha256ChaCha20Poly1305 decrypts the given ciphertext using
// ChaCha20Poly1305 with a shared secret (usually derived using ECDH between the
// sender's ephemeral key and the receiver's public key) that is hardened using
// HKDF with SHA256. The cipher also authenticates the additional data and
// prepends it to the returned encrypted message. The additional data is limited
// to at most 255 bytes. The ciphertext must be in the format:
//
// <1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
// <* bytes ciphertext>
func DecryptSha256ChaCha20Poly1305(sharedSecret [32]byte,
	msg []byte) ([]byte, error) {

	// Make sure the message correctly encodes the additional data.
	version, additionalData, remainder, err := ExtractAdditionalData(msg)
	if err != nil {
		return nil, err
	}

	// Currently, only the latest version is supported.
	if version != latestVersion {
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	// Split additional data, nonce, and ciphertext.
	nonceSize := chacha20poly1305.NonceSizeX
	nonce := remainder[:nonceSize]
	ciphertext := remainder[nonceSize:]

	// Derive a strong session key from the shared secret using HKDF-SHA256.
	// The nonce is used as the salt, and the protocol name as the info
	// label. This mitigates risks from weak shared secrets.
	stretchedKey, err := HkdfSha256(
		sharedSecret[:], nonce, []byte(protocolName),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// We can now create a new XChaCha20Poly1305 AEAD cipher using the
	// stretched key.
	aead, err := chacha20poly1305.NewX(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new chacha20poly1305 "+
			"cipher: %w", err)
	}

	// Sanity check the nonce size used.
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length")
	}

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt message: %w", err)
	}

	return plaintext, nil
}

// HkdfSha256 derives a 32-byte key from the given secret and salt using HKDF
// with SHA256.
func HkdfSha256(secret, salt, info []byte) ([32]byte, error) {
	var key [32]byte
	kdf := hkdf.New(sha256.New, secret, salt, info)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("cannot read secret from HKDF "+
			"reader: %w", err)
	}

	return key, nil
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// target private key and remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx = k*P
//	s = sha256(sx.SerializeCompressed())
func ECDH(privKey *btcec.PrivateKey, pub *btcec.PublicKey) ([32]byte, error) {
	var (
		pubJacobian btcec.JacobianPoint
		s           btcec.JacobianPoint
	)
	pub.AsJacobian(&pubJacobian)

	btcec.ScalarMultNonConst(&privKey.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := btcec.NewPublicKey(&s.X, &s.Y)
	return sha256.Sum256(sPubKey.SerializeCompressed()), nil
}
