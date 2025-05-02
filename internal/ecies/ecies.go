// This package implements an ECIES (Elliptic Curve Integrated Encryption
// Scheme) encryption. It uses ChaCha20Poly1305 for encryption and HKDF with
// SHA256 for key derivation. The package provides functions to encrypt and
// decrypt messages using a shared secret derived between two parties using ECDH
// (Elliptic Curve Diffie-Hellman).

package ecies

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// EncryptSha256ChaCha20Poly1305 encrypts the given message using
// ChaCha20Poly1305 with a shared secret (usually derived using ECDH between the
// sender's ephemeral key and the receiver's public key) that is stretched using
// HKDF with SHA256. The cipher also authenticates the additional data.
// The output is a byte slice containing:
//
//	<12 bytes nonce> <... bytes ciphertext>
func EncryptSha256ChaCha20Poly1305(sharedSecret [32]byte, msg []byte,
	additionalData []byte) ([]byte, error) {

	// We begin by stretching the shared secret using HKDF with SHA256.
	stretchedKey, err := HkdfSha256(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// We can now create a new ChaCha20Poly1305 AEAD cipher using the
	// stretched key.
	aead, err := chacha20poly1305.New(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new chacha20poly1305 "+
			"cipher: %w", err)
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make(
		[]byte, aead.NonceSize(),
		aead.NonceSize()+len(msg)+aead.Overhead(),
	)

	if _, err := crand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, msg, additionalData)

	return ciphertext, nil
}

// DecryptSha256ChaCha20Poly1305 decrypts the given ciphertext using
// ChaCha20Poly1305 with a shared secret (usually derived using ECDH between the
// sender's ephemeral key and the receiver's public key) that is stretched using
// HKDF with SHA256. The cipher also verifies the authenticity of the additional
// data. The ciphertext must be in the format:
//
//	<12 bytes nonce> <... bytes ciphertext>
func DecryptSha256ChaCha20Poly1305(sharedSecret [32]byte, msg []byte,
	additionalData []byte) ([]byte, error) {

	// Before we start, we check that the ciphertext is at least 12 bytes
	// long. This is the minimum size for a valid ciphertext, as it contains
	// the nonce (12 bytes).
	if len(msg) < chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes "+
			"given, %d bytes minimum", len(msg),
			chacha20poly1305.NonceSize)
	}

	// We begin by stretching the shared secret using HKDF with SHA256.
	stretchedKey, err := HkdfSha256(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// We can now create a new ChaCha20Poly1305 AEAD cipher using the
	// stretched key.
	aead, err := chacha20poly1305.New(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new chacha20poly1305 "+
			"cipher: %w", err)
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := msg[:aead.NonceSize()], msg[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt message: %w", err)
	}

	return plaintext, nil
}

// HkdfSha256 derives a 32-byte key from the given secret using HKDF with
// SHA256.
func HkdfSha256(secret []byte) ([32]byte, error) {
	var key [32]byte
	kdf := hkdf.New(sha256.New, secret, nil, nil)
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
