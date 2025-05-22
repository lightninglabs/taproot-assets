// This package implements an ECIES (Elliptic Curve Integrated Encryption
// Scheme) encryption. It uses AES256-GCM for encryption and HKDF with SHA256
// for key derivation. The package provides functions to encrypt and decrypt
// messages using a shared secret derived between two parties using ECDH
// (Elliptic Curve Diffie-Hellman).
// Inspiration for parts of the code in this package was taken from
// https://github.com/ecies/go.

package ecies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// GCMNonceSize is the size of the nonce used in AES-GCM mode.
	GCMNonceSize = 16
)

// EncryptSha256Aes256 encrypts the given message using AES256-GCM with a shared
// secret (usually derived using ECDH between the sender's ephemeral key and the
// receiver's public key) that is stretched using HKDF with SHA256. The output
// is a byte slice containing:
//
//	<16 bytes nonce> <16 bytes tag> <... bytes ciphertext>
func EncryptSha256Aes256(sharedSecret [32]byte, msg []byte) ([]byte, error) {
	// We begin by stretching the shared secret using HKDF with SHA256.
	stretchedKey, err := HkdfSha256(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// Then we create a new AES block cipher using the stretched key. With
	// the stretched key length of 32 bytes, this will be AES256.
	block, err := aes.NewCipher(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	nonce := make([]byte, GCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: "+
			"%w", err)
	}

	// The buffer will contain the nonce, tag and ciphertext. We preallocate
	// the buffer to the final size to avoid multiple allocations.
	var result bytes.Buffer
	result.Write(nonce)

	gcm, err := cipher.NewGCMWithNonceSize(block, GCMNonceSize)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, msg, nil)

	// The tag is the last 16 bytes of the ciphertext. We want to move it
	// to before the ciphertext, so we extract it and write it into the
	// result buffer first.
	tag := ciphertext[len(ciphertext)-gcm.NonceSize():]
	result.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	result.Write(ciphertext)

	return result.Bytes(), nil
}

// DecryptSha256Aes256 decrypts the given ciphertext using AES256-GCM with a
// shared secret (usually derived using ECDH between the sender's ephemeral key
// and the receiver's public key) that is stretched using HKDF with SHA256. The
// ciphertext must be in the format:
//
//	<16 bytes nonce> <16 bytes tag> <... bytes ciphertext>
func DecryptSha256Aes256(sharedSecret [32]byte, msg []byte) ([]byte, error) {
	// Before we start, we check that the ciphertext is at least 32 bytes
	// long. This is the minimum size for a valid ciphertext, as it
	// contains a nonce (16 bytes) and a tag (16 bytes).
	if len(msg) < 32 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes "+
			"given, 32 bytes minimum", len(msg))
	}

	var (
		nonce       = make([]byte, GCMNonceSize)
		tag         = make([]byte, GCMNonceSize)
		payloadSize = len(msg) - GCMNonceSize*2
	)
	copy(nonce, msg[:GCMNonceSize])
	copy(tag, msg[GCMNonceSize:GCMNonceSize*2])

	// The ciphertext is the rest of the input message, after the nonce and
	// tag. But we need to assemble `<payload> <tag>` again, as the GCM mode
	// needs the data in that form to decrypt the ciphertext.
	ciphertext := make([]byte, payloadSize+GCMNonceSize)
	copy(ciphertext, msg[GCMNonceSize*2:])
	copy(ciphertext[payloadSize:], tag)

	// We begin by stretching the shared secret using HKDF with SHA256.
	stretchedKey, err := HkdfSha256(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("cannot derive hkdf key: %w", err)
	}

	// Then we create a new AES block cipher using the stretched key. With
	// the stretched key length of 32 bytes, this will be AES256.
	block, err := aes.NewCipher(stretchedKey[:])
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, GCMNonceSize)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
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
