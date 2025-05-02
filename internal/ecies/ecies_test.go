package ecies

import (
	"bytes"
	crand "crypto/rand"
	"math/rand/v2"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestEncryptDecryptSha256ChaCha20Poly1305 tests the
// EncryptSha256ChaCha20Poly1305 and DecryptSha256ChaCha20Poly1305 functions. It
// generates a shared secret using ECDH between a sender and receiver key pair,
// encrypts a message using the shared secret, and then decrypts it to verify
// that the original message is recovered.
func TestEncryptDecryptSha256ChaCha20Poly1305(t *testing.T) {
	tests := []struct {
		name           string
		message        []byte
		additionalData []byte
	}{
		{
			name:    "short message",
			message: []byte("hello"),
		},
		{
			name:           "short message with AD",
			message:        []byte("hello"),
			additionalData: []byte("additional data"),
		},
		{
			name:    "empty message",
			message: nil,
		},
		{
			name:    "long message",
			message: bytes.Repeat([]byte("a"), 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			senderPriv, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			receiverPriv, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			receiverPub := receiverPriv.PubKey()

			sharedSecret, err := ECDH(senderPriv, receiverPub)
			require.NoError(t, err)

			// Encrypt the message.
			ciphertext, err := EncryptSha256ChaCha20Poly1305(
				sharedSecret, tt.message, tt.additionalData,
			)
			require.NoError(t, err)

			require.NotContains(t, ciphertext, tt.message)
			require.GreaterOrEqual(
				t, len(ciphertext), chacha20poly1305.NonceSize,
			)

			// Decrypt the message.
			plaintext, err := DecryptSha256ChaCha20Poly1305(
				sharedSecret, ciphertext, tt.additionalData,
			)
			require.NoError(t, err)

			// Verify the decrypted message matches the original.
			require.Equal(t, tt.message, plaintext)
		})
	}
}

// TestEncryptDecryptSha256ChaCha20Poly1305Random tests the
// EncryptSha256ChaCha20Poly1305 and DecryptSha256ChaCha20Poly1305 functions
// with random messages.
func TestEncryptDecryptSha256ChaCha20Poly1305Random(t *testing.T) {
	for i := 0; i < 100; i++ {
		msgLen := rand.Int()%65536 + 1
		msg := make([]byte, msgLen)
		_, err := crand.Read(msg)
		require.NoError(t, err)

		ad := make([]byte, 32)
		_, err = crand.Read(ad)
		require.NoError(t, err)

		senderPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		receiverPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		receiverPub := receiverPriv.PubKey()

		sharedSecret, err := ECDH(senderPriv, receiverPub)
		require.NoError(t, err)

		// Encrypt the message.
		ciphertext, err := EncryptSha256ChaCha20Poly1305(
			sharedSecret, msg, ad,
		)
		require.NoError(t, err)

		require.NotContains(t, ciphertext, msg)
		require.GreaterOrEqual(t, len(ciphertext), 32)

		// Decrypt the message.
		plaintext, err := DecryptSha256ChaCha20Poly1305(
			sharedSecret, ciphertext, ad,
		)
		require.NoError(t, err)

		// Verify the decrypted message matches the original.
		require.Equal(t, msg, plaintext)
	}
}

// EncryptSha256ChaCha20Poly1305 tests the performance of the
// EncryptSha256ChaCha20Poly1305 function.
func BenchmarkEncryptSha256ChaCha20Poly1305(b *testing.B) {
	senderPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	receiverPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)
	receiverPub := receiverPriv.PubKey()

	sharedSecret, err := ECDH(senderPriv, receiverPub)
	require.NoError(b, err)

	longMessage := bytes.Repeat([]byte("secret"), 10240)
	ad := bytes.Repeat([]byte("ad"), 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptSha256ChaCha20Poly1305(
			sharedSecret, longMessage, ad,
		)
		if err != nil {
			b.Fail()
		}
	}
}

// BenchmarkDecryptSha256Aes256 tests the performance of the
// DecryptSha256ChaCha20Poly1305 function.
func BenchmarkDecryptSha256ChaCha20Poly1305(b *testing.B) {
	senderPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	receiverPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)
	receiverPub := receiverPriv.PubKey()

	sharedSecret, err := ECDH(senderPriv, receiverPub)
	require.NoError(b, err)

	longMessage := bytes.Repeat([]byte("secret"), 10240)
	ad := bytes.Repeat([]byte("ad"), 1024)

	ciphertext, err := EncryptSha256ChaCha20Poly1305(
		sharedSecret, longMessage, ad,
	)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptSha256ChaCha20Poly1305(
			sharedSecret, ciphertext, ad,
		)
		if err != nil {
			b.Fail()
		}
	}
}

// FuzzEncryptSha256ChaCha20Poly1305 is a fuzz test for the
// EncryptSha256ChaCha20Poly1305 function.
func FuzzEncryptSha256ChaCha20Poly1305(f *testing.F) {
	f.Fuzz(func(t *testing.T, secretBytes, msg, ad []byte) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], secretBytes)
		_, _ = EncryptSha256ChaCha20Poly1305(sharedSecret, msg, ad)
	})
}

// FuzzDecryptSha256ChaCha20Poly1305 is a fuzz test for the
// DecryptSha256ChaCha20Poly1305 function.
func FuzzDecryptSha256ChaCha20Poly1305(f *testing.F) {
	f.Fuzz(func(t *testing.T, secretBytes, msg, ad []byte) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], secretBytes)
		_, _ = DecryptSha256ChaCha20Poly1305(sharedSecret, msg, ad)
	})
}
