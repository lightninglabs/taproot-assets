package ecies

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"math/rand/v2"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestEncryptDecryptSha256Aes256 tests the EncryptSha256Aes256 and
// DecryptSha256Aes256 functions. It generates a shared secret using ECDH
// between a sender and receiver key pair, encrypts a message using the shared
// secret, and then decrypts it to verify that the original message is
// recovered.
func TestEncryptDecryptSha256Aes256(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "short message",
			message: []byte("hello"),
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

			sharedSecret, err := ecdh(senderPriv, receiverPub)

			// Encrypt the message.
			ciphertext, err := EncryptSha256Aes256(
				sharedSecret, tt.message,
			)
			require.NoError(t, err)

			require.NotContains(t, ciphertext, tt.message)
			require.GreaterOrEqual(t, len(ciphertext), 32)

			// Decrypt the message.
			plaintext, err := DecryptSha256Aes256(
				sharedSecret, ciphertext,
			)
			require.NoError(t, err)

			// Verify the decrypted message matches the original.
			require.Equal(t, tt.message, plaintext)
		})
	}
}

// TestEncryptDecryptSha256Aes256Random tests the EncryptSha256Aes256 and
// DecryptSha256Aes256 functions with random messages.
func TestEncryptDecryptSha256Aes256Random(t *testing.T) {
	for i := 0; i < 100; i++ {
		msgLen := rand.Int()%65536 + 1
		msg := make([]byte, msgLen)
		_, err := crand.Read(msg)
		require.NoError(t, err)

		senderPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		receiverPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		receiverPub := receiverPriv.PubKey()

		sharedSecret, err := ecdh(senderPriv, receiverPub)

		// Encrypt the message.
		ciphertext, err := EncryptSha256Aes256(sharedSecret, msg)
		require.NoError(t, err)

		require.NotContains(t, ciphertext, msg)
		require.GreaterOrEqual(t, len(ciphertext), 32)

		// Decrypt the message.
		plaintext, err := DecryptSha256Aes256(sharedSecret, ciphertext)
		require.NoError(t, err)

		// Verify the decrypted message matches the original.
		require.Equal(t, msg, plaintext)
	}
}

// BenchmarkEncryptSha256Aes256 tests the performance of the EncryptSha256Aes256
// function.
func BenchmarkEncryptSha256Aes256(b *testing.B) {
	senderPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	receiverPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)
	receiverPub := receiverPriv.PubKey()

	sharedSecret, err := ecdh(senderPriv, receiverPub)

	longMessage := bytes.Repeat([]byte("secret"), 10240)
	for i := 0; i < b.N; i++ {
		_, err := EncryptSha256Aes256(sharedSecret, longMessage)
		if err != nil {
			b.Fail()
		}
	}
}

// BenchmarkDecryptSha256Aes256 tests the performance of the
// DecryptSha256Aes256 function.
func BenchmarkDecryptSha256Aes256(b *testing.B) {
	senderPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	receiverPriv, err := btcec.NewPrivateKey()
	require.NoError(b, err)
	receiverPub := receiverPriv.PubKey()

	sharedSecret, err := ecdh(senderPriv, receiverPub)

	longMessage := bytes.Repeat([]byte("secret"), 10240)

	ciphertext, err := EncryptSha256Aes256(sharedSecret, longMessage)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err := DecryptSha256Aes256(sharedSecret, ciphertext)
		if err != nil {
			b.Fail()
		}
	}
}

// FuzzEncryptSha256Aes256 is a fuzz test for the EncryptSha256Aes256 function.
func FuzzEncryptSha256Aes256(f *testing.F) {
	f.Fuzz(func(t *testing.T, secretBytes []byte, msg []byte) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], secretBytes)
		_, _ = EncryptSha256Aes256(sharedSecret, msg)
	})
}

// FuzzDecryptSha256Aes256 is a fuzz test for the DecryptSha256Aes256 function.
func FuzzDecryptSha256Aes256(f *testing.F) {
	f.Fuzz(func(t *testing.T, secretBytes []byte, msg []byte) {
		var sharedSecret [32]byte
		copy(sharedSecret[:], secretBytes)
		_, _ = DecryptSha256Aes256(sharedSecret, msg)
	})
}

// ecdh performs a scalar multiplication (ECDH-like operation) between the
// target private key and remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx = k*P
//	s = sha256(sx.SerializeCompressed())
func ecdh(privKey *btcec.PrivateKey, pub *btcec.PublicKey) ([32]byte, error) {
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
