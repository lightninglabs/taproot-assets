package test

import (
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// RandBool rolls a random boolean.
func RandBool() bool {
	return rand.Int()%2 == 0
}

func RandPrivKey(t *testing.T) *btcec.PrivateKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return privKey
}

func SchnorrPubKey(t *testing.T, privKey *btcec.PrivateKey) *btcec.PublicKey {
	return SchnorrKey(t, privKey.PubKey())
}

func SchnorrKey(t *testing.T, pubKey *btcec.PublicKey) *btcec.PublicKey {
	key, err := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))
	require.NoError(t, err)
	return key
}

func RandPubKey(t *testing.T) *btcec.PublicKey {
	return SchnorrPubKey(t, RandPrivKey(t))
}

func RandBytes(num int) []byte {
	randBytes := make([]byte, num)
	_, _ = rand.Read(randBytes)
	return randBytes
}
