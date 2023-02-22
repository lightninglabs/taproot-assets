package test

import (
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/constraints"
)

// RandBool rolls a random boolean.
func RandBool() bool {
	return rand.Int()%2 == 0
}

// RandInt makes a random integer of the specified type.
func RandInt[T constraints.Integer]() T {
	return T(rand.Int63()) // nolint:gosec
}

func RandOp(t testing.TB) wire.OutPoint {
	t.Helper()

	op := wire.OutPoint{
		Index: uint32(RandInt[int32]()),
	}
	_, err := rand.Read(op.Hash[:])
	require.NoError(t, err)

	return op
}

func RandPrivKey(t testing.TB) *btcec.PrivateKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return privKey
}

func SchnorrPubKey(t testing.TB, privKey *btcec.PrivateKey) *btcec.PublicKey {
	return SchnorrKey(t, privKey.PubKey())
}

func SchnorrKey(t testing.TB, pubKey *btcec.PublicKey) *btcec.PublicKey {
	key, err := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))
	require.NoError(t, err)
	return key
}

func RandPubKey(t testing.TB) *btcec.PublicKey {
	return SchnorrPubKey(t, RandPrivKey(t))
}

func RandBytes(num int) []byte {
	randBytes := make([]byte, num)
	_, _ = rand.Read(randBytes)
	return randBytes
}

func PubToKeyDesc(p *btcec.PublicKey) keychain.KeyDescriptor {
	return keychain.KeyDescriptor{
		PubKey: p,
	}
}

func ParseRPCKeyDescriptor(t testing.TB,
	rpcDesc *signrpc.KeyDescriptor) keychain.KeyDescriptor {

	pubKey, err := btcec.ParsePubKey(rpcDesc.RawKeyBytes)
	require.NoError(t, err)

	require.NotNil(t, rpcDesc.KeyLoc)

	return keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(rpcDesc.KeyLoc.KeyFamily),
			Index:  uint32(rpcDesc.KeyLoc.KeyIndex),
		},
		PubKey: pubKey,
	}
}

func ComputeTaprootScript(t testing.TB, taprootKey *btcec.PublicKey) []byte {
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
	require.NoError(t, err)
	return script
}

func RandHash() chainhash.Hash {
	var hash chainhash.Hash
	copy(hash[:], RandBytes(chainhash.HashSize))
	return hash
}

func RandTxWitnesses(t testing.TB) wire.TxWitness {
	numElements := RandInt[int]() % 5
	if numElements == 0 {
		return nil
	}

	w := make(wire.TxWitness, numElements)
	for i := 0; i < numElements; i++ {
		elem := make([]byte, 10)
		_, err := rand.Read(elem)
		require.NoError(t, err)

		w[i] = elem
	}

	return w
}

// ScriptHashLock returns a simple bitcoin script that locks the funds to a hash
// lock of the given preimage.
func ScriptHashLock(t *testing.T, preimage []byte) txscript.TapLeaf {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(preimage))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	script1, err := builder.Script()
	require.NoError(t, err)
	return txscript.NewBaseTapLeaf(script1)
}

// ScriptSchnorrSig returns a simple bitcoin script that locks the funds to a
// Schnorr signature of the given public key.
func ScriptSchnorrSig(t *testing.T, pubKey *btcec.PublicKey) txscript.TapLeaf {
	builder := txscript.NewScriptBuilder()
	builder.AddData(schnorr.SerializePubKey(pubKey))
	builder.AddOp(txscript.OP_CHECKSIG)
	script2, err := builder.Script()
	require.NoError(t, err)
	return txscript.NewBaseTapLeaf(script2)
}
