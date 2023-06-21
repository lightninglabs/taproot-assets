package test

import (
	"sync"
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

var (
	// randLock is a mutex that must be held when accessing the global rand
	// instance.
	randLock sync.Mutex
)

// RandBool rolls a random boolean.
func RandBool() bool {
	randLock.Lock()
	defer randLock.Unlock()

	return rand.Int()%2 == 0
}

// RandInt31n returns a random 32-bit integer in the range [0, n).
func RandInt31n(n int32) int32 {
	randLock.Lock()
	defer randLock.Unlock()

	return rand.Int31n(n)
}

// RandIntn returns a random integer in the range [0, n).
func RandIntn(n int) int {
	randLock.Lock()
	defer randLock.Unlock()

	return rand.Intn(n)
}

// RandInt makes a random integer of the specified type.
func RandInt[T constraints.Integer]() T {
	randLock.Lock()
	defer randLock.Unlock()

	return T(rand.Int63()) // nolint:gosec
}

// RandRead fills the passed byte slice with random data.
func RandRead(t testing.TB, b []byte) {
	randLock.Lock()
	defer randLock.Unlock()

	_, err := rand.Read(b)
	require.NoError(t, err)
}

func RandOp(t testing.TB) wire.OutPoint {
	t.Helper()

	op := wire.OutPoint{
		Index: uint32(RandInt[int32]()),
	}
	RandRead(t, op.Hash[:])

	return op
}

func RandPrivKey(_ testing.TB) *btcec.PrivateKey {
	priv, _ := btcec.PrivKeyFromBytes(RandBytes(32))
	return priv
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
	randLock.Lock()
	defer randLock.Unlock()

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
		RandRead(t, elem)

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
