package test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/constraints"
)

var (
	// randLock is a mutex that must be held when accessing the global rand
	// instance.
	randLock sync.Mutex

	HexCompressedPubKeyLen = hex.EncodedLen(btcec.PubKeyBytesLenCompressed)
	HexTaprootPkScript     = hex.EncodedLen(input.P2TRSize)
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

func SchnorrKeysEqual(t testing.TB, a, b *btcec.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}

	return SchnorrKey(t, a).IsEqual(SchnorrKey(t, b))
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

func ParsePubKey(t testing.TB, key string) *btcec.PublicKey {
	t.Helper()

	if len(key) == 0 {
		return nil
	}

	pkBytes, err := hex.DecodeString(key)
	require.NoError(t, err)

	pk, err := btcec.ParsePubKey(pkBytes)
	require.NoError(t, err)

	return pk
}

func ParseSchnorrPubKey(t testing.TB, key string) *btcec.PublicKey {
	t.Helper()

	if len(key) == 0 {
		return nil
	}

	pkBytes, err := hex.DecodeString(key)
	require.NoError(t, err)

	pk, err := schnorr.ParsePubKey(pkBytes)
	require.NoError(t, err)

	return pk
}

func ParseOutPoint(t testing.TB, op string) wire.OutPoint {
	t.Helper()

	if op == "" {
		return wire.OutPoint{}
	}

	parts := strings.Split(op, ":")
	require.Len(t, parts, 2)

	hash := ParseChainHash(t, parts[0])

	outputIndex, err := strconv.Atoi(parts[1])
	require.NoError(t, err)

	return wire.OutPoint{
		Hash:  hash,
		Index: uint32(outputIndex),
	}
}

func ParseChainHash(t testing.TB, hash string) chainhash.Hash {
	t.Helper()

	if hash == "" {
		return chainhash.Hash{}
	}

	require.Equal(t, chainhash.HashSize, hex.DecodedLen(len(hash)))

	h, err := chainhash.NewHashFromStr(hash)
	require.NoError(t, err)
	return *h
}

func Parse32Byte(t testing.TB, b string) [32]byte {
	t.Helper()

	if b == "" {
		return [32]byte{}
	}

	require.Equal(t, hex.EncodedLen(32), len(b))

	var result [32]byte
	_, err := hex.Decode(result[:], []byte(b))
	require.NoError(t, err)

	return result
}

func Parse33Byte(t testing.TB, b string) [33]byte {
	t.Helper()

	if b == "" {
		return [33]byte{}
	}

	require.Equal(t, hex.EncodedLen(33), len(b))

	var result [33]byte
	_, err := hex.Decode(result[:], []byte(b))
	require.NoError(t, err)

	return result
}

func ParseHex(t testing.TB, b string) []byte {
	t.Helper()

	if len(b) == 0 {
		return nil
	}

	result, err := hex.DecodeString(b)
	require.NoError(t, err)

	return result
}

func ParseSchnorrSig(t testing.TB, sigHex string) *schnorr.Signature {
	t.Helper()

	require.Len(t, sigHex, hex.EncodedLen(schnorr.SignatureSize))

	sigBytes, err := hex.DecodeString(sigHex)
	require.NoError(t, err)

	sig, err := schnorr.ParseSignature(sigBytes)
	require.NoError(t, err)

	return sig
}

func ParseTx(t testing.TB, tx string) *wire.MsgTx {
	t.Helper()

	txBytes, err := hex.DecodeString(tx)
	require.NoError(t, err)

	var msgTx wire.MsgTx
	require.NoError(t, msgTx.Deserialize(bytes.NewReader(txBytes)))

	return &msgTx
}

func HexPubKey(pk *btcec.PublicKey) string {
	if pk == nil {
		return ""
	}

	return hex.EncodeToString(pk.SerializeCompressed())
}

func HexSchnorrPubKey(pk *btcec.PublicKey) string {
	if pk == nil {
		return ""
	}

	return hex.EncodeToString(schnorr.SerializePubKey(pk))
}

func HexSignature(sig *schnorr.Signature) string {
	if sig == nil {
		return ""
	}

	return hex.EncodeToString(sig.Serialize())
}

func HexTx(t testing.TB, tx *wire.MsgTx) string {
	t.Helper()

	if tx == nil {
		return ""
	}

	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))

	return hex.EncodeToString(buf.Bytes())
}

func ComputeTaprootScriptErr(witnessProgram []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(witnessProgram[:]).
		Script()
}

func ComputeTaprootScript(t testing.TB, taprootKey *btcec.PublicKey) []byte {
	script, err := ComputeTaprootScriptErr(
		schnorr.SerializePubKey(taprootKey),
	)
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

func RandTapLeaf(customScriptLen *int) txscript.TapLeaf {
	scriptLen := 500

	// Ensure that we never have an empty script.
	randScriptLen := RandIntn(scriptLen)
	if randScriptLen == 0 {
		randScriptLen = 1
	}

	if customScriptLen != nil {
		randScriptLen = *customScriptLen
	}

	return txscript.NewBaseTapLeaf(RandBytes(randScriptLen))
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

// ReadTestDataFile reads a file from the testdata directory and returns its
// content as a string.
func ReadTestDataFile(t *testing.T, fileName string) string {
	path := filepath.Join("testdata", fileName)
	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(fileBytes)
}

// BuildTapscriptTree builds a Tapscript tree with two leaves, a hash lock
// script and a signature verification script.
func BuildTapscriptTreeNoReveal(t *testing.T,
	internalKey *btcec.PublicKey) txscript.TapBranch {

	hashLockWitness := []byte("foobar")
	hashLockLeaf := ScriptHashLock(t, hashLockWitness)
	sigLeaf := ScriptSchnorrSig(t, internalKey)

	tree := txscript.AssembleTaprootScriptTree(hashLockLeaf, sigLeaf)
	return txscript.NewTapBranch(
		tree.RootNode.Left(), tree.RootNode.Right(),
	)
}

// BuildTapscriptTree builds a Tapscript tree with two leaves, a hash lock
// script and a signature verification script. It also returns the data needed
// to satisfy one of the two leaves.
func BuildTapscriptTree(t *testing.T, useHashLock, valid bool,
	internalKey *btcec.PublicKey) (*txscript.TapLeaf, *waddrmgr.Tapscript,
	*psbt.TaprootTapLeafScript, []byte, []byte) {

	// Let's create a taproot asset script now. This is a hash lock with a
	// simple preimage of "foobar".
	hashLockWitness := []byte("foobar")
	invalidHashLockWitness := []byte("not-foobar")
	hashLockLeaf := ScriptHashLock(t, hashLockWitness)

	// Let's add a second script output as well to test the partial reveal.
	sigLeaf := ScriptSchnorrSig(t, internalKey)
	invalidSigWitness := make([]byte, 64)

	var (
		usedLeaf      *txscript.TapLeaf
		testTapScript *waddrmgr.Tapscript
		scriptWitness []byte
	)

	if useHashLock {
		usedLeaf = &hashLockLeaf
		inclusionProof := sigLeaf.TapHash()
		testTapScript = input.TapscriptPartialReveal(
			internalKey, hashLockLeaf, inclusionProof[:],
		)
		scriptWitness = hashLockWitness

		if !valid {
			scriptWitness = invalidHashLockWitness
		}
	} else {
		usedLeaf = &sigLeaf
		inclusionProof := hashLockLeaf.TapHash()
		testTapScript = input.TapscriptPartialReveal(
			internalKey, sigLeaf, inclusionProof[:],
		)

		// If we leave the scriptWitness nil, the genTaprootScriptSpend
		// function will automatically create a signature for us.
		// We only need to create a witness if we want an invalid
		// signature.
		if !valid {
			scriptWitness = invalidSigWitness
		}
	}

	// Compute the final tapscript root and leaf script needed to create a
	// key that includes the above tapscript tree.
	tapTweak := testTapScript.ControlBlock.RootHash(
		testTapScript.RevealedScript,
	)
	controlBlockBytes, err := testTapScript.ControlBlock.ToBytes()
	require.NoError(t, err)

	tapLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: controlBlockBytes,
		Script:       usedLeaf.Script,
		LeafVersion:  usedLeaf.LeafVersion,
	}

	return usedLeaf, testTapScript, tapLeaf, tapTweak, scriptWitness
}
