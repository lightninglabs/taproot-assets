package proof

import (
	"errors"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// packedBitsLen returns the length in bytes that a packed bit vector would
// consume.
func packedBitsLen(bits uint64) uint64 {
	return (bits + 8 - 1) / 8 // Round up to nearest byte.
}

// packBits packs a bit vector into a byte slice.
func packBits(bits []bool) []byte {
	bytes := make([]byte, packedBitsLen(uint64(len(bits))))
	for i, isBitSet := range bits {
		if !isBitSet {
			continue
		}

		byteIdx := i / 8
		bitIdx := i % 8
		bytes[byteIdx] |= byte(1 << bitIdx)
	}

	return bytes
}

// unpackBits unpacks a byte slice into a bit vector.
func unpackBits(bytes []byte) []bool {
	bits := make([]bool, len(bytes)*8)
	for i := 0; i < len(bits); i++ {
		byteIdx := i / 8
		byteVal := bytes[byteIdx]
		bitIdx := i % 8
		bits[i] = (byteVal>>bitIdx)&1 == 1
	}

	return bits
}

// txSpendsPrevOut returns whether the given prevout is spent by the given
// transaction.
func txSpendsPrevOut(tx *wire.MsgTx, prevOut *wire.OutPoint) bool {
	for _, txIn := range tx.TxIn {
		if txIn.PreviousOutPoint == *prevOut {
			return true
		}
	}

	return false
}

// ExtractTaprootKey attempts to extract a Taproot tweaked key from the output
// found at `outputIndex`.
func ExtractTaprootKey(tx *wire.MsgTx,
	outputIndex uint32) (*btcec.PublicKey, error) {

	if outputIndex >= uint32(len(tx.TxOut)) {
		return nil, errors.New("invalid output index")
	}

	return ExtractTaprootKeyFromScript(tx.TxOut[outputIndex].PkScript)
}

// ExtractTaprootKeyFromScript attempts to extract a Taproot tweaked key from
// the given output script.
func ExtractTaprootKeyFromScript(pkScript []byte) (*btcec.PublicKey, error) {
	version, keyBytes, err := txscript.ExtractWitnessProgramInfo(pkScript)
	if err != nil {
		return nil, err
	}

	if version != txscript.TaprootWitnessVersion {
		return nil, errors.New("invalid witness version")
	}

	return schnorr.ParsePubKey(keyBytes)
}

// nextPowerOfTwo returns the next highest power of two from a given number if
// it is not already a power of two.  This is a helper function used during the
// calculation of a merkle tree.
func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}
