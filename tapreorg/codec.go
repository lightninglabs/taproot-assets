package tapreorg

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/wire/v2"
)

// Encode returns the canonical binary encoding of the witness, as
// used inside phase evidence and in staged foreclosure records.
func (w Witness) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeWitness(&buf, w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeWitnessBlob decodes a witness from its canonical binary
// encoding; trailing bytes are an error.
func DecodeWitnessBlob(blob []byte) (Witness, error) {
	r := bytes.NewReader(blob)
	w, err := decodeWitness(r)
	if err != nil {
		return Witness{}, err
	}
	if r.Len() != 0 {
		return Witness{}, fmt.Errorf("%d trailing witness bytes",
			r.Len())
	}

	return w, nil
}

// outPointSize is the encoded size of one outpoint: a 32-byte txid
// followed by a big-endian uint32 index.
const outPointSize = 32 + 4

// EncodeOutPoints encodes outpoints as a concatenation of
// (txid || big-endian index) tuples.
func EncodeOutPoints(ops []wire.OutPoint) []byte {
	var buf bytes.Buffer
	for _, op := range ops {
		buf.Write(op.Hash[:])
		writeU32(&buf, op.Index)
	}

	return buf.Bytes()
}

// DecodeOutPoints decodes a concatenation of (txid || big-endian
// index) tuples.
func DecodeOutPoints(blob []byte) ([]wire.OutPoint, error) {
	if len(blob)%outPointSize != 0 {
		return nil, fmt.Errorf("outpoint blob length %d is not a "+
			"multiple of %d", len(blob), outPointSize)
	}

	ops := make([]wire.OutPoint, 0, len(blob)/outPointSize)
	r := bytes.NewReader(blob)
	for r.Len() > 0 {
		var op wire.OutPoint
		if _, err := r.Read(op.Hash[:]); err != nil {
			return nil, err
		}

		index, err := readU32(r)
		if err != nil {
			return nil, err
		}
		op.Index = index

		ops = append(ops, op)
	}

	return ops, nil
}
