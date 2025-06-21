package fn

import (
	"bytes"
	"io"
)

// Encoder is an interface that defines a method to encode data into an
// io.Writer.
type Encoder interface {
	// Encode writes the encoded data to the provided io.Writer.
	Encode(w io.Writer) error
}

// Encode encodes the given Encoder into a byte slice.
func Encode(e Encoder) ([]byte, error) {
	if e == nil {
		return nil, nil
	}

	var buf bytes.Buffer
	err := e.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Serializer is an interface that defines a method to serialize data
// into an io.Writer.
type Serializer interface {
	Serialize(w io.Writer) error
}

// Serialize encodes the given Serializer into a byte slice.
func Serialize(s Serializer) ([]byte, error) {
	if s == nil {
		return nil, nil
	}

	var buf bytes.Buffer
	err := s.Serialize(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
