package tapdb

import (
	"database/sql"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/constraints"
)

var (
	// MaxValidSQLTime is the maximum valid time that can be rendered as a
	// time string and can be used for comparisons in SQL.
	MaxValidSQLTime = time.Date(9999, 12, 31, 23, 59, 59, 999999, time.UTC)
)

// sqlInt32 turns a numerical integer type into the NullInt32 that sql/sqlc
// uses when an integer field can be permitted to be NULL.
//
// We use the constraints.Integer constraint here which maps to all signed and
// unsigned integer types.
func sqlInt32[T constraints.Integer](num T) sql.NullInt32 {
	return sql.NullInt32{
		Int32: int32(num),
		Valid: true,
	}
}

// sqlInt16 turns a numerical integer type into the NullInt16 that sql/sqlc
// uses when an integer field can be permitted to be NULL.
//
// We use the constraints.Integer constraint here which maps to all signed and
// unsigned integer types.
func sqlInt16[T constraints.Integer](num T) sql.NullInt16 {
	return sql.NullInt16{
		Int16: int16(num),
		Valid: true,
	}
}

// sqlBool turns a boolean into the NullBool that sql/sqlc uses when a boolean
// field can be permitted to be NULL.
func sqlBool(b bool) sql.NullBool {
	return sql.NullBool{
		Bool:  b,
		Valid: true,
	}
}

// sqlStr turns a string into the NullString that sql/sqlc uses when a string
// can be permitted to be NULL.
func sqlStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}

	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

// extractSqlInt32 turns a NullInt32 into a numerical type. This can be useful
// when reading directly from the database, as this function handles extracting
// the inner value from the "option"-like struct.
func extractSqlInt32[T constraints.Integer](num sql.NullInt32) T {
	return T(num.Int32)
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
//
// NOTE: This function is intended to be used along with the wire.WriteOutPoint
// function. Once the ReadOutPoint function is exported, then it can be used in
// place of this.
func readOutPoint(r io.Reader, pver uint32, version int32, op *wire.OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	return binary.Read(r, binary.LittleEndian, &op.Index)
}

// fMapKeys extracts the set of keys from a map, applies the function f to each
// element and returns the results in a new slice.
func fMapKeys[K comparable, V, R any](m map[K]V, f func(K) R) []R {
	keys := make([]R, 0, len(m))
	for k := range m {
		r := f(k)
		keys = append(keys, r)
	}
	return keys
}

// mergeMap adds all the values that are in map b to map a.
func mergeMap[K comparable, V any](a, b map[K]V) map[K]V {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// noError1 calls a function with 1 argument and verifies that no error is
// returned. If the error is nil, then the value is returned.
func noError1[T any, Q any](t *testing.T, f func(Q) (T, error), args Q) T {
	v, err := f(args)
	require.NoError(t, err)
	return v
}

// fMap takes an input slice, and applies the function f to each element,
// yielding a new slice.
func fMap[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	r := make([]T2, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}
