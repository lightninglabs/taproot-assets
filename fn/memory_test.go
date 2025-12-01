package fn

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// TestLowerBoundByteSizeNilAndPrimitives ensures the byte estimator handles nil
// interfaces and primitive concrete values using their inline sizes.
func TestLowerBoundByteSizeNilAndPrimitives(t *testing.T) {
	actualNil := LowerBoundByteSize(nil)
	require.Zero(
		t, actualNil, "nil interface bytes: expected 0, actual %d",
		actualNil,
	)

	var num int64 = 99
	expectedInt := uint64(unsafe.Sizeof(num))
	actualInt := LowerBoundByteSize(num)
	require.Equal(
		t, expectedInt, actualInt,
		"int64 bytes mismatch: expected %d, actual %d",
		expectedInt, actualInt,
	)

	const str = "taproot-assets"
	expectedString := stringHeaderSize + uint64(len(str))
	actualString := LowerBoundByteSize(str)
	require.Equal(
		t, expectedString, actualString,
		"string bytes mismatch: expected %d, actual %d",
		expectedString, actualString,
	)
}

// TestLowerBoundByteSizeStructsAndSlices covers structs that embed slices
// and validates shared backing arrays are only counted once via the seen set.
func TestLowerBoundByteSizeStructsAndSlices(t *testing.T) {
	type structWithSlice struct {
		Count uint16
		Data  []byte
	}

	t.Run("structWithSlice", func(t *testing.T) {
		payload := []byte{1, 2, 3, 4}
		value := structWithSlice{
			Count: 42,
			Data:  payload,
		}

		expected := uint64(unsafe.Sizeof(structWithSlice{}))
		expected += sliceHeaderSize
		expected += uint64(len(payload))
		actual := LowerBoundByteSize(value)

		require.Equal(
			t, expected, actual,
			"struct with slice size mismatch: expected %d, "+
				"actual %d",
			expected, actual,
		)
	})

	t.Run("sharedBackingArrayCountedOnce", func(t *testing.T) {
		payload := []byte{5, 6, 7}

		type twoSlices struct {
			Left  []byte
			Right []byte
		}

		value := twoSlices{
			Left:  payload,
			Right: payload,
		}

		expected := uint64(unsafe.Sizeof(twoSlices{}))
		expected += 2 * sliceHeaderSize
		expected += uint64(len(payload))
		actual := LowerBoundByteSize(value)

		require.Equal(
			t, expected, actual,
			"shared backing array size mismatch: expected %d, "+
				"actual %d",
			expected, actual,
		)
	})
}

// TestLowerBoundByteSizePointerCycle confirms pointer cycles do not blow up the
// traversal and only count the struct once.
func TestLowerBoundByteSizePointerCycle(t *testing.T) {
	type node struct {
		Value uint32
		Next  *node
	}

	root := &node{Value: 1}
	root.Next = root

	expected := uint64(unsafe.Sizeof(node{}))
	actual := LowerBoundByteSize(root)
	require.Equal(
		t, expected, actual,
		"pointer cycle size mismatch: expected %d, actual %d",
		expected, actual,
	)
}

// TestLowerBoundByteSizeMap verifies map headers and key/value payloads are
// included in the lower bound calculation.
func TestLowerBoundByteSizeMap(t *testing.T) {
	payload := []byte{9, 8, 7}
	value := map[string][]byte{
		"alpha": payload,
	}

	expected := uint64(unsafe.Sizeof(any(value)))
	expected += stringHeaderSize + uint64(len("alpha"))
	expected += sliceHeaderSize + uint64(len(payload))
	actual := LowerBoundByteSize(value)

	require.Equal(
		t, expected, actual,
		"map size mismatch: expected %d, actual %d",
		expected, actual,
	)
}
