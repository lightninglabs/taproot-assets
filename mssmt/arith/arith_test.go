package arith

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdd(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		a        uint64
		b        uint64
		expected uint64
		err      error
	}{
		{
			name:     "zero",
			expected: 0,
		},
		{
			name:     "simple sum",
			a:        2,
			b:        3,
			expected: 5,
		},
		{
			name:     "max without overflow",
			a:        math.MaxUint64 - 1,
			b:        1,
			expected: math.MaxUint64,
		},
		{
			name: "overflow by one",
			a:    math.MaxUint64,
			b:    1,
			err:  ErrOverflow,
		},
		{
			name: "overflow both operands",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			err:  ErrOverflow,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result := Add(testCase.a, testCase.b)
			if testCase.err != nil {
				require.ErrorIs(t, result.Err(), testCase.err)

				return
			}

			sum, err := result.Unpack()
			require.NoError(t, err)
			require.Equal(t, testCase.expected, sum)
		})
	}
}

func TestAddUint32(t *testing.T) {
	t.Parallel()

	sum, err := Add[uint32](math.MaxUint32-1, 1).Unpack()
	require.NoError(t, err)
	require.EqualValues(t, math.MaxUint32, sum)

	require.ErrorIs(t, Add[uint32](math.MaxUint32, 1).Err(), ErrOverflow)
}

func TestCheckAdd(t *testing.T) {
	t.Parallel()

	require.NoError(t, CheckAdd(uint64(math.MaxUint64-1), uint64(1)))
	require.ErrorIs(
		t, CheckAdd(uint64(math.MaxUint64), uint64(1)), ErrOverflow,
	)
	require.NoError(t, CheckAdd(uint32(math.MaxUint32-1), uint32(1)))
	require.ErrorIs(
		t, CheckAdd(uint32(math.MaxUint32), uint32(1)), ErrOverflow,
	)
}
