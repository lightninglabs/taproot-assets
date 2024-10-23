package rfqmath

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func testAddition[N Int[N]](t *rapid.T) {
	zero := NewInt[N]().FromUint64(0)

	gen := rapid.Custom(func(t *rapid.T) N {
		return NewInt[N]().FromUint64(
			rapid.Uint64Range(0, math.MaxUint64).Draw(t, "n"),
		)
	})

	a := gen.Draw(t, "a")
	b := gen.Draw(t, "b")

	// Adding zero to a value should not change it.
	if c := a.Add(zero); !c.Equals(a) {
		t.Errorf("a + 0 = %v, expected %v", c, a)
	}

	// A+B should be equal to B+A.
	if c := a.Add(b); !c.Equals(b.Add(a)) {
		t.Errorf("a + b = %v, b + a = %v", c, b.Add(a))
	}

	// (A + B) + C should be equal to A + (B + C) (associativity).
	c := gen.Draw(t, "c")
	if d, e := a.Add(b).Add(c), a.Add(b.Add(c)); !d.Equals(e) {
		t.Errorf("associativity: (a + b) + c = %v, a + (b + c) = %v",
			d, e)
	}
}

// TestArithmeticAddition tests some basic invariants around addition of the
// integer type.
func TestArithmeticAddition(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testAddition[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testAddition[BigInt])
	})
}

func testMultiplication[N Int[N]](t *rapid.T) {
	one := NewInt[N]().FromUint64(1)

	gen := rapid.Custom(func(t *rapid.T) N {
		return NewInt[N]().FromUint64(
			rapid.Uint64Range(0, math.MaxUint64).Draw(t, "n"),
		)
	})

	a := gen.Draw(t, "a")
	b := gen.Draw(t, "b")

	// Multiplying by one should not change the value.
	if c := a.Mul(one); !c.Equals(a) {
		t.Errorf("a * 1 = %v, expected %v", c, a)
	}

	// A*B should be equal to B*A (commutativity).
	if c := a.Mul(b); !c.Equals(b.Mul(a)) {
		t.Errorf("a * b = %v, b * a = %v", c, b.Mul(a))
	}
}

// TestArithmeticMultiplication tests some basic invariants around
// multiplication of the integer type.
func TestArithmeticMultiplication(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testMultiplication[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testMultiplication[BigInt])
	})
}

func testSubtraction[N Int[N]](t *rapid.T) {
	zero := NewInt[N]().FromUint64(0)

	gen := rapid.Custom(func(t *rapid.T) N {
		return NewInt[N]().FromUint64(
			rapid.Uint64Range(0, math.MaxUint64).Draw(t, "n"),
		)
	})

	a := gen.Draw(t, "a")

	// Subtracting zero should not change the value>
	if c := a.Sub(zero); !c.Equals(a) {
		t.Errorf("a - 0 = %v, expected %v", c, a)
	}

	// a - a should equal zero>
	if c := a.Sub(a); !c.Equals(zero) {
		t.Errorf("a - a = %v, expected 0", c)
	}
}

// TestArithmeticSubtraction tests some basic invariants around subtraction of
// the integer type.
func TestArithmeticSubtraction(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testSubtraction[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testSubtraction[BigInt])
	})
}

// testDivision tests the division operation
func testDivision[N Int[N]](t *rapid.T) {
	one := NewInt[N]().FromUint64(1)
	zero := NewInt[N]().FromUint64(0)

	gen := rapid.Custom(func(t *rapid.T) N {
		return NewInt[N]().FromUint64(
			rapid.Uint64Range(1, math.MaxUint64).Draw(t, "n"),
		)
	})

	a := gen.Draw(t, "a")
	b := gen.Draw(t, "b")

	_, isUint64 := any(a).(GoInt[uint64])

	// Dividing by one should not change the value.
	if c := a.Div(one); !c.Equals(a) {
		t.Errorf("a / 1 = %v, expected %v", c, a)
	}

	// a / a should equal one.
	if c := a.Div(a); !c.Equals(one) {
		t.Errorf("a / a = %v, expected 1", c)
	}

	// (a * b) / b should equal a (for non-zero b).
	if !b.Equals(zero) {
		product := a.Mul(b)

		// If this is the uint64 implementation, and the product
		// overflows, then we can skip this check.
		//
		// TODO(roasbeef): predicate it all on checked arithmetic
		switch {
		case isUint64 && a.ToUint64() > math.MaxUint64/b.ToUint64():
			fallthrough
		case isUint64 && product.ToUint64() < a.ToUint64():
			break
		default:
			quotient := product.Div(b)
			if !quotient.Equals(a) {
				t.Errorf("(a * b) / b: (%v * %v) / %v = %v, "+
					"expected %v", a, b, b, quotient, a)
			}
		}
	}

	// a / 1 should equal a
	divByOne := a.Div(one)
	if !divByOne.Equals(a) {
		t.Errorf("division by one: %v / 1 = %v, expected %v", a,
			divByOne, a)
	}

	// 0 / a should equal 0 (for non-zero a).
	if !a.Equals(zero) {
		zeroDiv := zero.Div(a)
		if !zeroDiv.Equals(zero) {
			t.Errorf("zero divided by a: 0 / %v = %v, expected 0",
				a, zeroDiv)
		}
	}
}

// TestArithmeticDivision tests some basic invariants around division of the
// integer type.
func TestArithmeticDivision(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testDivision[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testDivision[BigInt])
	})
}

func testToFromFloat[N Int[N]](t *rapid.T) {
	gen := rapid.Custom(func(t *rapid.T) N {
		return NewInt[N]().FromUint64(
			rapid.Uint64Range(0, math.MaxUint64).Draw(t, "n"),
		)
	})

	a := gen.Draw(t, "a")

	// For this test, we can only support values less than
	// 9007199254740991, or 2^53-1.
	if a.ToUint64() > 9007199254740991 {
		return
	}

	// Converting to float and back should preserve the value.
	float := a.ToFloat()
	b := NewInt[N]().FromFloat(float)

	if !a.Equals(b) {
		t.Errorf("toFloat/fromFloat conversion failed: original %v, "+
			"got %v", a, b)
	}
}

// TestArithmeticToFromFloat tests the conversion to and from float for the
// integer type.
func TestArithmeticToFromFloat(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testToFromFloat[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testToFromFloat[BigInt])
	})
}

// testToFromUint64 tests the conversion between uint64 and Int
func testToFromUint64[N Int[N]](t *rapid.T) {
	gen := rapid.Uint64().Draw(t, "n")

	a := NewInt[N]().FromUint64(gen)

	// Converting to uint64 and back should preserve the value.
	uint64Val := a.ToUint64()
	b := NewInt[N]().FromUint64(uint64Val)
	if !a.Equals(b) {
		t.Errorf("toUint64/fromUint64 conversion failed: original %v, "+
			"got %v", a, b)
	}
}

// TestArithmeticToFromUint64 tests the conversion to and from uint64 for the
// integer type.
func TestArithmeticToFromUint64(t *testing.T) {
	t.Parallel()

	t.Run("go_uint_64", func(t *testing.T) {
		rapid.Check(t, testToFromUint64[GoInt[uint64]])
	})
	t.Run("big_int", func(t *testing.T) {
		rapid.Check(t, testToFromUint64[BigInt])
	})
}

// TestArithmeticGoIntConstructor tests the NewGoInt constructor for the GoInt
// type.
func TestArithmeticGoIntConstructor(t *testing.T) {
	t.Parallel()

	// We should be able to create a new GoInt from a uint64.
	val := uint64(123)
	a := NewGoInt[uint64](val)
	require.Equal(t, val, a.value)
}

// TestArithmeticIntConstructor tests the NewInt constructor for the BigInt.
func TestArithmeticIntConstructor(t *testing.T) {
	t.Parallel()

	// We should be able to create a new BigInt from a uint64.
	val := uint64(123)
	a := NewBigIntFromUint64(val)
	if !a.Equals(NewInt[BigInt]().FromUint64(val)) {
		t.Fatalf("expected %v, got %v", val, a)
	}
}
