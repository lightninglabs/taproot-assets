package fn

import "fmt"

// Option represents a value which may or may not be there. This is very
// often preferable to nil-able pointers.
type Option[A any] struct {
	isSome bool
	some   A
}

// String returns a string representation of the Option.
func (o Option[A]) String() string {
	if o.isSome {
		return fmt.Sprintf("Some(%v)", o.some)
	}

	return "None"
}

// Some trivially injects a value into an optional context.
//
// Some : A -> Option[A].
func Some[A any](a A) Option[A] {
	return Option[A]{
		isSome: true,
		some:   a,
	}
}

// None trivially constructs an empty option.
//
// None : Option[A].
func None[A any]() Option[A] {
	return Option[A]{}
}

// MaybeSome constructs an option from a pointer.
//
// MaybeSome : *A -> Option[A].
func MaybeSome[A any](a *A) Option[A] {
	if a == nil {
		return None[A]()
	}

	return Some[A](*a)
}

// ElimOption is the universal Option eliminator. It can be used to safely
// handle all possible values inside the Option by supplying two continuations.
//
// ElimOption : (Option[A], () -> B, A -> B) -> B.
func ElimOption[A, B any](o Option[A], b func() B, f func(A) B) B {
	if o.isSome {
		return f(o.some)
	}

	return b()
}

// UnwrapOr is used to extract a value from an option, and we supply the default
// value in the case when the Option is empty.
//
// UnwrapOr : (Option[A], A) -> A.
func (o Option[A]) UnwrapOr(a A) A {
	if o.isSome {
		return o.some
	}

	return a
}

// UnwrapToPtr is used to extract a reference to a value from an option, and we
// supply an empty pointer in the case when the Option is empty.
func (o Option[A]) UnwrapToPtr() *A {
	var v *A
	o.WhenSome(func(a A) {
		v = &a
	})

	return v
}

// UnwrapOrFunc is used to extract a value from an option, and we supply a
// thunk to be evaluated in the case when the Option is empty.
func (o Option[A]) UnwrapOrFunc(f func() A) A {
	return ElimOption(o, f, func(a A) A { return a })
}

// UnwrapOrFuncErr is used to extract a value from an option, and we supply a
// thunk to be evaluated in the case when the Option is empty.
func (o Option[A]) UnwrapOrFuncErr(f func() (A, error)) (A, error) {
	if o.isSome {
		return o.some, nil
	}

	return f()
}

// UnwrapOrErr is used to extract a value from an option, if the option is
// empty, then the specified error is returned directly.
func (o Option[A]) UnwrapOrErr(err error) (A, error) {
	if !o.isSome {
		var zero A
		return zero, err
	}

	return o.some, nil
}

// WhenSome is used to conditionally perform a side-effecting function that
// accepts a value of the type that parameterizes the option. If this function
// performs no side effects, WhenSome is useless.
//
// WhenSome : (Option[A], A -> ()) -> ().
func (o Option[A]) WhenSome(f func(A)) {
	if o.isSome {
		f(o.some)
	}
}

// IsSome returns true if the Option contains a value
//
// IsSome : Option[A] -> bool.
func (o Option[A]) IsSome() bool {
	return o.isSome
}

// IsNone returns true if the Option is empty
//
// IsNone : Option[A] -> bool.
func (o Option[A]) IsNone() bool {
	return !o.isSome
}

// FlattenOption joins multiple layers of Options together such that if any of
// the layers is None, then the joined value is None. Otherwise the innermost
// Some value is returned.
//
// FlattenOption : Option[Option[A]] -> Option[A].
func FlattenOption[A any](oo Option[Option[A]]) Option[A] {
	if oo.IsNone() {
		return None[A]()
	}
	if oo.some.IsNone() {
		return None[A]()
	}

	return oo.some
}

// ChainOption transforms a function A -> Option[B] into one that accepts an
// Option[A] as an argument.
//
// ChainOption : (A -> Option[B]) -> Option[A] -> Option[B].
func ChainOption[A, B any](f func(A) Option[B]) func(Option[A]) Option[B] {
	return func(o Option[A]) Option[B] {
		if o.isSome {
			return f(o.some)
		}

		return None[B]()
	}
}

// MapOption transforms a pure function A -> B into one that will operate
// inside the Option context.
//
// MapOption : (A -> B) -> Option[A] -> Option[B].
func MapOption[A, B any](f func(A) B) func(Option[A]) Option[B] {
	return func(o Option[A]) Option[B] {
		if o.isSome {
			return Some(f(o.some))
		}

		return None[B]()
	}
}

// MapOptionZ transforms a pure function A -> B into one that will operate
// inside the Option context. Unlike MapOption, this function will return the
// default/zero argument of the return type if the Option is empty.
func MapOptionZ[A, B any](o Option[A], f func(A) B) B {
	var zero B

	if o.IsNone() {
		return zero
	}

	return f(o.some)
}

// LiftA2Option transforms a pure function (A, B) -> C into one that will
// operate in an Option context. For the returned function, if either of its
// arguments are None, then the result will be None.
//
// LiftA2Option : ((A, B) -> C) -> (Option[A], Option[B]) -> Option[C].
func LiftA2Option[A, B, C any](
	f func(A, B) C) func(Option[A], Option[B]) Option[C] {

	return func(o1 Option[A], o2 Option[B]) Option[C] {
		if o1.isSome && o2.isSome {
			return Some(f(o1.some, o2.some))
		}

		return None[C]()
	}
}

// Alt chooses the left Option if it is full, otherwise it chooses the right
// option. This can be useful in a long chain if you want to choose between
// many different ways of producing the needed value.
//
// Alt : Option[A] -> Option[A] -> Option[A].
func (o Option[A]) Alt(o2 Option[A]) Option[A] {
	if o.isSome {
		return o
	}

	return o2
}
