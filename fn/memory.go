package fn

import (
	"errors"
	"reflect"
	"unsafe"
)

var (
	// ErrNilPointerDeference is returned when a nil pointer is
	// dereferenced.
	ErrNilPointerDeference = errors.New("nil pointer dereference")
)

var (
	// sliceHeaderSize is the size of a slice header.
	sliceHeaderSize = uint64(unsafe.Sizeof([]byte(nil)))

	// stringHeaderSize is the size of a string header.
	stringHeaderSize = uint64(unsafe.Sizeof(""))
)

// Ptr returns the pointer of the given value. This is useful in instances
// where a function returns the value, but a pointer is wanted. Without this,
// then an intermediate variable is needed.
func Ptr[T any](v T) *T {
	return &v
}

// ByteArray is a type constraint for type that reduces down to a fixed sized
// array.
type ByteArray interface {
	~[32]byte
}

// ByteSlice takes a byte array, and returns a slice. This is useful when a
// function returns an array, but a slice is wanted. Without this, then an
// intermediate variable is needed.
func ByteSlice[T ByteArray](v T) []byte {
	return v[:]
}

// ToArray takes a byte slice, and returns an array. This is useful when a
// fixed sized array is needed and the byte slice is known to be of the correct
// size.
func ToArray[T ByteArray](v []byte) T {
	var arr T
	copy(arr[:], v)
	return arr
}

// CopySlice returns a copy of the given slice. Does a shallow copy of the
// slice itself, not the underlying elements.
func CopySlice[T any](slice []T) []T {
	if slice == nil {
		return nil
	}

	newSlice := make([]T, len(slice))
	copy(newSlice, slice)
	return newSlice
}

// Deref safely dereferences a pointer. If the pointer is nil, it returns the
// zero value of type T and an error.
func Deref[T any](ptr *T) (T, error) {
	if ptr == nil {
		var zero T
		return zero, ErrNilPointerDeference
	}

	return *ptr, nil
}

// DerefPanic dereferences a pointer. If the pointer is nil, it panics.
func DerefPanic[T any](ptr *T) T {
	if ptr == nil {
		panic(ErrNilPointerDeference)
	}

	return *ptr
}

// LowerBoundByteSize returns a conservative deep-size estimate in bytes.
//
// Notes:
//   - Pointer-recursive and cycle safe; each heap allocation is counted once
//     using its data pointer.
//   - Lower bound: ignores allocator overhead, GC metadata, unused slice
//     capacity, map buckets/overflow, evacuation, rounding, and runtime
//     internals (chan/func).
func LowerBoundByteSize(x any) uint64 {
	// seen is a map of heap object identities which have already been
	// counted.
	seen := make(map[uintptr]struct{})
	return byteSizeVisit(reflect.ValueOf(x), true, seen)
}

// byteSizeVisit returns a conservative lower-bound byte count for `subject`.
//
// Notes:
//   - addSelf: include subject’s inline bytes when true. Parents pass false.
//   - seen: set of heap data pointers to avoid double counting and break
//     cycles.
//
// Lower bound: ignores allocator overhead, GC metadata, unused capacity, and
// runtime internals.
func byteSizeVisit(subject reflect.Value, addSelf bool,
	seen map[uintptr]struct{}) uint64 {

	if !subject.IsValid() {
		return 0
	}

	subjectType := subject.Type()
	subjectTypeKind := subjectType.Kind()

	if subjectTypeKind == reflect.Interface {
		n := uint64(unsafe.Sizeof(subject.Interface()))
		if !subject.IsNil() {
			n += byteSizeVisit(subject.Elem(), true, seen)
		}
		return n
	}

	switch subjectTypeKind {
	case reflect.Ptr:
		if subject.IsNil() {
			return 0
		}

		ptr := subject.Pointer()
		if markSeen(ptr, seen) {
			return 0
		}

		return byteSizeVisit(subject.Elem(), true, seen)

	case reflect.Struct:
		n := uint64(0)
		if addSelf {
			n += uint64(subjectType.Size())
		}

		for i := 0; i < subject.NumField(); i++ {
			n += byteSizeVisit(subject.Field(i), false, seen)
		}

		return n

	case reflect.Array:
		n := uint64(0)
		if addSelf {
			n += uint64(subjectType.Size())
		}

		for i := 0; i < subject.Len(); i++ {
			n += byteSizeVisit(subject.Index(i), false, seen)
		}

		return n

	case reflect.Slice:
		if subject.IsNil() {
			return 0
		}

		n := sliceHeaderSize
		dataPtr := subject.Pointer()
		if dataPtr != 0 && !markSeen(dataPtr, seen) {
			elem := subjectType.Elem()
			n += uint64(subject.Len()) * uint64(elem.Size())
		}

		for i := 0; i < subject.Len(); i++ {
			n += byteSizeVisit(subject.Index(i), false, seen)
		}

		return n

	case reflect.String:
		n := stringHeaderSize
		dataPtr := subject.Pointer()
		if dataPtr != 0 && markSeen(dataPtr, seen) {
			return n
		}

		return n + uint64(subject.Len())

	case reflect.Map:
		n := uint64(unsafe.Sizeof(subject.Interface()))
		if subject.IsNil() {
			return n
		}

		it := subject.MapRange()
		for it.Next() {
			n += byteSizeVisit(it.Key(), false, seen)
			n += byteSizeVisit(it.Value(), false, seen)
		}

		return n

	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return uint64(unsafe.Sizeof(subject.Interface()))

	default:
		if addSelf {
			return uint64(subjectType.Size())
		}

		return 0
	}
}

// markSeen marks the given pointer as seen and returns true if it was already
// seen.
func markSeen(ptr uintptr, seen map[uintptr]struct{}) bool {
	if _, ok := seen[ptr]; ok {
		return true
	}

	seen[ptr] = struct{}{}
	return false
}
