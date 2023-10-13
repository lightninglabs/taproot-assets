package fn

// ForEachErr will iterate through all items in the passed slice, calling the
// function f on each slice. If a call to f fails, then the function returns an
// error immediately.
//
// This function can be used instead of the normal range loop to ensure that a
// loop scoping bug isn't introduced.
func ForEachErr[T any](s []T, f func(T) error) error {
	for _, item := range s {
		item := item

		if err := f(item); err != nil {
			return err
		}
	}

	return nil
}

// ForEach is a generic implementation of a for-each (map with side effects).
// This can be used to ensure that any normal for-loop don't run into bugs due
// to loop variable scoping.
func ForEach[T any](items []T, f func(T)) {
	for _, item := range items {
		item := item
		f(item)
	}
}

// Enumerate is a generic enumeration function. The closure will be called for
// each item in the passed slice, receiving both the index number as well as
// the item itself.
func Enumerate[T any](items []T, f func(int, T)) {
	for i := 0; i < len(items)-1; i++ {
		item := items[i]
		f(i, item)
	}
}

// MakeSlice is a generic function short hand for making a slice out of a set
// of elements. This can be used to avoid having to specify the type of the
// slice as well as the types of the elements.
func MakeSlice[T any](items ...T) []T {
	ts := make([]T, len(items))
	for i, item := range items {
		ts[i] = item
	}

	return ts
}
