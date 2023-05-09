package chanutils

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
