package fn

import "errors"

// CriticalError is an error type that should be used for errors that are
// critical and should cause the application to exit.
type CriticalError struct {
	Err error
}

// NewCriticalError creates a new CriticalError instance.
func NewCriticalError(err error) *CriticalError {
	return &CriticalError{Err: err}
}

// Error implements the error interface.
func (e *CriticalError) Error() string {
	return e.Err.Error()
}

// Unwrap implements the errors.Wrapper interface.
func (e *CriticalError) Unwrap() error {
	return e.Err
}

// ErrorAs behaves the same as `errors.As` except there's no need to declare
// the target error as a variable first.
// Instead of writing:
//
//	var targetErr *TargetErr
//	errors.As(err, &targetErr)
//
// We can write:
//
//	lnutils.ErrorAs[*TargetErr](err)
//
// To save us from declaring the target error variable.
func ErrorAs[Target error](err error) bool {
	var targetErr Target

	return errors.As(err, &targetErr)
}
