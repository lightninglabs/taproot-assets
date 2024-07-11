package fn

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// errRpcCanceled is the error that is sent over the gRPC interface when
	// it's coming from the server side. The status.FromContextError()
	// function won't recognize it correctly, since the error sent over the
	// wire is a string and not a structured error anymore.
	errRpcCanceled = status.Error(codes.Canceled, context.Canceled.Error())
)

// IsCanceled returns true if the passed error is a gRPC error with the
// context.Canceled error as the cause.
func IsCanceled(err error) bool {
	if err == nil {
		return false
	}

	st := status.FromContextError(err)
	if st.Code() == codes.Canceled {
		return true
	}

	if strings.Contains(err.Error(), errRpcCanceled.Error()) {
		return true
	}

	return false
}

// IsRpcErr returns true if the given error is a gRPC error with the given
// candidate error as the cause.
func IsRpcErr(err error, candidate error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), candidate.Error())
}

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
