package fn

import (
	"context"
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
