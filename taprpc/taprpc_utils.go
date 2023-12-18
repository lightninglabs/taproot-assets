package taprpc

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	// ProtoJSONMarshalOpts is a struct that holds the default marshal
	// options for marshaling protobuf messages into JSON in a
	// human-readable way. This should only be used in the CLI and in
	// integration tests.
	ProtoJSONMarshalOpts = &protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "    ",
		UseHexForBytes:  true,
	}

	// ProtoJSONUnmarshalOpts is a struct that holds the default unmarshal
	// options for un-marshaling lncli JSON into protobuf messages. This
	// should only be used in the CLI and in integration tests.
	ProtoJSONUnmarshalOpts = &protojson.UnmarshalOptions{
		AllowPartial:   false,
		UseHexForBytes: true,
	}

	// RESTJsonMarshalOpts is a struct that holds the default marshal
	// options for marshaling protobuf messages into REST JSON in a
	// human-readable way. This should be used when interacting with the
	// REST proxy only.
	RESTJsonMarshalOpts = &protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		UseHexForBytes:  true,
	}

	// RESTJsonUnmarshalOpts is a struct that holds the default unmarshal
	// options for un-marshaling REST JSON into protobuf messages. This
	// should be used when interacting with the REST proxy only.
	RESTJsonUnmarshalOpts = &protojson.UnmarshalOptions{
		AllowPartial:   false,
		UseHexForBytes: true,
	}
)

// IsUnimplemented returns true if the error is a gRPC error with the code
// Unimplemented.
func IsUnimplemented(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	return s.Code() == codes.Unimplemented
}
