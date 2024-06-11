package taprpc

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// MetadataDecDisplayKey is the JSON key used in the metadata field of a
	// minted asset to express the decimal display of the minted asset.
	MetadataDecDisplayKey = "decimal_display"
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

// EncodeDecimalDisplayInJSON takes a single value and an encoded json object
// and attempts to append a specific key-value pair in the json object which
// represents the decimal display value, then encodes it again and returns it.
func EncodeDecimalDisplayInJSON(decDisplay uint32,
	jBytes []byte) ([]byte, error) {

	var jMeta map[string]interface{}

	// Only attempt to decode the serialized json object if not empty.
	if len(jBytes) != 0 {
		err := json.Unmarshal(jBytes, &jMeta)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal json "+
				"asset meta: %w", err)
		}

		if _, exists := jMeta[MetadataDecDisplayKey]; exists {
			return nil, fmt.Errorf("decimal display key already " +
				"exists in asset meta")
		}
	}

	jMeta[MetadataDecDisplayKey] = decDisplay

	updatedMeta, err := json.Marshal(jMeta)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal updated json asset "+
			"meta: %w", err)
	}

	return updatedMeta, nil
}
