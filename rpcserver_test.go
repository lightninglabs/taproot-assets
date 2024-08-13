package taprootassets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"pgregory.net/rapid"
)

// Result is used to store the output of a fallible function call.
type Result[T any] struct {
	res T
	err error
}

// genUniIDField is an interface that is used to compare generated input data
// with unmarshalled data.
type genUniIDField[T any, U universe.Identifier] interface {
	// IsValid checks if the generated data should be rejected during
	// unmarshal.
	IsValid() error

	// IsEqual checks if the generated data is equal to the unmarshalled
	// data.
	IsEqual(Result[U]) error

	// Inner returns the generated data.
	Inner() T

	// ValidInputErrorMsg returns an error message for valid input that
	// unmarshal failed on.
	ValidInputErrorMsg(error) error

	// InvalidInputErrorMsg returns an error message for an invalid input
	// that unmarshal succeeded on.
	InvalidInputErrorMsg(error) error
}

// Compare compares generated input data to unmarshalled data, checking for
// the expected behavior of unmarshalling and data equality.
func Compare[T any, U universe.Identifier](gen genUniIDField[T, U],
	res Result[U]) error {

	validGen := gen.IsValid()

	// Unmarshal was expected to fail.
	if res.err != nil && validGen != nil {
		return nil
	}

	// Unmarshal failed on valid input.
	if res.err != nil && validGen == nil {
		return gen.ValidInputErrorMsg(res.err)
	}

	// Unmarshal succeeded on invalid input.
	if res.err == nil && validGen != nil {
		return gen.InvalidInputErrorMsg(res.err)
	}

	// Unmarhsal succeeded on valid input; check equality.
	if res.err == nil && validGen == nil {
		return gen.IsEqual(res)
	}

	// This should be unreachable.
	return nil
}

// genAssetId is generated data used to populate universerpc.ID_AssetId.
type genAssetId struct {
	Bytes []byte
}

func (id genAssetId) Inner() []byte {
	return id.Bytes
}

// NewAssetId creates a new genAssetId instance.
func NewAssetId(t *rapid.T) genAssetId {
	var id genAssetId
	id.Bytes = rapid.SliceOf(rapid.Byte()).Draw(t, "ID")

	return id
}

func (id genAssetId) IsValid() error {
	// The only valid size for an asset ID is 32 bytes.
	idSize := len(id.Bytes)
	if idSize != sha256.Size {
		return fmt.Errorf("generated asset ID invalid size: %d", idSize)
	}

	return nil
}

func (id genAssetId) IsEqual(other Result[universe.Identifier]) error {
	otherBytes := other.res.AssetID[:]
	if len(otherBytes) == 0 {
		return fmt.Errorf("asset ID bytes not unmarshalled: %v",
			id.Inner())
	}

	if !bytes.Equal(id.Bytes, otherBytes) {
		return fmt.Errorf("asset ID mismatch: generated %x, "+
			"unmarshalled %x", id.Inner(), otherBytes)
	}

	return nil
}

func (id genAssetId) ValidInputErrorMsg(err error) error {
	return fmt.Errorf("unmarshal asset ID bytes failed: %v, %w",
		id.Inner(), err)
}

func (id genAssetId) InvalidInputErrorMsg(err error) error {
	return fmt.Errorf("invalid asset ID bytes not rejected: %v, %w",
		id.Inner(), id.IsValid())
}

var _ genUniIDField[[]byte, universe.Identifier] = (*genAssetId)(nil)

// genAssetIdStr is generated data used to populate universerpc.ID_AssetIdStr.
type genAssetIdStr struct {
	Str string
}

func (id genAssetIdStr) Inner() string {
	return id.Str
}

// NewAssetIDStr creates a new genAssetIdStr instance.
func NewAssetIDStr(t *rapid.T) genAssetIdStr {
	var id genAssetIdStr
	id.Str = rapid.String().Draw(t, "ID string")

	return id
}

func (id genAssetIdStr) IsValid() error {
	idSize := len(id.Inner())
	if idSize == 0 {
		return fmt.Errorf("asset ID string empty")
	}

	// Invalid hex should be rejected.
	_, hexErr := hex.DecodeString(id.Inner())
	if hexErr != nil {
		return fmt.Errorf("non-hex asset ID string: %w", hexErr)
	}

	// The only valid size for a hex-encoded asset ID is 64 bytes.
	if idSize != sha256.Size*2 {
		return fmt.Errorf("asset ID string invalid size: %d", idSize)
	}

	return nil
}

func (id genAssetIdStr) IsEqual(other Result[universe.Identifier]) error {
	otherStr := other.res.AssetID.String()
	if len(otherStr) == 0 {
		return fmt.Errorf("asset ID string not unmarshalled: "+
			"generated %v", id.Inner())
	}

	if id.Str != otherStr {
		return fmt.Errorf("asset ID string mismatch: generated %s, "+
			"unmarshalled %s", id.Inner(), otherStr)
	}

	return nil
}

func (id genAssetIdStr) ValidInputErrorMsg(err error) error {
	return fmt.Errorf("unmarshal asset ID string failed: %v, %w",
		id.Inner(), err)
}

func (id genAssetIdStr) InvalidInputErrorMsg(err error) error {
	return fmt.Errorf("invalid asset ID string not rejected: %v, %w",
		id.Inner(), id.IsValid())
}

var _ genUniIDField[string, universe.Identifier] = (*genAssetIdStr)(nil)

// genGroupKey is generated data used to populate universerpc.ID_GroupKey.
type genGroupKey struct {
	Bytes []byte
}

func (id genGroupKey) Inner() []byte {
	return id.Bytes
}

// NewGroupKey creates a new genGroupKey instance.
func NewGroupKey(t *rapid.T) genGroupKey {
	var id genGroupKey
	id.Bytes = rapid.SliceOf(rapid.Byte()).Draw(t, "Group key")

	return id
}

func (id genGroupKey) IsValid() error {
	// The only valid size for a group key is 32 or 33 bytes.
	idSize := len(id.Bytes)
	if idSize != schnorr.PubKeyBytesLen &&
		idSize != btcec.PubKeyBytesLenCompressed {

		return fmt.Errorf("generated group key invalid size: %d",
			idSize)
	}

	// The generated key must be valid.
	_, keyErr := parseUserKey(id.Bytes)
	return keyErr
}

func (id genGroupKey) IsEqual(otherResult Result[universe.Identifier]) error {
	otherKey := otherResult.res.GroupKey
	if otherKey == nil {
		return fmt.Errorf("group key not unmarshalled: %v", id.Inner())
	}

	// Since we parse the provided key as Schnorr, we must drop the parity
	// byte from the generated bytes before comparison.
	otherKeyBytes := schnorr.SerializePubKey(otherKey)
	idBytes := id.Inner()
	if len(id.Inner()) == btcec.PubKeyBytesLenCompressed {
		idBytes = idBytes[1:]
	}

	if !bytes.Equal(idBytes, otherKeyBytes) {
		return fmt.Errorf("group key mismatch: generated %x, "+
			"unmarshalled %x", id.Inner(), otherKeyBytes)
	}

	return nil
}

func (id genGroupKey) ValidInputErrorMsg(err error) error {
	return fmt.Errorf("unmarshal group key bytes failed: %x, %w",
		id.Inner(), err)
}

func (id genGroupKey) InvalidInputErrorMsg(err error) error {
	return fmt.Errorf("invalid group key bytes not rejected: %x, %w",
		id.Inner(), id.IsValid())
}

var _ genUniIDField[[]byte, universe.Identifier] = (*genGroupKey)(nil)

// genGroupKeyStr is generated data used to populate universerpc.ID_GroupKeyStr.
type genGroupKeyStr struct {
	Str string
}

func (id genGroupKeyStr) Inner() string {
	return id.Str
}

// NewGroupKeyStr creates a new genGroupKeyStr instance.
func NewGroupKeyStr(t *rapid.T) genGroupKeyStr {
	var id genGroupKeyStr
	id.Str = rapid.String().Draw(t, "Group key string")

	return id
}

func (id genGroupKeyStr) IsValid() error {
	idSize := len(id.Inner())
	if idSize == 0 {
		return fmt.Errorf("group key string empty")
	}

	// Invalid hex should be rejected.
	_, hexErr := hex.DecodeString(id.Inner())
	if hexErr != nil {
		return fmt.Errorf("non-hex group key string: %w", hexErr)
	}

	// The only valid sizes for a group key string is 64 or 66 bytes.
	if idSize != schnorr.PubKeyBytesLen*2 &&
		idSize != btcec.PubKeyBytesLenCompressed*2 {

		return fmt.Errorf("generated group key string invalid size: %d",
			idSize)
	}

	return nil
}

func (id genGroupKeyStr) IsEqual(
	otherResult Result[universe.Identifier]) error {

	otherKey := otherResult.res.GroupKey
	if otherKey == nil {
		return fmt.Errorf("group key string not unmarshalled: %v",
			id.Inner())
	}

	// Since we parse the provided key as Schnorr, we must drop the parity
	// byte from the generated string before comparison.
	otherKeyStr := hex.EncodeToString(schnorr.SerializePubKey(otherKey))
	idStr := id.Inner()
	if len(id.Inner()) == btcec.PubKeyBytesLenCompressed*2 {
		idStr = idStr[2:]
	}

	if idStr != otherKeyStr {
		return fmt.Errorf("group key string mismatch: generated %s, "+
			"unmarshalled %s", id.Inner(), otherKeyStr)
	}

	return nil
}

func (id genGroupKeyStr) ValidInputErrorMsg(err error) error {
	return fmt.Errorf("unmarshal group key string failed: %v, %w",
		id.Inner(), err)
}

func (id genGroupKeyStr) InvalidInputErrorMsg(err error) error {
	return fmt.Errorf("invalid group key string not rejected: %v, %w",
		id.Inner(), id.IsValid())
}

var _ genUniIDField[string, universe.Identifier] = (*genGroupKeyStr)(nil)

// testUnmarshalUniId tests that UnmarshalUniID correctly unmarshals a
// well-formed rpc ID, and rejects an invalid ID.
func testUnmarshalUniId(t *rapid.T) {
	KnownProofTypes := map[universerpc.ProofType]int32{
		universerpc.ProofType_PROOF_TYPE_UNSPECIFIED: 0,
		universerpc.ProofType_PROOF_TYPE_ISSUANCE:    1,
		universerpc.ProofType_PROOF_TYPE_TRANSFER:    2,
	}

	IDBytes := NewAssetId(t)
	IDStr := NewAssetIDStr(t)
	IDGroupKeyBytes := NewGroupKey(t)
	IDGroupKeyStr := NewGroupKeyStr(t)

	IDFieldSelector := rapid.ByteMax(0x5).Draw(t, "ID field selector")
	proofType := rapid.Int32().Draw(t, "proofType")
	rpcProofType := universerpc.ProofType(proofType)

	uniId := &universerpc.ID{
		ProofType: rpcProofType,
	}

	// Set the ID to random data, of a random type.
	switch IDFieldSelector {
	case 0:
		uniId.Id = &universerpc.ID_AssetId{
			AssetId: IDBytes.Inner(),
		}

	case 1:
		uniId.Id = &universerpc.ID_AssetIdStr{
			AssetIdStr: IDStr.Inner(),
		}

	case 2:
		uniId.Id = &universerpc.ID_GroupKey{
			GroupKey: IDGroupKeyBytes.Inner(),
		}

	case 3:
		uniId.Id = &universerpc.ID_GroupKeyStr{
			GroupKeyStr: IDGroupKeyStr.Inner(),
		}

		// Empty ID field.
	case 4:

		// Empty universe ID.
	case 5:
		uniId = nil
	}

	nativeUniID, err := UnmarshalUniID(uniId)
	unmarshalResult := Result[universe.Identifier]{
		res: nativeUniID,
		err: err,
	}

	// Unmarshalling an unknown proof type should fail.
	_, knownProofType := KnownProofTypes[rpcProofType]
	if !knownProofType {
		if err == nil {
			t.Fatalf("unknown proof type not rejected: %v",
				rpcProofType)
		}

		return
	}

	switch IDFieldSelector {
	case 0:
		if cmpErr := Compare(IDBytes, unmarshalResult); cmpErr != nil {
			t.Fatalf("%v", err)
		}

	case 1:
		if cmpErr := Compare(IDStr, unmarshalResult); cmpErr != nil {
			t.Fatalf("%v", err)
		}

	case 2:
		cmpErr := Compare(IDGroupKeyBytes, unmarshalResult)
		if cmpErr != nil {
			t.Fatalf("%v", err)
		}

	case 3:
		cmpErr := Compare(IDGroupKeyStr, unmarshalResult)
		if cmpErr != nil {
			t.Fatalf("%v", err)
		}

	case 4:
		if err == nil {
			t.Fatalf("unmarshal empty ID not rejected: %v", err)
		}

	case 5:
		if err == nil {
			t.Fatalf("unmarshal ID with empty ID not rejected: %v",
				err)
		}
	}

	// Check equality of the proof type.
	if err == nil && int32(nativeUniID.ProofType) != proofType {
		t.Fatalf("proof type mismatch: generated %v, unmarshalled %v",
			proofType, nativeUniID.ProofType)
	}
}

func TestUnmarshalUniId(t *testing.T) {
	rapid.Check(t, testUnmarshalUniId)
}
