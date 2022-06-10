package address

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

// Human-readable prefixes for bech32m encoded addresses for each network.
const (
	Bech32HRPTaroMainnet = "taro"
	Bech32HRPTaroTestnet = "tarot"
)

// Set of all supported prefixes for bech32m encoded addresses.
var (
	bech32TaroPrefixes = map[string]struct{}{
		Bech32HRPTaroMainnet + "1": {},
		Bech32HRPTaroTestnet + "1": {},
	}
)

// IsBech32TaroPrefix returns whether the prefix is a known prefix for Taro
// addresses on any supported network.  This is used when decoding an address
// string into a TLV.
func IsBech32TaroPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32TaroPrefixes[prefix]
	return ok
}

type AddressTaro struct {
	hrp     string
	payload AddressTLV
}

type AddressTLV struct {
	// Version is the Taro version of the asset.
	Version asset.Version

	// ID is the hash that uniquely identifies the asset requested by the receiver.
	ID asset.ID

	// FamilyKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	FamilyKey *btcec.PublicKey

	// ScriptKey represents a tweaked Taproot output key encumbering the
	// different ways an asset can be spent.
	ScriptKey btcec.PublicKey

	// Internal is the
	InternalKey btcec.PublicKey

	// Amount is the number of asset units being requested by the receiver.
	Amount uint64

	// Type uniquely identifies the type of Taro asset.
	Type asset.Type
}

// New creates an address for receiving a Taro asset.
func New(id asset.ID, familyKey *btcec.PublicKey, scriptKey btcec.PublicKey,
	internalKey btcec.PublicKey, amount uint64, assetType asset.Type, hrp string,
) *AddressTaro {

	payload := AddressTLV{
		Version:     asset.V0,
		ID:          id,
		FamilyKey:   familyKey,
		ScriptKey:   scriptKey,
		InternalKey: internalKey,
		Amount:      amount,
		Type:        assetType,
	}
	if IsBech32TaroPrefix(hrp + "1") {
		return &AddressTaro{
			hrp:     hrp,
			payload: payload,
		}
	}
	return nil
}

// EncodeRecords determines the non-nil records to include when encoding an
// address at runtime.
func (a AddressTLV) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 7)
	records = append(records, NewAddressVersionRecord(&a.Version))
	records = append(records, NewAddressIDRecord(&a.ID))
	if a.FamilyKey != nil {
		records = append(records, NewAddressFamilyKeyRecord(&a.FamilyKey))
	}
	records = append(records, NewAddressScriptKeyRecord(&a.ScriptKey))
	records = append(records, NewAddressInternalKeyRecord(&a.InternalKey))
	records = append(records, NewAddressAmountRecord(&a.Amount))
	if a.Type != asset.Normal {
		records = append(records, NewAddressTypeRecord(&a.Type))
	}
	return records
}

// DecodeRecords provides all records known for an address for proper
// decoding.
func (a *AddressTLV) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		NewAddressVersionRecord(&a.Version),
		NewAddressIDRecord(&a.ID),
		NewAddressFamilyKeyRecord(&a.FamilyKey),
		NewAddressScriptKeyRecord(&a.ScriptKey),
		NewAddressInternalKeyRecord(&a.InternalKey),
		NewAddressAmountRecord(&a.Amount),
		NewAddressTypeRecord(&a.Type),
	}
}

// Encode encodes an address into a TLV stream.
func (a AddressTLV) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes an address from a TLV stream.
func (a *AddressTLV) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(a.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// EncodeAddress returns a bech32m string encoding of a Taro address.
func (a AddressTaro) EncodeAddress() (string, error) {
	var buf bytes.Buffer
	if err := a.payload.Encode(&buf); err != nil {
		return "", err
	}
	// Group the address bytes into 5 bit groups, as this is what is used to
	// encode each character in the address string.
	converted, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", err
	}

	// Check that our address is targeting a supported network.
	if IsBech32TaroPrefix(a.hrp + "1") {
		bech, err := bech32.EncodeM(a.hrp, converted)
		if err != nil {
			return "", err
		}
		return bech, nil
	} else {
		return "", fmt.Errorf("unsupported hrp value %s", a.hrp)
	}
}

// DecodeAddress parses a bech32m encoded Taro address string and
// returns the HRP and address TLV.
func DecodeAddress(addr string) (*AddressTaro, error) {
	// Bech32m encoded Taro addresses start with a human-readable part
	// (hrp) followed by '1'. For Bitcoin mainnet the hrp is "taro", and for
	// testnet it is "tarot". If the address string has a prefix that matches
	// one of the prefixes for the known networks, we try to decode it as
	// a Taro address.
	oneIndex := strings.LastIndexByte(addr, '1')
	if oneIndex > 1 {
		prefix := addr[:oneIndex+1]
		if IsBech32TaroPrefix(prefix) {
			_, data, err := bech32.DecodeNoLimit(addr)
			if err != nil {
				return nil, err
			}

			// The remaining characters of the address returned are grouped into
			// words of 5 bits. In order to restore the original address TLV
			// bytes, we'll need to regroup into 8 bit words.
			converted, err := bech32.ConvertBits(data, 5, 8, false)
			if err != nil {
				return nil, err
			}

			// The HRP is everything before the found '1'.
			hrp := prefix[:len(prefix)-1]

			buf := bytes.NewBuffer(converted)
			var a AddressTaro
			if err := a.payload.Decode(buf); err != nil {
				return nil, err
			}
			a.hrp = hrp
			return &a, nil
		}
	}
	return nil, fmt.Errorf("invalid bech32m string")
}
