package proof

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MaxSendFragmentOutputs is the maximum number of outputs that can be
	// included in a single send fragment. This is to limit the size of the
	// encrypted message that is sent to the auth mailbox server. That means
	// a single send to an address can only use at most pieces from 256
	// different asset tranches, which should not really ever be a limiting
	// factor in practice.
	MaxSendFragmentOutputs = 256
)

// SendFragmentVersion is the version of the send fragment.
type SendFragmentVersion uint8

const (
	// SendFragmentVersionUnknown is the version of the send fragment that
	// indicates an unknown version. This is used to signal that the
	// fragment version is not recognized.
	SendFragmentVersionUnknown SendFragmentVersion = 0

	// SendFragmentV0 is the first version of the send fragment.
	SendFragmentV0 SendFragmentVersion = 1

	// LatestVersion is the latest version of the send fragment.
	LatestVersion = SendFragmentV0
)

// SendOutput is a single asset UTXO or leaf that is being sent to the receiver
// of a V2 TAP address send. It contains the asset version, amount, derivation
// method, and the script key that can be used to spend the output.
type SendOutput struct {
	// AssetVersion is the version of the asset that is being sent.
	AssetVersion asset.Version

	// Amount is the amount of this asset output.
	Amount uint64

	// DerivationMethod is the method used to derive the script key for this
	// output.
	DerivationMethod asset.ScriptKeyDerivationMethod

	// ScriptKey is the serialized script key that can be used to spend the
	// output. The script key is derived from the recipient's internal key
	// specified in the TAP address, and the asset ID of the output (using
	// the derivation method specified in the above field).
	ScriptKey asset.SerializedKey
}

// SendFragment is the message that needs to be sent from the sender to the
// receiver of a V2 TAP address send. It contains all the information required
// to reconstruct the information required to fetch proofs from the universe,
// and to materialize the asset outputs on the receiver's side. We assume that
// the receiver has access to the TAP address that was used to send the assets.
type SendFragment struct {
	// Version is the version of the send fragment.
	Version SendFragmentVersion

	// BlockHeader is the block header of the block that contains the
	// transaction. This is useful to fetch the full block to extract the
	// transaction on a node that doesn't have the transaction index
	// enabled.
	BlockHeader wire.BlockHeader

	// BlockHeight is the height of the block that contains the transaction.
	BlockHeight uint32

	// OutPoint is the outpoint of the transaction that contains the asset
	// outputs that are being sent.
	OutPoint wire.OutPoint

	// Outputs is a map of asset IDs to the outputs that are being sent.
	Outputs map[asset.ID]SendOutput

	// TaprootAssetRoot is the root of the Taproot Asset commitment tree.
	TaprootAssetRoot [sha256.Size]byte

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
}

// Validate ensures that the send fragment is formally valid.
func (f *SendFragment) Validate() error {
	// Ensure the version is known.
	if f.Version <= SendFragmentVersionUnknown ||
		f.Version > LatestVersion {

		return fmt.Errorf("unknown send fragment version: %d",
			f.Version)
	}

	// Ensure the outputs are not empty and do not exceed the maximum
	// allowed number of outputs.
	if len(f.Outputs) == 0 || len(f.Outputs) > MaxSendFragmentOutputs {
		return fmt.Errorf("invalid number of outputs: %d, must be "+
			"between 1 and %d", len(f.Outputs),
			MaxSendFragmentOutputs)
	}

	return nil
}

// EncodeRecords returns the encoding records for the SendFragment.
func (f *SendFragment) EncodeRecords() []tlv.Record {
	records := []tlv.Record{
		FragmentVersionRecord(&f.Version),
		FragmentBlockHeaderRecord(&f.BlockHeader),
		FragmentBlockHeightRecord(&f.BlockHeight),
		FragmentOutPointRecord(&f.OutPoint),
		FragmentOutputsRecord(&f.Outputs),
		FragmentTaprootAssetRootRecord(&f.TaprootAssetRoot),
	}

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, f.UnknownOddTypes)
}

// DecodeRecords returns the decoding records for the SendFragment.
func (f *SendFragment) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		FragmentVersionRecord(&f.Version),
		FragmentBlockHeaderRecord(&f.BlockHeader),
		FragmentBlockHeightRecord(&f.BlockHeight),
		FragmentOutPointRecord(&f.OutPoint),
		FragmentOutputsRecord(&f.Outputs),
		FragmentTaprootAssetRootRecord(&f.TaprootAssetRoot),
	}
}

// Encode attempts to encode the SendFragment into the passed io.Writer.
func (f *SendFragment) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(f.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode attempts to decode the SendFragment from the passed io.Reader.
func (f *SendFragment) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(f.DecodeRecords()...)
	if err != nil {
		return err
	}

	unknownOddTypes, err := asset.TlvStrictDecodeP2P(
		stream, r, KnownSendFragmentTypes,
	)
	if err != nil {
		return err
	}

	f.UnknownOddTypes = unknownOddTypes

	return nil
}

// DecodeSendFragment decodes a serialized send fragment from the given blob of
// bytes.
func DecodeSendFragment(blob []byte) (*SendFragment, error) {
	fragment := &SendFragment{
		Outputs: make(map[asset.ID]SendOutput),
	}

	if err := fragment.Decode(bytes.NewReader(blob)); err != nil {
		return nil, fmt.Errorf("unable to decode send fragment: %w",
			err)
	}

	return fragment, nil
}

// SendManifest holds the shipping instruction that contains all the information
// required to send a fragment to the receiver of a V2 TAP address send. The
// manifest itself isn't encoded, only the actual fragment is serialized and
// encrypted and sent to the auth mailbox server as a message. The manifest
// contains all the meta information required to send the encrypted fragment to
// the auth mailbox server, including the TX proof to show we own the output and
// have committed it to the chain.
type SendManifest struct {
	// TxProof is the proof of the transaction that contains the asset
	// outputs that are being sent. This is used as proof-of work to show
	// to the auth mailbox server.
	TxProof TxProof

	// Receiver is the receiver's public key of the asset outputs, used
	// to decrypt the send fragment. This is the internal key of the address
	// that was used to send the assets.
	Receiver btcec.PublicKey

	// CourierURL is the URL of the auth mailbox server that will be used to
	// send the fragment to the receiver.
	CourierURL url.URL

	// Fragment is the send fragment that contains all the information the
	// receiver needs to reconstruct the asset outputs and fetch proofs from
	// the universe. The fragment will be encoded and encrypted and uploaded
	// as a message to the auth mailbox server.
	Fragment SendFragment
}
