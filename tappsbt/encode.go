package tappsbt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// falseAsBytes is a byte slice containing a single byte with the value
	// 0x00, representing the boolean value "false".
	falseAsBytes = []byte{0x00}

	// trueAsBytes is a byte slice containing a single byte with the value
	// 0x01, representing the boolean value "true".
	trueAsBytes = []byte{0x01}
)

// customPsbtField is a type alias psbt.Unknown to make it more clear that we
// are using the Unknown struct to represent a custom PSBT field.
type customPsbtField = psbt.Unknown

// encoderFunc is a function type for encoding a virtual PSBT item into a list
// of Unknown struct.
type encoderFunc func(key []byte) ([]*customPsbtField, error)

// encoderMapping maps a PSBT key to an encoder function.
type encoderMapping struct {
	key     []byte
	encoder encoderFunc
}

// EncodeAsPsbt returns the PSBT encoding of the current virtual packet, or an
// error if the encoding fails.
func (p *VPacket) EncodeAsPsbt() (*psbt.Packet, error) {
	unsignedTx := &wire.MsgTx{
		Version: 2,
		TxIn:    make([]*wire.TxIn, len(p.Inputs)),
		TxOut:   make([]*wire.TxOut, len(p.Outputs)),
	}
	packet := &psbt.Packet{
		UnsignedTx: unsignedTx,
		Inputs:     make([]psbt.PInput, len(p.Inputs)),
		Outputs:    make([]psbt.POutput, len(p.Outputs)),
		Unknowns: []*customPsbtField{
			{
				Key:   PsbtKeyTypeGlobalTapIsVirtualTx,
				Value: trueAsBytes,
			},
			{
				Key:   PsbtKeyTypeGlobalTapChainParamsHRP,
				Value: []byte(p.ChainParams.TapHRP),
			},
			{
				Key:   PsbtKeyTypeGlobalTapPsbtVersion,
				Value: []byte{p.Version},
			},
		},
	}

	for idx := range p.Inputs {
		pIn, err := p.Inputs[idx].encode()
		if err != nil {
			return nil, fmt.Errorf("error encoding input %d: %w",
				idx, err)
		}

		unsignedTx.TxIn[idx] = &wire.TxIn{}
		packet.Inputs[idx] = pIn
	}

	for idx := range p.Outputs {
		pOut, txOut, err := p.Outputs[idx].encode(
			p.ChainParams.HDCoinType,
		)
		if err != nil {
			return nil, fmt.Errorf("error encoding output %d: %w",
				idx, err)
		}

		unsignedTx.TxOut[idx] = txOut
		packet.Outputs[idx] = pOut
	}

	return packet, nil
}

// Serialize creates a binary serialization of the referenced VPacket struct
// with lexicographical ordering (by key) of the subsections.
func (p *VPacket) Serialize(w io.Writer) error {
	packet, err := p.EncodeAsPsbt()
	if err != nil {
		return fmt.Errorf("error encoding as PSBT: %w", err)
	}

	return packet.Serialize(w)
}

// B64Encode returns the base64 encoding of the serialization of the current
// virtual packet, or an error if the encoding fails.
func (p *VPacket) B64Encode() (string, error) {
	var b bytes.Buffer
	if err := p.Serialize(&b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// encode encodes the current VInput struct into a PInput and a wire.TxIn.
func (i *VInput) encode() (psbt.PInput, error) {
	pIn := i.PInput

	var (
		prevID      = &i.PrevID
		anchorValue = uint64(i.Anchor.Value)
		sigHashType = uint64(i.Anchor.SigHashType)
	)

	mapping := []encoderMapping{
		{
			key:     PsbtKeyTypeInputTapPrevID,
			encoder: tlvEncoder(&prevID, asset.PrevIDEncoder),
		},
		{
			key:     PsbtKeyTypeInputTapAnchorValue,
			encoder: tlvEncoder(&anchorValue, tlv.EUint64),
		},
		{
			key:     PsbtKeyTypeInputTapAnchorPkScript,
			encoder: tlvEncoder(&i.Anchor.PkScript, tlv.EVarBytes),
		},
		{
			key:     PsbtKeyTypeInputTapAnchorSigHashType,
			encoder: tlvEncoder(&sigHashType, tlv.EUint64),
		},
		{
			key:     PsbtKeyTypeInputTapAnchorInternalKey,
			encoder: pubKeyEncoder(i.Anchor.InternalKey),
		},
		{
			key: PsbtKeyTypeInputTapAnchorMerkleRoot,
			encoder: tlvEncoder(
				&i.Anchor.MerkleRoot, tlv.EVarBytes,
			),
		},
		{
			key: PsbtKeyTypeInputTapAnchorOutputBip32Derivation,
			encoder: bip32DerivationEncoder(
				i.Anchor.Bip32Derivation,
			),
		},
		{
			//nolint:lll
			key: PsbtKeyTypeInputTapAnchorOutputTaprootBip32Derivation,
			encoder: taprootBip32DerivationEncoder(
				i.Anchor.TrBip32Derivation,
			),
		},
		{
			key: PsbtKeyTypeInputTapAnchorTapscriptSibling,
			encoder: tlvEncoder(
				&i.Anchor.TapscriptSibling, tlv.EVarBytes,
			),
		},
		{
			key:     PsbtKeyTypeInputTapAsset,
			encoder: assetEncoder(i.asset),
		},
		{
			key:     PsbtKeyTypeInputTapAssetProof,
			encoder: proofEncoder(i.Proof),
		},
	}

	for idx := range mapping {
		customFields, err := mapping[idx].encoder(mapping[idx].key)
		if err != nil {
			return pIn, fmt.Errorf("error encoding input key %x: "+
				"%w", mapping[idx].key, err)
		}

		if len(customFields) > 0 {
			pIn.Unknowns = append(pIn.Unknowns, customFields...)
		}
	}

	return pIn, nil
}

// encode encodes the current VOutput struct into a POutput and a wire.TxOut.
func (o *VOutput) encode(coinType uint32) (psbt.POutput, *wire.TxOut, error) {
	// The full script key derivation information is not serialized in the
	// output asset leaf, so we need to set the information on the virtual
	// output.
	pOut := serializeTweakedScriptKey(
		o.ScriptKey.TweakedScriptKey, coinType,
	)

	if o.Amount > math.MaxInt64 {
		return pOut, nil, fmt.Errorf("output amount exceeds maximum " +
			"value")
	}

	if o.ScriptKey.PubKey == nil {
		return pOut, nil, fmt.Errorf("output script key is required")
	}

	// Before we start with any fields that need to go into the Unknowns
	// slice, we add the information that we can stuff into the wire TX or
	// existing PSBT fields.
	assetPkScript, err := payToTaprootScript(o.ScriptKey.PubKey)
	if err != nil {
		return pOut, nil, fmt.Errorf("error creating asset taproot "+
			"script: %w", err)
	}
	txOut := &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: assetPkScript,
	}

	anchorOutputIndex := uint64(o.AnchorOutputIndex)
	mapping := []encoderMapping{
		{
			key:     PsbtKeyTypeOutputTapType,
			encoder: tlvEncoder(&o.Type, vOutputTypeEncoder),
		},
		{
			key:     PsbtKeyTypeOutputTapIsInteractive,
			encoder: booleanEncoder(o.Interactive),
		},
		{
			key:     PsbtKeyTypeOutputTapAnchorOutputIndex,
			encoder: tlvEncoder(&anchorOutputIndex, tlv.EUint64),
		},
		{
			key:     PsbtKeyTypeOutputTapAnchorOutputInternalKey,
			encoder: pubKeyEncoder(o.AnchorOutputInternalKey),
		},
		{
			key: PsbtKeyTypeOutputTapAnchorOutputBip32Derivation,
			encoder: bip32DerivationEncoder(
				o.AnchorOutputBip32Derivation,
			),
		},
		{
			//nolint:lll
			key: PsbtKeyTypeOutputTapAnchorOutputTaprootBip32Derivation,
			encoder: taprootBip32DerivationEncoder(
				o.AnchorOutputTaprootBip32Derivation,
			),
		},
		{
			key:     PsbtKeyTypeOutputTapAsset,
			encoder: assetEncoder(o.Asset),
		},
		{
			key:     PsbtKeyTypeOutputTapSplitAsset,
			encoder: assetEncoder(o.SplitAsset),
		},
		{
			key: PsbtKeyTypeOutputTapAnchorTapscriptSibling,
			encoder: tapscriptPreimageEncoder(
				o.AnchorOutputTapscriptSibling,
			),
		},
		{
			key: PsbtKeyTypeOutputTapAssetVersion,
			encoder: tlvEncoder(
				&o.AssetVersion, vOutputAssetVersionEncoder,
			),
		},
		{
			key:     PsbtKeyTypeOutputTapProofDeliveryAddress,
			encoder: urlEncoder(o.ProofDeliveryAddress),
		},
		{
			key:     PsbtKeyTypeOutputTapAssetProofSuffix,
			encoder: proofEncoder(o.ProofSuffix),
		},
	}

	for idx := range mapping {
		customFields, err := mapping[idx].encoder(mapping[idx].key)
		if err != nil {
			return pOut, nil, fmt.Errorf("error encoding input "+
				"key %x: %w", mapping[idx].key, err)
		}

		if len(customFields) > 0 {
			pOut.Unknowns = append(pOut.Unknowns, customFields...)
		}
	}

	return pOut, txOut, nil
}

// tlvEncoder returns a function that encodes the given value using the given TLV
// tlvEncoder.
func tlvEncoder(val any, enc tlv.Encoder) encoderFunc {
	return func(key []byte) ([]*customPsbtField, error) {
		if val == nil {
			return nil, nil
		}

		var (
			b       bytes.Buffer
			scratch [8]byte
		)
		if err := enc(&b, val, &scratch); err != nil {
			return nil, fmt.Errorf("error encoding TLV record: %w",
				err)
		}

		return []*customPsbtField{
			{
				Key:   fn.CopySlice(key),
				Value: b.Bytes(),
			},
		}, nil
	}
}

// pubKeyEncoder is an encoder that does nothing if the given public key is nil.
func pubKeyEncoder(pubKey *btcec.PublicKey) encoderFunc {
	if pubKey == nil {
		return func([]byte) ([]*customPsbtField, error) {
			return nil, nil
		}
	}

	return tlvEncoder(&pubKey, tlv.EPubKey)
}

// proofEncoder is an encoder that does nothing if the given proof is nil.
func proofEncoder(p *proof.Proof) encoderFunc {
	return func(key []byte) ([]*customPsbtField, error) {
		if p == nil {
			return nil, nil
		}

		var buf bytes.Buffer
		err := p.Encode(&buf)
		if err != nil {
			return nil, err
		}

		return []*customPsbtField{
			{
				Key:   fn.CopySlice(key),
				Value: buf.Bytes(),
			},
		}, nil
	}
}

// assetEncoder is an encoder that does nothing if the given asset is nil.
func assetEncoder(a *asset.Asset) encoderFunc {
	if a == nil {
		return func([]byte) ([]*customPsbtField, error) {
			return nil, nil
		}
	}

	return tlvEncoder(a, asset.LeafEncoder)
}

// booleanEncoder returns a function that encodes the given boolean value as a
// byte slice.
func booleanEncoder(val bool) encoderFunc {
	return func(key []byte) ([]*customPsbtField, error) {
		unknown := &customPsbtField{
			Key:   fn.CopySlice(key),
			Value: fn.CopySlice(falseAsBytes),
		}
		if val {
			unknown.Value = fn.CopySlice(trueAsBytes)
		}

		return []*customPsbtField{unknown}, nil
	}
}

// bip32DerivationEncoder returns a function that encodes the given bip32
// derivation.
func bip32DerivationEncoder(derivations []*psbt.Bip32Derivation) encoderFunc {
	return func(key []byte) ([]*customPsbtField, error) {
		if derivations == nil {
			return nil, nil
		}

		unknowns := make([]*customPsbtField, len(derivations))
		for idx := range derivations {
			d := derivations[idx]

			keyCopy := fn.CopySlice(key)
			unknowns[idx] = &customPsbtField{
				Key: append(keyCopy, d.PubKey...),
				Value: psbt.SerializeBIP32Derivation(
					d.MasterKeyFingerprint, d.Bip32Path,
				),
			}
		}

		return unknowns, nil
	}
}

// taprootBip32DerivationEncoder returns a function that encodes the given
// taproot bip32 derivation.
func taprootBip32DerivationEncoder(
	derivations []*psbt.TaprootBip32Derivation) encoderFunc {

	return func(key []byte) ([]*customPsbtField, error) {
		if derivations == nil {
			return nil, nil
		}

		unknowns := make([]*customPsbtField, len(derivations))
		for idx := range derivations {
			d := derivations[idx]
			value, err := psbt.SerializeTaprootBip32Derivation(d)
			if err != nil {
				return nil, err
			}

			keyCopy := fn.CopySlice(key)
			unknowns[idx] = &customPsbtField{
				Key:   append(keyCopy, d.XOnlyPubKey...),
				Value: value,
			}
		}

		return unknowns, nil
	}
}

// tapscriptPreimageEncoder is an encoder that does nothing if the given
// preimage is nil.
func tapscriptPreimageEncoder(t *commitment.TapscriptPreimage) encoderFunc {
	if t == nil {
		return func(key []byte) ([]*customPsbtField, error) {
			return nil, nil
		}
	}

	return tlvEncoder(&t, commitment.TapscriptPreimageEncoder)
}

// payToTaprootScript creates a pk script for a pay-to-taproot output key. We
// create a copy of the tapscript.PayToTaprootScript function here to avoid a
// circular dependency.
func payToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

// vOutputTypeEncoder is a TLV encoder that encodes the given VOutputType to the
// given writer.
func vOutputTypeEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*VOutputType); ok {
		num := uint8(*t)
		return tlv.EUint8T(w, num, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "VOutputType")
}

// vOutputAssetVersionEncoder is a TLV encoder that encodes the given asset
// version to the given writer.
func vOutputAssetVersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*asset.Version); ok {
		num := uint8(*t)
		return tlv.EUint8T(w, num, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "VOutputAssetVersion")
}

// urlEncoder returns a function that encodes the given URL as a custom PSBT
// field.
func urlEncoder(val *url.URL) encoderFunc {
	return func(key []byte) ([]*customPsbtField, error) {
		if val == nil {
			return nil, nil
		}

		var (
			b       bytes.Buffer
			scratch [8]byte
		)
		if err := address.UrlEncoder(&b, val, &scratch); err != nil {
			return nil, fmt.Errorf("error encoding TLV record: %w",
				err)
		}

		return []*customPsbtField{
			{
				Key:   fn.CopySlice(key),
				Value: b.Bytes(),
			},
		}, nil
	}
}
