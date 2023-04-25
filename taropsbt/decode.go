package taropsbt

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrKeyNotFound is returned when a key is not found among the unknown
	// fields of a packet.
	ErrKeyNotFound = errors.New("taropsbt: key not found")
)

// decoderFunc is a function type for decoding a virtual PSBT item from a byte
// slice key and value.
type decoderFunc func(key, byteVal []byte) error

// decoderMapping maps a PSBT key to a decoder function.
type decoderMapping struct {
	key     []byte
	decoder decoderFunc
}

// NewFromRawBytes returns a new instance of a VPacket struct created by reading
// from a byte slice. If the format is invalid, an error is returned. If the
// argument b64 is true, the passed byte slice is decoded from base64 encoding
// before processing.
func NewFromRawBytes(r io.Reader, b64 bool) (*VPacket, error) {
	packet, err := psbt.NewFromRawBytes(r, b64)
	if err != nil {
		return nil, fmt.Errorf("error decoding PSBT: %w", err)
	}

	return NewFromPsbt(packet)
}

// NewFromPsbt returns a new instance of a VPacket struct created by reading the
// custom fields on the given PSBT packet.
func NewFromPsbt(packet *psbt.Packet) (*VPacket, error) {
	// Make sure we have the correct markers for a virtual transaction.
	if len(packet.Unknowns) != 3 {
		return nil, fmt.Errorf("expected 3 global unknown fields, "+
			"got %d", len(packet.Unknowns))
	}

	// We want an explicit "isVirtual" boolean marker.
	isVirtual, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTaroIsVirtualTx,
	)
	if err != nil {
		return nil, fmt.Errorf("error checking if virtual tx: %w", err)
	}
	if !bytes.Equal(isVirtual.Value, trueAsBytes) {
		return nil, fmt.Errorf("not a virtual transaction")
	}

	// We also want the HRP of the Taro chain params.
	hrp, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTaroChainParamsHRP,
	)
	if err != nil {
		return nil, fmt.Errorf("error reading Taro chain params HRP: "+
			"%w", err)
	}
	chainParams, err := address.Net(string(hrp.Value))
	if err != nil {
		return nil, fmt.Errorf("error parsing Taro chain params HRP: "+
			"%w", err)
	}

	// The version is currently optional, as it's not used anywhere.
	var version uint8
	versionField, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTaroPsbtVersion,
	)
	if err == nil {
		version = versionField.Value[0]
	}

	vPkt := &VPacket{
		Version:     version,
		ChainParams: chainParams,
		Inputs:      make([]*VInput, len(packet.Inputs)),
		Outputs:     make([]*VOutput, len(packet.Outputs)),
	}

	for idx := range packet.Inputs {
		vIn := &VInput{}
		err = vIn.decode(packet.Inputs[idx])
		if err != nil {
			return nil, fmt.Errorf("error decoding virtual input "+
				"%d: %w", idx, err)
		}

		vPkt.Inputs[idx] = vIn
	}

	for idx := range packet.Outputs {
		vOut := &VOutput{}
		err = vOut.decode(
			packet.Outputs[idx], packet.UnsignedTx.TxOut[idx],
		)
		if err != nil {
			return nil, fmt.Errorf("error decoding virtual output "+
				"%d: %w", idx, err)
		}

		vPkt.Outputs[idx] = vOut
	}

	return vPkt, nil
}

// decode decodes the given PInput into the current VInput.
func (i *VInput) decode(pIn psbt.PInput) error {
	i.PInput = pIn

	var (
		prevID            *asset.PrevID
		anchorValue       uint64
		anchorSigHashType uint64
	)

	mapping := []decoderMapping{{
		key:     PsbtKeyTypeInputTaroPrevID,
		decoder: tlvDecoder(&prevID, asset.PrevIDDecoder),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorValue,
		decoder: tlvDecoder(&anchorValue, tlv.DUint64),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorPkScript,
		decoder: tlvDecoder(&i.Anchor.PkScript, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorSigHashType,
		decoder: tlvDecoder(&anchorSigHashType, tlv.DUint64),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorInternalKey,
		decoder: tlvDecoder(&i.Anchor.InternalKey, tlv.DPubKey),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorMerkleRoot,
		decoder: tlvDecoder(&i.Anchor.MerkleRoot, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorOutputBip32Derivation,
		decoder: bip32DerivationDecoder(&i.Anchor.Bip32Derivation),
	}, {
		key: PsbtKeyTypeInputTaroAnchorOutputTaprootBip32Derivation,
		decoder: taprootBip32DerivationDecoder(
			&i.Anchor.TrBip32Derivation,
		),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorTapscriptSibling,
		decoder: tlvDecoder(&i.Anchor.TapscriptSibling, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTaroAsset,
		decoder: assetDecoder(&i.asset),
	}, {
		key:     PsbtKeyTypeInputTaroAssetProof,
		decoder: tlvDecoder(&i.proof, tlv.DVarBytes),
	}}

	for idx := range mapping {
		unknown, err := findCustomFieldsByKeyPrefix(
			i.Unknowns, mapping[idx].key,
		)

		// Some value are optional.
		if errors.Is(err, ErrKeyNotFound) || len(unknown.Value) == 0 {
			continue
		}

		err = mapping[idx].decoder(unknown.Key, unknown.Value)
		if err != nil {
			return fmt.Errorf("error decoding input key %x: %w",
				mapping[idx].key, err)
		}
	}

	// For some fields an intermediate step was required, copy them over
	// into their target type now.
	if prevID != nil {
		i.PrevID = *prevID
	}
	i.Anchor.Value = btcutil.Amount(anchorValue)
	i.Anchor.SigHashType = txscript.SigHashType(anchorSigHashType)

	// The asset leaf encoding doesn't store the full script key info, only
	// the top level Taproot key. In order to be able to sign for it, we
	// need all the info populated properly.
	if err := i.deserializeScriptKey(); err != nil {
		return err
	}
	i.Unknowns = nil

	return nil
}

// decode decodes the given POutput and wire.TxOut into the current VOutput.
func (o *VOutput) decode(pOut psbt.POutput, txOut *wire.TxOut) error {
	o.Amount = uint64(txOut.Value)

	if len(txOut.PkScript) != schnorr.PubKeyBytesLen+2 {
		return fmt.Errorf("expected %d bytes for taproot pkScript, "+
			"got %d", schnorr.PubKeyBytesLen+2, len(txOut.PkScript))
	}
	scriptKey, err := schnorr.ParsePubKey(txOut.PkScript[2:])
	if err != nil {
		return fmt.Errorf("error parsing taproot script key: %w", err)
	}

	o.ScriptKey = asset.ScriptKey{
		PubKey: scriptKey,
	}
	o.ScriptKey.TweakedScriptKey, err = deserializeTweakedScriptKey(pOut)
	if err != nil {
		return fmt.Errorf("error deserializing tweaked script key: %w",
			err)
	}

	anchorOutputIndex := uint64(o.AnchorOutputIndex)
	mapping := []decoderMapping{{
		key:     PsbtKeyTypeOutputTaroIsSplitRoot,
		decoder: booleanDecoder(&o.IsSplitRoot),
	}, {
		key:     PsbtKeyTypeOutputTaroIsInteractive,
		decoder: booleanDecoder(&o.Interactive),
	}, {
		key:     PsbtKeyTypeOutputTaroAnchorOutputIndex,
		decoder: tlvDecoder(&anchorOutputIndex, tlv.DUint64),
	}, {
		key:     PsbtKeyTypeOutputTaroAnchorOutputInternalKey,
		decoder: tlvDecoder(&o.AnchorOutputInternalKey, tlv.DPubKey),
	}, {
		key:     PsbtKeyTypeOutputTaroAnchorOutputBip32Derivation,
		decoder: bip32DerivationDecoder(&o.AnchorOutputBip32Derivation),
	}, {
		key: PsbtKeyTypeOutputTaroAnchorOutputTaprootBip32Derivation,
		decoder: taprootBip32DerivationDecoder(
			&o.AnchorOutputTaprootBip32Derivation,
		),
	}, {
		key:     PsbtKeyTypeOutputTaroAsset,
		decoder: assetDecoder(&o.Asset),
	}, {
		key:     PsbtKeyTypeOutputTaroSplitAsset,
		decoder: assetDecoder(&o.SplitAsset),
	}, {
		key: PsbtKeyTypeOutputTaroAnchorTapscriptPreimage,
		decoder: tlvDecoder(
			&o.AnchorOutputTapscriptPreimage,
			commitment.TapscriptPreimageDecoder,
		),
	}}

	for idx := range mapping {
		unknown, err := findCustomFieldsByKeyPrefix(
			pOut.Unknowns, mapping[idx].key,
		)

		// Some value are optional.
		if errors.Is(err, ErrKeyNotFound) || len(unknown.Value) == 0 {
			continue
		}

		err = mapping[idx].decoder(unknown.Key, unknown.Value)
		if err != nil {
			return fmt.Errorf("error decoding output key %x: %w",
				mapping[idx].key, err)
		}
	}

	// For some fields an intermediate step was required, copy them over
	// into their target type now.
	o.AnchorOutputIndex = uint32(anchorOutputIndex)

	return nil
}

// tlvDecoder returns a function that encodes the given byte slice using the
// given TLV tlvDecoder.
func tlvDecoder(val any, dec tlv.Decoder) decoderFunc {
	return func(_, byteVal []byte) error {
		var (
			r       = bytes.NewReader(byteVal)
			l       = uint64(len(byteVal))
			scratch [8]byte
		)
		if err := dec(r, val, &scratch, l); err != nil {
			return fmt.Errorf("error decoding TLV: %w", err)
		}

		return nil
	}
}

// assetDecoder returns a decoder function that can handle nil assets.
func assetDecoder(a **asset.Asset) decoderFunc {
	return func(key, byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		if *a == nil {
			*a = &asset.Asset{}
		}
		return tlvDecoder(*a, asset.LeafDecoder)(key, byteVal)
	}
}

// booleanDecoder returns a function that decodes the given byte slice as a
// boolean.
func booleanDecoder(target *bool) decoderFunc {
	return func(_, byteVal []byte) error {
		*target = bytes.Equal(byteVal, trueAsBytes)

		return nil
	}
}

// bip32DerivationDecoder returns a function that decodes the given bip32
// derivation.
func bip32DerivationDecoder(target *[]*psbt.Bip32Derivation) decoderFunc {
	return func(key, byteVal []byte) error {
		// Make sure the public key encoded in the key itself (directly
		// following the one byte key type) is a valid 33-byte
		// compressed public key.
		if len(key) != btcec.PubKeyBytesLenCompressed+1 {
			return fmt.Errorf("invalid key length for bip32 " +
				"derivation")
		}
		_, err := btcec.ParsePubKey(key[1:])
		if err != nil {
			return fmt.Errorf("invalid public key for bip32 "+
				"derivation: %w", err)
		}

		master, derivationPath, err := psbt.ReadBip32Derivation(
			byteVal,
		)
		if err != nil {
			return err
		}

		*target = append(*target, &psbt.Bip32Derivation{
			PubKey:               key[1:],
			MasterKeyFingerprint: master,
			Bip32Path:            derivationPath,
		})

		return nil
	}
}

// taprootBip32DerivationDecoder returns a function that decodes the given
// taproot bip32 derivation.
func taprootBip32DerivationDecoder(
	target *[]*psbt.TaprootBip32Derivation) decoderFunc {

	return func(key, byteVal []byte) error {
		// Make sure the public key encoded in the key itself (directly
		// following the one byte key type) is a valid 32-byte x-only
		// public key.
		if len(key) != schnorr.PubKeyBytesLen+1 {
			return fmt.Errorf("invalid key length for taproot " +
				"bip32 derivation")
		}
		_, err := schnorr.ParsePubKey(key[1:])
		if err != nil {
			return fmt.Errorf("invalid public key for taproot "+
				"bip32 derivation: %w", err)
		}

		derivation, err := psbt.ReadTaprootBip32Derivation(
			key[1:], byteVal,
		)
		if err != nil {
			return err
		}

		*target = append(*target, derivation)

		return nil
	}
}

// findCustomFieldsByKeyPrefix is a helper function that finds a custom field in
// the list of custom fields by the key type prefix. If the key is not found, an
// error is returned.
func findCustomFieldsByKeyPrefix(customFields []*customPsbtField,
	keyPrefix []byte) (*customPsbtField, error) {

	for _, customField := range customFields {
		if bytes.HasPrefix(customField.Key, keyPrefix) {
			return customField, nil
		}
	}

	return nil, fmt.Errorf("%w: key %x not found in list of unkonwns",
		ErrKeyNotFound, keyPrefix)
}
