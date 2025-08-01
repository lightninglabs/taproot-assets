package tappsbt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrKeyNotFound is returned when a key is not found among the unknown
	// fields of a packet.
	ErrKeyNotFound = errors.New("tappsbt: key not found")
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
	// We want an explicit "isVirtual" boolean marker.
	isVirtual, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTapIsVirtualTx,
	)
	if err != nil {
		return nil, fmt.Errorf("error checking if virtual tx: %w", err)
	}
	if !bytes.Equal(isVirtual.Value, trueAsBytes) {
		return nil, fmt.Errorf("not a virtual transaction")
	}

	// We also want the HRP of the Taproot Asset chain params.
	hrp, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTapChainParamsHRP,
	)
	if err != nil {
		return nil, fmt.Errorf("error reading Taproot asset chain "+
			"params HRP: %w", err)
	}
	chainParams, err := address.Net(string(hrp.Value))
	if err != nil {
		return nil, fmt.Errorf("error parsing Taproot Asset chain "+
			"params HRP: %w", err)
	}

	// We also need the VPacket version.
	versionField, err := findCustomFieldsByKeyPrefix(
		packet.Unknowns, PsbtKeyTypeGlobalTapPsbtVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("error finding virtual tx version: %w",
			err)
	}

	version := versionField.Value[0]
	switch version {
	case uint8(V0), uint8(V1):
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidVPacketVersion,
			version)
	}

	vPkt := &VPacket{
		Version:     VPacketVersion(version),
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
			chainParams,
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
		key:     PsbtKeyTypeInputTapPrevID,
		decoder: tlvDecoder(&prevID, asset.PrevIDDecoder),
	}, {
		key:     PsbtKeyTypeInputTapAnchorValue,
		decoder: tlvDecoder(&anchorValue, tlv.DUint64),
	}, {
		key:     PsbtKeyTypeInputTapAnchorPkScript,
		decoder: tlvDecoder(&i.Anchor.PkScript, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTapAnchorSigHashType,
		decoder: tlvDecoder(&anchorSigHashType, tlv.DUint64),
	}, {
		key:     PsbtKeyTypeInputTapAnchorInternalKey,
		decoder: tlvDecoder(&i.Anchor.InternalKey, tlv.DPubKey),
	}, {
		key:     PsbtKeyTypeInputTapAnchorMerkleRoot,
		decoder: tlvDecoder(&i.Anchor.MerkleRoot, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTapAnchorOutputBip32Derivation,
		decoder: bip32DerivationDecoder(&i.Anchor.Bip32Derivation),
	}, {
		key: PsbtKeyTypeInputTapAnchorOutputTaprootBip32Derivation,
		decoder: taprootBip32DerivationDecoder(
			&i.Anchor.TrBip32Derivation,
		),
	}, {
		key:     PsbtKeyTypeInputTapAnchorTapscriptSibling,
		decoder: tlvDecoder(&i.Anchor.TapscriptSibling, tlv.DVarBytes),
	}, {
		key:     PsbtKeyTypeInputTapAsset,
		decoder: assetDecoder(&i.asset),
	}, {
		key:     PsbtKeyTypeInputTapAssetProof,
		decoder: proofDecoder(&i.Proof),
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
func (o *VOutput) decode(pOut psbt.POutput, txOut *wire.TxOut,
	chainParams *address.ChainParams) error {

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
	mapping := []decoderMapping{
		{
			key:     PsbtKeyTypeOutputTapType,
			decoder: tlvDecoder(&o.Type, vOutputTypeDecoder),
		},
		{
			key:     PsbtKeyTypeOutputTapIsInteractive,
			decoder: booleanDecoder(&o.Interactive),
		},
		{
			key:     PsbtKeyTypeOutputTapAnchorOutputIndex,
			decoder: tlvDecoder(&anchorOutputIndex, tlv.DUint64),
		},
		{
			key: PsbtKeyTypeOutputTapAnchorOutputInternalKey,
			decoder: tlvDecoder(
				&o.AnchorOutputInternalKey, tlv.DPubKey,
			),
		},
		{
			key: PsbtKeyTypeOutputTapAnchorOutputBip32Derivation,
			decoder: bip32DerivationDecoder(
				&o.AnchorOutputBip32Derivation,
			),
		},
		{
			//nolint:lll
			key: PsbtKeyTypeOutputTapAnchorOutputTaprootBip32Derivation,
			decoder: taprootBip32DerivationDecoder(
				&o.AnchorOutputTaprootBip32Derivation,
			),
		},
		{
			key:     PsbtKeyTypeOutputTapAsset,
			decoder: assetDecoder(&o.Asset),
		},
		{
			key:     PsbtKeyTypeOutputTapSplitAsset,
			decoder: assetDecoder(&o.SplitAsset),
		},
		{
			key: PsbtKeyTypeOutputTapAnchorTapscriptSibling,
			decoder: tlvDecoder(
				&o.AnchorOutputTapscriptSibling,
				commitment.TapscriptPreimageDecoder,
			),
		},
		{
			key: PsbtKeyTypeOutputTapAssetVersion,
			decoder: tlvDecoder(
				&o.AssetVersion, vOutputAssetVersionDecoder,
			),
		},
		{
			key:     PsbtKeyTypeOutputTapProofDeliveryAddress,
			decoder: urlDecoder(&o.ProofDeliveryAddress),
		},
		{
			key:     PsbtKeyTypeOutputTapAssetProofSuffix,
			decoder: proofDecoder(&o.ProofSuffix),
		},
		{
			key:     PsbtKeyTypeOutputTapAssetLockTime,
			decoder: tlvDecoder(&o.LockTime, tlv.DUint64),
		},
		{
			key:     PsbtKeyTypeOutputTapAssetRelativeLockTime,
			decoder: tlvDecoder(&o.RelativeLockTime, tlv.DUint64),
		}, {
			key:     PsbtKeyTypeOutputTapAltLeaves,
			decoder: altLeavesDecoder(&o.AltLeaves),
		}, {
			key:     PsbtKeyTypeOutputTapAddress,
			decoder: addressDecoder(&o.Address, chainParams),
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

// tlvDecoder returns a function that decodes the given byte slice using the
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

// proofDecoder returns a decoder function that can handle nil proofs.
func proofDecoder(p **proof.Proof) decoderFunc {
	return func(key, byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		if *p == nil {
			*p = &proof.Proof{}
		}
		return (*p).Decode(bytes.NewReader(byteVal))
	}
}

// altLeavesDecoder returns a decoder function that can handle nil alt leaves.
func altLeavesDecoder(a *[]asset.AltLeaf[asset.Asset]) decoderFunc {
	return func(key, byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		return tlvDecoder(a, asset.AltLeavesDecoder)(key, byteVal)
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

	return nil, fmt.Errorf("%w: key %x not found in list of unknowns",
		ErrKeyNotFound, keyPrefix)
}

// vOutputTypeDecoder is a TLV decoder function that decodes from the given
// reader into a VOutputType.
func vOutputTypeDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*VOutputType); ok {
		var num uint8
		err := tlv.DUint8(r, &num, buf, l)
		if err != nil {
			return err
		}
		*typ = VOutputType(num)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "VOutputType", 8, l)
}

// vOutputAssetVersionDecoder is a TLV decoder function that decodes from the
// given reader into an asset version.
func vOutputAssetVersionDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	if typ, ok := val.(*asset.Version); ok {
		var num uint8
		err := tlv.DUint8(r, &num, buf, l)
		if err != nil {
			return err
		}
		*typ = asset.Version(num)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "VOutputAssetVersion", 8, l)
}

// urlDecoder returns a decoder function that can handle nil URLs.
func urlDecoder(u **url.URL) decoderFunc {
	return func(key, byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		if *u == nil {
			*u = &url.URL{}
		}
		return tlvDecoder(*u, asset.UrlDecoder)(key, byteVal)
	}
}

// addressDecoder returns a decoder function that can handle nil Taproot
// addresses.
func addressDecoder(a **address.Tap,
	chainParams *address.ChainParams) decoderFunc {

	return func(key, byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		addr := address.Tap{
			ChainParams: chainParams,
		}
		err := addr.Decode(bytes.NewReader(byteVal))
		if err != nil {
			return fmt.Errorf("error decoding Taproot address: %w",
				err)
		}

		*a = &addr

		return nil
	}
}
