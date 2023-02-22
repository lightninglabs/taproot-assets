package taropsbt

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrKeyNotFound is returned when a key is not found among the unknown
	// fields of a packet.
	ErrKeyNotFound = errors.New("taropsbt: key not found")
)

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
	if len(packet.Unknowns) != 2 {
		return nil, fmt.Errorf("expected 2 global unknown fields, "+
			"got %d", len(packet.Unknowns))
	}

	// We want an explicit "isVirtual" boolean marker.
	isVirtual, err := value(
		packet.Unknowns, PsbtKeyTypeGlobalTaroIsVirtualTx,
	)
	if err != nil {
		return nil, fmt.Errorf("error checking if virtual tx: %w", err)
	}
	if !bytes.Equal(isVirtual, trueAsBytes) {
		return nil, fmt.Errorf("not a virtual transaction")
	}

	// We also want the HRP of the Taro chain params.
	hrp, err := value(packet.Unknowns, PsbtKeyTypeGlobalTaroChainParamsHRP)
	if err != nil {
		return nil, fmt.Errorf("error reading Taro chain params HRP: "+
			"%w", err)
	}
	chainParams, err := address.Net(string(hrp))
	if err != nil {
		return nil, fmt.Errorf("error parsing Taro chain params HRP: "+
			"%w", err)
	}

	vPkt := &VPacket{
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

	mapping := []struct {
		key     []byte
		decoder func([]byte) error
	}{{
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
		key: PsbtKeyTypeInputTaroAnchorOutputBip32Derivation,
		decoder: func(byteVal []byte) error {
			master, derivationPath, err := psbt.ReadBip32Derivation(
				byteVal,
			)
			if err != nil {
				return err
			}

			i.Anchor.Bip32Derivation = &psbt.Bip32Derivation{
				MasterKeyFingerprint: master,
				Bip32Path:            derivationPath,
			}

			return nil
		},
	}, {
		key: PsbtKeyTypeInputTaroAnchorOutputTaprootBip32Derivation,
		decoder: func(byteVal []byte) error {
			derivation, err := psbt.ReadTaprootBip32Derivation(
				nil, byteVal,
			)
			if err != nil {
				return err
			}

			i.Anchor.TrBip32Derivation = derivation

			return nil
		},
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
		byteValue, err := value(i.Unknowns, mapping[idx].key)

		// Some value are optional.
		if errors.Is(err, ErrKeyNotFound) || len(byteValue) == 0 {
			continue
		}

		err = mapping[idx].decoder(byteValue)
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

	// The actual pubKey isn't serialized together with the derivation path,
	// and is therefore not de-serialized either. So we set it manually here
	// in case some code relies on it being set (even though we already
	// have the key in the internal key field).
	if i.Anchor.InternalKey != nil {
		pubKeyBytes := i.Anchor.InternalKey.SerializeCompressed()
		sPK := pubKeyBytes[1:]
		if i.Anchor.Bip32Derivation != nil {
			i.Anchor.Bip32Derivation.PubKey = pubKeyBytes
		}
		if i.Anchor.TrBip32Derivation != nil {
			i.Anchor.TrBip32Derivation.XOnlyPubKey = sPK
		}
	}

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
	mapping := []struct {
		key     []byte
		decoder func([]byte) error
	}{{
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
		key: PsbtKeyTypeOutputTaroAnchorOutputBip32Derivation,
		decoder: func(byteVal []byte) error {
			master, derivationPath, err := psbt.ReadBip32Derivation(
				byteVal,
			)
			if err != nil {
				return err
			}

			o.AnchorOutputBip32Derivation = &psbt.Bip32Derivation{
				MasterKeyFingerprint: master,
				Bip32Path:            derivationPath,
			}

			return nil
		},
	}, {
		key: PsbtKeyTypeOutputTaroAnchorOutputTaprootBip32Derivation,
		decoder: func(byteVal []byte) error {
			derivation, err := psbt.ReadTaprootBip32Derivation(
				nil, byteVal,
			)
			if err != nil {
				return err
			}

			o.AnchorOutputTaprootBip32Derivation = derivation

			return nil
		},
	}, {
		key:     PsbtKeyTypeOutputTaroAsset,
		decoder: assetDecoder(&o.Asset),
	}, {
		key:     PsbtKeyTypeOutputTaroSplitAsset,
		decoder: assetDecoder(&o.SplitAsset),
	}}

	for idx := range mapping {
		byteValue, err := value(pOut.Unknowns, mapping[idx].key)

		// Some value are optional.
		if errors.Is(err, ErrKeyNotFound) || len(byteValue) == 0 {
			continue
		}

		err = mapping[idx].decoder(byteValue)
		if err != nil {
			return fmt.Errorf("error decoding output key %x: %w",
				mapping[idx].key, err)
		}
	}

	// For some fields an intermediate step was required, copy them over
	// into their target type now.
	o.AnchorOutputIndex = uint32(anchorOutputIndex)
	if o.AnchorOutputInternalKey != nil {
		pubKeyBytes := o.AnchorOutputInternalKey.SerializeCompressed()
		sPK := pubKeyBytes[1:]
		if o.AnchorOutputBip32Derivation != nil {
			o.AnchorOutputBip32Derivation.PubKey = pubKeyBytes
		}
		if o.AnchorOutputTaprootBip32Derivation != nil {
			o.AnchorOutputTaprootBip32Derivation.XOnlyPubKey = sPK
		}
	}

	return nil
}

// tlvDecoder returns a function that encodes the given byte slice using the
// given TLV tlvDecoder.
func tlvDecoder(val any, dec tlv.Decoder) func([]byte) error {
	return func(byteVal []byte) error {
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
func assetDecoder(a **asset.Asset) func([]byte) error {
	return func(byteVal []byte) error {
		if len(byteVal) == 0 {
			return nil
		}

		if *a == nil {
			*a = &asset.Asset{}
		}
		return tlvDecoder(*a, asset.LeafDecoder)(byteVal)
	}
}

// booleanDecoder returns a function that decodes the given byte slice as a
// boolean.
func booleanDecoder(target *bool) func([]byte) error {
	return func(byteVal []byte) error {
		*target = bytes.Equal(byteVal, trueAsBytes)

		return nil
	}
}

// value is a helper function that returns the value of the given key in the
// list of unknowns. If the key is not found, an error is returned.
func value(unknowns []*psbt.Unknown, key []byte) ([]byte, error) {
	for _, unknown := range unknowns {
		if bytes.Equal(unknown.Key, key) {
			return unknown.Value, nil
		}
	}

	return nil, fmt.Errorf("%w: key %x not found in list of unkonwns",
		ErrKeyNotFound, key)
}
