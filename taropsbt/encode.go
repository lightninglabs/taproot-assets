package taropsbt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
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
		Unknowns: []*psbt.Unknown{
			{
				Key:   PsbtKeyTypeGlobalTaroIsVirtualTx,
				Value: trueAsBytes,
			},
			{
				Key:   PsbtKeyTypeGlobalTaroChainParamsHRP,
				Value: []byte(p.ChainParams.TaroHRP),
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

	mapping := []struct {
		key     []byte
		encoder func() ([]byte, error)
	}{{
		key:     PsbtKeyTypeInputTaroPrevID,
		encoder: tlvEncoder(&prevID, asset.PrevIDEncoder),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorValue,
		encoder: tlvEncoder(&anchorValue, tlv.EUint64),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorPkScript,
		encoder: tlvEncoder(&i.Anchor.PkScript, tlv.EVarBytes),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorSigHashType,
		encoder: tlvEncoder(&sigHashType, tlv.EUint64),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorInternalKey,
		encoder: pubKeyEncoder(i.Anchor.InternalKey),
	}, {
		key:     PsbtKeyTypeInputTaroAnchorMerkleRoot,
		encoder: tlvEncoder(&i.Anchor.MerkleRoot, tlv.EVarBytes),
	}, {
		key: PsbtKeyTypeInputTaroAnchorOutputBip32Derivation,
		encoder: func() ([]byte, error) {
			derivation := i.Anchor.Bip32Derivation
			if derivation == nil {
				return nil, nil
			}

			return psbt.SerializeBIP32Derivation(
				derivation.MasterKeyFingerprint,
				derivation.Bip32Path,
			), nil
		},
	}, {
		key: PsbtKeyTypeInputTaroAnchorOutputTaprootBip32Derivation,
		encoder: func() ([]byte, error) {
			derivation := i.Anchor.TrBip32Derivation
			if derivation == nil {
				return nil, nil
			}

			return psbt.SerializeTaprootBip32Derivation(
				derivation,
			)
		},
	}, {
		key:     PsbtKeyTypeInputTaroAnchorTapscriptSibling,
		encoder: tlvEncoder(&i.Anchor.TapscriptSibling, tlv.EVarBytes),
	}, {
		key:     PsbtKeyTypeInputTaroAsset,
		encoder: assetEncoder(i.asset),
	}, {
		key:     PsbtKeyTypeInputTaroAssetProof,
		encoder: tlvEncoder(&i.proof, tlv.EVarBytes),
	}}

	for idx := range mapping {
		value, err := mapping[idx].encoder()
		if err != nil {
			return pIn, fmt.Errorf("error encoding input key %x: "+
				"%w", mapping[idx].key, err)
		}

		if value != nil {
			pIn.Unknowns = append(pIn.Unknowns, &psbt.Unknown{
				Key:   mapping[idx].key,
				Value: value,
			})
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

	// Before we start with any fields that need to go into the Unknowns
	// slice, we add the information that we can stuff into the wire TX or
	// existing PSBT fields.
	taroPkScript, err := payToTaprootScript(o.ScriptKey.PubKey)
	if err != nil {
		return pOut, nil, fmt.Errorf("error creating asset taproot "+
			"script: %w", err)
	}
	txOut := &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: taroPkScript,
	}

	anchorOutputIndex := uint64(o.AnchorOutputIndex)
	mapping := []struct {
		key     []byte
		encoder func() ([]byte, error)
	}{{
		key:     PsbtKeyTypeOutputTaroIsSplitRoot,
		encoder: booleanEncoder(o.IsSplitRoot),
	}, {
		key:     PsbtKeyTypeOutputTaroIsInteractive,
		encoder: booleanEncoder(o.Interactive),
	}, {
		key:     PsbtKeyTypeOutputTaroAnchorOutputIndex,
		encoder: tlvEncoder(&anchorOutputIndex, tlv.EUint64),
	}, {
		key:     PsbtKeyTypeOutputTaroAnchorOutputInternalKey,
		encoder: pubKeyEncoder(o.AnchorOutputInternalKey),
	}, {
		key: PsbtKeyTypeOutputTaroAnchorOutputBip32Derivation,
		encoder: func() ([]byte, error) {
			derivation := o.AnchorOutputBip32Derivation
			if derivation == nil {
				return nil, nil
			}

			return psbt.SerializeBIP32Derivation(
				derivation.MasterKeyFingerprint,
				derivation.Bip32Path,
			), nil
		},
	}, {
		key: PsbtKeyTypeOutputTaroAnchorOutputTaprootBip32Derivation,
		encoder: func() ([]byte, error) {
			derivation := o.AnchorOutputTaprootBip32Derivation
			if derivation == nil {
				return nil, nil
			}

			return psbt.SerializeTaprootBip32Derivation(
				derivation,
			)
		},
	}, {
		key:     PsbtKeyTypeOutputTaroAsset,
		encoder: assetEncoder(o.Asset),
	}, {
		key:     PsbtKeyTypeOutputTaroSplitAsset,
		encoder: assetEncoder(o.SplitAsset),
	}}

	for idx := range mapping {
		value, err := mapping[idx].encoder()
		if err != nil {
			return pOut, nil, fmt.Errorf("error encoding input "+
				"key %x: %w", mapping[idx].key, err)
		}

		if value != nil {
			pOut.Unknowns = append(pOut.Unknowns, &psbt.Unknown{
				Key:   mapping[idx].key,
				Value: value,
			})
		}
	}

	return pOut, txOut, nil
}

// tlvEncoder returns a function that encodes the given value using the given TLV
// tlvEncoder.
func tlvEncoder(val any, enc tlv.Encoder) func() ([]byte, error) {
	return func() ([]byte, error) {
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

		return b.Bytes(), nil
	}
}

// pubKeyEncoder is an encoder that does nothing if the given public key is nil.
func pubKeyEncoder(pubKey *btcec.PublicKey) func() ([]byte, error) {
	if pubKey == nil {
		return func() ([]byte, error) {
			return nil, nil
		}
	}

	return tlvEncoder(&pubKey, tlv.EPubKey)
}

// assetEncoder is an encoder that does nothing if the given asset is nil.
func assetEncoder(a *asset.Asset) func() ([]byte, error) {
	if a == nil {
		return func() ([]byte, error) {
			return nil, nil
		}
	}

	return tlvEncoder(a, asset.LeafEncoder)
}

// booleanEncoder returns a function that encodes the given boolean value as a
// byte slice.
func booleanEncoder(val bool) func() ([]byte, error) {
	return func() ([]byte, error) {
		if val {
			return trueAsBytes, nil
		}

		return falseAsBytes, nil
	}
}

// payToTaprootScript creates a pk script for a pay-to-taproot output key. We
// create a copy of the taroscript.PayToTaprootScript function here to avoid a
// circular dependency.
func payToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}
