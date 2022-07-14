package address

import (
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/tlv"
)

func schnorrPubKeyEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*btcec.PublicKey); ok {
		var keyBytes [schnorr.PubKeyBytesLen]byte
		copy(keyBytes[:], schnorr.SerializePubKey(t))
		return tlv.EBytes32(w, &keyBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*btcec.PublicKey")
}

func schnorrPubKeyDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*btcec.PublicKey); ok {
		var keyBytes [schnorr.PubKeyBytesLen]byte
		err := tlv.DBytes32(r, &keyBytes, buf, schnorr.PubKeyBytesLen)
		if err != nil {
			return err
		}
		var key *btcec.PublicKey
		// Handle empty key, which is not on the curve.
		if keyBytes == [32]byte{} {
			key = &btcec.PublicKey{}
		} else {
			key, err = schnorr.ParsePubKey(keyBytes[:])
			if err != nil {
				return err
			}
		}
		*typ = *key
		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*btcec.PublicKey", l, schnorr.PubKeyBytesLen,
	)
}
