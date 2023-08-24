package address

import (
	"io"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/tlv"
)

func compressedPubKeyEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*btcec.PublicKey); ok {
		var keyBytes [btcec.PubKeyBytesLenCompressed]byte
		copy(keyBytes[:], t.SerializeCompressed())
		return tlv.EBytes33(w, &keyBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*btcec.PublicKey")
}

func compressedPubKeyDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*btcec.PublicKey); ok {
		var keyBytes [btcec.PubKeyBytesLenCompressed]byte
		err := tlv.DBytes33(r, &keyBytes, buf, btcec.PubKeyBytesLenCompressed)
		if err != nil {
			return err
		}
		var key *btcec.PublicKey
		// Handle empty key, which is not on the curve.
		if keyBytes == [btcec.PubKeyBytesLenCompressed]byte{} {
			key = &btcec.PublicKey{}
		} else {
			key, err = btcec.ParsePubKey(keyBytes[:])
			if err != nil {
				return err
			}
		}
		*typ = *key
		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*btcec.PublicKey", l, btcec.PubKeyBytesLenCompressed,
	)
}

// urlEncoder encodes a url.URL as a variable length byte slice.
func urlEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*url.URL); ok {
		addrBytes := []byte((*t).String())
		return tlv.EVarBytes(w, &addrBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*url.URL")
}

// urlDecoder decodes a variable length byte slice as an url.URL.
func urlDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if t, ok := val.(*url.URL); ok {
		var addrBytes []byte
		err := tlv.DVarBytes(r, &addrBytes, buf, l)
		if err != nil {
			return err
		}

		addr, err := url.ParseRequestURI(string(addrBytes))
		if err != nil {
			return err
		}
		*t = *addr

		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*url.URL", l, l,
	)
}

// schnorrSigEncoder encodes a schnorr.Signature as a variable length byte
// slice.
func schnorrSigEncoder(w io.Writer, val any, buf *[8]byte) error {
	if s, ok := val.(**schnorr.Signature); ok {
		sigBytes := (*s).Serialize()
		return tlv.EVarBytes(w, &sigBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*schnorr.Signature")
}

// urlDecoder decodes a variable length byte slice as a schnorr.Signature.
func schnorrSigDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if s, ok := val.(**schnorr.Signature); ok {
		var sigBytes []byte
		err := tlv.DVarBytes(r, &sigBytes, buf, l)
		if err != nil {
			return err
		}

		sig, err := schnorr.ParseSignature(sigBytes)
		if err != nil {
			return err
		}
		*s = sig

		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*schnorr.Signature", l, l,
	)
}
