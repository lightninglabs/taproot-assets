package address

import (
	"io"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
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

// UrlEncoder encodes a url.URL as a variable length byte slice.
func UrlEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*url.URL); ok {
		addrBytes := []byte((*t).String())
		return tlv.EVarBytes(w, &addrBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*url.URL")
}

// UrlDecoder decodes a variable length byte slice as an url.URL.
func UrlDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
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
	return tlv.NewTypeForDecodingErr(val, "*url.URL", l, l)
}

func VersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Version); ok {
		return tlv.EUint8T(w, uint8(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "Version")
}

func VersionDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*Version); ok {
		var t uint8
		if err := tlv.DUint8(r, &t, buf, l); err != nil {
			return err
		}
		*typ = Version(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "Version", l, 1)
}
