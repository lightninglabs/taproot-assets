package asset

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// DeriveBurnKey derives a provably un-spendable but unique key by tweaking the
// public NUMS key with a tap tweak:
//
//	burnTweak = h_tapTweak(NUMSKey || outPoint || assetID || scriptKey)
//	burnKey = NUMSKey + burnTweak*G
//
// The firstPrevID must be the PrevID from the first input that is being spent
// by the virtual transaction that contains the burn.
func DeriveBurnKey(firstPrevID PrevID) *btcec.PublicKey {
	var b bytes.Buffer

	// The data we use in the tap tweak of the NUMS point is the serialized
	// PrevID, which consists of an outpoint, the asset ID and the script
	// key. Because these three values combined are larger than 32 bytes, we
	// explicitly make the script spend path invalid because a merkle root
	// hash would be exactly 32 bytes.
	//
	// NOTE: All errors here are ignored, since they can only be returned
	// from a Write() call, which on the bytes.Buffer will _never_ fail.
	_ = wire.WriteOutPoint(&b, 0, 0, &firstPrevID.OutPoint)
	_, _ = b.Write(firstPrevID.ID[:])
	_, _ = b.Write(firstPrevID.ScriptKey.SchnorrSerialized())

	// Since we'll never query lnd for a burn key, it doesn't matter if we
	// lose the parity information here. And this will only ever be
	// serialized on chain in a 32-bit representation as well, as this is
	// always a script key.
	burnKey := txscript.ComputeTaprootOutputKey(NUMSPubKey, b.Bytes())
	burnKey, _ = schnorr.ParsePubKey(schnorr.SerializePubKey(burnKey))
	return burnKey
}
