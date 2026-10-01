package asset

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// spenderKeyTag is the tag whose hash prefixes the data that tweaks the NUMS
// key into the script key of a spender leaf.
const spenderKeyTag = "taproot-assets:stxo-spender"

// DeriveSpenderKey derives the script key of the spender leaf of an input, by
// tweaking the public NUMS key with a tap tweak:
//
//	tweak = h_tapTweak(
//		NUMSKey || sha256(tag) || outPoint || assetID || scriptKey,
//	)
//	spenderKey = NUMSKey + tweak*G
//
// The key depends on the input alone, so a commitment holds at most one
// spender leaf per input. The tag separates the key from the burn key of any
// input, which also serves as the script key of its STXO leaf.
func DeriveSpenderKey(prevID PrevID) *btcec.PublicKey {
	var b bytes.Buffer

	// As for the burn key, the tweak data is larger than 32 bytes, so it
	// can't be taken for a merkle root hash and the script spend path is
	// invalid.
	//
	// NOTE: All errors here are ignored, since they can only be returned
	// from a Write() call, which on the bytes.Buffer will _never_ fail.
	tag := sha256.Sum256([]byte(spenderKeyTag))
	_, _ = b.Write(tag[:])
	_ = wire.WriteOutPoint(&b, 0, 0, &prevID.OutPoint)
	_, _ = b.Write(prevID.ID[:])
	_, _ = b.Write(prevID.ScriptKey.SchnorrSerialized())

	// The key is only ever serialized as a script key, so the parity
	// information is dropped, as it is for the burn key.
	spenderKey := txscript.ComputeTaprootOutputKey(NUMSPubKey, b.Bytes())
	spenderKey, _ = schnorr.ParsePubKey(
		schnorr.SerializePubKey(spenderKey),
	)

	return spenderKey
}

// CollectSpenders returns an Alt Leaf for each input spent by the given output
// asset, that names the output asset as the spender of the input. They are
// committed to next to the STXOs of the inputs.
func CollectSpenders(outAsset *Asset) ([]AltLeaf[Asset], error) {
	// Only the root asset of a transfer spends inputs, so there are no
	// spender leaves for genesis assets and split leaves, as there are no
	// STXOs for them.
	if !outAsset.IsTransferRoot() {
		return nil, nil
	}

	// At this point, the asset must have at least one witness.
	if len(outAsset.PrevWitnesses) == 0 {
		return nil, fmt.Errorf("asset has no witnesses")
	}

	altLeaves := make([]*Asset, len(outAsset.PrevWitnesses))
	for idx, wit := range outAsset.PrevWitnesses {
		altLeaf, err := MakeSpenderAsset(wit, outAsset)
		if err != nil {
			return nil, fmt.Errorf("error collecting spender for "+
				"witness %d: %w", idx, err)
		}

		altLeaves[idx] = altLeaf
	}

	return ToAltLeaves(altLeaves), nil
}

// MakeSpenderAsset creates an Alt Leaf that names the given asset as the
// spender of the input referenced by the PrevId of the witness. The script key
// of the leaf is derived from the input. The leaf carries a single witness
// element, the hash of the keys that locate the spender within the commitment
// of its anchor output:
//
//	sha256(tapCommitmentKey || assetCommitmentKey)
//
// A commitment holds one leaf per script key, and one asset per pair of
// commitment keys. An anchor output that commits to the leaf therefore commits
// to a single spender of the input.
func MakeSpenderAsset(witness Witness, spender *Asset) (*Asset, error) {
	if witness.PrevID == nil {
		return nil, fmt.Errorf("witness has no prevID")
	}

	spenderKey := DeriveSpenderKey(*witness.PrevID)
	scriptKey := NewScriptKey(spenderKey)

	spenderAsset, err := NewAltLeaf(scriptKey, ScriptV0)
	if err != nil {
		return nil, fmt.Errorf("error creating altLeaf: %w", err)
	}

	tapKey := spender.TapCommitmentKey()
	assetKey := spender.AssetCommitmentKey()

	h := sha256.New()
	_, _ = h.Write(tapKey[:])
	_, _ = h.Write(assetKey[:])

	spenderAsset.PrevWitnesses = []Witness{{
		TxWitness: wire.TxWitness{h.Sum(nil)},
	}}

	return spenderAsset, nil
}
