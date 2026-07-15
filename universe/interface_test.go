package universe

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// randLeafProofGen generates an encodable proof with the optional TLV
// surface (block height, meta reveal, challenge witness, genesis reveal,
// alt leaves) varied by rapid draws.
func randLeafProofGen(t *rapid.T) *proof.Proof {
	proofAsset := asset.AssetGen.Draw(t, "asset")

	sliceGen := rapid.SliceOfN(rapid.Byte(), 32, 32)
	witnessData := sliceGen.Draw(t, "witness_data")
	pkScript := sliceGen.Draw(t, "pk_script")

	p := &proof.Proof{
		PrevOut: wire.OutPoint{},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(1e9, 0),
		},
		BlockHeight: rapid.Uint32().Draw(t, "block_height"),
		AnchorTx: wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				Witness: [][]byte{witnessData},
			}},
			TxOut: []*wire.TxOut{{
				PkScript: pkScript,
				Value:    1000,
			}},
		},
		TxMerkleProof: proof.TxMerkleProof{},
		Asset:         proofAsset,
		InclusionProof: proof.TaprootProof{
			InternalKey: asset.PubKeyGen.Draw(t, "internal_key"),
		},
	}

	if rapid.Bool().Draw(t, "meta_reveal") {
		p.MetaReveal = &proof.MetaReveal{
			Type: proof.MetaOpaque,
			Data: rapid.SliceOfN(
				rapid.Byte(), 1, 32,
			).Draw(t, "meta_data"),
		}
	}

	if rapid.Bool().Draw(t, "challenge_witness") {
		p.ChallengeWitness = wire.TxWitness{
			rapid.SliceOfN(
				rapid.Byte(), 1, 32,
			).Draw(t, "challenge"),
		}
	}

	if rapid.Bool().Draw(t, "genesis_reveal") {
		p.GenesisReveal = &proofAsset.Genesis
	}

	if rapid.Bool().Draw(t, "alt_leaves") {
		altAssets := rapid.SliceOfN[asset.Asset](
			asset.AltLeafGen(t), 1, 5,
		).Draw(t, "alt_assets")
		p.AltLeaves = asset.ToAltLeaves(
			lfn.Map(altAssets, lnutils.Ptr),
		)
	}

	return p
}

// TestLeafDecodedProof asserts that DecodedProof agrees with a fresh decode
// of RawProof for proofs across the encodable value space, and that the
// decode is memoized.
func TestLeafDecodedProof(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		p := randLeafProofGen(t)

		var buf bytes.Buffer
		require.NoError(t, p.Encode(&buf))

		leaf := &Leaf{
			GenesisWithGroup: GenesisWithGroup{
				Genesis: p.Asset.Genesis,
			},
			RawProof: buf.Bytes(),
			Asset:    &p.Asset,
			Amt:      p.Asset.Amount,
		}

		var fresh proof.Proof
		require.NoError(
			t, fresh.Decode(bytes.NewReader(leaf.RawProof)),
		)

		decoded, err := leaf.DecodedProof()
		require.NoError(t, err)
		require.Equal(t, &fresh, decoded)

		// The decode must be memoized: subsequent calls return the
		// same object.
		again, err := leaf.DecodedProof()
		require.NoError(t, err)
		require.Same(t, decoded, again)
	})
}
