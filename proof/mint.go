package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
)

// Blob represents a serialized proof file, including the checksum.
type Blob []byte

// AssetBlobs is a data structure used to pass around the proof files for a
// set of assets which may have been created in the same batched transaction.
// This maps the script key of the asset to the serialized proof file blob.
type AssetBlobs map[asset.SerializedKey]Blob

// MintParams holds the set of chain level information needed to make a proof
// file for the set of assets minted in a batch.
type MintParams struct {
	// Block is the block that mined the transaction that minted the
	// specified assets.
	Block *wire.MsgBlock

	// Tx is the transaction that created the assets.
	//
	// TODO(roasbeef): assumes only 2 outputs (minting tx and change) need
	// more information to make exclusion proofs for the others
	Tx *wire.MsgTx

	// TxIndex is the index of the transaction within the block above.
	TxIndex int

	// OutputIndex is the index of the output in the above transaction that
	// holds the asset commitment.
	OutputIndex int

	// InternalKey is the internal key used to derive the taproot output
	// key in the above transaction.
	InternalKey *btcec.PublicKey

	// GenesisPoint is the genesis outpoint (first spent outpoint in the
	// transaction above).
	GenesisPoint wire.OutPoint

	// TaroRoot is the asset root that commits to all assets created in the
	// above transaction.
	TaroRoot *commitment.TaroCommitment
}

// encodeAsProofFile encodes the passed proof into a blob.
//
// TODO(roasbeef): change main file to use pointers instead?
func encodeAsProofFile(proof *Proof) (Blob, error) {
	proofFile := NewFile(V0, *proof)

	var b bytes.Buffer
	if err := proofFile.Encode(&b); err != nil {
		// TODO(roasbeef): proper error
		return nil, fmt.Errorf("unable to encode proof "+
			"file: %w", err)
	}

	return b.Bytes(), nil
}

// NewMintingBlobs takes a set of minting parameters, and produces a series of
// serialized proof files, which proves the creation/existence of each of the
// assets within the batch.
//
// TODO(roasbeef): move into the proof dir?
func NewMintingBlobs(params *MintParams) (AssetBlobs, error) {
	// First, we'll create the merkle proof for the anchor transaction.  In
	// this case, since all the assets were created in the same block, we
	// only need a single merkle proof.
	merkleProof, err := NewTxMerkleProof(
		params.Block.Transactions, params.TxIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create merkle proof: %w", err)
	}

	// Next, we'll construct the base proof that all the assets created in
	// this batch will share.
	baseProof := &Proof{
		PrevOut:       params.GenesisPoint,
		BlockHeader:   params.Block.Header,
		AnchorTx:      *params.Tx,
		TxMerkleProof: *merkleProof,
		InclusionProof: TaprootProof{
			OutputIndex: uint32(params.OutputIndex),
			InternalKey: params.InternalKey,
		},
	}

	// For each asset we'll construct the asset specific proof information,
	// then encode that as a proof file blob in the blobs map.
	assets := params.TaroRoot.CommittedAssets()
	blobs := make(AssetBlobs, len(assets))
	ctx := context.Background()
	for _, newAsset := range assets {
		// First, we'll copy over the base proof and also set the asset
		// within the proof itself.
		assetProof := *baseProof
		assetProof.Asset = *newAsset

		// With the base information contained, we'll now need to
		// generate our series of MS-SMT inclusion proofs that prove
		// the existence of the asset.
		_, assetMerkleProof, err := params.TaroRoot.Proof(
			newAsset.TaroCommitmentKey(),
			newAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// With the merkle proof obtained, we can now set that in the
		// main inclusion proof.
		//
		// NOTE: We don't add a TapSiblingPreimage here since we assume
		// that this minting output ONLY commits to the Taro
		// commitment.
		assetProof.InclusionProof.CommitmentProof = &CommitmentProof{
			Proof: *assetMerkleProof,
		}

		// Before we encode the proof file, we'll verify that we
		// generate a valid proof.
		if _, err := assetProof.Verify(ctx, nil); err != nil {
			return nil, fmt.Errorf("invalid proof file "+
				"generated: %v", err)
		}

		// With all the information for this asset populated, we'll
		// make a new proof file, and encode it into raw bytes.
		proofBlob, err := encodeAsProofFile(&assetProof)
		if err != nil {
			return nil, err
		}
		blobs[asset.ToSerialized(newAsset.ScriptKey.PubKey)] = proofBlob
	}

	return blobs, nil
}
