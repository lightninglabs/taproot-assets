package proof

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
)

// Blob either represents a serialized proof file, including the checksum or a
// single serialized issuance/transition proof. Which one it is can be found out
// from the leading magic bytes (or the helper methods that inspect those).
type Blob []byte

// IsFile returns true if the blob is a serialized proof file.
func (b Blob) IsFile() bool {
	return IsProofFile(b)
}

// IsSingleProof returns true if the blob is a serialized single proof.
func (b Blob) IsSingleProof() bool {
	return IsSingleProof(b)
}

// AsFile returns the blob as a parsed file. If the blob is a single proof, it
// will be parsed as a file with a single proof.
func (b Blob) AsFile() (*File, error) {
	switch {
	// We have a full file, we can just parse it and return it.
	case b.IsFile():
		file := NewEmptyFile(V0)
		if err := file.Decode(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("error decoding proof file: %w",
				err)
		}

		return file, nil

	// We have a single proof, so let's parse it and return it directly,
	// assuming it is the most recent proof the caller is interested in.
	case b.IsSingleProof():
		p := Proof{}
		if err := p.Decode(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("error decoding single proof: "+
				"%w", err)
		}

		file, err := NewFile(V0, p)
		if err != nil {
			return nil, err
		}

		return file, nil

	default:
		return nil, fmt.Errorf("unknown proof blob type")
	}
}

// AsSingleProof returns the blob as a parsed single proof. If the blob is a
// full proof file, the parsed last proof of that file will be returned.
func (b Blob) AsSingleProof() (*Proof, error) {
	switch {
	// We have a full file, we can just parse it and return it.
	case b.IsFile():
		file := NewEmptyFile(V0)
		if err := file.Decode(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("error decoding proof file: %w",
				err)
		}

		return file.LastProof()

	// We have a single proof, so let's parse it and return it directly,
	// assuming it is the most recent proof the caller is interested in.
	case b.IsSingleProof():
		p := Proof{}
		if err := p.Decode(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("error decoding single proof: "+
				"%w", err)
		}

		return &p, nil

	default:
		return nil, fmt.Errorf("unknown proof blob type")
	}
}

// AssetBlobs is a data structure used to pass around the proof files for a
// set of assets which may have been created in the same batched transaction.
// This maps the script key of the asset to the serialized proof file blob.
type AssetBlobs map[asset.SerializedKey]Blob

// AssetProofs is a data structure used to pass around the native proof suffix
// structures for a set of assets which may have been created in the same batch
// transaction. This maps the script key of the asset to the proof suffix.
type AssetProofs map[asset.SerializedKey]*Proof

// BaseProofParams holds the set of chain level information needed to create a
// proof.
type BaseProofParams struct {
	// Block is the block that mined the transaction that minted the
	// specified assets.
	Block *wire.MsgBlock

	// BlockHeight is the height of the block that mined the transaction
	// which minted the specified assets.
	BlockHeight uint32

	// Tx is the transaction that created the assets.
	Tx *wire.MsgTx

	// TxIndex is the index of the transaction within the block above.
	TxIndex int

	// OutputIndex is the index of the output in the above transaction that
	// holds the asset commitment.
	OutputIndex int

	// InternalKey is the internal key used to derive the taproot output
	// key in the above transaction.
	InternalKey *btcec.PublicKey

	// TaprootAssetRoot is the asset root that commits to all assets created
	// in the above transaction.
	TaprootAssetRoot *commitment.TapCommitment

	// TapscriptSibling is the pre-image to the tapscript hash of the
	// sibling to the Taproot Asset root. If this is nil then it means the
	// Taproot Asset root is the only tapscript leaf in the tree.
	TapscriptSibling *commitment.TapscriptPreimage

	// ExclusionProofs is the set of TaprootProofs proving the exclusion of
	// any assets from all other Taproot outputs within Tx.
	ExclusionProofs []TaprootProof
}

// HaveExclusionProof returns true if the set of exclusion proofs already
// contains a proof for the given anchor output index.
func (p *BaseProofParams) HaveExclusionProof(anchorOutputIndex uint32) bool {
	for _, proof := range p.ExclusionProofs {
		if proof.OutputIndex == anchorOutputIndex {
			return true
		}
	}

	return false
}

// HaveInclusionProof returns true if the inclusion proof is for the given
// anchor output index.
func (p *BaseProofParams) HaveInclusionProof(anchorOutputIndex uint32) bool {
	return p.OutputIndex == int(anchorOutputIndex)
}

// MintParams holds the set of chain level information needed to make a proof
// file for the set of assets minted in a batch.
type MintParams struct {
	// BaseProofParams houses the basic chain level parameters needed to
	// construct a proof.
	BaseProofParams

	// GenesisPoint is the genesis outpoint (first spent outpoint in the
	// transaction above).
	GenesisPoint wire.OutPoint
}

// EncodeAsProofFile encodes the passed proof into a blob.
func EncodeAsProofFile(proof *Proof) (Blob, error) {
	proofFile, err := NewFile(V0, *proof)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if err := proofFile.Encode(&b); err != nil {
		return nil, fmt.Errorf("unable to encode proof file: %w", err)
	}

	return b.Bytes(), nil
}

// MintingBlobOption allows the caller to modify how the final set of minting
// blobs is created. This can be used to attach optional data to the proof
// file.
type MintingBlobOption func(*mintingBlobOpts)

// mintingBlobOpts is a set of options that can be used to modify the final
// proof files created.
type mintingBlobOpts struct {
	metaReveals        map[asset.SerializedKey]*MetaReveal
	tapSiblingPreimage *commitment.TapscriptPreimage
}

// defaultMintingBlobOpts returns the default set of options for creating a
// minting blob.
func defaultMintingBlobOpts() *mintingBlobOpts {
	return &mintingBlobOpts{
		metaReveals: make(map[asset.SerializedKey]*MetaReveal),
	}
}

// WithAssetMetaReveals is a MintingBlobOption that allows the caller to attach
// meta reveal information to the initial minting blob created.
func WithAssetMetaReveals(
	metaReveals map[asset.SerializedKey]*MetaReveal) MintingBlobOption {

	return func(o *mintingBlobOpts) {
		o.metaReveals = metaReveals
	}
}

// WithSiblingPreimage is a MintingBlobOption that allows the caller to provide
// a tapscript sibling preimage to be used when building the initial minting
// blob.
func WithSiblingPreimage(
	sibling *commitment.TapscriptPreimage) MintingBlobOption {

	return func(o *mintingBlobOpts) {
		o.tapSiblingPreimage = sibling
	}
}

// NewMintingBlobs takes a set of minting parameters, and produces a series of
// serialized proof files, which proves the creation/existence of each of the
// assets within the batch.
func NewMintingBlobs(params *MintParams, headerVerifier HeaderVerifier,
	merkleVerifier MerkleVerifier, groupVerifier GroupVerifier,
	anchorVerifier GroupAnchorVerifier,
	blobOpts ...MintingBlobOption) (AssetProofs, error) {

	opts := defaultMintingBlobOpts()
	for _, blobOpt := range blobOpts {
		blobOpt(opts)
	}

	base, err := baseProof(&params.BaseProofParams, params.GenesisPoint)
	if err != nil {
		return nil, err
	}

	proofs, err := committedProofs(
		base, params.TaprootAssetRoot, anchorVerifier, opts,
	)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// Verify the generated proofs.
	for key := range proofs {
		proof := proofs[key]

		_, err := proof.Verify(
			ctx, nil, headerVerifier, merkleVerifier, groupVerifier,
		)
		if err != nil {
			return nil, fmt.Errorf("invalid proof file generated: "+
				"%w", err)
		}
	}

	return proofs, nil
}

// baseProof creates the basic proof template that contains all anchor
// transaction related fields.
func baseProof(params *BaseProofParams, prevOut wire.OutPoint) (*Proof, error) {
	// First, we'll create the merkle proof for the anchor transaction. In
	// this case, since all the assets were created in the same block, we
	// only need a single merkle proof.
	proof, err := coreProof(params)
	if err != nil {
		return nil, err
	}

	// Now, we'll construct the base proof that all the assets created in
	// this batch or spent in this transaction will share.
	proof.PrevOut = prevOut
	proof.InclusionProof = TaprootProof{
		OutputIndex: uint32(params.OutputIndex),
		InternalKey: params.InternalKey,
	}
	proof.ExclusionProofs = params.ExclusionProofs
	return proof, nil
}

// coreProof creates the basic proof template that contains only fields
// dependent on anchor transaction confirmation.
func coreProof(params *BaseProofParams) (*Proof, error) {
	merkleProof, err := NewTxMerkleProof(
		params.Block.Transactions, params.TxIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create merkle proof: %w", err)
	}

	return &Proof{
		BlockHeader:   params.Block.Header,
		BlockHeight:   params.BlockHeight,
		AnchorTx:      *params.Tx,
		TxMerkleProof: *merkleProof,
	}, nil
}

// committedProofs creates a map of proofs, keyed by the script key of each of
// the assets committed to in the Taproot Asset root of the given params.
func committedProofs(baseProof *Proof, tapTreeRoot *commitment.TapCommitment,
	groupAnchorVerifier GroupAnchorVerifier,
	opts *mintingBlobOpts) (AssetProofs, error) {

	// For each asset we'll construct the asset specific proof information,
	// then encode that as a proof file blob in the blobs map.
	assets := tapTreeRoot.CommittedAssets()
	proofs := make(AssetProofs, len(assets))

	// If a sibling preimage was provided for this Tap commitment, we'll
	// need to include it with every inclusion proof.
	var batchSiblingPreimage *commitment.TapscriptPreimage
	if opts.tapSiblingPreimage != nil {
		batchSiblingPreimage = opts.tapSiblingPreimage
	}

	for idx := range assets {
		// First, we'll copy over the base proof and also set the asset
		// within the proof itself.
		newAsset := assets[idx]
		assetProof := *baseProof
		assetProof.Asset = *newAsset.Copy()

		// With the base information contained, we'll now need to
		// generate our series of MS-SMT inclusion proofs that prove
		// the existence of the asset.
		_, assetMerkleProof, err := tapTreeRoot.Proof(
			newAsset.TapCommitmentKey(),
			newAsset.AssetCommitmentKey(),
		)
		if err != nil {
			return nil, err
		}

		// With the merkle proof obtained, we can now set that in the
		// main inclusion proof.
		//
		assetProof.InclusionProof.CommitmentProof = &CommitmentProof{
			Proof:              *assetMerkleProof,
			TapSiblingPreimage: batchSiblingPreimage,
		}

		scriptKey := asset.ToSerialized(newAsset.ScriptKey.PubKey)

		// With all the base data set above, we'll also check to see if
		// we have any meta reveals. If so, then we'll attach that as
		// well.
		if metaReveal, ok := opts.metaReveals[scriptKey]; ok {
			assetProof.MetaReveal = metaReveal
		}

		// Set the genesis reveal info on the minting proof. To save on
		// some space, the genesis info is no longer included in
		// transition proofs.
		assetProof.GenesisReveal = &newAsset.Genesis

		// If the asset has a group key, we only need to populate the
		// group key reveal if the asset is the group anchor.
		if newAsset.GroupKey != nil {
			groupKey := newAsset.GroupKey

			err := groupAnchorVerifier(&newAsset.Genesis, groupKey)
			if err == nil {
				groupReveal := &asset.GroupKeyReveal{
					RawKey: asset.ToSerialized(
						groupKey.RawKey.PubKey,
					),
					TapscriptRoot: groupKey.TapscriptRoot,
				}
				assetProof.GroupKeyReveal = groupReveal
			}
		}

		// With all the information for this asset populated, we'll
		// now reference the proof by the script key used.
		proofs[scriptKey] = &assetProof
	}

	return proofs, nil
}
