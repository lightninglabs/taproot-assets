package proof

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// tapBranchPreimageLen is the length of a TapBranch preimage, excluding
	// the TapBranchTag.
	tapBranchPreimageLen = 64
)

var (
	// ErrInvalidCommitmentProof is an error returned upon attempting to
	// prove a malformed CommitmentProof.
	ErrInvalidCommitmentProof = errors.New("invalid taro commitment proof")

	// ErrInvalidTapscriptProof is an error returned upon attempting to
	// prove a malformed TapscriptProof.
	ErrInvalidTapscriptProof = errors.New("invalid tapscript proof")

	// ErrInvalidEmptyTapscriptPreimage is an error returned upon attempting
	// to generate the tap hash of an empty preimage.
	ErrInvalidEmptyTapscriptPreimage = errors.New(
		"invalid empty tapscript preimage",
	)

	// ErrInvalidTapscriptPreimageLen is an error returned upon attempting
	// to generate the tap hash of a branch preimage with invalid length.
	ErrInvalidTapscriptPreimageLen = errors.New(
		"invalid tapscript preimage length",
	)
)

// TapscriptPreimageType denotes the type of tapscript sibling preimage.
type TapscriptPreimageType uint8

const (
	// LeafPreimage is a pre-image that's a leaf script.
	LeafPreimage TapscriptPreimageType = 0

	// BranchPreimage is a pre-image that's a branch, so it's actually
	// 64-bytes of two child pre-images.
	BranchPreimage TapscriptPreimageType = 1
)

// String returns a human-readable string for the TapscriptPreimageType.
func (t TapscriptPreimageType) String() string {
	switch t {
	case LeafPreimage:
		return "LeafPreimage"

	case BranchPreimage:
		return "BranchPreimage"

	default:
		return fmt.Sprintf("UnKnownSiblingType(%d)", t)
	}
}

// TapscriptPreimage wraps a pre-image byte slice with a type byte that self
// identifies what type of pre-image it is.
type TapscriptPreimage struct {
	// SiblingPreimage is the pre-image itself. This will be either 32 or
	// 64 bytes.
	SiblingPreimage []byte

	// SiblingType is the type of the pre-image.
	SiblingType TapscriptPreimageType
}

// NewPreimageFromLeaf creates a new TapscriptPreimage from a single tap leaf.
func NewPreimageFromLeaf(leaf txscript.TapLeaf) *TapscriptPreimage {
	// The leaf encoding is: leafVersion || compactSizeof(script) ||
	// script, where compactSizeof returns the compact size needed to
	// encode the value.
	var encodedLeaf bytes.Buffer

	_ = encodedLeaf.WriteByte(byte(leaf.LeafVersion))
	_ = wire.WriteVarBytes(&encodedLeaf, 0, leaf.Script)

	return &TapscriptPreimage{
		SiblingPreimage: encodedLeaf.Bytes(),
		SiblingType:     LeafPreimage,
	}
}

// NewPreimageFromBranch creates a new TapscriptPreimage from a tap branch.
func NewPreimageFromBranch(branch txscript.TapBranch) *TapscriptPreimage {
	var (
		encodedBranch bytes.Buffer
		leftHash      = branch.Left().TapHash()
		rightHash     = branch.Right().TapHash()
	)
	_, _ = encodedBranch.Write(leftHash[:])
	_, _ = encodedBranch.Write(rightHash[:])

	return &TapscriptPreimage{
		SiblingPreimage: encodedBranch.Bytes(),
		SiblingType:     BranchPreimage,
	}
}

// IsEmpty returns true if the sibling pre-image is empty.
func (t *TapscriptPreimage) IsEmpty() bool {
	if t == nil {
		return true
	}

	return len(t.SiblingPreimage) == 0
}

// TapHash returns the tap hash of this preimage according to its type.
func (t *TapscriptPreimage) TapHash() (*chainhash.Hash, error) {
	if t.IsEmpty() {
		return nil, ErrInvalidEmptyTapscriptPreimage
	}

	switch t.SiblingType {
	// The sibling is actually a leaf pre-image, so we'll verify that it
	// isn't a Taro commitment, and then hash it with the commitment to
	// obtain our root.
	case LeafPreimage:
		return tapLeafHash(t.SiblingPreimage)

	// The sibling is actually a branch pre-image, so we'll verify that the
	// branch pre-image is 64-bytes (the two 32-byte hashes of the left
	// and right nodes), and then derive the key from that.
	case BranchPreimage:
		return tapBranchHash(t.SiblingPreimage)

	default:
		return nil, fmt.Errorf("unknown sibling type: <%d>",
			t.SiblingType)
	}
}

// CommitmentProof represents a full commitment proof for an asset. It can
// either prove inclusion or exclusion of an asset within a Taro commitment.
type CommitmentProof struct {
	commitment.Proof

	// TapSiblingPreimage is an optional preimage of a tap node used to
	// hash together with the Taro commitment leaf node to arrive at the
	// tapscript root of the expected output.
	TapSiblingPreimage *TapscriptPreimage
}

// EncodeRecords returns the encoding records for the CommitmentProof.
func (p CommitmentProof) EncodeRecords() []tlv.Record {
	records := p.Proof.EncodeRecords()
	if p.TapSiblingPreimage != nil {
		records = append(records, CommitmentProofTapSiblingPreimageRecord(
			&p.TapSiblingPreimage,
		))
	}
	return records
}

// DecodeRecords returns the decoding records for the CommitmentProof.
func (p *CommitmentProof) DecodeRecords() []tlv.Record {
	records := p.Proof.DecodeRecords()
	return append(
		records,
		CommitmentProofTapSiblingPreimageRecord(&p.TapSiblingPreimage),
	)
}

// Encode attempts to encode the CommitmentProof into the passed io.Writer.
func (p CommitmentProof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode attempts to decode the CommitmentProof from the passed io.Reader.
func (p *CommitmentProof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// TapscriptProof represents a proof of a Taproot output not including a
// Taro commitment. Taro commitments must exist at a leaf with depth 0 or 1, so
// we can guarantee that a Taro commitment doesn't exist by revealing the
// preimage of one node at depth 0 or two nodes at depth 1.
//
// TODO(roasbeef): make *this* into the control block proof?
type TapscriptProof struct {
	// TapPreimage1 is the preimage for a TapNode at depth 0 or 1.
	TapPreimage1 *TapscriptPreimage

	// TapPreimage2, if specified, is the pair preimage for TapPreimage1 at
	// depth 1.
	TapPreimage2 *TapscriptPreimage

	// BIP86 indicates this is a normal BIP-86 wallet output (likely a
	// change output) that does not commit to any script or Taro root.
	BIP86 bool
}

// EncodeRecords returns the encoding records for TapscriptProof.
func (p TapscriptProof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)
	if p.TapPreimage1 != nil && len(p.TapPreimage1.SiblingPreimage) > 0 {
		records = append(records, TapscriptProofTapPreimage1Record(
			&p.TapPreimage1,
		))
	}
	if p.TapPreimage2 != nil && len(p.TapPreimage2.SiblingPreimage) > 0 {
		records = append(records, TapscriptProofTapPreimage2Record(
			&p.TapPreimage2,
		))
	}
	records = append(records, TapscriptProofBIP86Record(&p.BIP86))
	return records
}

// DecodeRecords returns the decoding records for TapscriptProof.
func (p *TapscriptProof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		TapscriptProofTapPreimage1Record(&p.TapPreimage1),
		TapscriptProofTapPreimage2Record(&p.TapPreimage2),
		TapscriptProofBIP86Record(&p.BIP86),
	}
}

// Encode attempts to encode the TapscriptProof to the passed io.Writer.
func (p TapscriptProof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode attempts to decode the TapscriptProof to the passed io.Reader.
func (p *TapscriptProof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// TaprootProof represents a proof that reveals the partial contents to a
// tapscript tree within a taproot output. It can prove whether an asset is being
// included/excluded from a Taro commitment through a CommitmentProof, or that
// no Taro commitment exists at all through a TapscriptProof.
type TaprootProof struct {
	// OutputIndex is the index of the output for which the proof applies.
	OutputIndex uint32

	// InternalKey is the internal key of the taproot output at OutputIndex.
	InternalKey *btcec.PublicKey

	// CommitmentProof represents a commitment proof for an asset, proving
	// inclusion or exclusion of an asset within a Taro commitment.
	CommitmentProof *CommitmentProof

	// TapscriptProof represents a taproot control block to prove that a
	// taproot output is not committing to a Taro commitment.
	//
	// NOTE: This field will be set only if the output does NOT contain a
	// valid Taro commitment.
	TapscriptProof *TapscriptProof
}

func (p TaprootProof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)
	records = append(records, TaprootProofOutputIndexRecord(&p.OutputIndex))
	records = append(records, TaprootProofInternalKeyRecord(&p.InternalKey))
	if p.CommitmentProof != nil {
		records = append(records, TaprootProofCommitmentProofRecord(
			&p.CommitmentProof,
		))
	} else if p.TapscriptProof != nil {
		records = append(records, TaprootProofTapscriptProofRecord(
			&p.TapscriptProof,
		))
	}
	return records
}

func (p *TaprootProof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		TaprootProofOutputIndexRecord(&p.OutputIndex),
		TaprootProofInternalKeyRecord(&p.InternalKey),
		TaprootProofCommitmentProofRecord(&p.CommitmentProof),
		TaprootProofTapscriptProofRecord(&p.TapscriptProof),
	}
}

func (p TaprootProof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

func (p *TaprootProof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// tapBranchHash computes the TapHash of a TapBranch node from its preimage
// if possible, otherwise an error is returned.
func tapBranchHash(preimage []byte) (*chainhash.Hash, error) {
	// Empty preimage or leaf preimage, return typed error.
	if len(preimage) != tapBranchPreimageLen {
		return nil, ErrInvalidTapscriptPreimageLen
	}

	left := (*chainhash.Hash)(preimage[:chainhash.HashSize])
	right := (*chainhash.Hash)(preimage[chainhash.HashSize:])
	h := newTapBranchHash(*left, *right)

	return &h, nil
}

// tapLeafHash computes the TapHash of a TapLeaf node from its preimage
// if possible, otherwise an error is returned.
func tapLeafHash(preimage []byte) (*chainhash.Hash, error) {
	// Empty preimage.
	if len(preimage) == 0 {
		return nil, ErrInvalidEmptyTapscriptPreimage
	}

	// Enforce that it is not including another Taro commitment.
	if bytes.Contains(preimage, commitment.TaroMarker[:]) {
		return nil, ErrInvalidTaprootProof
	}

	version := txscript.TapscriptLeafVersion(preimage[0])

	// The script is encoded with a leading VarByte that indicates its total
	// length.
	remaining := preimage[1:]
	script, err := wire.ReadVarBytes(
		bytes.NewReader(remaining), 0, uint32(len(remaining)), "script",
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding leaf pre-image: %w", err)
	}

	h := txscript.NewTapLeaf(version, script).TapHash()
	return &h, nil
}

// deriveTaprootKey derives the taproot key backing a Taro commitment.
func deriveTaprootKeyFromTaroCommitment(commitment *commitment.TaroCommitment,
	sibling *chainhash.Hash, internalKey *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	// TODO(roasbeef): should just be control block proof verification?
	//  * should be getting the party bit from that itself

	tapscriptRoot := commitment.TapscriptRoot(sibling)
	return schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(internalKey, tapscriptRoot[:]),
	))
}

// deriveTaprootKeys derives the possible taproot keys backing a Taro
// commitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func deriveTaprootKeysFromTaroCommitment(commitment *commitment.TaroCommitment,
	internalKey *btcec.PublicKey, siblingTapPreimage *TapscriptPreimage) (
	*btcec.PublicKey, error) {

	// If there's no actual sibling pre-image, meaning the only thing
	// committed to is the Taro asset root, then this will remain nil.
	var siblingHash *chainhash.Hash

	// If there is a sibling pre-image, it's either a leaf or a branch that
	// we need to hash in order to get our sibling hash.
	if siblingTapPreimage != nil {
		var err error
		siblingHash, err = siblingTapPreimage.TapHash()
		if err != nil {
			return nil, fmt.Errorf("error calculating tapscript "+
				"sibling hash: %w", err)
		}
	}

	return deriveTaprootKeyFromTaroCommitment(
		commitment, siblingHash, internalKey,
	)
}

// DeriveByAssetInclusion derives the unique taproot output key backing a Taro
// commitment by interpreting the TaprootProof as an asset inclusion proof.
//
// There are at most two _possible_ keys that exist if each leaf preimage
// matches the length of a branch preimage. However, using the annotated type
// information we only need to derive a single key.
func (p TaprootProof) DeriveByAssetInclusion(
	asset *asset.Asset) (*btcec.PublicKey, *commitment.TaroCommitment,
	error) {

	if p.CommitmentProof == nil || p.TapscriptProof != nil {
		return nil, nil, ErrInvalidCommitmentProof
	}

	// If this is an asset with a split commitment, then we need to verify
	// the inclusion proof without this information. As the output of the
	// receiver was created without this present.
	if asset.HasSplitCommitmentWitness() {
		asset = asset.Copy()
		asset.PrevWitnesses[0].SplitCommitment = nil
	}

	// Use the commitment proof to go from the asset leaf all the way up to
	// the Taro commitment root, which is then mapped to a TapLeaf and is
	// hashed with a sibling node, if any, to derive the tapscript root and
	// taproot output key.
	taroCommitment, err := p.CommitmentProof.DeriveByAssetInclusion(asset)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := deriveTaprootKeysFromTaroCommitment(
		taroCommitment, p.InternalKey,
		p.CommitmentProof.TapSiblingPreimage,
	)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, taroCommitment, nil
}

// DeriveByAssetExclusion derives the possible taproot keys backing a Taro
// commitment by interpreting the TaprootProof as an asset exclusion proof.
// Asset exclusion proofs can take two forms: one where an asset proof proves
// that the asset no longer exists within its AssetCommitment, and another
// where the AssetCommitment corresponding to the excluded asset no longer
// exists within the TaroCommitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage. However, based on the type of the sibling
// pre-image we'll derive just a single version of it.
func (p TaprootProof) DeriveByAssetExclusion(assetCommitmentKey,
	taroCommitmentKey [32]byte) (*btcec.PublicKey, error) {

	if p.CommitmentProof == nil || p.TapscriptProof != nil {
		return nil, ErrInvalidCommitmentProof
	}

	// Use the commitment proof to go from the empty asset leaf or empty
	// asset commitment leaf all the way up to the Taro commitment root,
	// which is then mapped to a TapLeaf and is hashed with a sibling node,
	// if any, to derive the tapscript root and taproot output key. We'll do
	// this twice, one for the possible branch sibling and another for the
	// possible leaf sibling.
	var (
		commitment *commitment.TaroCommitment
		err        error
	)

	switch {
	// In this case, there's no asset proof, so we want to verify that the
	// specified key maps to an empty leaf node (no asset ID sub-tree in
	// the root commitment).
	case p.CommitmentProof.AssetProof == nil:
		commitment, err = p.CommitmentProof.
			DeriveByAssetCommitmentExclusion(taroCommitmentKey)

	// Otherwise, we have an asset proof, which means the tree contains the
	// asset ID, but we want to verify that the particular asset we care
	// about isn't included.
	default:
		commitment, err = p.CommitmentProof.
			DeriveByAssetExclusion(assetCommitmentKey)
	}
	if err != nil {
		return nil, err
	}

	return deriveTaprootKeysFromTaroCommitment(
		commitment, p.InternalKey, p.CommitmentProof.TapSiblingPreimage,
	)
}

// DeriveTaprootKeys derives the expected taproot key from a TapsscriptProof
// backing a taproot output that does not include a Taro commitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage. However, based on the annotated type
// information, we only need to derive a single expected key.
func (p TapscriptProof) DeriveTaprootKeys(internalKey *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	var tapscriptRoot []byte
	// There're 4 possible cases for tapscript exclusion proofs:
	switch {
	// Two pre-images are specified, and both of the pre-images are leaf
	// hashes. In this case, the tapscript tree has two elements, with both
	// of them being leaves.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.SiblingType == LeafPreimage &&
		p.TapPreimage2.SiblingType == LeafPreimage:

		leafHash1, err := tapLeafHash(p.TapPreimage1.SiblingPreimage)
		if err != nil {
			return nil, err
		}
		leafHash2, err := tapLeafHash(p.TapPreimage2.SiblingPreimage)
		if err != nil {
			return nil, err
		}

		rootHash := newTapBranchHash(*leafHash1, *leafHash2)
		tapscriptRoot = rootHash[:]

	// Two pre-images are specified, with both of the pre-images being a
	// branch. In this case, we don't know how many elements the tree has,
	// we just care that these are actually branches and the hash up
	// correctly.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.SiblingType == BranchPreimage &&
		p.TapPreimage2.SiblingType == BranchPreimage:

		branch1, err := tapBranchHash(p.TapPreimage1.SiblingPreimage)
		if err != nil {
			return nil, err
		}
		branch2, err := tapBranchHash(p.TapPreimage2.SiblingPreimage)
		if err != nil {
			return nil, err
		}

		rootHash := newTapBranchHash(*branch1, *branch2)
		tapscriptRoot = rootHash[:]

	// Two pre-images are specified, with one of them being a leaf and the
	// other being a branch. In this case, we have an un-balanced tapscript
	// tree. We'll verify the first sibling is a leaf, and the other is
	// actually a branch.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.SiblingType == LeafPreimage &&
		p.TapPreimage2.SiblingType == BranchPreimage:

		leafHash, err := tapLeafHash(p.TapPreimage1.SiblingPreimage)
		if err != nil {
			return nil, err
		}

		branchHash, err := tapBranchHash(p.TapPreimage2.SiblingPreimage)
		if err != nil {
			return nil, err
		}

		rootHash := newTapBranchHash(*leafHash, *branchHash)
		tapscriptRoot = rootHash[:]

	// Only a single pre-image was specified, and the pre-image is a leaf.
	case !p.TapPreimage1.IsEmpty() &&
		p.TapPreimage1.SiblingType == BranchPreimage:

		tapHash, err := tapLeafHash(p.TapPreimage1.SiblingPreimage)
		if err != nil {
			return nil, err
		}

		tapscriptRoot = tapHash[:]

	// This is a BIP-86 change output that doesn't commit to any root hash.
	case p.BIP86:
		tapscriptRoot = []byte{}

	default:
		// TODO(roasbeef): revisit
		return nil, fmt.Errorf("invalid tapscript pre-images: "+
			"%v + %v (bip86=%v)", spew.Sdump(p.TapPreimage1),
			spew.Sdump(p.TapPreimage2), p.BIP86)
	}

	// Now that we have the expected tapscript root, we'll derive our
	// expected tapscript root.
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot,
	)

	// TODO(roasbeef): same here -- just need to verify as actual
	// control block proof?
	return schnorr.ParsePubKey(schnorr.SerializePubKey(taprootKey))
}

// DeriveByTapscriptProof derives the possible taproot keys from a
// TapscriptProof backing a taproot output that does not include a Taro
// commitment.
//
// NOTE: There are at most two possible keys to try if each leaf preimage
// matches the length of a branch preimage. However, we can derive only the one
// specified in the contained proof.
func (p TaprootProof) DeriveByTapscriptProof() (*btcec.PublicKey, error) {
	if p.CommitmentProof != nil || p.TapscriptProof == nil {
		return nil, ErrInvalidTapscriptProof
	}
	return p.TapscriptProof.DeriveTaprootKeys(p.InternalKey)
}

// AddExclusionProofs adds exclusion proofs to the base proof for each P2TR
// output in the given PSBT that isn't an anchor output itself. To determine
// which output is the anchor output, the passed isAnchor function should
// return true for the output index that houses the anchor TX.
func AddExclusionProofs(baseProof *BaseProofParams, packet *psbt.Packet,
	isAnchor func(uint32) bool) error {

	for outIdx := range packet.Outputs {
		txOut := packet.UnsignedTx.TxOut[outIdx]

		// Skip any anchor output since that will get an inclusion proof
		// instead.
		if isAnchor(uint32(outIdx)) {
			continue
		}

		// We only need to add exclusion proofs for P2TR outputs as only
		// those could commit to a Taro tree.
		if !txscript.IsPayToTaproot(txOut.PkScript) {
			continue
		}

		// For a P2TR output the internal key must be declared and must
		// be a valid 32-byte x-only public key.
		out := packet.Outputs[outIdx]
		if len(out.TaprootInternalKey) != schnorr.PubKeyBytesLen {
			return fmt.Errorf("cannot add exclusion proof, output "+
				"%d is a P2TR output but is missing the "+
				"internal key in the PSBT", outIdx)
		}
		internalKey, err := schnorr.ParsePubKey(out.TaprootInternalKey)
		if err != nil {
			return fmt.Errorf("cannot add exclusion proof, output "+
				"%d is a P2TR output but the internal key is "+
				"invalid: %w", outIdx, err)
		}

		// Make sure this is a BIP0086 key spend as that is the only
		// method we currently support here.
		if len(out.TaprootTapTree) > 0 {
			return fmt.Errorf("cannot add exclusion proof, output "+
				"%d uses a tap tree which is currently not "+
				"supported", outIdx)
		}

		// Okay, we now know this is a normal BIP0086 key spend and can
		// add the exclusion proof accordingly.
		baseProof.ExclusionProofs = append(
			baseProof.ExclusionProofs, TaprootProof{
				OutputIndex: uint32(outIdx),
				InternalKey: internalKey,
				TapscriptProof: &TapscriptProof{
					BIP86: true,
				},
			},
		)
	}

	return nil
}
