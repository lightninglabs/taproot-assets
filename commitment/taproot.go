package commitment

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
)

const (
	// tapBranchPreimageLen is the length of a TapBranch preimage, excluding
	// the TapBranchTag.
	tapBranchPreimageLen = 64
)

var (
	// ErrInvalidTaprootProof is an error returned upon verifying an invalid
	// Taproot proof.
	ErrInvalidTaprootProof = errors.New("invalid taproot proof")

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

	// ErrInvalidTapscriptPreimageType is an error returned when a tapscript
	// preimage has an unknown type that is not leaf nor branch.
	ErrInvalidTapscriptPreimageType = errors.New(
		"unknown tapscript preimage type",
	)

	// ErrPreimageIsTapCommitment is an error returned when a tapscript
	// preimage is a valid Taproot Asset commitment.
	ErrPreimageIsTapCommitment = errors.New(
		"preimage is a Taproot Asset commitment",
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
		return fmt.Sprintf("UnknownSiblingType(%d)", t)
	}
}

// TapscriptPreimage wraps a pre-image byte slice with a type byte that self
// identifies what type of pre-image it is.
type TapscriptPreimage struct {
	// SiblingPreimage is the pre-image itself. This will be 64 bytes if
	// representing a TapBranch, or any size under 4 MBytes if representing
	// a TapLeaf.
	siblingPreimage []byte

	// SiblingType is the type of the pre-image.
	siblingType TapscriptPreimageType
}

// NewPreimageFromLeaf creates a new TapscriptPreimage from a single tap leaf.
func NewPreimageFromLeaf(leaf txscript.TapLeaf) (*TapscriptPreimage, error) {
	// Check the leaf size and version, and assert that the leaf script is
	// not a Taproot Asset Commitment.
	err := asset.CheckTapLeafSanity(&leaf)
	if err != nil {
		return nil, err
	}

	if IsTaprootAssetCommitmentScript(leaf.Script) {
		return nil, ErrPreimageIsTapCommitment
	}

	// The leaf encoding is: leafVersion || compactSizeof(script) || script,
	// where compactSizeof returns the compact size needed to encode the
	// value.
	var encodedLeaf bytes.Buffer

	_ = encodedLeaf.WriteByte(byte(leaf.LeafVersion))
	_ = wire.WriteVarBytes(&encodedLeaf, 0, leaf.Script)

	return &TapscriptPreimage{
		siblingPreimage: encodedLeaf.Bytes(),
		siblingType:     LeafPreimage,
	}, nil
}

// NewLeafFromPreimage sanity checks a TapscriptPreimage and decodes it into a
// TapLeaf.
func NewLeafFromPreimage(preimage TapscriptPreimage) (*txscript.TapLeaf,
	error) {

	// The preimage must be a TapLeaf.
	if preimage.Type() != LeafPreimage {
		return nil, ErrInvalidTapscriptPreimageType
	}

	// Remove the leaf version and script size prefix from the preimage.
	// The prefix is at least 2 bytes long, and if it's missing then this
	// preimage was not created correctly.
	if len(preimage.siblingPreimage) < 2 {
		return nil, ErrInvalidTapscriptPreimageLen
	}

	// The script is encoded with a leading VarByte that indicates its total
	// length.
	version := txscript.TapscriptLeafVersion(preimage.siblingPreimage[0])
	remaining := preimage.siblingPreimage[1:]
	script, err := wire.ReadVarBytes(
		bytes.NewReader(remaining), 0, uint32(len(remaining)), "script",
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding leaf pre-image: %w", err)
	}

	// The script must not be a Taproot Asset Commitment.
	if IsTaprootAssetCommitmentScript(script) {
		return nil, ErrPreimageIsTapCommitment
	}

	return fn.Ptr(txscript.NewTapLeaf(version, script)), nil
}

// NewPreimageFromBranch creates a new TapscriptPreimage from a tap branch.
func NewPreimageFromBranch(branch txscript.TapBranch) TapscriptPreimage {
	leftHash := branch.Left().TapHash()
	rightHash := branch.Right().TapHash()
	branchBytes := bytes.Join([][]byte{leftHash[:], rightHash[:]}, nil)

	return TapscriptPreimage{
		siblingPreimage: branchBytes,
		siblingType:     BranchPreimage,
	}
}

// TapTreeToSibling constucts a taproot sibling hash from Tapscript tree nodes,
// to be used with a TapCommitment tree root to derive a tapscript root. This
// could be multiple TapLeaf objects, or a representation of a TapBranch.
func NewPreimageFromTapscriptTreeNodes(
	tn asset.TapscriptTreeNodes) (*TapscriptPreimage, error) {

	var (
		preimage    *TapscriptPreimage
		preimageErr error
	)

	asset.GetLeaves(tn).WhenSome(func(tln asset.TapLeafNodes) {
		leaves := asset.ToLeaves(tln)

		// Check that none of the leaves are a Taproot Asset Commitment.
		badLeaves := fn.Any(leaves, func(leaf txscript.TapLeaf) bool {
			return IsTaprootAssetCommitmentScript(leaf.Script)
		})
		if badLeaves {
			preimageErr = ErrPreimageIsTapCommitment
			return
		}

		switch len(leaves) {
		case 1:
			// If we only have one leaf, our preimage is just the
			// encoded leaf.
			preimage, preimageErr = NewPreimageFromLeaf(leaves[0])

		default:
			// Make a branch from the leaves.
			tree := txscript.AssembleTaprootScriptTree(leaves...)
			branch := txscript.NewTapBranch(
				tree.RootNode.Left(), tree.RootNode.Right(),
			)
			preimage = fn.Ptr(NewPreimageFromBranch(branch))
		}
	})

	asset.GetBranch(tn).WhenSome(func(tbn asset.TapBranchNodes) {
		branch := asset.ToBranch(tbn)
		preimage = &TapscriptPreimage{
			siblingPreimage: bytes.Join(branch, nil),
			siblingType:     BranchPreimage,
		}
	})

	if preimageErr != nil {
		return nil, preimageErr
	}
	if preimage == nil {
		return nil, fmt.Errorf("malformed tapscript tree nodes")
	}

	return preimage, nil
}

// IsEmpty returns true if the sibling pre-image is empty.
func (t *TapscriptPreimage) IsEmpty() bool {
	if t == nil {
		return true
	}

	return len(t.siblingPreimage) == 0
}

// Type returns the preimage type.
func (t *TapscriptPreimage) Type() TapscriptPreimageType {
	return t.siblingType
}

// TapHash returns the tap hash of this preimage according to its type.
func (t *TapscriptPreimage) TapHash() (*chainhash.Hash, error) {
	if t.IsEmpty() {
		return nil, ErrInvalidEmptyTapscriptPreimage
	}

	switch t.siblingType {
	// The sibling is a leaf pre-image, so we'll verify that it isn't a
	// Taproot Asset commitment, and then compute its TapHash.
	case LeafPreimage:
		leaf, err := NewLeafFromPreimage(*t)
		if err != nil {
			return nil, err
		}

		return fn.Ptr(leaf.TapHash()), nil

	// The sibling is a branch pre-image, so we'll verify that the pre-image
	// is 64-bytes (the two 32-byte hashes of the left and right nodes),
	// and then derive the TapHash from that.
	case BranchPreimage:
		if len(t.siblingPreimage) != tapBranchPreimageLen {
			return nil, ErrInvalidTapscriptPreimageLen
		}

		var left, right chainhash.Hash
		left = (chainhash.Hash)(t.siblingPreimage[:chainhash.HashSize])
		right = (chainhash.Hash)(t.siblingPreimage[chainhash.HashSize:])

		return fn.Ptr(asset.NewTapBranchHash(left, right)), nil

	default:
		return nil, fmt.Errorf("%w: %d",
			ErrInvalidTapscriptPreimageType, t.siblingType)
	}
}

// MaybeDecodeTapscriptPreimage returns the decoded preimage and hash of the
// Tapscript sibling or nil if the encoded content is empty.
func MaybeDecodeTapscriptPreimage(encoded []byte) (*TapscriptPreimage,
	*chainhash.Hash, error) {

	if len(encoded) == 0 {
		return nil, nil, nil
	}

	var (
		preimage = &TapscriptPreimage{}
		scratch  [8]byte
	)
	err := TapscriptPreimageDecoder(
		bytes.NewReader(encoded), &preimage, &scratch,
		uint64(len(encoded)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding tapscript "+
			"preimage: %w", err)
	}

	// Validate the correctness of the decoded preimage and compute its
	// TapHash.
	tapHash, err := preimage.TapHash()
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving tap hash "+
			"from preimage: %w", err)
	}

	return preimage, tapHash, nil
}

// MaybeEncodeTapscriptPreimage returns the encoded preimage and hash of the
// Tapscript sibling or nil if the preimage is nil.
func MaybeEncodeTapscriptPreimage(t *TapscriptPreimage) ([]byte,
	*chainhash.Hash, error) {

	if t == nil {
		return nil, nil, nil
	}

	tapHash, err := t.TapHash()
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving tap hash "+
			"from preimage: %w", err)
	}

	var (
		b       bytes.Buffer
		scratch [8]byte
	)
	if err := TapscriptPreimageEncoder(&b, &t, &scratch); err != nil {
		return nil, tapHash, fmt.Errorf("error encoding tapscript "+
			"preimage: %w", err)
	}

	return b.Bytes(), tapHash, nil
}
