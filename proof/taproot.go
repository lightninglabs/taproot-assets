package proof

import (
	"bytes"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
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
)

// CommitmentProof represents a full commitment proof for an asset. It can
// either prove inclusion or exclusion of an asset within a Taro commitment.
type CommitmentProof struct {
	commitment.Proof

	// TapSiblingPreimage is an optional preimage of a tap node used to hash
	// together with the Taro commitment leaf node to arrive at the
	// tapscript root of the expected output.
	TapSiblingPreimage []byte
}

func (p CommitmentProof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)
	if p.AssetProof != nil {
		records = append(records, CommitmentProofAssetProofRecord(
			&p.AssetProof,
		))
	}
	records = append(records, CommitmentProofTaroProofRecord(&p.TaroProof))
	if len(p.TapSiblingPreimage) > 0 {
		records = append(records, CommitmentProofTapSiblingPreimageRecord(
			&p.TapSiblingPreimage,
		))
	}
	return records
}

func (p *CommitmentProof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		CommitmentProofAssetProofRecord(&p.AssetProof),
		CommitmentProofTaroProofRecord(&p.TaroProof),
		CommitmentProofTapSiblingPreimageRecord(&p.TapSiblingPreimage),
	}
}

func (p CommitmentProof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

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
type TapscriptProof struct {
	// TapPreimage1 is the preimage for a TapNode at depth 0 or 1.
	TapPreimage1 []byte

	// TapPreimage2, if specified, is the pair preimage for TapPreimage1 at
	// depth 1.
	TapPreimage2 []byte
}

func (p TapscriptProof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 2)
	records = append(records, TapscriptProofTapPreimage1Record(
		&p.TapPreimage1,
	))
	if len(p.TapPreimage2) > 0 {
		records = append(records, TapscriptProofTapPreimage2Record(
			&p.TapPreimage2,
		))
	}
	return records
}

func (p *TapscriptProof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		TapscriptProofTapPreimage1Record(&p.TapPreimage1),
		TapscriptProofTapPreimage2Record(&p.TapPreimage2),
	}
}

func (p TapscriptProof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

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
// if possible, otherwise `nil` is returned.
func tapBranchHash(preimage []byte) *chainhash.Hash {
	// Empty preimage or leaf preimage, return nil.
	if len(preimage) != tapBranchPreimageLen {
		return nil
	}
	left := (*chainhash.Hash)(preimage[:chainhash.HashSize])
	right := (*chainhash.Hash)(preimage[chainhash.HashSize:])
	h := newTapBranchHash(*left, *right)
	return &h
}

// tapLeafHash computes the TapHash of a TapLeaf node from its preimage
// if possible, otherwise `nil` is returned.
func tapLeafHash(preimage []byte) (*chainhash.Hash, error) {
	// Empty preimage.
	if len(preimage) == 0 {
		return nil, nil
	}

	// Enforce that it is not including another Taro commitment.
	if bytes.Contains(preimage, commitment.TaroMarker[:]) {
		return nil, ErrInvalidTaprootProof
	}
	version := txscript.TapscriptLeafVersion(preimage[0])
	script := preimage[1:]
	h := txscript.NewTapLeaf(version, script).TapHash()
	return &h, nil
}

// deriveTaprootKey derives the taproot key backing a Taro commitment.
func deriveTaprootKeyFromTaroCommitment(commitment *commitment.TaroCommitment,
	sibling *chainhash.Hash, internalKey *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	tapscriptRoot := commitment.TapscriptRoot(sibling)
	// TODO: Change txscript.ComputeTaprootOutputKey to return the tweaked
	// key as an even Y key.
	return schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(internalKey, tapscriptRoot[:]),
	))
}

// deriveTaprootKeys derives the possible taproot keys backing a Taro
// commitment.

// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func deriveTaprootKeysFromTaroCommitment(commitment *commitment.TaroCommitment,
	internalKey *btcec.PublicKey, siblingTapPreimage []byte) (
	[]*btcec.PublicKey, error) {

	branch := tapBranchHash(siblingTapPreimage)
	leaf, err := tapLeafHash(siblingTapPreimage)
	if err != nil {
		return nil, err
	}

	taprootKeyWithBranch, err := deriveTaprootKeyFromTaroCommitment(
		commitment, branch, internalKey,
	)
	if err != nil {
		return nil, err
	}
	taprootKeyWithLeaf, err := deriveTaprootKeyFromTaroCommitment(
		commitment, leaf, internalKey,
	)
	if err != nil {
		return nil, err
	}
	return []*btcec.PublicKey{taprootKeyWithBranch, taprootKeyWithLeaf}, nil

}

// DeriveByAssetInclusion derives the possible taproot keys backing a Taro
// commitment by interpreting the TaprootProof as an asset inclusion proof.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func (p TaprootProof) DeriveByAssetInclusion(asset *asset.Asset) (
	[]*btcec.PublicKey, error) {

	if p.CommitmentProof == nil || p.TapscriptProof != nil {
		return nil, ErrInvalidCommitmentProof
	}

	// Use the commitment proof to go from the asset leaf all the way up to
	// the Taro commitment root, which is then mapped to a TapLeaf and is
	// hashed with a sibling node, if any, to derive the tapscript root
	// and taproot output key. We'll do this twice, one for the possible
	// branch sibling and another for the possible leaf sibling.
	taroCommitment, err := p.CommitmentProof.DeriveByAssetInclusion(asset)
	if err != nil {
		return nil, err
	}
	return deriveTaprootKeysFromTaroCommitment(
		taroCommitment, p.InternalKey,
		p.CommitmentProof.TapSiblingPreimage,
	)
}

// DeriveByAssetExclusion derives the possible taproot keys backing a Taro
// commitment by interpreting the TaprootProof as an asset exclusion proof.
// Asset exclusion proofs can take two forms: one where an asset proof proves
// that the asset no longer exists within its AssetCommitment, and another
// where the AssetCommitment corresponding to the excluded asset no longer
// exists within the TaroCommitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func (p TaprootProof) DeriveByAssetExclusion(assetCommitmentKey,
	taroCommitmentKey [32]byte) ([]*btcec.PublicKey, error) {

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
	if p.CommitmentProof.AssetProof == nil {
		commitment, err = p.CommitmentProof.
			DeriveByAssetCommitmentExclusion(taroCommitmentKey)
	} else {
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

// DeriveTaprootKeys derives the possible taproot keys from a TapsscriptProof
// backing a taproot output that does not include a Taro commitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func (p TapscriptProof) DeriveTaprootKeys(internalKey *btcec.PublicKey) (
	[]*btcec.PublicKey, error) {

	var tapscriptRoots []chainhash.Hash
	switch {
	// Either both preimages are provided.
	case len(p.TapPreimage1) > 0 && len(p.TapPreimage2) > 0:
		// When both preimages are provided, we have two possible
		// tapscript roots: one derived from both preimages being
		// leaves and another from both preimages being branches.
		tapscriptRoots = append(tapscriptRoots, newTapBranchHash(
			*tapBranchHash(p.TapPreimage1),
			*tapBranchHash(p.TapPreimage2),
		))

		leafHash1, err := tapLeafHash(p.TapPreimage1)
		if err != nil {
			return nil, err
		}
		leafHash2, err := tapLeafHash(p.TapPreimage2)
		if err != nil {
			return nil, err
		}
		tapscriptRoots = append(tapscriptRoots, newTapBranchHash(
			*leafHash1, *leafHash2,
		))

	// Or only the first is.
	case len(p.TapPreimage1) > 0:
		tapHash, err := tapLeafHash(p.TapPreimage1)
		if err != nil {
			return nil, err
		}
		tapscriptRoots = []chainhash.Hash{*tapHash}

	default:
		return nil, ErrInvalidTapscriptProof
	}

	taprootKeys := make([]*btcec.PublicKey, 0, len(tapscriptRoots))
	for _, tapscriptRoot := range tapscriptRoots {
		taprootKey := txscript.ComputeTaprootOutputKey(
			internalKey, tapscriptRoot[:],
		)
		var err error
		taprootKey, err = schnorr.ParsePubKey(
			schnorr.SerializePubKey(taprootKey),
		)
		if err != nil {
			return nil, err
		}
		taprootKeys = append(taprootKeys, taprootKey)
	}

	return taprootKeys, nil

}

// DeriveByTapscriptProof derives the possible taproot keys from a
// TapscriptProof backing a taproot output that does not include a Taro
// commitment.
//
// NOTE: There are at most two possible keys to try if each leaf preimage
// matches the length of a branch preimage, so we derive both to make sure we
// arrive at the expected key.
func (p TaprootProof) DeriveByTapscriptProof() ([]*btcec.PublicKey, error) {
	if p.CommitmentProof != nil || p.TapscriptProof == nil {
		return nil, ErrInvalidTapscriptProof
	}
	return p.TapscriptProof.DeriveTaprootKeys(p.InternalKey)
}
