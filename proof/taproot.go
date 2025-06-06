package proof

import (
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
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/maps"
)

var (
	// ErrInvalidCommitmentProof is an error returned upon attempting to
	// prove a malformed CommitmentProof.
	ErrInvalidCommitmentProof = errors.New(
		"invalid Taproot Asset commitment proof",
	)

	// ErrStxoInputProofMissing is returned when a required STXO input proof
	// is missing.
	ErrStxoInputProofMissing = errors.New(
		"missing STXO input proof for Taproot Asset commitment",
	)
)

// CommitmentProof represents a full commitment proof for an asset. It can
// either prove inclusion or exclusion of an asset within a Taproot Asset
// commitment.
type CommitmentProof struct {
	commitment.Proof

	// TapSiblingPreimage is an optional preimage of a tap node used to
	// hash together with the Taproot Asset commitment leaf node to arrive
	// at the tapscript root of the expected output.
	TapSiblingPreimage *commitment.TapscriptPreimage

	// STXOProofs is a list of proofs that either prove the spend of the
	// inputs as referenced in the asset's previous witnesses' prevIDs when
	// this is in an inclusion proof, or the non-spend of an input if this
	// is in an exclusion proof. Only the root assets in a transfer (so no
	// minted or split assets) will have STXO inclusion or exclusion proofs.
	STXOProofs map[asset.SerializedKey]commitment.Proof

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
}

// EncodeRecords returns the encoding records for the CommitmentProof.
func (p CommitmentProof) EncodeRecords() []tlv.Record {
	records := p.Proof.EncodeRecords()
	if p.TapSiblingPreimage != nil {
		records = append(
			records, CommitmentProofTapSiblingPreimageRecord(
				&p.TapSiblingPreimage,
			),
		)
	}
	if len(p.STXOProofs) > 0 {
		records = append(records, CommitmentProofSTXOProofsRecord(
			&p.STXOProofs,
		))
	}

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, p.UnknownOddTypes)
}

// DecodeRecords returns the decoding records for the CommitmentProof.
func (p *CommitmentProof) DecodeRecords() []tlv.Record {
	records := p.Proof.DecodeRecords()
	records = append(
		records,
		CommitmentProofTapSiblingPreimageRecord(&p.TapSiblingPreimage),
	)
	return append(
		records,
		CommitmentProofSTXOProofsRecord(&p.STXOProofs),
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

	unknownOddTypes, err := asset.TlvStrictDecodeP2P(
		stream, r, KnownCommitmentProofTypes,
	)
	if err != nil {
		return err
	}

	p.UnknownOddTypes = unknownOddTypes

	return nil
}

// TapscriptProof represents a proof of a Taproot output not including a
// Taproot Asset commitment. Taproot Asset commitments must exist at a leaf with
// depth 0 or 1, so we can guarantee that a Taproot Asset commitment doesn't
// exist by revealing the preimage of one node at depth 0 or two nodes at depth
// 1.
//
// TODO(roasbeef): make *this* into the control block proof?
type TapscriptProof struct {
	// TapPreimage1 is the preimage for a TapNode at depth 0 or 1.
	TapPreimage1 *commitment.TapscriptPreimage

	// TapPreimage2, if specified, is the pair preimage for TapPreimage1 at
	// depth 1.
	TapPreimage2 *commitment.TapscriptPreimage

	// Bip86 indicates this is a normal BIP-0086 wallet output (likely a
	// change output) that does not commit to any script or Taproot Asset
	// root.
	Bip86 bool

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
}

// EncodeRecords returns the encoding records for TapscriptProof.
func (p TapscriptProof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)
	if p.TapPreimage1 != nil && !p.TapPreimage1.IsEmpty() {
		records = append(records, TapscriptProofTapPreimage1Record(
			&p.TapPreimage1,
		))
	}
	if p.TapPreimage2 != nil && !p.TapPreimage2.IsEmpty() {
		records = append(records, TapscriptProofTapPreimage2Record(
			&p.TapPreimage2,
		))
	}
	records = append(records, TapscriptProofBip86Record(&p.Bip86))

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, p.UnknownOddTypes)
}

// DecodeRecords returns the decoding records for TapscriptProof.
func (p *TapscriptProof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		TapscriptProofTapPreimage1Record(&p.TapPreimage1),
		TapscriptProofTapPreimage2Record(&p.TapPreimage2),
		TapscriptProofBip86Record(&p.Bip86),
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

	unknownOddTypes, err := asset.TlvStrictDecodeP2P(
		stream, r, KnownTapscriptProofTypes,
	)
	if err != nil {
		return err
	}

	p.UnknownOddTypes = unknownOddTypes

	return nil
}

// TaprootProof represents a proof that reveals the partial contents to a
// tapscript tree within a taproot output. It can prove whether an asset is
// being included/excluded from a Taproot Asset commitment through a
// CommitmentProof, or that no Taproot Asset commitment exists at all through a
// TapscriptProof.
type TaprootProof struct {
	// OutputIndex is the index of the output for which the proof applies.
	OutputIndex uint32

	// InternalKey is the internal key of the taproot output at OutputIndex.
	InternalKey *btcec.PublicKey

	// CommitmentProof represents a commitment proof for an asset, proving
	// inclusion or exclusion of an asset within a Taproot Asset commitment.
	CommitmentProof *CommitmentProof

	// TapscriptProof represents a taproot control block to prove that a
	// taproot output is not committing to a Taproot Asset commitment.
	//
	// NOTE: This field will be set only if the output does NOT contain a
	// valid Taproot Asset commitment.
	TapscriptProof *TapscriptProof

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
}

// ProofCommitmentKeys stores the Taproot Asset commitments and taproot output
// keys derived from a TaprootProof.
type ProofCommitmentKeys map[asset.SerializedKey]*commitment.TapCommitment

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

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, p.UnknownOddTypes)
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

	unknownOddTypes, err := asset.TlvStrictDecodeP2P(
		stream, r, KnownTaprootProofTypes,
	)
	if err != nil {
		return err
	}

	p.UnknownOddTypes = unknownOddTypes

	return nil
}

// deriveTaprootKey derives the taproot key backing a Taproot Asset commitment.
func deriveTaprootKeyFromTapCommitment(commitment *commitment.TapCommitment,
	sibling *chainhash.Hash,
	internalKey *btcec.PublicKey) (*btcec.PublicKey, error) {

	// TODO(roasbeef): should just be control block proof verification?
	//  * should be getting the party bit from that itself
	tapscriptRoot := commitment.TapscriptRoot(sibling)
	return schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(internalKey, tapscriptRoot[:]),
	))
}

// deriveTaprootKeys derives the possible taproot keys backing a Taproot Asset
// commitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage, so we derive both to make sure we arrive at the
// expected key.
func deriveTaprootKeysFromTapCommitment(commitment *commitment.TapCommitment,
	internalKey *btcec.PublicKey,
	siblingTapPreimage *commitment.TapscriptPreimage) (*btcec.PublicKey,
	error) {

	// If there's no actual sibling pre-image, meaning the only thing
	// committed to is the Taproot asset root, then this will remain nil.
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

	return deriveTaprootKeyFromTapCommitment(
		commitment, siblingHash, internalKey,
	)
}

// DeriveByAssetInclusion derives the unique taproot output key backing a
// Taproot Asset commitment by interpreting the TaprootProof as an asset
// inclusion proof.
//
// There are at most two _possible_ keys that exist if each leaf preimage
// matches the length of a branch preimage. However, using the annotated type
// information we only need to derive a single key.
func (p TaprootProof) DeriveByAssetInclusion(asset *asset.Asset,
	single *bool) (ProofCommitmentKeys, error) {

	if p.CommitmentProof == nil || p.TapscriptProof != nil {
		return nil, ErrInvalidCommitmentProof
	}

	// If this is an asset with a split commitment, then we need to verify
	// the inclusion proof without this information. As the output of the
	// receiver was created without this present.
	if asset.HasSplitCommitmentWitness() {
		asset = asset.Copy()
		asset.PrevWitnesses[0].SplitCommitment = nil
	}

	// Use the commitment proof to go from the asset leaf all the way up to
	// the Taproot Asset commitment root, which is then mapped to a TapLeaf
	// and is hashed with a sibling node, if any, to derive the tapscript
	// root and taproot output key.
	tapCommitment, err := p.CommitmentProof.DeriveByAssetInclusion(asset)
	if err != nil {
		return nil, err
	}

	// Derive multiple keys by default.
	downgrade := true
	if single != nil {
		downgrade = *single
	}

	return deriveCommitmentKeys(
		tapCommitment, p.InternalKey,
		p.CommitmentProof.TapSiblingPreimage, true, downgrade,
	)
}

// DeriveByAssetExclusion derives the possible taproot keys backing a Taproot
// Asset commitment by interpreting the TaprootProof as an asset exclusion
// proof. Asset exclusion proofs can take two forms: one where an asset proof
// proves that the asset no longer exists within its AssetCommitment, and
// another where the AssetCommitment corresponding to the excluded asset no
// longer exists within the TapCommitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage. However, based on the type of the sibling
// pre-image we'll derive just a single version of it.
func (p TaprootProof) DeriveByAssetExclusion(assetCommitmentKey,
	tapCommitmentKey [32]byte) (ProofCommitmentKeys, error) {

	if p.CommitmentProof == nil || p.TapscriptProof != nil {
		return nil, ErrInvalidCommitmentProof
	}

	// Use the commitment proof to go from the empty asset leaf or empty
	// asset commitment leaf all the way up to the Taproot Asset commitment
	// root, which is then mapped to a TapLeaf and is hashed with a sibling
	// node, if any, to derive the tapscript root and taproot output key.
	// We'll do this twice, one for the possible branch sibling and another
	// for the possible leaf sibling.
	var (
		tapCommitment *commitment.TapCommitment
		err           error
	)

	switch {
	// In this case, there's no asset proof, so we want to verify that the
	// specified key maps to an empty leaf node (no asset ID sub-tree in
	// the root commitment).
	case p.CommitmentProof.AssetProof == nil:
		log.Debugf("Deriving commitment by asset commitment exclusion")
		tapCommitment, err = p.CommitmentProof.
			DeriveByAssetCommitmentExclusion(tapCommitmentKey)

	// Otherwise, we have an asset proof, which means the tree contains the
	// asset ID, but we want to verify that the particular asset we care
	// about isn't included.
	default:
		log.Debugf("Deriving commitment by asset exclusion")
		tapCommitment, err = p.CommitmentProof.
			DeriveByAssetExclusion(assetCommitmentKey)
	}
	if err != nil {
		return nil, err
	}

	return deriveCommitmentKeys(
		tapCommitment, p.InternalKey,
		p.CommitmentProof.TapSiblingPreimage, false, true,
	)
}

// deriveCommitmentKeys derives the multiple possible taproot output keys for a
// TaprootProof.
func deriveCommitmentKeys(commitment *commitment.TapCommitment,
	internalKey *btcec.PublicKey,
	siblingPreimage *commitment.TapscriptPreimage,
	inclusion, downgrade bool) (ProofCommitmentKeys, error) {

	proofType := "exclusion"
	if inclusion {
		proofType = "inclusion"
	}

	log.Tracef("Derived Taproot Asset commitment by %s "+
		"taproot_asset_root=%x, internal_key=%x",
		proofType, fn.ByteSlice(commitment.TapscriptRoot(nil)),
		internalKey.SerializeCompressed())

	commitmentKeys := make(ProofCommitmentKeys)
	pubKeyV2, err := deriveTaprootKeysFromTapCommitment(
		commitment, internalKey, siblingPreimage,
	)
	if err != nil {
		return nil, err
	}

	commitmentCopy, err := commitment.Copy()
	if err != nil {
		return nil, err
	}

	commitmentKeys[asset.ToSerialized(pubKeyV2)] = commitmentCopy
	downgradedCommitment, err := commitment.Downgrade()
	if err != nil {
		return nil, fmt.Errorf("error downgrading commitment: %w", err)
	}

	pubKeyNonV2, err := deriveTaprootKeysFromTapCommitment(
		downgradedCommitment, internalKey, siblingPreimage,
	)
	if err != nil {
		return nil, err
	}

	if downgrade {
		downgradePubKey := asset.ToSerialized(pubKeyNonV2)
		commitmentKeys[downgradePubKey] = downgradedCommitment
	}

	log.Debugf("Derived Taproot Asset commitment by %s "+
		"taproot_asset_root=%x, internal_key=%x, Commitment V2 "+
		"taproot_key=%x, NonV2 taproot_key=%x",
		proofType, fn.ByteSlice(commitment.TapscriptRoot(nil)),
		internalKey.SerializeCompressed(),
		schnorr.SerializePubKey(pubKeyV2),
		schnorr.SerializePubKey(pubKeyNonV2))

	return commitmentKeys, nil
}

func (k ProofCommitmentKeys) GetCommitment() (*commitment.TapCommitment,
	error) {

	if len(k) != 1 {
		return nil, fmt.Errorf("expected exactly 1 commitment")
	}

	return maps.Values(k)[0], nil
}

// DeriveTaprootKeys derives the expected taproot key from a TapscriptProof
// backing a taproot output that does not include a Taproot Asset commitment.
//
// There are at most two possible keys to try if each leaf preimage matches the
// length of a branch preimage. However, based on the annotated type
// information, we only need to derive a single expected key.
func (p TapscriptProof) DeriveTaprootKeys(internalKey *btcec.PublicKey) (
	*btcec.PublicKey, error) {

	var tapscriptRoot []byte
	// There're 5 possible cases for tapscript exclusion proofs:
	switch {
	// Two pre-images are specified, and both of the pre-images are leaf
	// hashes. In this case, the tapscript tree has two elements, with both
	// of them being leaves.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.Type() == commitment.LeafPreimage &&
		p.TapPreimage2.Type() == commitment.LeafPreimage:

		leafHash1, err := p.TapPreimage1.TapHash()
		if err != nil {
			return nil, err
		}

		leafHash2, err := p.TapPreimage2.TapHash()
		if err != nil {
			return nil, err
		}

		rootHash := asset.NewTapBranchHash(*leafHash1, *leafHash2)
		tapscriptRoot = rootHash[:]

	// Two pre-images are specified, with both of the pre-images being a
	// branch. In this case, we don't know how many elements the tree has,
	// we just care that these are actually branches and the hash up
	// correctly.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.Type() == commitment.BranchPreimage &&
		p.TapPreimage2.Type() == commitment.BranchPreimage:

		branch1, err := p.TapPreimage1.TapHash()
		if err != nil {
			return nil, err
		}
		branch2, err := p.TapPreimage2.TapHash()
		if err != nil {
			return nil, err
		}

		rootHash := asset.NewTapBranchHash(*branch1, *branch2)
		tapscriptRoot = rootHash[:]

	// Two pre-images are specified, with one of them being a leaf and the
	// other being a branch. In this case, we have an un-balanced tapscript
	// tree. We'll verify the first sibling is a leaf, and the other is
	// actually a branch.
	case !p.TapPreimage1.IsEmpty() && !p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.Type() == commitment.LeafPreimage &&
		p.TapPreimage2.Type() == commitment.BranchPreimage:

		leafHash, err := p.TapPreimage1.TapHash()
		if err != nil {
			return nil, err
		}

		branchHash, err := p.TapPreimage2.TapHash()
		if err != nil {
			return nil, err
		}

		rootHash := asset.NewTapBranchHash(*leafHash, *branchHash)
		tapscriptRoot = rootHash[:]

	// Only a single pre-image was specified, and the pre-image is a leaf.
	case !p.TapPreimage1.IsEmpty() && p.TapPreimage2.IsEmpty() &&
		p.TapPreimage1.Type() == commitment.LeafPreimage:

		tapHash, err := p.TapPreimage1.TapHash()
		if err != nil {
			return nil, err
		}

		tapscriptRoot = tapHash[:]

	// This is a BIP-0086 change output that doesn't commit to any root
	// hash.
	case p.Bip86:
		tapscriptRoot = []byte{}

	default:
		// TODO(roasbeef): revisit
		return nil, fmt.Errorf("invalid tapscript pre-images: "+
			"%v + %v (bip86=%v)", spew.Sdump(p.TapPreimage1),
			spew.Sdump(p.TapPreimage2), p.Bip86)
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
// TapscriptProof backing a taproot output that does not include a Taproot Asset
// commitment.
//
// NOTE: There are at most two possible keys to try if each leaf preimage
// matches the length of a branch preimage. However, we can derive only the one
// specified in the contained proof.
func (p TaprootProof) DeriveByTapscriptProof() (*btcec.PublicKey, error) {
	if p.CommitmentProof != nil || p.TapscriptProof == nil {
		return nil, commitment.ErrInvalidTapscriptProof
	}
	return p.TapscriptProof.DeriveTaprootKeys(p.InternalKey)
}

// AddExclusionProofs adds exclusion proofs to the base proof for each P2TR
// output in the given PSBT that isn't an anchor output itself. To determine
// which output is the anchor output, the passed isAnchor function should
// return true for the output index that houses the anchor TX.
func AddExclusionProofs(baseProof *BaseProofParams, finalTx *wire.MsgTx,
	finalTxPacketOutputs []psbt.POutput, isAnchor func(uint32) bool) error {

	for outIdx := range finalTxPacketOutputs {
		txOut := finalTx.TxOut[outIdx]

		// Skip any anchor output since that will get an inclusion proof
		// instead.
		if isAnchor(uint32(outIdx)) {
			continue
		}

		// We only need to add exclusion proofs for P2TR outputs as only
		// those could commit to a Taproot Asset tree.
		if !txscript.IsPayToTaproot(txOut.PkScript) {
			continue
		}

		// For a P2TR output the internal key must be declared and must
		// be a valid 32-byte x-only public key.
		out := finalTxPacketOutputs[outIdx]
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

		// Make sure this is a BIP-0086 key spend as that is the only
		// method we currently support here.
		if len(out.TaprootTapTree) > 0 {
			return fmt.Errorf("cannot add exclusion proof, output "+
				"%d uses a tap tree which is currently not "+
				"supported", outIdx)
		}

		// Okay, we now know this is a normal BIP-0086 key spend and can
		// add the exclusion proof accordingly.
		baseProof.ExclusionProofs = append(
			baseProof.ExclusionProofs, TaprootProof{
				OutputIndex: uint32(outIdx),
				InternalKey: internalKey,
				TapscriptProof: &TapscriptProof{
					Bip86: true,
				},
			},
		)
	}

	return nil
}

// CreateTapscriptProof creates a TapscriptProof from a list of tapscript leaves
// proving that there is no asset commitment contained in the output the proof
// is for.
func CreateTapscriptProof(leaves []txscript.TapLeaf) (*TapscriptProof, error) {
	// There are 5 different possibilities. These correspond in the order
	// with those in DeriveTaprootKeys.
	switch len(leaves) {
	// Exactly two leaves, means both of the preimages are leaves.
	case 2:
		left, err := commitment.NewPreimageFromLeaf(leaves[0])
		if err != nil {
			return nil, fmt.Errorf("error creating preimage from "+
				"leaf: %w", err)
		}

		right, err := commitment.NewPreimageFromLeaf(leaves[1])
		if err != nil {
			return nil, fmt.Errorf("error creating preimage from "+
				"leaf: %w", err)
		}

		return &TapscriptProof{
			TapPreimage1: left,
			TapPreimage2: right,
		}, nil

	// More than 3 branches, means both of the preimages are branches. We
	// use the default here because all other cases from 0 to 3 are covered
	// by explicit cases. We do this to retain the same order as in
	// DeriveTaprootKeys.
	//nolint:gocritic
	default:
		tree := txscript.AssembleTaprootScriptTree(leaves...)
		topLeft := tree.RootNode.Left()
		topRight := tree.RootNode.Right()

		topLeftBranch, ok := topLeft.(txscript.TapBranch)
		if !ok {
			return nil, fmt.Errorf("expected left node to be a "+
				"branch, got %T", topLeft)
		}
		leftPreimage := commitment.NewPreimageFromBranch(topLeftBranch)

		topRightBranch, ok := topRight.(txscript.TapBranch)
		if !ok {
			return nil, fmt.Errorf("expected right node to be a "+
				"branch, got %T", topRight)
		}
		rightPreimage := commitment.NewPreimageFromBranch(
			topRightBranch,
		)

		return &TapscriptProof{
			TapPreimage1: &leftPreimage,
			TapPreimage2: &rightPreimage,
		}, nil

	case 3:
		// Three leaves is a bit special. The AssembleTaprootScriptTree
		// method puts the sole, third leaf to the right. But we need to
		// specify the single leaf as a leaf preimage in the
		// TapscriptProof. So we'll swap things below.
		tree := txscript.AssembleTaprootScriptTree(leaves...)
		topLeft := tree.RootNode.Left()
		topRight := tree.RootNode.Right()

		topLeftBranch, ok := topLeft.(txscript.TapBranch)
		if !ok {
			return nil, fmt.Errorf("expected left node to be a "+
				"branch, got %T", topLeft)
		}
		leftPreimage := commitment.NewPreimageFromBranch(topLeftBranch)

		topRightLeaf, ok := topRight.(txscript.TapLeaf)
		if !ok {
			return nil, fmt.Errorf("expected right node to be a "+
				"leaf, got %T", topRight)
		}
		rightPreimage, err := commitment.NewPreimageFromLeaf(
			topRightLeaf,
		)
		if err != nil {
			return nil, fmt.Errorf("error creating preimage from "+
				"leaf: %w", err)
		}

		return &TapscriptProof{
			TapPreimage1: rightPreimage,
			TapPreimage2: &leftPreimage,
		}, nil

	// Just a single leaf, means the first preimage is a leaf.
	case 1:
		preimage, err := commitment.NewPreimageFromLeaf(leaves[0])
		if err != nil {
			return nil, fmt.Errorf("error creating preimage from "+
				"leaf: %w", err)
		}

		return &TapscriptProof{
			TapPreimage1: preimage,
		}, nil

	// No leaves, means this is a BIP-0086 output.
	case 0:
		return &TapscriptProof{
			Bip86: true,
		}, nil
	}
}
