package asset

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/pedersen"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
)

// GroupKeyVersion denotes the version of the group key construction.
type GroupKeyVersion uint8

const (
	// GroupKeyV0 is the initial version of the group key where the group
	// internal key is tweaked with the group anchor's asset ID.
	GroupKeyV0 GroupKeyVersion = 0

	// GroupKeyV1 is the version of the group key that uses a construction
	// that is compatible with PSBT signing where the group anchor's asset
	// ID is appended as a sibling to any user-provided tapscript tree.
	GroupKeyV1 GroupKeyVersion = 1
)

// NewGroupKeyVersion creates a new GroupKeyVersion from an int32. This
// function is useful for decoding GroupKeyVersions from the SQL database.
func NewGroupKeyVersion(v int32) (GroupKeyVersion, error) {
	if v > math.MaxUint8 {
		return 0, fmt.Errorf("invalid group key version: %d", v)
	}

	return GroupKeyVersion(v), nil
}

// GroupKey is the tweaked public key that is used to associate assets together
// across distinct asset IDs, allowing further issuance of the asset to be made
// possible.
type GroupKey struct {
	// Version is the version of the group key construction.
	Version GroupKeyVersion

	// RawKey is the raw group key before the tweak with the genesis point
	// has been applied.
	RawKey keychain.KeyDescriptor

	// GroupPubKey is the tweaked public key that is used to associate
	// assets together across distinct asset IDs, allowing further issuance
	// of the asset to be made possible.
	//
	// The precise construction of this key depends on the version of the
	// group key construction.
	GroupPubKey btcec.PublicKey

	// TapscriptRoot represents the root of the Tapscript tree that commits
	// to all script spend conditions associated with the group key. Instead
	// of simply authorizing asset spending, these scripts enable more
	// complex witness mechanisms beyond a Schnorr signature, allowing for
	// reissuance of assets. A group key with an empty Tapscript root can
	// only authorize reissuance using a signature.
	//
	// In the V1 group key construction, this root is never empty. It always
	// includes two layers of script leaves that commit to the group
	// anchor's (genesis) asset ID, ensuring any user-provided Tapscript
	// root is positioned at level 2.
	TapscriptRoot []byte

	// CustomTapscriptRoot is an optional tapscript root to graft at the
	// second level of the tapscript tree, if specified.
	CustomTapscriptRoot fn.Option[chainhash.Hash]

	// Witness is a stack of witness elements that authorizes the membership
	// of an asset in a particular asset group. The witness can be a single
	// signature or a script from the tapscript tree committed to with the
	// TapscriptRoot, and follows the witness rules in BIP-341.
	Witness wire.TxWitness
}

// GroupKeyRequest contains the essential fields used to derive a group key.
type GroupKeyRequest struct {
	// Version is the version of the group key construction.
	Version GroupKeyVersion

	// RawKey is the raw group key before the tweak with the genesis point
	// has been applied.
	RawKey keychain.KeyDescriptor

	// ExternalKey specifies a public key that, when provided, is used to
	// externally sign the group virtual transaction outside of tapd.
	//
	// If this field is set, RawKey is not used.
	ExternalKey fn.Option[ExternalKey]

	// AnchorGen is the genesis of the group anchor, which is the asset used
	// to derive the single tweak for the group key. For a new group key,
	// this will be the genesis of the new asset.
	AnchorGen Genesis

	// TapscriptRoot is the root of a Tapscript tree that includes script
	// spend conditions for the group key. A group key with an empty
	// Tapscript root can only authorize re-issuance with a signature. This
	// is the root of any user-defined scripts. For a V1 group key
	// construction the final tapscript root will never be empty.
	TapscriptRoot []byte

	// CustomTapscriptRoot is an optional tapscript root to graft at the
	// second level of the tapscript tree, if specified.
	CustomTapscriptRoot fn.Option[chainhash.Hash]

	// NewAsset is the asset which we are requesting group membership for.
	// A successful request will produce a witness that authorizes this
	// asset to be a member of this asset group.
	NewAsset *Asset
}

// NewGroupKeyV1FromExternal creates a new V1 group key from an external key and
// asset ID. The customRootHash is optional and can be used to specify a custom
// tapscript root.
func NewGroupKeyV1FromExternal(version NonSpendLeafVersion,
	externalKey ExternalKey, assetID ID,
	customRoot fn.Option[chainhash.Hash]) (btcec.PublicKey, chainhash.Hash,
	error) {

	var (
		zeroHash   chainhash.Hash
		zeroPubKey btcec.PublicKey
	)

	internalKey, err := externalKey.PubKey()
	if err != nil {
		return zeroPubKey, zeroHash, fmt.Errorf("cannot derive group "+
			"internal key from provided external key "+
			"(e.g. xpub): %w", err)
	}

	root, _, err := NewGroupKeyTapscriptRoot(version, assetID, customRoot)
	if err != nil {
		return zeroPubKey, zeroHash, fmt.Errorf("cannot derive group "+
			"key reveal tapscript root: %w", err)
	}

	groupPubKey, err := GroupPubKeyV1(&internalKey, root, assetID)
	if err != nil {
		return zeroPubKey, zeroHash, fmt.Errorf("cannot derive group "+
			"public key: %w", err)
	}

	return *groupPubKey, root.root, nil
}

// GroupVirtualTx contains all the information needed to produce an asset group
// witness, except for the group internal key descriptor (or private key). A
// GroupVirtualTx is constructed from a GroupKeyRequest.
type GroupVirtualTx struct {
	// Tx is a virtual transaction that represents the genesis state
	// transition of a grouped asset.
	Tx wire.MsgTx

	// PrevOut is a transaction output that represents a grouped asset.
	// PrevOut uses the tweaked group key as its PkScript. This is used in
	// combination with GroupVirtualTx.Tx as input for a GenesisSigner.
	PrevOut wire.TxOut

	// GenID is the asset ID of the grouped asset in a GroupKeyRequest. This
	// ID is needed to construct a sign descriptor for a GenesisSigner, as
	// it is the single tweak for the group internal key.
	GenID ID

	// TweakedKey is the tweaked group key for the given GroupKeyRequest.
	// This is later used to construct a complete GroupKey, after a
	// GenesisSigner has produced an asset group witness.
	TweakedKey btcec.PublicKey
}

// GroupKeyReveal represents the data used to derive the adjusted key that
// uniquely identifies an asset group.
type GroupKeyReveal interface {
	// Encode encodes the group key reveal into a writer.
	Encode(w io.Writer) error

	// Decode decodes the group key reveal from a reader.
	Decode(r io.Reader, buf *[8]byte, l uint64) error

	// RawKey returns the raw key of the group key reveal.
	RawKey() SerializedKey

	// SetRawKey sets the raw key of the group key reveal.
	SetRawKey(SerializedKey)

	// TapscriptRoot returns the tapscript root of the group key reveal.
	TapscriptRoot() []byte

	// SetTapscriptRoot sets the tapscript root of the group key reveal.
	SetTapscriptRoot([]byte)

	// GroupPubKey returns the group public key derived from the group key
	// reveal.
	GroupPubKey(assetID ID) (*btcec.PublicKey, error)
}

// NewNonSpendableScriptLeaf creates a new non-spendable tapscript script leaf
// that includes the specified data. If the data is nil, the leaf will not
// contain any data but will still be a valid non-spendable script leaf.
//
// The script leaf is made non-spendable by including an OP_RETURN at the start
// of the script (or an OP_CHECKSIG at the end, depending on the version). While
// the script can still be executed, it will always fail and cannot be used to
// spend funds.
func NewNonSpendableScriptLeaf(version NonSpendLeafVersion,
	data []byte) (txscript.TapLeaf, error) {

	var builder *txscript.ScriptBuilder
	switch version {
	// For the OP_RETURN based version, we'll use a single OP_RETURN opcode.
	case OpReturnVersion:
		builder = txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN)
		if data != nil {
			builder = builder.AddData(data)
		}

	// For the Pedersen commitment based version, we'll use a single
	// OP_CEHCKSIG with an un-spendable key.
	case PedersenVersion:
		// Make sure we don't accidentally truncate the data.
		if len(data) > sha256.Size {
			return txscript.TapLeaf{}, fmt.Errorf("data too large")
		}

		var msg [sha256.Size]byte
		copy(msg[:], data)

		_, commitPoint, err := TweakedNumsKey(msg)
		if err != nil {
			return txscript.TapLeaf{}, fmt.Errorf("failed to "+
				"derive tweaked NUMS key: %w", err)
		}

		commitBytes := schnorr.SerializePubKey(commitPoint)
		builder = txscript.NewScriptBuilder().AddData(commitBytes).
			AddOp(txscript.OP_CHECKSIG)

	default:
		return txscript.TapLeaf{}, fmt.Errorf("unknown "+
			"version %v", version)
	}

	// Construct script from the script builder.
	script, err := builder.Script()
	if err != nil {
		return txscript.TapLeaf{}, fmt.Errorf("failed to construct "+
			"non-spendable script: %w", err)
	}

	// Create a new tapscript leaf from the script.
	leaf := txscript.NewBaseTapLeaf(script)
	return leaf, nil
}

// GroupKeyRevealTlvType represents the different TLV types for GroupKeyReveal
// TLV records.
type GroupKeyRevealTlvType = tlv.Type

const (
	GKRVersion           GroupKeyRevealTlvType = 0
	GKRInternalKey       GroupKeyRevealTlvType = 2
	GKRTapscriptRoot     GroupKeyRevealTlvType = 4
	GKRCustomSubtreeRoot GroupKeyRevealTlvType = 7
)

func NewGKRVersionRecord(version *uint8) tlv.Record {
	return tlv.MakePrimitiveRecord(GKRVersion, version)
}

func NewGKRInternalKeyRecord(internalKey *SerializedKey) tlv.Record {
	return tlv.MakePrimitiveRecord(GKRInternalKey, (*[33]byte)(internalKey))
}

func NewGKRTapscriptRootRecord(root *chainhash.Hash) tlv.Record {
	return tlv.MakePrimitiveRecord(GKRTapscriptRoot, (*[32]byte)(root))
}

func NewGKRCustomSubtreeRootRecord(root *chainhash.Hash) tlv.Record {
	return tlv.MakePrimitiveRecord(GKRCustomSubtreeRoot, (*[32]byte)(root))
}

// NumsXPub turns the given NUMS key into an extended public key (using the x
// coordinate of the public key as the chain code), then derives the actual key
// to use from the derivation path 0/0. The extended key always has the mainnet
// version, but can be converted to any network on demand by the caller with
// CloneWithVersion().
func NumsXPub(numsKey btcec.PublicKey) (*hdkeychain.ExtendedKey,
	*btcec.PublicKey, error) {

	keyBytes := numsKey.SerializeCompressed()
	chainCode := keyBytes[1:]

	// We use a depth of 3, emulating BIP44/49/84/86 style derivation for
	// xpubs. We also always use mainnet to not require the caller to pass
	// in the net params. Converting to another network is possible with
	// CloneWithVersion().
	const depth = 3
	extendedNumsKey := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], keyBytes, chainCode,
		[]byte{0, 0, 0, 0}, depth, 0, false,
	)

	// Derive the actual key to use from the xpub.
	changeBranch, err := extendedNumsKey.Derive(0)
	if err != nil {
		return nil, nil, err
	}

	indexBranch, err := changeBranch.Derive(0)
	if err != nil {
		return nil, nil, err
	}

	actualKey, err := indexBranch.ECPubKey()
	if err != nil {
		return nil, nil, err
	}

	return extendedNumsKey, actualKey, nil
}

// TweakedNumsKey derives the NUMS key from the given data, then creates the
// extended key from it and derives the actual (derived child) key to use from
// the derivation path 0/0. The extended key always has the mainnet version, but
// can be converted to any network on demand by the caller with
// CloneWithVersion().
func TweakedNumsKey(msg [32]byte) (*hdkeychain.ExtendedKey, *btcec.PublicKey,
	error) {

	// Make a Pedersen opening that uses no mask (we don't carry on
	// the random value, as we don't care about hiding here). We'll
	// also use the existing NUMs point.
	op := pedersen.Opening{
		Msg: msg,
	}
	commitPoint := pedersen.NewCommitment(op).Point()

	return NumsXPub(commitPoint)
}

// GroupKeyRevealTapscript holds data used to derive the tapscript root, which
// is then used to calculate the asset group key.
//
// More broadly, the asset group key is the Taproot output key, derived using
// the standard formula:
//
//	outputKey = internalKey + TapTweak(internalKey || tapscriptRoot) * G
//
// This formula demonstrates that the asset group key (Taproot output key)
// commits to both the internal key and the tapscript tree root hash.
//
// By design, the tapscript root commits to a single genesis asset ID, which
// ensures that the asset group key also commits to the same unique genesis
// asset ID. This prevents asset group keys from being reused across different
// genesis assets or non-compliant asset minting tranches (e.g., tranches of
// a different asset type).
//
// The tapscript tree is formulated to guarantee that only one recognizable
// genesis asset ID can exist in the tree. The ID is uniquely placed in the
// first leaf layer, which contains exactly two nodes: the ID leaf and its
// sibling (if present). The sibling node is deliberately constructed to ensure
// it cannot be mistaken for a genesis asset ID leaf.
//
// The sibling node, `[tweaked_custom_branch]`, of the genesis asset ID leaf is
// a branch node by design and is only required if the user wants to use custom
// scripts. It serves two purposes:
//  1. It ensures that only one genesis asset ID leaf can exist in the first
//     layer, as it is not a valid genesis asset ID leaf.
//  2. It optionally supports user-defined script spending leaves, enabling
//     flexibility for custom tapscript subtrees.
//
// User-defined script spending leaves are nested under
// `[tweaked_custom_branch]` as a single node hash, `custom_root_hash`. This
// hash may represent either a single leaf or the root hash of an entire
// subtree.
//
// A sibling node is included alongside the `custom_root_hash` node. This
// sibling is a non-spendable script leaf containing `non_spend()`. Its
// presence ensures that one of the two positions in the first layer of the
// tapscript tree is occupied by a branch node. Due to the pre-image
// resistance of SHA-256, this prevents the existence of a second recognizable
// genesis asset ID leaf.
//
// The final tapscript tree adopts the following structure:
//
//	                       [tapscript_root]
//	                         /          \
//	[non_spend(<genesis asset ID>)]   [tweaked_custom_branch]
//	                                      /        \
//	                              [non_spend()]   <custom_root_hash>
//
// Where:
//   - [tapscript_root] is the root of the final tapscript tree.
//   - [non_spend(<genesis asset ID>)] is a first-layer non-spendable script
//     leaf that commits to the genesis asset ID.
//   - [tweaked_custom_branch] is a branch node that serves two purposes:
//     1. It cannot be misinterpreted as a genesis asset ID leaf.
//     2. It optionally includes user-defined script spending leaves.
//   - <custom_root_hash> is the root hash of the custom tapscript subtree.
//     If not specified, the whole right branch [tweaked_custom_branch] is
//     omitted (see below).
//   - non_spend(data) is a non-spendable script leaf that contains the data
//     argument. The data can be nil/empty in which case, the un-spendable
//     script doesn't commit to the data. Its presence ensures that
//     [tweaked_custom_branch] remains a branch node and cannot be a valid
//     genesis asset ID leaf. Two non-spendable script leaves are possible:
//   - One that uses an OP_RETURN to create a script that will "return
//     early" and terminate the script execution.
//   - One that uses a normal OP_CHECKSIG operator where the pubkey
//     argument is a key that cannot be signed with. We generate this
//     special public key using a Pedersen commitment, where the message is
//     the asset ID (or 32 all-zero bytes in case data is nil/empty). To achieve
//     hardware wallet support, that key is then turned into an extended key
//     (xpub) and a child key at path 0/0 is used as the actual public key that
//     goes into the OP_CHECKSIG script.
//
// If `custom_root_hash` is not provided, then there is no sibling to the asset
// ID leaf, meaning the tree only has a single leaf. This makes it possible to
// turn the single asset ID leaf into a miniscript policy, either using
// raw(hex(OP_RETURN <asset_id>)) or pk(<Pedersen commitment key>).
// The final tapscript tree with no custom scripts adopts the following
// structure:
//
//	      [tapscript_root]
//	             |
//	[non_spend(<genesis asset ID>)]
//
// Where:
//   - [tapscript_root] is the root of the final tapscript tree.
//   - [non_spend(<genesis asset ID>)] is a first-layer non-spendable script
//     leaf that commits to the genesis asset ID.
//   - non_spend(data) is a non-spendable script leaf that contains the data
//     argument. The data can be nil/empty in which case, the un-spendable
//     script doesn't commit to the data. Its presence ensures that
//     [tweaked_custom_branch] remains a branch node and cannot be a valid
//     genesis asset ID leaf. Two non-spendable script leaves are possible:
//   - One that uses an OP_RETURN to create a script that will "return
//     early" and terminate the script execution.
//   - One that uses a normal OP_CHECKSIG operator where the pubkey
//     argument is a key that cannot be signed with. We generate this
//     special public key using a Pedersen commitment, where the message is
//     the asset ID (or 32 all-zero bytes in case data is nil/empty). To
//     achieve hardware wallet support, that key is then turned into an extended
//     key (xpub) and a child key at path 0/0 is used as the actual public key
//     that goes into the OP_CHECKSIG script.
type GroupKeyRevealTapscript struct {
	// version is the version of the group key reveal that determines how
	// the non-spendable leaf is created.
	version NonSpendLeafVersion

	// root is the final tapscript root after all tapscript tweaks have
	// been applied. The asset group key is derived from this root and the
	// internal key.
	root chainhash.Hash

	// customSubtreeRoot is an optional root hash representing a
	// user-defined tapscript subtree that is integrated into the final
	// tapscript tree. This subtree may define script spending conditions
	// associated with the group key.
	customSubtreeRoot fn.Option[chainhash.Hash]
}

// NewGroupKeyTapscriptRoot computes the final tapscript root hash
// which is used to derive the asset group key. The final tapscript root
// hash is computed from the genesis asset ID and an optional custom tapscript
// subtree root hash.
func NewGroupKeyTapscriptRoot(version NonSpendLeafVersion, genesisAssetID ID,
	customRoot fn.Option[chainhash.Hash]) (GroupKeyRevealTapscript, []byte,
	error) {

	// First, we compute the tweaked custom branch hash. This hash is
	// derived by combining the hash of a non-spendable leaf and the root
	// hash of the custom tapscript subtree.
	//
	// If a custom tapscript subtree root hash is provided, we use it.
	// Otherwise, we default to an empty non-spendable leaf hash as well.
	emptyNonSpendLeaf, err := NewNonSpendableScriptLeaf(version, nil)
	if err != nil {
		return GroupKeyRevealTapscript{}, nil, err
	}

	// Next, we'll combine the tweaked custom branch hash with the genesis
	// asset ID leaf hash to compute the final tapscript root hash.
	//
	// Construct a non-spendable tapscript leaf for the genesis asset ID.
	assetIDLeaf, err := NewNonSpendableScriptLeaf(
		version, genesisAssetID[:],
	)
	if err != nil {
		return GroupKeyRevealTapscript{}, nil, err
	}

	// Compute the tweaked custom branch hash or leaf, depending on whether
	// we have a custom tapscript subtree root hash. We move the
	// un-spendable leaf to level 1 if there is no custom root hash. This is
	// mainly due to the fact that we require valid scripts in order to have
	// hardware wallet support. An empty leaf cannot be represented as a
	// list of scripts in a PSBT. That also means that custom scripts are
	// currently not compatible with miniscript policy based hardware
	// wallets.
	rootHash := assetIDLeaf.TapHash()
	customRoot.WhenSome(func(customRoot chainhash.Hash) {
		rightHash := TapBranchHash(
			emptyNonSpendLeaf.TapHash(), customRoot,
		)
		rootHash = TapBranchHash(assetIDLeaf.TapHash(), rightHash)
	})

	// Construct the custom subtree inclusion proof. This proof is required
	// to spend custom tapscript leaves in the tapscript tree.
	emptyNonSpendLeafHash := emptyNonSpendLeaf.TapHash()
	assetIDLeafHash := assetIDLeaf.TapHash()

	customSubtreeInclusionProof := bytes.Join([][]byte{
		emptyNonSpendLeafHash[:],
		assetIDLeafHash[:],
	}, nil)

	return GroupKeyRevealTapscript{
		version:           version,
		root:              rootHash,
		customSubtreeRoot: customRoot,
	}, customSubtreeInclusionProof, nil
}

// Validate checks that the group key reveal tapscript is well-formed and
// compliant.
func (g *GroupKeyRevealTapscript) Validate(assetID ID) error {
	// Compute the final tapscript root hash from the genesis asset ID and
	// the custom tapscript subtree root hash.
	tapscript, _, err := NewGroupKeyTapscriptRoot(
		g.version, assetID, g.customSubtreeRoot,
	)
	if err != nil {
		return fmt.Errorf("failed to compute tapscript root hash: %w",
			err)
	}

	// Ensure that the final tapscript root hash matches the computed root
	// hash.
	customRoot := g.customSubtreeRoot.UnwrapOr(chainhash.Hash{})

	if !g.root.IsEqual(&tapscript.root) {
		return fmt.Errorf("failed to derive tapscript root from "+
			"internal key, genesis asset ID, and "+
			"custom subtree root (expected_root=%s, "+
			"computed_root=%s, custom_subtree_root=%s, "+
			"genesis_asset_id=%x)",
			g.root, tapscript.root, customRoot, assetID[:])
	}

	return nil
}

// Root returns the final tapscript root hash of the group key reveal tapscript.
func (g *GroupKeyRevealTapscript) Root() chainhash.Hash {
	return g.root
}

// NonSpendLeafVersion is the version of the group key reveal.
//
// Version 1 is the original version that's based on an OP_RETURN.
//
// Version 2 is a follow-up version that instead uses a Pedersen commitment.
type NonSpendLeafVersion = uint8

const (
	// OpReturnVersion is the version of the group key reveal that uses an
	// OP_RETURN.
	OpReturnVersion NonSpendLeafVersion = 1

	// PedersenVersion is the version of the group key reveal that uses a
	// Pedersen commitment.
	PedersenVersion NonSpendLeafVersion = 2
)

// GroupKeyRevealV1 is a version 1 group key reveal type for representing the
// data used to derive and verify the tweaked key used to identify an asset
// group.
type GroupKeyRevealV1 struct {
	// version is the version of the group key reveal that determines how
	// the non-spendable leaf is created.
	version NonSpendLeafVersion

	// internalKey refers to the internal key used to derive the asset
	// group key. Typically, this internal key is the user's signing public
	// key.
	internalKey SerializedKey

	// tapscript is the tapscript tree that commits to the genesis asset ID
	// and any script spend conditions for the group key.
	tapscript GroupKeyRevealTapscript
}

// Ensure that GroupKeyRevealV1 implements the GroupKeyReveal interface.
var _ GroupKeyReveal = (*GroupKeyRevealV1)(nil)

// NewGroupKeyReveal creates a new group key reveal instance from the given
// group key and genesis asset ID.
func NewGroupKeyReveal(groupKey GroupKey, genesisAssetID ID) (GroupKeyReveal,
	error) {

	switch groupKey.Version {
	case GroupKeyV1:
		gkr, err := NewGroupKeyRevealV1(
			// TODO(guggero): Make this configurable in the future.
			PedersenVersion, *groupKey.RawKey.PubKey,
			genesisAssetID, groupKey.CustomTapscriptRoot,
		)
		if err != nil {
			return nil, err
		}

		return &gkr, nil

	case GroupKeyV0:
		rawKey := ToSerialized(groupKey.RawKey.PubKey)
		gkr := NewGroupKeyRevealV0(rawKey, groupKey.TapscriptRoot)
		return gkr, nil

	default:
		return nil, fmt.Errorf("unsupported group key version: %d",
			groupKey.Version)
	}
}

// NewGroupKeyRevealV1 creates a new version 1 group key reveal instance.
func NewGroupKeyRevealV1(version NonSpendLeafVersion,
	internalKey btcec.PublicKey, genesisAssetID ID,
	customRoot fn.Option[chainhash.Hash]) (GroupKeyRevealV1, error) {

	// Compute the final tapscript root.
	gkrTapscript, _, err := NewGroupKeyTapscriptRoot(
		version, genesisAssetID, customRoot,
	)
	if err != nil {
		return GroupKeyRevealV1{}, fmt.Errorf("failed to generate "+
			"group key reveal tapscript: %w", err)
	}

	return GroupKeyRevealV1{
		version:     version,
		internalKey: ToSerialized(&internalKey),
		tapscript:   gkrTapscript,
	}, nil
}

// ScriptSpendControlBlock returns the control block for the script spending
// path in the custom tapscript subtree.
func (g *GroupKeyRevealV1) ScriptSpendControlBlock(
	genesisAssetID ID) (txscript.ControlBlock, error) {

	internalKey, err := btcec.ParsePubKey(g.internalKey[:])
	if err != nil {
		return txscript.ControlBlock{}, fmt.Errorf("failed to parse "+
			"internal key: %w", err)
	}

	outputKey := txscript.ComputeTaprootOutputKey(
		internalKey, g.tapscript.root[:],
	)
	outputKeyIsOdd := outputKey.SerializeCompressed()[0] ==
		secp256k1.PubKeyFormatCompressedOdd

	// We now re-calculate the group key reveal tapscript root, which also
	// gives us the inclusion proof for the custom tapscript subtree.
	gkrTapscript, inclusionProof, err := NewGroupKeyTapscriptRoot(
		g.version, genesisAssetID, g.tapscript.customSubtreeRoot,
	)
	if err != nil {
		return txscript.ControlBlock{}, fmt.Errorf("failed to "+
			"generate tapscript artifacts: %w", err)
	}

	// Ensure that the computed tapscript root matches the expected
	// root.
	if !gkrTapscript.root.IsEqual(&g.tapscript.root) {
		return txscript.ControlBlock{}, fmt.Errorf("tapscript "+
			"root mismatch (expected=%s, computed=%s)",
			g.tapscript.root, gkrTapscript.root)
	}

	return txscript.ControlBlock{
		InternalKey:     internalKey,
		OutputKeyYIsOdd: outputKeyIsOdd,
		LeafVersion:     txscript.BaseLeafVersion,
		InclusionProof:  inclusionProof,
	}, nil
}

// Encode encodes the group key reveal into a writer.
//
// This encoding routine must ensure the resulting serialized bytes are
// sufficiently long to prevent the decoding routine from mistakenly using the
// wrong group key reveal version. Specifically, the raw key, tapscript root,
// and version fields must be properly populated.
func (g *GroupKeyRevealV1) Encode(w io.Writer) error {
	records := []tlv.Record{
		NewGKRVersionRecord(&g.version),
		NewGKRInternalKeyRecord(&g.internalKey),
		NewGKRTapscriptRootRecord(&g.tapscript.root),
	}

	// Add encode record for the custom tapscript root, if present.
	g.tapscript.customSubtreeRoot.WhenSome(func(hash chainhash.Hash) {
		records = append(records, NewGKRCustomSubtreeRootRecord(&hash))
	})

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes the group key reveal from a reader.
func (g *GroupKeyRevealV1) Decode(r io.Reader, buf *[8]byte, l uint64) error {
	var customSubtreeRoot chainhash.Hash

	tlvStream, err := tlv.NewStream(
		NewGKRVersionRecord(&g.version),
		NewGKRInternalKeyRecord(&g.internalKey),
		NewGKRTapscriptRootRecord(&g.tapscript.root),
		NewGKRCustomSubtreeRootRecord(&customSubtreeRoot),
	)
	if err != nil {
		return err
	}

	// Decode the reader's contents into the tlv stream.
	_, err = tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	// If the custom subtree root is not zero, set it on the group key
	// reveal.
	var zeroHash chainhash.Hash
	if customSubtreeRoot != zeroHash {
		g.tapscript.customSubtreeRoot =
			fn.Some[chainhash.Hash](customSubtreeRoot)
	}

	// Thread the version through to the reveal tapscript, which is needed
	// for the validation context.
	g.tapscript.version = g.version

	return nil
}

// Version returns the commitment version of the group key reveal V1.
func (g *GroupKeyRevealV1) Version() NonSpendLeafVersion {
	return g.version
}

// RawKey returns the raw key of the group key reveal.
func (g *GroupKeyRevealV1) RawKey() SerializedKey {
	return g.internalKey
}

// SetRawKey sets the raw key of the group key reveal.
func (g *GroupKeyRevealV1) SetRawKey(rawKey SerializedKey) {
	g.internalKey = rawKey
}

// TapscriptRoot returns the tapscript root of the group key reveal.
func (g *GroupKeyRevealV1) TapscriptRoot() []byte {
	return g.tapscript.root[:]
}

// SetTapscriptRoot sets the tapscript root of the group key reveal.
func (g *GroupKeyRevealV1) SetTapscriptRoot(tapscriptRootBytes []byte) {
	var tapscriptRoot chainhash.Hash
	copy(tapscriptRoot[:], tapscriptRootBytes)

	g.tapscript.root = tapscriptRoot
}

// CustomSubtreeRoot returns the custom subtree root hash of the group key
// reveal.
func (g *GroupKeyRevealV1) CustomSubtreeRoot() fn.Option[chainhash.Hash] {
	return g.tapscript.customSubtreeRoot
}

// GroupPubKey returns the group public key derived from the group key reveal.
func (g *GroupKeyRevealV1) GroupPubKey(assetID ID) (*btcec.PublicKey, error) {
	internalKey, err := g.RawKey().ToPubKey()
	if err != nil {
		return nil, fmt.Errorf("group reveal raw key invalid: %w", err)
	}

	return GroupPubKeyV1(internalKey, g.tapscript, assetID)
}

// GroupPubKeyV1 derives a version 1 asset group key from a signing public key
// and a tapscript tree.
func GroupPubKeyV1(internalKey *btcec.PublicKey,
	tapscriptTree GroupKeyRevealTapscript, assetID ID) (*btcec.PublicKey,
	error) {

	err := tapscriptTree.Validate(assetID)
	if err != nil {
		return nil, fmt.Errorf("group key reveal tapscript tree "+
			"invalid: %w", err)
	}

	tapOutputKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptTree.root[:],
	)
	return tapOutputKey, nil
}

// GroupKeyRevealV0 is a version 0 group key reveal type for representing the
// data used to derive the tweaked key used to identify an asset group. The
// final tweaked key is the result of: TapTweak(groupInternalKey, tapscriptRoot)
type GroupKeyRevealV0 struct {
	// RawKey is the public key that is tweaked twice to derive the final
	// tweaked group key. The final tweaked key is the result of:
	// internalKey = rawKey + singleTweak * G
	// tweakedGroupKey = TapTweak(internalKey, tapTweak)
	rawKey SerializedKey

	// TapscriptRoot is the root of the Tapscript tree that commits to all
	// script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets. This is either empty/nil or
	// a 32-byte hash.
	tapscriptRoot []byte
}

// Ensure that GroupKeyRevealV0 implements the GroupKeyReveal interface.
var _ GroupKeyReveal = (*GroupKeyRevealV0)(nil)

// NewGroupKeyRevealV0 creates a new version 0 group key reveal instance.
func NewGroupKeyRevealV0(rawKey SerializedKey,
	tapscriptRoot []byte) GroupKeyReveal {

	return &GroupKeyRevealV0{
		rawKey:        rawKey,
		tapscriptRoot: tapscriptRoot,
	}
}

// Encode encodes the group key reveal into the writer.
func (g *GroupKeyRevealV0) Encode(w io.Writer) error {
	// Define a placeholder scratch buffer which won't be used.
	var buf [8]byte

	// Encode the raw key into the writer.
	if err := SerializedKeyEncoder(w, &g.rawKey, &buf); err != nil {
		return err
	}

	// Encode the tapscript root into the writer.
	if err := tlv.EVarBytes(w, &g.tapscriptRoot, &buf); err != nil {
		return err
	}

	return nil
}

// Decode decodes the group key reveal from the reader.
func (g *GroupKeyRevealV0) Decode(r io.Reader, buf *[8]byte, l uint64) error {
	// Verify that the group key reveal is not excessively long. This check
	// is essential to prevent misinterpreting V1 and later group key
	// reveals as V0.
	switch {
	case l > btcec.PubKeyBytesLenCompressed+sha256.Size:
		return tlv.ErrRecordTooLarge
	case l < btcec.PubKeyBytesLenCompressed:
		return fmt.Errorf("group key reveal too short")
	}

	var rawKey SerializedKey
	err := SerializedKeyDecoder(
		r, &rawKey, buf, btcec.PubKeyBytesLenCompressed,
	)
	if err != nil {
		return err
	}

	remaining := l - btcec.PubKeyBytesLenCompressed
	var tapscriptRoot []byte
	err = tlv.DVarBytes(r, &tapscriptRoot, buf, remaining)
	if err != nil {
		return err
	}

	// Set fields now that decoding is complete.
	g.rawKey = rawKey
	g.tapscriptRoot = tapscriptRoot

	return nil
}

// RawKey returns the raw key of the group key reveal.
func (g *GroupKeyRevealV0) RawKey() SerializedKey {
	return g.rawKey
}

// SetRawKey sets the raw key of the group key reveal.
func (g *GroupKeyRevealV0) SetRawKey(rawKey SerializedKey) {
	g.rawKey = rawKey
}

// TapscriptRoot returns the tapscript root of the group key reveal.
func (g *GroupKeyRevealV0) TapscriptRoot() []byte {
	return g.tapscriptRoot
}

// SetTapscriptRoot sets the tapscript root of the group key reveal.
func (g *GroupKeyRevealV0) SetTapscriptRoot(tapscriptRoot []byte) {
	g.tapscriptRoot = tapscriptRoot
}

// GroupPubKey returns the group public key derived from the group key reveal.
func (g *GroupKeyRevealV0) GroupPubKey(assetID ID) (*btcec.PublicKey, error) {
	rawKey, err := g.RawKey().ToPubKey()
	if err != nil {
		return nil, fmt.Errorf("group reveal raw key invalid: %w", err)
	}

	return GroupPubKeyV0(rawKey, assetID[:], g.TapscriptRoot())
}

// GroupPubKeyV0 derives a version 0 tweaked group key from a public key and two
// tweaks; the single tweak is the asset ID of the group anchor asset, and the
// tapTweak is the root of a tapscript tree that commits to script-based
// conditions for reissuing assets as part of this asset group. The tweaked key
// is defined by:
//
//	internalKey = rawKey + singleTweak * G
//	tweakedGroupKey = TapTweak(internalKey, tapTweak)
func GroupPubKeyV0(rawKey *btcec.PublicKey, singleTweak, tapTweak []byte) (
	*btcec.PublicKey, error) {

	if len(singleTweak) != sha256.Size {
		return nil, fmt.Errorf("genesis tweak must be %d bytes",
			sha256.Size)
	}

	internalKey := input.TweakPubKeyWithTweak(rawKey, singleTweak)

	switch len(tapTweak) {
	case 0:
		return txscript.ComputeTaprootKeyNoScript(internalKey), nil

	case sha256.Size:
		return txscript.ComputeTaprootOutputKey(internalKey, tapTweak),
			nil

	default:
		return nil, fmt.Errorf("tapscript tweaks must be %d bytes",
			sha256.Size)
	}
}

// IsEqual returns true if this group key and signature are exactly equivalent
// to the passed other group key.
func (g *GroupKey) IsEqual(otherGroupKey *GroupKey) bool {
	if g == nil {
		return otherGroupKey == nil
	}

	if otherGroupKey == nil {
		return false
	}

	equalGroup := g.IsEqualGroup(otherGroupKey)
	if !equalGroup {
		return false
	}

	if !bytes.Equal(g.TapscriptRoot, otherGroupKey.TapscriptRoot) {
		return false
	}

	if len(g.Witness) != len(otherGroupKey.Witness) {
		return false
	}

	return slices.EqualFunc(g.Witness, otherGroupKey.Witness, bytes.Equal)
}

// IsEqualGroup returns true if this group key describes the same asset group
// as the passed other group key.
func (g *GroupKey) IsEqualGroup(otherGroupKey *GroupKey) bool {
	// If this key is nil, the other must be nil too.
	if g == nil {
		return otherGroupKey == nil
	}

	// This key is non nil, other must be non nil too.
	if otherGroupKey == nil {
		return false
	}

	// Make sure the RawKey are equivalent.
	if !EqualKeyDescriptors(g.RawKey, otherGroupKey.RawKey) {
		return false
	}

	return g.GroupPubKey.IsEqual(&otherGroupKey.GroupPubKey)
}

// IsLocal returns true if the private key that corresponds to this group key
// is held by this daemon. A non-local group key is stored with the internal key
// family and index set to their default values, 0.
func (g *GroupKey) IsLocal() bool {
	return g.RawKey.Family == TaprootAssetsKeyFamily
}

// hasAnnex returns true if the provided witness includes an annex element,
// otherwise returns false.
func hasAnnex(witness wire.TxWitness) bool {
	// By definition, the annex element can not be the sole element in the
	// witness stack.
	if len(witness) < 2 {
		return false
	}

	// If an annex element is included in the witness stack, by definition,
	// it will be the last element and will be prefixed by a Taproot annex
	// tag.
	lastElement := witness[len(witness)-1]
	if len(lastElement) == 0 {
		return false
	}

	return lastElement[0] == txscript.TaprootAnnexTag
}

// IsGroupSig checks if the given witness represents a key path spend of the
// tweaked group key. Such a witness must include one Schnorr signature, and
// can include an optional annex (matching the rules specified in BIP-341).
// If the signature is valid, IsGroupSig returns true and the parsed signature.
func IsGroupSig(witness wire.TxWitness) (*schnorr.Signature, bool) {
	if len(witness) == 0 || len(witness) > 2 {
		return nil, false
	}

	if len(witness[0]) != schnorr.SignatureSize {
		return nil, false
	}

	// If we have two witness elements and the first is a signature, the
	// second must be a valid annex.
	if len(witness) == 2 && !hasAnnex(witness) {
		return nil, false
	}

	groupSig, err := schnorr.ParseSignature(witness[0])
	if err != nil {
		return nil, false
	}

	return groupSig, true
}

// ParseGroupWitness parses a group witness that was stored as a TLV stream
// in the DB.
func ParseGroupWitness(witness []byte) (wire.TxWitness, error) {
	var (
		buf          [8]byte
		b            = bytes.NewReader(witness)
		witnessStack wire.TxWitness
	)

	err := TxWitnessDecoder(b, &witnessStack, &buf, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to parse group witness: %w", err)
	}

	return witnessStack, nil
}

// SerializeGroupWitness serializes a group witness into a TLV stream suitable
// for storing in the DB.
func SerializeGroupWitness(witness wire.TxWitness) ([]byte, error) {
	if len(witness) == 0 {
		return nil, fmt.Errorf("group witness cannot be empty")
	}

	var (
		buf [8]byte
		b   bytes.Buffer
	)

	err := TxWitnessEncoder(&b, &witness, &buf)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize group witness: %w",
			err)
	}

	return b.Bytes(), nil
}

// ParseGroupSig parses a group signature that was stored as a group witness in
// the DB. It returns an error if the witness is not a single Schnorr signature.
func ParseGroupSig(witness []byte) (*schnorr.Signature, error) {
	groupWitness, err := ParseGroupWitness(witness)
	if err != nil {
		return nil, err
	}

	groupSig, isSig := IsGroupSig(groupWitness)
	if !isSig {
		return nil, fmt.Errorf("group witness must be a single " +
			"Schnorr signature")
	}

	return groupSig, nil
}

// NewGroupKeyRequest constructs and validates a group key request.
func NewGroupKeyRequest(internalKey keychain.KeyDescriptor,
	externalKey fn.Option[ExternalKey], anchorGen Genesis,
	newAsset *Asset, tapscriptRoot []byte,
	customTapscriptRoot fn.Option[chainhash.Hash]) (*GroupKeyRequest,
	error) {

	// Specify the group key version based on the presence of an external
	// key.
	var version GroupKeyVersion
	if externalKey.IsSome() {
		version = GroupKeyV1
	}

	req := &GroupKeyRequest{
		Version:             version,
		RawKey:              internalKey,
		ExternalKey:         externalKey,
		AnchorGen:           anchorGen,
		NewAsset:            newAsset,
		TapscriptRoot:       tapscriptRoot,
		CustomTapscriptRoot: customTapscriptRoot,
	}

	err := req.Validate()
	if err != nil {
		return nil, err
	}

	return req, nil
}

// Validate ensures that the asset intended to be a member of an asset group is
// well-formed.
func (req *GroupKeyRequest) Validate() error {
	// Perform the final checks on the asset being authorized for group
	// membership.
	if req.NewAsset == nil {
		return fmt.Errorf("grouped asset cannot be nil")
	}

	// The asset in the request must have the default genesis asset witness,
	// and no group key. Those fields can only be populated after group
	// witness creation.
	if !req.NewAsset.HasGenesisWitness() {
		return fmt.Errorf("asset is not a genesis asset")
	}

	if req.NewAsset.GroupKey != nil {
		return fmt.Errorf("asset already has group key")
	}

	if req.AnchorGen.Type != req.NewAsset.Type {
		return fmt.Errorf("asset group type mismatch")
	}

	if req.RawKey.PubKey == nil {
		return fmt.Errorf("missing group internal key")
	}

	tapscriptRootSize := len(req.TapscriptRoot)
	if tapscriptRootSize != 0 && tapscriptRootSize != sha256.Size {
		return fmt.Errorf("tapscript root must be %d bytes",
			sha256.Size)
	}

	// Version 1 specific checks.
	if req.Version == GroupKeyV1 {
		tapscriptRoot, err := chainhash.NewHash(req.TapscriptRoot)
		if err != nil {
			return fmt.Errorf("version 1 group key request " +
				"tapscript root must be a valid hash")
		}

		if tapscriptRoot.IsEqual(&chainhash.Hash{}) {
			return fmt.Errorf("version 1 group key request " +
				"tapscript root must not be all zeros")
		}
	}

	if req.ExternalKey.IsSome() && req.Version != GroupKeyV1 {
		return fmt.Errorf("external key can only be specified for " +
			"version 1 group key request")
	}

	return nil
}

// NewGroupPubKey derives a group key for the asset group based on the group key
// request and the genesis asset ID.
func (req *GroupKeyRequest) NewGroupPubKey(genesisAssetID ID) (btcec.PublicKey,
	error) {

	// If the external key is not specified, we will construct a version 0
	// group key.
	if req.ExternalKey.IsNone() {
		// Compute the tweaked group key and set it in the asset before
		// creating the virtual minting transaction.
		groupPubKey, err := GroupPubKeyV0(
			req.RawKey.PubKey, genesisAssetID[:], req.TapscriptRoot,
		)
		if err != nil {
			return btcec.PublicKey{}, fmt.Errorf("cannot tweak "+
				"group key: %w", err)
		}

		return *groupPubKey, nil
	}

	// At this point, the external key should be specified. We will now
	// construct a new version 1 group key.
	externalKey, err := req.ExternalKey.UnwrapOrErr(
		fmt.Errorf("unexpected nil external key"),
	)
	if err != nil {
		return btcec.PublicKey{}, err
	}

	groupPubKey, _, err := NewGroupKeyV1FromExternal(
		// TODO(guggero): Make version configurable.
		PedersenVersion, externalKey, genesisAssetID,
		req.CustomTapscriptRoot,
	)
	if err != nil {
		return btcec.PublicKey{}, fmt.Errorf("cannot derive group "+
			"key: %w", err)
	}

	return groupPubKey, nil
}

// BuildGroupVirtualTx derives the tweaked group key for group key request,
// and constructs the group virtual TX needed to construct a sign descriptor and
// produce an asset group witness.
func (req *GroupKeyRequest) BuildGroupVirtualTx(genBuilder GenesisTxBuilder) (
	*GroupVirtualTx, error) {

	// First, perform the final checks on the asset being authorized for
	// group membership.
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	// Construct an asset group pub key.
	genesisAssetID := req.AnchorGen.ID()
	groupPubKey, err := req.NewGroupPubKey(genesisAssetID)
	if err != nil {
		return nil, fmt.Errorf("cannot derive group key: %w", err)
	}

	// Build the virtual transaction that represents the minting of the new
	// asset, which will be signed to generate the group witness.
	assetWithGroup := req.NewAsset.Copy()
	assetWithGroup.GroupKey = &GroupKey{
		GroupPubKey: groupPubKey,
	}

	genesisTx, prevOut, err := genBuilder.BuildGenesisTx(assetWithGroup)
	if err != nil {
		return nil, fmt.Errorf("cannot build virtual tx: %w", err)
	}

	return &GroupVirtualTx{
		Tx:         *genesisTx,
		PrevOut:    *prevOut,
		GenID:      genesisAssetID,
		TweakedKey: groupPubKey,
	}, nil
}

// AssembleGroupKeyFromWitness constructs a group key given a group witness
// generated externally.
func AssembleGroupKeyFromWitness(genTx GroupVirtualTx, req GroupKeyRequest,
	tapLeaf *psbt.TaprootTapLeafScript, scriptWitness []byte) (*GroupKey,
	error) {

	if scriptWitness == nil {
		return nil, fmt.Errorf("script witness cannot be nil")
	}

	groupKey := &GroupKey{
		RawKey:        req.RawKey,
		GroupPubKey:   genTx.TweakedKey,
		TapscriptRoot: req.TapscriptRoot,
		Witness:       wire.TxWitness{scriptWitness},
	}

	if tapLeaf != nil {
		if tapLeaf.LeafVersion != txscript.BaseLeafVersion {
			return nil, fmt.Errorf("unsupported script version")
		}

		groupKey.Witness = append(
			groupKey.Witness, tapLeaf.Script, tapLeaf.ControlBlock,
		)
	}

	return groupKey, nil
}

// DeriveGroupKey derives an asset's group key based on an internal public key
// descriptor, the original group asset genesis, and the asset's genesis.
func DeriveGroupKey(genSigner GenesisSigner, genTx GroupVirtualTx,
	req GroupKeyRequest, tapLeaf *psbt.TaprootTapLeafScript) (*GroupKey,
	error) {

	// Cannot derive the group key witness for an external key.
	if req.ExternalKey.IsSome() {
		return nil, fmt.Errorf("cannot derive group key witness for " +
			"group key with external key")
	}

	// Populate the signing descriptor needed to sign the virtual minting
	// transaction.
	signDesc := &lndclient.SignDescriptor{
		KeyDesc:     req.RawKey,
		SingleTweak: genTx.GenID[:],
		TapTweak:    req.TapscriptRoot,
		Output:      &genTx.PrevOut,
		HashType:    txscript.SigHashDefault,
		InputIndex:  0,
	}

	// There are three possible signing cases: BIP-0086 key spend path, key
	// spend path with a script root, and script spend path.
	switch {
	// If there is no tapscript root, we're doing a BIP-0086 key spend.
	case len(signDesc.TapTweak) == 0:
		signDesc.SignMethod = input.TaprootKeySpendBIP0086SignMethod

	// No leaf means we're not signing a specific script, so this is the key
	// spend path with a tapscript root.
	case len(signDesc.TapTweak) != 0 && tapLeaf == nil:
		signDesc.SignMethod = input.TaprootKeySpendSignMethod

	// One leaf hash and a merkle root means we're signing a specific
	// script.
	case len(signDesc.TapTweak) != 0 && tapLeaf != nil:
		signDesc.SignMethod = input.TaprootScriptSpendSignMethod
		signDesc.WitnessScript = tapLeaf.Script

	default:
		return nil, fmt.Errorf("bad sign descriptor for group key")
	}

	sig, err := genSigner.SignVirtualTx(signDesc, &genTx.Tx, &genTx.PrevOut)
	if err != nil {
		return nil, err
	}

	witness := wire.TxWitness{sig.Serialize()}

	// If this was a script spend, we also have to add the script itself and
	// the control block to the witness, otherwise the verifier will reject
	// the generated witness.
	if signDesc.SignMethod == input.TaprootScriptSpendSignMethod {
		witness = append(
			witness, signDesc.WitnessScript, tapLeaf.ControlBlock,
		)
	}

	return &GroupKey{
		Version:       GroupKeyV0,
		RawKey:        signDesc.KeyDesc,
		GroupPubKey:   genTx.TweakedKey,
		TapscriptRoot: signDesc.TapTweak,
		Witness:       witness,
	}, nil
}
