package rpcutils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest"
)

// Shorthand for the asset transfer output proof delivery status enum.
//
// nolint: lll
var (
	ProofDeliveryStatusNotApplicable = taprpc.ProofDeliveryStatus_PROOF_DELIVERY_STATUS_NOT_APPLICABLE
	ProofDeliveryStatusComplete      = taprpc.ProofDeliveryStatus_PROOF_DELIVERY_STATUS_COMPLETE
	ProofDeliveryStatusPending       = taprpc.ProofDeliveryStatus_PROOF_DELIVERY_STATUS_PENDING
)

// KeyLookup is used to determine whether a key is under the control of the
// local wallet.
type KeyLookup interface {
	// IsLocalKey returns true if the key is under the control of the
	// wallet and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}

// MarshalKeyDescriptor marshals the native key descriptor into the RPC
// counterpart.
func MarshalKeyDescriptor(desc keychain.KeyDescriptor) *taprpc.KeyDescriptor {
	var rawKeyBytes []byte
	if desc.PubKey != nil {
		rawKeyBytes = desc.PubKey.SerializeCompressed()
	}

	return &taprpc.KeyDescriptor{
		RawKeyBytes: rawKeyBytes,
		KeyLoc: &taprpc.KeyLocator{
			KeyFamily: int32(desc.KeyLocator.Family),
			KeyIndex:  int32(desc.KeyLocator.Index),
		},
	}
}

// UnmarshalKeyDescriptor parses the RPC key descriptor into the native
// counterpart.
func UnmarshalKeyDescriptor(
	rpcDesc *taprpc.KeyDescriptor) (keychain.KeyDescriptor, error) {

	var (
		desc keychain.KeyDescriptor
		err  error
	)

	// The public key of a key descriptor is mandatory. It is enough to
	// locate the corresponding private key in the backing wallet. But to
	// speed things up (and for additional context), the locator should
	// still be provided if available.
	desc.PubKey, err = btcec.ParsePubKey(rpcDesc.RawKeyBytes)
	if err != nil {
		return desc, err
	}

	if rpcDesc.KeyLoc != nil {
		desc.KeyLocator = keychain.KeyLocator{
			Family: keychain.KeyFamily(rpcDesc.KeyLoc.KeyFamily),
			Index:  uint32(rpcDesc.KeyLoc.KeyIndex),
		}
	}

	return desc, nil
}

// UnmarshalScriptKey parses the RPC script key into the native counterpart.
func UnmarshalScriptKey(rpcKey *taprpc.ScriptKey) (*asset.ScriptKey, error) {
	var (
		scriptKey = asset.ScriptKey{
			TweakedScriptKey: &asset.TweakedScriptKey{
				// The tweak is optional, if it's empty it means
				// the key is derived using BIP-0086.
				Tweak: rpcKey.TapTweak,
			},
		}
		err error
	)

	// The script public key is a Taproot key, so 32-byte x-only.
	scriptKey.PubKey, err = schnorr.ParsePubKey(rpcKey.PubKey)
	if err != nil {
		return nil, err
	}

	// The key descriptor is optional for script keys that are completely
	// independent of the backing wallet.
	if rpcKey.KeyDesc != nil {
		scriptKey.RawKey, err = UnmarshalKeyDescriptor(rpcKey.KeyDesc)
		if err != nil {
			return nil, err
		}
	}

	scriptKey.Type, err = UnmarshalScriptKeyType(rpcKey.Type)
	if err != nil {
		return nil, err
	}

	return &scriptKey, nil
}

// MarshalScriptKey marshals the native script key into the RPC counterpart.
func MarshalScriptKey(scriptKey asset.ScriptKey) *taprpc.ScriptKey {
	rpcScriptKey := &taprpc.ScriptKey{
		PubKey: schnorr.SerializePubKey(scriptKey.PubKey),
	}

	if scriptKey.TweakedScriptKey != nil {
		rpcScriptKey.KeyDesc = MarshalKeyDescriptor(
			scriptKey.TweakedScriptKey.RawKey,
		)
		rpcScriptKey.TapTweak = scriptKey.TweakedScriptKey.Tweak
		rpcScriptKey.Type = MarshalScriptKeyType(scriptKey.Type)
	}

	return rpcScriptKey
}

// UnmarshalScriptKeyType parses the script key type from the RPC variant.
func UnmarshalScriptKeyType(rpcType taprpc.ScriptKeyType) (asset.ScriptKeyType,
	error) {

	switch rpcType {
	case taprpc.ScriptKeyType_SCRIPT_KEY_UNKNOWN:
		return asset.ScriptKeyUnknown, nil

	case taprpc.ScriptKeyType_SCRIPT_KEY_BIP86:
		return asset.ScriptKeyBip86, nil

	case taprpc.ScriptKeyType_SCRIPT_KEY_SCRIPT_PATH_EXTERNAL:
		return asset.ScriptKeyScriptPathExternal, nil

	case taprpc.ScriptKeyType_SCRIPT_KEY_BURN:
		return asset.ScriptKeyBurn, nil

	case taprpc.ScriptKeyType_SCRIPT_KEY_TOMBSTONE:
		return asset.ScriptKeyTombstone, nil

	case taprpc.ScriptKeyType_SCRIPT_KEY_CHANNEL:
		return asset.ScriptKeyScriptPathChannel, nil

	default:
		return 0, fmt.Errorf("unknown script key type: %v", rpcType)
	}
}

// MarshalScriptKeyType marshals the script key type from the RPC variant.
func MarshalScriptKeyType(typ asset.ScriptKeyType) taprpc.ScriptKeyType {
	switch typ {
	case asset.ScriptKeyBip86:
		return taprpc.ScriptKeyType_SCRIPT_KEY_BIP86

	case asset.ScriptKeyScriptPathExternal:
		return taprpc.ScriptKeyType_SCRIPT_KEY_SCRIPT_PATH_EXTERNAL

	case asset.ScriptKeyBurn:
		return taprpc.ScriptKeyType_SCRIPT_KEY_BURN

	case asset.ScriptKeyTombstone:
		return taprpc.ScriptKeyType_SCRIPT_KEY_TOMBSTONE

	case asset.ScriptKeyScriptPathChannel:
		return taprpc.ScriptKeyType_SCRIPT_KEY_CHANNEL

	default:
		return taprpc.ScriptKeyType_SCRIPT_KEY_UNKNOWN
	}
}

// UnmarshalAssetVersion parses an asset version from the RPC variant.
func UnmarshalAssetVersion(version taprpc.AssetVersion) (asset.Version, error) {
	// For now, we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case taprpc.AssetVersion_ASSET_VERSION_V0:
		return asset.V0, nil

	case taprpc.AssetVersion_ASSET_VERSION_V1:
		return asset.V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalAssetVersion parses an asset version from the RPC variant.
func MarshalAssetVersion(version asset.Version) (taprpc.AssetVersion, error) {
	// For now, we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case asset.V0:
		return taprpc.AssetVersion_ASSET_VERSION_V0, nil

	case asset.V1:
		return taprpc.AssetVersion_ASSET_VERSION_V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalGenesisInfo marshals the native asset genesis into the RPC
// counterpart.
func MarshalGenesisInfo(gen *asset.Genesis,
	assetType asset.Type) *taprpc.GenesisInfo {

	return &taprpc.GenesisInfo{
		GenesisPoint: gen.FirstPrevOut.String(),
		AssetType:    taprpc.AssetType(assetType),
		Name:         gen.Tag,
		MetaHash:     gen.MetaHash[:],
		AssetId:      fn.ByteSlice(gen.ID()),
		OutputIndex:  gen.OutputIndex,
	}
}

// UnmarshalGenesisInfo parses an asset Genesis from the RPC variant.
func UnmarshalGenesisInfo(rpcGen *taprpc.GenesisInfo) (*asset.Genesis, error) {
	firstPrevOut, err := wire.NewOutPointFromString(rpcGen.GenesisPoint)
	if err != nil {
		return nil, err
	}

	if len(rpcGen.MetaHash) != sha256.Size {
		return nil, fmt.Errorf("meta hash must be %d bytes",
			sha256.Size)
	}

	return &asset.Genesis{
		FirstPrevOut: *firstPrevOut,
		Tag:          rpcGen.Name,
		MetaHash:     fn.ToArray[[32]byte](rpcGen.MetaHash),
		OutputIndex:  rpcGen.OutputIndex,
		Type:         asset.Type(rpcGen.AssetType),
	}, nil
}

// UnmarshalTapscriptFullTree parses a Tapscript tree from the RPC variant.
func UnmarshalTapscriptFullTree(tree *taprpc.TapscriptFullTree) (
	*asset.TapscriptTreeNodes, error) {

	rpcLeaves := tree.GetAllLeaves()
	leaves := make([]txscript.TapLeaf, len(rpcLeaves))

	// Check that none of the leaves are a Taproot Asset Commitment.
	for i, leaf := range rpcLeaves {
		if commitment.IsTaprootAssetCommitmentScript(leaf.Script) {
			return nil, fmt.Errorf("tapscript leaf is a Taproot " +
				"Asset Commitment")
		}

		leaves[i] = txscript.NewBaseTapLeaf(leaf.Script)
	}

	tapTreeNodes, err := asset.TapTreeNodesFromLeaves(leaves)
	if err != nil {
		return nil, fmt.Errorf("invalid tapscript tree: %w", err)
	}

	return tapTreeNodes, nil
}

// UnmarshalTapscriptBranch parses a Tapscript branch from the RPC variant.
func UnmarshalTapscriptBranch(
	branch *taprpc.TapBranch) (*asset.TapscriptTreeNodes, error) {

	branchData := [][]byte{branch.LeftTaphash, branch.RightTaphash}
	tapBranch, err := asset.DecodeTapBranchNodes(branchData)
	if err != nil {
		return nil, fmt.Errorf("invalid tapscript branch: %w", err)
	}

	return fn.Ptr(asset.FromBranch(*tapBranch)), nil
}

// UnmarshalTapscriptSibling parses a Tapscript sibling from the RPC variant.
func UnmarshalTapscriptSibling(rpcTree *taprpc.TapscriptFullTree,
	rpcBranch *taprpc.TapBranch) (fn.Option[asset.TapscriptTreeNodes],
	error) {

	var (
		tapSibling *asset.TapscriptTreeNodes
		err        error
	)
	switch {
	case rpcTree != nil && rpcBranch != nil:
		err = fmt.Errorf("cannot specify both tapscript tree and " +
			"tapscript tree branches")

	case rpcTree != nil:
		tapSibling, err = UnmarshalTapscriptFullTree(rpcTree)

	case rpcBranch != nil:
		tapSibling, err = UnmarshalTapscriptBranch(rpcBranch)
	}

	if err != nil {
		return fn.None[asset.TapscriptTreeNodes](), err
	}

	return fn.MaybeSome(tapSibling), nil
}

// UnmarshalGroupKeyRequest parses a group key request from the RPC variant.
func UnmarshalGroupKeyRequest(
	req *taprpc.GroupKeyRequest) (*asset.GroupKeyRequest, error) {

	rawKey, err := UnmarshalKeyDescriptor(req.RawKey)
	if err != nil {
		return nil, err
	}

	anchorGen, err := UnmarshalGenesisInfo(req.AnchorGenesis)
	if err != nil {
		return nil, err
	}

	if len(req.TapscriptRoot) != 0 &&
		len(req.TapscriptRoot) != sha256.Size {

		return nil, fmt.Errorf("tapscript root must be %d bytes",
			sha256.Size)
	}

	var newAsset asset.Asset
	err = newAsset.Decode(bytes.NewReader(req.NewAsset))
	if err != nil {
		return nil, err
	}

	var externalKey fn.Option[asset.ExternalKey]
	if req.ExternalKey != nil {
		key, err := UnmarshalExternalKey(req.ExternalKey)
		if err != nil {
			return nil, err
		}

		externalKey = fn.Some(key)
	}

	return &asset.GroupKeyRequest{
		RawKey:        rawKey,
		ExternalKey:   externalKey,
		AnchorGen:     *anchorGen,
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      &newAsset,
	}, nil
}

// MarshalGroupKeyRequest marshals the native group key request into the RPC
// counterpart.
func MarshalGroupKeyRequest(
	req *asset.GroupKeyRequest) (*taprpc.GroupKeyRequest, error) {

	err := req.Validate()
	if err != nil {
		return nil, err
	}

	var assetBuf bytes.Buffer
	err = req.NewAsset.Encode(&assetBuf)
	if err != nil {
		return nil, err
	}

	// Marshal the external key into the RPC format.
	externalKey := fn.MapOptionZ(req.ExternalKey, MarshalExternalKey)

	// Marshal raw key into RPC format.
	//
	// We only need to marshal the raw key if the external key is not set.
	var rawKey *taprpc.KeyDescriptor
	if req.ExternalKey.IsNone() {
		rawKey = MarshalKeyDescriptor(req.RawKey)
	}

	return &taprpc.GroupKeyRequest{
		RawKey: rawKey,
		AnchorGenesis: MarshalGenesisInfo(
			&req.AnchorGen, req.NewAsset.Type,
		),
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      assetBuf.Bytes(),
		ExternalKey:   externalKey,
	}, nil
}

// MarshalExternalKey marshals an external key into its RPC counterpart.
func MarshalExternalKey(key asset.ExternalKey) *taprpc.ExternalKey {
	var masterFingerprint [4]byte
	binary.LittleEndian.PutUint32(
		masterFingerprint[:], key.MasterFingerprint,
	)

	// The first three elements of the derivation path are hardened, so to
	// format we need to subtract the hardened key offset again.
	path := key.DerivationPath
	purpose := path[0] - hdkeychain.HardenedKeyStart
	coinType := path[1] - hdkeychain.HardenedKeyStart
	account := path[2] - hdkeychain.HardenedKeyStart
	internalExternalAddr := path[3]
	addrIndex := path[4]

	derivationPathStr := fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", purpose,
		coinType, account, internalExternalAddr, addrIndex)

	return &taprpc.ExternalKey{
		Xpub:              key.XPub.String(),
		MasterFingerprint: masterFingerprint[:],
		DerivationPath:    derivationPathStr,
	}
}

// UnmarshalExternalKey parses an external key from the RPC variant.
func UnmarshalExternalKey(rpcKey *taprpc.ExternalKey) (asset.ExternalKey,
	error) {

	if rpcKey == nil {
		return asset.ExternalKey{}, fmt.Errorf("unexpected nil RPC " +
			"external key")
	}

	// Parse xpub.
	xpub, err := hdkeychain.NewKeyFromString(rpcKey.Xpub)
	if err != nil {
		return asset.ExternalKey{}, err
	}

	// Parse derivation path.
	path, err := lntest.ParseDerivationPath(rpcKey.DerivationPath)
	if err != nil {
		return asset.ExternalKey{}, err
	}

	// We assume the first three elements of the derivation path are
	// hardened, so we need to add the hardened key offset.
	for i := 0; i < 3; i++ {
		path[i] += hdkeychain.HardenedKeyStart
	}

	// Parse master fingerprint.
	var masterFingerprint uint32
	if len(rpcKey.MasterFingerprint) > 0 {
		if len(rpcKey.MasterFingerprint) != 4 {
			return asset.ExternalKey{}, fmt.Errorf("master " +
				"fingerprint must be 4 bytes")
		}

		masterFingerprint = binary.LittleEndian.Uint32(
			rpcKey.MasterFingerprint,
		)
	}

	return asset.ExternalKey{
		XPub:              *xpub,
		MasterFingerprint: masterFingerprint,
		DerivationPath:    path,
	}, nil
}

// MarshalGroupVirtualTx marshals the native asset group virtual transaction
// into the RPC counterpart.
func MarshalGroupVirtualTx(genTx *asset.GroupVirtualTx) (*taprpc.GroupVirtualTx,
	error) {

	var groupTxBuf bytes.Buffer
	err := genTx.Tx.Serialize(&groupTxBuf)
	if err != nil {
		return nil, err
	}

	rpcPrevOut := taprpc.TxOut{
		Value:    genTx.PrevOut.Value,
		PkScript: genTx.PrevOut.PkScript,
	}

	return &taprpc.GroupVirtualTx{
		Transaction: groupTxBuf.Bytes(),
		PrevOut:     &rpcPrevOut,
		GenesisId:   fn.ByteSlice(genTx.GenID),
		TweakedKey:  genTx.TweakedKey.SerializeCompressed(),
	}, nil
}

// UnmarshalGroupVirtualTx parses a group virtual transaction from the RPC
// variant.
func UnmarshalGroupVirtualTx(
	genTx *taprpc.GroupVirtualTx) (*asset.GroupVirtualTx, error) {

	var virtualTx wire.MsgTx
	err := virtualTx.Deserialize(bytes.NewReader(genTx.Transaction))
	if err != nil {
		return nil, err
	}

	if genTx.PrevOut == nil {
		return nil, fmt.Errorf("prevout cannot be empty")
	}

	prevOut := wire.TxOut{
		Value:    genTx.PrevOut.Value,
		PkScript: genTx.PrevOut.PkScript,
	}
	if len(genTx.GenesisId) != sha256.Size {
		return nil, fmt.Errorf("genesis id must be %d bytes",
			sha256.Size)
	}

	tweakedKey, err := btcec.ParsePubKey(genTx.TweakedKey)
	if err != nil {
		return nil, err
	}

	return &asset.GroupVirtualTx{
		Tx:         virtualTx,
		PrevOut:    prevOut,
		GenID:      asset.ID(genTx.GenesisId),
		TweakedKey: *tweakedKey,
	}, nil
}

// MarshalChainAsset marshals a chain asset into its RPC counterpart.
func MarshalChainAsset(ctx context.Context, a asset.ChainAsset,
	decDisplay fn.Option[uint32], withWitness bool,
	keyRing KeyLookup) (*taprpc.Asset, error) {

	rpcAsset, err := MarshalAsset(
		ctx, a.Asset, a.IsSpent, withWitness, keyRing, decDisplay,
	)
	if err != nil {
		return nil, err
	}

	var anchorTxBytes []byte
	if a.AnchorTx != nil {
		var b bytes.Buffer
		err := a.AnchorTx.Serialize(&b)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize anchor "+
				"tx: %w", err)
		}
		anchorTxBytes = b.Bytes()
	}

	rpcAsset.ChainAnchor = &taprpc.AnchorInfo{
		AnchorTx:         anchorTxBytes,
		AnchorBlockHash:  a.AnchorBlockHash.String(),
		AnchorOutpoint:   a.AnchorOutpoint.String(),
		InternalKey:      a.AnchorInternalKey.SerializeCompressed(),
		MerkleRoot:       a.AnchorMerkleRoot,
		TapscriptSibling: a.AnchorTapscriptSibling,
		BlockHeight:      a.AnchorBlockHeight,
		BlockTimestamp:   a.AnchorBlockTimestamp,
	}

	if a.AnchorLeaseOwner != [32]byte{} {
		rpcAsset.LeaseOwner = a.AnchorLeaseOwner[:]
		rpcAsset.LeaseExpiry = a.AnchorLeaseExpiry.UTC().Unix()
	}

	return rpcAsset, nil
}

// MarshalAsset converts an asset to its rpc representation.
func MarshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool, keyRing KeyLookup,
	decDisplay fn.Option[uint32]) (*taprpc.Asset, error) {

	var (
		scriptKeyIsLocal = false
		scriptKeyType    = asset.ScriptKeyUnknown
	)
	if a.ScriptKey.TweakedScriptKey != nil {
		if keyRing != nil {
			scriptKeyIsLocal = keyRing.IsLocalKey(
				ctx, a.ScriptKey.RawKey,
			)
		}

		scriptKeyType = a.ScriptKey.Type
	}

	assetVersion, err := MarshalAssetVersion(a.Version)
	if err != nil {
		return nil, err
	}

	scriptKeyBytes := a.ScriptKey.PubKey.SerializeCompressed()
	rpcAsset := &taprpc.Asset{
		Version:                assetVersion,
		AssetGenesis:           MarshalGenesisInfo(&a.Genesis, a.Type),
		Amount:                 a.Amount,
		LockTime:               int32(a.LockTime),
		RelativeLockTime:       int32(a.RelativeLockTime),
		ScriptVersion:          int32(a.ScriptVersion),
		ScriptKey:              scriptKeyBytes,
		ScriptKeyIsLocal:       scriptKeyIsLocal,
		ScriptKeyDeclaredKnown: a.ScriptKey.DeclaredAsKnown(),
		ScriptKeyHasScriptPath: a.ScriptKey.HasScriptPath(),
		IsSpent:                isSpent,
		IsBurn:                 a.IsBurn(),
		ScriptKeyType:          MarshalScriptKeyType(scriptKeyType),
	}

	decDisplay.WhenSome(func(u uint32) {
		rpcAsset.DecimalDisplay = &taprpc.DecimalDisplay{
			DecimalDisplay: u,
		}
	})

	if a.GroupKey != nil {
		var (
			rawKey        []byte
			groupWitness  []byte
			tapscriptRoot []byte
			err           error
		)

		if a.GroupKey.RawKey.PubKey != nil {
			rawKey = a.GroupKey.RawKey.PubKey.SerializeCompressed()
		}
		if len(a.GroupKey.Witness) != 0 {
			groupWitness, err = asset.SerializeGroupWitness(
				a.GroupKey.Witness,
			)
			if err != nil {
				return nil, err
			}
		}
		if len(a.GroupKey.TapscriptRoot) != 0 {
			tapscriptRoot = a.GroupKey.TapscriptRoot[:]
		}
		rpcAsset.AssetGroup = &taprpc.AssetGroup{
			RawGroupKey: rawKey,
			TweakedGroupKey: a.GroupKey.GroupPubKey.
				SerializeCompressed(),
			AssetWitness:  groupWitness,
			TapscriptRoot: tapscriptRoot,
		}
	}

	if withWitness {
		for idx := range a.PrevWitnesses {
			witness := a.PrevWitnesses[idx]

			prevID := witness.PrevID
			rpcPrevID := &taprpc.PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *taprpc.SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := MarshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true, nil, decDisplay,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &taprpc.SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &taprpc.PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
}

// ParseScriptKeyTypeQuery parses the script key type query from the RPC
// variant.
func ParseScriptKeyTypeQuery(
	q *taprpc.ScriptKeyTypeQuery) (fn.Option[asset.ScriptKeyType], bool,
	error) {

	if q == nil || q.Type == nil {
		return fn.Some(asset.ScriptKeyBip86), false, nil
	}

	switch t := q.Type.(type) {
	case *taprpc.ScriptKeyTypeQuery_ExplicitType:
		explicitType, err := UnmarshalScriptKeyType(t.ExplicitType)
		if err != nil {
			return fn.None[asset.ScriptKeyType](), false, err
		}

		// Because burns and tombstones are not spendable, we always
		// insert them as "spent". So if the user wants to see any of
		// those keys, we need to toggle the "includeSpent" flag,
		// otherwise the result will always be empty.
		includeSpent := false
		switch explicitType {
		case asset.ScriptKeyTombstone, asset.ScriptKeyBurn:
			includeSpent = true

		default:
		}

		return fn.Some(explicitType), includeSpent, nil

	case *taprpc.ScriptKeyTypeQuery_AllTypes:
		return fn.None[asset.ScriptKeyType](), false, nil

	default:
		return fn.Some(asset.ScriptKeyBip86), false, nil
	}
}
