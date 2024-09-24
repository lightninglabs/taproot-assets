package taprpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/keychain"
)

// Shorthand for the asset transfer output proof delivery status enum.
//
// nolint: lll
var (
	ProofDeliveryStatusNotApplicable = ProofDeliveryStatus_PROOF_DELIVERY_STATUS_NOT_APPLICABLE
	ProofDeliveryStatusComplete      = ProofDeliveryStatus_PROOF_DELIVERY_STATUS_COMPLETE
	ProofDeliveryStatusPending       = ProofDeliveryStatus_PROOF_DELIVERY_STATUS_PENDING
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
func MarshalKeyDescriptor(desc keychain.KeyDescriptor) *KeyDescriptor {
	var rawKeyBytes []byte
	if desc.PubKey != nil {
		rawKeyBytes = desc.PubKey.SerializeCompressed()
	}

	return &KeyDescriptor{
		RawKeyBytes: rawKeyBytes,
		KeyLoc: &KeyLocator{
			KeyFamily: int32(desc.KeyLocator.Family),
			KeyIndex:  int32(desc.KeyLocator.Index),
		},
	}
}

// UnmarshalKeyDescriptor parses the RPC key descriptor into the native
// counterpart.
func UnmarshalKeyDescriptor(rpcDesc *KeyDescriptor) (keychain.KeyDescriptor,
	error) {

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
func UnmarshalScriptKey(rpcKey *ScriptKey) (*asset.ScriptKey, error) {
	var (
		scriptKey asset.ScriptKey
		err       error
	)

	// The script public key is a Taproot key, so 32-byte x-only.
	scriptKey.PubKey, err = schnorr.ParsePubKey(rpcKey.PubKey)
	if err != nil {
		return nil, err
	}

	// The key descriptor is optional for script keys that are completely
	// independent of the backing wallet.
	if rpcKey.KeyDesc != nil {
		keyDesc, err := UnmarshalKeyDescriptor(rpcKey.KeyDesc)
		if err != nil {
			return nil, err
		}
		scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
			RawKey: keyDesc,

			// The tweak is optional, if it's empty it means the key
			// is derived using BIP-0086.
			Tweak: rpcKey.TapTweak,
		}
	}

	return &scriptKey, nil
}

// MarshalScriptKey marshals the native script key into the RPC counterpart.
func MarshalScriptKey(scriptKey asset.ScriptKey) *ScriptKey {
	rpcScriptKey := &ScriptKey{
		PubKey: schnorr.SerializePubKey(scriptKey.PubKey),
	}

	if scriptKey.TweakedScriptKey != nil {
		rpcScriptKey.KeyDesc = MarshalKeyDescriptor(
			scriptKey.TweakedScriptKey.RawKey,
		)
		rpcScriptKey.TapTweak = scriptKey.TweakedScriptKey.Tweak
	}

	return rpcScriptKey
}

// UnmarshalAssetVersion parses an asset version from the RPC variant.
func UnmarshalAssetVersion(version AssetVersion) (asset.Version, error) {
	// For now, we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case AssetVersion_ASSET_VERSION_V0:
		return asset.V0, nil

	case AssetVersion_ASSET_VERSION_V1:
		return asset.V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalAssetVersion parses an asset version from the RPC variant.
func MarshalAssetVersion(version asset.Version) (AssetVersion, error) {
	// For now, we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case asset.V0:
		return AssetVersion_ASSET_VERSION_V0, nil

	case asset.V1:
		return AssetVersion_ASSET_VERSION_V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// UnmarshalAddressVerion parses an address version from the RPC variant.
func UnmarshalAddressVersion(version AddrVersion) (address.Version, error) {
	// For now we'll only support two address versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case AddrVersion_ADDR_VERSION_UNSPECIFIED:
		return address.V1, nil

	case AddrVersion_ADDR_VERSION_V0:
		return address.V0, nil

	case AddrVersion_ADDR_VERSION_V1:
		return address.V1, nil

	default:
		return 0, fmt.Errorf("unknown address version: %v", version)
	}
}

// MarshalAddressVerion marshals the native address version into the RPC
// variant.
func MarshalAddressVersion(version address.Version) (AddrVersion, error) {
	// For now we'll only support two address versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case address.V0:
		return AddrVersion_ADDR_VERSION_V0, nil

	case address.V1:
		return AddrVersion_ADDR_VERSION_V1, nil

	default:
		return 0, fmt.Errorf("unknown address version: %v", version)
	}
}

// MarshalGenesisInfo marshals the native asset genesis into the RPC
// counterpart.
func MarshalGenesisInfo(gen *asset.Genesis, assetType asset.Type) *GenesisInfo {
	return &GenesisInfo{
		GenesisPoint: gen.FirstPrevOut.String(),
		AssetType:    AssetType(assetType),
		Name:         gen.Tag,
		MetaHash:     gen.MetaHash[:],
		AssetId:      fn.ByteSlice(gen.ID()),
		OutputIndex:  gen.OutputIndex,
	}
}

// UnmarshalGenesisInfo parses an asset Genesis from the RPC variant.
func UnmarshalGenesisInfo(rpcGen *GenesisInfo) (*asset.Genesis, error) {
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
func UnmarshalTapscriptFullTree(tree *TapscriptFullTree) (
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
func UnmarshalTapscriptBranch(branch *TapBranch) (*asset.TapscriptTreeNodes,
	error) {

	branchData := [][]byte{branch.LeftTaphash, branch.RightTaphash}
	tapBranch, err := asset.DecodeTapBranchNodes(branchData)
	if err != nil {
		return nil, fmt.Errorf("invalid tapscript branch: %w", err)
	}

	return fn.Ptr(asset.FromBranch(*tapBranch)), nil
}

// UnmarshalTapscriptSibling parses a Tapscript sibling from the RPC variant.
func UnmarshalTapscriptSibling(rpcTree *TapscriptFullTree,
	rpcBranch *TapBranch) (fn.Option[asset.TapscriptTreeNodes], error) {

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
func UnmarshalGroupKeyRequest(req *GroupKeyRequest) (*asset.GroupKeyRequest,
	error) {

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

	return &asset.GroupKeyRequest{
		RawKey:        rawKey,
		AnchorGen:     *anchorGen,
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      &newAsset,
	}, nil
}

// MarshalGroupKeyRequest marshals the native group key request into the RPC
// counterpart.
func MarshalGroupKeyRequest(req *asset.GroupKeyRequest) (*GroupKeyRequest,
	error) {

	err := req.Validate()
	if err != nil {
		return nil, err
	}

	var assetBuf bytes.Buffer
	err = req.NewAsset.Encode(&assetBuf)
	if err != nil {
		return nil, err
	}

	return &GroupKeyRequest{
		RawKey: MarshalKeyDescriptor(req.RawKey),
		AnchorGenesis: MarshalGenesisInfo(
			&req.AnchorGen, req.NewAsset.Type,
		),
		TapscriptRoot: req.TapscriptRoot,
		NewAsset:      assetBuf.Bytes(),
	}, nil
}

// MarshalGroupVirtualTx marshals the native asset group virtual transaction
// into the RPC counterpart.
func MarshalGroupVirtualTx(genTx *asset.GroupVirtualTx) (*GroupVirtualTx,
	error) {

	var groupTxBuf bytes.Buffer
	err := genTx.Tx.Serialize(&groupTxBuf)
	if err != nil {
		return nil, err
	}

	rpcPrevOut := TxOut{
		Value:    genTx.PrevOut.Value,
		PkScript: genTx.PrevOut.PkScript,
	}

	return &GroupVirtualTx{
		Transaction: groupTxBuf.Bytes(),
		PrevOut:     &rpcPrevOut,
		GenesisId:   fn.ByteSlice(genTx.GenID),
		TweakedKey:  genTx.TweakedKey.SerializeCompressed(),
	}, nil
}

// UnmarshalGroupVirtualTx parses a group virtual transaction from the RPC
// variant.
func UnmarshalGroupVirtualTx(genTx *GroupVirtualTx) (*asset.GroupVirtualTx,
	error) {

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

// UnmarshalGroupWitness parses an asset group witness from the RPC variant.
func UnmarshalGroupWitness(wit *GroupWitness) (*asset.PendingGroupWitness,
	error) {

	if len(wit.GenesisId) != sha256.Size {
		return nil, fmt.Errorf("invalid genesis id length: "+
			"%d, %x", len(wit.GenesisId), wit.GenesisId)
	}

	// Assert that a given witness stack does not exceed the limit used by
	// the VM.
	witSize := 0
	for _, witItem := range wit.Witness {
		witSize += len(witItem)
	}

	if witSize > blockchain.MaxBlockWeight {
		return nil, fmt.Errorf("asset group witness too large: %d",
			witSize)
	}

	return &asset.PendingGroupWitness{
		GenID:   asset.ID(wit.GenesisId),
		Witness: wit.Witness,
	}, nil
}

// MarshalAsset converts an asset to its rpc representation.
func MarshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool, keyRing KeyLookup,
	decDisplay fn.Option[uint32]) (*Asset, error) {

	scriptKeyIsLocal := false
	if a.ScriptKey.TweakedScriptKey != nil && keyRing != nil {
		scriptKeyIsLocal = keyRing.IsLocalKey(
			ctx, a.ScriptKey.RawKey,
		)
	}

	assetVersion, err := MarshalAssetVersion(a.Version)
	if err != nil {
		return nil, err
	}

	scriptKeyBytes := a.ScriptKey.PubKey.SerializeCompressed()
	rpcAsset := &Asset{
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
	}

	decDisplay.WhenSome(func(u uint32) {
		rpcAsset.DecimalDisplay = &DecimalDisplay{
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
		rpcAsset.AssetGroup = &AssetGroup{
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
			rpcPrevID := &PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := MarshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true, nil, decDisplay,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
}

// MarshalAcceptedSellQuoteEvent marshals a peer accepted sell quote event to
// its rpc representation.
func MarshalAcceptedSellQuoteEvent(
	event *rfq.PeerAcceptedSellQuoteEvent) *rfqrpc.PeerAcceptedSellQuote {

	return &rfqrpc.PeerAcceptedSellQuote{
		Peer:        event.Peer.String(),
		Id:          event.ID[:],
		Scid:        uint64(event.ShortChannelId()),
		AssetAmount: event.Request.AssetAmount,
		BidPrice:    uint64(event.BidPrice),
		Expiry:      event.Expiry,
	}
}

// MarshalAcceptedBuyQuoteEvent marshals a peer accepted buy quote event to
// its rpc representation.
func MarshalAcceptedBuyQuoteEvent(
	event *rfq.PeerAcceptedBuyQuoteEvent) *rfqrpc.PeerAcceptedBuyQuote {

	return &rfqrpc.PeerAcceptedBuyQuote{
		Peer:        event.Peer.String(),
		Id:          event.ID[:],
		Scid:        uint64(event.ShortChannelId()),
		AssetAmount: event.Request.AssetAmount,
		AskAssetRate: &rfqrpc.FixedPoint{
			Coefficient: event.AssetRate.Coefficient.ToUint64(),
			Scale:       uint32(event.AssetRate.Scale),
		},
		Expiry: event.Expiry,
	}
}

// MarshalInvalidQuoteRespEvent marshals an invalid quote response event to
// its rpc representation.
func MarshalInvalidQuoteRespEvent(
	event *rfq.InvalidQuoteRespEvent) *rfqrpc.InvalidQuoteResponse {

	peer := event.QuoteResponse.MsgPeer()
	id := event.QuoteResponse.MsgID()

	return &rfqrpc.InvalidQuoteResponse{
		Status: rfqrpc.QuoteRespStatus(event.Status),
		Peer:   peer.String(),
		Id:     id[:],
	}
}

// MarshalIncomingRejectQuoteEvent marshals an incoming reject quote event to
// its RPC representation.
func MarshalIncomingRejectQuoteEvent(
	event *rfq.IncomingRejectQuoteEvent) *rfqrpc.RejectedQuoteResponse {

	return &rfqrpc.RejectedQuoteResponse{
		Peer:         event.Peer.String(),
		Id:           event.ID.Val[:],
		ErrorMessage: event.Err.Val.Msg,
		ErrorCode:    uint32(event.Err.Val.Code),
	}
}

// NewAddAssetBuyOrderResponse creates a new AddAssetBuyOrderResponse from
// the given RFQ event.
func NewAddAssetBuyOrderResponse(
	event fn.Event) (*rfqrpc.AddAssetBuyOrderResponse, error) {

	resp := &rfqrpc.AddAssetBuyOrderResponse{}

	switch e := event.(type) {
	case *rfq.PeerAcceptedBuyQuoteEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote{
			AcceptedQuote: MarshalAcceptedBuyQuoteEvent(e),
		}
		return resp, nil

	case *rfq.InvalidQuoteRespEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_InvalidQuote{
			InvalidQuote: MarshalInvalidQuoteRespEvent(e),
		}
		return resp, nil

	case *rfq.IncomingRejectQuoteEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_RejectedQuote{
			RejectedQuote: MarshalIncomingRejectQuoteEvent(e),
		}
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown AddAssetBuyOrder event "+
			"type: %T", e)
	}
}

// NewAddAssetSellOrderResponse creates a new AddAssetSellOrderResponse from
// the given RFQ event.
func NewAddAssetSellOrderResponse(
	event fn.Event) (*rfqrpc.AddAssetSellOrderResponse, error) {

	resp := &rfqrpc.AddAssetSellOrderResponse{}

	switch e := event.(type) {
	case *rfq.PeerAcceptedSellQuoteEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_AcceptedQuote{
			AcceptedQuote: MarshalAcceptedSellQuoteEvent(e),
		}
		return resp, nil

	case *rfq.InvalidQuoteRespEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_InvalidQuote{
			InvalidQuote: MarshalInvalidQuoteRespEvent(e),
		}
		return resp, nil

	case *rfq.IncomingRejectQuoteEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_RejectedQuote{
			RejectedQuote: MarshalIncomingRejectQuoteEvent(e),
		}
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown AddAssetSellOrder event "+
			"type: %T", e)
	}
}
