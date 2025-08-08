package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
)

// RpcSupplySync is an implementation of the universe.SupplySyncer interface
// that uses an RPC connection to target a remote universe server.
type RpcSupplySync struct {
	conn *universeClientConn
}

// NewRpcSupplySync creates a new RpcSupplySync instance that dials out to
// the target remote universe server address.
func NewRpcSupplySync(
	serverAddr universe.ServerAddr) (supplyverifier.UniverseClient, error) {

	conn, err := ConnectUniverse(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to universe RPC "+
			"server: %w", err)
	}

	return &RpcSupplySync{
		conn: conn,
	}, nil
}

// Ensure NewRpcSupplySync is of type UniverseClientFactory.
var _ supplyverifier.UniverseClientFactory = NewRpcSupplySync

// FetchSupplyLeaves fetches the supply leaves for a specific asset group
// within a specified block height range.
func (r *RpcSupplySync) FetchSupplyLeaves(ctx context.Context,
	assetSpec asset.Specifier, startBlockHeight,
	endBlockHeight fn.Option[uint32]) (supplycommit.SupplyLeaves,
	error) {

	var zero supplycommit.SupplyLeaves

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return zero, fmt.Errorf("unable to unwrap group key: %w", err)
	}

	req := &unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKey.SerializeCompressed(),
		},
		BlockHeightStart: startBlockHeight.UnwrapOr(0),
		BlockHeightEnd:   endBlockHeight.UnwrapOr(0),
	}

	resp, err := r.conn.FetchSupplyLeaves(ctx, req)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves: %w",
			err)
	}

	// Convert the RPC response into a SupplyLeaves instance.
	supplyLeaves := supplycommit.SupplyLeaves{
		IssuanceLeafEntries: make(
			[]supplycommit.NewMintEvent, 0,
			len(resp.IssuanceLeaves),
		),
		BurnLeafEntries: make(
			[]supplycommit.NewBurnEvent, 0, len(resp.BurnLeaves),
		),
		IgnoreLeafEntries: make(
			[]supplycommit.NewIgnoreEvent, 0,
			len(resp.IgnoreLeaves),
		),
	}

	for _, rpcLeaf := range resp.IssuanceLeaves {
		mintEvent, err := unmarshalMintSupplyLeaf(rpcLeaf)
		if err != nil {
			return zero, fmt.Errorf("unable to unmarshal mint "+
				"event: %w", err)
		}

		supplyLeaves.IssuanceLeafEntries = append(
			supplyLeaves.IssuanceLeafEntries, *mintEvent,
		)
	}

	for _, rpcLeaf := range resp.BurnLeaves {
		burnEvent, err := unmarshalBurnSupplyLeaf(rpcLeaf)
		if err != nil {
			return zero, fmt.Errorf("unable to unmarshal burn "+
				"event: %w", err)
		}

		supplyLeaves.BurnLeafEntries = append(
			supplyLeaves.BurnLeafEntries, *burnEvent,
		)
	}

	for _, rpcLeaf := range resp.IgnoreLeaves {
		ignoreEvent, err := unmarshalIgnoreSupplyLeaf(rpcLeaf)
		if err != nil {
			return zero, fmt.Errorf("unable to unmarshal ignore "+
				"event: %w", err)
		}

		supplyLeaves.IgnoreLeafEntries = append(
			supplyLeaves.IgnoreLeafEntries, *ignoreEvent,
		)
	}

	return supplyLeaves, nil
}

// InsertSupplyLeaves inserts supply leaves for a specific asset group into
// the remote universe server.
func (r *RpcSupplySync) InsertSupplyLeaves(ctx context.Context,
	assetSpec asset.Specifier,
	leaves supplycommit.SupplyLeaves) error {

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to unwrap group key: %w", err)
	}

	// Marshal issuance leaves to RPC format.
	rpcIssuanceLeaves := make(
		[]*unirpc.SupplyLeafEntry, 0, len(leaves.IssuanceLeafEntries),
	)
	for idx := range leaves.IssuanceLeafEntries {
		leafEntry := &leaves.IssuanceLeafEntries[idx]
		rpcLeaf, err := marshalSupplyUpdateEvent(leafEntry)
		if err != nil {
			return fmt.Errorf("unable to marshal issuance leaf: %w",
				err)
		}

		rpcIssuanceLeaves = append(rpcIssuanceLeaves, rpcLeaf)
	}

	// Marshal burn leaves to RPC format.
	rpcBurnLeaves := make(
		[]*unirpc.SupplyLeafEntry, 0, len(leaves.BurnLeafEntries),
	)
	for idx := range leaves.BurnLeafEntries {
		leafEntry := &leaves.BurnLeafEntries[idx]
		rpcLeaf, err := marshalSupplyUpdateEvent(leafEntry)
		if err != nil {
			return fmt.Errorf("unable to marshal burn leaf: %w",
				err)
		}

		rpcBurnLeaves = append(rpcBurnLeaves, rpcLeaf)
	}

	// Marshal ignore leaves to RPC format.
	rpcIgnoreLeaves := make(
		[]*unirpc.SupplyLeafEntry, 0, len(leaves.IgnoreLeafEntries),
	)
	for idx := range leaves.IgnoreLeafEntries {
		leafEntry := &leaves.IgnoreLeafEntries[idx]
		rpcLeaf, err := marshalSupplyUpdateEvent(leafEntry)
		if err != nil {
			return fmt.Errorf("unable to marshal ignore leaf: %w",
				err)
		}

		rpcIgnoreLeaves = append(rpcIgnoreLeaves, rpcLeaf)
	}

	req := &unirpc.InsertSupplyLeavesRequest{
		GroupKey: &unirpc.InsertSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKey.SerializeCompressed(),
		},
		IssuanceLeaves: rpcIssuanceLeaves,
		BurnLeaves:     rpcBurnLeaves,
		IgnoreLeaves:   rpcIgnoreLeaves,
	}

	_, err = r.conn.InsertSupplyLeaves(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to insert supply leaves: %w", err)
	}

	return nil
}

// Close closes the RPC connection to the universe server.
func (r *RpcSupplySync) Close() error {
	if r.conn != nil && r.conn.ClientConn != nil {
		return r.conn.ClientConn.Close()
	}
	return nil
}

// unmarshalMintSupplyLeaf converts an RPC SupplyLeafEntry into a NewMintEvent.
func unmarshalMintSupplyLeaf(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewMintEvent, error) {

	if rpcLeaf == nil {
		return nil, fmt.Errorf("supply leaf entry is nil")
	}

	if rpcLeaf.LeafKey == nil {
		return nil, fmt.Errorf("supply leaf key is nil")
	}

	if rpcLeaf.LeafNode == nil {
		return nil, fmt.Errorf("supply leaf node is nil")
	}

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for mint event")
	}

	var mintEvent supplycommit.NewMintEvent
	err := mintEvent.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode mint event: %w", err)
	}

	// Validate that the decoded event matches the provided metadata.
	if mintEvent.BlockHeight() != rpcLeaf.BlockHeight {
		return nil, fmt.Errorf("block height mismatch: "+
			"decoded=%d, provided=%d", mintEvent.BlockHeight(),
			rpcLeaf.BlockHeight)
	}

	return &mintEvent, nil
}

// unmarshalBurnSupplyLeaf converts an RPC SupplyLeafEntry into a NewBurnEvent.
func unmarshalBurnSupplyLeaf(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewBurnEvent, error) {

	if rpcLeaf == nil {
		return nil, fmt.Errorf("supply leaf entry is nil")
	}

	if rpcLeaf.LeafKey == nil {
		return nil, fmt.Errorf("supply leaf key is nil")
	}

	if rpcLeaf.LeafNode == nil {
		return nil, fmt.Errorf("supply leaf node is nil")
	}

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for burn event")
	}

	// Create and decode the burn leaf from raw leaf bytes.
	var burnLeaf universe.BurnLeaf
	err := burnLeaf.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode burn leaf: %w", err)
	}

	burnEvent := &supplycommit.NewBurnEvent{
		BurnLeaf: burnLeaf,
	}

	// Validate that the decoded event matches the provided metadata.
	if burnEvent.BlockHeight() != rpcLeaf.BlockHeight {
		return nil, fmt.Errorf("block height mismatch: "+
			"decoded=%d, provided=%d", burnEvent.BlockHeight(),
			rpcLeaf.BlockHeight)
	}

	return burnEvent, nil
}

// unmarshalIgnoreSupplyLeaf converts an RPC SupplyLeafEntry into a
// NewIgnoreEvent.
func unmarshalIgnoreSupplyLeaf(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewIgnoreEvent, error) {

	if rpcLeaf == nil {
		return nil, fmt.Errorf("supply leaf entry is nil")
	}

	if rpcLeaf.LeafKey == nil {
		return nil, fmt.Errorf("supply leaf key is nil")
	}

	if rpcLeaf.LeafNode == nil {
		return nil, fmt.Errorf("supply leaf node is nil")
	}

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for ignore event")
	}

	var signedIgnoreTuple universe.SignedIgnoreTuple
	err := signedIgnoreTuple.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode signed ignore "+
			"tuple: %w", err)
	}

	ignoreEvent := &supplycommit.NewIgnoreEvent{
		SignedIgnoreTuple: signedIgnoreTuple,
	}

	// Validate that the decoded event matches the provided metadata.
	if ignoreEvent.BlockHeight() != rpcLeaf.BlockHeight {
		return nil, fmt.Errorf("block height mismatch: "+
			"decoded=%d, provided=%d", ignoreEvent.BlockHeight(),
			rpcLeaf.BlockHeight)
	}

	return ignoreEvent, nil
}

// marshalSupplyUpdateEvent converts a SupplyUpdateEvent into an RPC
// SupplyLeafEntry.
func marshalSupplyUpdateEvent(
	leafEntry supplycommit.SupplyUpdateEvent) (*unirpc.SupplyLeafEntry,
	error) {

	leafNode, err := leafEntry.UniverseLeafNode()
	if err != nil {
		return nil, fmt.Errorf("unable to get universe leaf node "+
			"from leaf entry: %w", err)
	}

	leafKey := leafEntry.UniverseLeafKey()

	outPoint := leafKey.LeafOutPoint()
	rpcOutPoint := unirpc.Outpoint{
		HashStr: outPoint.Hash.String(),
		Index:   int32(outPoint.Index),
	}

	// Encode the leaf as a byte slice.
	var leafBuf bytes.Buffer
	err = leafEntry.Encode(&leafBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to encode leaf entry: %w", err)
	}

	return &unirpc.SupplyLeafEntry{
		LeafKey: &unirpc.SupplyLeafKey{
			Outpoint: &rpcOutPoint,
			ScriptKey: schnorr.SerializePubKey(
				leafKey.LeafScriptKey().PubKey,
			),
			AssetId: fn.ByteSlice(leafKey.LeafAssetID()),
		},
		LeafNode:    marshalMssmtNode(leafNode),
		BlockHeight: leafEntry.BlockHeight(),
		RawLeaf:     leafBuf.Bytes(),
	}, nil
}
