package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverify"
)

// RpcSupplySync is an implementation of the universe.SupplySyncer interface
// that uses an RPC connection to target a remote universe server.
type RpcSupplySync struct {
	conn *universeClientConn
}

// NewRpcSupplySync creates a new RpcSupplySync instance that dials out to
// the target remote universe server address.
func NewRpcSupplySync(
	serverAddr universe.ServerAddr) (supplyverify.SupplyLeafFetcher,
	error) {

	conn, err := ConnectUniverse(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to universe RPC "+
			"server: %w", err)
	}

	return &RpcSupplySync{
		conn: conn,
	}, nil
}

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

	// Convert the RPC response into a supplycommit.SupplyLeaves instance.
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

	// Unmarshal issuance (mint) leaves.
	for _, rpcLeaf := range resp.IssuanceLeaves {
		mintEvent, err := unmarshalMintEvent(rpcLeaf)
		if err != nil {
			return zero, fmt.Errorf("unable to unmarshal mint "+
				"event: %w", err)
		}

		supplyLeaves.IssuanceLeafEntries = append(
			supplyLeaves.IssuanceLeafEntries, *mintEvent,
		)
	}

	// Unmarshal burn leaves.
	for _, rpcLeaf := range resp.BurnLeaves {
		burnEvent, err := unmarshalBurnEvent(rpcLeaf)
		if err != nil {
			return zero, fmt.Errorf("unable to unmarshal burn "+
				"event: %w", err)
		}

		supplyLeaves.BurnLeafEntries = append(
			supplyLeaves.BurnLeafEntries, *burnEvent,
		)
	}

	// Unmarshal ignore leaves.
	for _, rpcLeaf := range resp.IgnoreLeaves {
		ignoreEvent, err := unmarshalIgnoreEvent(rpcLeaf)
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

// Close closes the RPC connection to the universe server.
func (r *RpcSupplySync) Close() error {
	if r.conn != nil && r.conn.ClientConn != nil {
		return r.conn.ClientConn.Close()
	}
	return nil
}

// unmarshalMintEvent converts an RPC SupplyLeafEntry into a NewMintEvent.
func unmarshalMintEvent(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewMintEvent, error) {

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for mint event")
	}

	var mintEvent supplycommit.NewMintEvent
	err := mintEvent.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode mint event: %w", err)
	}

	return &mintEvent, nil
}

// unmarshalBurnEvent converts an RPC SupplyLeafEntry into a NewBurnEvent.
func unmarshalBurnEvent(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewBurnEvent, error) {

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for burn event")
	}

	var burnEvent supplycommit.NewBurnEvent
	err := burnEvent.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode burn event: %w", err)
	}

	return &burnEvent, nil
}

// unmarshalIgnoreEvent converts an RPC SupplyLeafEntry into a NewIgnoreEvent.
func unmarshalIgnoreEvent(
	rpcLeaf *unirpc.SupplyLeafEntry) (*supplycommit.NewIgnoreEvent, error) {

	if len(rpcLeaf.RawLeaf) == 0 {
		return nil, fmt.Errorf("missing RawLeaf data for ignore event")
	}

	var signedIgnoreTuple universe.SignedIgnoreTuple
	err := signedIgnoreTuple.Decode(bytes.NewReader(rpcLeaf.RawLeaf))
	if err != nil {
		return nil, fmt.Errorf("unable to decode signed ignore "+
			"tuple: %w", err)
	}

	return &supplycommit.NewIgnoreEvent{
		SignedIgnoreTuple: signedIgnoreTuple,
	}, nil
}
