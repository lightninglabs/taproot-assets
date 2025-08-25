package taprootassets

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

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
	addr url.URL) (supplyverifier.UniverseClient, error) {

	serverAddr := universe.NewServerAddrFromStr(addr.String())
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

// InsertSupplyCommit inserts a supply commitment for a specific asset
// group into the remote universe server.
func (r *RpcSupplySync) InsertSupplyCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof) error {

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to unwrap group key: %w", err)
	}

	// Marshal the supply commit chain data to RPC format.
	rpcChainData, err := marshalSupplyCommitChainData(
		commitment, chainProof,
	)
	if err != nil {
		return fmt.Errorf("unable to marshal chain data: %w", err)
	}

	issuanceLeaves, burnLeaves, ignoreLeaves, err := marshalSupplyLeaves(
		leaves,
	)
	if err != nil {
		return fmt.Errorf("unable to marshal supply leaves: %w", err)
	}

	req := &unirpc.InsertSupplyCommitRequest{
		GroupKey: &unirpc.InsertSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKey.SerializeCompressed(),
		},
		ChainData:      rpcChainData,
		IssuanceLeaves: issuanceLeaves,
		BurnLeaves:     burnLeaves,
		IgnoreLeaves:   ignoreLeaves,
	}

	_, err = r.conn.InsertSupplyCommit(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to insert supply commitment: %w", err)
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

// marshalSupplyCommitChainData converts a supplycommit.RootCommitment and
// supplycommit.ChainProof into a combined RPC SupplyCommitChainData.
func marshalSupplyCommitChainData(
	rootCommitment supplycommit.RootCommitment,
	chainProof supplycommit.ChainProof) (*unirpc.SupplyCommitChainData,
	error) {

	// Serialize the transaction.
	var txnBuf bytes.Buffer
	err := rootCommitment.Txn.Serialize(&txnBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize transaction: %w",
			err)
	}

	// Serialize the block header.
	var headerBuf bytes.Buffer
	err = chainProof.Header.Serialize(&headerBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize block header: %w",
			err)
	}

	// Serialize the merkle proof.
	var merkleProofBuf bytes.Buffer
	err = chainProof.MerkleProof.Encode(&merkleProofBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to encode merkle proof: %w",
			err)
	}

	// nolint: lll
	rpcChainData := &unirpc.SupplyCommitChainData{
		Txn:                txnBuf.Bytes(),
		TxOutIdx:           rootCommitment.TxOutIdx,
		InternalKey:        rootCommitment.InternalKey.PubKey.SerializeCompressed(),
		OutputKey:          rootCommitment.OutputKey.SerializeCompressed(),
		SupplyRootHash:     fn.ByteSlice(rootCommitment.SupplyRoot.NodeHash()),
		SupplyRootSum:      rootCommitment.SupplyRoot.NodeSum(),
		BlockHeader:        headerBuf.Bytes(),
		BlockHeight:        chainProof.BlockHeight,
		TxBlockMerkleProof: merkleProofBuf.Bytes(),
		TxIndex:            chainProof.TxIndex,
	}

	// Handle optional commitment block hash.
	rootCommitment.CommitmentBlock.WhenSome(
		func(block supplycommit.CommitmentBlock) {
			rpcChainData.BlockHash = block.Hash[:]
		},
	)

	return rpcChainData, nil
}

// unmarshalSupplyLeaves converts the RPC supply leaves into a SupplyLeaves
// struct that can be used by the supply commitment verifier.
func unmarshalSupplyLeaves(issuanceLeaves, burnLeaves,
	ignoreLeaves []*unirpc.SupplyLeafEntry) (*supplycommit.SupplyLeaves,
	error) {

	var (
		supplyLeaves supplycommit.SupplyLeaves
		err          error
	)
	supplyLeaves.IssuanceLeafEntries, err = fn.MapErrWithPtr(
		issuanceLeaves, unmarshalMintSupplyLeaf,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal mint event: %w",
			err)
	}

	supplyLeaves.BurnLeafEntries, err = fn.MapErrWithPtr(
		burnLeaves, unmarshalBurnSupplyLeaf,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal burn event: %w",
			err)
	}

	supplyLeaves.IgnoreLeafEntries, err = fn.MapErrWithPtr(
		ignoreLeaves, unmarshalIgnoreSupplyLeaf,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal ignore event: %w",
			err)
	}

	return &supplyLeaves, nil
}

// mapSupplyLeaves is a generic helper that converts a slice of supply update
// events into a slice of RPC SupplyLeafEntry objects.
func mapSupplyLeaves[E any](entries []E) ([]*unirpc.SupplyLeafEntry, error) {
	return fn.MapErr(entries, func(i E) (*unirpc.SupplyLeafEntry, error) {
		interfaceType, ok := any(&i).(supplycommit.SupplyUpdateEvent)
		if !ok {
			return nil, fmt.Errorf("expected supply update event, "+
				"got %T", i)
		}
		return marshalSupplyUpdateEvent(interfaceType)
	})
}

// marshalSupplyLeaves converts a SupplyLeaves struct into the corresponding
// RPC SupplyLeafEntry slices for issuance, burn, and ignore leaves.
func marshalSupplyLeaves(
	leaves supplycommit.SupplyLeaves) ([]*unirpc.SupplyLeafEntry,
	[]*unirpc.SupplyLeafEntry, []*unirpc.SupplyLeafEntry, error) {

	rpcIssuanceLeaves, err := mapSupplyLeaves(leaves.IssuanceLeafEntries)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to marshal issuance "+
			"leaf: %w", err)
	}

	rpcBurnLeaves, err := mapSupplyLeaves(leaves.BurnLeafEntries)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to marshal burn "+
			"leaf: %w", err)
	}

	rpcIgnoreLeaves, err := mapSupplyLeaves(leaves.IgnoreLeafEntries)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to marshal burn "+
			"leaf: %w", err)
	}

	return rpcIssuanceLeaves, rpcBurnLeaves, rpcIgnoreLeaves, nil
}
