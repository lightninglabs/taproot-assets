package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
)

// RpcSupplySync is an implementation of the universe.SupplySyncer interface
// that uses an RPC connection to target a remote universe server.
type RpcSupplySync struct {
	// serverAddr is the address of the remote universe server.
	serverAddr universe.ServerAddr

	// conn is the RPC connection to the remote universe server.
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
		serverAddr: serverAddr,
		conn:       conn,
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

	srvrLog.Infof("[RpcSupplySync.InsertSupplyCommit]: inserting supply "+
		"commitment into remote server "+
		"(server_addr=%s, asset=%s, supply_tree_root_hash=%s)",
		r.serverAddr.HostStr(), assetSpec.String(),
		commitment.SupplyRoot.NodeHash().String())

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

	// Marshall spent commitment outpoint.
	var spentCommitmentOutpoint *taprpc.OutPoint
	commitment.SpentCommitment.WhenSome(func(point wire.OutPoint) {
		spentCommitmentOutpoint = &taprpc.OutPoint{
			Txid:        point.Hash[:],
			OutputIndex: point.Index,
		}
	})

	req := &unirpc.InsertSupplyCommitRequest{
		GroupKey: &unirpc.InsertSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKey.SerializeCompressed(),
		},
		ChainData:               rpcChainData,
		SpentCommitmentOutpoint: spentCommitmentOutpoint,
		IssuanceLeaves:          issuanceLeaves,
		BurnLeaves:              burnLeaves,
		IgnoreLeaves:            ignoreLeaves,
	}

	_, err = r.conn.InsertSupplyCommit(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to insert supply commitment: %w", err)
	}

	srvrLog.Infof("[RpcSupplySync.InsertSupplyCommit]: succeeded in "+
		"inserting supply commitment "+
		"(server_addr=%s, asset=%s, supply_tree_root_hash=%s)",
		r.serverAddr.HostStr(), assetSpec.String(),
		commitment.SupplyRoot.NodeHash().String())

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
