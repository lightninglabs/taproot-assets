package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
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

// FetchSupplyCommit fetches a supply commitment for a specific asset group
// from the remote universe server.
func (r *RpcSupplySync) FetchSupplyCommit(ctx context.Context,
	assetSpec asset.Specifier,
	spentCommitOutpoint fn.Option[wire.OutPoint]) (
	supplycommit.FetchSupplyCommitResult, error) {

	var zero supplycommit.FetchSupplyCommitResult

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return zero, fmt.Errorf("unable to unwrap group key: %w", err)
	}

	req := &unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKey.SerializeCompressed(),
		},
		Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
			VeryFirst: true,
		},
	}

	// If a spent commit outpoint is provided, use that to locate the next
	// supply commitment.
	spentCommitOutpoint.WhenSome(func(outpoint wire.OutPoint) {
		// nolint: lll
		req.Locator = &unirpc.FetchSupplyCommitRequest_SpentCommitOutpoint{
			SpentCommitOutpoint: &taprpc.OutPoint{
				Txid:        outpoint.Hash[:],
				OutputIndex: outpoint.Index,
			},
		}
	})

	resp, err := r.conn.FetchSupplyCommit(ctx, req)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply commitment: %w",
			err)
	}

	// Unmarshal the chain data to get the root commitment.
	rootCommitment, err := unmarshalSupplyCommitChainData(resp.ChainData)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal root "+
			"commitment: %w", err)
	}

	// Extract the chain proof from the response data.
	chainProof, err := unmarshalChainProof(resp.ChainData)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal chain proof: %w",
			err)
	}

	// Set the spent commitment outpoint if provided in response.
	if resp.SpentCommitmentOutpoint != nil {
		spentOutpoint := wire.OutPoint{
			Index: resp.SpentCommitmentOutpoint.OutputIndex,
		}
		copy(spentOutpoint.Hash[:], resp.SpentCommitmentOutpoint.Txid)
		rootCommitment.SpentCommitment = fn.Some(spentOutpoint)
	}

	// Unmarshal the supply leaves.
	supplyLeaves, err := unmarshalSupplyLeaves(
		resp.IssuanceLeaves, resp.BurnLeaves, resp.IgnoreLeaves,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal supply leaves: %w",
			err)
	}

	// Convert spent commitment outpoint from RPC response to fn.Option.
	var respSpentCommitOutpoint fn.Option[wire.OutPoint]
	if resp.SpentCommitmentOutpoint != nil {
		outpoint := wire.OutPoint{
			Index: resp.SpentCommitmentOutpoint.OutputIndex,
		}
		copy(outpoint.Hash[:], resp.SpentCommitmentOutpoint.Txid)
		respSpentCommitOutpoint = fn.Some(outpoint)
	}

	// Unmarshall RPC subtree roots.
	issuanceSubtreeRoot, err := unmarshalSupplyCommitSubtreeRoot(
		resp.IssuanceSubtreeRoot,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal issuance subtree "+
			"root: %w", err)
	}

	burnSubtreeRoot, err := unmarshalSupplyCommitSubtreeRoot(
		resp.BurnSubtreeRoot,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal burn subtree "+
			"root: %w", err)
	}

	ignoreSubtreeRoot, err := unmarshalSupplyCommitSubtreeRoot(
		resp.IgnoreSubtreeRoot,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal ignore subtree "+
			"root: %w", err)
	}

	return supplycommit.FetchSupplyCommitResult{
		RootCommitment:  *rootCommitment,
		SupplyLeaves:    *supplyLeaves,
		ChainProof:      chainProof,
		TxChainFeesSats: resp.TxChainFeesSats,

		IssuanceSubtreeRoot: issuanceSubtreeRoot,
		BurnSubtreeRoot:     burnSubtreeRoot,
		IgnoreSubtreeRoot:   ignoreSubtreeRoot,

		SpentCommitmentOutpoint: respSpentCommitOutpoint,
	}, nil
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

// unmarshalChainProof converts an RPC SupplyCommitChainData into
// a supplycommit.ChainProof.
func unmarshalChainProof(
	rpcData *unirpc.SupplyCommitChainData) (supplycommit.ChainProof,
	error) {

	var zero supplycommit.ChainProof

	if rpcData == nil {
		return zero, fmt.Errorf("supply commit chain data is nil")
	}

	var blockHeader wire.BlockHeader
	err := blockHeader.Deserialize(bytes.NewReader(rpcData.BlockHeader))
	if err != nil {
		return zero, fmt.Errorf("unable to deserialize block "+
			"header: %w", err)
	}

	var merkleProof proof.TxMerkleProof
	err = merkleProof.Decode(bytes.NewReader(rpcData.TxBlockMerkleProof))
	if err != nil {
		return zero, fmt.Errorf("unable to decode merkle proof: %w",
			err)
	}

	return supplycommit.ChainProof{
		Header:      blockHeader,
		BlockHeight: rpcData.BlockHeight,
		MerkleProof: merkleProof,
		TxIndex:     rpcData.TxIndex,
	}, nil
}

// unmarshalSupplyCommitSubtreeRoot converts an RPC SubtreeRootProof
// into a domain-specific SubtreeRootProof.
func unmarshalSupplyCommitSubtreeRoot(rpcRoot *unirpc.SupplyCommitSubtreeRoot) (
	supplycommit.SubtreeRootProof, error) {

	var zero supplycommit.SubtreeRootProof

	if rpcRoot == nil {
		return zero, nil
	}

	// Convert the RPC string type to SupplySubTree enum.
	subTreeType, err := supplycommit.NewSubtreeTypeFromStr(rpcRoot.Type)
	if err != nil {
		return zero, fmt.Errorf("unknown subtree type: %w", err)
	}

	// Convert the RPC MerkleSumNode to our domain BranchNode.
	if rpcRoot.RootNode == nil {
		return zero, fmt.Errorf("supply root node is nil")
	}

	// Create a computed branch from the RPC node data.
	nodeHash, err := mssmt.NewNodeHashFromBytes(rpcRoot.RootNode.RootHash)
	if err != nil {
		return zero, fmt.Errorf("unable to parse node hash: %w", err)
	}

	rootNode := mssmt.NewComputedBranch(
		nodeHash, uint64(rpcRoot.RootNode.RootSum),
	)

	// Convert the leaf key byte slice to a UniverseKey.
	leafKey, err := universe.NewUniverseKeyFromBytes(
		rpcRoot.SupplyTreeLeafKey,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to parse leaf key: %w", err)
	}

	// Unmarshall the compressed inclusion proof.
	supplyTreeInclusionProof, err := mssmt.NewProofFromCompressedBytes(
		rpcRoot.SupplyTreeInclusionProof,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to decompress inclusion "+
			"proof: %w", err)
	}

	return supplycommit.SubtreeRootProof{
		Type:                     subTreeType,
		RootNode:                 *rootNode,
		SupplyTreeLeafKey:        leafKey,
		SupplyTreeInclusionProof: supplyTreeInclusionProof,
	}, nil
}
