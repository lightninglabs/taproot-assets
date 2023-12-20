package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"golang.org/x/exp/maps"
)

// RpcUniverseDiff is an implementation of the universe.DiffEngine interface
// that uses an RPC connection to target Universe.
type RpcUniverseDiff struct {
	conn unirpc.UniverseClient
}

// NewRpcUniverseDiff creates a new RpcUniverseDiff instance that dials out to
// the target remote universe server address.
func NewRpcUniverseDiff(
	serverAddr universe.ServerAddr) (universe.DiffEngine, error) {

	conn, err := ConnectUniverse(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to universe RPC "+
			"server: %w", err)
	}

	return &RpcUniverseDiff{
		conn: conn,
	}, nil
}

func unmarshalMerkleSumNode(root *unirpc.MerkleSumNode) mssmt.Node {
	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], root.RootHash)

	return mssmt.NewComputedBranch(nodeHash, uint64(root.RootSum))
}

func unmarshalUniverseRoot(
	root *unirpc.UniverseRoot) (universe.Root, error) {

	id, err := UnmarshalUniID(root.Id)
	if err != nil {
		return universe.Root{}, err
	}

	return universe.Root{
		ID:   id,
		Node: unmarshalMerkleSumNode(root.MssmtRoot),
	}, nil
}

func unmarshalUniverseRoots(
	roots []*unirpc.UniverseRoot) ([]universe.Root, error) {

	uniRoots := make([]universe.Root, 0, len(roots))
	for _, root := range roots {
		id, err := UnmarshalUniID(root.Id)
		if err != nil {
			return nil, err
		}

		uniRoots = append(uniRoots, universe.Root{
			ID:   id,
			Node: unmarshalMerkleSumNode(root.MssmtRoot),
		})
	}

	return uniRoots, nil
}

// RootNodes returns the complete set of known root nodes for the set
// of assets tracked in the universe.
func (r *RpcUniverseDiff) RootNodes(ctx context.Context,
	q universe.RootNodesQuery) ([]universe.Root, error) {

	universeRoots, err := r.conn.AssetRoots(
		ctx, &unirpc.AssetRootRequest{
			WithAmountsById: q.WithAmountsById,
			Offset:          int32(q.Offset),
			Limit:           int32(q.Limit),
			Direction:       unirpc.SortDirection(q.SortDirection),
		},
	)
	if err != nil {
		return nil, err
	}

	return unmarshalUniverseRoots(
		maps.Values(universeRoots.UniverseRoots),
	)
}

// RootNode returns the root node for a given universe.
func (r *RpcUniverseDiff) RootNode(ctx context.Context,
	id universe.Identifier) (universe.Root, error) {

	uniID, err := MarshalUniID(id)
	if err != nil {
		return universe.Root{}, err
	}
	rootReq := &universerpc.AssetRootQuery{
		Id: uniID,
	}

	universeRoot, err := r.conn.QueryAssetRoots(ctx, rootReq)
	if err != nil {
		return universe.Root{}, err
	}

	if id.ProofType == universe.ProofTypeIssuance {
		return unmarshalUniverseRoot(universeRoot.IssuanceRoot)
	}

	return unmarshalUniverseRoot(universeRoot.TransferRoot)
}

// UniverseLeafKeys returns all the keys inserted in the universe.
func (r *RpcUniverseDiff) UniverseLeafKeys(ctx context.Context,
	q universe.UniverseLeafKeysQuery) ([]universe.LeafKey, error) {

	uniID, err := MarshalUniID(q.Id)
	if err != nil {
		return nil, err
	}

	assetKeys, err := r.conn.AssetLeafKeys(
		ctx, &unirpc.AssetLeafKeysRequest{
			Id:        uniID,
			Direction: unirpc.SortDirection(q.SortDirection),
			Offset:    int32(q.Offset),
			Limit:     int32(q.Limit),
		},
	)
	if err != nil {
		return nil, err
	}

	keys := make([]universe.LeafKey, len(assetKeys.AssetKeys))
	for i, key := range assetKeys.AssetKeys {
		leafKey, err := unmarshalLeafKey(key)
		if err != nil {
			return nil, err
		}

		keys[i] = leafKey
	}

	return keys, nil
}

// FetchProofLeaf attempts to fetch a proof leaf for the target leaf key
// and given a universe identifier (assetID/groupKey).
//
// TODO(roasbeef): actually add this somewhere else?  * rn kinda
// asymmetric, as just need this to complete final portion
// of diff
func (r *RpcUniverseDiff) FetchProofLeaf(ctx context.Context,
	id universe.Identifier,
	key universe.LeafKey) ([]*universe.Proof, error) {

	uniID, err := MarshalUniID(id)
	if err != nil {
		return nil, err
	}

	uProofs, err := r.conn.QueryProof(ctx, &universerpc.UniverseKey{
		Id:      uniID,
		LeafKey: marshalLeafKey(key),
	})
	if err != nil {
		return nil, err
	}

	uniRoot, err := unmarshalUniverseRoot(uProofs.UniverseRoot)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := unmarshalAssetLeaf(uProofs.AssetLeaf)
	if err != nil {
		return nil, err
	}

	var compressedProof mssmt.CompressedProof
	err = compressedProof.Decode(
		bytes.NewReader(uProofs.UniverseInclusionProof),
	)
	if err != nil {
		return nil, err
	}

	inclusionProof, err := compressedProof.Decompress()
	if err != nil {
		return nil, err
	}

	uniProof := &universe.Proof{
		LeafKey:                key,
		UniverseRoot:           uniRoot,
		UniverseInclusionProof: inclusionProof,
		Leaf:                   assetLeaf,
	}

	return []*universe.Proof{uniProof}, nil
}

// MultiverseRoot returns the root node of the multiverse for the
// specified proof type. If the given list of universe IDs is non-empty,
// then the root will be calculated just for those universes.
func (r *RpcUniverseDiff) MultiverseRoot(ctx context.Context,
	proofType universe.ProofType,
	filterByIDs []universe.Identifier) (fn.Option[universe.MultiverseRoot],
	error) {

	none := fn.None[universe.MultiverseRoot]()

	proofTypeRpc, err := MarshalUniProofType(proofType)
	if err != nil {
		return none, fmt.Errorf("unable to marshal proof type: %w", err)
	}

	rpcIDs := make([]*unirpc.ID, len(filterByIDs))
	for i, id := range filterByIDs {
		uniID, err := MarshalUniID(id)
		if err != nil {
			return none, err
		}

		rpcIDs[i] = uniID
	}

	root, err := r.conn.MultiverseRoot(ctx, &unirpc.MultiverseRootRequest{
		ProofType:   proofTypeRpc,
		SpecificIds: rpcIDs,
	})
	if err != nil {
		return none, err
	}

	return fn.Some(universe.MultiverseRoot{
		ProofType: proofType,
		Node:      unmarshalMerkleSumNode(root.MultiverseRoot),
	}), nil
}

// A compile time interface to ensure that RpcUniverseDiff implements the
// universe.DiffEngine interface.
var _ universe.DiffEngine = (*RpcUniverseDiff)(nil)
