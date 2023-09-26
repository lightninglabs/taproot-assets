package taprootassets

import (
	"bytes"
	"context"
	"fmt"

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
	root *unirpc.UniverseRoot) (universe.BaseRoot, error) {

	id, err := unmarshalUniID(root.Id)
	if err != nil {
		return universe.BaseRoot{}, err
	}

	return universe.BaseRoot{
		ID:   id,
		Node: unmarshalMerkleSumNode(root.MssmtRoot),
	}, nil
}

func unmarshalUniverseRoots(
	roots []*unirpc.UniverseRoot) ([]universe.BaseRoot, error) {

	baseRoots := make([]universe.BaseRoot, 0, len(roots))
	for _, root := range roots {
		id, err := unmarshalUniID(root.Id)
		if err != nil {
			return nil, err
		}

		baseRoots = append(baseRoots, universe.BaseRoot{
			ID:   id,
			Node: unmarshalMerkleSumNode(root.MssmtRoot),
		})
	}

	return baseRoots, nil
}

// RootNodes returns the complete set of known root nodes for the set
// of assets tracked in the base Universe.
func (r *RpcUniverseDiff) RootNodes(
	ctx context.Context) ([]universe.BaseRoot, error) {

	universeRoots, err := r.conn.AssetRoots(
		ctx, &unirpc.AssetRootRequest{},
	)
	if err != nil {
		return nil, err
	}

	return unmarshalUniverseRoots(
		maps.Values(universeRoots.UniverseRoots),
	)
}

// RootNode returns the root node for a given base universe.
func (r *RpcUniverseDiff) RootNode(ctx context.Context,
	id universe.Identifier) (universe.BaseRoot, error) {

	rootReq := &universerpc.AssetRootQuery{
		Id: marshalUniID(id),
	}

	universeRoot, err := r.conn.QueryAssetRoots(ctx, rootReq)
	if err != nil {
		return universe.BaseRoot{}, err
	}

	return unmarshalUniverseRoot(universeRoot.AssetRoot)
}

// MintingKeys returns all the keys inserted in the universe.
func (r *RpcUniverseDiff) MintingKeys(ctx context.Context,
	id universe.Identifier) ([]universe.LeafKey, error) {

	assetKeys, err := r.conn.AssetLeafKeys(ctx, marshalUniID(id))
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

// FetchIssuanceProof attempts to fetch an issuance proof for the
// target base leaf based on the universe identifier
// (assetID/groupKey).
//
// TODO(roasbeef): actually add this somewhere else?  * rn kinda
// asymmetric, as just need this to complete final portion
// of diff
func (r *RpcUniverseDiff) FetchIssuanceProof(ctx context.Context,
	id universe.Identifier,
	key universe.LeafKey) ([]*universe.IssuanceProof, error) {

	uProofs, err := r.conn.QueryProof(ctx, &universerpc.UniverseKey{
		Id:      marshalUniID(id),
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

	uniProof := &universe.IssuanceProof{
		LeafKey:        key,
		UniverseRoot:   uniRoot,
		InclusionProof: inclusionProof,
		Leaf:           assetLeaf,
	}

	return []*universe.IssuanceProof{uniProof}, nil
}

// A compile time interface to ensure that RpcUniverseDiff implements the
// universe.DiffEngine interface.
var _ universe.DiffEngine = (*RpcUniverseDiff)(nil)
