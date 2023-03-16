package taro

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/tarorpc/universerpc"
	unirpc "github.com/lightninglabs/taro/tarorpc/universerpc"
	"github.com/lightninglabs/taro/universe"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RpcUniverseDiff is an implementation of the universe.DiffEngine interface
// that uses an RPC connection to target Universe.
type RpcUniverseDiff struct {
	conn unirpc.UniverseClient
}

// NewRpcUniverseDiff creates a new RpcUniverseDiff instance that dials out to
// the target remote universe server address.
func NewRpcUniverseDiff(serverAddr universe.ServerAddr,
) (universe.DiffEngine, error) {

	// TODO(roasbeef): all info is authenticated, but also want to allow
	// brontide connect as well, can avoid TLS certs
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
	})

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	conn, err := grpc.Dial(serverAddr.Addr.String(), opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC "+
			"server: %v", err)
	}

	return &RpcUniverseDiff{
		conn: unirpc.NewUniverseClient(conn),
	}, nil
}

func unmarshalMerkleSumNode(root *unirpc.MerkleSumNode) mssmt.Node {
	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], root.RootHash)

	return mssmt.NewComputedBranch(nodeHash, uint64(root.RootSum))
}

func unmarshalUniverseRoot(root *unirpc.UniverseRoot) (universe.BaseRoot, error) {
	id, err := unmarshalUniID(root.Id)
	if err != nil {
		return universe.BaseRoot{}, err
	}

	return universe.BaseRoot{
		ID:   id,
		Node: unmarshalMerkleSumNode(root.MssmtRoot),
	}, nil
}

func unmarshalUniverseRoots(roots []*unirpc.UniverseRoot) ([]universe.BaseRoot, error) {
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
func (r *RpcUniverseDiff) RootNodes(ctx context.Context,
) ([]universe.BaseRoot, error) {

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
	id universe.Identifier) ([]universe.BaseKey, error) {

	assetKeys, err := r.conn.AssetLeafKeys(ctx, marshalUniID(id))
	if err != nil {
		return nil, err
	}

	keys := make([]universe.BaseKey, len(assetKeys.AssetKeys))
	for i, key := range assetKeys.AssetKeys {
		baseKey, err := unmarshalLeafKey(key)
		if err != nil {
			return nil, err
		}

		keys[i] = baseKey
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
	key universe.BaseKey) ([]*universe.IssuanceProof, error) {

	uProofs, err := r.conn.QueryIssuanceProof(ctx, &universerpc.UniverseKey{
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
		MintingKey:     key,
		UniverseRoot:   uniRoot,
		InclusionProof: inclusionProof,
		Leaf:           assetLeaf,
	}

	return []*universe.IssuanceProof{uniProof}, nil
}

// A compile time interface to ensure that RpcUniverseDiff implements the
// universe.DiffEngine interface.
var _ universe.DiffEngine = (*RpcUniverseDiff)(nil)
