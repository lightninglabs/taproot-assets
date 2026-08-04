package rpcserver

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RpcUniverseDiff is an implementation of the universe.DiffEngine interface
// that uses an RPC connection to target Universe.
type RpcUniverseDiff struct {
	conn *universeClientConn
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
			Offset:          q.Offset,
			Limit:           q.Limit,
			Direction:       taprpc.SortDirection(q.SortDirection),
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
	switch {
	// We're calling using the RPC endpoint, so the error cannot be mapped
	// directly using errors.Is.
	case fn.IsRpcErr(err, universe.ErrNoUniverseRoot):
		return universe.Root{}, universe.ErrNoUniverseRoot

	case err != nil:
		return universe.Root{}, err
	}

	// Old universe servers will return an empty response instead of the
	// above error. But our sync engine now understands the error, so we can
	// transform the empty response to the error. Future servers will return
	// the error directly, which can be handled by newer clients.
	if universe.IsEmptyRootResponse(universeRoot) {
		return universe.Root{}, universe.ErrNoUniverseRoot
	}

	if id.ProofType == universe.ProofTypeIssuance {
		return unmarshalUniverseRoot(universeRoot.IssuanceRoot)
	}

	return unmarshalUniverseRoot(universeRoot.TransferRoot)
}

// UniverseLeafKeys returns all the leaf entries in the universe.
// When the responding peer populates `entries`, each returned
// LeafEntry carries the peer's MS-SMT leaf node hash so the syncer
// can diff on content. When only the legacy `asset_keys` field is
// populated, NodeHash is left as None and callers must fall back to
// a key-only diff for that peer.
func (r *RpcUniverseDiff) UniverseLeafKeys(ctx context.Context,
	q universe.UniverseLeafKeysQuery) ([]universe.LeafEntry, error) {

	uniID, err := MarshalUniID(q.Id)
	if err != nil {
		return nil, err
	}

	resp, err := r.conn.AssetLeafKeys(
		ctx, &unirpc.AssetLeafKeysRequest{
			Id:        uniID,
			Direction: taprpc.SortDirection(q.SortDirection),
			Offset:    q.Offset,
			Limit:     q.Limit,
		},
	)
	if err != nil {
		return nil, err
	}

	// Prefer the entries field (carries per-leaf node hashes) when
	// the peer populated it; otherwise fall back to the legacy
	// asset_keys field with NodeHash unset.
	if len(resp.Entries) > 0 {
		entries := make([]universe.LeafEntry, len(resp.Entries))
		for i, entry := range resp.Entries {
			leafKey, err := unmarshalLeafKey(entry.AssetKey)
			if err != nil {
				return nil, err
			}

			nodeHash := fn.None[mssmt.NodeHash]()
			if len(entry.LeafNodeHash) > 0 {
				h, err := mssmt.NewNodeHashFromBytes(
					entry.LeafNodeHash,
				)
				if err != nil {
					return nil, fmt.Errorf("invalid "+
						"leaf node hash: %w", err)
				}
				nodeHash = fn.Some(h)
			}

			entries[i] = universe.LeafEntry{
				Key:      leafKey,
				NodeHash: nodeHash,
			}
		}

		return entries, nil
	}

	entries := make([]universe.LeafEntry, len(resp.AssetKeys))
	for i, key := range resp.AssetKeys {
		leafKey, err := unmarshalLeafKey(key)
		if err != nil {
			return nil, err
		}

		entries[i] = universe.LeafEntry{
			Key:      leafKey,
			NodeHash: fn.None[mssmt.NodeHash](),
		}
	}

	return entries, nil
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

// SyncDelta returns the page of leaves inserted on the remote server
// after sinceSeq, in insertion order. If the remote server predates the
// delta sync RPC, universe.ErrDeltaUnsupported is returned and the
// caller should fall back to enumeration-based sync.
//
// NOTE: this is part of the universe.DeltaEngine interface.
func (r *RpcUniverseDiff) SyncDelta(ctx context.Context, sinceSeq uint64,
	pageSize int32) (*universe.DeltaPage, error) {

	resp, err := r.conn.SyncDelta(ctx, &universerpc.SyncDeltaRequest{
		SinceSeq: sinceSeq,
		PageSize: pageSize,
	})
	if status.Code(err) == codes.Unimplemented {
		return nil, universe.ErrDeltaUnsupported
	}
	if err != nil {
		return nil, err
	}

	page := &universe.DeltaPage{
		Roots: make(
			map[universe.IdentifierKey]universe.Root,
			len(resp.UniverseRoots),
		),
		LatestSeq: resp.LatestSeq,
	}

	for _, rpcRoot := range resp.UniverseRoots {
		root, err := unmarshalUniverseRoot(rpcRoot)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal "+
				"universe root: %w", err)
		}

		page.Roots[root.ID.Key()] = root
	}

	for _, rpcItem := range resp.Items {
		uniID, err := UnmarshalUniID(rpcItem.UniverseId)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal "+
				"universe ID (seq=%d): %w", rpcItem.Seq, err)
		}

		leafKey, err := unmarshalLeafKey(rpcItem.Key)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal leaf "+
				"key (seq=%d): %w", rpcItem.Seq, err)
		}

		leaf, err := unmarshalAssetLeaf(rpcItem.Leaf)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal asset "+
				"leaf (seq=%d): %w", rpcItem.Seq, err)
		}

		var compressedProof mssmt.CompressedProof
		err = compressedProof.Decode(
			bytes.NewReader(rpcItem.UniverseInclusionProof),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode inclusion "+
				"proof (seq=%d): %w", rpcItem.Seq, err)
		}

		inclusionProof, err := compressedProof.Decompress()
		if err != nil {
			return nil, fmt.Errorf("unable to decompress "+
				"inclusion proof (seq=%d): %w", rpcItem.Seq,
				err)
		}

		page.Items = append(page.Items, universe.DeltaLeafItem{
			Seq:            rpcItem.Seq,
			ID:             uniID,
			Key:            leafKey,
			Leaf:           leaf,
			InclusionProof: inclusionProof,
		})
	}

	return page, nil
}

// Close closes the underlying RPC connection to the remote universe server.
func (r *RpcUniverseDiff) Close() error {
	if err := r.conn.Close(); err != nil {
		tapdLog.Warnf("unable to close universe RPC "+
			"connection: %v", err)
		return err
	}

	return nil
}

// A compile time interface to ensure that RpcUniverseDiff implements the
// universe.DiffEngine interface.
var _ universe.DiffEngine = (*RpcUniverseDiff)(nil)

// A compile time interface to ensure that RpcUniverseDiff implements the
// universe.DeltaEngine interface.
var _ universe.DeltaEngine = (*RpcUniverseDiff)(nil)
