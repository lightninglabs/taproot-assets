package taprootassets

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"

	"github.com/lightninglabs/taproot-assets/chanutils"
	"github.com/lightninglabs/taproot-assets/mssmt"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RpcUniverseRegistar is an implementation of the universe.Registrar interface
// that uses an RPC connection to target Universe.
type RpcUniverseRegistar struct {
	conn unirpc.UniverseClient
}

// NewRpcUniverseRegistrar creates a new RpcUniverseRegistrar instance that
// dials out to the target remote universe server address.
func NewRpcUniverseRegistar(serverAddr universe.ServerAddr,
) (universe.Registrar, error) {

	// TODO(roasbeef): all info is authenticated, but also want to allow
	// brontide connect as well, can avoid TLS certs
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
	})

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	uniAddr, err := serverAddr.Addr()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(uniAddr.String(), opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC "+
			"server: %v", err)
	}

	return &RpcUniverseRegistar{
		conn: unirpc.NewUniverseClient(conn),
	}, nil
}

// unmarshalIssuanceProof unmarshals an issuance proof response into a struct
// useable by the universe package.
func unmarshalIssuanceProof(ctx context.Context,
	uniKey *unirpc.UniverseKey, proofResp *unirpc.IssuanceProofResponse,
) (*universe.IssuanceProof, error) {

	baseKey, err := unmarshalLeafKey(uniKey.LeafKey)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := unmarshalAssetLeaf(proofResp.AssetLeaf)
	if err != nil {
		return nil, err
	}

	var compressedProof mssmt.CompressedProof
	err = compressedProof.Decode(
		bytes.NewReader(proofResp.UniverseInclusionProof),
	)
	if err != nil {
		return nil, err
	}

	inclusionProof, err := compressedProof.Decompress()
	if err != nil {
		return nil, err
	}

	return &universe.IssuanceProof{
		MintingKey: baseKey,
		UniverseRoot: mssmt.NewComputedBranch(
			chanutils.ToArray[mssmt.NodeHash](
				proofResp.UniverseRoot.MssmtRoot.RootHash,
			),
			uint64(proofResp.UniverseRoot.MssmtRoot.RootSum),
		),
		InclusionProof: inclusionProof,
		Leaf:           assetLeaf,
	}, nil
}

// RegisterIssuance is an implementation of the universe.Registrar interface
// that uses a remote Universe server as the Registry instance.
func (r *RpcUniverseRegistar) RegisterIssuance(ctx context.Context,
	id universe.Identifier, key universe.BaseKey,
	leaf *universe.MintingLeaf) (*universe.IssuanceProof, error) {

	// First, we'll parse the proofs and key into their RPC counterparts.
	uniKey := &unirpc.UniverseKey{
		Id:      marshalUniID(id),
		LeafKey: marshalLeafKey(key),
	}

	assetLeaf, err := marshalAssetLeaf(ctx, nil, leaf)
	if err != nil {
		return nil, err
	}

	// With the RPC req prepared, we'll now send it off to the remote
	// Universe serve as a new proof insertion request.
	proofResp, err := r.conn.InsertIssuanceProof(
		ctx, &unirpc.IssuanceProof{
			Key:       uniKey,
			AssetLeaf: assetLeaf,
		},
	)
	if err != nil {
		return nil, err
	}

	// Finally, we'll map the response back into the IssuanceProof we
	// expect as a response.
	return unmarshalIssuanceProof(ctx, uniKey, proofResp)
}

// A compile time interface to ensure that RpcUniverseRegistrar implements the
// universe.Registrar interface.
var _ universe.Registrar = (*RpcUniverseRegistar)(nil)
