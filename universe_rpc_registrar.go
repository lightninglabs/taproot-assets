package taprootassets

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RpcUniverseRegistrar is an implementation of the universe.Registrar interface
// that uses an RPC connection to target Universe.
type RpcUniverseRegistrar struct {
	conn unirpc.UniverseClient
}

// NewRpcUniverseRegistrar creates a new RpcUniverseRegistrar instance that
// dials out to the target remote universe server address.
func NewRpcUniverseRegistrar(
	serverAddr universe.ServerAddr) (universe.Registrar, error) {

	conn, err := ConnectUniverse(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to universe RPC "+
			"server: %w", err)
	}

	return &RpcUniverseRegistrar{
		conn: conn,
	}, nil
}

// unmarshalIssuanceProof un-marshals an issuance proof response into a struct
// usable by the universe package.
func unmarshalIssuanceProof(uniKey *unirpc.UniverseKey,
	proofResp *unirpc.AssetProofResponse) (*universe.Proof, error) {

	leafKey, err := unmarshalLeafKey(uniKey.LeafKey)
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

	return &universe.Proof{
		LeafKey: leafKey,
		UniverseRoot: mssmt.NewComputedBranch(
			fn.ToArray[mssmt.NodeHash](
				proofResp.UniverseRoot.MssmtRoot.RootHash,
			),
			uint64(proofResp.UniverseRoot.MssmtRoot.RootSum),
		),
		UniverseInclusionProof: inclusionProof,
		Leaf:                   assetLeaf,
	}, nil
}

// RegisterIssuance is an implementation of the universe.Registrar interface
// that uses a remote Universe server as the Registry instance.
func (r *RpcUniverseRegistrar) RegisterIssuance(ctx context.Context,
	id universe.Identifier, key universe.LeafKey,
	leaf *universe.Leaf) (*universe.Proof, error) {

	uniID, err := MarshalUniID(id)
	if err != nil {
		return nil, err
	}

	// First, we'll parse the proofs and key into their RPC counterparts.
	uniKey := &unirpc.UniverseKey{
		Id:      uniID,
		LeafKey: marshalLeafKey(key),
	}

	assetLeaf, err := marshalAssetLeaf(ctx, nil, leaf)
	if err != nil {
		return nil, err
	}

	// With the RPC req prepared, we'll now send it off to the remote
	// Universe serve as a new proof insertion request.
	proofResp, err := r.conn.InsertProof(ctx, &unirpc.AssetProof{
		Key:       uniKey,
		AssetLeaf: assetLeaf,
	})
	if err != nil {
		return nil, err
	}

	// Finally, we'll map the response back into the Proof we expect
	// as a response.
	return unmarshalIssuanceProof(uniKey, proofResp)
}

// A compile time interface to ensure that RpcUniverseRegistrar implements the
// universe.Registrar interface.
var _ universe.Registrar = (*RpcUniverseRegistrar)(nil)

// CheckFederationServer attempts to connect to the target server and ensure
// that it is a valid federation server that isn't the local daemon.
func CheckFederationServer(localRuntimeID int64, connectTimeout time.Duration,
	server universe.ServerAddr) error {

	srvrLog.Debugf("Attempting to connect to federation server %v",
		server.HostStr())

	conn, err := ConnectUniverse(server)
	if err != nil {
		return fmt.Errorf("error connecting to server %v: %w",
			server.HostStr(), err)
	}

	// We don't allow adding ourselves as a federation member.
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, connectTimeout)
	defer cancel()

	info, err := conn.Info(ctxt, &unirpc.InfoRequest{})
	if err != nil {
		return fmt.Errorf("error getting info from server %v: %w",
			server.HostStr(), err)
	}

	if info.RuntimeId == localRuntimeID {
		return fmt.Errorf("cannot add ourselves as a federation member")
	}

	return nil
}

// ConnectUniverse connects to a remote Universe server using the provided
// server address.
func ConnectUniverse(
	serverAddr universe.ServerAddr) (unirpc.UniverseClient, error) {

	// TODO(roasbeef): all info is authenticated, but also want to allow
	// brontide connect as well, can avoid TLS certs
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
	})

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(MaxMsgReceiveSize),
	}

	uniAddr, err := serverAddr.Addr()
	if err != nil {
		return nil, err
	}

	rawConn, err := grpc.Dial(uniAddr.String(), opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC "+
			"server: %v", err)
	}

	return unirpc.NewUniverseClient(rawConn), nil
}
