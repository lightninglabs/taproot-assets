package taro

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/rpcperms"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// poolMacaroonLocation is the value we use for the taro macaroons'
	// "Location" field when baking them.
	taroMacaroonLocation = "taro"
)

var (
	// RequiredPermissions is a map of all taro RPC methods and their
	// required macaroon permissions to access tarod.
	//
	// TODO(roasbeef): re think these and go instead w/ the * approach?
	RequiredPermissions = map[string][]bakery.Op{
		"/tarorpc.Taro/StopDaemon": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/tarorpc.Taro/DebugLevel": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/tarorpc.Taro/MintAsset": {{
			Entity: "assets",
			Action: "write",
		}},
		"/tarorpc.Taro/ListAssets": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/QueryTaroAddrs": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/NewTaroAddr": {{
			Entity: "addresses",
			Action: "write",
		}},
		"/tarorpc.Taro/DecodeTaroAddr": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/VerifyProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/tarorpc.Taro/ExportProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/tarorpc.Taro/ImportProof": {{
			Entity: "proofs",
			Action: "write",
		}},
	}
)

// rpcServer is the main RPC server for the Taro daemon that handles
// gRPC/REST/Websockets incoming requests.
type rpcServer struct {
	started  int32
	shutdown int32

	tarorpc.UnimplementedTaroServer

	interceptor signal.Interceptor

	interceptorChain *rpcperms.InterceptorChain

	cfg *Config

	quit chan struct{}
	wg   sync.WaitGroup
}

// newRPCServer creates a new RPC sever from the set of input dependencies.
func newRPCServer(interceptor signal.Interceptor,
	interceptorChain *rpcperms.InterceptorChain,
	cfg *Config) (*rpcServer, error) {

	// Register all our known permission with the macaroon service.
	for method, ops := range RequiredPermissions {
		if err := interceptorChain.AddPermission(method, ops); err != nil {
			return nil, err
		}
	}

	return &rpcServer{
		interceptor:      interceptor,
		interceptorChain: interceptorChain,
		quit:             make(chan struct{}),
		cfg:              cfg,
	}, nil
}

// TODO(roasbeef): build in batching for asset creation?

// Start signals that the RPC server starts accepting requests.
func (r *rpcServer) Start() error {
	if atomic.AddInt32(&r.started, 1) != 1 {
		return nil
	}

	rpcsLog.Infof("Starting RPC Server")

	return nil
}

// Stop signals that the RPC server should attempt a graceful shutdown and
// cancel any outstanding requests.
func (r *rpcServer) Stop() error {
	if atomic.AddInt32(&r.shutdown, 1) != 1 {
		return nil
	}

	rpcsLog.Infof("Stopping RPC Server")

	close(r.quit)

	r.wg.Wait()

	return nil
}

// RegisterWithGrpcServer registers the rpcServer with the passed root gRPC
// server.
func (r *rpcServer) RegisterWithGrpcServer(grpcServer *grpc.Server) error {
	// Register the main RPC server.
	tarorpc.RegisterTaroServer(grpcServer, r)
	return nil
}

// RegisterWithRestProxy registers the RPC server with the given rest proxy.
func (r *rpcServer) RegisterWithRestProxy(restCtx context.Context,
	restMux *proxy.ServeMux, restDialOpts []grpc.DialOption,
	restProxyDest string) error {

	// With our custom REST proxy mux created, register our main RPC and
	// give all subservers a chance to register as well.
	err := tarorpc.RegisterTaroHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	return nil
}

// allowCORS wraps the given http.Handler with a function that adds the
// Access-Control-Allow-Origin header to the response.
func allowCORS(handler http.Handler, origins []string) http.Handler {
	allowHeaders := "Access-Control-Allow-Headers"
	allowMethods := "Access-Control-Allow-Methods"
	allowOrigin := "Access-Control-Allow-Origin"

	// If the user didn't supply any origins that means CORS is disabled
	// and we should return the original handler.
	if len(origins) == 0 {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Skip everything if the browser doesn't send the Origin field.
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}

		// Set the static header fields first.
		w.Header().Set(
			allowHeaders,
			"Content-Type, Accept, Grpc-Metadata-Macaroon",
		)
		w.Header().Set(allowMethods, "GET, POST, DELETE")

		// Either we allow all origins or the incoming request matches
		// a specific origin in our list of allowed origins.
		for _, allowedOrigin := range origins {
			if allowedOrigin == "*" || origin == allowedOrigin {
				// Only set allowed origin to requested origin.
				w.Header().Set(allowOrigin, origin)

				break
			}
		}

		// For a pre-flight request we only need to send the headers
		// back. No need to call the rest of the chain.
		if r.Method == "OPTIONS" {
			return
		}

		// Everything's prepared now, we can pass the request along the
		// chain of handlers.
		handler.ServeHTTP(w, r)
	})
}

// StopDaemon will send a shutdown request to the interrupt handler, triggering
// a graceful shutdown of the daemon.
func (r *rpcServer) StopDaemon(_ context.Context,
	_ *tarorpc.StopRequest) (*tarorpc.StopResponse, error) {

	r.interceptor.RequestShutdown()
	return &tarorpc.StopResponse{}, nil
}

// DebugLevel allows a caller to programmatically set the logging verbosity of
// tarod. The logging can be targeted according to a coarse daemon-wide logging
// level, or in a granular fashion to specify the logging for a target
// sub-system.
func (r *rpcServer) DebugLevel(ctx context.Context,
	req *tarorpc.DebugLevelRequest) (*tarorpc.DebugLevelResponse, error) {

	// If show is set, then we simply print out the list of available
	// sub-systems.
	if req.Show {
		return &tarorpc.DebugLevelResponse{
			SubSystems: strings.Join(
				r.cfg.LogWriter.SupportedSubsystems(), " ",
			),
		}, nil
	}

	rpcsLog.Infof("[debuglevel] changing debug level to: %v", req.LevelSpec)

	// Otherwise, we'll attempt to set the logging level using the
	// specified level spec.
	err := build.ParseAndSetDebugLevels(req.LevelSpec, r.cfg.LogWriter)
	if err != nil {
		return nil, err
	}

	return &tarorpc.DebugLevelResponse{}, nil
}

// MintAsset will attempts to mint the set of assets (async by default to
// ensure proper batching) specified in the request.
func (r *rpcServer) MintAsset(ctx context.Context,
	req *tarorpc.MintAssetRequest) (*tarorpc.MintAssetResponse, error) {

	seedling := &tarogarden.Seedling{
		AssetType:      asset.Type(req.AssetType),
		AssetName:      req.Name,
		Metadata:       req.MetaData,
		Amount:         uint64(req.Amount),
		EnableEmission: req.EnableEmission,
		NoBatch:        req.SkipBatch,
	}
	updates, err := r.cfg.AssetMinter.QueueNewSeedling(seedling)
	if err != nil {
		return nil, fmt.Errorf("unable to mint new asset: %w", err)
	}

	// Wait for an initial update so we can report back if things succeeded
	// or failed.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context closed: %w", ctx.Err())

	case update := <-updates:
		if update.Error != nil {
			return nil, fmt.Errorf("unable to mint asset: %w",
				update.Error)
		}

		return &tarorpc.MintAssetResponse{
			BatchKey: update.BatchKey.SerializeCompressed(),
		}, nil
	}
}

// ListAssets lists the set of assets owned by the target daemon.
func (r *rpcServer) ListAssets(ctx context.Context,
	req *tarorpc.ListAssetRequest) (*tarorpc.ListAssetResponse, error) {

	assets, err := r.cfg.AssetStore.FetchAllAssets(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to read chain assets: %w", err)
	}

	rpcAssets := make([]*tarorpc.Asset, len(assets))
	for i, asset := range assets {
		assetID := asset.Genesis.ID()

		var anchorTxBytes []byte
		if asset.AnchorTx != nil {
			var anchorTxBuf bytes.Buffer
			err := asset.AnchorTx.Serialize(&anchorTxBuf)
			if err != nil {
				return nil, fmt.Errorf("unable to serialize "+
					"anchor tx: %v", err)
			}
			anchorTxBytes = anchorTxBuf.Bytes()
		}
		rpcAssets[i] = &tarorpc.Asset{
			AssetGenesis: &tarorpc.GenesisInfo{
				GenesisPoint: asset.Genesis.FirstPrevOut.String(),
				Name:         asset.Genesis.Tag,
				Meta:         asset.Genesis.Metadata,
				AssetId:      assetID[:],
			},
			AssetType:        tarorpc.AssetType(asset.Type),
			Amount:           int64(asset.Amount),
			LockTime:         int32(asset.LockTime),
			RelativeLockTime: int32(asset.RelativeLockTime),
			ScriptVersion:    int32(asset.ScriptVersion),
			ScriptKey:        asset.ScriptKey.PubKey.SerializeCompressed(),
			ChainAnchor: &tarorpc.AnchorInfo{
				AnchorTx:        anchorTxBytes,
				AnchorTxid:      asset.AnchorTxid[:],
				AnchorBlockHash: asset.AnchorBlockHash[:],
				AnchorOutpoint:  asset.AnchorOutpoint.String(),
			},
		}

		if asset.FamilyKey != nil {
			rpcAssets[i].AssetFamily = &tarorpc.AssetFamily{
				RawFamilyKey:     asset.FamilyKey.RawKey.PubKey.SerializeCompressed(),
				TweakedFamilyKey: asset.FamilyKey.FamKey.SerializeCompressed(),
				AssetIdSig:       asset.FamilyKey.Sig.Serialize(),
			}
		}
	}

	return &tarorpc.ListAssetResponse{
		Assets: rpcAssets,
	}, nil
}

// QueryAddrs queries the set of Taro addresses stored in the database.
func (r *rpcServer) QueryAddrs(ctx context.Context,
	in *tarorpc.QueryAddrRequest) (*tarorpc.QueryAddrResponse, error) {

	query := address.QueryParams{
		CreatedAfter:  time.Unix(in.CreatedAfter, 0),
		CreatedBefore: time.Unix(in.CreatedBefore, 0),
		Limit:         in.Limit,
		Offset:        in.Offset,
	}

	rpcsLog.Debugf("[QueryAddrs]: addr query params: %v",
		spew.Sdump(query))

	dbAddrs, err := r.cfg.AddrBook.ListAddrs(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("unable to query addrs: %w", err)
	}

	// TODO(roasbeef): just stop storing the hrp in the addr?
	taroParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	addrs := make([]*tarorpc.Addr, len(dbAddrs))
	for i, dbAddr := range dbAddrs {
		dbAddr.ChainParams = &taroParams

		addrStr, err := dbAddr.EncodeAddress()
		if err != nil {
			return nil, fmt.Errorf("unable to encode addr: %w", err)
		}

		addrs[i] = &tarorpc.Addr{
			Addr: addrStr,
		}
	}

	rpcsLog.Debugf("[QueryTaroAddrs]: returning %v addrs", len(addrs))

	return &tarorpc.QueryAddrResponse{
		Addrs: addrs,
	}, nil
}

// NewAddr makes a new address from the set of request params.
func (r *rpcServer) NewAddr(ctx context.Context,
	in *tarorpc.NewAddrRequest) (*tarorpc.Addr, error) {

	var (
		famKey *btcec.PublicKey
		err    error
	)

	// The family key is optional, so we'll only decode it if it's
	// specified.
	if len(in.FamKey) != 0 {
		famKey, err = btcec.ParsePubKey(in.FamKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode "+
				"fam key: %w", err)
		}
	}

	var assetID asset.ID
	copy(assetID[:], in.AssetId)

	rpcsLog.Infof("[NewTaroAddr]: making new addr: asset_id=%x, amt=%v, type=%v",
		assetID, in.Amt, asset.Type(in.AssetType))

	// Now that we have all the params, we'll try to add a new address to
	// the addr book.
	addr, err := r.cfg.AddrBook.NewAddress(
		ctx, assetID, famKey, uint64(in.Amt), asset.Type(in.AssetType),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new addr: %w", err)
	}

	// With our addr obtained, we'll encode it as a string then send off
	// the response.
	addrStr, err := addr.EncodeAddress()
	if err != nil {
		return nil, fmt.Errorf("unable to encode addr: %w", err)
	}
	return &tarorpc.Addr{
		Addr: addrStr,
	}, nil
}

// DecodeAddr decode a Taro address into a partial asset message that
// represents the asset it wants to receive.
func (r *rpcServer) DecodeAddr(ctx context.Context,
	in *tarorpc.Addr) (*tarorpc.Asset, error) {

	if len(in.Addr) == 0 {
		return nil, fmt.Errorf("must specify an addr")
	}

	taroParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	addr, err := address.DecodeAddress(in.Addr, &taroParams)
	if err != nil {
		return nil, fmt.Errorf("unable to decode addr: %w", err)
	}

	var famKeyBytes []byte
	if addr.FamilyKey != nil {
		famKeyBytes = addr.FamilyKey.SerializeCompressed()
	}

	// TODO(roasbeef): display internal key somewhere?
	return &tarorpc.Asset{
		AssetGenesis: &tarorpc.GenesisInfo{
			AssetId: addr.ID[:],
		},
		AssetFamily: &tarorpc.AssetFamily{
			TweakedFamilyKey: famKeyBytes,
		},
		ScriptKey: addr.ScriptKey.SerializeCompressed(),
		Amount:    int64(addr.Amount),
		AssetType: tarorpc.AssetType(addr.Type),
	}, nil
}

// VerifyProof attempts to verify a given proof file that claims to be anchored
// at the specified genesis point.
func (r *rpcServer) VerifyProof(ctx context.Context,
	in *tarorpc.ProofFile) (*tarorpc.ProofVerifyResponse, error) {

	if len(in.RawProof) == 0 {
		return nil, fmt.Errorf("proof file must be specified")
	}

	var proofFile proof.File
	err := proofFile.Decode(bytes.NewReader(in.RawProof))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	_, err = proofFile.Verify(ctx)
	valid := err == nil

	// TODO(roasbeef): also show additional final resting anchor
	// information, etc?

	// TODO(roasbeef): show the final resting place of the asset?
	return &tarorpc.ProofVerifyResponse{
		Valid: valid,
	}, nil
}

// ExportProof exports the latest raw proof file anchored at the specified
// script_key.
func (r *rpcServer) ExportProof(ctx context.Context,
	in *tarorpc.ExportProofRequest) (*tarorpc.ProofFile, error) {

	if len(in.ScriptKey) == 0 {
		return nil, fmt.Errorf("a valid script key must be specified")
	}

	scriptKey, err := btcec.ParsePubKey(in.ScriptKey)
	if err != nil {
		return nil, fmt.Errorf("invalid script key: %w", err)
	}

	if len(in.AssetId) != 32 {
		return nil, fmt.Errorf("asset ID must be 32 bytes")
	}

	var assetID asset.ID
	copy(assetID[:], in.AssetId)

	proofBlob, err := r.cfg.ProofArchive.FetchProof(ctx, proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *scriptKey,
	})
	if err != nil {
		return nil, err
	}

	return &tarorpc.ProofFile{
		RawProof: proofBlob,
	}, nil
}

// ImportProof attempts to import a proof file into the daemon. If successful, a
// new asset will be inserted on disk, spendable using the specified target
// script key, and internal key.
func (r *rpcServer) ImportProof(ctx context.Context,
	in *tarorpc.ImportProofRequest) (*tarorpc.ImportProofResponse, error) {

	// We'll perform some basic input validation before we move forward.
	if len(in.ProofFile) == 0 {
		return nil, fmt.Errorf("proof file must be specified")
	}

	// Now that we know the proof file is at least present, we'll attempt
	// to import it into the main archive.
	err := r.cfg.ProofArchive.ImportProofs(ctx, &proof.AnnotatedProof{
		Blob: in.ProofFile,
	})
	if err != nil {
		return nil, err
	}

	return &tarorpc.ImportProofResponse{}, nil
}
