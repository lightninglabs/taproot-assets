package taro

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/rpcperms"
	"github.com/lightninglabs/taro/tarofreighter"
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
		"/tarorpc.Taro/ListBalances": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/QueryAddrs": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/NewAddr": {{
			Entity: "addresses",
			Action: "write",
		}},
		"/tarorpc.Taro/DecodeAddr": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/AddrReceives": {{
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
		"/tarorpc.Taro/SendAsset": {{
			Entity: "assets",
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

// MintAsset attempts to mint the set of assets (async by default to ensure
// proper batching) specified in the request.
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
	for i, a := range assets {
		assetID := a.Genesis.ID()

		var bootstrapInfoBuf bytes.Buffer
		if err := a.Genesis.Encode(&bootstrapInfoBuf); err != nil {
			return nil, fmt.Errorf("unable to encode genesis: %w",
				err)
		}

		var anchorTxBytes []byte
		if a.AnchorTx != nil {
			var anchorTxBuf bytes.Buffer
			err := a.AnchorTx.Serialize(&anchorTxBuf)
			if err != nil {
				return nil, fmt.Errorf("unable to serialize "+
					"anchor tx: %w", err)
			}
			anchorTxBytes = anchorTxBuf.Bytes()
		}
		rpcAssets[i] = &tarorpc.Asset{
			Version: int32(a.Version),
			AssetGenesis: &tarorpc.GenesisInfo{
				GenesisPoint:         a.Genesis.FirstPrevOut.String(),
				Name:                 a.Genesis.Tag,
				Meta:                 a.Genesis.Metadata,
				AssetId:              assetID[:],
				OutputIndex:          a.Genesis.OutputIndex,
				GenesisBootstrapInfo: bootstrapInfoBuf.Bytes(),
			},
			AssetType:        tarorpc.AssetType(a.Type),
			Amount:           int64(a.Amount),
			LockTime:         int32(a.LockTime),
			RelativeLockTime: int32(a.RelativeLockTime),
			ScriptVersion:    int32(a.ScriptVersion),
			ScriptKey:        a.ScriptKey.PubKey.SerializeCompressed(),
			ChainAnchor: &tarorpc.AnchorInfo{
				AnchorTx:        anchorTxBytes,
				AnchorTxid:      a.AnchorTxid[:],
				AnchorBlockHash: a.AnchorBlockHash[:],
				AnchorOutpoint:  a.AnchorOutpoint.String(),
				InternalKey:     a.AnchorInternalKey.SerializeCompressed(),
			},
		}

		if a.FamilyKey != nil {
			rpcAssets[i].AssetFamily = &tarorpc.AssetFamily{
				RawFamilyKey:     a.FamilyKey.RawKey.PubKey.SerializeCompressed(),
				TweakedFamilyKey: a.FamilyKey.FamKey.SerializeCompressed(),
				AssetIdSig:       a.FamilyKey.Sig.Serialize(),
			}
		}
	}

	return &tarorpc.ListAssetResponse{
		Assets: rpcAssets,
	}, nil
}

func (r *rpcServer) listBalancesByAsset(ctx context.Context,
	assetID *asset.ID) (*tarorpc.ListBalancesResponse, error) {

	balances, err := r.cfg.AssetStore.QueryBalancesByAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("unable to list balances: %w", err)
	}

	resp := &tarorpc.ListBalancesResponse{
		AssetBalances: make(map[string]*tarorpc.AssetBalance, len(balances)),
	}

	for _, balance := range balances {
		assetIDStr := hex.EncodeToString(balance.ID[:])

		gen := asset.Genesis{
			FirstPrevOut: balance.GenesisPoint,
			Tag:          balance.Tag,
			Metadata:     balance.Meta,
			OutputIndex:  balance.OutputIndex,
			Type:         balance.Type,
		}
		var bootstrapInfoBuf bytes.Buffer
		if err := gen.Encode(&bootstrapInfoBuf); err != nil {
			return nil, fmt.Errorf("unable to encode genesis: %w",
				err)
		}

		resp.AssetBalances[assetIDStr] = &tarorpc.AssetBalance{
			AssetGenesis: &tarorpc.GenesisInfo{
				Version:              int32(balance.Version),
				GenesisPoint:         balance.GenesisPoint.String(),
				Name:                 balance.Tag,
				Meta:                 balance.Meta,
				AssetId:              balance.ID[:],
				GenesisBootstrapInfo: bootstrapInfoBuf.Bytes(),
			},
			AssetType: tarorpc.AssetType(balance.Type),
			Balance:   int64(balance.Balance),
		}
	}

	return resp, nil
}

func (r *rpcServer) listBalancesByFamilyKey(ctx context.Context,
	famKey *btcec.PublicKey) (*tarorpc.ListBalancesResponse, error) {

	balances, err := r.cfg.AssetStore.QueryAssetBalancesByFamily(
		ctx, famKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list balances: %w", err)
	}

	resp := &tarorpc.ListBalancesResponse{
		AssetFamilyBalances: make(
			map[string]*tarorpc.AssetFamilyBalance, len(balances),
		),
	}

	for _, balance := range balances {
		var famKey []byte
		if balance.FamKey != nil {
			famKey = balance.FamKey.SerializeCompressed()
		}

		famKeyString := hex.EncodeToString(famKey)
		resp.AssetFamilyBalances[famKeyString] = &tarorpc.AssetFamilyBalance{
			FamilyKey: famKey,
			Balance:   int64(balance.Balance),
		}
	}

	return resp, nil
}

// ListBalances lists the asset balances owned by the daemon.
func (r *rpcServer) ListBalances(ctx context.Context,
	in *tarorpc.ListBalancesRequest) (*tarorpc.ListBalancesResponse, error) {

	switch groupBy := in.GroupBy.(type) {
	case *tarorpc.ListBalancesRequest_AssetId:
		if !groupBy.AssetId {
			return nil, fmt.Errorf("invalid group_by")
		}

		var assetID *asset.ID
		if len(in.AssetFilter) != 0 {
			assetID = &asset.ID{}
			if len(in.AssetFilter) != len(assetID) {
				return nil, fmt.Errorf("invalid asset filter")
			}

			copy(assetID[:], in.AssetFilter)
		}

		return r.listBalancesByAsset(ctx, assetID)

	case *tarorpc.ListBalancesRequest_FamKey:
		if !groupBy.FamKey {
			return nil, fmt.Errorf("invalid group_by")
		}

		var famKey *btcec.PublicKey
		if len(in.FamilyKeyFilter) != 0 {
			var err error
			famKey, err = btcec.ParsePubKey(in.FamilyKeyFilter)
			if err != nil {
				return nil, fmt.Errorf("invalid family key "+
					"filter: %v", err)
			}
		}

		return r.listBalancesByFamilyKey(ctx, famKey)

	default:
		return nil, fmt.Errorf("invalid group_by")
	}
}

// QueryAddrs queries the set of Taro addresses stored in the database.
func (r *rpcServer) QueryAddrs(ctx context.Context,
	in *tarorpc.QueryAddrRequest) (*tarorpc.QueryAddrResponse, error) {

	query := address.QueryParams{
		Limit:  in.Limit,
		Offset: in.Offset,
	}

	// The unix time of 0 (1970-01-01) is not the same as an empty Time
	// struct (0000-00-00). For our query to succeed, we need to set the
	// time values the way the address book expects them.
	if in.CreatedBefore > 0 {
		query.CreatedBefore = time.Unix(in.CreatedBefore, 0)
	}
	if in.CreatedAfter > 0 {
		query.CreatedAfter = time.Unix(in.CreatedAfter, 0)
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
		addrs[i], err = marshalAddr(dbAddr.Taro)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal addr: %w",
				err)
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

	genReader := bytes.NewReader(in.GenesisBootstrapInfo)
	genesis, err := asset.DecodeGenesis(genReader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode genesis bootstrap "+
			"info: %w", err)
	}

	assetID := genesis.ID()
	rpcsLog.Infof("[NewAddr]: making new addr: asset_id=%x, amt=%v, "+
		"type=%v", assetID[:], in.Amt, asset.Type(genesis.Type))

	// Now that we have all the params, we'll try to add a new address to
	// the addr book.
	addr, err := r.cfg.AddrBook.NewAddress(
		ctx, genesis, famKey, uint64(in.Amt),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new addr: %w", err)
	}

	// With our addr obtained, we'll marshal it as an RPC message then send
	// off the response.
	rpcAddr, err := marshalAddr(addr.Taro)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal addr: %w", err)
	}

	return rpcAddr, nil
}

// DecodeAddr decode a Taro address into a partial asset message that
// represents the asset it wants to receive.
func (r *rpcServer) DecodeAddr(_ context.Context,
	in *tarorpc.DecodeAddrRequest) (*tarorpc.Addr, error) {

	if len(in.Addr) == 0 {
		return nil, fmt.Errorf("must specify an addr")
	}

	taroParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	addr, err := address.DecodeAddress(in.Addr, &taroParams)
	if err != nil {
		return nil, fmt.Errorf("unable to decode addr: %w", err)
	}

	rpcAddr, err := marshalAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal addr: %w", err)
	}

	return rpcAddr, nil
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

// AddrReceives lists all receives for incoming asset transfers for addresses
// that were created previously.
func (r *rpcServer) AddrReceives(ctx context.Context,
	in *tarorpc.AddrReceivesRequest) (*tarorpc.AddrReceivesResponse,
	error) {

	var sqlQuery address.EventQueryParams

	if len(in.FilterAddr) > 0 {
		taroParams := address.ParamsForChain(r.cfg.ChainParams.Name)

		addr, err := address.DecodeAddress(in.FilterAddr, &taroParams)
		if err != nil {
			return nil, fmt.Errorf("unable to decode addr: %w", err)
		}

		taprootOutputKey, err := addr.TaprootOutputKey(nil)
		if err != nil {
			return nil, fmt.Errorf("error deriving Taproot key: %w",
				err)
		}

		sqlQuery.AddrTaprootOutputKey = schnorr.SerializePubKey(
			taprootOutputKey,
		)
	}

	if in.FilterStatus != tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_UNKNOWN {
		status, err := unmarshalAddrEventStatus(in.FilterStatus)
		if err != nil {
			return nil, fmt.Errorf("error parsing status: %w", err)
		}

		sqlQuery.StatusFrom = &status
		sqlQuery.StatusTo = &status
	}

	events, err := r.cfg.AddrBook.QueryEvents(ctx, sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("error querying events: %w", err)
	}

	resp := &tarorpc.AddrReceivesResponse{
		Events: make([]*tarorpc.AddrEvent, len(events)),
	}

	for idx, event := range events {
		resp.Events[idx], err = marshalAddrEvent(event)
		if err != nil {
			return nil, fmt.Errorf("error marshaling event: %w",
				err)
		}
	}

	return resp, nil
}

// marshalAddr turns an address into its RPC counterpart.
func marshalAddr(addr *address.Taro) (*tarorpc.Addr, error) {
	addrStr, err := addr.EncodeAddress()
	if err != nil {
		return nil, fmt.Errorf("unable to encode addr: %w", err)
	}

	taprootOutputKey, err := addr.TaprootOutputKey(nil)
	if err != nil {
		return nil, fmt.Errorf("error deriving Taproot output key: %w",
			err)
	}

	id := addr.ID()
	rpcAddr := &tarorpc.Addr{
		Encoded:          addrStr,
		AssetId:          id[:],
		AssetType:        tarorpc.AssetType(addr.Type),
		Amount:           int64(addr.Amount),
		ScriptKey:        addr.ScriptKey.SerializeCompressed(),
		InternalKey:      addr.InternalKey.SerializeCompressed(),
		TaprootOutputKey: schnorr.SerializePubKey(taprootOutputKey),
	}

	if addr.FamilyKey != nil {
		rpcAddr.FamilyKey = addr.FamilyKey.SerializeCompressed()
	}

	return rpcAddr, nil
}

// marshalAddrEvent turns an address event into its RPC counterpart.
func marshalAddrEvent(event *address.Event) (*tarorpc.AddrEvent, error) {
	rpcAddr, err := marshalAddr(event.Addr.Taro)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addr: %w", err)
	}

	rpcStatus, err := marshalAddrEventStatus(event.Status)
	if err != nil {
		return nil, fmt.Errorf("error marshaling status: %w", err)
	}

	return &tarorpc.AddrEvent{
		CreationTimeUnixSeconds: uint64(event.CreationTime.Unix()),
		Addr:                    rpcAddr,
		Status:                  rpcStatus,
		Outpoint:                event.Outpoint.String(),
		UtxoAmtSat:              uint64(event.Amt),
		TaprootSibling:          event.TapscriptSibling,
		ConfirmationHeight:      event.ConfirmationHeight,
		HasProof:                event.HasProof,
	}, nil
}

// unmarshalAddrEventStatus parses the RPC address event status into the native
// counterpart.
func unmarshalAddrEventStatus(
	rpcStatus tarorpc.AddrEventStatus) (address.Status, error) {

	switch rpcStatus {
	case tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED:
		return address.StatusTransactionDetected, nil

	case tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED:
		return address.StatusTransactionConfirmed, nil

	case tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_PROOF_RECEIVED:
		return address.StatusProofReceived, nil

	case tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED:
		return address.StatusCompleted, nil

	default:
		return 0, fmt.Errorf("unknown address event status <%d>",
			rpcStatus)
	}
}

// marshalAddrEventStatus turns the address event status into the RPC
// counterpart.
func marshalAddrEventStatus(status address.Status) (tarorpc.AddrEventStatus,
	error) {

	switch status {
	case address.StatusTransactionDetected:
		return tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED,
			nil

	case address.StatusTransactionConfirmed:
		return tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED,
			nil

	case address.StatusProofReceived:
		return tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_PROOF_RECEIVED,
			nil

	case address.StatusCompleted:
		return tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED, nil

	default:
		return 0, fmt.Errorf("unknown address event status <%d>",
			status)
	}
}

// SendAsset uses a passed taro address to attempt to complete an asset send.
// The method returns information w.r.t the on chain send, as well as the proof
// file information the receiver needs to fully receive the asset.
func (r *rpcServer) SendAsset(ctx context.Context,
	in *tarorpc.SendAssetRequest) (*tarorpc.SendAssetResponse, error) {

	if in.TaroAddr == "" {
		return nil, fmt.Errorf("addr must be set")
	}

	taroParams := address.ParamsForChain(r.cfg.ChainParams.Name)
	taroAddr, err := address.DecodeAddress(in.TaroAddr, &taroParams)
	if err != nil {
		return nil, err
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(&tarofreighter.AssetParcel{
		Dest: taroAddr,
	})
	if err != nil {
		return nil, err
	}

	transferTXID := resp.TransferTx.TxHash()

	var txBuf bytes.Buffer
	if err := resp.TransferTx.Serialize(&txBuf); err != nil {
		return nil, err
	}
	transferTxBytes := txBuf.Bytes()

	prevInputs := make([]*tarorpc.PrevInputAsset, len(resp.AssetInputs))
	newOutputs := make([]*tarorpc.AssetOutput, len(resp.AssetOutputs))

	for i, input := range resp.AssetInputs {
		prevInputs[i] = &tarorpc.PrevInputAsset{
			AnchorPoint: input.PrevID.OutPoint.String(),
			AssetId:     input.PrevID.ID[:],
			ScriptKey:   input.PrevID.ScriptKey[:],
			Amount:      int64(input.Amount),
		}
	}
	for i, output := range resp.AssetOutputs {
		newOutputs[i] = &tarorpc.AssetOutput{
			AnchorPoint: output.PrevID.OutPoint.String(),
			AssetId:     output.PrevID.ID[:],
			ScriptKey:   output.PrevID.ScriptKey[:],
			Amount:      int64(output.Amount),
			// TODO(roasbeef): add blob and split proof
		}
	}

	return &tarorpc.SendAssetResponse{
		TransferTxid:      transferTXID[:],
		AnchorOutputIndex: int32(resp.NewAnchorPoint.Index),
		TransferTxBytes:   transferTxBytes,
		TaroTransfer: &tarorpc.TaroTransfer{
			OldTaroRoot: resp.OldTaroRoot,
			NewTaroRoot: resp.NewTaroRoot,
			PrevInputs:  prevInputs,
			NewOutputs:  newOutputs,
		},
		TotalFeeSats: 0,
	}, nil
}
