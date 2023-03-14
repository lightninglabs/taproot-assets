package taro

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/rpcperms"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
	unirpc "github.com/lightninglabs/taro/tarorpc/universerpc"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/universe"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
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
		"/tarorpc.Taro/ListAssets": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListUtxos": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListGroups": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListBalances": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListTransfers": {{
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
		"/tarorpc.Taro/SubscribeSendAssetEventNtfns": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/FundVirtualPsbt": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/SignVirtualPsbt": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/AnchorVirtualPsbts": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/NextInternalKey": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/NextScriptKey": {{
			Entity: "assets",
			Action: "write",
		}},
		"/mintrpc.Mint/MintAsset": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/FinalizeBatch": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/CancelBatch": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/ListBatches": {{
			Entity: "mint",
			Action: "read",
		}},
		"/universerpc.Universe/AssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryAssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetLeafKeys": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetLeaves": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryIssuanceProof": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/InsertIssuanceProof": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/SyncUniverse": {{
			Entity: "universe",
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
	wrpc.UnimplementedAssetWalletServer
	mintrpc.UnimplementedMintServer
	unirpc.UnimplementedUniverseServer

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
	wrpc.RegisterAssetWalletServer(grpcServer, r)
	mintrpc.RegisterMintServer(grpcServer, r)
	unirpc.RegisterUniverseServer(grpcServer, r)
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

	err = walletrpc.RegisterWalletKitHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	err = mintrpc.RegisterMintHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	err = unirpc.RegisterUniverseHandlerFromEndpoint(
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
	req *mintrpc.MintAssetRequest) (*mintrpc.MintAssetResponse, error) {

	// Using a specific group key implies disabling emission.
	if req.EnableEmission && len(req.Asset.GroupKey) != 0 {
		return nil, fmt.Errorf("must disable emission")
	}

	seedling := &tarogarden.Seedling{
		AssetType:      asset.Type(req.Asset.AssetType),
		AssetName:      req.Asset.Name,
		Amount:         uint64(req.Asset.Amount),
		EnableEmission: req.EnableEmission,
	}

	// If a group key is provided, parse the provided group public key
	// before creating the asset seedling.
	if len(req.Asset.GroupKey) != 0 {
		groupTweakedKey, err := btcec.ParsePubKey(req.Asset.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("invalid group key: %w", err)
		}

		seedling.GroupInfo = &asset.AssetGroup{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *groupTweakedKey,
			},
		}
	}

	if !req.EnableEmission && seedling.GroupInfo != nil {
		err := r.checkBalanceOverflow(
			ctx, nil, &seedling.GroupInfo.GroupPubKey,
			req.Asset.Amount,
		)
		if err != nil {
			return nil, err
		}
	}

	if req.Asset.AssetMeta != nil {
		seedling.Meta = &proof.MetaReveal{
			Type: proof.MetaType(req.Asset.AssetMeta.Type),
			Data: req.Asset.AssetMeta.Data,
		}
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

		return &mintrpc.MintAssetResponse{
			BatchKey: update.BatchKey.SerializeCompressed(),
		}, nil
	}
}

// FinalizeBatch attempts to finalize the current pending batch.
func (r *rpcServer) FinalizeBatch(_ context.Context,
	_ *mintrpc.FinalizeBatchRequest) (*mintrpc.FinalizeBatchResponse,
	error) {

	batchKey, err := r.cfg.AssetMinter.FinalizeBatch()
	if err != nil {
		return nil, fmt.Errorf("unable to finalize batch: %w", err)
	}

	// If there was no batch to finalize, return an empty response.
	if batchKey == nil {
		return &mintrpc.FinalizeBatchResponse{}, nil
	}

	return &mintrpc.FinalizeBatchResponse{
		BatchKey: batchKey.SerializeCompressed(),
	}, nil
}

// CancelBatch attempts to cancel the current pending batch.
func (r *rpcServer) CancelBatch(_ context.Context,
	_ *mintrpc.CancelBatchRequest) (*mintrpc.CancelBatchResponse,
	error) {

	batchKey, err := r.cfg.AssetMinter.CancelBatch()
	if err != nil {
		return nil, fmt.Errorf("unable to cancel batch: %w", err)
	}

	// If there was no batch to cancel, return an empty response.
	if batchKey == nil {
		return &mintrpc.CancelBatchResponse{}, nil
	}

	return &mintrpc.CancelBatchResponse{
		BatchKey: batchKey.SerializeCompressed(),
	}, nil
}

// ListBatches lists the set of batches submitted for minting, including pending
// and cancelled batches.
func (r *rpcServer) ListBatches(_ context.Context,
	req *mintrpc.ListBatchRequest) (*mintrpc.ListBatchResponse, error) {

	var (
		batchKey *btcec.PublicKey
		err      error
	)

	if len(req.BatchKey) != 0 {
		batchKey, err = btcec.ParsePubKey(req.BatchKey)
		if err != nil {
			return nil, fmt.Errorf("invalid batch key: %w", err)
		}
	}

	batches, err := r.cfg.AssetMinter.ListBatches(batchKey)
	if err != nil {
		return nil, fmt.Errorf("unable to list batches: %w", err)
	}

	rpcBatches, err := chanutils.MapErr(batches, marshalMintingBatch)
	if err != nil {
		return nil, err
	}

	return &mintrpc.ListBatchResponse{
		Batches: rpcBatches,
	}, nil
}

// checkBalanceOverflow ensures that the new asset amount will not overflow
// the max allowed asset (or asset group) balance.
func (r *rpcServer) checkBalanceOverflow(ctx context.Context,
	assetID *asset.ID, groupPubKey *btcec.PublicKey,
	newAmount uint64) error {

	if assetID != nil && groupPubKey != nil {
		return fmt.Errorf("asset ID and group public key cannot both " +
			"be set")
	}

	if assetID == nil && groupPubKey == nil {
		return fmt.Errorf("asset ID and group public key cannot both " +
			"be nil")
	}

	var balance uint64

	switch {
	case assetID != nil:
		// Retrieve the current asset balance.
		balances, err := r.cfg.AssetStore.QueryBalancesByAsset(
			ctx, assetID,
		)
		if err != nil {
			return fmt.Errorf("unable to query asset balance: %w",
				err)
		}

		// There should only be one balance entry per asset.
		for _, balanceEntry := range balances {
			balance = balanceEntry.Balance
			break
		}

	case groupPubKey != nil:
		// Retrieve the current balance of the group.
		balances, err := r.cfg.AssetStore.QueryAssetBalancesByGroup(
			ctx, groupPubKey,
		)
		if err != nil {
			return fmt.Errorf("unable to query group balance: %w",
				err)
		}

		// There should only be one balance entry per group.
		for _, balanceEntry := range balances {
			balance = balanceEntry.Balance
			break
		}
	}

	// Check for overflow.
	err := mssmt.CheckSumOverflowUint64(balance, newAmount)
	if err != nil {
		return fmt.Errorf("new asset amount would overflow "+
			"asset balance: %w", err)
	}

	return nil
}

// ListAssets lists the set of assets owned by the target daemon.
func (r *rpcServer) ListAssets(ctx context.Context,
	req *tarorpc.ListAssetRequest) (*tarorpc.ListAssetResponse, error) {

	rpcAssets, err := r.fetchRpcAssets(
		ctx, req.WithWitness, req.IncludeSpent,
	)
	if err != nil {
		return nil, err
	}

	return &tarorpc.ListAssetResponse{
		Assets: rpcAssets,
	}, nil
}

func (r *rpcServer) fetchRpcAssets(ctx context.Context,
	withWitness, includeSpent bool) ([]*tarorpc.Asset, error) {

	assets, err := r.cfg.AssetStore.FetchAllAssets(ctx, includeSpent, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to read chain assets: %w", err)
	}

	rpcAssets := make([]*tarorpc.Asset, len(assets))
	for i, a := range assets {
		rpcAssets[i], err = r.marshalChainAsset(ctx, a, withWitness)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal asset: %w",
				err)
		}
	}

	return rpcAssets, nil
}

func (r *rpcServer) marshalChainAsset(ctx context.Context, a *tarodb.ChainAsset,
	withWitness bool) (*tarorpc.Asset, error) {

	rpcAsset, err := r.marshalAsset(ctx, a.Asset, a.IsSpent, withWitness)
	if err != nil {
		return nil, err
	}

	var bootstrapInfoBuf bytes.Buffer
	if err := a.Genesis.Encode(&bootstrapInfoBuf); err != nil {
		return nil, fmt.Errorf("unable to encode genesis: %w", err)
	}
	rpcAsset.AssetGenesis.GenesisBootstrapInfo = bootstrapInfoBuf.Bytes()

	var anchorTxBytes []byte
	if a.AnchorTx != nil {
		var anchorTxBuf bytes.Buffer
		err := a.AnchorTx.Serialize(&anchorTxBuf)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize anchor "+
				"tx: %w", err)
		}
		anchorTxBytes = anchorTxBuf.Bytes()
	}

	rpcAsset.ChainAnchor = &tarorpc.AnchorInfo{
		AnchorTx:        anchorTxBytes,
		AnchorTxid:      a.AnchorTxid.String(),
		AnchorBlockHash: a.AnchorBlockHash[:],
		AnchorOutpoint:  a.AnchorOutpoint.String(),
		InternalKey:     a.AnchorInternalKey.SerializeCompressed(),
	}

	return rpcAsset, nil
}

func (r *rpcServer) marshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool) (*tarorpc.Asset, error) {

	assetID := a.Genesis.ID()
	scriptKeyIsLocal := false
	if a.ScriptKey.TweakedScriptKey != nil {
		scriptKeyIsLocal = r.cfg.AddrBook.IsLocalKey(
			ctx, a.ScriptKey.RawKey,
		)
	}

	rpcAsset := &tarorpc.Asset{
		Version: int32(a.Version),
		AssetGenesis: &tarorpc.GenesisInfo{
			GenesisPoint: a.Genesis.FirstPrevOut.String(),
			Name:         a.Genesis.Tag,
			MetaHash:     a.Genesis.MetaHash[:],
			AssetId:      assetID[:],
			OutputIndex:  a.Genesis.OutputIndex,
		},
		AssetType:        tarorpc.AssetType(a.Type),
		Amount:           a.Amount,
		LockTime:         int32(a.LockTime),
		RelativeLockTime: int32(a.RelativeLockTime),
		ScriptVersion:    int32(a.ScriptVersion),
		ScriptKey:        a.ScriptKey.PubKey.SerializeCompressed(),
		ScriptKeyIsLocal: scriptKeyIsLocal,
		IsSpent:          isSpent,
	}

	if a.GroupKey != nil {
		rpcAsset.AssetGroup = &tarorpc.AssetGroup{
			RawGroupKey:     a.GroupKey.RawKey.PubKey.SerializeCompressed(),
			TweakedGroupKey: a.GroupKey.GroupPubKey.SerializeCompressed(),
			AssetIdSig:      a.GroupKey.Sig.Serialize(),
		}
	}

	if withWitness {
		for idx := range a.PrevWitnesses {
			witness := a.PrevWitnesses[idx]

			prevID := witness.PrevID
			rpcPrevID := &tarorpc.PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *tarorpc.SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := r.marshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &tarorpc.SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &tarorpc.PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
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
			MetaHash:     balance.MetaHash,
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
				MetaHash:             balance.MetaHash[:],
				AssetId:              balance.ID[:],
				GenesisBootstrapInfo: bootstrapInfoBuf.Bytes(),
			},
			AssetType: tarorpc.AssetType(balance.Type),
			Balance:   balance.Balance,
		}
	}

	return resp, nil
}

func (r *rpcServer) listBalancesByGroupKey(ctx context.Context,
	groupKey *btcec.PublicKey) (*tarorpc.ListBalancesResponse, error) {

	balances, err := r.cfg.AssetStore.QueryAssetBalancesByGroup(
		ctx, groupKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list balances: %w", err)
	}

	resp := &tarorpc.ListBalancesResponse{
		AssetGroupBalances: make(
			map[string]*tarorpc.AssetGroupBalance, len(balances),
		),
	}

	for _, balance := range balances {
		var groupKey []byte
		if balance.GroupKey != nil {
			groupKey = balance.GroupKey.SerializeCompressed()
		}

		groupKeyString := hex.EncodeToString(groupKey)
		resp.AssetGroupBalances[groupKeyString] = &tarorpc.AssetGroupBalance{
			GroupKey: groupKey,
			Balance:  balance.Balance,
		}
	}

	return resp, nil
}

// ListUtxos lists the UTXOs managed by the target daemon, and the assets they
// hold.
func (r *rpcServer) ListUtxos(ctx context.Context,
	_ *tarorpc.ListUtxosRequest) (*tarorpc.ListUtxosResponse, error) {

	rpcAssets, err := r.fetchRpcAssets(ctx, false, false)
	if err != nil {
		return nil, err
	}

	managedUtxos, err := r.cfg.AssetStore.FetchManagedUTXOs(ctx)
	if err != nil {
		return nil, err
	}

	utxos := make(map[string]*tarorpc.ManagedUtxo)
	for _, u := range managedUtxos {
		utxos[u.OutPoint.String()] = &tarorpc.ManagedUtxo{
			OutPoint:    u.OutPoint.String(),
			AmtSat:      int64(u.OutputValue),
			InternalKey: u.InternalKey.PubKey.SerializeCompressed(),
			TaroRoot:    u.TaroRoot,
		}
	}

	// Populate the assets managed by each UTXO.
	for _, a := range rpcAssets {
		op := a.ChainAnchor.AnchorOutpoint
		utxo, ok := utxos[op]
		if !ok {
			return nil, fmt.Errorf("unable to find utxo %s for "+
				"asset_id=%x", op, a.AssetGenesis.AssetId)
		}

		utxo.Assets = append(utxo.Assets, a)
		utxos[op] = utxo
	}

	return &tarorpc.ListUtxosResponse{
		ManagedUtxos: utxos,
	}, nil
}

// ListGroups lists known groups and the assets held in each group.
func (r *rpcServer) ListGroups(ctx context.Context,
	_ *tarorpc.ListGroupsRequest) (*tarorpc.ListGroupsResponse, error) {

	readableAssets, err := r.cfg.AssetStore.FetchGroupedAssets(ctx)
	if err != nil {
		return nil, err
	}

	groupsWithAssets := make(map[string]*tarorpc.GroupedAssets)

	// Populate the map of group keys to assets in that group.
	for _, a := range readableAssets {
		groupKey := hex.EncodeToString(a.GroupKey.SerializeCompressed())
		asset := &tarorpc.AssetHumanReadable{
			Id:               a.ID[:],
			Amount:           a.Amount,
			LockTime:         int32(a.LockTime),
			RelativeLockTime: int32(a.RelativeLockTime),
			Tag:              a.Tag,
			MetaHash:         a.MetaHash[:],
			Type:             tarorpc.AssetType(a.Type),
		}

		_, ok := groupsWithAssets[groupKey]
		if !ok {
			groupsWithAssets[groupKey] = &tarorpc.GroupedAssets{
				Assets: []*tarorpc.AssetHumanReadable{},
			}
		}

		groupsWithAssets[groupKey].Assets = append(
			groupsWithAssets[groupKey].Assets, asset,
		)
	}

	return &tarorpc.ListGroupsResponse{Groups: groupsWithAssets}, nil
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

	case *tarorpc.ListBalancesRequest_GroupKey:
		if !groupBy.GroupKey {
			return nil, fmt.Errorf("invalid group_by")
		}

		var groupKey *btcec.PublicKey
		if len(in.GroupKeyFilter) != 0 {
			var err error
			groupKey, err = btcec.ParsePubKey(in.GroupKeyFilter)
			if err != nil {
				return nil, fmt.Errorf("invalid group key "+
					"filter: %v", err)
			}
		}

		return r.listBalancesByGroupKey(ctx, groupKey)

	default:
		return nil, fmt.Errorf("invalid group_by")
	}
}

// ListTransfers lists all asset transfers managed by this deamon.
func (r *rpcServer) ListTransfers(ctx context.Context,
	in *tarorpc.ListTransfersRequest) (*tarorpc.ListTransfersResponse,
	error) {

	parcels, err := r.cfg.AssetStore.QueryParcels(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to query parcels: %w", err)
	}

	resp := &tarorpc.ListTransfersResponse{
		Transfers: make([]*tarorpc.AssetTransfer, len(parcels)),
	}

	for idx := range parcels {
		resp.Transfers[idx], err = marshalOutboundParcel(parcels[idx])
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parcel: %w",
				err)
		}
	}

	return resp, nil
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
		groupKey *btcec.PublicKey
		err      error
	)

	// The group key is optional, so we'll only decode it if it's
	// specified.
	if len(in.GroupKey) != 0 {
		groupKey, err = btcec.ParsePubKey(in.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode "+
				"group key: %w", err)
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

	err = r.checkBalanceOverflow(ctx, &assetID, nil, in.Amt)
	if err != nil {
		return nil, err
	}

	var addr *address.AddrWithKeyInfo
	switch {
	// No key was specified, we'll let the address book derive them.
	case in.ScriptKey == nil && in.InternalKey == nil:
		// Now that we have all the params, we'll try to add a new
		// address to the addr book.
		addr, err = r.cfg.AddrBook.NewAddress(
			ctx, genesis, groupKey, uint64(in.Amt),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make new addr: %w",
				err)
		}

	// Only the script key was specified.
	case in.ScriptKey != nil && in.InternalKey == nil:
		return nil, fmt.Errorf("internal key must also be specified " +
			"if script key is specified")

	// Only the internal key was specified.
	case in.ScriptKey == nil && in.InternalKey != nil:
		return nil, fmt.Errorf("script key must also be specified " +
			"if internal key is specified")

	// Both the script and internal keys were specified.
	default:
		scriptKey, err := UnmarshalScriptKey(in.ScriptKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}

		rpcsLog.Debugf("Decoded script key %x (internal %x, tweak %x)",
			scriptKey.PubKey.SerializeCompressed(),
			scriptKey.RawKey.PubKey.SerializeCompressed(),
			scriptKey.Tweak[:])

		internalKey, err := UnmarshalKeyDescriptor(in.InternalKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode internal "+
				"key: %w", err)
		}

		// Now that we have all the params, we'll try to add a new
		// address to the addr book.
		addr, err = r.cfg.AddrBook.NewAddressWithKeys(
			ctx, genesis, groupKey, uint64(in.Amt), *scriptKey,
			internalKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make new addr: %w",
				err)
		}
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

	headerVerifier := tarogarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	_, err = proofFile.Verify(
		ctx, headerVerifier,
	)
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

	headerVerifier := tarogarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)

	// Now that we know the proof file is at least present, we'll attempt
	// to import it into the main archive.
	err := r.cfg.ProofArchive.ImportProofs(
		ctx, headerVerifier, &proof.AnnotatedProof{Blob: in.ProofFile},
	)
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

// FundVirtualPsbt selects inputs from the available asset commitments to fund
// a virtual transaction matching the template.
func (r *rpcServer) FundVirtualPsbt(ctx context.Context,
	in *wrpc.FundVirtualPsbtRequest) (*wrpc.FundVirtualPsbtResponse,
	error) {

	var fundedVPkt *tarofreighter.FundedVPacket
	switch {
	case in.GetPsbt() != nil:
		vPkt, err := taropsbt.NewFromRawBytes(
			bytes.NewReader(in.GetPsbt()), false,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode psbt: %w", err)
		}

		desc, err := taroscript.DescribeRecipients(vPkt)
		if err != nil {
			return nil, fmt.Errorf("unable to describe packet "+
				"recipients: %w", err)
		}

		fundedVPkt, err = r.cfg.AssetWallet.FundPacket(
			ctx, desc, vPkt,
		)
		if err != nil {
			return nil, fmt.Errorf("error funding packet: %w", err)
		}

	case in.GetRaw() != nil:
		raw := in.GetRaw()
		if len(raw.Inputs) > 0 {
			return nil, fmt.Errorf("template inputs not yet " +
				"supported")
		}
		if len(raw.Recipients) > 1 {
			return nil, fmt.Errorf("only one recipient supported")
		}

		var (
			taroParams = address.ParamsForChain(
				r.cfg.ChainParams.Name,
			)
			addr *address.Taro
			err  error
		)
		for a := range raw.Recipients {
			addr, err = address.DecodeAddress(a, &taroParams)
			if err != nil {
				return nil, fmt.Errorf("unable to decode "+
					"addr: %w", err)
			}
		}

		if addr == nil {
			return nil, fmt.Errorf("no recipients specified")
		}

		fundedVPkt, err = r.cfg.AssetWallet.FundAddressSend(ctx, *addr)
		if err != nil {
			return nil, fmt.Errorf("error funding address send: "+
				"%w", err)
		}

	default:
		return nil, fmt.Errorf("either PSBT or raw template must be " +
			"specified")
	}

	var b bytes.Buffer
	if err := fundedVPkt.VPacket.Serialize(&b); err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return &wrpc.FundVirtualPsbtResponse{
		FundedPsbt:        b.Bytes(),
		ChangeOutputIndex: 0,
	}, nil
}

// SignVirtualPsbt signs the inputs of a virtual transaction and prepares the
// commitments of the inputs and outputs.
func (r *rpcServer) SignVirtualPsbt(_ context.Context,
	in *wrpc.SignVirtualPsbtRequest) (*wrpc.SignVirtualPsbtResponse,
	error) {

	vPkt, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(in.FundedPsbt), false,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	signedInputs, err := r.cfg.AssetWallet.SignVirtualPacket(vPkt)
	if err != nil {
		return nil, fmt.Errorf("error signing packet: %w", err)
	}

	var b bytes.Buffer
	if err := vPkt.Serialize(&b); err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return &wrpc.SignVirtualPsbtResponse{
		SignedPsbt:   b.Bytes(),
		SignedInputs: signedInputs,
	}, nil
}

// AnchorVirtualPsbts merges and then commits multiple virtual transactions in
// a single BTC level anchor transaction.
//
// TODO(guggero): Actually implement accepting and merging multiple
// transactions.
func (r *rpcServer) AnchorVirtualPsbts(ctx context.Context,
	in *wrpc.AnchorVirtualPsbtsRequest) (*tarorpc.SendAssetResponse,
	error) {

	if len(in.VirtualPsbts) > 1 {
		return nil, fmt.Errorf("only one virtual PSBT supported")
	}

	vPacket, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(in.VirtualPsbts[0]), false,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	if len(vPacket.Inputs) != 1 {
		return nil, fmt.Errorf("only one input is currently supported")
	}

	inputAsset := vPacket.Inputs[0].Asset()
	prevID := vPacket.Inputs[0].PrevID
	inputCommitment, err := r.cfg.AssetStore.FetchCommitment(
		ctx, inputAsset.ID(), prevID.OutPoint, inputAsset.GroupKey,
		&inputAsset.ScriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching input commitment: %w",
			err)
	}

	rpcsLog.Debugf("Selected commitment for anchor point %v, requesting "+
		"delivery", inputCommitment.AnchorPoint)

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tarofreighter.NewPreSignedParcel(
			vPacket, inputCommitment.Commitment,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("error requesting delivery: %w", err)
	}

	parcel, err := marshalOutboundParcel(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling outbound parcel: %w",
			err)
	}

	return &tarorpc.SendAssetResponse{
		Transfer: parcel,
	}, nil
}

// NextInternalKey derives the next internal key for the given key family and
// stores it as an internal key in the database to make sure it is identified
// as a local key later on when importing proofs. While an internal key can
// also be used as the internal key of a script key, it is recommended to use
// the NextScriptKey RPC instead, to make sure the tweaked Taproot output key
// is also recognized as a local key.
func (r *rpcServer) NextInternalKey(ctx context.Context,
	req *wrpc.NextInternalKeyRequest) (*wrpc.NextInternalKeyResponse,
	error) {

	// Due to how we detect local keys, we need to make sure that the key
	// family is not zero.
	if req.KeyFamily == 0 {
		return nil, fmt.Errorf("key family must be set to a non-zero " +
			"value")
	}

	keyDesc, err := r.cfg.AddrBook.NextInternalKey(ctx, keychain.KeyFamily(
		req.KeyFamily,
	))
	if err != nil {
		return nil, fmt.Errorf("error inserting internal key: %w", err)
	}

	return &wrpc.NextInternalKeyResponse{
		InternalKey: marshalKeyDescriptor(keyDesc),
	}, nil
}

// NextScriptKey derives the next script key (and its corresponding internal
// key) and stores them both in the database to make sure they are identified
// as local keys later on when importing proofs.
func (r *rpcServer) NextScriptKey(ctx context.Context,
	req *wrpc.NextScriptKeyRequest) (*wrpc.NextScriptKeyResponse,
	error) {

	// Due to how we detect local keys, we need to make sure that the key
	// family is not zero.
	if req.KeyFamily == 0 {
		return nil, fmt.Errorf("key family must be set to a non-zero " +
			"value")
	}

	scriptKey, err := r.cfg.AddrBook.NextScriptKey(ctx, keychain.KeyFamily(
		req.KeyFamily,
	))
	if err != nil {
		return nil, fmt.Errorf("error inserting internal key: %w", err)
	}

	return &wrpc.NextScriptKeyResponse{
		ScriptKey: marshalScriptKey(scriptKey),
	}, nil
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
		Amount:           addr.Amount,
		ScriptKey:        addr.ScriptKey.SerializeCompressed(),
		InternalKey:      addr.InternalKey.SerializeCompressed(),
		TaprootOutputKey: schnorr.SerializePubKey(taprootOutputKey),
	}

	if addr.GroupKey != nil {
		rpcAddr.GroupKey = addr.GroupKey.SerializeCompressed()
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

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tarofreighter.NewAddressParcel(taroAddr),
	)
	if err != nil {
		return nil, err
	}

	parcel, err := marshalOutboundParcel(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling outbound parcel: %w",
			err)
	}

	return &tarorpc.SendAssetResponse{
		Transfer: parcel,
	}, nil
}

// marshalOutboundParcel turns a pending parcel into its RPC counterpart.
func marshalOutboundParcel(
	parcel *tarofreighter.OutboundParcel) (*tarorpc.AssetTransfer,
	error) {

	rpcInputs := make([]*tarorpc.TransferInput, len(parcel.Inputs))
	for idx := range parcel.Inputs {
		in := parcel.Inputs[idx]
		rpcInputs[idx] = &tarorpc.TransferInput{
			AnchorPoint: in.OutPoint.String(),
			AssetId:     in.ID[:],
			ScriptKey:   in.ScriptKey[:],
			Amount:      in.Amount,
		}
	}

	rpcOutputs := make(
		[]*tarorpc.TransferOutput, len(parcel.Outputs),
	)
	for idx := range parcel.Outputs {
		out := parcel.Outputs[idx]

		internalPubKey := out.Anchor.InternalKey.PubKey
		internalKeyBytes := internalPubKey.SerializeCompressed()
		rpcAnchor := &tarorpc.TransferOutputAnchor{
			Outpoint:         out.Anchor.OutPoint.String(),
			Value:            int64(out.Anchor.Value),
			InternalKey:      internalKeyBytes,
			MerkleRoot:       out.Anchor.MerkleRoot[:],
			TapscriptSibling: out.Anchor.TapscriptSibling[:],
			NumPassiveAssets: out.Anchor.NumPassiveAssets,
		}
		scriptPubKey := out.ScriptKey.PubKey

		var splitCommitRoot []byte
		if out.SplitCommitmentRoot != nil {
			hash := out.SplitCommitmentRoot.NodeHash()
			if hash != mssmt.ZeroNodeHash {
				splitCommitRoot = hash[:]
			}
		}
		rpcOutputs[idx] = &tarorpc.TransferOutput{
			Anchor:              rpcAnchor,
			ScriptKey:           scriptPubKey.SerializeCompressed(),
			ScriptKeyIsLocal:    out.ScriptKeyLocal,
			Amount:              out.Amount,
			NewProofBlob:        out.ProofSuffix,
			SplitCommitRootHash: splitCommitRoot,
		}
	}

	anchorTxHash := parcel.AnchorTx.TxHash()
	return &tarorpc.AssetTransfer{
		TransferTimestamp:  parcel.TransferTime.Unix(),
		AnchorTxHash:       anchorTxHash[:],
		AnchorTxHeightHint: parcel.AnchorTxHeightHint,
		AnchorTxChainFees:  parcel.ChainFees,
		Inputs:             rpcInputs,
		Outputs:            rpcOutputs,
	}, nil
}

// SubscribeSendAssetEventNtfns registers a subscription to the event
// notification stream which relates to the asset sending process.
func (r *rpcServer) SubscribeSendAssetEventNtfns(
	in *tarorpc.SubscribeSendAssetEventNtfnsRequest,
	ntfnStream tarorpc.Taro_SubscribeSendAssetEventNtfnsServer) error {

	// Create a new event subscriber and pass a copy to the chain porter.
	// We will then read events from the subscriber.
	eventSubscriber := chanutils.NewEventReceiver[chanutils.Event](
		chanutils.DefaultQueueSize,
	)
	defer eventSubscriber.Stop()

	err := r.cfg.ChainPorter.RegisterSubscriber(eventSubscriber, false, false)
	if err != nil {
		return fmt.Errorf("failed to register event notifications "+
			"subscription: %w", err)
	}

	// Loop and read from the ChainPorter event subscription and forward to
	// the RPC stream.
	for {
		select {
		// Handle receiving a new event from the ChainPorter.
		// The event will be mapped to the RPC event type and
		// sent over the stream.
		case event := <-eventSubscriber.NewItemCreated.ChanOut():

			rpcEvent, err := marshallSendAssetEvent(event)
			if err != nil {
				return fmt.Errorf("failed to marshall "+
					"ChainPorter event into RPC event: "+
					"%w", err)
			}

			err = ntfnStream.Send(rpcEvent)
			if err != nil {
				return fmt.Errorf("failed to RPC stream send "+
					"event: %w", err)
			}

		// Handle the case where the RPC stream is closed by the
		// client.
		case <-ntfnStream.Context().Done():
			// Don't return an error if a normal context
			// cancellation has occurred.
			isCanceledContext := errors.Is(
				ntfnStream.Context().Err(), context.Canceled,
			)
			if isCanceledContext {
				return nil
			}

			return ntfnStream.Context().Err()

		// Handle the case where the RPC server is shutting down.
		case <-r.quit:
			return nil
		}
	}
}

// marshallSendAssetEvent maps a ChainPorter event to its RPC counterpart.
func marshallSendAssetEvent(
	eventInterface chanutils.Event) (*tarorpc.SendAssetEvent, error) {

	switch event := eventInterface.(type) {
	case *tarofreighter.ExecuteSendStateEvent:
		eventRpc := &tarorpc.SendAssetEvent_ExecuteSendStateEvent{
			ExecuteSendStateEvent: &tarorpc.ExecuteSendStateEvent{
				Timestamp: event.Timestamp().UnixMicro(),
				SendState: event.SendState.String(),
			},
		}
		return &tarorpc.SendAssetEvent{
			Event: eventRpc,
		}, nil

	case *proof.ReceiverProofBackoffWaitEvent:
		eventRpc := tarorpc.SendAssetEvent_ReceiverProofBackoffWaitEvent{
			ReceiverProofBackoffWaitEvent: &tarorpc.ReceiverProofBackoffWaitEvent{
				Timestamp:    event.Timestamp().UnixMicro(),
				Backoff:      event.Backoff.Microseconds(),
				TriesCounter: event.TriesCounter,
			},
		}
		return &tarorpc.SendAssetEvent{
			Event: &eventRpc,
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %T", eventInterface)
	}
}

// marshalMintingBatch marshals a minting batch into the RPC counterpart.
func marshalMintingBatch(batch *tarogarden.MintingBatch) (*mintrpc.MintingBatch,
	error) {

	rpcAssets := make([]*mintrpc.MintAsset, 0, len(batch.Seedlings))
	for _, seedling := range batch.Seedlings {
		var groupKeyBytes []byte
		if seedling.HasGroupKey() {
			groupKey := seedling.GroupInfo.GroupKey
			groupPubKey := groupKey.GroupPubKey
			groupKeyBytes = groupPubKey.SerializeCompressed()
		}

		metaHash := seedling.Meta.MetaHash()

		rpcAssets = append(rpcAssets, &mintrpc.MintAsset{
			AssetType: tarorpc.AssetType(seedling.AssetType),
			Name:      seedling.AssetName,
			AssetMeta: &tarorpc.AssetMeta{
				MetaHash: metaHash[:],
				Data:     seedling.Meta.Data,
				Type: tarorpc.AssetMetaType(
					seedling.Meta.Type,
				),
			},
			Amount:   seedling.Amount,
			GroupKey: groupKeyBytes,
		})
	}

	rpcBatchState, err := marshalBatchState(batch)
	if err != nil {
		return nil, err
	}

	return &mintrpc.MintingBatch{
		BatchKey: batch.BatchKey.PubKey.SerializeCompressed(),
		State:    rpcBatchState,
		Assets:   rpcAssets,
	}, nil
}

// marshalBatchState converts the batch state field into its RPC counterpart.
func marshalBatchState(batch *tarogarden.MintingBatch) (mintrpc.BatchState,
	error) {

	switch batch.BatchState {
	case tarogarden.BatchStatePending:
		return mintrpc.BatchState_BATCH_STATE_PEDNING, nil

	case tarogarden.BatchStateFrozen:
		return mintrpc.BatchState_BATCH_STATE_FROZEN, nil

	case tarogarden.BatchStateCommitted:
		return mintrpc.BatchState_BATCH_STATE_COMMITTED, nil

	case tarogarden.BatchStateBroadcast:
		return mintrpc.BatchState_BATCH_STATE_BROADCAST, nil

	case tarogarden.BatchStateConfirmed:
		return mintrpc.BatchState_BATCH_STATE_CONFIRMED, nil

	case tarogarden.BatchStateFinalized:
		return mintrpc.BatchState_BATCH_STATE_FINALIZED, nil

	case tarogarden.BatchStateSeedlingCancelled:
		return mintrpc.BatchState_BATCH_STATE_SEEDLING_CANCELLED, nil

	case tarogarden.BatchStateSproutCancelled:
		return mintrpc.BatchState_BATCH_STATE_SPROUT_CANCELLED, nil

	default:
		return 0, fmt.Errorf("unknown batch state: %d",
			batch.BatchState)
	}
}

// UnmarshalScriptKey parses the RPC script key into the native counterpart.
func UnmarshalScriptKey(rpcKey *tarorpc.ScriptKey) (*asset.ScriptKey, error) {
	var (
		scriptKey asset.ScriptKey
		err       error
	)

	// The script public key is a Taproot key, so 32-byte x-only.
	scriptKey.PubKey, err = schnorr.ParsePubKey(rpcKey.PubKey)
	if err != nil {
		return nil, err
	}

	// The key descriptor is optional for script keys that are completely
	// independent of the backing wallet.
	if rpcKey.KeyDesc != nil {
		keyDesc, err := UnmarshalKeyDescriptor(rpcKey.KeyDesc)
		if err != nil {
			return nil, err
		}
		scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
			RawKey: keyDesc,

			// The tweak is optional, if it's empty it means the key
			// is derived using BIP 86.
			Tweak: rpcKey.TapTweak,
		}
	}

	return &scriptKey, nil
}

// marshalScriptKey marshals the native script key into the RPC counterpart.
func marshalScriptKey(scriptKey asset.ScriptKey) *tarorpc.ScriptKey {
	rpcScriptKey := &tarorpc.ScriptKey{
		PubKey: schnorr.SerializePubKey(scriptKey.PubKey),
	}

	if scriptKey.TweakedScriptKey != nil {
		rpcScriptKey.KeyDesc = marshalKeyDescriptor(
			scriptKey.TweakedScriptKey.RawKey,
		)
		rpcScriptKey.TapTweak = scriptKey.TweakedScriptKey.Tweak
	}

	return rpcScriptKey
}

// marshalKeyDescriptor marshals the native key descriptor into the RPC
// counterpart.
func marshalKeyDescriptor(desc keychain.KeyDescriptor) *tarorpc.KeyDescriptor {
	return &tarorpc.KeyDescriptor{
		RawKeyBytes: desc.PubKey.SerializeCompressed(),
		KeyLoc: &tarorpc.KeyLocator{
			KeyFamily: int32(desc.KeyLocator.Family),
			KeyIndex:  int32(desc.KeyLocator.Index),
		},
	}
}

// UnmarshalKeyDescriptor parses the RPC key descriptor into the native
// counterpart.
func UnmarshalKeyDescriptor(
	rpcDesc *tarorpc.KeyDescriptor) (keychain.KeyDescriptor, error) {

	var (
		desc keychain.KeyDescriptor
		err  error
	)

	// The public key of a key descriptor is mandatory. It is enough to
	// locate the corresponding private key in the backing wallet. But to
	// speed things up (and for additional context), the locator should
	// still be provided if available.
	desc.PubKey, err = btcec.ParsePubKey(rpcDesc.RawKeyBytes)
	if err != nil {
		return desc, err
	}

	if rpcDesc.KeyLoc != nil {
		desc.KeyLocator = keychain.KeyLocator{
			Family: keychain.KeyFamily(rpcDesc.KeyLoc.KeyFamily),
			Index:  uint32(rpcDesc.KeyLoc.KeyIndex),
		}
	}

	return desc, nil
}

// FetchAssetMeta allows a caller to fetch the reveal meta data for an asset
// either by the asset ID for that asset, or a meta hash.
func (r *rpcServer) FetchAssetMeta(ctx context.Context,
	in *tarorpc.FetchAssetMetaRequest) (*tarorpc.AssetMeta, error) {

	var (
		assetMeta *proof.MetaReveal
		err       error
	)
	switch {
	case in.GetAssetId() != nil:
		if len(in.GetAssetId()) != sha256.Size {
			return nil, fmt.Errorf("asset ID must be 32 bytes")
		}

		var assetID asset.ID
		copy(assetID[:], in.GetAssetId())

		assetMeta, err = r.cfg.AssetStore.FetchAssetMetaForAsset(
			ctx, assetID,
		)

	case in.GetMetaHash() != nil:
		if len(in.GetMetaHash()) != sha256.Size {
			return nil, fmt.Errorf("meta hash must be 32 bytes")
		}

		var metaHash [asset.MetaHashLen]byte
		copy(metaHash[:], in.GetMetaHash())

		assetMeta, err = r.cfg.AssetStore.FetchAssetMetaByHash(
			ctx, metaHash,
		)

	default:
		return nil, fmt.Errorf("either asset ID or meta hash must " +
			"be set")
	}
	if err != nil {
		return nil, fmt.Errorf("unable to fetch asset "+
			"meta: %w", err)
	}

	metaHash := assetMeta.MetaHash()
	return &tarorpc.AssetMeta{
		Data:     assetMeta.Data,
		Type:     tarorpc.AssetMetaType(assetMeta.Type),
		MetaHash: metaHash[:],
	}, nil
}

// marshallUniverseRoot marshals the universe root into the RPC counterpart.
func marshalUniverseRoot(node mssmt.Node) (*unirpc.UniverseRoot, error) {
	branchNode, ok := node.(*mssmt.BranchNode)
	if !ok {
		return nil, fmt.Errorf("unable to obtain branch node: "+
			"have %T", node)
	}

	nodeHash := branchNode.NodeHash()

	return &unirpc.UniverseRoot{
		MssmtRoot: &unirpc.MerkleSumNode{
			RootHash: nodeHash[:],
			RootSum:  int64(branchNode.NodeSum()),
		},
	}, nil
}

// AssetRoots queries for the known Universe roots associated with each known
// asset. These roots represent the supply/audit state for each known asset.
func (r *rpcServer) AssetRoots(ctx context.Context,
	req *unirpc.AssetRootRequest) (*unirpc.AssetRootResponse, error) {

	// First, we'll retreive the full set of known asset Universe roots.
	assetRoots, err := r.cfg.BaseUniverse.RootNodes(ctx)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetRootResponse{
		UniverseRoots: make(map[string]*unirpc.UniverseRoot),
	}

	// For each universe roto, marhsal it into the RPC form, taking care to
	// specify the proper universe ID.
	for _, assetRoot := range assetRoots {
		idStr := assetRoot.ID.String()

		resp.UniverseRoots[idStr], err = marshalUniverseRoot(
			assetRoot.Node,
		)
		if err != nil {
			return nil, err
		}

		if assetRoot.ID.GroupKey == nil {
			resp.UniverseRoots[idStr].Id = &unirpc.UniverseRoot_AssetId{
				AssetId: assetRoot.ID.AssetID[:],
			}
		} else {
			resp.UniverseRoots[idStr].Id = &unirpc.UniverseRoot_GroupKey{
				GroupKey: schnorr.SerializePubKey(
					assetRoot.ID.GroupKey,
				),
			}
		}
	}

	return resp, nil
}

// unmarshalUniID parses the RPC universe ID into the native counterpart.
func unmarshalUniID(rpcID *unirpc.ID) (universe.Identifier, error) {
	switch {
	case rpcID.GetAssetId() != nil:
		var assetID asset.ID
		copy(assetID[:], rpcID.GetAssetId())

		return universe.Identifier{
			AssetID: assetID,
		}, nil

	case rpcID.GetAssetIdStr() != "":
		assetIDBytes, err := hex.DecodeString(rpcID.GetAssetIdStr())
		if err != nil {
			return universe.Identifier{}, err
		}

		// TODO(roasbeef): reuse with above

		var assetID asset.ID
		copy(assetID[:], assetIDBytes)

		return universe.Identifier{
			AssetID: assetID,
		}, nil

	case rpcID.GetGroupKey() != nil:
		groupKey, err := schnorr.ParsePubKey(rpcID.GetGroupKey())
		if err != nil {
			return universe.Identifier{}, err
		}

		return universe.Identifier{
			GroupKey: groupKey,
		}, nil

	case rpcID.GetGroupKeyStr() != "":
		groupKeyBytes, err := hex.DecodeString(rpcID.GetGroupKeyStr())
		if err != nil {
			return universe.Identifier{}, err
		}

		// TODO(roasbeef): reuse with above

		groupKey, err := schnorr.ParsePubKey(groupKeyBytes)
		if err != nil {
			return universe.Identifier{}, err
		}

		return universe.Identifier{
			GroupKey: groupKey,
		}, nil

	default:
		return universe.Identifier{}, fmt.Errorf("no id set")
	}
}

// QueryAssetRoots attempts to locate the current Universe root for a specific
// asset. This asset can be identified by its asset ID or group key.
func (r *rpcServer) QueryAssetRoots(ctx context.Context,
	req *unirpc.AssetRootQuery) (*unirpc.QueryRootResponse, error) {

	universeID, err := unmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}

	assetRoot, err := r.cfg.BaseUniverse.RootNode(ctx, universeID)
	if err != nil {
		return nil, err
	}

	uniRoot, err := marshalUniverseRoot(assetRoot)
	if err != nil {
		return nil, err
	}

	return &unirpc.QueryRootResponse{
		AssetRoot: uniRoot,
	}, nil
}

// AssetLeafKeys queries for the set of Universe keys associated with a given
// asset_id or group_key. Each key takes the form: (outpoint, script_key),
// where outpoint is an outpoint in the Bitcoin blockcahin that anchors a valid
// Taro asset commitment, and script_key is the script_key of the asset within
// the Taro asset commitment for the given asset_id or group_key.
func (r *rpcServer) AssetLeafKeys(ctx context.Context,
	req *unirpc.ID) (*unirpc.AssetLeafKeyResponse, error) {

	universeID, err := unmarshalUniID(req)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): tell above if was tring or not, then would set
	// below diff

	leafKeys, err := r.cfg.BaseUniverse.MintingKeys(ctx, universeID)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetLeafKeyResponse{
		AssetKeys: make([]*unirpc.AssetKey, len(leafKeys)),
	}

	for i, leafKey := range leafKeys {
		resp.AssetKeys[i] = &unirpc.AssetKey{
			Outpoint: &unirpc.AssetKey_OpStr{
				OpStr: leafKey.MintingOutpoint.String(),
			},
			ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
				ScriptKeyBytes: schnorr.SerializePubKey(
					leafKey.ScriptKey.PubKey,
				),
			},
		}
	}

	return resp, nil
}

// marshalAssetLeaf marshals an asset leaf into the RPC form.
func marshalAssetLeaf(assetLeaf *universe.MintingLeaf) (*unirpc.AssetLeaf, error) {
	// In order to display the full asset, we'll parse the genesis
	// proof so we can map that to the asset being proved.
	var assetProof proof.Proof
	if err := assetProof.Decode(
		bytes.NewReader(assetLeaf.GenesisProof),
	); err != nil {
		return nil, err
	}

	rpcAsset, err := MarshalAsset(&assetProof.Asset, false)
	if err != nil {
		return nil, err
	}

	return &unirpc.AssetLeaf{
		Asset:         rpcAsset,
		IssuanceProof: assetLeaf.GenesisProof[:],
	}, nil
}

// AssetLeaves queries for the set of asset leaves (the values in the Universe
// MS-SMT tree) for a given asset_id or group_key. These represents either
// asset issuance events (they have a genesis witness) or asset transfers that
// took place on chain. The leaves contain a normal Taro asset proof, as well
// as details for the asset.
func (r *rpcServer) AssetLeaves(ctx context.Context,
	req *unirpc.ID) (*unirpc.AssetLeafResponse, error) {

	universeID, err := unmarshalUniID(req)
	if err != nil {
		return nil, err
	}

	assetLeaves, err := r.cfg.BaseUniverse.MintingLeaves(ctx, universeID)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetLeafResponse{
		Leaves: make([]*unirpc.AssetLeaf, len(assetLeaves)),
	}
	for i, assetLeaf := range assetLeaves {
		assetLeaf := assetLeaf

		resp.Leaves[i], err = marshalAssetLeaf(&assetLeaf)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// unmarshalLeafKey unmarshals a leaf key from the RPC form.
func unmarshalLeafKey(key *unirpc.AssetKey) (universe.BaseKey, error) {
	var (
		baseKey universe.BaseKey
		err     error
	)

	switch {
	case key.GetScriptKeyBytes() != nil:
		pubKey, err := schnorr.ParsePubKey(
			key.GetScriptKeyBytes(),
		)
		if err != nil {
			return baseKey, err
		}

		baseKey.ScriptKey = &asset.ScriptKey{
			PubKey: pubKey,
		}

	case key.GetScriptKeyStr() != "":
		scriptKeyBytes, sErr := hex.DecodeString(key.GetScriptKeyStr())
		if sErr != nil {
			return baseKey, err
		}

		pubKey, err := schnorr.ParsePubKey(
			scriptKeyBytes,
		)
		if err != nil {
			return baseKey, err
		}

		baseKey.ScriptKey = &asset.ScriptKey{
			PubKey: pubKey,
		}
	default:
		// TODO(roasbeef): can actually allow not to be, then would
		// fetch all for the given outpoint
		return baseKey, fmt.Errorf("script key must be set")
	}

	switch {
	case key.GetOpStr() != "":
		// Parse a bitcoin outpoint in the form txid:index into a
		// wire.OutPoint struct.
		parts := strings.Split(key.GetOpStr(), ":")
		if len(parts) != 2 {
			return baseKey, errors.New("outpoint should be of " +
				"the form txid:index")
		}
		txidStr := parts[0]
		if hex.DecodedLen(len(txidStr)) != chainhash.HashSize {
			return baseKey, fmt.Errorf("invalid hex-encoded "+
				"txid %v", txidStr)
		}

		txid, err := chainhash.NewHashFromStr(txidStr)
		if err != nil {
			return baseKey, err
		}

		outputIndex, err := strconv.Atoi(parts[1])
		if err != nil {
			return baseKey, fmt.Errorf("invalid output "+
				"index: %v", err)
		}

		baseKey.MintingOutpoint = wire.OutPoint{
			Hash:  *txid,
			Index: uint32(outputIndex),
		}

	case key.GetOutpoint() != nil:
		op := key.GetOp()

		hash, err := chainhash.NewHashFromStr(op.HashStr)
		if err != nil {
			return baseKey, err
		}

		baseKey.MintingOutpoint = wire.OutPoint{
			Hash:  *hash,
			Index: uint32(op.Index),
		}

	default:
		return baseKey, fmt.Errorf("outpoint not set: %v", err)
	}

	return baseKey, nil
}

// marshalUniverseProof marshals a universe proof into the RPC form.
func marshalUniverseProof(proof *mssmt.Proof) ([]byte, error) {
	compressedProof := proof.Compress()

	var b bytes.Buffer
	if err := compressedProof.Encode(&b); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// marshalIssuanceProof marshals an issuance proof into the RPC form.
func marshalIssuanceProof(req *unirpc.UniverseKey,
	proof *universe.IssuanceProof) (*unirpc.IssuanceProofResponse, error) {

	uniRoot, err := marshalUniverseRoot(proof.UniverseRoot)
	if err != nil {
		return nil, err
	}
	uniProof, err := marshalUniverseProof(proof.InclusionProof)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := marshalAssetLeaf(proof.Leaf)
	if err != nil {
		return nil, err
	}

	return &unirpc.IssuanceProofResponse{
		Req:                    req,
		UniverseRoot:           uniRoot,
		UniverseInclusionProof: uniProof,
		AssetLeaf:              assetLeaf,
	}, nil
}

// QueryIssuanceProof attempts to query for an issuance proof for a given asset
// based on its UniverseKey. A UniverseKey is composed of the Universe ID
// (asset_id/group_key) and also a leaf key (outpoint || script_key). If found,
// then the issuance proof is returned that includes an inclusion proof to the
// known Universe root, as well as a Taro state transition or issuance proof
// for the said asset.
func (r *rpcServer) QueryIssuanceProof(ctx context.Context,
	req *unirpc.UniverseKey) (*unirpc.IssuanceProofResponse, error) {

	universeID, err := unmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}
	leafKey, err := unmarshalLeafKey(req.LeafKey)
	if err != nil {
		return nil, err
	}

	proofs, err := r.cfg.BaseUniverse.FetchIssuanceProof(
		ctx, universeID, leafKey,
	)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): query may return multiple proofs, if allow key to
	// not be fully specified
	proof := proofs[0]

	return marshalIssuanceProof(req, proof)
}

// unmarsalAssetLeaf unmarshals an asset leaf from the RPC form.
func unmarshalAssetLeaf(leaf *unirpc.AssetLeaf) (*universe.MintingLeaf, error) {
	// We'll just pull the asset details from the serialized issuance proof
	// itself.
	var assetProof proof.Proof
	if err := assetProof.Decode(
		bytes.NewReader(leaf.IssuanceProof),
	); err != nil {
		return nil, err
	}

	// TODO(roasbeef): double check posted file format everywhere
	//  * raw proof, or within file?

	return &universe.MintingLeaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  assetProof.Asset.Genesis,
			GroupKey: assetProof.Asset.GroupKey,
		},
		GenesisProof: leaf.IssuanceProof,
		Amt:          assetProof.Asset.Amount,
	}, nil
}

// InsertIssuanceProof attempts to insert a new issuance proof into the
// Universe tree specified by the UniverseKey. If valid, then the proof is
// inserted into the database, with a new Universe root returned for the
// updated asset_id/group_key.
func (r *rpcServer) InsertIssuanceProof(ctx context.Context,
	req *unirpc.IssuanceProof) (*unirpc.IssuanceProofResponse, error) {

	universeID, err := unmarshalUniID(req.Key.Id)
	if err != nil {
		return nil, err
	}
	leafKey, err := unmarshalLeafKey(req.Key.LeafKey)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := unmarshalAssetLeaf(req.AssetLeaf)
	if err != nil {
		return nil, err
	}

	newUniverseState, err := r.cfg.BaseUniverse.RegisterIssuance(
		ctx, universeID, leafKey, assetLeaf,
	)
	if err != nil {
		return nil, err
	}

	return marshalIssuanceProof(req.Key, newUniverseState)
}

// SyncUniverse takes host information for a remote Universe server, then
// attempts to synchronize either only the set of specified asset_ids, or all
// assets if none are specified. The sync process will attempt to query for the
// latest known root for each asset, performing tree based reconciliation to
// arrive at a new shared root.
func (r *rpcServer) SyncUniverse(ctx context.Context,
	req *unirpc.SyncRequest) (*unirpc.SyncResponse, error) {

	return nil, nil
}
