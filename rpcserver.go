package taprootassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcperms"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/signal"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

var (
	// MaxMsgReceiveSize is the largest message our client will receive. We
	// set this to 200MiB atm.
	MaxMsgReceiveSize = grpc.MaxCallRecvMsgSize(lnrpc.MaxGrpcMsgSize)

	// ServerMaxMsgReceiveSize is the largest message our server will
	// receive.
	ServerMaxMsgReceiveSize = grpc.MaxRecvMsgSize(lnrpc.MaxGrpcMsgSize)
)

const (
	// tapdMacaroonLocation is the value we use for the tapd macaroons'
	// "Location" field when baking them.
	tapdMacaroonLocation = "tapd"

	// maxNumBlocksInCache is the maximum number of blocks we'll cache
	// timestamps for. With 100k blocks we should only take up approximately
	// 800kB of memory (4 bytes for the block height and 4 bytes for the
	// timestamp, not including any map/cache overhead).
	maxNumBlocksInCache = 100_000

	// AssetBurnConfirmationText is the text that needs to be set on the
	// RPC to confirm an asset burn.
	AssetBurnConfirmationText = "assets will be destroyed"
)

type (
	// cacheableTimestamp is a wrapper around a uint32 that can be used as a
	// value in an LRU cache.
	cacheableTimestamp uint32

	// subSendEventNtfnsStream is a type alias for the asset send event
	// notification stream.
	subSendEventNtfnsStream = taprpc.TaprootAssets_SubscribeSendAssetEventNtfnsServer

	// subReceiveEventNtfnsStream is a type alias for the asset receive
	// event notification stream.
	subReceiveEventNtfnsStream = taprpc.TaprootAssets_SubscribeReceiveAssetEventNtfnsServer
)

// Size returns the size of the cacheable timestamp. Since we scale the cache by
// the number of items and not the total memory size, we can simply return 1
// here to count each timestamp as 1 item.
func (c cacheableTimestamp) Size() (uint64, error) {
	return 1, nil
}

// rpcServer is the main RPC server for the Taproot Assets daemon that handles
// gRPC/REST/Websockets incoming requests.
type rpcServer struct {
	started  int32
	shutdown int32

	taprpc.UnimplementedTaprootAssetsServer
	wrpc.UnimplementedAssetWalletServer
	mintrpc.UnimplementedMintServer
	rfqrpc.UnimplementedRfqServer
	unirpc.UnimplementedUniverseServer
	tapdevrpc.UnimplementedTapDevServer

	interceptor signal.Interceptor

	interceptorChain *rpcperms.InterceptorChain

	cfg *Config

	blockTimestampCache *lru.Cache[uint32, cacheableTimestamp]

	proofQueryRateLimiter *rate.Limiter

	quit chan struct{}
	wg   sync.WaitGroup
}

// newRPCServer creates a new RPC sever from the set of input dependencies.
func newRPCServer(interceptor signal.Interceptor,
	interceptorChain *rpcperms.InterceptorChain,
	cfg *Config) (*rpcServer, error) {

	return &rpcServer{
		interceptor:      interceptor,
		interceptorChain: interceptorChain,
		blockTimestampCache: lru.NewCache[uint32, cacheableTimestamp](
			maxNumBlocksInCache,
		),
		quit: make(chan struct{}),
		proofQueryRateLimiter: rate.NewLimiter(
			cfg.UniverseQueriesPerSecond, cfg.UniverseQueriesBurst,
		),
		cfg: cfg,
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
	taprpc.RegisterTaprootAssetsServer(grpcServer, r)
	wrpc.RegisterAssetWalletServer(grpcServer, r)
	mintrpc.RegisterMintServer(grpcServer, r)
	rfqrpc.RegisterRfqServer(grpcServer, r)
	unirpc.RegisterUniverseServer(grpcServer, r)
	tapdevrpc.RegisterGrpcServer(grpcServer, r)
	return nil
}

// RegisterWithRestProxy registers the RPC server with the given rest proxy.
func (r *rpcServer) RegisterWithRestProxy(restCtx context.Context,
	restMux *proxy.ServeMux, restDialOpts []grpc.DialOption,
	restProxyDest string) error {

	// With our custom REST proxy mux created, register our main RPC and
	// give all subservers a chance to register as well.
	err := taprpc.RegisterTaprootAssetsHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	err = wrpc.RegisterAssetWalletHandlerFromEndpoint(
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
	_ *taprpc.StopRequest) (*taprpc.StopResponse, error) {

	r.interceptor.RequestShutdown()
	return &taprpc.StopResponse{}, nil
}

// DebugLevel allows a caller to programmatically set the logging verbosity of
// tapd. The logging can be targeted according to a coarse daemon-wide logging
// level, or in a granular fashion to specify the logging for a target
// sub-system.
func (r *rpcServer) DebugLevel(ctx context.Context,
	req *taprpc.DebugLevelRequest) (*taprpc.DebugLevelResponse, error) {

	// If show is set, then we simply print out the list of available
	// sub-systems.
	if req.Show {
		return &taprpc.DebugLevelResponse{
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

	return &taprpc.DebugLevelResponse{}, nil
}

// GetInfo returns general information relating to the active daemon. For
// example: its version, network, and lnd version.
func (r *rpcServer) GetInfo(ctx context.Context,
	_ *taprpc.GetInfoRequest) (*taprpc.GetInfoResponse, error) {

	// Retrieve the best block hash and height from the chain backend.
	blockHash, blockHeight, err := r.cfg.Lnd.ChainKit.GetBestBlock(ctx)
	if err != nil {
		return nil, err
	}

	// Retrieve the current lnd node's info.
	info, err := r.cfg.Lnd.Client.GetInfo(context.Background())
	if err != nil {
		return nil, err
	}

	return &taprpc.GetInfoResponse{
		Version:           Version(),
		LndVersion:        r.cfg.Lnd.Version.Version,
		Network:           r.cfg.ChainParams.Name,
		LndIdentityPubkey: r.cfg.Lnd.NodePubkey.String(),
		NodeAlias:         info.Alias,
		BlockHeight:       uint32(blockHeight),
		BlockHash:         blockHash.String(),
		SyncToChain:       info.SyncedToChain,
	}, nil
}

// MintAsset attempts to mint the set of assets (async by default to ensure
// proper batching) specified in the request.
func (r *rpcServer) MintAsset(ctx context.Context,
	req *mintrpc.MintAssetRequest) (*mintrpc.MintAssetResponse, error) {

	if req.Asset == nil {
		return nil, fmt.Errorf("asset cannot be nil")
	}

	err := asset.ValidateAssetName(req.Asset.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid asset name: %w", err)
	}

	specificGroupKey := len(req.Asset.GroupKey) != 0
	specificGroupAnchor := len(req.Asset.GroupAnchor) != 0

	switch {
	// New grouped asset and grouped asset cannot both be set.
	case req.Asset.NewGroupedAsset && req.Asset.GroupedAsset:
		return nil, fmt.Errorf("cannot set both new grouped asset " +
			"and grouped asset",
		)

	// Using a specific group key or anchor implies disabling emission.
	case req.Asset.NewGroupedAsset:
		if specificGroupKey || specificGroupAnchor {
			return nil, fmt.Errorf("must disable emission to " +
				"specify a group")
		}

	// If the asset is intended to be part of an existing group, a group key
	// or anchor must be specified, but not both.
	case req.Asset.GroupedAsset:
		if !specificGroupKey && !specificGroupAnchor {
			return nil, fmt.Errorf("must specify a group key or" +
				"group anchor")
		}

		if specificGroupKey && specificGroupAnchor {
			return nil, fmt.Errorf("cannot specify both a group " +
				"key and a group anchor")
		}

	// A group was specified without GroupedAsset being set.
	case specificGroupKey || specificGroupAnchor:
		return nil, fmt.Errorf("must set grouped asset to mint into " +
			"a specific group")
	}

	assetVersion, err := taprpc.UnmarshalAssetVersion(
		req.Asset.AssetVersion,
	)
	if err != nil {
		return nil, err
	}

	seedling := &tapgarden.Seedling{
		AssetVersion:   assetVersion,
		AssetType:      asset.Type(req.Asset.AssetType),
		AssetName:      req.Asset.Name,
		Amount:         req.Asset.Amount,
		EnableEmission: req.Asset.NewGroupedAsset,
	}

	rpcsLog.Infof("[MintAsset]: version=%v, type=%v, name=%v, amt=%v, "+
		"issuance=%v", seedling.AssetVersion, seedling.AssetType,
		seedling.AssetName, seedling.Amount, seedling.EnableEmission)

	switch {
	// If a group key is provided, parse the provided group public key
	// before creating the asset seedling.
	case specificGroupKey:
		groupTweakedKey, err := btcec.ParsePubKey(req.Asset.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("invalid group key: %w", err)
		}

		err = r.checkBalanceOverflow(
			ctx, nil, groupTweakedKey, req.Asset.Amount,
		)
		if err != nil {
			return nil, err
		}

		seedling.GroupInfo = &asset.AssetGroup{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *groupTweakedKey,
			},
		}

	// If a group anchor is provided, propoate the name to the seedling.
	// We cannot do any name validation from outside the minter.
	case specificGroupAnchor:
		seedling.GroupAnchor = &req.Asset.GroupAnchor
	}

	if req.Asset.AssetMeta != nil {
		// Ensure that the meta field is within bounds.
		switch {
		case req.Asset.AssetMeta.Type < 0:
			return nil, fmt.Errorf("meta type cannot be negative")

		case req.Asset.AssetMeta.Type > math.MaxUint8:
			return nil, fmt.Errorf("meta type is too large: %v, "+
				"max is: %v", req.Asset.AssetMeta.Type,
				math.MaxUint8)
		}

		seedling.Meta = &proof.MetaReveal{
			Type: proof.MetaType(req.Asset.AssetMeta.Type),
			Data: req.Asset.AssetMeta.Data,
		}

		// If the asset meta field was specified, then the data inside
		// must be valid. Let's check that now.
		if err := seedling.Meta.Validate(); err != nil {
			return nil, fmt.Errorf("invalid asset meta: %w", err)
		}
	}

	updates, err := r.cfg.AssetMinter.QueueNewSeedling(seedling)
	if err != nil {
		return nil, fmt.Errorf("unable to mint new asset: %w", err)
	}

	// Wait for an initial update, so we can report back if things succeeded
	// or failed.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context closed: %w", ctx.Err())

	case update := <-updates:
		if update.Error != nil {
			return nil, fmt.Errorf("unable to mint asset: %w",
				update.Error)
		}

		rpcBatch, err := marshalMintingBatch(
			update.PendingBatch, req.ShortResponse,
		)
		if err != nil {
			return nil, err
		}

		return &mintrpc.MintAssetResponse{
			PendingBatch: rpcBatch,
		}, nil
	}
}

// checkFeeRateSanity ensures that the provided fee rate, in sat/kw, is above
// the same minimum fee used as a floor in the fee estimator.
func checkFeeRateSanity(rpcFeeRate uint32) (*chainfee.SatPerKWeight, error) {
	feeFloor := uint32(chainfee.FeePerKwFloor)
	switch {
	// No manual fee rate was set, which is the default.
	case rpcFeeRate == 0:
		return nil, nil

	// A manual fee was set but is below a reasonable floor.
	case rpcFeeRate < feeFloor:
		return nil, fmt.Errorf("manual fee rate below floor: "+
			"(fee_rate=%d, floor=%d sat/kw)", rpcFeeRate, feeFloor)

	// Set the fee rate for this transaction.
	default:
		return fn.Ptr(chainfee.SatPerKWeight(rpcFeeRate)), nil
	}
}

// FinalizeBatch attempts to finalize the current pending batch.
func (r *rpcServer) FinalizeBatch(_ context.Context,
	req *mintrpc.FinalizeBatchRequest) (*mintrpc.FinalizeBatchResponse,
	error) {

	var batchSibling *asset.TapscriptTreeNodes

	feeRate, err := checkFeeRateSanity(req.FeeRate)
	if err != nil {
		return nil, err
	}
	feeRateOpt := fn.MaybeSome(feeRate)

	batchTapscriptTree := req.GetFullTree()
	batchTapBranch := req.GetBranch()

	switch {
	case batchTapscriptTree != nil && batchTapBranch != nil:
		return nil, fmt.Errorf("cannot specify both tapscript tree " +
			"and tapscript tree branches")

	case batchTapscriptTree != nil:
		batchSibling, err = marshalTapscriptFullTree(batchTapscriptTree)
		if err != nil {
			return nil, fmt.Errorf("invalid tapscript tree: %w",
				err)
		}

	case batchTapBranch != nil:
		batchSibling, err = marshalTapscriptBranch(batchTapBranch)
		if err != nil {
			return nil, fmt.Errorf("invalid tapscript branch: %w",
				err)
		}
	}
	tapTreeOpt := fn.MaybeSome(batchSibling)

	batch, err := r.cfg.AssetMinter.FinalizeBatch(
		tapgarden.FinalizeParams{
			FeeRate:        feeRateOpt,
			SiblingTapTree: tapTreeOpt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize batch: %w", err)
	}

	// If there was no batch to finalize, return an empty response.
	if batch == nil {
		return &mintrpc.FinalizeBatchResponse{}, nil
	}

	rpcBatch, err := marshalMintingBatch(batch, req.ShortResponse)
	if err != nil {
		return nil, err
	}

	return &mintrpc.FinalizeBatchResponse{
		Batch: rpcBatch,
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

	switch {
	case len(req.GetBatchKey()) > 0 && len(req.GetBatchKeyStr()) > 0:
		return nil, fmt.Errorf("cannot specify both batch_key and " +
			"batch_key_string")

	case len(req.GetBatchKey()) > 0:
		batchKey, err = btcec.ParsePubKey(req.GetBatchKey())
		if err != nil {
			return nil, fmt.Errorf("invalid batch key: %w", err)
		}

	case len(req.GetBatchKeyStr()) > 0:
		batchKeyBytes, err := hex.DecodeString(req.GetBatchKeyStr())
		if err != nil {
			return nil, fmt.Errorf("invalid batch key string: %w",
				err)
		}

		batchKey, err = btcec.ParsePubKey(batchKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid batch key: %w", err)
		}
	}

	batches, err := r.cfg.AssetMinter.ListBatches(batchKey)
	if err != nil {
		return nil, fmt.Errorf("unable to list batches: %w", err)
	}

	rpcBatches, err := fn.MapErr(
		batches,
		func(b *tapgarden.MintingBatch) (*mintrpc.MintingBatch, error) {
			return marshalMintingBatch(b, false)
		},
	)
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
	req *taprpc.ListAssetRequest) (*taprpc.ListAssetResponse, error) {

	if req.IncludeSpent && req.IncludeLeased {
		return nil, fmt.Errorf("cannot specify both include_spent " +
			"and include_leased")
	}

	rpcAssets, err := r.fetchRpcAssets(
		ctx, req.WithWitness, req.IncludeSpent, req.IncludeLeased,
	)
	if err != nil {
		return nil, err
	}

	return &taprpc.ListAssetResponse{
		Assets: rpcAssets,
	}, nil
}

func (r *rpcServer) fetchRpcAssets(ctx context.Context, withWitness,
	includeSpent, includeLeased bool) ([]*taprpc.Asset, error) {

	assets, err := r.cfg.AssetStore.FetchAllAssets(
		ctx, includeSpent, includeLeased, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read chain assets: %w", err)
	}

	rpcAssets := make([]*taprpc.Asset, len(assets))
	for i, a := range assets {
		rpcAssets[i], err = r.marshalChainAsset(ctx, a, withWitness)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal asset: %w",
				err)
		}
	}

	return rpcAssets, nil
}

func (r *rpcServer) marshalChainAsset(ctx context.Context, a *asset.ChainAsset,
	withWitness bool) (*taprpc.Asset, error) {

	rpcAsset, err := taprpc.MarshalAsset(
		ctx, a.Asset, a.IsSpent, withWitness, r.cfg.AddrBook,
	)
	if err != nil {
		return nil, err
	}

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

	rpcAsset.ChainAnchor = &taprpc.AnchorInfo{
		AnchorTx:         anchorTxBytes,
		AnchorBlockHash:  a.AnchorBlockHash.String(),
		AnchorOutpoint:   a.AnchorOutpoint.String(),
		InternalKey:      a.AnchorInternalKey.SerializeCompressed(),
		MerkleRoot:       a.AnchorMerkleRoot,
		TapscriptSibling: a.AnchorTapscriptSibling,
		BlockHeight:      a.AnchorBlockHeight,
	}

	if a.AnchorLeaseOwner != [32]byte{} {
		rpcAsset.LeaseOwner = a.AnchorLeaseOwner[:]
		rpcAsset.LeaseExpiry = a.AnchorLeaseExpiry.UTC().Unix()
	}

	return rpcAsset, nil
}

func (r *rpcServer) listBalancesByAsset(ctx context.Context,
	assetID *asset.ID) (*taprpc.ListBalancesResponse, error) {

	balances, err := r.cfg.AssetStore.QueryBalancesByAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("unable to list balances: %w", err)
	}

	resp := &taprpc.ListBalancesResponse{
		AssetBalances: make(map[string]*taprpc.AssetBalance, len(balances)),
	}

	for _, balance := range balances {
		balance := balance

		assetIDStr := hex.EncodeToString(balance.ID[:])

		resp.AssetBalances[assetIDStr] = &taprpc.AssetBalance{
			AssetGenesis: &taprpc.GenesisInfo{
				Version:      balance.Version,
				GenesisPoint: balance.GenesisPoint.String(),
				AssetType:    taprpc.AssetType(balance.Type),
				Name:         balance.Tag,
				MetaHash:     balance.MetaHash[:],
				AssetId:      balance.ID[:],
			},
			Balance: balance.Balance,
		}
	}

	return resp, nil
}

func (r *rpcServer) listBalancesByGroupKey(ctx context.Context,
	groupKey *btcec.PublicKey) (*taprpc.ListBalancesResponse, error) {

	balances, err := r.cfg.AssetStore.QueryAssetBalancesByGroup(
		ctx, groupKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list balances: %w", err)
	}

	resp := &taprpc.ListBalancesResponse{
		AssetGroupBalances: make(
			map[string]*taprpc.AssetGroupBalance, len(balances),
		),
	}

	for _, balance := range balances {
		balance := balance

		var groupKey []byte
		if balance.GroupKey != nil {
			groupKey = balance.GroupKey.SerializeCompressed()
		}

		groupKeyString := hex.EncodeToString(groupKey)
		resp.AssetGroupBalances[groupKeyString] = &taprpc.AssetGroupBalance{
			GroupKey: groupKey,
			Balance:  balance.Balance,
		}
	}

	return resp, nil
}

// ListUtxos lists the UTXOs managed by the target daemon, and the assets they
// hold.
func (r *rpcServer) ListUtxos(ctx context.Context,
	req *taprpc.ListUtxosRequest) (*taprpc.ListUtxosResponse, error) {

	rpcAssets, err := r.fetchRpcAssets(ctx, false, false, req.IncludeLeased)
	if err != nil {
		return nil, err
	}

	managedUtxos, err := r.cfg.AssetStore.FetchManagedUTXOs(ctx)
	if err != nil {
		return nil, err
	}

	utxos := make(map[string]*taprpc.ManagedUtxo)
	for _, u := range managedUtxos {
		utxos[u.OutPoint.String()] = &taprpc.ManagedUtxo{
			OutPoint:         u.OutPoint.String(),
			AmtSat:           int64(u.OutputValue),
			InternalKey:      u.InternalKey.PubKey.SerializeCompressed(),
			TaprootAssetRoot: u.TaprootAssetRoot,
			MerkleRoot:       u.MerkleRoot,
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

	// As a final pass, we'll prune out any UTXOs that don't have any
	// assets, as these may be in the DB just for record keeping.
	for _, utxo := range utxos {
		if len(utxo.Assets) == 0 {
			delete(utxos, utxo.OutPoint)
		}
	}

	return &taprpc.ListUtxosResponse{
		ManagedUtxos: utxos,
	}, nil
}

// ListGroups lists known groups and the assets held in each group.
func (r *rpcServer) ListGroups(ctx context.Context,
	_ *taprpc.ListGroupsRequest) (*taprpc.ListGroupsResponse, error) {

	readableAssets, err := r.cfg.AssetStore.FetchGroupedAssets(ctx)
	if err != nil {
		return nil, err
	}

	groupsWithAssets := make(map[string]*taprpc.GroupedAssets)

	// Populate the map of group keys to assets in that group.
	for _, a := range readableAssets {
		groupKey := hex.EncodeToString(a.GroupKey.SerializeCompressed())

		assetVersion, err := taprpc.MarshalAssetVersion(
			a.Version,
		)
		if err != nil {
			return nil, err
		}

		asset := &taprpc.AssetHumanReadable{
			Id:               a.ID[:],
			Version:          assetVersion,
			Amount:           a.Amount,
			LockTime:         int32(a.LockTime),
			RelativeLockTime: int32(a.RelativeLockTime),
			Tag:              a.Tag,
			MetaHash:         a.MetaHash[:],
			Type:             taprpc.AssetType(a.Type),
		}

		_, ok := groupsWithAssets[groupKey]
		if !ok {
			groupsWithAssets[groupKey] = &taprpc.GroupedAssets{
				Assets: []*taprpc.AssetHumanReadable{},
			}
		}

		groupsWithAssets[groupKey].Assets = append(
			groupsWithAssets[groupKey].Assets, asset,
		)
	}

	return &taprpc.ListGroupsResponse{Groups: groupsWithAssets}, nil
}

// ListBalances lists the asset balances owned by the daemon.
func (r *rpcServer) ListBalances(ctx context.Context,
	req *taprpc.ListBalancesRequest) (*taprpc.ListBalancesResponse, error) {

	switch groupBy := req.GroupBy.(type) {
	case *taprpc.ListBalancesRequest_AssetId:
		if !groupBy.AssetId {
			return nil, fmt.Errorf("invalid group_by")
		}

		var assetID *asset.ID
		if len(req.AssetFilter) != 0 {
			assetID = &asset.ID{}
			if len(req.AssetFilter) != len(assetID) {
				return nil, fmt.Errorf("invalid asset filter")
			}

			copy(assetID[:], req.AssetFilter)
		}

		return r.listBalancesByAsset(ctx, assetID)

	case *taprpc.ListBalancesRequest_GroupKey:
		if !groupBy.GroupKey {
			return nil, fmt.Errorf("invalid group_by")
		}

		var groupKey *btcec.PublicKey
		if len(req.GroupKeyFilter) != 0 {
			var err error
			groupKey, err = btcec.ParsePubKey(req.GroupKeyFilter)
			if err != nil {
				return nil, fmt.Errorf("invalid group key "+
					"filter: %w", err)
			}
		}

		return r.listBalancesByGroupKey(ctx, groupKey)

	default:
		return nil, fmt.Errorf("invalid group_by")
	}
}

// ListTransfers lists all asset transfers managed by this daemon.
func (r *rpcServer) ListTransfers(ctx context.Context,
	req *taprpc.ListTransfersRequest) (*taprpc.ListTransfersResponse,
	error) {

	// Unmarshal the anchor tx hash if one was provided.
	var (
		anchorTxHash *chainhash.Hash
		err          error
	)

	if len(req.AnchorTxid) != 0 {
		anchorTxHash, err = chainhash.NewHashFromStr(req.AnchorTxid)
		if err != nil {
			return nil, fmt.Errorf("invalid anchor tx hash: %w",
				err)
		}
	}

	parcels, err := r.cfg.AssetStore.QueryParcels(ctx, anchorTxHash, false)
	if err != nil {
		return nil, fmt.Errorf("failed to query parcels: %w", err)
	}

	resp := &taprpc.ListTransfersResponse{
		Transfers: make([]*taprpc.AssetTransfer, len(parcels)),
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

// QueryAddrs queries the set of Taproot Asset addresses stored in the database.
func (r *rpcServer) QueryAddrs(ctx context.Context,
	req *taprpc.QueryAddrRequest) (*taprpc.QueryAddrResponse, error) {

	query := address.QueryParams{
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	// The unix time of 0 (1970-01-01) is not the same as an empty Time
	// struct (0000-00-00). For our query to succeed, we need to set the
	// time values the way the address book expects them.
	if req.CreatedBefore > 0 {
		query.CreatedBefore = time.Unix(req.CreatedBefore, 0)
	}
	if req.CreatedAfter > 0 {
		query.CreatedAfter = time.Unix(req.CreatedAfter, 0)
	}

	rpcsLog.Debugf("[QueryAddrs]: addr query params: %v",
		spew.Sdump(query))

	dbAddrs, err := r.cfg.AddrBook.ListAddrs(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("unable to query addrs: %w", err)
	}

	// TODO(roasbeef): just stop storing the hrp in the addr?
	tapParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	addrs := make([]*taprpc.Addr, len(dbAddrs))
	for i, dbAddr := range dbAddrs {
		dbAddr.ChainParams = &tapParams

		addrs[i], err = marshalAddr(dbAddr.Tap, r.cfg.TapAddrBook)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal addr: %w",
				err)
		}
	}

	rpcsLog.Debugf("[QueryAddrs]: returning %v addrs", len(addrs))

	return &taprpc.QueryAddrResponse{
		Addrs: addrs,
	}, nil
}

// NewAddr makes a new address from the set of request params.
func (r *rpcServer) NewAddr(ctx context.Context,
	req *taprpc.NewAddrRequest) (*taprpc.Addr, error) {

	// Parse the proof courier address if one was provided, otherwise use
	// the default specified in the config.
	courierAddr := r.cfg.DefaultProofCourierAddr
	if req.ProofCourierAddr != "" {
		var err error
		courierAddr, err = proof.ParseCourierAddress(
			req.ProofCourierAddr,
		)
		if err != nil {
			return nil, fmt.Errorf("invalid proof courier "+
				"address: %w", err)
		}
	}

	// Check that the proof courier address is set. This should never
	// happen, but we check anyway to avoid panics (possibly caused by
	// future erroneous config changes).
	if courierAddr == nil {
		return nil, fmt.Errorf("no proof courier address provided")
	}

	if len(req.AssetId) != 32 {
		return nil, fmt.Errorf("invalid asset id length")
	}

	var assetID asset.ID
	copy(assetID[:], req.AssetId)

	rpcsLog.Infof("[NewAddr]: making new addr: asset_id=%x, amt=%v",
		assetID[:], req.Amt)

	err := r.checkBalanceOverflow(ctx, &assetID, nil, req.Amt)
	if err != nil {
		return nil, err
	}

	// Was there a tapscript sibling preimage specified? If so, decode it
	// and check that it is not a Taproot Asset Commitment.
	tapscriptSibling, _, err := commitment.MaybeDecodeTapscriptPreimage(
		req.TapscriptSibling,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid tapscript sibling: %w", err)
	}

	assetVersion, err := taprpc.UnmarshalAssetVersion(req.AssetVersion)
	if err != nil {
		return nil, err
	}

	var addr *address.AddrWithKeyInfo
	switch {
	// No key was specified, we'll let the address book derive them.
	case req.ScriptKey == nil && req.InternalKey == nil:
		// Now that we have all the params, we'll try to add a new
		// address to the addr book.
		addr, err = r.cfg.AddrBook.NewAddress(
			ctx, assetID, req.Amt, tapscriptSibling, *courierAddr,
			address.WithAssetVersion(assetVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make new addr: %w",
				err)
		}

	// Only the script key was specified.
	case req.ScriptKey != nil && req.InternalKey == nil:
		return nil, fmt.Errorf("internal key must also be specified " +
			"if script key is specified")

	// Only the internal key was specified.
	case req.ScriptKey == nil && req.InternalKey != nil:
		return nil, fmt.Errorf("script key must also be specified " +
			"if internal key is specified")

	// Both the script and internal keys were specified.
	default:
		scriptKey, err := UnmarshalScriptKey(req.ScriptKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}

		rpcsLog.Debugf("Decoded script key %x (internal %x, tweak %x)",
			scriptKey.PubKey.SerializeCompressed(),
			scriptKey.RawKey.PubKey.SerializeCompressed(),
			scriptKey.Tweak[:])

		internalKey, err := UnmarshalKeyDescriptor(req.InternalKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode internal "+
				"key: %w", err)
		}

		// Now that we have all the params, we'll try to add a new
		// address to the addr book.
		addr, err = r.cfg.AddrBook.NewAddressWithKeys(
			ctx, assetID, req.Amt, *scriptKey, internalKey,
			tapscriptSibling, *courierAddr,
			address.WithAssetVersion(assetVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make new addr: %w",
				err)
		}
	}

	// With our addr obtained, we'll marshal it as an RPC message then send
	// off the response.
	rpcAddr, err := marshalAddr(addr.Tap, r.cfg.TapAddrBook)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal addr: %w", err)
	}

	return rpcAddr, nil
}

// DecodeAddr decode a Taproot Asset address into a partial asset message that
// represents the asset it wants to receive.
func (r *rpcServer) DecodeAddr(_ context.Context,
	req *taprpc.DecodeAddrRequest) (*taprpc.Addr, error) {

	if len(req.Addr) == 0 {
		return nil, fmt.Errorf("must specify an addr")
	}

	tapParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	addr, err := address.DecodeAddress(req.Addr, &tapParams)
	if err != nil {
		return nil, fmt.Errorf("unable to decode addr: %w", err)
	}

	rpcAddr, err := marshalAddr(addr, r.cfg.TapAddrBook)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal addr: %w", err)
	}

	return rpcAddr, nil
}

// VerifyProof attempts to verify a given proof file that claims to be anchored
// at the specified genesis point.
func (r *rpcServer) VerifyProof(ctx context.Context,
	req *taprpc.ProofFile) (*taprpc.VerifyProofResponse, error) {

	if !proof.IsProofFile(req.RawProofFile) {
		return nil, fmt.Errorf("invalid raw proof, expect file, not " +
			"single encoded mint or transition proof")
	}

	if err := proof.CheckMaxFileSize(req.RawProofFile); err != nil {
		return nil, fmt.Errorf("invalid proof file: %w", err)
	}

	var proofFile proof.File
	err := proofFile.Decode(bytes.NewReader(req.RawProofFile))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)
	_, err = proofFile.Verify(
		ctx, headerVerifier, proof.DefaultMerkleVerifier, groupVerifier,
	)
	if err != nil {
		// We don't want to fail the RPC request because of a proof
		// verification error, but we do want to log it for easier
		// debugging.
		rpcsLog.Errorf("Proof verification failed with err: %v", err)
	}
	valid := err == nil

	p, err := proofFile.LastProof()
	if err != nil {
		return nil, err
	}
	decodedProof, err := r.marshalProof(ctx, p, false, false)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal proof: %w", err)
	}

	decodedProof.ProofAtDepth = 0
	decodedProof.NumberOfProofs = uint32(proofFile.NumProofs())

	return &taprpc.VerifyProofResponse{
		Valid:        valid,
		DecodedProof: decodedProof,
	}, nil
}

// DecodeProof attempts to decode a given proof file that claims to be anchored
// at the specified genesis point.
func (r *rpcServer) DecodeProof(ctx context.Context,
	req *taprpc.DecodeProofRequest) (*taprpc.DecodeProofResponse, error) {

	var (
		proofReader = bytes.NewReader(req.RawProof)
		rpcProof    *taprpc.DecodedProof
	)
	switch {
	case proof.IsSingleProof(req.RawProof):
		var p proof.Proof
		err := p.Decode(proofReader)
		if err != nil {
			return nil, fmt.Errorf("unable to decode proof: %w",
				err)
		}

		rpcProof, err = r.marshalProof(
			ctx, &p, req.WithPrevWitnesses, req.WithMetaReveal,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal proof: %w",
				err)
		}

		rpcProof.NumberOfProofs = 1

	case proof.IsProofFile(req.RawProof):
		if err := proof.CheckMaxFileSize(req.RawProof); err != nil {
			return nil, fmt.Errorf("invalid proof file: %w", err)
		}

		var proofFile proof.File
		if err := proofFile.Decode(proofReader); err != nil {
			return nil, fmt.Errorf("unable to decode proof file: "+
				"%w", err)
		}

		latestProofIndex := uint32(proofFile.NumProofs() - 1)
		if req.ProofAtDepth > latestProofIndex {
			return nil, fmt.Errorf("invalid depth %d is greater "+
				"than latest proof index of %d",
				req.ProofAtDepth, latestProofIndex)
		}

		// Default to latest proof.
		index := latestProofIndex - req.ProofAtDepth
		p, err := proofFile.ProofAt(index)
		if err != nil {
			return nil, err
		}

		rpcProof, err = r.marshalProof(
			ctx, p, req.WithPrevWitnesses,
			req.WithMetaReveal,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal proof: %w",
				err)
		}

		rpcProof.ProofAtDepth = req.ProofAtDepth
		rpcProof.NumberOfProofs = uint32(proofFile.NumProofs())

	default:
		return nil, fmt.Errorf("invalid raw proof, could not " +
			"identify decoding format")
	}

	return &taprpc.DecodeProofResponse{
		DecodedProof: rpcProof,
	}, nil
}

// marshalProof turns a transition proof into an RPC DecodedProof.
func (r *rpcServer) marshalProof(ctx context.Context, p *proof.Proof,
	withPrevWitnesses, withMetaReveal bool) (*taprpc.DecodedProof, error) {

	var (
		rpcMeta        *taprpc.AssetMeta
		rpcGenesis     = p.GenesisReveal
		rpcGroupKey    = p.GroupKeyReveal
		anchorOutpoint = wire.OutPoint{
			Hash:  p.AnchorTx.TxHash(),
			Index: p.InclusionProof.OutputIndex,
		}
		txMerkleProof  = p.TxMerkleProof
		inclusionProof = p.InclusionProof
		splitRootProof = p.SplitRootProof
	)

	var txMerkleProofBuf bytes.Buffer
	if err := txMerkleProof.Encode(&txMerkleProofBuf); err != nil {
		return nil, fmt.Errorf("unable to encode serialized Bitcoin "+
			"merkle proof: %w", err)
	}

	var inclusionProofBuf bytes.Buffer
	if err := inclusionProof.Encode(&inclusionProofBuf); err != nil {
		return nil, fmt.Errorf("unable to encode inclusion proof: %w",
			err)
	}

	if inclusionProof.CommitmentProof == nil {
		return nil, fmt.Errorf("inclusion proof is missing " +
			"commitment proof")
	}
	tsSibling, tsHash, err := commitment.MaybeEncodeTapscriptPreimage(
		inclusionProof.CommitmentProof.TapSiblingPreimage,
	)
	if err != nil {
		return nil, fmt.Errorf("error encoding tapscript sibling: %w",
			err)
	}

	tapProof, err := inclusionProof.CommitmentProof.DeriveByAssetInclusion(
		&p.Asset,
	)
	if err != nil {
		return nil, fmt.Errorf("error deriving inclusion proof: %w",
			err)
	}
	merkleRoot := tapProof.TapscriptRoot(tsHash)

	var exclusionProofs [][]byte
	for _, exclusionProof := range p.ExclusionProofs {
		var exclusionProofBuf bytes.Buffer
		err = exclusionProof.Encode(&exclusionProofBuf)
		if err != nil {
			return nil, fmt.Errorf("unable to encode exclusion "+
				"proofs: %w", err)
		}
		exclusionProofs = append(
			exclusionProofs, exclusionProofBuf.Bytes(),
		)
	}

	var splitRootProofBuf bytes.Buffer
	if splitRootProof != nil {
		err = splitRootProof.Encode(&splitRootProofBuf)
		if err != nil {
			return nil, fmt.Errorf("unable to encode split root "+
				"proof: %w", err)
		}
	}

	rpcAsset, err := r.marshalChainAsset(ctx, &asset.ChainAsset{
		Asset:                  &p.Asset,
		AnchorTx:               &p.AnchorTx,
		AnchorBlockHash:        p.BlockHeader.BlockHash(),
		AnchorBlockHeight:      p.BlockHeight,
		AnchorOutpoint:         anchorOutpoint,
		AnchorInternalKey:      p.InclusionProof.InternalKey,
		AnchorMerkleRoot:       merkleRoot[:],
		AnchorTapscriptSibling: tsSibling,
	}, withPrevWitnesses)
	if err != nil {
		return nil, err
	}

	if withMetaReveal {
		switch {
		case p.MetaReveal != nil:
			rpcMeta = &taprpc.AssetMeta{
				Data: p.MetaReveal.Data,
				Type: taprpc.AssetMetaType(
					p.MetaReveal.Type,
				),
				MetaHash: fn.ByteSlice(p.MetaReveal.MetaHash()),
			}

		case len(rpcAsset.AssetGenesis.MetaHash) == 0:
			return nil, fmt.Errorf("asset does not contain meta " +
				"data")

		default:
			metaHash := rpcAsset.AssetGenesis.MetaHash
			req := &taprpc.FetchAssetMetaRequest{
				Asset: &taprpc.FetchAssetMetaRequest_MetaHash{
					MetaHash: metaHash,
				},
			}
			rpcMeta, err = r.FetchAssetMeta(ctx, req)
			if err != nil {
				return nil, err
			}
		}
	}

	decodedAssetID := p.Asset.ID()
	var genesisReveal *taprpc.GenesisReveal
	if rpcGenesis != nil {
		genesisReveal = &taprpc.GenesisReveal{
			GenesisBaseReveal: &taprpc.GenesisInfo{
				GenesisPoint: rpcGenesis.FirstPrevOut.String(),
				Name:         rpcGenesis.Tag,
				MetaHash:     rpcGenesis.MetaHash[:],
				AssetId:      decodedAssetID[:],
				OutputIndex:  rpcGenesis.OutputIndex,
				AssetType:    taprpc.AssetType(p.Asset.Type),
			},
		}
	}

	var GroupKeyReveal taprpc.GroupKeyReveal
	if rpcGroupKey != nil {
		GroupKeyReveal = taprpc.GroupKeyReveal{
			RawGroupKey:   rpcGroupKey.RawKey[:],
			TapscriptRoot: rpcGroupKey.TapscriptRoot,
		}
	}

	return &taprpc.DecodedProof{
		Asset:               rpcAsset,
		MetaReveal:          rpcMeta,
		TxMerkleProof:       txMerkleProofBuf.Bytes(),
		InclusionProof:      inclusionProofBuf.Bytes(),
		ExclusionProofs:     exclusionProofs,
		SplitRootProof:      splitRootProofBuf.Bytes(),
		NumAdditionalInputs: uint32(len(p.AdditionalInputs)),
		ChallengeWitness:    p.ChallengeWitness,
		IsBurn:              p.Asset.IsBurn(),
		GenesisReveal:       genesisReveal,
		GroupKeyReveal:      &GroupKeyReveal,
	}, nil
}

// ExportProof exports the latest raw proof file anchored at the specified
// script_key.
func (r *rpcServer) ExportProof(ctx context.Context,
	req *taprpc.ExportProofRequest) (*taprpc.ProofFile, error) {

	if len(req.ScriptKey) == 0 {
		return nil, fmt.Errorf("a valid script key must be specified")
	}

	scriptKey, err := parseUserKey(req.ScriptKey)
	if err != nil {
		return nil, fmt.Errorf("invalid script key: %w", err)
	}

	if len(req.AssetId) != 32 {
		return nil, fmt.Errorf("asset ID must be 32 bytes")
	}

	var (
		assetID  asset.ID
		outPoint *wire.OutPoint
	)
	copy(assetID[:], req.AssetId)

	// The outpoint is optional when querying for a proof file. But if
	// multiple proofs exist for the same assetID and script key, then an
	// error will be returned and the outpoint needs to be specified to
	// disambiguate.
	if req.Outpoint != nil {
		txid, err := chainhash.NewHash(req.Outpoint.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing outpoint: %w",
				err)
		}
		outPoint = &wire.OutPoint{
			Hash:  *txid,
			Index: req.Outpoint.OutputIndex,
		}
	}

	proofBlob, err := r.cfg.ProofArchive.FetchProof(ctx, proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *scriptKey,
		OutPoint:  outPoint,
	})
	if err != nil {
		return nil, err
	}

	return &taprpc.ProofFile{
		RawProofFile: proofBlob,
	}, nil
}

// ImportProof attempts to import a proof file into the daemon. If successful, a
// new asset will be inserted on disk, spendable using the specified target
// script key, and internal key.
func (r *rpcServer) ImportProof(ctx context.Context,
	req *tapdevrpc.ImportProofRequest) (*tapdevrpc.ImportProofResponse,
	error) {

	// We'll perform some basic input validation before we move forward.
	if len(req.ProofFile) == 0 {
		return nil, fmt.Errorf("proof file must be specified")
	}

	// We need to parse the proof file and extract the last proof, so we can
	// get the locator that is required for storage.
	var proofFile proof.File
	err := proofFile.Decode(bytes.NewReader(req.ProofFile))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	lastProof, err := proofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("error extracting last proof: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	// Now that we know the proof file is at least present, we'll attempt
	// to import it into the main archive.
	err = r.cfg.ProofArchive.ImportProofs(
		ctx, headerVerifier, proof.DefaultMerkleVerifier, groupVerifier,
		false, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   fn.Ptr(lastProof.Asset.ID()),
				ScriptKey: *lastProof.Asset.ScriptKey.PubKey,
				OutPoint:  fn.Ptr(lastProof.OutPoint()),
			},
			Blob: req.ProofFile,
		},
	)
	if err != nil {
		return nil, err
	}

	return &tapdevrpc.ImportProofResponse{}, nil
}

// AddrReceives lists all receives for incoming asset transfers for addresses
// that were created previously.
func (r *rpcServer) AddrReceives(ctx context.Context,
	req *taprpc.AddrReceivesRequest) (*taprpc.AddrReceivesResponse,
	error) {

	var sqlQuery address.EventQueryParams

	if len(req.FilterAddr) > 0 {
		tapParams := address.ParamsForChain(r.cfg.ChainParams.Name)

		addr, err := address.DecodeAddress(req.FilterAddr, &tapParams)
		if err != nil {
			return nil, fmt.Errorf("unable to decode addr: %w", err)
		}

		// Now that we've decoded the address, we'll check to make sure
		// that we can fetch the genesis for this address. Otherwise,
		// that means we don't know anything about what it should look
		// like on chain (the genesis is required to derive the taproot
		// output key).
		assetGroup, err := r.cfg.TapAddrBook.QueryAssetGroup(
			ctx, addr.AssetID,
		)
		if err != nil {
			return nil, fmt.Errorf("unknown asset=%x: %w",
				addr.AssetID[:], err)
		}

		rpcsLog.Tracef("Listing receives for group: %v",
			spew.Sdump(assetGroup))

		addr.AttachGenesis(*assetGroup.Genesis)

		taprootOutputKey, err := addr.TaprootOutputKey()
		if err != nil {
			return nil, fmt.Errorf("error deriving Taproot key: %w",
				err)
		}

		sqlQuery.AddrTaprootOutputKey = schnorr.SerializePubKey(
			taprootOutputKey,
		)
	}

	if req.FilterStatus != taprpc.AddrEventStatus_ADDR_EVENT_STATUS_UNKNOWN {
		status, err := unmarshalAddrEventStatus(req.FilterStatus)
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

	resp := &taprpc.AddrReceivesResponse{
		Events: make([]*taprpc.AddrEvent, len(events)),
	}

	for idx, event := range events {
		resp.Events[idx], err = marshalAddrEvent(
			event, r.cfg.TapAddrBook,
		)
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
	req *wrpc.FundVirtualPsbtRequest) (*wrpc.FundVirtualPsbtResponse,
	error) {

	var fundedVPkt *tapfreighter.FundedVPacket
	switch {
	case req.GetPsbt() != nil:
		vPkt, err := tappsbt.NewFromRawBytes(
			bytes.NewReader(req.GetPsbt()), false,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode psbt: %w", err)
		}

		// Extract the recipient information from the packet. This
		// basically assembles the asset ID we want to send to and the
		// sum of all output amounts.
		desc, err := tapsend.DescribeRecipients(
			ctx, vPkt, r.cfg.TapAddrBook,
		)
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

	case req.GetRaw() != nil:
		raw := req.GetRaw()
		if len(raw.Inputs) > 0 {
			return nil, fmt.Errorf("template inputs not yet " +
				"supported")
		}
		if len(raw.Recipients) > 1 {
			return nil, fmt.Errorf("only one recipient supported")
		}

		var (
			tapParams = address.ParamsForChain(
				r.cfg.ChainParams.Name,
			)
			addr *address.Tap
			err  error
		)
		for a := range raw.Recipients {
			addr, err = address.DecodeAddress(a, &tapParams)
			if err != nil {
				return nil, fmt.Errorf("unable to decode "+
					"addr: %w", err)
			}
		}

		if addr == nil {
			return nil, fmt.Errorf("no recipients specified")
		}

		fundedVPkt, err = r.cfg.AssetWallet.FundAddressSend(ctx, addr)
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
func (r *rpcServer) SignVirtualPsbt(ctx context.Context,
	req *wrpc.SignVirtualPsbtRequest) (*wrpc.SignVirtualPsbtResponse,
	error) {

	if req.FundedPsbt == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	vPkt, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	// Make sure the input keys are known.
	for _, input := range vPkt.Inputs {
		// If we have all the derivation information, we don't need to
		// do anything.
		if len(input.Bip32Derivation) > 0 &&
			len(input.TaprootBip32Derivation) > 0 {

			continue
		}

		scriptKey := input.Asset().ScriptKey

		// If the full tweaked script key isn't set on the asset, we
		// need to look it up in the local database, to make sure we'll
		// be able to sign for it.
		if scriptKey.TweakedScriptKey == nil {
			tweakedScriptKey, err := r.cfg.AssetWallet.FetchScriptKey(
				ctx, scriptKey.PubKey,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching "+
					"script key: %w", err)
			}

			scriptKey.TweakedScriptKey = tweakedScriptKey
		}

		derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
			scriptKey.TweakedScriptKey.RawKey,
			r.cfg.ChainParams.HDCoinType,
		)
		input.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
		input.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trDerivation,
		}
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
	req *wrpc.AnchorVirtualPsbtsRequest) (*taprpc.SendAssetResponse,
	error) {

	if len(req.VirtualPsbts) == 0 {
		return nil, fmt.Errorf("no virtual PSBTs specified")
	}

	if len(req.VirtualPsbts) > 1 {
		return nil, fmt.Errorf("only one virtual PSBT supported")
	}

	vPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(req.VirtualPsbts[0]), false,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	// Query the asset store to gather tap commitments for all inputs.
	inputCommitments := make(tappsbt.InputCommitments, len(vPacket.Inputs))
	for idx := range vPacket.Inputs {
		input := vPacket.Inputs[idx]

		inputAsset := input.Asset()
		prevID := input.PrevID

		inputCommitment, err := r.cfg.AssetStore.FetchCommitment(
			ctx, inputAsset.ID(), prevID.OutPoint,
			inputAsset.GroupKey, &inputAsset.ScriptKey, true,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching input "+
				"commitment: %w", err)
		}

		inputCommitments[prevID] = inputCommitment.Commitment
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewPreSignedParcel(vPacket, inputCommitments),
	)
	if err != nil {
		return nil, fmt.Errorf("error requesting delivery: %w", err)
	}

	parcel, err := marshalOutboundParcel(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling outbound parcel: %w",
			err)
	}

	return &taprpc.SendAssetResponse{
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

// QueryInternalKey returns the key descriptor for the given internal key.
func (r *rpcServer) QueryInternalKey(ctx context.Context,
	req *wrpc.QueryInternalKeyRequest) (*wrpc.QueryInternalKeyResponse,
	error) {

	var (
		internalKey *btcec.PublicKey
		keyLocator  keychain.KeyLocator
		err         error
	)

	// We allow the user to specify the key either in the 33-byte compressed
	// format or the 32-byte x-only format.
	switch {
	case len(req.InternalKey) == 33:
		internalKey, err = btcec.ParsePubKey(req.InternalKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing internal key: %w",
				err)
		}

		// If the full 33-byte key was specified, we expect the user to
		// already know the parity byte, so we only try once.
		keyLocator, err = r.cfg.AssetWallet.FetchInternalKeyLocator(
			ctx, internalKey,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching internal key: "+
				"%w", err)
		}

	case len(req.InternalKey) == 32:
		internalKey, err = schnorr.ParsePubKey(req.InternalKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing internal key: %w",
				err)
		}

		keyLocator, err = r.cfg.AssetWallet.FetchInternalKeyLocator(
			ctx, internalKey,
		)

		switch {
		// If the key can't be found with the even parity, we'll try
		// the odd parity.
		case errors.Is(err, address.ErrInternalKeyNotFound):
			internalKey = tapscript.FlipParity(internalKey)

			keyLocator, err = r.cfg.AssetWallet.FetchInternalKeyLocator(
				ctx, internalKey,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching "+
					"internal key: %w", err)
			}

		// For any other error from above, we'll return it to the user.
		case err != nil:
			return nil, fmt.Errorf("error fetching internal key: "+
				"%w", err)
		}

	default:
		return nil, fmt.Errorf("invalid internal key length")
	}

	return &wrpc.QueryInternalKeyResponse{
		InternalKey: marshalKeyDescriptor(keychain.KeyDescriptor{
			PubKey:     internalKey,
			KeyLocator: keyLocator,
		}),
	}, nil
}

// QueryScriptKey returns the full script key descriptor for the given tweaked
// script key.
func (r *rpcServer) QueryScriptKey(ctx context.Context,
	req *wrpc.QueryScriptKeyRequest) (*wrpc.QueryScriptKeyResponse, error) {

	var (
		scriptKey  *btcec.PublicKey
		tweakedKey *asset.TweakedScriptKey
		err        error
	)

	// We allow the user to specify the key either in the 33-byte compressed
	// format or the 32-byte x-only format.
	switch {
	case len(req.TweakedScriptKey) == 33:
		scriptKey, err = btcec.ParsePubKey(req.TweakedScriptKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing script key: %w",
				err)
		}

		tweakedKey, err = r.cfg.AssetWallet.FetchScriptKey(
			ctx, scriptKey,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching script key: %w",
				err)
		}

	case len(req.TweakedScriptKey) == 32:
		scriptKey, err = schnorr.ParsePubKey(req.TweakedScriptKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing script key: %w",
				err)
		}

		tweakedKey, err = r.cfg.AssetWallet.FetchScriptKey(
			ctx, scriptKey,
		)

		// If the key can't be found with the even parity, we'll try
		// the odd parity.
		if errors.Is(err, address.ErrScriptKeyNotFound) {
			scriptKey = tapscript.FlipParity(scriptKey)

			tweakedKey, err = r.cfg.AssetWallet.FetchScriptKey(
				ctx, scriptKey,
			)
		}

		// Return either the original error or the error from the re-try
		// with odd parity.
		if err != nil {
			return nil, fmt.Errorf("error fetching script key: %w",
				err)
		}

	default:
		return nil, fmt.Errorf("invalid script key length")
	}

	return &wrpc.QueryScriptKeyResponse{
		ScriptKey: marshalScriptKey(asset.ScriptKey{
			PubKey:           scriptKey,
			TweakedScriptKey: tweakedKey,
		}),
	}, nil
}

// marshalAddr turns an address into its RPC counterpart.
func marshalAddr(addr *address.Tap,
	db address.Storage) (*taprpc.Addr, error) {

	addrStr, err := addr.EncodeAddress()
	if err != nil {
		return nil, fmt.Errorf("unable to encode addr: %w", err)
	}

	// We can only derive the taproot output if we already know the genesis
	// for this asset, as that's required to make the template asset that
	// will be committed to in the tapscript tree.
	var taprootOutputKey []byte
	assetGroup, err := db.QueryAssetGroup(
		context.Background(), addr.AssetID,
	)
	if err == nil {
		addr.AttachGenesis(*assetGroup.Genesis)

		outputKey, err := addr.TaprootOutputKey()
		if err != nil {
			return nil, fmt.Errorf("error deriving Taproot "+
				"output key: %w", err)
		}

		taprootOutputKey = schnorr.SerializePubKey(outputKey)
	}

	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		addr.TapscriptSibling,
	)
	if err != nil {
		return nil, fmt.Errorf("error encoding tapscript sibling: %w",
			err)
	}

	assetVersion, err := taprpc.MarshalAssetVersion(addr.AssetVersion)
	if err != nil {
		return nil, err
	}

	id := addr.AssetID
	rpcAddr := &taprpc.Addr{
		AssetVersion:     assetVersion,
		Encoded:          addrStr,
		AssetId:          id[:],
		Amount:           addr.Amount,
		ScriptKey:        addr.ScriptKey.SerializeCompressed(),
		InternalKey:      addr.InternalKey.SerializeCompressed(),
		TapscriptSibling: siblingBytes,
		TaprootOutputKey: taprootOutputKey,
		AssetType:        taprpc.AssetType(addr.AssetType()),
		ProofCourierAddr: addr.ProofCourierAddr.String(),
	}

	if addr.GroupKey != nil {
		rpcAddr.GroupKey = addr.GroupKey.SerializeCompressed()
	}

	return rpcAddr, nil
}

// marshalAddrEvent turns an address event into its RPC counterpart.
func marshalAddrEvent(event *address.Event,
	db address.Storage) (*taprpc.AddrEvent, error) {

	rpcAddr, err := marshalAddr(event.Addr.Tap, db)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addr: %w", err)
	}

	rpcStatus, err := marshalAddrEventStatus(event.Status)
	if err != nil {
		return nil, fmt.Errorf("error marshaling status: %w", err)
	}

	return &taprpc.AddrEvent{
		CreationTimeUnixSeconds: uint64(event.CreationTime.Unix()),
		Addr:                    rpcAddr,
		Status:                  rpcStatus,
		Outpoint:                event.Outpoint.String(),
		UtxoAmtSat:              uint64(event.Amt),
		ConfirmationHeight:      event.ConfirmationHeight,
		HasProof:                event.HasProof,
	}, nil
}

// unmarshalAddrEventStatus parses the RPC address event status into the native
// counterpart.
func unmarshalAddrEventStatus(
	rpcStatus taprpc.AddrEventStatus) (address.Status, error) {

	switch rpcStatus {
	case taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED:
		return address.StatusTransactionDetected, nil

	case taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED:
		return address.StatusTransactionConfirmed, nil

	case taprpc.AddrEventStatus_ADDR_EVENT_STATUS_PROOF_RECEIVED:
		return address.StatusProofReceived, nil

	case taprpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED:
		return address.StatusCompleted, nil

	default:
		return 0, fmt.Errorf("unknown address event status <%d>",
			rpcStatus)
	}
}

// marshalAddrEventStatus turns the address event status into the RPC
// counterpart.
func marshalAddrEventStatus(status address.Status) (taprpc.AddrEventStatus,
	error) {

	switch status {
	case address.StatusTransactionDetected:
		return taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED,
			nil

	case address.StatusTransactionConfirmed:
		return taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED,
			nil

	case address.StatusProofReceived:
		return taprpc.AddrEventStatus_ADDR_EVENT_STATUS_PROOF_RECEIVED,
			nil

	case address.StatusCompleted:
		return taprpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED, nil

	default:
		return 0, fmt.Errorf("unknown address event status <%d>",
			status)
	}
}

// SendAsset uses one or multiple passed Taproot Asset address(es) to attempt to
// complete an asset send. The method returns information w.r.t the on chain
// send, as well as the proof file information the receiver needs to fully
// receive the asset.
func (r *rpcServer) SendAsset(_ context.Context,
	req *taprpc.SendAssetRequest) (*taprpc.SendAssetResponse, error) {

	if len(req.TapAddrs) == 0 {
		return nil, fmt.Errorf("at least one addr is required")
	}

	var (
		tapParams = address.ParamsForChain(r.cfg.ChainParams.Name)
		tapAddrs  = make([]*address.Tap, len(req.TapAddrs))
		err       error
	)
	for idx := range req.TapAddrs {
		if req.TapAddrs[idx] == "" {
			return nil, fmt.Errorf("addr %d must be specified", idx)
		}

		tapAddrs[idx], err = address.DecodeAddress(
			req.TapAddrs[idx], &tapParams,
		)
		if err != nil {
			return nil, err
		}

		// Ensure all addrs are of the same asset ID. Within a single
		// transfer (=a single virtual packet), we expect only to have
		// inputs and outputs of the same asset ID. Multiple assets can
		// be moved in a single BTC level anchor output, but the
		// expectation is that they would be in separate virtual
		// packets, one for each asset ID. They would then be merged
		// into the same anchor output in the wallet's
		// AnchorVirtualTransactions call.
		//
		// TODO(guggero): Support creating multiple virtual packets, one
		// for each asset ID when the user wants to send multiple asset
		// IDs at the same time without going through the PSBT flow.
		//
		// TODO(guggero): Revisit after we have a way to send fungible
		// assets with different IDs to an address (non-interactive).
		if idx > 0 {
			if tapAddrs[idx].AssetID != tapAddrs[0].AssetID {
				return nil, fmt.Errorf("all addrs must be of "+
					"the same asset ID %v",
					tapAddrs[0].AssetID)
			}
		}
	}

	feeRate, err := checkFeeRateSanity(req.FeeRate)
	if err != nil {
		return nil, err
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewAddressParcel(feeRate, tapAddrs...),
	)
	if err != nil {
		return nil, err
	}

	parcel, err := marshalOutboundParcel(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling outbound parcel: %w",
			err)
	}

	return &taprpc.SendAssetResponse{
		Transfer: parcel,
	}, nil
}

// BurnAsset burns the given number of units of a given asset by sending them
// to a provably un-spendable script key. Burning means irrevocably destroying
// a certain number of assets, reducing the total supply of the asset. Because
// burning is such a destructive and non-reversible operation, some specific
// values need to be set in the request to avoid accidental burns.
func (r *rpcServer) BurnAsset(ctx context.Context,
	in *taprpc.BurnAssetRequest) (*taprpc.BurnAssetResponse, error) {

	rpcsLog.Debug("Executing asset burn")

	var assetID asset.ID
	switch {
	case len(in.GetAssetId()) > 0:
		copy(assetID[:], in.GetAssetId())

	case len(in.GetAssetIdStr()) > 0:
		assetIDBytes, err := hex.DecodeString(in.GetAssetIdStr())
		if err != nil {
			return nil, fmt.Errorf("error decoding asset ID: %w",
				err)
		}

		copy(assetID[:], assetIDBytes)

	default:
		return nil, fmt.Errorf("asset ID must be specified")
	}

	if in.AmountToBurn == 0 {
		return nil, fmt.Errorf("amount to burn must be specified")
	}
	if in.ConfirmationText != AssetBurnConfirmationText {
		return nil, fmt.Errorf("invalid confirmation text, please " +
			"read API doc and confirm safety measure to avoid " +
			"accidental asset burns")
	}

	var groupKey *btcec.PublicKey
	assetGroup, err := r.cfg.TapAddrBook.QueryAssetGroup(ctx, assetID)
	switch {
	case err == nil && assetGroup.GroupKey != nil:
		// We found the asset group, so we can use the group key to
		// burn the asset.
		groupKey = &assetGroup.GroupPubKey
	case errors.Is(err, address.ErrAssetGroupUnknown):
		// We don't know the asset group, so we'll try to burn the
		// asset using the asset ID only.
		rpcsLog.Debug("Asset group key not found, asset may not be " +
			"part of a group")
	case err != nil:
		return nil, fmt.Errorf("error querying asset group: %w", err)
	}

	var serializedGroupKey []byte
	if groupKey != nil {
		serializedGroupKey = groupKey.SerializeCompressed()
	}

	rpcsLog.Infof("Burning asset (asset_id=%x, group_key=%x, "+
		"burn_amount=%d)", assetID[:], serializedGroupKey,
		in.AmountToBurn)

	fundResp, err := r.cfg.AssetWallet.FundBurn(
		ctx, &tapsend.FundingDescriptor{
			ID:       assetID,
			GroupKey: groupKey,
			Amount:   in.AmountToBurn,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error funding burn: %w", err)
	}

	// Now we can sign the packet and send it to the chain.
	_, err = r.cfg.AssetWallet.SignVirtualPacket(fundResp.VPacket)
	if err != nil {
		return nil, fmt.Errorf("error signing packet: %w", err)
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewPreSignedParcel(
			fundResp.VPacket, fundResp.InputCommitments,
		),
	)
	if err != nil {
		return nil, err
	}

	parcel, err := marshalOutboundParcel(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling outbound parcel: %w",
			err)
	}

	var burnProof *taprpc.DecodedProof
	for idx := range resp.Outputs {
		vOut := fundResp.VPacket.Outputs[idx]
		tOut := resp.Outputs[idx]
		if vOut.Asset.IsBurn() {
			var p proof.Proof
			err = p.Decode(bytes.NewReader(tOut.ProofSuffix))
			if err != nil {
				return nil, fmt.Errorf("error decoding "+
					"burn proof: %w", err)
			}

			burnProof, err = r.marshalProof(ctx, &p, true, false)
			if err != nil {
				return nil, fmt.Errorf("error decoding "+
					"burn proof: %w", err)
			}
		}
	}

	return &taprpc.BurnAssetResponse{
		BurnTransfer: parcel,
		BurnProof:    burnProof,
	}, nil
}

// marshalOutboundParcel turns a pending parcel into its RPC counterpart.
func marshalOutboundParcel(
	parcel *tapfreighter.OutboundParcel) (*taprpc.AssetTransfer,
	error) {

	rpcInputs := make([]*taprpc.TransferInput, len(parcel.Inputs))
	for idx := range parcel.Inputs {
		in := parcel.Inputs[idx]
		rpcInputs[idx] = &taprpc.TransferInput{
			AnchorPoint: in.OutPoint.String(),
			AssetId:     in.ID[:],
			ScriptKey:   in.ScriptKey[:],
			Amount:      in.Amount,
		}
	}

	rpcOutputs := make(
		[]*taprpc.TransferOutput, len(parcel.Outputs),
	)
	for idx := range parcel.Outputs {
		out := parcel.Outputs[idx]

		internalPubKey := out.Anchor.InternalKey.PubKey
		internalKeyBytes := internalPubKey.SerializeCompressed()
		rpcAnchor := &taprpc.TransferOutputAnchor{
			Outpoint:         out.Anchor.OutPoint.String(),
			Value:            int64(out.Anchor.Value),
			InternalKey:      internalKeyBytes,
			TaprootAssetRoot: out.Anchor.TaprootAssetRoot[:],
			MerkleRoot:       out.Anchor.MerkleRoot[:],
			TapscriptSibling: out.Anchor.TapscriptSibling,
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

		rpcOutType, err := marshalOutputType(out.Type)
		if err != nil {
			return nil, err
		}

		assetVersion, err := taprpc.MarshalAssetVersion(
			out.AssetVersion,
		)
		if err != nil {
			return nil, err
		}

		rpcOutputs[idx] = &taprpc.TransferOutput{
			Anchor:              rpcAnchor,
			ScriptKey:           scriptPubKey.SerializeCompressed(),
			ScriptKeyIsLocal:    out.ScriptKeyLocal,
			Amount:              out.Amount,
			NewProofBlob:        out.ProofSuffix,
			SplitCommitRootHash: splitCommitRoot,
			OutputType:          rpcOutType,
			AssetVersion:        assetVersion,
		}
	}

	anchorTxHash := parcel.AnchorTx.TxHash()
	return &taprpc.AssetTransfer{
		TransferTimestamp:  parcel.TransferTime.Unix(),
		AnchorTxHash:       anchorTxHash[:],
		AnchorTxHeightHint: parcel.AnchorTxHeightHint,
		AnchorTxChainFees:  parcel.ChainFees,
		Inputs:             rpcInputs,
		Outputs:            rpcOutputs,
	}, nil
}

// marshalOutputType turns the transfer output type into the RPC counterpart.
func marshalOutputType(outputType tappsbt.VOutputType) (taprpc.OutputType,
	error) {

	switch outputType {
	case tappsbt.TypeSimple:
		return taprpc.OutputType_OUTPUT_TYPE_SIMPLE, nil

	case tappsbt.TypeSplitRoot:
		return taprpc.OutputType_OUTPUT_TYPE_SPLIT_ROOT, nil

	default:
		return 0, fmt.Errorf("unknown output type: %d", outputType)
	}
}

// SubscribeSendAssetEventNtfns registers a subscription to the event
// notification stream which relates to the asset sending process.
func (r *rpcServer) SubscribeSendAssetEventNtfns(
	_ *taprpc.SubscribeSendAssetEventNtfnsRequest,
	ntfnStream subSendEventNtfnsStream) error {

	// Create a new event subscriber and pass a copy to the chain porter.
	// We will then read events from the subscriber.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	// Register the subscriber with the ChainPorter.
	err := r.cfg.ChainPorter.RegisterSubscriber(
		eventSubscriber, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to register chain porter event "+
			"notifications subscription: %w", err)
	}

	// Loop and read from the event subscription and forward to the RPC
	// stream.
	for {
		select {
		// Handle receiving a new event from the ChainPorter.
		// The event will be mapped to the RPC event type and
		// sent over the stream.
		case event := <-eventSubscriber.NewItemCreated.ChanOut():

			rpcEvent, err := marshallSendAssetEvent(event)
			if err != nil {
				return fmt.Errorf("failed to marshall asset "+
					"send event into RPC event: %w", err)
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

// SubscribeReceiveAssetEventNtfns registers a subscription to the event
// notification stream which relates to the asset receiving process.
func (r *rpcServer) SubscribeReceiveAssetEventNtfns(
	_ *taprpc.SubscribeReceiveAssetEventNtfnsRequest,
	ntfnStream subReceiveEventNtfnsStream) error {

	// Create a new event subscriber and pass a copy to the component(s)
	// which are involved in the asset receive process. We will then read
	// events from the subscriber.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	// Register the subscriber with the AssetCustodian.
	err := r.cfg.AssetCustodian.RegisterSubscriber(
		eventSubscriber, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to register custodian event"+
			"notifications subscription: %w", err)
	}

	// Loop and read from the event subscription and forward to the RPC
	// stream.
	for {
		select {
		// Handle receiving a new event. The event will be mapped to the
		// RPC event type and sent over the stream.
		case event := <-eventSubscriber.NewItemCreated.ChanOut():

			rpcEvent, err := marshallReceiveAssetEvent(
				event, r.cfg.TapAddrBook,
			)
			if err != nil {
				return fmt.Errorf("failed to marshall "+
					"asset receive event into RPC event: "+
					"%w", err)
			}

			err = ntfnStream.Send(rpcEvent)
			if err != nil {
				return fmt.Errorf("failed to RPC stream "+
					"asset receive event: %w", err)
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

// marshallReceiveAssetEvent maps an asset receive event to its RPC counterpart.
func marshallReceiveAssetEvent(eventInterface fn.Event,
	db address.Storage) (*taprpc.ReceiveAssetEvent, error) {

	switch event := eventInterface.(type) {
	case *proof.BackoffWaitEvent:
		// Map the transfer type to the RPC counterpart. We only
		// support the "receive" transfer type for asset receive events.
		var transferTypeRpc taprpc.ProofTransferType
		switch event.TransferType {
		case proof.ReceiveTransferType:
			transferTypeRpc = taprpc.ProofTransferType_PROOF_TRANSFER_TYPE_RECEIVE
		default:
			return nil, fmt.Errorf("unexpected transfer type: %v",
				event.TransferType)
		}

		eventRpc := taprpc.ReceiveAssetEvent_ProofTransferBackoffWaitEvent{
			ProofTransferBackoffWaitEvent: &taprpc.ProofTransferBackoffWaitEvent{
				Timestamp:    event.Timestamp().UnixMicro(),
				Backoff:      event.Backoff.Microseconds(),
				TriesCounter: event.TriesCounter,
				TransferType: transferTypeRpc,
			},
		}
		return &taprpc.ReceiveAssetEvent{
			Event: &eventRpc,
		}, nil

	case *tapgarden.AssetReceiveCompleteEvent:
		rpcAddr, err := marshalAddr(&event.Address, db)
		if err != nil {
			return nil, fmt.Errorf("error marshaling addr: %w", err)
		}

		eventRpc := taprpc.ReceiveAssetEvent_AssetReceiveCompleteEvent{
			AssetReceiveCompleteEvent: &taprpc.AssetReceiveCompleteEvent{
				Timestamp: event.Timestamp().UnixMicro(),
				Address:   rpcAddr,
				Outpoint:  event.OutPoint.String(),
			},
		}
		return &taprpc.ReceiveAssetEvent{
			Event: &eventRpc,
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %T", eventInterface)
	}
}

// marshallSendAssetEvent maps an asset send event to its RPC counterpart.
func marshallSendAssetEvent(
	eventInterface fn.Event) (*taprpc.SendAssetEvent, error) {

	switch event := eventInterface.(type) {
	case *tapfreighter.ExecuteSendStateEvent:
		eventRpc := &taprpc.SendAssetEvent_ExecuteSendStateEvent{
			ExecuteSendStateEvent: &taprpc.ExecuteSendStateEvent{
				Timestamp: event.Timestamp().UnixMicro(),
				SendState: event.SendState.String(),
			},
		}
		return &taprpc.SendAssetEvent{
			Event: eventRpc,
		}, nil

	case *proof.BackoffWaitEvent:
		// Map the transfer type to the RPC counterpart. We only
		// support the send transfer type for asset send events.
		var transferTypeRpc taprpc.ProofTransferType
		switch event.TransferType {
		case proof.SendTransferType:
			transferTypeRpc = taprpc.ProofTransferType_PROOF_TRANSFER_TYPE_SEND
		default:
			return nil, fmt.Errorf("unexpected transfer type: %v",
				event.TransferType)
		}

		eventRpc := taprpc.SendAssetEvent_ProofTransferBackoffWaitEvent{
			ProofTransferBackoffWaitEvent: &taprpc.ProofTransferBackoffWaitEvent{
				Timestamp:    event.Timestamp().UnixMicro(),
				Backoff:      event.Backoff.Microseconds(),
				TriesCounter: event.TriesCounter,
				TransferType: transferTypeRpc,
			},
		}
		return &taprpc.SendAssetEvent{
			Event: &eventRpc,
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %T", eventInterface)
	}
}

// marshalMintingBatch marshals a minting batch into the RPC counterpart.
func marshalMintingBatch(batch *tapgarden.MintingBatch,
	skipSeedlings bool) (*mintrpc.MintingBatch, error) {

	rpcBatchState, err := marshalBatchState(batch)
	if err != nil {
		return nil, err
	}

	rpcBatch := &mintrpc.MintingBatch{
		BatchKey: batch.BatchKey.PubKey.SerializeCompressed(),
		State:    rpcBatchState,
	}

	// If we have the genesis packet available (funded+signed), then we'll
	// display the txid as well.
	if batch.GenesisPacket != nil {
		batchTx, err := psbt.Extract(batch.GenesisPacket.Pkt)
		if err == nil {
			rpcBatch.BatchTxid = batchTx.TxHash().String()
		} else {
			rpcsLog.Errorf("unable to extract batch tx: %v", err)
		}
	}

	// If we don't need to include the seedlings, we can return here.
	if skipSeedlings {
		return rpcBatch, nil
	}

	// When we have sprouts, then they represent the same assets as the
	// seedlings but in a more "grown up" state. So in that case we only
	// marshal the sprouts.
	switch {
	// We have sprouts, ignore seedlings.
	case batch.RootAssetCommitment != nil &&
		len(batch.RootAssetCommitment.CommittedAssets()) > 0:

		rpcBatch.Assets = marshalSprouts(
			batch.RootAssetCommitment.CommittedAssets(),
			batch.AssetMetas,
		)

	// No sprouts, so we marshal the seedlings.
	case len(batch.Seedlings) > 0:
		rpcBatch.Assets, err = marshalSeedlings(batch.Seedlings)
		if err != nil {
			return nil, err
		}
	}

	return rpcBatch, nil
}

// marshalSeedlings marshals the seedlings into the RPC counterpart.
func marshalSeedlings(
	seedlings map[string]*tapgarden.Seedling) ([]*mintrpc.PendingAsset,
	error) {

	rpcAssets := make([]*mintrpc.PendingAsset, 0, len(seedlings))
	for _, seedling := range seedlings {
		var groupKeyBytes []byte
		if seedling.HasGroupKey() {
			groupKey := seedling.GroupInfo.GroupKey
			groupPubKey := groupKey.GroupPubKey
			groupKeyBytes = groupPubKey.SerializeCompressed()
		}

		var groupAnchor string
		if seedling.GroupAnchor != nil {
			groupAnchor = *seedling.GroupAnchor
		}

		var seedlingMeta *taprpc.AssetMeta
		if seedling.Meta != nil {
			seedlingMeta = &taprpc.AssetMeta{
				MetaHash: fn.ByteSlice(
					seedling.Meta.MetaHash(),
				),
				Data: seedling.Meta.Data,
				Type: taprpc.AssetMetaType(seedling.Meta.Type),
			}
		}

		assetVersion, err := taprpc.MarshalAssetVersion(
			seedling.AssetVersion,
		)
		if err != nil {
			return nil, err
		}

		nextSeedling := &mintrpc.PendingAsset{
			AssetType:    taprpc.AssetType(seedling.AssetType),
			AssetVersion: assetVersion,
			Name:         seedling.AssetName,
			AssetMeta:    seedlingMeta,
			Amount:       seedling.Amount,
			GroupKey:     groupKeyBytes,
			GroupAnchor:  groupAnchor,
		}

		if seedling.EnableEmission {
			nextSeedling.NewGroupedAsset = true
		}

		rpcAssets = append(rpcAssets, nextSeedling)
	}

	return rpcAssets, nil
}

// marshalSprouts marshals the sprouts into the RPC counterpart.
func marshalSprouts(sprouts []*asset.Asset,
	metas tapgarden.AssetMetas) []*mintrpc.PendingAsset {

	rpcAssets := make([]*mintrpc.PendingAsset, 0, len(sprouts))
	for _, sprout := range sprouts {
		scriptKey := asset.ToSerialized(sprout.ScriptKey.PubKey)

		var assetMeta *taprpc.AssetMeta
		if metas != nil {
			if m, ok := metas[scriptKey]; ok && m != nil {
				assetMeta = &taprpc.AssetMeta{
					MetaHash: fn.ByteSlice(m.MetaHash()),
					Data:     m.Data,
					Type:     taprpc.AssetMetaType(m.Type),
				}
			}
		}

		var groupKeyBytes []byte
		if sprout.GroupKey != nil {
			gpk := sprout.GroupKey.GroupPubKey
			groupKeyBytes = gpk.SerializeCompressed()
		}

		rpcAssets = append(rpcAssets, &mintrpc.PendingAsset{
			AssetType: taprpc.AssetType(sprout.Type),
			Name:      sprout.Tag,
			AssetMeta: assetMeta,
			Amount:    sprout.Amount,
			GroupKey:  groupKeyBytes,
		})
	}

	return rpcAssets
}

// marshalBatchState converts the batch state field into its RPC counterpart.
func marshalBatchState(batch *tapgarden.MintingBatch) (mintrpc.BatchState,
	error) {

	currentBatchState := batch.State()

	switch currentBatchState {
	case tapgarden.BatchStatePending:
		return mintrpc.BatchState_BATCH_STATE_PENDING, nil

	case tapgarden.BatchStateFrozen:
		return mintrpc.BatchState_BATCH_STATE_FROZEN, nil

	case tapgarden.BatchStateCommitted:
		return mintrpc.BatchState_BATCH_STATE_COMMITTED, nil

	case tapgarden.BatchStateBroadcast:
		return mintrpc.BatchState_BATCH_STATE_BROADCAST, nil

	case tapgarden.BatchStateConfirmed:
		return mintrpc.BatchState_BATCH_STATE_CONFIRMED, nil

	case tapgarden.BatchStateFinalized:
		return mintrpc.BatchState_BATCH_STATE_FINALIZED, nil

	case tapgarden.BatchStateSeedlingCancelled:
		return mintrpc.BatchState_BATCH_STATE_SEEDLING_CANCELLED, nil

	case tapgarden.BatchStateSproutCancelled:
		return mintrpc.BatchState_BATCH_STATE_SPROUT_CANCELLED, nil

	default:
		return 0, fmt.Errorf("unknown batch state: %v",
			currentBatchState.String())
	}
}

func marshalTapscriptFullTree(tree *taprpc.TapscriptFullTree) (
	*asset.TapscriptTreeNodes, error) {

	rpcLeaves := tree.GetAllLeaves()
	leaves := fn.Map(rpcLeaves, func(l *taprpc.TapLeaf) txscript.TapLeaf {
		return txscript.NewBaseTapLeaf(l.Script)
	})

	return asset.TapTreeNodesFromLeaves(leaves)
}

func marshalTapscriptBranch(branch *taprpc.TapBranch) (*asset.TapscriptTreeNodes,
	error) {

	branchData := [][]byte{branch.LeftTaphash, branch.RightTaphash}
	tapBranch, err := asset.DecodeTapBranchNodes(branchData)
	if err != nil {
		return nil, err
	}

	return fn.Ptr(asset.FromBranch(*tapBranch)), nil
}

// UnmarshalScriptKey parses the RPC script key into the native counterpart.
func UnmarshalScriptKey(rpcKey *taprpc.ScriptKey) (*asset.ScriptKey, error) {
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
			// is derived using BIP-0086.
			Tweak: rpcKey.TapTweak,
		}
	}

	return &scriptKey, nil
}

// marshalScriptKey marshals the native script key into the RPC counterpart.
func marshalScriptKey(scriptKey asset.ScriptKey) *taprpc.ScriptKey {
	rpcScriptKey := &taprpc.ScriptKey{
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

// parseUserKey parses a user-provided script or group key, which can be in
// either the Schnorr or Compressed format.
func parseUserKey(scriptKey []byte) (*btcec.PublicKey, error) {
	switch len(scriptKey) {
	case schnorr.PubKeyBytesLen:
		return schnorr.ParsePubKey(scriptKey)

	// Truncate the key and then parse as a Schnorr key.
	case btcec.PubKeyBytesLenCompressed:
		return schnorr.ParsePubKey(scriptKey[1:])

	default:
		return nil, fmt.Errorf("unknown script key length: %v",
			len(scriptKey))
	}
}

// marshalKeyDescriptor marshals the native key descriptor into the RPC
// counterpart.
func marshalKeyDescriptor(desc keychain.KeyDescriptor) *taprpc.KeyDescriptor {
	return &taprpc.KeyDescriptor{
		RawKeyBytes: desc.PubKey.SerializeCompressed(),
		KeyLoc: &taprpc.KeyLocator{
			KeyFamily: int32(desc.KeyLocator.Family),
			KeyIndex:  int32(desc.KeyLocator.Index),
		},
	}
}

// UnmarshalKeyDescriptor parses the RPC key descriptor into the native
// counterpart.
func UnmarshalKeyDescriptor(
	rpcDesc *taprpc.KeyDescriptor) (keychain.KeyDescriptor, error) {

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
	req *taprpc.FetchAssetMetaRequest) (*taprpc.AssetMeta, error) {

	var (
		assetMeta *proof.MetaReveal
		err       error
	)

	switch {
	case req.GetAssetId() != nil:
		if len(req.GetAssetId()) != sha256.Size {
			return nil, fmt.Errorf("asset ID must be 32 bytes")
		}

		var assetID asset.ID
		copy(assetID[:], req.GetAssetId())

		assetMeta, err = r.cfg.AssetStore.FetchAssetMetaForAsset(
			ctx, assetID,
		)

	case req.GetAssetIdStr() != "":
		if len(req.GetAssetIdStr()) != hex.EncodedLen(sha256.Size) {
			return nil, fmt.Errorf("asset ID must be 32 bytes")
		}

		var assetIDBytes []byte
		assetIDBytes, err = hex.DecodeString(req.GetAssetIdStr())
		if err != nil {
			return nil, fmt.Errorf("error hex decoding asset ID: "+
				"%w", err)
		}

		var assetID asset.ID
		copy(assetID[:], assetIDBytes)

		assetMeta, err = r.cfg.AssetStore.FetchAssetMetaForAsset(
			ctx, assetID,
		)

	case req.GetMetaHash() != nil:
		if len(req.GetMetaHash()) != sha256.Size {
			return nil, fmt.Errorf("meta hash must be 32 bytes")
		}

		var metaHash [asset.MetaHashLen]byte
		copy(metaHash[:], req.GetMetaHash())

		assetMeta, err = r.cfg.AssetStore.FetchAssetMetaByHash(
			ctx, metaHash,
		)

	case req.GetMetaHashStr() != "":
		if len(req.GetMetaHashStr()) != hex.EncodedLen(sha256.Size) {
			return nil, fmt.Errorf("meta hash must be 32 bytes")
		}

		var metaHashBytes []byte
		metaHashBytes, err = hex.DecodeString(req.GetMetaHashStr())
		if err != nil {
			return nil, fmt.Errorf("error hex decoding meta hash: "+
				"%w", err)
		}

		var metaHash [asset.MetaHashLen]byte
		copy(metaHash[:], metaHashBytes)

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
	return &taprpc.AssetMeta{
		Data:     assetMeta.Data,
		Type:     taprpc.AssetMetaType(assetMeta.Type),
		MetaHash: metaHash[:],
	}, nil
}

// MarshalUniProofType marshals the universe proof type into the RPC
// counterpart.
func MarshalUniProofType(
	proofType universe.ProofType) (unirpc.ProofType, error) {

	switch proofType {
	case universe.ProofTypeUnspecified:
		return unirpc.ProofType_PROOF_TYPE_UNSPECIFIED, nil
	case universe.ProofTypeIssuance:
		return unirpc.ProofType_PROOF_TYPE_ISSUANCE, nil
	case universe.ProofTypeTransfer:
		return unirpc.ProofType_PROOF_TYPE_TRANSFER, nil

	default:
		return 0, fmt.Errorf("unknown universe proof type: %v",
			proofType)
	}
}

// MarshalUniID marshals the universe ID into the RPC counterpart.
func MarshalUniID(id universe.Identifier) (*unirpc.ID, error) {
	var uniID unirpc.ID

	if id.GroupKey != nil {
		uniID.Id = &unirpc.ID_GroupKey{
			GroupKey: schnorr.SerializePubKey(id.GroupKey),
		}
	} else {
		uniID.Id = &unirpc.ID_AssetId{
			AssetId: id.AssetID[:],
		}
	}

	proofTypeRpc, err := MarshalUniProofType(id.ProofType)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal proof type: %w", err)
	}
	uniID.ProofType = proofTypeRpc

	return &uniID, nil
}

// marshalMssmtNode marshals a MS-SMT node into the RPC counterpart.
func marshalMssmtNode(node mssmt.Node) *unirpc.MerkleSumNode {
	nodeHash := node.NodeHash()

	return &unirpc.MerkleSumNode{
		RootHash: nodeHash[:],
		RootSum:  int64(node.NodeSum()),
	}
}

// marshallUniverseRoot marshals the universe root into the RPC counterpart.
func marshalUniverseRoot(node universe.Root) (*unirpc.UniverseRoot, error) {
	// There was no old base root, so we'll just return a blank root.
	if node.Node == nil {
		return &unirpc.UniverseRoot{}, nil
	}
	mssmtRoot := marshalMssmtNode(node.Node)

	rpcGroupedAssets := make(map[string]uint64, len(node.GroupedAssets))
	for assetID, amount := range node.GroupedAssets {
		rpcGroupedAssets[assetID.String()] = amount
	}

	uniID, err := MarshalUniID(node.ID)
	if err != nil {
		return nil, err
	}

	return &unirpc.UniverseRoot{
		Id:               uniID,
		MssmtRoot:        mssmtRoot,
		AssetName:        node.AssetName,
		AmountsByAssetId: rpcGroupedAssets,
	}, nil
}

// MultiverseRoot returns the root of the multiverse tree. This is useful to
// determine the equality of two multiverse trees, since the root can directly
// be compared to another multiverse root to find out if a sync is required.
func (r *rpcServer) MultiverseRoot(ctx context.Context,
	req *unirpc.MultiverseRootRequest) (*unirpc.MultiverseRootResponse,
	error) {

	proofType, err := UnmarshalUniProofType(req.ProofType)
	if err != nil {
		return nil, fmt.Errorf("invalid proof type: %w", err)
	}

	if proofType == universe.ProofTypeUnspecified {
		return nil, fmt.Errorf("proof type must be specified")
	}

	filterByIDs := make([]universe.Identifier, len(req.SpecificIds))
	for idx, rpcID := range req.SpecificIds {
		filterByIDs[idx], err = UnmarshalUniID(rpcID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse universe id: "+
				"%w", err)
		}

		// Allow the RPC user to not specify the proof type for each ID
		// individually since the outer one is mandatory.
		if filterByIDs[idx].ProofType == universe.ProofTypeUnspecified {
			filterByIDs[idx].ProofType = proofType
		}

		if filterByIDs[idx].ProofType != proofType {
			return nil, fmt.Errorf("proof type mismatch in ID "+
				"%d: %v != %v", idx, filterByIDs[idx].ProofType,
				proofType)
		}
	}

	rootNode, err := r.cfg.UniverseArchive.MultiverseRoot(
		ctx, proofType, filterByIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch multiverse root: %w",
			err)
	}

	var resp unirpc.MultiverseRootResponse
	rootNode.WhenSome(func(node universe.MultiverseRoot) {
		resp.MultiverseRoot = marshalMssmtNode(node)
	})

	return &resp, nil
}

// AssetRoots queries for the known Universe roots associated with each known
// asset. These roots represent the supply/audit state for each known asset.
func (r *rpcServer) AssetRoots(ctx context.Context,
	req *unirpc.AssetRootRequest) (*unirpc.AssetRootResponse, error) {

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err := r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// First, we'll retrieve the full set of known asset Universe roots.
	assetRoots, err := r.cfg.UniverseArchive.RootNodes(
		ctx, universe.RootNodesQuery{
			WithAmountsById: req.WithAmountsById,
			SortDirection:   universe.SortDirection(req.Direction),
			Offset:          req.Offset,
			Limit:           req.Limit,
		},
	)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetRootResponse{
		UniverseRoots: make(map[string]*unirpc.UniverseRoot),
	}

	// Retrieve config for use in filtering asset roots based on sync export
	// settings.
	syncConfigs, err := r.cfg.UniverseFederation.QuerySyncConfigs(ctx)
	if err != nil {
		return nil, err
	}

	// For each universe root, marshal it into the RPC form, taking care to
	// specify the proper universe ID.
	for _, assetRoot := range assetRoots {
		idStr := assetRoot.ID.String()

		// Skip this asset if it's not configured for sync export.
		if !syncConfigs.IsSyncExportEnabled(assetRoot.ID) {
			continue
		}

		resp.UniverseRoots[idStr], err = marshalUniverseRoot(assetRoot)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// UnmarshalUniProofType parses the RPC universe proof type into the native
// counterpart.
func UnmarshalUniProofType(rpcType unirpc.ProofType) (universe.ProofType,
	error) {

	switch rpcType {
	case unirpc.ProofType_PROOF_TYPE_UNSPECIFIED:
		return universe.ProofTypeUnspecified, nil

	case unirpc.ProofType_PROOF_TYPE_ISSUANCE:
		return universe.ProofTypeIssuance, nil

	case unirpc.ProofType_PROOF_TYPE_TRANSFER:
		return universe.ProofTypeTransfer, nil

	default:
		return 0, fmt.Errorf("unknown universe proof type: %v", rpcType)
	}
}

// unmarshalAssetSyncConfig parses the RPC asset sync config into the native
// counterpart.
func unmarshalAssetSyncConfig(
	config *unirpc.AssetFederationSyncConfig) (*universe.FedUniSyncConfig,
	error) {

	if config == nil {
		return nil, fmt.Errorf("empty universe sync config")
	}

	// Parse the universe ID from the RPC form.
	uniID, err := UnmarshalUniID(config.Id)
	if err != nil {
		return nil, fmt.Errorf("unable to parse universe id: %w",
			err)
	}

	return &universe.FedUniSyncConfig{
		UniverseID:      uniID,
		AllowSyncInsert: config.AllowSyncInsert,
		AllowSyncExport: config.AllowSyncExport,
	}, nil
}

// UnmarshalUniID parses the RPC universe ID into the native counterpart.
func UnmarshalUniID(rpcID *unirpc.ID) (universe.Identifier, error) {
	if rpcID == nil {
		return universe.Identifier{}, fmt.Errorf("missing universe id")
	}

	// Unmarshal the proof type.
	proofType, err := UnmarshalUniProofType(rpcID.ProofType)
	if err != nil {
		return universe.Identifier{}, fmt.Errorf("unable to unmarshal "+
			"proof type: %w", err)
	}
	switch {
	case rpcID.GetAssetId() != nil:
		var assetID asset.ID
		copy(assetID[:], rpcID.GetAssetId())

		return universe.Identifier{
			AssetID:   assetID,
			ProofType: proofType,
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
			AssetID:   assetID,
			ProofType: proofType,
		}, nil

	case rpcID.GetGroupKey() != nil:
		groupKey, err := parseUserKey(rpcID.GetGroupKey())
		if err != nil {
			return universe.Identifier{}, err
		}

		return universe.Identifier{
			GroupKey:  groupKey,
			ProofType: proofType,
		}, nil

	case rpcID.GetGroupKeyStr() != "":
		groupKeyBytes, err := hex.DecodeString(rpcID.GetGroupKeyStr())
		if err != nil {
			return universe.Identifier{}, err
		}

		// TODO(roasbeef): reuse with above

		groupKey, err := parseUserKey(groupKeyBytes)
		if err != nil {
			return universe.Identifier{}, err
		}

		return universe.Identifier{
			GroupKey:  groupKey,
			ProofType: proofType,
		}, nil

	default:
		return universe.Identifier{}, fmt.Errorf("no id set")
	}
}

// QueryAssetRoots attempts to locate the current Universe root for a specific
// asset. This asset can be identified by its asset ID or group key.
func (r *rpcServer) QueryAssetRoots(ctx context.Context,
	req *unirpc.AssetRootQuery) (*unirpc.QueryRootResponse, error) {

	universeID, err := UnmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}

	// Attempt to retrieve the issuance universe root.
	rpcsLog.Debugf("Querying for asset (group) issuance universe root "+
		"for %v", spew.Sdump(universeID))

	universeID.ProofType = universe.ProofTypeIssuance

	// Ensure proof export is enabled for the given universe.
	syncConfigs, err := r.cfg.UniverseFederation.QuerySyncConfigs(ctx)
	if err != nil {
		return nil, err
	}

	if !syncConfigs.IsSyncExportEnabled(universeID) {
		return nil, fmt.Errorf("proof export is disabled for the " +
			"given universe")
	}

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err = r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Query for both a issaunce and transfer universe root.
	assetRoots, err := r.queryAssetProofRoots(ctx, universeID)
	if err != nil {
		return nil, err
	}

	// If no roots were found and the universe ID had no group key, the
	// asset may be a grouped asset.
	mayBeGrouped := assetRoots.IssuanceRoot.Id == nil &&
		assetRoots.TransferRoot.Id == nil && universeID.GroupKey == nil

	// We already found some universe roots, or the original
	// request was for an asset group. Return the roots we have.
	if !mayBeGrouped {
		return assetRoots, nil
	}

	// Query for a matching asset group, and fetch the matching universe
	// roots if we find a group.
	groupedAssetID := universeID.AssetID
	rpcsLog.Debugf("No roots found for asset %v, checking if this "+
		"asset is part of a group", groupedAssetID.String())

	assetGroup, err := r.cfg.TapAddrBook.QueryAssetGroup(
		ctx, groupedAssetID,
	)

	switch {
	// No asset info was found; we will return empty universe roots.
	case errors.Is(err, address.ErrAssetGroupUnknown):
		return assetRoots, nil

	case err != nil:
		return nil, fmt.Errorf("asset group lookup failed: %w",
			err)

	// We found the correct group for this asset; fetch the universe
	// roots for the group.
	case assetGroup.GroupKey != nil:
		foundGroupKey := &assetGroup.GroupPubKey
		groupUniID := universe.Identifier{
			GroupKey:  foundGroupKey,
			ProofType: universe.ProofTypeIssuance,
		}

		rpcsLog.Debugf("Found group %x for asset %v",
			foundGroupKey.SerializeCompressed(),
			groupedAssetID.String())

		assetRoots, err = r.queryAssetProofRoots(ctx, groupUniID)
		if err != nil {
			return nil, err
		}

		return assetRoots, nil

	// The asset has no group; we will return empty universe roots.
	default:
		return assetRoots, nil
	}
}

// queryAssetProofRoots attempts to locate the current Universe root for a
// specific asset, for both proof types. The asset can be identified by its
// asset ID or group key.
func (r *rpcServer) queryAssetProofRoots(ctx context.Context,
	id universe.Identifier) (*unirpc.QueryRootResponse, error) {

	var issuanceRootRPC, transferRootRPC *unirpc.UniverseRoot
	uniID := id

	issuanceRoot, issuanceErr := r.cfg.UniverseArchive.RootNode(ctx, uniID)
	if issuanceErr != nil {
		// Do not return at this point if the error only indicates that
		// the root wasn't found. We'll try to find the transfer root
		// below.
		if !errors.Is(issuanceErr, universe.ErrNoUniverseRoot) {
			return nil, issuanceErr
		}
	}

	issuanceRootRPC, err := marshalUniverseRoot(issuanceRoot)
	if err != nil {
		return nil, err
	}

	// Attempt to retrieve the transfer universe root.
	rpcsLog.Debugf("Querying for asset (group) transfer universe root "+
		"for %v", spew.Sdump(uniID))

	uniID.ProofType = universe.ProofTypeTransfer

	transferRoot, transferErr := r.cfg.UniverseArchive.RootNode(ctx, uniID)
	if transferErr != nil {
		// Do not return at this point if the error only indicates that
		// the root wasn't found. We may have found the issuance root
		// above.
		if !errors.Is(transferErr, universe.ErrNoUniverseRoot) {
			return nil, transferErr
		}
	}

	transferRootRPC, err = marshalUniverseRoot(transferRoot)
	if err != nil {
		return nil, err
	}

	return &unirpc.QueryRootResponse{
		IssuanceRoot: issuanceRootRPC,
		TransferRoot: transferRootRPC,
	}, nil
}

// DeleteAssetRoot attempts to locate the current Universe root for a specific
// asset, and deletes the associated Universe tree if found.
func (r *rpcServer) DeleteAssetRoot(ctx context.Context,
	req *unirpc.DeleteRootQuery) (*unirpc.DeleteRootResponse, error) {

	universeID, err := UnmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}

	rpcsLog.Debugf("Deleting asset root for %v", spew.Sdump(universeID))

	// If the universe proof type is unspecified, we'll delete both the
	// issuance and transfer roots.
	if universeID.ProofType == universe.ProofTypeUnspecified {
		universeID.ProofType = universe.ProofTypeIssuance
		_, err = r.cfg.UniverseArchive.DeleteRoot(ctx, universeID)
		if err != nil {
			return nil, err
		}

		universeID.ProofType = universe.ProofTypeTransfer
		_, err = r.cfg.UniverseArchive.DeleteRoot(ctx, universeID)
		if err != nil {
			return nil, err
		}

		return &unirpc.DeleteRootResponse{}, nil
	}

	// At this point the universe proof type was specified, so we'll only
	// delete the root for that proof type.
	_, err = r.cfg.UniverseArchive.DeleteRoot(ctx, universeID)
	if err != nil {
		return nil, err
	}

	return &unirpc.DeleteRootResponse{}, nil
}

func marshalLeafKey(leafKey universe.LeafKey) *unirpc.AssetKey {
	return &unirpc.AssetKey{
		Outpoint: &unirpc.AssetKey_OpStr{
			OpStr: leafKey.OutPoint.String(),
		},
		ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
			ScriptKeyBytes: schnorr.SerializePubKey(
				leafKey.ScriptKey.PubKey,
			),
		},
	}
}

// AssetLeafKeys queries for the set of Universe keys associated with a given
// asset_id or group_key. Each key takes the form: (outpoint, script_key),
// where outpoint is an outpoint in the Bitcoin blockchain that anchors a valid
// Taproot Asset commitment, and script_key is the script_key of the asset
// within the Taproot Asset commitment for the given asset_id or group_key.
func (r *rpcServer) AssetLeafKeys(ctx context.Context,
	req *unirpc.AssetLeafKeysRequest) (*unirpc.AssetLeafKeyResponse, error) {

	if req == nil {
		return nil, fmt.Errorf("request must be set")
	}

	universeID, err := UnmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}

	// If the proof type wasn't specified, then we'll return an error as we
	// don't know which keys to actually fetch.
	if universeID.ProofType == universe.ProofTypeUnspecified {
		return nil, fmt.Errorf("proof type must be specified")
	}

	if req.Limit > universe.MaxPageSize || req.Limit < 0 {
		return nil, fmt.Errorf("invalid request limit")
	}

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err = r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	leafKeys, err := r.cfg.UniverseArchive.UniverseLeafKeys(
		ctx, universe.UniverseLeafKeysQuery{
			Id:            universeID,
			SortDirection: universe.SortDirection(req.Direction),
			Offset:        req.Offset,
			Limit:         req.Limit,
		},
	)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetLeafKeyResponse{
		AssetKeys: make([]*unirpc.AssetKey, len(leafKeys)),
	}

	for i, leafKey := range leafKeys {
		resp.AssetKeys[i] = marshalLeafKey(leafKey)
	}

	return resp, nil
}

func marshalAssetLeaf(ctx context.Context, keys taprpc.KeyLookup,
	assetLeaf *universe.Leaf) (*unirpc.AssetLeaf, error) {

	rpcAsset, err := taprpc.MarshalAsset(
		ctx, assetLeaf.Asset, false, true, keys,
	)
	if err != nil {
		return nil, err
	}

	return &unirpc.AssetLeaf{
		Asset: rpcAsset,
		Proof: assetLeaf.RawProof,
	}, nil
}

// marshalAssetLeaf marshals an asset leaf into the RPC form.
func (r *rpcServer) marshalAssetLeaf(ctx context.Context,
	assetLeaf *universe.Leaf) (*unirpc.AssetLeaf, error) {

	return marshalAssetLeaf(ctx, r.cfg.AddrBook, assetLeaf)
}

// AssetLeaves queries for the set of asset leaves (the values in the Universe
// MS-SMT tree) for a given asset_id or group_key. These represents either
// asset issuance events (they have a genesis witness) or asset transfers that
// took place on chain. The leaves contain a normal Taproot asset proof, as well
// as details for the asset.
func (r *rpcServer) AssetLeaves(ctx context.Context,
	req *unirpc.ID) (*unirpc.AssetLeafResponse, error) {

	universeID, err := UnmarshalUniID(req)
	if err != nil {
		return nil, err
	}

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err = r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	assetLeaves, err := r.cfg.UniverseArchive.MintingLeaves(ctx, universeID)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.AssetLeafResponse{
		Leaves: make([]*unirpc.AssetLeaf, len(assetLeaves)),
	}
	for i, assetLeaf := range assetLeaves {
		assetLeaf := assetLeaf

		resp.Leaves[i], err = r.marshalAssetLeaf(ctx, &assetLeaf)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// unmarshalLeafKey un-marshals a leaf key from the RPC form.
func unmarshalLeafKey(key *unirpc.AssetKey) (universe.LeafKey, error) {
	var leafKey universe.LeafKey

	switch {
	case key.GetScriptKeyBytes() != nil:
		scriptKey, err := parseUserKey(key.GetScriptKeyBytes())
		if err != nil {
			return leafKey, err
		}

		leafKey.ScriptKey = &asset.ScriptKey{
			PubKey: scriptKey,
		}

	case key.GetScriptKeyStr() != "":
		scriptKeyBytes, err := hex.DecodeString(key.GetScriptKeyStr())
		if err != nil {
			return leafKey, err
		}

		scriptKey, err := parseUserKey(scriptKeyBytes)
		if err != nil {
			return leafKey, err
		}

		leafKey.ScriptKey = &asset.ScriptKey{
			PubKey: scriptKey,
		}
	default:
		// TODO(roasbeef): can actually allow not to be, then would
		// fetch all for the given outpoint
		return leafKey, fmt.Errorf("script key must be set")
	}

	switch {
	case key.GetOpStr() != "":
		// Parse a bitcoin outpoint in the form txid:index into a
		// wire.OutPoint struct.
		outpoint, err := wire.NewOutPointFromString(key.GetOpStr())
		if err != nil {
			return leafKey, err
		}

		leafKey.OutPoint = *outpoint

	case key.GetOutpoint() != nil:
		op := key.GetOp()

		hash, err := chainhash.NewHashFromStr(op.HashStr)
		if err != nil {
			return leafKey, err
		}

		leafKey.OutPoint = wire.OutPoint{
			Hash:  *hash,
			Index: uint32(op.Index),
		}

	default:
		return leafKey, fmt.Errorf("outpoint not set")
	}

	return leafKey, nil
}

// marshalMssmtProof marshals a MS-SMT proof into the RPC form.
func marshalMssmtProof(proof *mssmt.Proof) ([]byte, error) {
	compressedProof := proof.Compress()

	var b bytes.Buffer
	if err := compressedProof.Encode(&b); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// marshalUniverseProofLeaf marshals a universe proof leaf into the RPC form.
func (r *rpcServer) marshalUniverseProofLeaf(ctx context.Context,
	req *unirpc.UniverseKey,
	proof *universe.Proof) (*unirpc.AssetProofResponse, error) {

	uniProof, err := marshalMssmtProof(proof.UniverseInclusionProof)
	if err != nil {
		return nil, err
	}

	assetLeaf, err := r.marshalAssetLeaf(ctx, proof.Leaf)
	if err != nil {
		return nil, err
	}

	uniRoot, err := marshalUniverseRoot(universe.Root{
		Node: proof.UniverseRoot,
	})
	if err != nil {
		return nil, err
	}

	uniRoot.AssetName = assetLeaf.Asset.AssetGenesis.Name
	uniRoot.Id = req.Id

	// Marshal multiverse specific fields.
	multiverseRoot := marshalMssmtNode(proof.MultiverseRoot)

	multiverseProof, err := marshalMssmtProof(
		proof.MultiverseInclusionProof,
	)
	if err != nil {
		return nil, err
	}

	return &unirpc.AssetProofResponse{
		Req:                      req,
		UniverseRoot:             uniRoot,
		UniverseInclusionProof:   uniProof,
		AssetLeaf:                assetLeaf,
		MultiverseRoot:           multiverseRoot,
		MultiverseInclusionProof: multiverseProof,
	}, nil
}

// QueryProof attempts to query for an issuance or transfer proof for a given
// asset based on its UniverseKey. A UniverseKey is composed of the Universe ID
// (asset_id/group_key) and also a leaf key (outpoint || script_key). If found,
// the target universe proof leaf is returned in addition to inclusion proofs
// for the Universe and Multiverse MS-SMTs. This allows a caller to verify the
// known Universe root, Multiverse root, and transition or issuance proof for
// the target asset.
func (r *rpcServer) QueryProof(ctx context.Context,
	req *unirpc.UniverseKey) (*unirpc.AssetProofResponse, error) {

	universeID, err := UnmarshalUniID(req.Id)
	if err != nil {
		return nil, err
	}
	leafKey, err := unmarshalLeafKey(req.LeafKey)
	if err != nil {
		return nil, err
	}

	rpcsLog.Tracef("[QueryProof]: fetching proof at (universeID=%v, "+
		"leafKey=%x)", universeID.StringForLog(), leafKey.UniverseKey())

	// Retrieve proof export config for the given universe.
	syncConfigs, err := r.cfg.UniverseFederation.QuerySyncConfigs(ctx)
	if err != nil {
		return nil, err
	}

	var candidateIDs []universe.Identifier

	if universeID.ProofType == universe.ProofTypeUnspecified {
		// If the proof type is unspecified, then we'll attempt to
		// retrieve both the issuance and transfer proofs. We gather the
		// corresponding universe IDs into a candidate set.
		universeID.ProofType = universe.ProofTypeIssuance
		if syncConfigs.IsSyncExportEnabled(universeID) {
			candidateIDs = append(candidateIDs, universeID)
		}

		universeID.ProofType = universe.ProofTypeTransfer
		if syncConfigs.IsSyncExportEnabled(universeID) {
			candidateIDs = append(candidateIDs, universeID)
		}
	} else {
		// Otherwise, we'll only attempt to retrieve the proof for the
		// specified proof type. But first we'll check that proof export
		// is enabled for the given universe.
		if !syncConfigs.IsSyncExportEnabled(universeID) {
			return nil, fmt.Errorf("proof export is disabled for " +
				"the given universe")
		}

		candidateIDs = append(candidateIDs, universeID)
	}

	// If no candidate IDs were applicable then our config must have
	// disabled proof export for the given universe.
	if len(candidateIDs) == 0 {
		return nil, fmt.Errorf("proof export is disabled for the " +
			"given universe")
	}

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err = r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Attempt to retrieve the proof given the candidate set of universe
	// IDs.
	var proofs []*universe.Proof
	for i := range candidateIDs {
		candidateID := candidateIDs[i]

		proofs, err = r.cfg.UniverseArchive.FetchProofLeaf(
			ctx, candidateID, leafKey,
		)
		if err != nil {
			if errors.Is(err, universe.ErrNoUniverseProofFound) {
				continue
			}

			rpcsLog.Debugf("[QueryProof]: error querying for "+
				"proof at (universeID=%v, leafKey=%x)",
				universeID.StringForLog(),
				leafKey.UniverseKey())
			return nil, err
		}

		// At this point we've found a proof, so we'll break out of the
		// loop. We don't need to attempt to retrieve a proof for any
		// other candidate IDs.
		break
	}

	if len(proofs) == 0 {
		return nil, universe.ErrNoUniverseProofFound
	}

	// TODO(roasbeef): query may return multiple proofs, if allow key to
	// not be fully specified
	firstProof := proofs[0]

	rpcsLog.Tracef("[QueryProof]: found proof at (universeID=%v, "+
		"leafKey=%x)", universeID.StringForLog(),
		leafKey.UniverseKey())

	return r.marshalUniverseProofLeaf(ctx, req, firstProof)
}

// unmarshalAssetLeaf unmarshals an asset leaf from the RPC form.
func unmarshalAssetLeaf(leaf *unirpc.AssetLeaf) (*universe.Leaf, error) {
	// We'll just pull the asset details from the serialized issuance proof
	// itself.
	var assetProof proof.Proof
	if err := assetProof.Decode(
		bytes.NewReader(leaf.Proof),
	); err != nil {
		return nil, err
	}

	// TODO(roasbeef): double check posted file format everywhere
	//  * raw proof, or within file?

	return &universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  assetProof.Asset.Genesis,
			GroupKey: assetProof.Asset.GroupKey,
		},
		RawProof: leaf.Proof,
		Asset:    &assetProof.Asset,
		Amt:      assetProof.Asset.Amount,
	}, nil
}

// InsertProof attempts to insert a new issuance or transfer proof into the
// Universe tree specified by the UniverseKey. If valid, then the proof is
// inserted into the database, with a new Universe root returned for the updated
// asset_id/group_key.
func (r *rpcServer) InsertProof(ctx context.Context,
	req *unirpc.AssetProof) (*unirpc.AssetProofResponse, error) {

	if req.Key == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}

	universeID, err := UnmarshalUniID(req.Key.Id)
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

	// If universe proof type unspecified, set based on the provided asset
	// proof.
	if universeID.ProofType == universe.ProofTypeUnspecified {
		universeID.ProofType, err = universe.NewProofTypeFromAsset(
			assetLeaf.Asset,
		)
		if err != nil {
			return nil, err
		}
	}

	// Ensure that the new proof is of the correct type for the target
	// universe.
	err = universe.ValidateProofUniverseType(assetLeaf.Asset, universeID)
	if err != nil {
		return nil, err
	}

	// Ensure proof insert is enabled for the given universe.
	syncConfigs, err := r.cfg.UniverseFederation.QuerySyncConfigs(ctx)
	if err != nil {
		return nil, err
	}

	if !syncConfigs.IsSyncInsertEnabled(universeID) {
		return nil, fmt.Errorf("proof insert is disabled for the " +
			"given universe")
	}

	// Check the rate limiter to see if we need to wait at all. If not then
	// this'll be a noop.
	if err = r.proofQueryRateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	rpcsLog.Debugf("[InsertProof]: inserting proof at "+
		"(universeID=%v, leafKey=%x)", universeID,
		leafKey.UniverseKey())

	newUniverseState, err := r.cfg.UniverseArchive.UpsertProofLeaf(
		ctx, universeID, leafKey, assetLeaf,
	)
	if err != nil {
		return nil, err
	}

	universeRootHash := newUniverseState.UniverseRoot.NodeHash()
	rpcsLog.Debugf("[InsertProof]: proof inserted, new universe root: %x",
		universeRootHash[:])

	return r.marshalUniverseProofLeaf(ctx, req.Key, newUniverseState)
}

// Info returns a set of information about the current state of the Universe.
func (r *rpcServer) Info(ctx context.Context,
	_ *unirpc.InfoRequest) (*unirpc.InfoResponse, error) {

	return &unirpc.InfoResponse{
		RuntimeId: r.cfg.RuntimeID,
	}, nil
}

// unmarshalUniverseSyncType maps an RPC universe sync type into a concrete
// type.
func unmarshalUniverseSyncType(req unirpc.UniverseSyncMode) (
	universe.SyncType, error) {

	switch req {
	case unirpc.UniverseSyncMode_SYNC_FULL:
		return universe.SyncFull, nil

	case unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY:
		return universe.SyncIssuance, nil

	default:
		return 0, fmt.Errorf("unknown sync type: %v", req)
	}
}

// unmarshalSyncTargets maps an RPC sync target into a concrete type.
func unmarshalSyncTargets(targets []*unirpc.SyncTarget) ([]universe.Identifier, error) {
	uniIDs := make([]universe.Identifier, 0, len(targets))
	for _, target := range targets {
		uniID, err := UnmarshalUniID(target.Id)
		if err != nil {
			return nil, err
		}
		uniIDs = append(uniIDs, uniID)
	}

	return uniIDs, nil
}

// marshalUniverseDiff marshals a universe diff into the RPC form.
func (r *rpcServer) marshalUniverseDiff(ctx context.Context,
	uniDiff []universe.AssetSyncDiff) (*unirpc.SyncResponse, error) {

	resp := &unirpc.SyncResponse{
		SyncedUniverses: make([]*unirpc.SyncedUniverse, 0, len(uniDiff)),
	}

	err := fn.ForEachErr(uniDiff, func(diff universe.AssetSyncDiff) error {
		oldUniRoot, err := marshalUniverseRoot(diff.OldUniverseRoot)
		if err != nil {
			return fmt.Errorf("unable to marshal old uni "+
				"root: %w", err)
		}
		newUniRoot, err := marshalUniverseRoot(diff.NewUniverseRoot)
		if err != nil {
			return fmt.Errorf("unable to marshal new unit "+
				"root: %w", err)
		}

		leaves := make([]*unirpc.AssetLeaf, len(diff.NewLeafProofs))
		for i, leaf := range diff.NewLeafProofs {
			leaves[i], err = r.marshalAssetLeaf(ctx, leaf)
			if err != nil {
				return err
			}
		}

		resp.SyncedUniverses = append(
			resp.SyncedUniverses, &unirpc.SyncedUniverse{
				OldAssetRoot:   oldUniRoot,
				NewAssetRoot:   newUniRoot,
				NewAssetLeaves: leaves,
			},
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// SyncUniverse takes host information for a remote Universe server, then
// attempts to synchronize either only the set of specified asset_ids, or all
// assets if none are specified. The sync process will attempt to query for the
// latest known root for each asset, performing tree based reconciliation to
// arrive at a new shared root.
func (r *rpcServer) SyncUniverse(ctx context.Context,
	req *unirpc.SyncRequest) (*unirpc.SyncResponse, error) {

	// TODO(roasbeef): have another layer, only allow single outstanding
	// sync request per host?

	syncMode, err := unmarshalUniverseSyncType(req.SyncMode)
	if err != nil {
		return nil, fmt.Errorf("unable to parse sync type: %w", err)
	}
	syncTargets, err := unmarshalSyncTargets(req.SyncTargets)
	if err != nil {
		return nil, fmt.Errorf("unable to parse sync targets: %w", err)
	}

	uniAddr := universe.NewServerAddrFromStr(req.UniverseHost)

	// Obtain the general and universe specific federation sync configs.
	queryFedSyncConfigs := r.cfg.FederationDB.QueryFederationSyncConfigs
	globalConfigs, uniSyncConfigs, err := queryFedSyncConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to query federation sync "+
			"config(s): %w", err)
	}

	syncConfigs := universe.SyncConfigs{
		GlobalSyncConfigs: globalConfigs,
		UniSyncConfigs:    uniSyncConfigs,
	}

	// TODO(roasbeef): add layer of indirection in front of?
	//  * just interface interaction
	// TODO(ffranr): Sync via the FederationEnvoy rather than syncer.
	universeDiff, err := r.cfg.UniverseSyncer.SyncUniverse(
		ctx, uniAddr, syncMode, syncConfigs, syncTargets...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to sync universe: %w", err)
	}

	return r.marshalUniverseDiff(ctx, universeDiff)
}

func marshalUniverseServer(server universe.ServerAddr,
) *unirpc.UniverseFederationServer {

	return &unirpc.UniverseFederationServer{
		Host: server.HostStr(),
		Id:   int32(server.ID),
	}
}

// ListFederationServers lists the set of servers that make up the federation
// of the local Universe server. This servers are used to push out new proofs,
// and also periodically call sync new proofs from the remote server.
func (r *rpcServer) ListFederationServers(ctx context.Context,
	_ *unirpc.ListFederationServersRequest,
) (*unirpc.ListFederationServersResponse, error) {

	uniServers, err := r.cfg.FederationDB.UniverseServers(ctx)
	if err != nil {
		return nil, err
	}

	return &unirpc.ListFederationServersResponse{
		Servers: fn.Map(uniServers, marshalUniverseServer),
	}, nil
}

func unmarshalUniverseServer(
	server *unirpc.UniverseFederationServer) universe.ServerAddr {

	return universe.NewServerAddr(int64(server.Id), server.Host)
}

// AddFederationServer adds a new server to the federation of the local
// Universe server. Once a server is added, this call can also optionally be
// used to trigger a sync of the remote server.
func (r *rpcServer) AddFederationServer(ctx context.Context,
	req *unirpc.AddFederationServerRequest,
) (*unirpc.AddFederationServerResponse, error) {

	serversToAdd := fn.Map(req.Servers, unmarshalUniverseServer)

	for idx := range serversToAdd {
		server := serversToAdd[idx]

		// Before we add the server as a federation member, we check
		// that we can actually connect to it and that it isn't
		// ourselves.
		err := CheckFederationServer(
			r.cfg.RuntimeID, universe.DefaultTimeout, server,
		)
		if err != nil {
			return nil, err
		}
	}

	err := r.cfg.UniverseFederation.AddServer(serversToAdd...)
	if err != nil {
		return nil, err
	}

	return &unirpc.AddFederationServerResponse{}, nil
}

// DeleteFederationServer removes a server from the federation of the local
// Universe server.
func (r *rpcServer) DeleteFederationServer(ctx context.Context,
	req *unirpc.DeleteFederationServerRequest,
) (*unirpc.DeleteFederationServerResponse, error) {

	serversToDel := fn.Map(req.Servers, unmarshalUniverseServer)

	// Remove the servers from the proofs sync log. This is necessary before
	// we can remove the servers from the database because of a foreign
	// key constraint.
	err := r.cfg.FederationDB.DeleteProofsSyncLogEntries(
		ctx, serversToDel...,
	)
	if err != nil {
		return nil, err
	}

	err = r.cfg.FederationDB.RemoveServers(ctx, serversToDel...)
	if err != nil {
		return nil, err
	}

	return &unirpc.DeleteFederationServerResponse{}, nil
}

// SetFederationSyncConfig sets the configuration of the universe federation
// sync.
func (r *rpcServer) SetFederationSyncConfig(ctx context.Context,
	req *unirpc.SetFederationSyncConfigRequest) (
	*unirpc.SetFederationSyncConfigResponse, error) {

	// Unmarshal global sync configs.
	globalSyncConfig := make(
		[]*universe.FedGlobalSyncConfig, len(req.GlobalSyncConfigs),
	)
	for i := range req.GlobalSyncConfigs {
		config := req.GlobalSyncConfigs[i]

		proofType, err := UnmarshalUniProofType(config.ProofType)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal "+
				"proof type: %w", err)
		}

		globalSyncConfig[i] = &universe.FedGlobalSyncConfig{
			ProofType:       proofType,
			AllowSyncInsert: config.AllowSyncInsert,
			AllowSyncExport: config.AllowSyncExport,
		}
	}

	// Unmarshal asset (asset/asset group) specific sync configs.
	assetSyncConfigs := make(
		[]*universe.FedUniSyncConfig, len(req.AssetSyncConfigs),
	)
	for i := range req.AssetSyncConfigs {
		assetSyncConfig := req.AssetSyncConfigs[i]
		config, err := unmarshalAssetSyncConfig(assetSyncConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to parse asset sync "+
				"config: %w", err)
		}

		assetSyncConfigs[i] = config
	}

	// Update asset (asset/asset group) specific sync configs.
	err := r.cfg.FederationDB.UpsertFederationSyncConfig(
		ctx, globalSyncConfig, assetSyncConfigs,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to set federation sync "+
			"config: %w", err)
	}

	return &unirpc.SetFederationSyncConfigResponse{}, nil
}

// QueryFederationSyncConfig queries the universe federation sync configuration
// settings.
func (r *rpcServer) QueryFederationSyncConfig(ctx context.Context,
	_ *unirpc.QueryFederationSyncConfigRequest,
) (*unirpc.QueryFederationSyncConfigResponse, error) {

	// Obtain the general and universe specific federation sync configs.
	queryFedSyncConfigs := r.cfg.FederationDB.QueryFederationSyncConfigs
	globalConfigs, uniSyncConfigs, err := queryFedSyncConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to query federation sync "+
			"config(s): %w", err)
	}

	// Marshal the general sync config into the RPC form.
	globalConfigRPC := make(
		[]*unirpc.GlobalFederationSyncConfig, len(globalConfigs),
	)
	for i := range globalConfigs {
		globalConfig := globalConfigs[i]

		proofTypeRpc, err := MarshalUniProofType(globalConfig.ProofType)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal "+
				"proof type: %w", err)
		}

		globalConfigRPC[i] = &unirpc.GlobalFederationSyncConfig{
			ProofType:       proofTypeRpc,
			AllowSyncInsert: globalConfig.AllowSyncInsert,
			AllowSyncExport: globalConfig.AllowSyncExport,
		}
	}

	// Marshal universe specific sync configs into the RPC form.
	uniConfigRPCs := make(
		[]*unirpc.AssetFederationSyncConfig, len(uniSyncConfigs),
	)
	for i := range uniSyncConfigs {
		uniSyncConfig := uniSyncConfigs[i]
		uniConfigRPC, err := MarshalAssetFedSyncCfg(*uniSyncConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal universe "+
				"specific federation sync config: %w", err)
		}
		uniConfigRPCs[i] = uniConfigRPC
	}

	return &unirpc.QueryFederationSyncConfigResponse{
		GlobalSyncConfigs: globalConfigRPC,
		AssetSyncConfigs:  uniConfigRPCs,
	}, nil
}

// ProveAssetOwnership creates an ownership proof embedded in an asset
// transition proof. That ownership proof is a signed virtual transaction
// spending the asset with a valid witness to prove the prover owns the keys
// that can spend the asset.
func (r *rpcServer) ProveAssetOwnership(ctx context.Context,
	req *wrpc.ProveAssetOwnershipRequest) (*wrpc.ProveAssetOwnershipResponse,
	error) {

	if len(req.ScriptKey) == 0 {
		return nil, fmt.Errorf("a valid script key must be specified")
	}

	scriptKey, err := parseUserKey(req.ScriptKey)
	if err != nil {
		return nil, fmt.Errorf("invalid script key: %w", err)
	}

	if len(req.AssetId) != 32 {
		return nil, fmt.Errorf("asset ID must be 32 bytes")
	}

	var (
		assetID  = fn.ToArray[asset.ID](req.AssetId)
		outPoint *wire.OutPoint
	)

	// The outpoint is optional when querying for a proof file. But if
	// multiple proofs exist for the same assetID and script key, then an
	// error will be returned and the outpoint needs to be specified to
	// disambiguate.
	if req.Outpoint != nil {
		txid, err := chainhash.NewHash(req.Outpoint.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing outpoint: %w",
				err)
		}
		outPoint = &wire.OutPoint{
			Hash:  *txid,
			Index: req.Outpoint.OutputIndex,
		}
	}

	proofBlob, err := r.cfg.ProofArchive.FetchProof(ctx, proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *scriptKey,
		OutPoint:  outPoint,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot fetch proof: %w", err)
	}

	proofFile := &proof.File{}
	err = proofFile.Decode(bytes.NewReader(proofBlob))
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)
	lastSnapshot, err := proofFile.Verify(
		ctx, headerVerifier, proof.DefaultMerkleVerifier, groupVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot verify proof: %w", err)
	}

	inputAsset := lastSnapshot.Asset
	inputCommitment, err := r.cfg.AssetStore.FetchCommitment(
		ctx, inputAsset.ID(), lastSnapshot.OutPoint,
		inputAsset.GroupKey, &inputAsset.ScriptKey, false,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching commitment: %w", err)
	}

	challengeWitness, err := r.cfg.AssetWallet.SignOwnershipProof(
		inputCommitment.Asset.Copy(),
	)
	if err != nil {
		return nil, fmt.Errorf("error signing ownership proof: %w", err)
	}

	lastProof, err := proofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("error fetching last proof: %w", err)
	}

	lastProof.ChallengeWitness = challengeWitness

	var buf bytes.Buffer
	if err := lastProof.Encode(&buf); err != nil {
		return nil, fmt.Errorf("error encoding proof file: %w", err)
	}

	return &wrpc.ProveAssetOwnershipResponse{
		ProofWithWitness: buf.Bytes(),
	}, nil
}

// VerifyAssetOwnership verifies the asset ownership proof embedded in the
// given transition proof of an asset and returns true if the proof is valid.
func (r *rpcServer) VerifyAssetOwnership(ctx context.Context,
	req *wrpc.VerifyAssetOwnershipRequest) (*wrpc.VerifyAssetOwnershipResponse,
	error) {

	if len(req.ProofWithWitness) == 0 {
		return nil, fmt.Errorf("a valid proof must be specified")
	}

	p := &proof.Proof{}
	err := p.Decode(bytes.NewReader(req.ProofWithWitness))
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof file: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)
	_, err = p.Verify(
		ctx, nil, headerVerifier, proof.DefaultMerkleVerifier,
		groupVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error verifying proof: %w", err)
	}

	return &wrpc.VerifyAssetOwnershipResponse{
		ValidProof: true,
	}, nil
}

// UniverseStats returns a set of aggregate statistics for the current state
// of the Universe.
func (r *rpcServer) UniverseStats(ctx context.Context,
	_ *unirpc.StatsRequest) (*unirpc.StatsResponse, error) {

	universeStats, err := r.cfg.UniverseStats.AggregateSyncStats(ctx)
	if err != nil {
		return nil, err
	}

	return &unirpc.StatsResponse{
		NumTotalAssets: int64(universeStats.NumTotalAssets),
		NumTotalGroups: int64(universeStats.NumTotalGroups),
		NumTotalSyncs:  int64(universeStats.NumTotalSyncs),
		NumTotalProofs: int64(universeStats.NumTotalProofs),
	}, nil
}

// marshalAssetSyncSnapshot maps a universe asset sync stat snapshot to the RPC
// counterpart.
func (r *rpcServer) marshalAssetSyncSnapshot(ctx context.Context,
	a universe.AssetSyncSnapshot) *unirpc.AssetStatsSnapshot {

	resp := &unirpc.AssetStatsSnapshot{
		TotalSyncs:  int64(a.TotalSyncs),
		TotalProofs: int64(a.TotalProofs),
		GroupSupply: int64(a.GroupSupply),
	}
	rpcAsset := &unirpc.AssetStatsAsset{
		AssetId:          a.AssetID[:],
		GenesisPoint:     a.GenesisPoint.String(),
		AssetName:        a.AssetName,
		AssetType:        taprpc.AssetType(a.AssetType),
		TotalSupply:      int64(a.TotalSupply),
		GenesisHeight:    int32(a.GenesisHeight),
		GenesisTimestamp: r.getBlockTimestamp(ctx, a.GenesisHeight),
		AnchorPoint:      a.AnchorPoint.String(),
	}

	if a.GroupKey != nil {
		resp.GroupKey = a.GroupKey.SerializeCompressed()
		resp.GroupAnchor = rpcAsset
	} else {
		resp.Asset = rpcAsset
	}

	return resp
}

// QueryAssetStats returns a set of statistics for a given set of assets.
// Stats can be queried for all assets, or based on the: asset ID, name, or
// asset type. Pagination is supported via the offset and limit params.
// Results can also be sorted based on any of the main query params.
func (r *rpcServer) QueryAssetStats(ctx context.Context,
	req *unirpc.AssetStatsQuery) (*unirpc.UniverseAssetStats, error) {

	assetStats, err := r.cfg.UniverseStats.QuerySyncStats(
		ctx, universe.SyncStatsQuery{
			AssetNameFilter: req.AssetNameFilter,
			AssetTypeFilter: func() *asset.Type {
				switch req.AssetTypeFilter {
				case unirpc.AssetTypeFilter_FILTER_ASSET_NORMAL:
					return fn.Ptr(asset.Normal)

				case unirpc.AssetTypeFilter_FILTER_ASSET_COLLECTIBLE:
					return fn.Ptr(asset.Collectible)

				default:
					return nil
				}
			}(),
			AssetIDFilter: fn.ToArray[asset.ID](
				req.AssetIdFilter,
			),
			SortBy:        universe.SyncStatsSort(req.SortBy),
			SortDirection: universe.SortDirection(req.Direction),
			Offset:        int(req.Offset),
			Limit:         int(req.Limit),
		},
	)
	if err != nil {
		return nil, err
	}

	resp := &unirpc.UniverseAssetStats{
		AssetStats: make(
			[]*unirpc.AssetStatsSnapshot, len(assetStats.SyncStats),
		),
	}
	for idx, snapshot := range assetStats.SyncStats {
		resp.AssetStats[idx] = r.marshalAssetSyncSnapshot(ctx, snapshot)
	}

	return resp, nil
}

// getBlockTimestamp returns the timestamp of the block at the given height.
func (r *rpcServer) getBlockTimestamp(ctx context.Context,
	height uint32) int64 {

	// Shortcut any lookup in case we don't have a valid height in the first
	// place.
	if height == 0 {
		return 0
	}

	cacheTS, err := r.blockTimestampCache.Get(height)
	if err == nil {
		return int64(cacheTS)
	}

	hash, err := r.cfg.Lnd.ChainKit.GetBlockHash(ctx, int64(height))
	if err != nil {
		return 0
	}

	block, err := r.cfg.Lnd.ChainKit.GetBlock(ctx, hash)
	if err != nil {
		return 0
	}

	ts := uint32(block.Header.Timestamp.Unix())
	_, _ = r.blockTimestampCache.Put(height, cacheableTimestamp(ts))

	return int64(ts)
}

// QueryEvents returns the number of sync and proof events for a given time
// period, grouped by day.
func (r *rpcServer) QueryEvents(ctx context.Context,
	req *unirpc.QueryEventsRequest) (*unirpc.QueryEventsResponse, error) {

	// If no start or end time is specified, default to the last 30 days.
	var (
		startTime = time.Now().AddDate(0, 0, -30)
		endTime   = time.Now()
	)
	if req.StartTimestamp > 0 {
		startTime = time.Unix(req.StartTimestamp, 0)
	}
	if req.EndTimestamp > 0 {
		endTime = time.Unix(req.EndTimestamp, 0)
	}

	if endTime.Before(startTime) {
		return nil, fmt.Errorf("end time cannot be before start time")
	}

	stats, err := r.cfg.UniverseStats.QueryAssetStatsPerDay(
		ctx, universe.GroupedStatsQuery{
			StartTime: startTime,
			EndTime:   endTime,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error querying stats: %w", err)
	}

	rpcStats := &unirpc.QueryEventsResponse{
		Events: make([]*unirpc.GroupedUniverseEvents, len(stats)),
	}
	for day, s := range stats {
		rpcStats.Events[day] = &unirpc.GroupedUniverseEvents{
			Date:           s.Date,
			SyncEvents:     s.NumTotalSyncs,
			NewProofEvents: s.NumTotalProofs,
		}
	}

	return rpcStats, nil
}

// RemoveUTXOLease removes the lease/lock/reservation of the given managed
// UTXO.
func (r *rpcServer) RemoveUTXOLease(ctx context.Context,
	req *wrpc.RemoveUTXOLeaseRequest) (*wrpc.RemoveUTXOLeaseResponse,
	error) {

	if req.Outpoint == nil {
		return nil, fmt.Errorf("outpoint must be specified")
	}

	hash, err := chainhash.NewHash(req.Outpoint.Txid)
	if err != nil {
		return nil, fmt.Errorf("error parsing txid: %w", err)
	}

	outPoint := wire.OutPoint{
		Hash:  *hash,
		Index: req.Outpoint.OutputIndex,
	}

	err = r.cfg.CoinSelect.ReleaseCoins(ctx, outPoint)
	if err != nil {
		return nil, err
	}

	return &wrpc.RemoveUTXOLeaseResponse{}, nil
}

// MarshalAssetFedSyncCfg returns an RPC ready asset specific federation sync
// config.
func MarshalAssetFedSyncCfg(
	config universe.FedUniSyncConfig) (*unirpc.AssetFederationSyncConfig,
	error) {

	// Marshal universe ID into the RPC form.
	uniID := config.UniverseID
	assetIDBytes := uniID.AssetID[:]

	var groupKeyBytes []byte
	if uniID.GroupKey != nil {
		groupKeyBytes = uniID.GroupKey.SerializeCompressed()
	}
	uniIdRPC := unirpc.MarshalUniverseID(assetIDBytes, groupKeyBytes)

	// Marshal proof type.
	proofTypeRpc, err := MarshalUniProofType(uniID.ProofType)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal proof type: %w", err)
	}
	uniIdRPC.ProofType = proofTypeRpc

	return &unirpc.AssetFederationSyncConfig{
		Id:              uniIdRPC,
		AllowSyncInsert: config.AllowSyncInsert,
		AllowSyncExport: config.AllowSyncExport,
	}, nil
}

// unmarshalAssetSpecifier unmarshals an asset specifier from the RPC form.
func unmarshalAssetSpecifier(req *rfqrpc.AssetSpecifier) (*asset.ID,
	*btcec.PublicKey, error) {

	// Attempt to decode the asset specifier from the RPC request. In cases
	// where both the asset ID and asset group key are provided, we will
	// give precedence to the asset ID due to its higher level of
	// specificity.
	var (
		assetID *asset.ID

		groupKeyBytes []byte
		groupKey      *btcec.PublicKey

		err error
	)

	switch {
	// Parse the asset ID if it's set.
	case len(req.GetAssetId()) > 0:
		var assetIdBytes [32]byte
		copy(assetIdBytes[:], req.GetAssetId())
		id := asset.ID(assetIdBytes)
		assetID = &id

	case len(req.GetAssetIdStr()) > 0:
		assetIDBytes, err := hex.DecodeString(req.GetAssetIdStr())
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding asset "+
				"ID: %w", err)
		}

		var id asset.ID
		copy(id[:], assetIDBytes)
		assetID = &id

	// Parse the group key if it's set.
	case len(req.GetGroupKey()) > 0:
		groupKeyBytes = req.GetGroupKey()
		groupKey, err = btcec.ParsePubKey(groupKeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing group "+
				"key: %w", err)
		}

	case len(req.GetGroupKeyStr()) > 0:
		groupKeyBytes, err := hex.DecodeString(
			req.GetGroupKeyStr(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding group "+
				"key: %w", err)
		}

		groupKey, err = btcec.ParsePubKey(groupKeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing group "+
				"key: %w", err)
		}

	default:
		// At this point, we know that neither the asset ID nor the
		// group key are specified. Return an error.
		return nil, nil, fmt.Errorf("either asset ID or asset group " +
			"key must be specified")
	}

	return assetID, groupKey, nil
}

// unmarshalAssetBuyOrder unmarshals an asset buy order from the RPC form.
func unmarshalAssetBuyOrder(
	req *rfqrpc.AddAssetBuyOrderRequest) (*rfq.BuyOrder, error) {

	assetId, assetGroupKey, err := unmarshalAssetSpecifier(
		req.AssetSpecifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling asset specifier: "+
			"%w", err)
	}

	// Unmarshal the peer if specified.
	var peer *route.Vertex
	if len(req.PeerPubKey) > 0 {
		pv, err := route.NewVertexFromBytes(req.PeerPubKey)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling peer "+
				"route vertex: %w", err)
		}

		peer = &pv
	}

	return &rfq.BuyOrder{
		AssetID:        assetId,
		AssetGroupKey:  assetGroupKey,
		MinAssetAmount: req.MinAssetAmount,
		MaxBid:         lnwire.MilliSatoshi(req.MaxBid),
		Expiry:         req.Expiry,
		Peer:           peer,
	}, nil
}

// AddAssetBuyOrder upserts a new buy order for the given asset into the RFQ
// manager. If the order already exists for the given asset, it will be updated.
func (r *rpcServer) AddAssetBuyOrder(_ context.Context,
	req *rfqrpc.AddAssetBuyOrderRequest) (*rfqrpc.AddAssetBuyOrderResponse,
	error) {

	// Unmarshal the buy order from the RPC form.
	buyOrder, err := unmarshalAssetBuyOrder(req)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling buy order: %w", err)
	}

	var peer string
	if buyOrder.Peer != nil {
		peer = buyOrder.Peer.String()
	}
	rpcsLog.Debugf("[AddAssetBuyOrder]: upserting buy order "+
		"(dest_peer=%s)", peer)

	// Upsert the buy order into the RFQ manager.
	err = r.cfg.RfqManager.UpsertAssetBuyOrder(*buyOrder)
	if err != nil {
		return nil, fmt.Errorf("error upserting buy order into RFQ "+
			"manager: %w", err)
	}

	return &rfqrpc.AddAssetBuyOrderResponse{}, nil
}

// AddAssetSellOffer upserts a new sell offer for the given asset into the
// RFQ manager. If the offer already exists for the given asset, it will be
// updated.
func (r *rpcServer) AddAssetSellOffer(_ context.Context,
	req *rfqrpc.AddAssetSellOfferRequest) (*rfqrpc.AddAssetSellOfferResponse,
	error) {

	// Unmarshal the sell offer from the RPC form.
	assetID, assetGroupKey, err := unmarshalAssetSpecifier(
		req.AssetSpecifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling asset specifier: "+
			"%w", err)
	}

	sellOffer := &rfq.SellOffer{
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		MaxUnits:      req.MaxUnits,
	}

	rpcsLog.Debugf("[AddAssetSellOffer]: upserting sell offer "+
		"(sell_offer=%v)", sellOffer)

	// Upsert the sell offer into the RFQ manager.
	err = r.cfg.RfqManager.UpsertAssetSellOffer(*sellOffer)
	if err != nil {
		return nil, fmt.Errorf("error upserting sell offer into RFQ "+
			"manager: %w", err)
	}

	return &rfqrpc.AddAssetSellOfferResponse{}, nil
}

// marshalAcceptedQuotes marshals a map of accepted quotes into the RPC form.
func marshalAcceptedQuotes(
	acceptedQuotes map[rfq.SerialisedScid]rfqmsg.BuyAccept) []*rfqrpc.AcceptedQuote {

	// Marshal the accepted quotes into the RPC form.
	rpcQuotes := make([]*rfqrpc.AcceptedQuote, 0, len(acceptedQuotes))
	for scid, quote := range acceptedQuotes {
		rpcQuote := &rfqrpc.AcceptedQuote{
			Peer:        quote.Peer.String(),
			Id:          quote.ID[:],
			Scid:        uint64(scid),
			AssetAmount: quote.AssetAmount,
			AskPrice:    uint64(quote.AskPrice),
			Expiry:      quote.Expiry,
		}
		rpcQuotes = append(rpcQuotes, rpcQuote)
	}

	return rpcQuotes
}

// QueryRfqAcceptedQuotes queries for accepted quotes from the RFQ system.
func (r *rpcServer) QueryRfqAcceptedQuotes(_ context.Context,
	_ *rfqrpc.QueryRfqAcceptedQuotesRequest) (
	*rfqrpc.QueryRfqAcceptedQuotesResponse, error) {

	// Query the RFQ manager for accepted quotes.
	acceptedQuotes := r.cfg.RfqManager.QueryAcceptedQuotes()

	rpcQuotes := marshalAcceptedQuotes(acceptedQuotes)

	return &rfqrpc.QueryRfqAcceptedQuotesResponse{
		AcceptedQuotes: rpcQuotes,
	}, nil
}

// marshallRfqEvent marshals an RFQ event into the RPC form.
func marshallRfqEvent(eventInterface fn.Event) (*rfqrpc.RfqEvent, error) {
	timestamp := eventInterface.Timestamp().UTC().Unix()

	switch event := eventInterface.(type) {
	case *rfq.IncomingAcceptQuoteEvent:
		acceptedQuote := &rfqrpc.AcceptedQuote{
			Peer:        event.Peer.String(),
			Id:          event.ID[:],
			Scid:        uint64(event.ShortChannelId()),
			AssetAmount: event.AssetAmount,
			AskPrice:    uint64(event.AskPrice),
			Expiry:      event.Expiry,
		}

		eventRpc := &rfqrpc.RfqEvent_IncomingAcceptQuote{
			IncomingAcceptQuote: &rfqrpc.IncomingAcceptQuoteEvent{
				Timestamp:     uint64(timestamp),
				AcceptedQuote: acceptedQuote,
			},
		}
		return &rfqrpc.RfqEvent{
			Event: eventRpc,
		}, nil

	case *rfq.AcceptHtlcEvent:
		eventRpc := &rfqrpc.RfqEvent_AcceptHtlc{
			AcceptHtlc: &rfqrpc.AcceptHtlcEvent{
				Timestamp: uint64(timestamp),
				Scid:      uint64(event.ChannelRemit.Scid),
			},
		}
		return &rfqrpc.RfqEvent{
			Event: eventRpc,
		}, nil

	default:
		return nil, fmt.Errorf("unknown RFQ event type: %T",
			eventInterface)
	}
}

// SubscribeRfqEventNtfns subscribes to RFQ event notifications.
func (r *rpcServer) SubscribeRfqEventNtfns(
	_ *rfqrpc.SubscribeRfqEventNtfnsRequest,
	ntfnStream rfqrpc.Rfq_SubscribeRfqEventNtfnsServer) error {

	// Create a new event subscriber and pass a copy to the RFQ manager.
	// We will then read events from the subscriber.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	// Register the subscriber with the ChainPorter.
	err := r.cfg.RfqManager.RegisterSubscriber(
		eventSubscriber, false, 0,
	)
	if err != nil {
		return fmt.Errorf("failed to register RFQ manager event "+
			"notifications subscription: %w", err)
	}

	for {
		select {
		// Handle new events from the subscriber.
		case event := <-eventSubscriber.NewItemCreated.ChanOut():
			// Marshal the event into its RPC form.
			rpcEvent, err := marshallRfqEvent(event)
			if err != nil {
				return fmt.Errorf("failed to marshall RFQ "+
					"event into RPC form: %w", err)
			}

			err = ntfnStream.Send(rpcEvent)
			if err != nil {
				return err
			}

		// Handle the case where the RPC stream is closed by the client.
		case <-ntfnStream.Context().Done():
			// Remove the subscriber from the RFQ manager.
			err := r.cfg.RfqManager.RemoveSubscriber(
				eventSubscriber,
			)
			if err != nil {
				return fmt.Errorf("failed to remove RFQ "+
					"manager event notifications "+
					"subscription: %w", err)
			}

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
