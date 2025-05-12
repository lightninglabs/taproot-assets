package taprootassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcperms"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/lightningnetwork/lnd/zpay32"
	"golang.org/x/exp/maps"
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

	// P2TRChangeType is the type of change address that should be used for
	// funding PSBTs, as we'll always want to use P2TR change addresses.
	P2TRChangeType = walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR
)

const (
	// tapdMacaroonLocation is the value we use for the tapd macaroons'
	// "Location" field when baking them.
	tapdMacaroonLocation = "tapd"

	// AssetBurnConfirmationText is the text that needs to be set on the
	// RPC to confirm an asset burn.
	AssetBurnConfirmationText = "assets will be destroyed"

	// proofTypeSend is an alias for the proof type used for sending assets.
	proofTypeSend = tapdevrpc.ProofTransferType_PROOF_TRANSFER_TYPE_SEND

	// proofTypeReceive is an alias for the proof type used for receiving
	// assets.
	proofTypeReceive = tapdevrpc.ProofTransferType_PROOF_TRANSFER_TYPE_RECEIVE
)

type (
	// devSendEventStream is a type alias for the asset send event
	// notification stream.
	devSendEventStream = tapdevrpc.TapDev_SubscribeSendAssetEventNtfnsServer

	// sendEventStream is a type alias for the asset send event notification
	// stream.
	sendEventStream = taprpc.TaprootAssets_SubscribeSendEventsServer

	// sendBackoff is a type alias for the backoff event that is sent when a
	// proof transfer receive process failed and needs to re-try.
	sendBackoff = tapdevrpc.SendAssetEvent_ProofTransferBackoffWaitEvent

	// sendExecute is a type alias for the complete event that is sent when
	// an asset is sent.
	sendExecute = tapdevrpc.SendAssetEvent_ExecuteSendStateEvent

	// devReceiveEventStream is a type alias for the asset receive event
	// notification stream.
	devReceiveEventStream = tapdevrpc.TapDev_SubscribeReceiveAssetEventNtfnsServer

	// receiveEventStream is a type alias for the asset receive event
	// notification stream.
	receiveEventStream = taprpc.TaprootAssets_SubscribeReceiveEventsServer

	// mintEventStream is a type alias for the asset mint event notification
	// stream.
	mintEventStream = mintrpc.Mint_SubscribeMintEventsServer

	// receiveBackOff is a type alias for the backoff event that is sent
	// when a proof transfer process failed and needs to re-try.
	receiveBackoff = tapdevrpc.ReceiveAssetEvent_ProofTransferBackoffWaitEvent

	// receiveComplete is a type alias for the complete event that is sent
	// when an asset is received.
	receiveComplete = tapdevrpc.ReceiveAssetEvent_AssetReceiveCompleteEvent

	// EventStream is a generic interface type for notification streams.
	EventStream[T any] interface {
		// Send sends an event object to the notification stream.
		Send(T) error
		grpc.ServerStream
	}
)

// rpcServer is the main RPC server for the Taproot Assets daemon that handles
// gRPC/REST/Websockets incoming requests.
type rpcServer struct {
	started  int32
	shutdown int32

	taprpc.UnimplementedTaprootAssetsServer
	wrpc.UnimplementedAssetWalletServer
	mintrpc.UnimplementedMintServer
	rfqrpc.UnimplementedRfqServer
	tchrpc.UnimplementedTaprootAssetChannelsServer
	tapdevrpc.UnimplementedTapDevServer
	unirpc.UnimplementedUniverseServer

	interceptor signal.Interceptor

	interceptorChain *rpcperms.InterceptorChain

	cfg *Config

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
		quit:             make(chan struct{}),
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
	tchrpc.RegisterTaprootAssetChannelsServer(grpcServer, r)
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

	err = rfqrpc.RegisterRfqHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	err = tchrpc.RegisterTaprootAssetChannelsHandlerFromEndpoint(
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
				r.cfg.LogMgr.SupportedSubsystems(), " ",
			),
		}, nil
	}

	rpcsLog.Infof("[debuglevel] changing debug level to: %v", req.LevelSpec)

	// Otherwise, we'll attempt to set the logging level using the
	// specified level spec.
	err := build.ParseAndSetDebugLevels(req.LevelSpec, r.cfg.LogMgr)
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
	specificGroupInternalKey := req.Asset.GroupInternalKey != nil
	groupTapscriptRootSize := len(req.Asset.GroupTapscriptRoot)

	// A group tapscript root must be 32 bytes.
	if groupTapscriptRootSize != 0 &&
		groupTapscriptRootSize != sha256.Size {

		return nil, fmt.Errorf("group tapscript root must be %d bytes",
			sha256.Size)
	}

	switch {
	// New grouped asset and grouped asset cannot both be set.
	case req.Asset.NewGroupedAsset && req.Asset.GroupedAsset:
		return nil, fmt.Errorf("cannot set both new grouped asset " +
			"and grouped asset",
		)

	// Using a specific group key or anchor implies disabling emission.
	case req.Asset.NewGroupedAsset:
		if specificGroupKey || specificGroupAnchor {
			return nil, fmt.Errorf("must not create new grouped " +
				"asset to specify an existing group")
		}

	// A group tapscript root cannot be specified if emission is disabled.
	case !req.Asset.NewGroupedAsset && groupTapscriptRootSize != 0:
		return nil, fmt.Errorf("cannot specify a group tapscript root" +
			"when not creating a new grouped asset")

	// A group internal key cannot be specified if emission is disabled.
	case !req.Asset.NewGroupedAsset && specificGroupInternalKey:
		return nil, fmt.Errorf("cannot specify a group internal key" +
			"when not creating a new grouped asset")

	// If the asset is intended to be part of an existing group, a group key
	// or anchor must be specified, but not both. Neither a group tapscript
	// root nor group internal key can be specified.
	case req.Asset.GroupedAsset:
		if !specificGroupKey && !specificGroupAnchor {
			return nil, fmt.Errorf("must specify a group key or" +
				"group anchor")
		}

		if specificGroupKey && specificGroupAnchor {
			return nil, fmt.Errorf("cannot specify both a group " +
				"key and a group anchor")
		}

		if groupTapscriptRootSize != 0 {
			return nil, fmt.Errorf("cannot specify a group " +
				"tapscript root when not creating a new " +
				"grouped asset")
		}

		if specificGroupInternalKey {
			return nil, fmt.Errorf("cannot specify a group " +
				"internal key when not creating a new " +
				"grouped asset")
		}

	// A group was specified without GroupedAsset being set.
	case specificGroupKey || specificGroupAnchor:
		return nil, fmt.Errorf("must set grouped asset to mint into " +
			"a specific group")
	}

	assetVersion, err := rpcutils.UnmarshalAssetVersion(
		req.Asset.AssetVersion,
	)
	if err != nil {
		return nil, err
	}

	// If a custom decimal display is set, we require the AssetMeta to be
	// set. That means the user has to at least specify the meta type.
	if req.Asset.DecimalDisplay != 0 && req.Asset.AssetMeta == nil {
		return nil, fmt.Errorf("decimal display requires asset " +
			"metadata")
	}

	// Decimal display doesn't really make sense for collectibles.
	if req.Asset.DecimalDisplay != 0 &&
		req.Asset.AssetType == taprpc.AssetType_COLLECTIBLE {

		return nil, fmt.Errorf("decimal display is not supported for " +
			"collectibles")
	}

	// TODO(ffranr): Move seedling MetaReveal construction into
	//  ChainPlanter. This will allow us to simplify delegation key
	//  management.
	var seedlingMeta proof.MetaReveal
	switch {
	// If we have an explicit asset meta field, we parse the content.
	case req.Asset.AssetMeta != nil:
		// Ensure that the meta type is valid.
		metaType, err := proof.IsValidMetaType(req.Asset.AssetMeta.Type)
		if err != nil {
			return nil, err
		}

		// If the asset meta field was specified, then the data inside
		// must be valid. Let's check that now.
		seedlingMeta = proof.MetaReveal{
			Data: req.Asset.AssetMeta.Data,
			Type: metaType,
		}

		// Before we set the TLV based decimal display, we first make
		// sure we wouldn't overwrite a custom decimal display in the
		// JSON meta data that has a different value.
		_, jsonDecDisplay, err := seedlingMeta.GetDecDisplay()
		if err == nil && jsonDecDisplay != req.Asset.DecimalDisplay {
			return nil, fmt.Errorf("decimal display in JSON " +
				"asset meta does not match the one in the " +
				"request")
		}

		// We always set the decimal display, even if it is the default
		// value of 0, since we now encode it in the TLV meta data.
		err = seedlingMeta.SetDecDisplay(req.Asset.DecimalDisplay)
		if err != nil {
			return nil, err
		}

	// If no asset meta field was specified, we create a default meta
	// reveal with the decimal display set.
	default:
		seedlingMeta = proof.MetaReveal{
			Type: proof.MetaOpaque,
		}

		// We always set the decimal display, even if it is the default
		// value of 0, since we now encode it in the TLV meta data.
		err = seedlingMeta.SetDecDisplay(req.Asset.DecimalDisplay)
		if err != nil {
			return nil, err
		}
	}

	// Parse the optional script key and group internal key. The group
	// tapscript root was length-checked above.
	var (
		scriptKey          *asset.ScriptKey
		groupInternalKey   keychain.KeyDescriptor
		groupTapscriptRoot []byte
	)
	if req.Asset.ScriptKey != nil {
		scriptKey, err = rpcutils.UnmarshalScriptKey(
			req.Asset.ScriptKey,
		)
		if err != nil {
			return nil, err
		}
	}

	if specificGroupInternalKey {
		groupInternalKey, err = rpcutils.UnmarshalKeyDescriptor(
			req.Asset.GroupInternalKey,
		)
		if err != nil {
			return nil, err
		}
	}

	if groupTapscriptRootSize != 0 {
		groupTapscriptRoot = bytes.Clone(req.Asset.GroupTapscriptRoot)
	}

	if req.Asset.ExternalGroupKey != nil &&
		req.Asset.GroupInternalKey != nil {

		return nil, fmt.Errorf("cannot set both external group key " +
			"and group internal key descriptor")
	}

	seedling := &tapgarden.Seedling{
		AssetVersion:        assetVersion,
		AssetType:           asset.Type(req.Asset.AssetType),
		AssetName:           req.Asset.Name,
		Amount:              req.Asset.Amount,
		EnableEmission:      req.Asset.NewGroupedAsset,
		Meta:                &seedlingMeta,
		UniverseCommitments: req.Asset.UniverseCommitments,
	}

	rpcsLog.Infof("[MintAsset]: version=%v, type=%v, name=%v, amt=%v, "+
		"new_grouped_asset=%v", seedling.AssetVersion,
		seedling.AssetType, seedling.AssetName, seedling.Amount,
		seedling.EnableEmission)

	if scriptKey != nil {
		seedling.ScriptKey = *scriptKey
	}

	if specificGroupInternalKey {
		seedling.GroupInternalKey = &groupInternalKey
	}

	if groupTapscriptRootSize != 0 {
		seedling.GroupTapscriptRoot = groupTapscriptRoot
	}

	if req.Asset.ExternalGroupKey != nil {
		externalKey, err := rpcutils.UnmarshalExternalKey(
			req.Asset.ExternalGroupKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse external key: "+
				"%w", err)
		}

		if err := externalKey.Validate(); err != nil {
			return nil, fmt.Errorf("invalid external key: %w", err)
		}

		internalKey, err := externalKey.PubKey()
		if err != nil {
			return nil, fmt.Errorf("unable to derive internal "+
				"group key from xpub: %w", err)
		}

		seedling.ExternalKey = fn.Some(externalKey)
		seedling.GroupInternalKey = &keychain.KeyDescriptor{
			PubKey: &internalKey,
		}
	}

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

	// If a group anchor is provided, propagate the name to the seedling.
	// We cannot do any name validation from outside the minter.
	case specificGroupAnchor:
		seedling.GroupAnchor = &req.Asset.GroupAnchor
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
func checkFeeRateSanity(ctx context.Context, rpcFeeRate chainfee.SatPerKWeight,
	lndWallet lndclient.WalletKitClient) (*chainfee.SatPerKWeight, error) {

	feeFloor := chainfee.FeePerKwFloor
	minRelayFee, err := lndWallet.MinRelayFee(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	// No manual fee rate was set, which is the default.
	case rpcFeeRate == chainfee.SatPerKWeight(0):
		return nil, nil

	// A manual fee was set but is below a reasonable floor or minRelayFee.
	case rpcFeeRate < feeFloor || rpcFeeRate < minRelayFee:
		if rpcFeeRate < feeFloor {
			return nil, fmt.Errorf("manual fee rate below floor: "+
				"(fee_rate=%s, floor=%s)", rpcFeeRate.String(),
				feeFloor.String())
		}
		return nil, fmt.Errorf("feerate does not meet minrelayfee: "+
			"(fee_rate=%s, minrelayfee=%s)", rpcFeeRate.String(),
			minRelayFee.String())

	// Set the fee rate for this transaction.
	default:
		return fn.Ptr(chainfee.SatPerKWeight(rpcFeeRate)), nil
	}
}

// FundBatch attempts to fund the current pending batch.
func (r *rpcServer) FundBatch(ctx context.Context,
	req *mintrpc.FundBatchRequest) (*mintrpc.FundBatchResponse, error) {

	feeRate, err := checkFeeRateSanity(
		ctx, chainfee.SatPerKWeight(req.FeeRate), r.cfg.Lnd.WalletKit,
	)
	if err != nil {
		return nil, err
	}
	feeRateOpt := fn.MaybeSome(feeRate)

	tapTreeOpt, err := rpcutils.UnmarshalTapscriptSibling(
		req.GetFullTree(), req.GetBranch(),
	)
	if err != nil {
		return nil, err
	}

	fundBatchResp, err := r.cfg.AssetMinter.FundBatch(tapgarden.FundParams{
		FeeRate:        feeRateOpt,
		SiblingTapTree: tapTreeOpt,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fund batch: %w", err)
	}

	// If there was no batch to fund, return an empty response.
	if fundBatchResp.Batch == nil {
		return &mintrpc.FundBatchResponse{}, nil
	}

	rpcBatch, err := marshalVerboseBatch(
		*r.cfg.ChainParams.Params, fundBatchResp.Batch,
		!req.ShortResponse, req.ShortResponse,
	)
	if err != nil {
		return nil, err
	}

	return &mintrpc.FundBatchResponse{
		Batch: rpcBatch,
	}, nil
}

// UnmarshalGroupWitness parses an asset group witness from the RPC variant.
func UnmarshalGroupWitness(
	wit *taprpc.GroupWitness) (*tapgarden.PendingGroupWitness, error) {

	if len(wit.GenesisId) != sha256.Size {
		return nil, fmt.Errorf("invalid genesis id length: "+
			"%d, %x", len(wit.GenesisId), wit.GenesisId)
	}

	// Assert that a given witness stack does not exceed the limit used by
	// the VM.
	witSize := 0
	for _, witItem := range wit.Witness {
		witSize += len(witItem)
	}

	if witSize > blockchain.MaxBlockWeight {
		return nil, fmt.Errorf("asset group witness too large: %d",
			witSize)
	}

	return &tapgarden.PendingGroupWitness{
		GenID:   asset.ID(wit.GenesisId),
		Witness: wit.Witness,
	}, nil
}

// SealBatch attempts to seal the current pending batch, validating provided
// asset group witnesses and generating asset group witnesses as needed.
func (r *rpcServer) SealBatch(ctx context.Context,
	req *mintrpc.SealBatchRequest) (*mintrpc.SealBatchResponse, error) {

	// Unmarshal group witnesses from the request.
	var groupWitnesses []tapgarden.PendingGroupWitness
	for i := range req.GroupWitnesses {
		wit, err := UnmarshalGroupWitness(req.GroupWitnesses[i])
		if err != nil {
			return nil, err
		}

		groupWitnesses = append(groupWitnesses, *wit)
	}

	// Unmarshal signed group virtual PSBTs from the request.
	var groupPSBTs []psbt.Packet
	for i := range req.SignedGroupVirtualPsbts {
		groupPsbt := req.SignedGroupVirtualPsbts[i]

		// Decode the signed group virtual PSBT.
		r := bytes.NewReader([]byte(groupPsbt))
		psbtPacket, err := psbt.NewFromRawBytes(r, true)
		if err != nil {
			return nil, fmt.Errorf("unable to parse signed "+
				"group virtual PSBT (signed_psbt=%s): %w",
				groupPsbt, err)
		}

		groupPSBTs = append(groupPSBTs, *psbtPacket)
	}

	batch, err := r.cfg.AssetMinter.SealBatch(
		tapgarden.SealParams{
			GroupWitnesses:          groupWitnesses,
			SignedGroupVirtualPsbts: groupPSBTs,
		},
	)
	if err != nil {
		return nil, err
	}

	rpcBatch, err := marshalMintingBatch(batch, req.ShortResponse)
	if err != nil {
		return nil, err
	}

	return &mintrpc.SealBatchResponse{
		Batch: rpcBatch,
	}, nil
}

// FinalizeBatch attempts to finalize the current pending batch.
func (r *rpcServer) FinalizeBatch(ctx context.Context,
	req *mintrpc.FinalizeBatchRequest) (*mintrpc.FinalizeBatchResponse,
	error) {

	feeRate, err := checkFeeRateSanity(
		ctx, chainfee.SatPerKWeight(req.FeeRate), r.cfg.Lnd.WalletKit,
	)
	if err != nil {
		return nil, err
	}
	feeRateOpt := fn.MaybeSome(feeRate)

	tapTreeOpt, err := rpcutils.UnmarshalTapscriptSibling(
		req.GetFullTree(), req.GetBranch(),
	)
	if err != nil {
		return nil, err
	}

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

	batches, err := r.cfg.AssetMinter.ListBatches(
		tapgarden.ListBatchesParams{
			BatchKey: batchKey,
			Verbose:  req.Verbose,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list batches: %w", err)
	}

	rpcBatches, err := fn.MapErr(
		batches, func(b *tapgarden.VerboseBatch) (*mintrpc.VerboseBatch,
			error) {

			return marshalVerboseBatch(
				*r.cfg.ChainParams.Params, b, req.Verbose,
				false,
			)
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
			ctx, assetID, true, fn.None[asset.ScriptKeyType](),
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
			ctx, groupPubKey, true, fn.None[asset.ScriptKeyType](),
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

	constraints := tapfreighter.CommitmentConstraints{
		MinAmt: req.MinAmount,
		MaxAmt: req.MaxAmount,
	}

	if len(req.GroupKey) > 0 {
		groupKey, err := btcec.ParsePubKey(req.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing group key: %w",
				err)
		}

		constraints.AssetSpecifier = asset.NewSpecifierFromGroupKey(
			*groupKey,
		)
	}

	filters := &tapdb.AssetQueryFilters{
		CommitmentConstraints: constraints,
	}

	if req.ScriptKey != nil {
		scriptKey, err := rpcutils.UnmarshalScriptKey(req.ScriptKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}

		filters.ScriptKey = scriptKey
	}

	if req.AnchorOutpoint != nil {
		txid, err := chainhash.NewHash(req.AnchorOutpoint.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing outpoint: %w",
				err)
		}
		outPoint := &wire.OutPoint{
			Hash:  *txid,
			Index: req.AnchorOutpoint.OutputIndex,
		}

		filters.AnchorPoint = outPoint
	}

	scriptKeyType, includeSpent, err := rpcutils.ParseScriptKeyTypeQuery(
		req.ScriptKeyType,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse script key type "+
			"query: %w", err)
	}
	filters.ScriptKeyType = scriptKeyType

	rpcAssets, err := r.fetchRpcAssets(
		ctx, req.WithWitness, req.IncludeSpent || includeSpent,
		req.IncludeLeased, filters,
	)

	if err != nil {
		return nil, err
	}

	var (
		filteredAssets   []*taprpc.Asset
		unconfirmedMints uint64
	)

	// We now count and filter the assets according to the
	// IncludeUnconfirmedMints flag.
	//
	// TODO(guggero): Do this on the SQL level once we add pagination to the
	// asset list query, as this will no longer work with pagination.
	for idx := range rpcAssets {
		switch {
		// If the asset isn't confirmed yet, we count it but only
		// include it in the output list if the client requested it.
		case rpcAssets[idx].ChainAnchor.BlockHeight == 0:
			unconfirmedMints++

			if req.IncludeUnconfirmedMints {
				filteredAssets = append(
					filteredAssets, rpcAssets[idx],
				)
			}

		// Don't filter out confirmed assets.
		default:
			filteredAssets = append(
				filteredAssets, rpcAssets[idx],
			)
		}
	}

	// We will also report the number of unconfirmed transfers. This is
	// useful for clients as unconfirmed asset coins are not included in the
	// asset list.
	outboundParcels, err := r.cfg.AssetStore.QueryParcels(ctx, nil, true)
	if err != nil {
		return nil, fmt.Errorf("unable to query for unconfirmed "+
			"outgoing parcels: %w", err)
	}

	return &taprpc.ListAssetResponse{
		Assets:               filteredAssets,
		UnconfirmedTransfers: uint64(len(outboundParcels)),
		UnconfirmedMints:     unconfirmedMints,
	}, nil
}

func (r *rpcServer) fetchRpcAssets(ctx context.Context, withWitness,
	includeSpent, includeLeased bool,
	queryFilters *tapdb.AssetQueryFilters) ([]*taprpc.Asset, error) {

	assets, err := r.cfg.AssetStore.FetchAllAssets(
		ctx, includeSpent, includeLeased, queryFilters,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read chain assets: %w", err)
	}

	rpcAssets := make([]*taprpc.Asset, len(assets))
	for i, a := range assets {
		if a == nil {
			return nil, fmt.Errorf("nil asset at index %d", i)
		}

		rpcAssets[i], err = r.MarshalChainAsset(
			ctx, *a, nil, withWitness, r.cfg.AddrBook,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal asset: %w",
				err)
		}
	}

	return rpcAssets, nil
}

// MarshalChainAsset marshals the given chain asset into an RPC asset.
func (r *rpcServer) MarshalChainAsset(ctx context.Context, a asset.ChainAsset,
	meta *proof.MetaReveal, withWitness bool,
	keyRing rpcutils.KeyLookup) (*taprpc.Asset, error) {

	var (
		decDisplay fn.Option[uint32]
		err        error
	)

	// If the asset metadata is provided, we don't need to look it up from
	// the database when decoding a decimal display value.
	switch {
	case meta != nil:
		decDisplay, err = meta.DecDisplayOption()
	default:
		decDisplay, err = r.DecDisplayForAssetID(ctx, a.ID())
	}
	if err != nil {
		return nil, err
	}

	// Ensure the block timestamp is set if a block height is set.
	if a.AnchorBlockTimestamp == 0 && a.AnchorBlockHeight > 0 {
		a.AnchorBlockTimestamp = r.cfg.ChainBridge.GetBlockTimestamp(
			ctx, a.AnchorBlockHeight,
		)
	}

	return rpcutils.MarshalChainAsset(
		ctx, a, decDisplay, withWitness, keyRing,
	)
}

func (r *rpcServer) listBalancesByAsset(ctx context.Context,
	assetID *asset.ID, includeLeased bool,
	skt fn.Option[asset.ScriptKeyType]) (*taprpc.ListBalancesResponse,
	error) {

	balances, err := r.cfg.AssetStore.QueryBalancesByAsset(
		ctx, assetID, includeLeased, skt,
	)
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
	groupKey *btcec.PublicKey, includeLeased bool,
	skt fn.Option[asset.ScriptKeyType]) (*taprpc.ListBalancesResponse,
	error) {

	balances, err := r.cfg.AssetStore.QueryAssetBalancesByGroup(
		ctx, groupKey, includeLeased, skt,
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

	scriptKeyType, includeSpent, err := rpcutils.ParseScriptKeyTypeQuery(
		req.ScriptKeyType,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse script key type "+
			"query: %w", err)
	}

	filters := &tapdb.AssetQueryFilters{
		CommitmentConstraints: tapfreighter.CommitmentConstraints{
			ScriptKeyType: scriptKeyType,
		},
	}

	rpcAssets, err := r.fetchRpcAssets(
		ctx, false, includeSpent, req.IncludeLeased, filters,
	)
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
			LeaseOwner:       u.LeaseOwner[:],
			LeaseExpiryUnix:  u.LeaseExpiry.Unix(),
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

		assetVersion, err := rpcutils.MarshalAssetVersion(
			a.Version,
		)
		if err != nil {
			return nil, err
		}

		rpcAsset := &taprpc.AssetHumanReadable{
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
			groupsWithAssets[groupKey].Assets, rpcAsset,
		)
	}

	return &taprpc.ListGroupsResponse{Groups: groupsWithAssets}, nil
}

// ListBalances lists the asset balances owned by the daemon.
func (r *rpcServer) ListBalances(ctx context.Context,
	req *taprpc.ListBalancesRequest) (*taprpc.ListBalancesResponse, error) {

	scriptKeyType, _, err := rpcutils.ParseScriptKeyTypeQuery(
		req.ScriptKeyType,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse script key type "+
			"query: %w", err)
	}

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

		return r.listBalancesByAsset(
			ctx, assetID, req.IncludeLeased, scriptKeyType,
		)

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

		return r.listBalancesByGroupKey(
			ctx, groupKey, req.IncludeLeased, scriptKeyType,
		)

	default:
		return nil, fmt.Errorf("invalid group_by")
	}
}

// ListTransfers returns a list of all asset transfers managed by this daemon.
// This includes both confirmed and unconfirmed transfers.
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

	addrs := make([]*taprpc.Addr, len(dbAddrs))
	for i, dbAddr := range dbAddrs {
		// TODO(roasbeef): just stop storing the hrp in the addr?
		dbAddr.ChainParams = &r.cfg.ChainParams

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

	assetVersion, err := rpcutils.UnmarshalAssetVersion(req.AssetVersion)
	if err != nil {
		return nil, err
	}

	addrVersion, err := address.UnmarshalVersion(req.AddressVersion)
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
			ctx, addrVersion, assetID, req.Amt, tapscriptSibling,
			*courierAddr, address.WithAssetVersion(assetVersion),
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
		scriptKey, err := rpcutils.UnmarshalScriptKey(req.ScriptKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}

		// If a script key was specified, it needs to contain the full
		// key descriptor.
		if scriptKey.TweakedScriptKey == nil {
			return nil, fmt.Errorf("script key must contain the " +
				"full tweaked key descriptor")
		}

		rpcsLog.Debugf("Decoded script key %x (internal %x, tweak %x)",
			scriptKey.PubKey.SerializeCompressed(),
			scriptKey.RawKey.PubKey.SerializeCompressed(),
			scriptKey.Tweak[:])

		internalKey, err := rpcutils.UnmarshalKeyDescriptor(
			req.InternalKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode internal "+
				"key: %w", err)
		}

		// Now that we have all the params, we'll try to add a new
		// address to the addr book.
		addr, err = r.cfg.AddrBook.NewAddressWithKeys(
			ctx, addrVersion, assetID, req.Amt, *scriptKey,
			internalKey, tapscriptSibling, *courierAddr,
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

	addr, err := address.DecodeAddress(req.Addr, &r.cfg.ChainParams)
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

	proofFile, err := proof.DecodeFile(req.RawProofFile)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: r.cfg.ChainBridge,
	}

	_, err = proofFile.Verify(ctx, vCtx)
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

	var rpcProof *taprpc.DecodedProof
	switch {
	case proof.IsSingleProof(req.RawProof):
		p, err := proof.Decode(req.RawProof)
		if err != nil {
			return nil, fmt.Errorf("unable to decode proof: %w",
				err)
		}

		rpcProof, err = r.marshalProof(
			ctx, p, req.WithPrevWitnesses, req.WithMetaReveal,
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

		proofFile, err := proof.DecodeFile(req.RawProof)
		if err != nil {
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

// UnpackProofFile unpacks a proof file into a list of the individual raw
// proofs in the proof chain.
func (r *rpcServer) UnpackProofFile(_ context.Context,
	req *taprpc.UnpackProofFileRequest) (*taprpc.UnpackProofFileResponse,
	error) {

	blob := proof.Blob(req.RawProofFile)
	file, err := blob.AsFile()
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	proofBlobs := make([][]byte, file.NumProofs())
	for i := 0; i < file.NumProofs(); i++ {
		proofBlobs[i], err = file.RawProofAt(uint32(i))
		if err != nil {
			return nil, fmt.Errorf("unable to extract proof: %w",
				err)
		}
	}

	return &taprpc.UnpackProofFileResponse{
		RawProofs: proofBlobs,
	}, nil
}

// marshalProof turns a transition proof into an RPC DecodedProof.
func (r *rpcServer) marshalProof(ctx context.Context, p *proof.Proof,
	withPrevWitnesses, withMetaReveal bool) (*taprpc.DecodedProof, error) {

	var (
		rpcMeta        *taprpc.AssetMeta
		rpcGenesis     = p.GenesisReveal
		rpcGroupKey    = p.GroupKeyReveal
		txMerkleProof  = p.TxMerkleProof
		inclusionProof = p.InclusionProof
		splitRootProof = p.SplitRootProof
		altLeaves      = p.AltLeaves
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

	var exclusionProofs [][]byte
	for _, exclusionProof := range p.ExclusionProofs {
		var exclusionProofBuf bytes.Buffer
		err := exclusionProof.Encode(&exclusionProofBuf)
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
		err := splitRootProof.Encode(&splitRootProofBuf)
		if err != nil {
			return nil, fmt.Errorf("unable to encode split root "+
				"proof: %w", err)
		}
	}

	var altLeavesBuf bytes.Buffer
	if len(altLeaves) > 0 {
		var scratch [8]byte

		err := asset.AltLeavesEncoder(
			&altLeavesBuf, &altLeaves, &scratch,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to encode alt leaves: "+
				"%w", err)
		}
	}

	chainAsset, err := p.ToChainAsset()
	if err != nil {
		return nil, fmt.Errorf("unable to convert proof to chain "+
			"asset: %w", err)
	}

	rpcAsset, err := r.MarshalChainAsset(
		ctx, chainAsset, p.MetaReveal, withPrevWitnesses,
		r.cfg.AddrBook,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal chain asset: %w",
			err)
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
		rawKey := rpcGroupKey.RawKey()
		GroupKeyReveal = taprpc.GroupKeyReveal{
			RawGroupKey:   rawKey[:],
			TapscriptRoot: rpcGroupKey.TapscriptRoot(),
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
		AltLeaves:           altLeavesBuf.Bytes(),
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
	proofFile, err := proof.DecodeFile(req.ProofFile)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof file: %w", err)
	}

	lastProof, err := proofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("error extracting last proof: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: r.cfg.ChainBridge,
	}

	// Now that we know the proof file is at least present, we'll attempt
	// to import it into the main archive.
	err = r.cfg.ProofArchive.ImportProofs(
		ctx, vCtx, false, &proof.AnnotatedProof{
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
		addr, err := address.DecodeAddress(
			req.FilterAddr, &r.cfg.ChainParams,
		)
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

	scriptKeyType, err := unmarshalCoinSelectType(req.CoinSelectType)
	if err != nil {
		return nil, fmt.Errorf("error parsing coin select type: %w",
			err)
	}

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

		desc.ScriptKeyType = scriptKeyType
		fundedVPkt, err = r.cfg.AssetWallet.FundPacket(ctx, desc, vPkt)
		if err != nil {
			return nil, fmt.Errorf("error funding packet: %w", err)
		}

	case req.GetRaw() != nil:
		var (
			raw     = req.GetRaw()
			prevIDs []asset.PrevID
		)
		for i, input := range raw.Inputs {
			if input.Outpoint == nil {
				return nil, fmt.Errorf("input at index %d has "+
					"a nil Outpoint", i)
			}

			hash, err := chainhash.NewHash(input.Outpoint.Txid)
			if err != nil {
				return nil, fmt.Errorf("input at index %d has "+
					"invalid Txid: %w", i, err)
			}

			scriptKey, err := parseUserKey(input.ScriptKey)
			if err != nil {
				return nil, fmt.Errorf("input at index %d has "+
					"invalid script key: %w", i, err)
			}

			if len(input.Id) != 32 {
				return nil, fmt.Errorf("input at index %d has "+
					"invalid asset ID of %d bytes, must "+
					"be 32 bytes", i, len(input.Id))
			}

			// Decode the input into an asset.PrevID.
			outpoint := wire.OutPoint{
				Hash:  *hash,
				Index: input.Outpoint.OutputIndex,
			}
			prevID := asset.PrevID{
				OutPoint: outpoint,
				ID:       asset.ID(input.Id),
				ScriptKey: asset.ToSerialized(
					scriptKey,
				),
			}
			prevIDs = append(prevIDs, prevID)
		}
		if len(raw.Recipients) > 1 {
			return nil, fmt.Errorf("only one recipient supported")
		}

		var (
			addr *address.Tap
			err  error
		)
		for a := range raw.Recipients {
			addr, err = address.DecodeAddress(a, &r.cfg.ChainParams)
			if err != nil {
				return nil, fmt.Errorf("unable to decode "+
					"addr: %w", err)
			}
		}

		if addr == nil {
			return nil, fmt.Errorf("no recipients specified")
		}

		fundedVPkt, err = r.cfg.AssetWallet.FundAddressSend(
			ctx, scriptKeyType, prevIDs, addr,
		)
		if err != nil {
			return nil, fmt.Errorf("error funding address send: "+
				"%w", err)
		}

	default:
		return nil, fmt.Errorf("either PSBT or raw template must be " +
			"specified")
	}

	// Extract the passive assets that are needed for the fully RPC driven
	// flow.
	passivePackets, err := r.cfg.AssetWallet.CreatePassiveAssets(
		ctx, fundedVPkt.VPackets, fundedVPkt.InputCommitments,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating passive assets: %w", err)
	}

	// Serialize the active and passive packets into the response now.
	response := &wrpc.FundVirtualPsbtResponse{
		PassiveAssetPsbts: make([][]byte, len(passivePackets)),
		ChangeOutputIndex: 0,
	}
	for idx := range passivePackets {
		response.PassiveAssetPsbts[idx], err = serialize(
			passivePackets[idx],
		)
		if err != nil {
			return nil, fmt.Errorf("error serializing passive "+
				"packet: %w", err)
		}
	}

	// TODO(guggero): Remove this once we support multiple packets.
	if len(fundedVPkt.VPackets) > 1 {
		return nil, fmt.Errorf("only one packet supported")
	}

	response.FundedPsbt, err = serialize(fundedVPkt.VPackets[0])
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return response, nil
}

// unmarshalCoinSelectType converts an RPC select type into a script key type
// that can be used to select the appropriate inputs.
func unmarshalCoinSelectType(
	coinSelectType wrpc.CoinSelectType) (fn.Option[asset.ScriptKeyType],
	error) {

	switch coinSelectType {
	case wrpc.CoinSelectType_COIN_SELECT_DEFAULT,
		wrpc.CoinSelectType_COIN_SELECT_SCRIPT_TREES_ALLOWED:

		return fn.None[asset.ScriptKeyType](), nil

	case wrpc.CoinSelectType_COIN_SELECT_BIP86_ONLY:
		return fn.Some(asset.ScriptKeyBip86), nil

	default:
		return fn.None[asset.ScriptKeyType](), fmt.Errorf("unknown "+
			"coin select type: %d", coinSelectType)
	}
}

// SignVirtualPsbt signs the inputs of a virtual transaction and prepares the
// commitments of the inputs and outputs.
func (r *rpcServer) SignVirtualPsbt(ctx context.Context,
	req *wrpc.SignVirtualPsbtRequest) (*wrpc.SignVirtualPsbtResponse,
	error) {

	if req.FundedPsbt == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	vPkt, err := tappsbt.Decode(req.FundedPsbt)
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

	signedPsbtBytes, err := serialize(vPkt)
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return &wrpc.SignVirtualPsbtResponse{
		SignedPsbt:   signedPsbtBytes,
		SignedInputs: signedInputs,
	}, nil
}

// AnchorVirtualPsbts merges and then commits multiple virtual transactions in
// a single BTC level anchor transaction.
func (r *rpcServer) AnchorVirtualPsbts(ctx context.Context,
	req *wrpc.AnchorVirtualPsbtsRequest) (*taprpc.SendAssetResponse,
	error) {

	if len(req.VirtualPsbts) == 0 {
		return nil, fmt.Errorf("no virtual PSBTs specified")
	}

	vPackets := make([]*tappsbt.VPacket, len(req.VirtualPsbts))
	for idx := range req.VirtualPsbts {
		var err error
		vPackets[idx], err = tappsbt.Decode(req.VirtualPsbts[idx])
		if err != nil {
			return nil, fmt.Errorf("error decoding packet %d: %w",
				idx, err)
		}
	}

	// Query the asset store to gather tap commitments for all inputs.
	inputCommitments := make(tappsbt.InputCommitments, len(vPackets))
	for _, vPkt := range vPackets {
		for idx := range vPkt.Inputs {
			input := vPkt.Inputs[idx]

			inputAsset := input.Asset()
			prevID := input.PrevID

			// If we've previously fetched the commitment for a prev
			// ID we can skip it, as we know it's going to be
			// identical.
			if _, ok := inputCommitments[prevID]; ok {
				continue
			}

			store := r.cfg.AssetStore

			inputCommitment, err := store.FetchCommitment(
				ctx, inputAsset.ID(), prevID.OutPoint,
				inputAsset.GroupKey, &inputAsset.ScriptKey,
				true,
			)
			if err != nil {
				return nil, fmt.Errorf("error fetching input "+
					"commitment: %w", err)
			}

			inputCommitments[prevID] = inputCommitment.Commitment
		}
	}

	rpcsLog.Debugf("Selected %d input commitments for send of %d virtual "+
		"transactions", len(inputCommitments), len(vPackets))
	for prevID := range inputCommitments {
		rpcsLog.Tracef("Selected input %v for send",
			prevID.OutPoint.String())
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewPreSignedParcel(vPackets, inputCommitments, ""),
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

// CommitVirtualPsbts creates the output commitments and proofs for the given
// virtual transactions by committing them to the BTC level anchor transaction.
// In addition, the BTC level anchor transaction is funded and prepared up to
// the point where it is ready to be signed.
func (r *rpcServer) CommitVirtualPsbts(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest) (*wrpc.CommitVirtualPsbtsResponse,
	error) {

	if len(req.VirtualPsbts) == 0 {
		return nil, fmt.Errorf("no virtual PSBTs specified")
	}

	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(req.AnchorPsbt), false)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	activePackets, err := decodeVirtualPackets(req.VirtualPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding active packets: %w", err)
	}

	passivePackets, err := decodeVirtualPackets(req.PassiveAssetPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding passive packets: %w",
			err)
	}

	// Make sure the assets given fully satisfy the input commitments.
	allPackets := append([]*tappsbt.VPacket{}, activePackets...)
	allPackets = append(allPackets, passivePackets...)
	err = r.validateInputAssets(ctx, pkt, allPackets)
	if err != nil {
		return nil, fmt.Errorf("error validating input assets: %w", err)
	}

	// We're ready to attempt to fund the transaction now. For that we first
	// need to re-serialize our packet.
	packetBytes, err := serialize(pkt)
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	// The change output and fee parameters of this RPC are identical to the
	// walletrpc.FundPsbt, so we just map them 1:1 and let lnd do the
	// validation.
	coinSelect := &walletrpc.PsbtCoinSelect{
		Psbt: packetBytes,
	}
	fundRequest := &walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: coinSelect,
		},
		MinConfs:              1,
		ChangeType:            P2TRChangeType,
		CustomLockId:          req.CustomLockId,
		LockExpirationSeconds: req.LockExpirationSeconds,
	}

	// Unfortunately we can't use the same RPC types, so we have to do a
	// 1:1 mapping to the walletrpc types for the anchor change output and
	// fee "oneof" fields.
	type existingIndex = walletrpc.PsbtCoinSelect_ExistingOutputIndex
	switch change := req.AnchorChangeOutput.(type) {
	case *wrpc.CommitVirtualPsbtsRequest_ExistingOutputIndex:
		coinSelect.ChangeOutput = &existingIndex{
			ExistingOutputIndex: change.ExistingOutputIndex,
		}

	case *wrpc.CommitVirtualPsbtsRequest_Add:
		coinSelect.ChangeOutput = &walletrpc.PsbtCoinSelect_Add{
			Add: change.Add,
		}

	default:
		return nil, fmt.Errorf("unknown change output type")
	}

	switch fee := req.Fees.(type) {
	case *wrpc.CommitVirtualPsbtsRequest_TargetConf:
		fundRequest.Fees = &walletrpc.FundPsbtRequest_TargetConf{
			TargetConf: fee.TargetConf,
		}

	case *wrpc.CommitVirtualPsbtsRequest_SatPerVbyte:
		fundRequest.Fees = &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: fee.SatPerVbyte,
		}

	default:
		return nil, fmt.Errorf("unknown fee type")
	}

	lndWallet := r.cfg.Lnd.WalletKit
	fundedPacket, changeIndex, lockedUTXO, err := lndWallet.FundPsbt(
		ctx, fundRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("error funding packet: %w", err)
	}

	lockedOutpoints := fn.Map(
		lockedUTXO, func(utxo *walletrpc.UtxoLease) wire.OutPoint {
			var hash chainhash.Hash
			copy(hash[:], utxo.Outpoint.TxidBytes)
			return wire.OutPoint{
				Hash:  hash,
				Index: utxo.Outpoint.OutputIndex,
			}
		},
	)

	// From now on, if we error out, we need to make sure we unlock the
	// UTXOs that lnd just locked for us.
	success := false
	defer func() {
		if !success {
			for idx, utxo := range lockedUTXO {
				var lockID wtxmgr.LockID
				copy(lockID[:], utxo.Id)

				op := lockedOutpoints[idx]
				err := lndWallet.ReleaseOutput(ctx, lockID, op)
				if err != nil {
					rpcsLog.Errorf("Error unlocking lnd "+
						"UTXO %v: %v", op, err)
				}
			}
		}
	}()

	// We can now update the anchor outputs as we have the final
	// commitments.
	outputCommitments, err := tapsend.CreateOutputCommitments(allPackets)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			fundedPacket, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot output "+
				"keys: %w", err)
		}
	}

	// We're done creating the output commitments, we can now create the
	// transition proof suffixes.
	for idx := range allPackets {
		vPkt := allPackets[idx]

		for vOutIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffix(
				fundedPacket.UnsignedTx, fundedPacket.Outputs,
				vPkt, outputCommitments, vOutIdx, allPackets,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"proof suffix for output %d of vPSBT "+
					"%d: %w", vOutIdx, idx, err)
			}

			vPkt.Outputs[vOutIdx].ProofSuffix = proofSuffix
		}
	}

	// We can now prepare the full answer, beginning with the serialized
	// final packet.
	response := &wrpc.CommitVirtualPsbtsResponse{
		ChangeOutputIndex: changeIndex,
	}

	response.AnchorPsbt, err = serialize(fundedPacket)
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	// Serialize the final active and passive virtual packets.
	response.VirtualPsbts, err = encodeVirtualPackets(activePackets)
	if err != nil {
		return nil, fmt.Errorf("error encoding active packets: %w", err)
	}
	response.PassiveAssetPsbts, err = encodeVirtualPackets(passivePackets)
	if err != nil {
		return nil, fmt.Errorf("error encoding passive packets: %w",
			err)
	}

	// And finally, we need to also return the locked UTXOs. We just return
	// the outpoint, as any additional information can be fetched from the
	// lnd wallet directly (we don't want to create pass-through RPCs for
	// all those methods).
	response.LndLockedUtxos = make([]*taprpc.OutPoint, len(lockedOutpoints))
	for idx := range lockedOutpoints {
		response.LndLockedUtxos[idx] = &taprpc.OutPoint{
			Txid:        lockedOutpoints[idx].Hash[:],
			OutputIndex: lockedOutpoints[idx].Index,
		}
	}

	// We were successful, let's cancel the UTXO release in the defer.
	success = true

	return response, nil
}

// validateInputAssets makes sure that the input assets are correct and their
// combined commitments match the inputs of the BTC level anchor transaction.
func (r *rpcServer) validateInputAssets(ctx context.Context,
	btcPkt *psbt.Packet, vPackets []*tappsbt.VPacket) error {

	err := tapsend.ValidateVPacketVersions(vPackets)
	if err != nil {
		return err
	}

	// Make sure we decorate all asset inputs with the correct internal key
	// derivation path (if it's indeed a key this daemon owns).
	for idx := range btcPkt.Inputs {
		pIn := &btcPkt.Inputs[idx]

		// We only care about asset inputs which always specify a
		// Taproot merkle root.
		if len(pIn.TaprootMerkleRoot) == 0 {
			continue
		}

		// We can't query the internal key if there is none specified.
		if len(pIn.TaprootInternalKey) != schnorr.PubKeyBytesLen {
			continue
		}

		// If we already have the derivation info, we can skip this
		// input.
		if len(pIn.TaprootBip32Derivation) > 0 {
			continue
		}

		// Let's query our node for the internal key information now.
		internalKey, keyLocator, err := r.querySchnorrInternalKey(
			ctx, pIn.TaprootInternalKey,
		)

		switch {
		case errors.Is(err, address.ErrInternalKeyNotFound):
			// If the internal key is not known, we can't add the
			// derivation info. Most likely this asset input is not
			// owned by this daemon but another party.
			continue

		case err != nil:
			return fmt.Errorf("error querying internal key: "+
				"%w", err)
		}

		keyDesc := keychain.KeyDescriptor{
			PubKey:     internalKey,
			KeyLocator: keyLocator,
		}
		derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
			keyDesc, r.cfg.ChainParams.HDCoinType,
		)
		pIn.Bip32Derivation = []*psbt.Bip32Derivation{derivation}
		pIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trDerivation,
		}
	}

	// We also want to make sure we actually have the assets that are being
	// spent in our database. We fetch the input commitments of all packets
	// to asset that. And while we're doing that, we also extract all the
	// pruned assets that are not re-created in the outputs, which we need
	// for the final validation. We de-duplicate the pruned assets in a
	// temporary map keyed by input outpoint and the asset commitment key.
	purgedAssetsDeDup := make(map[wire.OutPoint]map[[32]byte]*asset.Asset)
	for _, vPkt := range vPackets {
		for _, vIn := range vPkt.Inputs {
			inputAsset := vIn.Asset()
			outpoint := vIn.PrevID.OutPoint

			input, err := r.cfg.AssetStore.FetchCommitment(
				ctx, inputAsset.ID(), outpoint,
				inputAsset.GroupKey, &inputAsset.ScriptKey,
				true,
			)
			if err != nil {
				// If we can't fetch the input commitment, it
				// means this input asset isn't ours. We cannot
				// find out if there were any purged assets in
				// the commitment, so we just rely on all assets
				// being present. If some purged assets are
				// missing, then the anchor input equality check
				// further down will fail.
				rpcsLog.Warnf("Could not fetch input "+
					"commitment for outpoint %v: %v",
					outpoint, err)

				continue
			}

			assetsToPurge := tapsend.ExtractUnSpendable(
				input.Commitment,
			)
			for _, a := range assetsToPurge {
				key := a.AssetCommitmentKey()
				if purgedAssetsDeDup[outpoint] == nil {
					purgedAssetsDeDup[outpoint] = make(
						map[[32]byte]*asset.Asset,
					)
				}

				purgedAssetsDeDup[outpoint][key] = a
			}
		}
	}

	// With the assets de-duplicated by their asset commitment key, we can
	// now collect them grouped by input outpoint.
	purgedAssets := make(map[wire.OutPoint][]*asset.Asset)
	for outpoint, assets := range purgedAssetsDeDup {
		for key := range assets {
			purgedAssets[outpoint] = append(
				purgedAssets[outpoint], assets[key],
			)
		}
	}

	// At this point all the virtual packet inputs and outputs should fully
	// match the BTC level anchor transaction. Version 0 assets should also
	// be signed now.
	if err := tapsend.AssertInputAnchorsEqual(vPackets); err != nil {
		return fmt.Errorf("input anchors don't match: %w", err)
	}
	if err := tapsend.AssertOutputAnchorsEqual(vPackets); err != nil {
		return fmt.Errorf("output anchors don't match: %w", err)
	}
	err = tapsend.ValidateAnchorInputs(btcPkt, vPackets, purgedAssets)
	if err != nil {
		return fmt.Errorf("error validating anchor inputs: %w", err)
	}

	// Now that we know the packet inputs match the anchored assets, we can
	// also check that we don't inflate or deflate the asset supply with the
	// active and passive assets. We explicitly don't look at the pruned
	// assets. We have already made sure that the total sum of all inputs
	// that was committed to in the input anchor is accounted for with the
	// active, passive and pruned assets. Now we just need to make sure the
	// active and passive transfers don't create or destroy assets.
	inputBalances := make(map[asset.ID]uint64)
	outputBalances := make(map[asset.ID]uint64)
	for _, vPkt := range vPackets {
		for _, vIn := range vPkt.Inputs {
			inputBalances[vIn.Asset().ID()] += vIn.Asset().Amount
		}
		for _, vOut := range vPkt.Outputs {
			outputBalances[vOut.Asset.ID()] += vOut.Asset.Amount
		}
	}
	for assetID, inputBalance := range inputBalances {
		outputBalance := outputBalances[assetID]
		if inputBalance != outputBalance {
			return fmt.Errorf("input and output balances don't "+
				"match for asset %x: %d != %d", assetID[:],
				inputBalance, outputBalance)
		}
	}

	return nil
}

// PublishAndLogTransfer accepts a fully committed and signed anchor transaction
// and publishes it to the Bitcoin network. It also logs the transfer of the
// given active and passive assets in the database and ships any outgoing proofs
// to the counterparties.
func (r *rpcServer) PublishAndLogTransfer(ctx context.Context,
	req *wrpc.PublishAndLogRequest) (*taprpc.SendAssetResponse, error) {

	if len(req.VirtualPsbts) == 0 {
		return nil, fmt.Errorf("no virtual PSBTs specified")
	}

	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(req.AnchorPsbt), false)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	activePackets, err := decodeVirtualPackets(req.VirtualPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding active packets: %w", err)
	}

	passivePackets, err := decodeVirtualPackets(req.PassiveAssetPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding passive packets: %w",
			err)
	}

	// Before we commit the transaction to the database, we want to make
	// sure everything is in order. We start by validating the inputs.
	allPackets := append([]*tappsbt.VPacket{}, activePackets...)
	allPackets = append(allPackets, passivePackets...)
	err = r.validateInputAssets(ctx, pkt, allPackets)
	if err != nil {
		return nil, fmt.Errorf("error validating input assets: %w", err)
	}

	// And then the outputs as well.
	err = tapsend.ValidateAnchorOutputs(pkt, allPackets, true)
	if err != nil {
		return nil, fmt.Errorf("error validating anchor outputs: %w",
			err)
	}

	chainFees, err := pkt.GetTxFee()
	if err != nil {
		return nil, fmt.Errorf("error calculating transaction fees: %w",
			err)
	}

	// The BTC level transaction must be fully complete, and we must be able
	// to extract the final transaction from it.
	finalTx, err := psbt.Extract(pkt)
	if err != nil {
		return nil, fmt.Errorf("error extracting final anchor "+
			"transaction: %w", err)
	}

	anchorTx := &tapsend.AnchorTransaction{
		FundedPsbt: &tapsend.FundedPsbt{
			Pkt:               pkt,
			ChangeOutputIndex: req.ChangeOutputIndex,
			ChainFees:         int64(chainFees),
			LockedUTXOs: make(
				[]wire.OutPoint, len(req.LndLockedUtxos),
			),
		},
		ChainFees: int64(chainFees),
		FinalTx:   finalTx,
	}
	for idx, lndOutpoint := range req.LndLockedUtxos {
		hash, err := chainhash.NewHash(lndOutpoint.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing txid: %w", err)
		}

		anchorTx.FundedPsbt.LockedUTXOs[idx] = wire.OutPoint{
			Hash:  *hash,
			Index: lndOutpoint.OutputIndex,
		}
	}

	// We now have everything to ship the pre-anchored parcel using the
	// freighter. This will publish the TX, create the transfer database
	// entries and ship the proofs to the counterparties. It'll also wait
	// for a confirmation and then update the proofs with the block header
	// information.
	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewPreAnchoredParcel(
			activePackets, passivePackets, anchorTx,
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
		InternalKey: rpcutils.MarshalKeyDescriptor(keyDesc),
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
		ScriptKey: rpcutils.MarshalScriptKey(scriptKey),
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
		internalKey, keyLocator, err = r.querySchnorrInternalKey(
			ctx, req.InternalKey,
		)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid internal key length")
	}

	return &wrpc.QueryInternalKeyResponse{
		InternalKey: rpcutils.MarshalKeyDescriptor(
			keychain.KeyDescriptor{
				PubKey:     internalKey,
				KeyLocator: keyLocator,
			},
		),
	}, nil
}

// querySchnorrInternalKey returns the key descriptor for the given internal
// key. This is a special method for the case where the key is a Schnorr key,
// and we need to try both parities.
func (r *rpcServer) querySchnorrInternalKey(ctx context.Context,
	schnorrKey []byte) (*btcec.PublicKey, keychain.KeyLocator, error) {

	var keyLocator keychain.KeyLocator

	internalKey, err := schnorr.ParsePubKey(schnorrKey)
	if err != nil {
		return nil, keyLocator, fmt.Errorf("error parsing internal "+
			"key: %w", err)
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
			return nil, keyLocator, fmt.Errorf("error fetching "+
				"internal key: %w", err)
		}

	// For any other error from above, we'll return it to the user.
	case err != nil:
		return nil, keyLocator, fmt.Errorf("error fetching internal "+
			"key: %w", err)
	}

	return internalKey, keyLocator, nil
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
		ScriptKey: rpcutils.MarshalScriptKey(asset.ScriptKey{
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

	assetVersion, err := rpcutils.MarshalAssetVersion(addr.AssetVersion)
	if err != nil {
		return nil, err
	}

	addrVersion, err := address.MarshalVersion(addr.Version)
	if err != nil {
		return nil, err
	}

	id := addr.AssetID
	rpcAddr := &taprpc.Addr{
		AssetVersion:     assetVersion,
		AddressVersion:   addrVersion,
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
func (r *rpcServer) SendAsset(ctx context.Context,
	req *taprpc.SendAssetRequest) (*taprpc.SendAssetResponse, error) {

	if len(req.TapAddrs) == 0 {
		return nil, fmt.Errorf("at least one addr is required")
	}

	var (
		tapAddrs = make([]*address.Tap, len(req.TapAddrs))
		err      error
	)
	for idx := range req.TapAddrs {
		if req.TapAddrs[idx] == "" {
			return nil, fmt.Errorf("addr %d must be specified", idx)
		}

		tapAddrs[idx], err = address.DecodeAddress(
			req.TapAddrs[idx], &r.cfg.ChainParams,
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

	feeRate, err := checkFeeRateSanity(
		ctx, chainfee.SatPerKWeight(req.FeeRate), r.cfg.Lnd.WalletKit,
	)
	if err != nil {
		return nil, err
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewAddressParcel(
			feeRate, req.Label, req.SkipProofCourierPingCheck,
			tapAddrs...,
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

	assetSpecifier := asset.NewSpecifierOptionalGroupPubKey(
		assetID, groupKey,
	)

	fundResp, err := r.cfg.AssetWallet.FundBurn(
		ctx, &tapsend.FundingDescriptor{
			AssetSpecifier: assetSpecifier,
			Amount:         in.AmountToBurn,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error funding burn: %w", err)
	}

	// We don't support burning by group key yet, so we only expect a single
	// vPacket (which implies a single asset ID is involved).
	if len(fundResp.VPackets) > 1 {
		return nil, fmt.Errorf("only one packet supported")
	}

	// Now we can sign the packet and send it to the chain.
	vPkt := fundResp.VPackets[0]
	_, err = r.cfg.AssetWallet.SignVirtualPacket(vPkt)
	if err != nil {
		return nil, fmt.Errorf("error signing packet: %w", err)
	}

	resp, err := r.cfg.ChainPorter.RequestShipment(
		tapfreighter.NewPreSignedParcel(
			fundResp.VPackets, fundResp.InputCommitments, in.Note,
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
		vOut := vPkt.Outputs[idx]
		tOut := resp.Outputs[idx]
		if vOut.Asset.IsBurn() {
			p, err := proof.Decode(tOut.ProofSuffix)
			if err != nil {
				return nil, fmt.Errorf("error decoding "+
					"burn proof: %w", err)
			}

			burnProof, err = r.marshalProof(ctx, p, true, false)
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

// ListBurns returns a list of burnt assets. Some filters may be defined in the
// request to return more specific results.
func (r *rpcServer) ListBurns(ctx context.Context,
	in *taprpc.ListBurnsRequest) (*taprpc.ListBurnsResponse, error) {

	burns, err := r.cfg.AssetStore.QueryBurns(
		ctx, tapdb.QueryBurnsFilters{
			AssetID:    in.AssetId,
			GroupKey:   in.TweakedGroupKey,
			AnchorTxid: in.AnchorTxid,
		},
	)
	if err != nil {
		return nil, err
	}

	rpcBurns := fn.Map(burns, marshalRpcBurn)

	return &taprpc.ListBurnsResponse{
		Burns: rpcBurns,
	}, nil
}

// marshalRpcBurn creates an instance of *taprpc.AssetBurn from the tapdb model.
func marshalRpcBurn(b *tapfreighter.AssetBurn) *taprpc.AssetBurn {
	return &taprpc.AssetBurn{
		Note:            b.Note,
		AssetId:         b.AssetID,
		TweakedGroupKey: b.GroupKey,
		Amount:          b.Amount,
		AnchorTxid:      b.AnchorTxid[:],
	}
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
			PkScript:         out.Anchor.PkScript,
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

		assetVersion, err := rpcutils.MarshalAssetVersion(
			out.AssetVersion,
		)
		if err != nil {
			return nil, err
		}

		var proofAsset asset.Asset
		err = proof.SparseDecode(
			bytes.NewReader(out.ProofSuffix),
			proof.AssetLeafRecord(&proofAsset),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sparse decode "+
				"proof: %w", err)
		}

		// Marshall the proof delivery status.
		proofDeliveryStatus := marshalOutputProofDeliveryStatus(out)

		rpcOutputs[idx] = &taprpc.TransferOutput{
			Anchor:              rpcAnchor,
			ScriptKey:           scriptPubKey.SerializeCompressed(),
			ScriptKeyIsLocal:    out.ScriptKeyLocal,
			Amount:              out.Amount,
			LockTime:            out.LockTime,
			RelativeLockTime:    out.RelativeLockTime,
			NewProofBlob:        out.ProofSuffix,
			SplitCommitRootHash: splitCommitRoot,
			OutputType:          rpcOutType,
			AssetVersion:        assetVersion,
			ProofDeliveryStatus: proofDeliveryStatus,
			AssetId:             fn.ByteSlice(proofAsset.ID()),
		}
	}

	anchorTxHash := parcel.AnchorTx.TxHash()

	// Marshal the anchor tx block hash into its RPC counterpart.
	var anchorTxBlockHash *taprpc.ChainHash
	parcel.AnchorTxBlockHash.WhenSome(func(hash chainhash.Hash) {
		anchorTxBlockHash = &taprpc.ChainHash{
			Hash:    hash[:],
			HashStr: hash.String(),
		}
	})

	return &taprpc.AssetTransfer{
		TransferTimestamp:   parcel.TransferTime.Unix(),
		AnchorTxHash:        anchorTxHash[:],
		AnchorTxHeightHint:  parcel.AnchorTxHeightHint,
		AnchorTxChainFees:   parcel.ChainFees,
		AnchorTxBlockHash:   anchorTxBlockHash,
		AnchorTxBlockHeight: parcel.AnchorTxBlockHeight,
		Inputs:              rpcInputs,
		Outputs:             rpcOutputs,
		Label:               parcel.Label,
	}, nil
}

// marshalOutputProofDeliveryStatus turns the output proof delivery status into
// the RPC counterpart.
func marshalOutputProofDeliveryStatus(
	out tapfreighter.TransferOutput) taprpc.ProofDeliveryStatus {

	proofDeliveryStatus := rpcutils.ProofDeliveryStatusNotApplicable
	out.ProofDeliveryComplete.WhenSome(func(complete bool) {
		if complete {
			proofDeliveryStatus =
				rpcutils.ProofDeliveryStatusComplete
		} else {
			proofDeliveryStatus =
				rpcutils.ProofDeliveryStatusPending
		}
	})

	return proofDeliveryStatus
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
	_ *tapdevrpc.SubscribeSendAssetEventNtfnsRequest,
	ntfnStream devSendEventStream) error {

	filter := func(event fn.Event) (bool, error) {
		return true, nil
	}

	return handleEvents[bool, *tapdevrpc.SendAssetEvent](
		r.cfg.ChainPorter, ntfnStream, marshallSendAssetEvent, filter,
		r.quit, false,
	)
}

// SubscribeReceiveAssetEventNtfns registers a subscription to the event
// notification stream which relates to the asset receiving process.
func (r *rpcServer) SubscribeReceiveAssetEventNtfns(
	_ *tapdevrpc.SubscribeReceiveAssetEventNtfnsRequest,
	ntfnStream devReceiveEventStream) error {

	marshaler := func(event fn.Event) (*tapdevrpc.ReceiveAssetEvent, error) {
		return marshallReceiveAssetEvent(
			event, r.cfg.TapAddrBook,
		)
	}

	filter := func(event fn.Event) (bool, error) {
		switch e := event.(type) {
		case *proof.BackoffWaitEvent:
			return true, nil

		case *tapgarden.AssetReceiveEvent:
			return e.Status == address.StatusCompleted, nil

		default:
			return false, fmt.Errorf("unknown event type: %T", e)
		}
	}

	return handleEvents[time.Time, *tapdevrpc.ReceiveAssetEvent](
		r.cfg.AssetCustodian, ntfnStream, marshaler, filter, r.quit,
		time.Time{},
	)
}

// SubscribeReceiveEvents registers a subscription to the event notification
// stream which relates to the asset receiving process.
func (r *rpcServer) SubscribeReceiveEvents(
	req *taprpc.SubscribeReceiveEventsRequest,
	ntfnStream receiveEventStream) error {

	tapParams := address.ParamsForChain(r.cfg.ChainParams.Name)

	var deliverFrom time.Time
	if req.StartTimestamp != 0 {
		// The request timestamp is in microseconds, same as the event
		// timestamp we return.
		startTimestampNano := req.StartTimestamp * 1000
		deliverFrom = time.Unix(0, startTimestampNano)
	}

	// We just decode the address to make sure it's valid. But any
	// comparison for filtering happens on the string representation, as
	// that's easily comparable
	var addrString string
	if req.FilterAddr != "" {
		addr, err := address.DecodeAddress(req.FilterAddr, &tapParams)
		if err != nil {
			return fmt.Errorf("error decoding address: %w", err)
		}

		addrString, err = addr.EncodeAddress()
		if err != nil {
			return fmt.Errorf("error encoding address: %w", err)
		}
	}

	marshaler := func(event fn.Event) (*taprpc.ReceiveEvent, error) {
		e, ok := event.(*tapgarden.AssetReceiveEvent)
		if !ok {
			return nil, fmt.Errorf("invalid event type: %T", event)
		}

		rpcAddr, err := marshalAddr(&e.Address, r.cfg.TapAddrBook)
		if err != nil {
			return nil, fmt.Errorf("error marshaling addr: %w", err)
		}

		rpcStatus, err := marshalAddrEventStatus(e.Status)
		if err != nil {
			return nil, fmt.Errorf("error marshaling status: %w",
				err)
		}

		var errString string
		if e.Error != nil {
			errString = e.Error.Error()
		}

		return &taprpc.ReceiveEvent{
			Timestamp:          e.Timestamp().UnixMicro(),
			Address:            rpcAddr,
			Outpoint:           e.OutPoint.String(),
			Status:             rpcStatus,
			ConfirmationHeight: e.ConfirmationHeight,
			Error:              errString,
		}, nil
	}

	filter := func(event fn.Event) (bool, error) {
		var (
			eventAddrString string
			err             error
		)

		switch e := event.(type) {
		case *tapgarden.AssetReceiveEvent:
			eventAddrString, err = e.Address.EncodeAddress()
			if err != nil {
				return false, fmt.Errorf("error encoding "+
					"address: %w", err)
			}

		case *proof.BackoffWaitEvent:
			// We're not interested in any backoff events.
			return false, nil

		default:
			return false, fmt.Errorf("unknown event type: %T", e)
		}

		// If we're not filtering on a specific address, we return all
		// events.
		if addrString == "" {
			return true, nil
		}

		return eventAddrString == addrString, nil
	}

	return handleEvents[time.Time, *taprpc.ReceiveEvent](
		r.cfg.AssetCustodian, ntfnStream, marshaler, filter, r.quit,
		deliverFrom,
	)
}

// shouldNotifyAssetSendEvent returns true if the given AssetSendEvent matches
// all specified filter criteria. Unset filter values are ignored. If set, all
// filters must match (logical AND).
func shouldNotifyAssetSendEvent(event tapfreighter.AssetSendEvent,
	targetScriptKey fn.Option[btcec.PublicKey], targetLabel string) bool {

	// By default, if no filter values are provided, match on event.
	match := true

	// Filter by label if specified.
	if targetLabel != "" {
		match = match && (event.TransferLabel == targetLabel)
	}

	// Filter by target script key if specified.
	if targetScriptKey.IsSome() {
		// If script key is specified but there are no virtual packets,
		// early return as a match is impossible.
		if len(event.VirtualPackets) == 0 {
			return false
		}

		scriptKey := targetScriptKey.UnwrapToPtr()
		found := false

		for _, vPacket := range event.VirtualPackets {
			if found {
				break
			}

			for _, vOut := range vPacket.Outputs {
				if vOut.ScriptKey.PubKey == nil {
					continue
				}
				if vOut.ScriptKey.PubKey.IsEqual(scriptKey) {
					found = true
					break
				}
			}
		}

		match = match && found
	}

	return match
}

// SubscribeSendEvents registers a subscription to the event notification
// stream which relates to the asset sending process.
func (r *rpcServer) SubscribeSendEvents(req *taprpc.SubscribeSendEventsRequest,
	ntfnStream sendEventStream) error {

	var targetScriptKey fn.Option[btcec.PublicKey]
	if len(req.FilterScriptKey) > 0 {
		scriptKey, err := btcec.ParsePubKey(req.FilterScriptKey)
		if err != nil {
			return fmt.Errorf("error parsing script key: %w", err)
		}

		targetScriptKey = fn.MaybeSome(scriptKey)
	}

	shouldNotify := func(event fn.Event) (bool, error) {
		var e *tapfreighter.AssetSendEvent
		switch typedEvent := event.(type) {
		case *tapfreighter.AssetSendEvent:
			// Continue below.
			e = typedEvent

		case *proof.BackoffWaitEvent:
			// We're not interested in any backoff events.
			return false, nil

		default:
			return false, fmt.Errorf("invalid event type: %T",
				event)
		}

		return shouldNotifyAssetSendEvent(
			*e, targetScriptKey, req.FilterLabel,
		), nil
	}

	return handleEvents[bool, *taprpc.SendEvent](
		r.cfg.ChainPorter, ntfnStream, marshalSendEvent, shouldNotify,
		r.quit, false,
	)
}

// SubscribeMintEvents allows a caller to subscribe to mint events for asset
// creation batches.
func (r *rpcServer) SubscribeMintEvents(req *mintrpc.SubscribeMintEventsRequest,
	ntfnStream mintEventStream) error {

	marshaler := func(event fn.Event) (*mintrpc.MintEvent, error) {
		e, ok := event.(*tapgarden.AssetMintEvent)
		if !ok {
			return nil, fmt.Errorf("invalid event type: %T", event)
		}

		rpcState, err := marshalBatchState(e.BatchState)
		if err != nil {
			return nil, fmt.Errorf("error marshaling batch state: "+
				"%w", err)
		}

		rpcBatch, err := marshalMintingBatch(e.Batch, req.ShortResponse)
		if err != nil {
			return nil, fmt.Errorf("error marshaling minting "+
				"batch: %w", err)
		}

		var errString string
		if e.Error != nil {
			errString = e.Error.Error()
		}

		return &mintrpc.MintEvent{
			Timestamp:  e.Timestamp().UnixMicro(),
			BatchState: rpcState,
			Error:      errString,
			Batch:      rpcBatch,
		}, nil
	}

	filter := func(event fn.Event) (bool, error) {
		_, ok := event.(*tapgarden.AssetMintEvent)
		if !ok {
			return false, fmt.Errorf("invalid event type: %T",
				event)
		}

		return true, nil
	}

	return handleEvents[bool, *mintrpc.MintEvent](
		r.cfg.AssetMinter, ntfnStream, marshaler, filter, r.quit,
		false,
	)
}

// handleEvents is a helper function that reads events from an event source and
// forwards them to an RPC stream.
func handleEvents[T any, Q any](eventSource fn.EventPublisher[fn.Event, T],
	stream EventStream[Q], marshaler func(fn.Event) (Q, error),
	filter func(fn.Event) (bool, error), quit <-chan struct{},
	deliverFrom T) error {

	// Create a new event subscriber and pass a copy to the event source.
	// We will then read events from the subscriber.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	err := eventSource.RegisterSubscriber(
		eventSubscriber, false, deliverFrom,
	)
	if err != nil {
		return fmt.Errorf("failed to register event source "+
			"notifications subscription: %w", err)
	}

	// Remove the subscriber when we're done. Otherwise, the event source
	// will be blocked on sending new events, since we have a defer to stop
	// the concurrent queue above.
	defer func() {
		err := eventSource.RemoveSubscriber(eventSubscriber)
		if err != nil {
			rpcsLog.Errorf("Error unsubscribing subscriber: %v",
				err)
		}
	}()

	// Loop and read from the event subscription and forward to the RPC
	// stream.
	for {
		select {
		// Handle receiving a new event from the event source. The event
		// will be mapped to the RPC event type and sent over the
		// stream.
		case event := <-eventSubscriber.NewItemCreated.ChanOut():
			// Give the caller a chance to decide if this event
			// should be notified on or not.
			shouldNotify, err := filter(event)
			if err != nil {
				return fmt.Errorf("error filtering event: %w",
					err)
			}
			if !shouldNotify {
				continue
			}

			// We want the event, so let's marshal it to RPC and
			// send it out.
			rpcEvent, err := marshaler(event)
			if err != nil {
				return fmt.Errorf("failed to marshall event "+
					"into RPC event: %w", err)
			}

			err = stream.Send(rpcEvent)
			if err != nil {
				return fmt.Errorf("failed to RPC stream send "+
					"event: %w", err)
			}

		// Handle the case where the RPC stream is closed by the
		// client.
		case <-stream.Context().Done():
			// Don't return an error if a normal context
			// cancellation has occurred.
			isCanceledContext := errors.Is(
				stream.Context().Err(), context.Canceled,
			)
			if isCanceledContext {
				return nil
			}

			return stream.Context().Err()

		// Handle the case where the RPC server is shutting down.
		case <-quit:
			return nil
		}
	}
}

// marshallReceiveAssetEvent maps an asset receive event to its RPC counterpart.
func marshallReceiveAssetEvent(event fn.Event,
	db address.Storage) (*tapdevrpc.ReceiveAssetEvent, error) {

	switch e := event.(type) {
	case *proof.BackoffWaitEvent:
		// Map the transfer type to the RPC counterpart. We only
		// support the "receive" transfer type for asset receive events.
		var transferTypeRpc tapdevrpc.ProofTransferType
		switch e.TransferType {
		case proof.ReceiveTransferType:
			transferTypeRpc = proofTypeReceive
		default:
			return nil, fmt.Errorf("unexpected transfer type: %v",
				e.TransferType)
		}

		evt := &tapdevrpc.ProofTransferBackoffWaitEvent{
			Timestamp:    e.Timestamp().UnixMicro(),
			Backoff:      e.Backoff.Microseconds(),
			TriesCounter: e.TriesCounter,
			TransferType: transferTypeRpc,
		}
		return &tapdevrpc.ReceiveAssetEvent{
			Event: &receiveBackoff{
				ProofTransferBackoffWaitEvent: evt,
			},
		}, nil

	case *tapgarden.AssetReceiveEvent:
		rpcAddr, err := marshalAddr(&e.Address, db)
		if err != nil {
			return nil, fmt.Errorf("error marshaling addr: %w", err)
		}

		evt := &tapdevrpc.AssetReceiveCompleteEvent{
			Timestamp: e.Timestamp().UnixMicro(),
			Address:   rpcAddr,
			Outpoint:  e.OutPoint.String(),
		}
		return &tapdevrpc.ReceiveAssetEvent{
			Event: &receiveComplete{
				AssetReceiveCompleteEvent: evt,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %T", e)
	}
}

// marshallSendAssetEvent maps an asset send event to its RPC counterpart.
func marshallSendAssetEvent(event fn.Event) (*tapdevrpc.SendAssetEvent, error) {
	switch e := event.(type) {
	case *tapfreighter.AssetSendEvent:
		evt := &tapdevrpc.ExecuteSendStateEvent{
			Timestamp: e.Timestamp().UnixMicro(),
			SendState: e.SendState.String(),
		}
		return &tapdevrpc.SendAssetEvent{
			Event: &sendExecute{
				ExecuteSendStateEvent: evt,
			},
		}, nil

	case *proof.BackoffWaitEvent:
		// Map the transfer type to the RPC counterpart. We only
		// support the send transfer type for asset send events.
		var transferTypeRpc tapdevrpc.ProofTransferType
		switch e.TransferType {
		case proof.SendTransferType:
			transferTypeRpc = proofTypeSend
		default:
			return nil, fmt.Errorf("unexpected transfer type: %v",
				e.TransferType)
		}

		evt := &tapdevrpc.ProofTransferBackoffWaitEvent{
			Timestamp:    e.Timestamp().UnixMicro(),
			Backoff:      e.Backoff.Microseconds(),
			TriesCounter: e.TriesCounter,
			TransferType: transferTypeRpc,
		}
		return &tapdevrpc.SendAssetEvent{
			Event: &sendBackoff{
				ProofTransferBackoffWaitEvent: evt,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %T", e)
	}
}

// marshalSendEvent marshals an asset send event into the RPC counterpart.
func marshalSendEvent(event fn.Event) (*taprpc.SendEvent, error) {
	e, ok := event.(*tapfreighter.AssetSendEvent)
	if !ok {
		return nil, fmt.Errorf("invalid event type: %T", event)
	}

	result := &taprpc.SendEvent{
		Timestamp:             e.Timestamp().UnixMicro(),
		SendState:             e.SendState.String(),
		VirtualPackets:        make([][]byte, len(e.VirtualPackets)),
		PassiveVirtualPackets: make([][]byte, len(e.PassivePackets)),
		TransferLabel:         e.TransferLabel,
	}

	if e.Error != nil {
		result.Error = e.Error.Error()
	}

	var err error
	for idx, vPkt := range e.VirtualPackets {
		result.VirtualPackets[idx], err = tappsbt.Encode(vPkt)
		if err != nil {
			return nil, fmt.Errorf("error encoding virtual "+
				"packet: %w", err)
		}
	}
	for idx, vPkt := range e.PassivePackets {
		result.PassiveVirtualPackets[idx], err = tappsbt.Encode(vPkt)
		if err != nil {
			return nil, fmt.Errorf("error encoding virtual "+
				"packet: %w", err)
		}
	}

	switch e.Parcel.(type) {
	case *tapfreighter.AddressParcel:
		result.ParcelType = taprpc.ParcelType_PARCEL_TYPE_ADDRESS

	case *tapfreighter.PreSignedParcel:
		result.ParcelType = taprpc.ParcelType_PARCEL_TYPE_PRE_SIGNED

	case *tapfreighter.PendingParcel:
		result.ParcelType = taprpc.ParcelType_PARCEL_TYPE_PENDING

	case *tapfreighter.PreAnchoredParcel:
		result.ParcelType = taprpc.ParcelType_PARCEL_TYPE_PRE_ANCHORED

	default:
		return nil, fmt.Errorf("unknown parcel type %T", e.Parcel)
	}

	if e.AnchorTx != nil {
		var (
			psbtBuf, finalTxBuf bytes.Buffer
			changeOutputIndex   int32
			lockedOutpoints     []*taprpc.OutPoint
		)
		if e.AnchorTx.FundedPsbt != nil {
			fundedPsbt := e.AnchorTx.FundedPsbt
			changeOutputIndex = fundedPsbt.ChangeOutputIndex

			if fundedPsbt.Pkt == nil {
				return nil, fmt.Errorf("funded PSBT is missing")
			}

			err = fundedPsbt.Pkt.Serialize(&psbtBuf)
			if err != nil {
				return nil, fmt.Errorf("error serializing "+
					"funded PSBT: %w", err)
			}

			for idx := range fundedPsbt.LockedUTXOs {
				utxo := fundedPsbt.LockedUTXOs[idx]
				lockedOutpoints = append(
					lockedOutpoints, &taprpc.OutPoint{
						Txid:        utxo.Hash[:],
						OutputIndex: utxo.Index,
					},
				)
			}
		}

		if e.AnchorTx.FinalTx != nil {
			err = e.AnchorTx.FinalTx.Serialize(&finalTxBuf)
			if err != nil {
				return nil, fmt.Errorf("error serializing "+
					"final tx: %w", err)
			}
		}

		result.AnchorTransaction = &taprpc.AnchorTransaction{
			AnchorPsbt:         psbtBuf.Bytes(),
			ChangeOutputIndex:  changeOutputIndex,
			ChainFeesSats:      e.AnchorTx.ChainFees,
			TargetFeeRateSatKw: int32(e.AnchorTx.TargetFeeRate),
			LndLockedUtxos:     lockedOutpoints,
			FinalTx:            finalTxBuf.Bytes(),
		}
	}

	if e.Transfer != nil {
		result.Transfer, err = marshalOutboundParcel(e.Transfer)
		if err != nil {
			return nil, fmt.Errorf("error marshaling transfer: %w",
				err)
		}
	}

	return result, nil
}

// marshalVerboseBatch marshals a minting batch into the RPC counterpart.
func marshalVerboseBatch(params chaincfg.Params, batch *tapgarden.VerboseBatch,
	verbose bool, skipSeedlings bool) (*mintrpc.VerboseBatch, error) {

	rpcMintingBatch, err := marshalMintingBatch(
		batch.MintingBatch, skipSeedlings,
	)
	if err != nil {
		return nil, err
	}

	rpcBatch := &mintrpc.VerboseBatch{
		Batch: rpcMintingBatch,
	}

	// If we don't need to include the seedlings, we can return here.
	if skipSeedlings {
		return rpcBatch, nil
	}

	// No sprouts, so we marshal the seedlings.
	// We only need to convert the seedlings to unsealed seedlings.
	if len(batch.UnsealedSeedlings) > 0 {
		rpcBatch.UnsealedAssets, err = marshalUnsealedSeedlings(
			params, verbose, batch.UnsealedSeedlings,
		)
		if err != nil {
			return nil, err
		}

		rpcBatch.Batch.Assets = nil
	}

	return rpcBatch, nil
}

// marshalMintingBatch marshals a minting batch into the RPC counterpart.
func marshalMintingBatch(batch *tapgarden.MintingBatch,
	skipSeedlings bool) (*mintrpc.MintingBatch, error) {

	rpcBatchState, err := marshalBatchState(batch.State())
	if err != nil {
		return nil, err
	}

	rpcBatch := &mintrpc.MintingBatch{
		BatchKey:   batch.BatchKey.PubKey.SerializeCompressed(),
		State:      rpcBatchState,
		CreatedAt:  batch.CreationTime.UTC().Unix(),
		HeightHint: batch.HeightHint,
	}

	// If we have the genesis packet available (funded+signed), then we'll
	// display the txid as well.
	if batch.GenesisPacket != nil {
		rpcBatch.BatchPsbt, err = serialize(batch.GenesisPacket.Pkt)
		if err != nil {
			return nil, fmt.Errorf("error serializing batch PSBT: "+
				"%w", err)
		}

		if batch.State() > tapgarden.BatchStateFrozen {
			batchTx, err := psbt.Extract(batch.GenesisPacket.Pkt)
			if err == nil {
				rpcBatch.BatchTxid = batchTx.TxHash().String()
			} else {
				rpcsLog.Errorf("unable to extract batch tx: %v",
					err)
			}
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

// marshalSeedling marshals a seedling into the RPC counterpart.
func marshalSeedling(seedling *tapgarden.Seedling) (*mintrpc.PendingAsset,
	error) {

	var (
		scriptKey        *taprpc.ScriptKey
		groupKeyBytes    []byte
		groupInternalKey *taprpc.KeyDescriptor
		groupAnchor      string
		seedlingMeta     *taprpc.AssetMeta
		newGroupedAsset  bool
	)

	if seedling.ScriptKey.PubKey != nil {
		scriptKey = rpcutils.MarshalScriptKey(seedling.ScriptKey)
	}

	if seedling.HasGroupKey() {
		groupKey := seedling.GroupInfo.GroupKey
		groupKeyBytes = groupKey.GroupPubKey.SerializeCompressed()
	}

	if seedling.GroupInternalKey != nil {
		groupInternalKey = rpcutils.MarshalKeyDescriptor(
			*seedling.GroupInternalKey,
		)
	}

	if seedling.GroupAnchor != nil {
		groupAnchor = *seedling.GroupAnchor
	}

	if seedling.EnableEmission {
		newGroupedAsset = true
	}

	if seedling.Meta != nil {
		seedlingMeta = &taprpc.AssetMeta{
			MetaHash: fn.ByteSlice(
				seedling.Meta.MetaHash(),
			),
			Data: seedling.Meta.Data,
			Type: taprpc.AssetMetaType(seedling.Meta.Type),
		}
	}

	assetVersion, err := rpcutils.MarshalAssetVersion(
		seedling.AssetVersion,
	)
	if err != nil {
		return nil, err
	}

	return &mintrpc.PendingAsset{
		AssetType:          taprpc.AssetType(seedling.AssetType),
		AssetVersion:       assetVersion,
		Name:               seedling.AssetName,
		AssetMeta:          seedlingMeta,
		Amount:             seedling.Amount,
		ScriptKey:          scriptKey,
		GroupKey:           groupKeyBytes,
		GroupAnchor:        groupAnchor,
		GroupInternalKey:   groupInternalKey,
		GroupTapscriptRoot: seedling.GroupTapscriptRoot,
		NewGroupedAsset:    newGroupedAsset,
	}, nil
}

// marshalUnsealedSeedling marshals an unsealed seedling into the RPC
// counterpart.
func marshalUnsealedSeedling(params chaincfg.Params, verbose bool,
	seedling *tapgarden.UnsealedSeedling) (*mintrpc.UnsealedAsset, error) {

	var (
		groupVirtualTx   *taprpc.GroupVirtualTx
		groupReq         *taprpc.GroupKeyRequest
		groupVirtualPsbt string
		err              error
	)

	rpcSeedling, err := marshalSeedling(seedling.Seedling)
	if err != nil {
		return nil, err
	}

	if verbose && seedling.PendingAssetGroup != nil {
		groupVirtualTx, err = rpcutils.MarshalGroupVirtualTx(
			&seedling.PendingAssetGroup.GroupVirtualTx,
		)
		if err != nil {
			return nil, err
		}

		groupReq, err = rpcutils.MarshalGroupKeyRequest(
			&seedling.PendingAssetGroup.GroupKeyRequest,
		)
		if err != nil {
			return nil, err
		}

		// Generate PSBT equivalent of the group virtual tx.
		groupVirtualPacket, err := seedling.PendingAssetGroup.PSBT(
			params,
		)
		if err != nil {
			return nil, fmt.Errorf("error getting group virtual "+
				"PSBT for unsealed seedling: %w", err)
		}

		// Serialize PSBT to bytes.
		var psbtBuf bytes.Buffer
		err = groupVirtualPacket.Serialize(&psbtBuf)
		if err != nil {
			return nil, fmt.Errorf("error serializing group "+
				"virtual PSBT for unsealed seedling: %w", err)
		}

		groupVirtualPsbt = base64.StdEncoding.EncodeToString(
			psbtBuf.Bytes(),
		)
	}

	return &mintrpc.UnsealedAsset{
		Asset:            rpcSeedling,
		GroupVirtualTx:   groupVirtualTx,
		GroupVirtualPsbt: groupVirtualPsbt,
		GroupKeyRequest:  groupReq,
	}, nil
}

// marshalSeedlings marshals the seedlings into the RPC counterpart.
func marshalSeedlings(
	seedlings map[string]*tapgarden.Seedling) ([]*mintrpc.PendingAsset,
	error) {

	return fn.MapErr(maps.Values(seedlings), marshalSeedling)
}

// marshalUnsealedSeedlings marshals the unsealed seedlings into the RPC
// counterpart.
func marshalUnsealedSeedlings(params chaincfg.Params, verbose bool,
	seedlings map[string]*tapgarden.UnsealedSeedling) (
	[]*mintrpc.UnsealedAsset, error) {

	rpcAssets := make([]*mintrpc.UnsealedAsset, 0, len(seedlings))
	for _, seedling := range seedlings {
		nextSeedling, err := marshalUnsealedSeedling(
			params, verbose, seedling,
		)
		if err != nil {
			return nil, err
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
		var (
			groupKeyBytes      []byte
			groupTapscriptRoot []byte
			groupInternalKey   *taprpc.KeyDescriptor
			assetMeta          *taprpc.AssetMeta
		)

		if metas != nil {
			serializedScriptKey := asset.ToSerialized(
				sprout.ScriptKey.PubKey,
			)
			if m, ok := metas[serializedScriptKey]; ok && m != nil {
				assetMeta = &taprpc.AssetMeta{
					MetaHash: fn.ByteSlice(m.MetaHash()),
					Data:     m.Data,
					Type:     taprpc.AssetMetaType(m.Type),
				}
			}
		}

		if sprout.GroupKey != nil {
			grp := sprout.GroupKey
			groupKeyBytes = grp.GroupPubKey.SerializeCompressed()
			groupTapscriptRoot = grp.TapscriptRoot
			groupInternalKey = rpcutils.MarshalKeyDescriptor(
				grp.RawKey,
			)
		}

		rpcAssets = append(rpcAssets, &mintrpc.PendingAsset{
			AssetType:          taprpc.AssetType(sprout.Type),
			Name:               sprout.Tag,
			AssetMeta:          assetMeta,
			Amount:             sprout.Amount,
			GroupKey:           groupKeyBytes,
			GroupInternalKey:   groupInternalKey,
			GroupTapscriptRoot: groupTapscriptRoot,
			ScriptKey: rpcutils.MarshalScriptKey(
				sprout.ScriptKey,
			),
		})
	}

	return rpcAssets
}

// marshalBatchState converts the batch state field into its RPC counterpart.
func marshalBatchState(state tapgarden.BatchState) (mintrpc.BatchState, error) {
	switch state {
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
		return 0, fmt.Errorf("unknown batch state: %v", state)
	}
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

		assetMeta, err = r.cfg.AddrBook.FetchAssetMetaForAsset(
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

		assetMeta, err = r.cfg.AddrBook.FetchAssetMetaForAsset(
			ctx, assetID,
		)

	case req.GetMetaHash() != nil:
		if len(req.GetMetaHash()) != sha256.Size {
			return nil, fmt.Errorf("meta hash must be 32 bytes")
		}

		var metaHash [asset.MetaHashLen]byte
		copy(metaHash[:], req.GetMetaHash())

		assetMeta, err = r.cfg.AddrBook.FetchAssetMetaByHash(
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

		assetMeta, err = r.cfg.AddrBook.FetchAssetMetaByHash(
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

// marshalUniverseRoot marshals the universe root into the RPC counterpart.
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
		UniverseRoots: make(
			map[string]*unirpc.UniverseRoot, len(assetRoots),
		),
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

	// Query for both an issuance and transfer universe root.
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
		return nil, fmt.Errorf("asset group lookup failed: %w", err)

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
	uniID universe.Identifier) (*unirpc.QueryRootResponse, error) {

	var (
		resp unirpc.QueryRootResponse
		err  error
	)

	issuanceRoot, issuanceErr := r.cfg.UniverseArchive.RootNode(ctx, uniID)
	if issuanceErr != nil {
		// Do not return at this point if the error only indicates that
		// the root wasn't found. We'll try to find the transfer root
		// below.
		if !errors.Is(issuanceErr, universe.ErrNoUniverseRoot) {
			return nil, issuanceErr
		}
	}

	resp.IssuanceRoot, err = marshalUniverseRoot(issuanceRoot)
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

	resp.TransferRoot, err = marshalUniverseRoot(transferRoot)
	if err != nil {
		return nil, err
	}

	return &resp, nil
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
			OpStr: leafKey.LeafOutPoint().String(),
		},
		ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
			ScriptKeyBytes: schnorr.SerializePubKey(
				leafKey.LeafScriptKey().PubKey,
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
		return nil, fmt.Errorf("invalid request limit: %d", req.Limit)
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

func marshalAssetLeaf(ctx context.Context, keys rpcutils.KeyLookup,
	assetLeaf *universe.Leaf,
	decDisplay fn.Option[uint32]) (*unirpc.AssetLeaf, error) {

	// Decode the single proof to extract on-chain anchor info.
	p, err := proof.Decode(assetLeaf.RawProof)
	if err != nil {
		return nil, err
	}
	chainAsset, err := p.ToChainAsset()
	if err != nil {
		return nil, err
	}

	// Marshal as a chain asset to include chain_anchor details.
	rpcAsset, err := rpcutils.MarshalChainAsset(
		ctx, chainAsset, decDisplay, true, keys,
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
	assetLeaf *universe.Leaf,
	decDisplay fn.Option[uint32]) (*unirpc.AssetLeaf, error) {

	return marshalAssetLeaf(ctx, r.cfg.AddrBook, assetLeaf, decDisplay)
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

		decDisplay, err := r.DecDisplayForAssetID(ctx, assetLeaf.ID())
		if err != nil {
			return nil, err
		}

		resp.Leaves[i], err = r.marshalAssetLeaf(
			ctx, &assetLeaf, decDisplay,
		)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// unmarshalLeafKey un-marshals a leaf key from the RPC form.
func unmarshalLeafKey(key *unirpc.AssetKey) (universe.LeafKey, error) {
	var leafKey universe.BaseLeafKey

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

	decDisplay, err := r.DecDisplayForAssetID(ctx, proof.Leaf.ID())
	if err != nil {
		return nil, err
	}

	assetLeaf, err := r.marshalAssetLeaf(ctx, proof.Leaf, decDisplay)
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

	response := &unirpc.AssetProofResponse{
		Req:                      req,
		UniverseRoot:             uniRoot,
		UniverseInclusionProof:   uniProof,
		AssetLeaf:                assetLeaf,
		MultiverseRoot:           multiverseRoot,
		MultiverseInclusionProof: multiverseProof,
	}

	// For an issuance proof, it's useful to directly see some of the
	// genesis and meta reveal data in a decoded manner. Since we don't know
	// the proof type, if it was unspecified, we'll only skip this if the
	// proof type is transfer.
	if req.Id.ProofType != unirpc.ProofType_PROOF_TYPE_TRANSFER {
		p, err := proof.Leaf.RawProof.AsSingleProof()
		if err != nil {
			return nil, err
		}

		// If this isn't a genesis reveal, it means we have a transfer
		// proof after all (perhaps because the proof type was given
		// as ProofType_PROOF_TYPE_UNSPECIFIED).
		if p.GenesisReveal == nil {
			return response, nil
		}

		genInfo := &taprpc.GenesisInfo{
			GenesisPoint: p.GenesisReveal.FirstPrevOut.String(),
			Name:         p.GenesisReveal.Tag,
			MetaHash:     p.GenesisReveal.MetaHash[:],
			AssetId:      fn.ByteSlice(p.Asset.ID()),
			OutputIndex:  p.GenesisReveal.OutputIndex,
			AssetType:    taprpc.AssetType(p.Asset.Type),
		}
		issuanceData := &unirpc.IssuanceData{
			GenesisReveal: &taprpc.GenesisReveal{
				GenesisBaseReveal: genInfo,
			},
		}

		if p.GroupKeyReveal != nil {
			rawKey := p.GroupKeyReveal.RawKey()
			issuanceData.GroupKeyReveal = &taprpc.GroupKeyReveal{
				RawGroupKey:   rawKey[:],
				TapscriptRoot: p.GroupKeyReveal.TapscriptRoot(),
			}
		}

		if p.MetaReveal != nil {
			issuanceData.MetaReveal = &taprpc.AssetMeta{
				Data: p.MetaReveal.Data,
				Type: taprpc.AssetMetaType(
					p.MetaReveal.Type,
				),
				MetaHash: fn.ByteSlice(p.MetaReveal.MetaHash()),
			}
		}

		response.IssuanceData = issuanceData
	}

	return response, nil
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

	universeID, leafKey, err := unmarshalUniverseKey(req)
	if err != nil {
		return nil, err
	}

	firstProof, err := r.queryProof(ctx, universeID, leafKey)
	if err != nil {
		return nil, err
	}

	return r.marshalUniverseProofLeaf(ctx, req, firstProof)
}

// queryProof attempts to query for an issuance or transfer proof for a given
// asset based on its UniverseKey. A UniverseKey is composed of the Universe ID
// (asset_id/group_key) and also a leaf key (outpoint || script_key).
func (r *rpcServer) queryProof(ctx context.Context, uniID universe.Identifier,
	leafKey universe.LeafKey) (*universe.Proof, error) {

	rpcsLog.Tracef("[QueryProof]: fetching proof at (uniID=%v, "+
		"leafKey=%x)", uniID.StringForLog(), leafKey.UniverseKey())

	// Retrieve proof export config for the given universe.
	syncConfigs, err := r.cfg.UniverseFederation.QuerySyncConfigs(ctx)
	if err != nil {
		return nil, err
	}

	var candidateIDs []universe.Identifier

	if uniID.ProofType == universe.ProofTypeUnspecified {
		// If the proof type is unspecified, then we'll attempt to
		// retrieve both the issuance and transfer proofs. We gather the
		// corresponding universe IDs into a candidate set.
		uniID.ProofType = universe.ProofTypeIssuance
		if syncConfigs.IsSyncExportEnabled(uniID) {
			candidateIDs = append(candidateIDs, uniID)
		}

		uniID.ProofType = universe.ProofTypeTransfer
		if syncConfigs.IsSyncExportEnabled(uniID) {
			candidateIDs = append(candidateIDs, uniID)
		}
	} else {
		// Otherwise, we'll only attempt to retrieve the proof for the
		// specified proof type. But first we'll check that proof export
		// is enabled for the given universe.
		if !syncConfigs.IsSyncExportEnabled(uniID) {
			return nil, fmt.Errorf("proof export is disabled for " +
				"the given universe")
		}

		candidateIDs = append(candidateIDs, uniID)
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
				"proof at (uniID=%v, leafKey=%x)",
				uniID.StringForLog(), leafKey.UniverseKey())
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

	rpcsLog.Tracef("[QueryProof]: found proof at (uniID=%v, "+
		"leafKey=%x)", uniID.StringForLog(), leafKey.UniverseKey())

	return firstProof, nil
}

// unmarshalUniverseKey unmarshals a universe key from the RPC form.
func unmarshalUniverseKey(key *unirpc.UniverseKey) (universe.Identifier,
	universe.LeafKey, error) {

	var (
		uniID  = universe.Identifier{}
		uniKey = universe.BaseLeafKey{}
		err    error
	)

	if key == nil {
		return uniID, uniKey, fmt.Errorf("universe key cannot be nil")
	}

	uniID, err = UnmarshalUniID(key.Id)
	if err != nil {
		return uniID, uniKey, err
	}

	leafKey, err := unmarshalLeafKey(key.LeafKey)
	if err != nil {
		return uniID, uniKey, err
	}

	return uniID, leafKey, nil
}

// unmarshalAssetLeaf unmarshals an asset leaf from the RPC form.
func unmarshalAssetLeaf(leaf *unirpc.AssetLeaf) (*universe.Leaf, error) {
	// We'll just pull the asset details from the serialized issuance proof
	// itself.
	var proofAsset asset.Asset
	assetRecord := proof.AssetLeafRecord(&proofAsset)
	err := proof.SparseDecode(bytes.NewReader(leaf.Proof), assetRecord)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): double check posted file format everywhere
	//  * raw proof, or within file?

	return &universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  proofAsset.Genesis,
			GroupKey: proofAsset.GroupKey,
		},
		RawProof: leaf.Proof,
		Asset:    &proofAsset,
		Amt:      proofAsset.Amount,
	}, nil
}

// InsertProof attempts to insert a new issuance or transfer proof into the
// Universe tree specified by the UniverseKey. If valid, then the proof is
// inserted into the database, with a new Universe root returned for the updated
// asset_id/group_key.
func (r *rpcServer) InsertProof(ctx context.Context,
	req *unirpc.AssetProof) (*unirpc.AssetProofResponse, error) {

	universeID, leafKey, err := unmarshalUniverseKey(req.Key)
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
		"(universeID=%v, leafKey=%x)", universeID.StringForLog(),
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

// PushProof attempts to query the local universe for a proof specified by a
// UniverseKey. If found, a connection is made to a remote Universe server to
// attempt to upload the asset leaf.
func (r *rpcServer) PushProof(ctx context.Context,
	req *unirpc.PushProofRequest) (*unirpc.PushProofResponse, error) {

	switch {
	case req.Server == nil:
		return nil, fmt.Errorf("remote Universe must be specified")

	case req.Key == nil:
		return nil, fmt.Errorf("universe key must be specified")

	case req.Server.Host == "" && req.Server.Id == 0:
		return nil, fmt.Errorf("remote Universe must be specified")

	case req.Server.Host != "" && req.Server.Id != 0:
		return nil, fmt.Errorf("cannot specify both universe host " +
			"and id")
	}

	remoteUniAddr := unmarshalUniverseServer(req.Server)
	universeID, leafKey, err := unmarshalUniverseKey(req.Key)
	if err != nil {
		return nil, err
	}

	// Try to fetch the requested proof from the local universe.
	localProof, err := r.queryProof(ctx, universeID, leafKey)
	if err != nil {
		return nil, err
	}
	if localProof.Leaf == nil {
		return nil, fmt.Errorf("proof not found in local universe")
	}

	// Make sure that we aren't trying to push the proof to ourself, and
	// then attempt to push the proof.
	err = CheckFederationServer(
		r.cfg.RuntimeID, universe.DefaultTimeout, remoteUniAddr,
	)
	if err != nil {
		return nil, err
	}

	remoteUni, err := NewRpcUniverseRegistrar(remoteUniAddr)
	if err != nil {
		return nil, err
	}

	rpcsLog.Debugf("[PushProof]: pushing proof to universe "+
		"(universeID=%v, server=%v", universeID.StringForLog(),
		remoteUniAddr)

	_, err = remoteUni.UpsertProofLeaf(
		ctx, universeID, leafKey, localProof.Leaf,
	)
	if err != nil {
		return nil, err
	}

	rpcsLog.Debugf("[PushProof]: proof pushed to universe "+
		"(universeID=%v, server=%v", universeID.StringForLog(),
		remoteUniAddr)

	return &unirpc.PushProofResponse{
		Key: req.Key,
	}, nil
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
func unmarshalUniverseSyncType(
	req unirpc.UniverseSyncMode) (universe.SyncType, error) {

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
func unmarshalSyncTargets(
	targets []*unirpc.SyncTarget) ([]universe.Identifier, error) {

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
			decDisplay, err := r.DecDisplayForAssetID(
				ctx, leaf.ID(),
			)
			if err != nil {
				return err
			}

			leaves[i], err = r.marshalAssetLeaf(
				ctx, leaf, decDisplay,
			)
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

func marshalUniverseServer(
	server universe.ServerAddr) *unirpc.UniverseFederationServer {

	return &unirpc.UniverseFederationServer{
		Host: server.HostStr(),
		Id:   int32(server.ID),
	}
}

// ListFederationServers lists the set of servers that make up the federation
// of the local Universe server. These servers are used to push out new proofs,
// and also periodically call sync new proofs from the remote server.
func (r *rpcServer) ListFederationServers(ctx context.Context,
	_ *unirpc.ListFederationServersRequest) (
	*unirpc.ListFederationServersResponse, error) {

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

	if len(req.Challenge) != 0 && len(req.Challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
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

	proofFile, err := proof.DecodeFile(proofBlob)
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof: %w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: r.cfg.ChainBridge,
	}

	lastSnapshot, err := proofFile.Verify(ctx, vCtx)
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

	var challengeOpt fn.Option[[32]byte]

	if len(req.Challenge) == 32 {
		var bCopy [32]byte
		copy(bCopy[:], req.Challenge[:32])
		challengeOpt = fn.Some[[32]byte](bCopy)
	}

	challengeWitness, err := r.cfg.AssetWallet.SignOwnershipProof(
		inputCommitment.Asset.Copy(), challengeOpt,
	)
	if err != nil {
		return nil, fmt.Errorf("error signing ownership proof: %w", err)
	}

	lastProof, err := proofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("error fetching last proof: %w", err)
	}

	lastProof.ChallengeWitness = challengeWitness

	lastProofBytes, err := lastProof.Bytes()
	if err != nil {
		return nil, fmt.Errorf("error encoding proof file: %w", err)
	}

	return &wrpc.ProveAssetOwnershipResponse{
		ProofWithWitness: lastProofBytes,
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

	if len(req.Challenge) != 0 && len(req.Challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}

	p, err := proof.Decode(req.ProofWithWitness)
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof file: %w", err)
	}

	lookup, err := r.cfg.ChainBridge.GenProofChainLookup(p)
	if err != nil {
		return nil, fmt.Errorf("error generating proof chain lookup: "+
			"%w", err)
	}

	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	var (
		challengeBytes [32]byte
		opts           []proof.ProofVerificationOption
	)

	if len(req.Challenge) == 32 {
		copy(challengeBytes[:], req.Challenge[:32])
		opts = append(opts, proof.WithChallengeBytes(challengeBytes))
	}

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: r.cfg.ChainBridge,
	}

	snapShot, err := p.Verify(
		ctx, nil, lookup, vCtx, opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("error verifying proof: %w", err)
	}

	return &wrpc.VerifyAssetOwnershipResponse{
		ValidProof: true,
		Outpoint: &taprpc.OutPoint{
			Txid:        snapShot.OutPoint.Hash[:],
			OutputIndex: snapShot.OutPoint.Index,
		},
		OutpointStr:  snapShot.OutPoint.String(),
		BlockHash:    snapShot.AnchorBlockHash[:],
		BlockHashStr: snapShot.AnchorBlockHash.String(),
		BlockHeight:  snapShot.AnchorBlockHeight,
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
		AssetId:       a.AssetID[:],
		GenesisPoint:  a.GenesisPoint.String(),
		AssetName:     a.AssetName,
		AssetType:     taprpc.AssetType(a.AssetType),
		TotalSupply:   int64(a.TotalSupply),
		GenesisHeight: int32(a.GenesisHeight),
		GenesisTimestamp: r.cfg.ChainBridge.GetBlockTimestamp(
			ctx, a.GenesisHeight,
		),
		AnchorPoint: a.AnchorPoint.String(),
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
	uniIdRPC := rpcutils.MarshalUniverseID(assetIDBytes, groupKeyBytes)

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

// marshalAssetSpecifier marshals an asset specifier to the RPC form.
func marshalAssetSpecifier(specifier asset.Specifier) rfqrpc.AssetSpecifier {
	switch {
	case specifier.HasId():
		assetID := specifier.UnwrapIdToPtr()
		return rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: assetID[:],
			},
		}

	case specifier.HasGroupPubKey():
		groupKey := specifier.UnwrapGroupKeyToPtr()
		groupKeyBytes := groupKey.SerializeCompressed()
		return rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_GroupKey{
				GroupKey: groupKeyBytes,
			},
		}

	default:
		return rfqrpc.AssetSpecifier{}
	}
}

// unmarshalAssetSpecifier unmarshals an asset specifier from the RPC form.
func unmarshalAssetSpecifier(s *rfqrpc.AssetSpecifier) (*asset.ID,
	*btcec.PublicKey, error) {

	if s == nil {
		return nil, nil, fmt.Errorf("asset specifier must be specified")
	}

	return parseAssetSpecifier(
		s.GetAssetId(), s.GetAssetIdStr(), s.GetGroupKey(),
		s.GetGroupKeyStr(),
	)
}

// parseAssetSpecifier parses an asset specifier from the RPC form.
func parseAssetSpecifier(reqAssetID []byte, reqAssetIDStr string,
	reqGroupKey []byte, reqGroupKeyStr string) (*asset.ID, *btcec.PublicKey,
	error) {

	// Attempt to decode the asset specifier from the RPC request. In cases
	// where both the asset ID and asset group key are provided, we will
	// give precedence to the asset ID due to its higher level of
	// specificity.
	var (
		assetID  *asset.ID
		groupKey *btcec.PublicKey
		err      error
	)

	switch {
	// Parse the asset ID if it's set.
	case len(reqAssetID) > 0:
		if len(reqAssetID) != sha256.Size {
			return nil, nil, fmt.Errorf("asset ID must be 32 bytes")
		}

		var assetIdBytes [32]byte
		copy(assetIdBytes[:], reqAssetID)
		id := asset.ID(assetIdBytes)
		assetID = &id

	case len(reqAssetIDStr) > 0:
		assetIDBytes, err := hex.DecodeString(reqAssetIDStr)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding asset "+
				"ID: %w", err)
		}

		if len(assetIDBytes) != sha256.Size {
			return nil, nil, fmt.Errorf("asset ID must be 32 bytes")
		}

		var id asset.ID
		copy(id[:], assetIDBytes)
		assetID = &id

	// Parse the group key if it's set.
	case len(reqGroupKey) > 0:
		groupKey, err = btcec.ParsePubKey(reqGroupKey)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing group "+
				"key: %w", err)
		}

	case len(reqGroupKeyStr) > 0:
		groupKeyBytes, err := hex.DecodeString(reqGroupKeyStr)
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

	// Construct an asset specifier from the asset ID and/or group key.
	assetSpecifier, err := asset.NewSpecifier(
		assetId, assetGroupKey, nil, true,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating asset specifier: %w",
			err)
	}

	// Convert expiry unix timestamp in seconds to time.Time.
	if req.Expiry > math.MaxInt64 {
		return nil, fmt.Errorf("expiry must be less than or equal to "+
			"math.MaxInt64 (expiry=%d)", req.Expiry)
	}
	expiry := time.Unix(int64(req.Expiry), 0).UTC()

	return &rfq.BuyOrder{
		AssetSpecifier: assetSpecifier,
		AssetMaxAmt:    req.AssetMaxAmt,
		Expiry:         expiry,
		Peer:           fn.MaybeSome(peer),
	}, nil
}

// AddAssetBuyOrder upserts a new buy order for the given asset into the RFQ
// manager. If the order already exists for the given asset, it will be updated.
func (r *rpcServer) AddAssetBuyOrder(ctx context.Context,
	req *rfqrpc.AddAssetBuyOrderRequest) (*rfqrpc.AddAssetBuyOrderResponse,
	error) {

	if req.TimeoutSeconds == 0 {
		return nil, fmt.Errorf("timeout must be greater than 0")
	}

	// Unmarshal the buy order from the RPC form.
	buyOrder, err := unmarshalAssetBuyOrder(req)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling buy order: %w", err)
	}

	// Currently, we require the peer to be specified in the buy order.
	peer, err := buyOrder.Peer.UnwrapOrErr(
		fmt.Errorf("buy order peer must be specified"),
	)
	if err != nil {
		return nil, err
	}

	// Check if we have a channel with the peer.
	err = r.checkPeerChannel(
		ctx, peer, buyOrder.AssetSpecifier, req.SkipAssetChannelCheck,
	)
	if err != nil {
		return nil, fmt.Errorf("error checking peer channel: %w", err)
	}

	rpcsLog.Debugf("[AddAssetBuyOrder]: upserting buy order "+
		"(dest_peer=%s)", peer.String())

	// Register an event listener before actually inserting the order, so we
	// definitely don't miss any responses.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	err = r.cfg.RfqManager.RegisterSubscriber(eventSubscriber, false, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to register event listener: %w",
			err)
	}

	defer func() {
		_ = r.cfg.RfqManager.RemoveSubscriber(eventSubscriber)
	}()

	// Upsert the buy order into the RFQ manager.
	err = r.cfg.RfqManager.UpsertAssetBuyOrder(*buyOrder)
	if err != nil {
		return nil, fmt.Errorf("error upserting buy order into RFQ "+
			"manager: %w", err)
	}

	timeout := time.After(time.Second * time.Duration(req.TimeoutSeconds))

	for {
		type targetEventType = *rfq.PeerAcceptedBuyQuoteEvent
		select {
		case event := <-eventSubscriber.NewItemCreated.ChanOut():
			acceptedQuote, ok := event.(targetEventType)
			if !ok {
				rpcsLog.Debugf("Received event of type %T "+
					"but expected accepted sell quote, "+
					"skipping", event)

				continue
			}

			if !acceptedQuote.MatchesOrder(*buyOrder) {
				rpcsLog.Debugf("Received event of type %T "+
					"but order doesn't match, skipping",
					event)

				continue
			}

			resp, err := rfq.NewAddAssetBuyOrderResponse(event)
			if err != nil {
				return nil, fmt.Errorf("error marshalling "+
					"buy order response: %w", err)
			}

			return resp, nil

		case <-r.quit:
			return nil, fmt.Errorf("server shutting down")

		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response "+
				"(peer=%s)", peer.String())
		}
	}
}

// checkPeerChannel checks if there is a channel with the given peer. If the
// asset channel check is enabled, it will also check if there is a channel with
// the given asset with the peer.
func (r *rpcServer) checkPeerChannel(ctx context.Context, peer route.Vertex,
	specifier asset.Specifier, skipAssetChannelCheck bool) error {

	// We want to make sure there is at least a channel between us and the
	// peer, otherwise RFQ negotiation doesn't make sense.
	switch {
	// For integration tests, we can't create asset channels, so we allow
	// the asset channel check to be skipped. In this case we simply check
	// that we have any channel with the peer.
	case skipAssetChannelCheck:
		activeChannels, err := r.cfg.Lnd.Client.ListChannels(
			ctx, true, false,
		)
		if err != nil {
			return fmt.Errorf("unable to fetch channels: %w", err)
		}
		peerChannels := fn.Filter(
			activeChannels, func(c lndclient.ChannelInfo) bool {
				return c.PubKeyBytes == peer
			},
		)
		if len(peerChannels) == 0 {
			return fmt.Errorf("no active channel found with peer "+
				"%x", peer[:])
		}

	// For any other case, we'll want to make sure there is a channel with
	// a non-zero balance of the given asset to carry the order.
	default:
		// If we don't get an error here, it means we do have an asset
		// channel with the peer. The intention doesn't matter as we're
		// just checking whether a channel exists.
		_, err := r.rfqChannel(ctx, specifier, &peer, NoIntention)
		if err != nil {
			return fmt.Errorf("error checking asset channel: %w",
				err)
		}
	}

	return nil
}

// unmarshalAssetSellOrder unmarshals an asset sell order from the RPC form.
func unmarshalAssetSellOrder(
	req *rfqrpc.AddAssetSellOrderRequest) (*rfq.SellOrder, error) {

	assetId, assetGroupKey, err := unmarshalAssetSpecifier(
		req.AssetSpecifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling asset specifier: "+
			"%w", err)
	}

	// Unmarshal the peer if specified.
	var peer fn.Option[route.Vertex]
	if len(req.PeerPubKey) > 0 {
		pv, err := route.NewVertexFromBytes(req.PeerPubKey)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling peer "+
				"route vertex: %w", err)
		}

		peer = fn.Some(pv)
	}

	// Construct an asset specifier from the asset ID and/or group key.
	assetSpecifier, err := asset.NewSpecifier(
		assetId, assetGroupKey, nil, true,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating asset specifier: %w",
			err)
	}

	// Convert expiry unix timestamp in seconds to time.Time.
	if req.Expiry > math.MaxInt64 {
		return nil, fmt.Errorf("expiry must be less than or equal to "+
			"math.MaxInt64 (expiry=%d)", req.Expiry)
	}
	expiry := time.Unix(int64(req.Expiry), 0).UTC()

	return &rfq.SellOrder{
		AssetSpecifier: assetSpecifier,
		PaymentMaxAmt:  lnwire.MilliSatoshi(req.PaymentMaxAmt),
		Expiry:         expiry,
		Peer:           peer,
	}, nil
}

// AddAssetSellOrder upserts a new sell order for the given asset into the RFQ
// manager. If the order already exists for the given asset, it will be updated.
func (r *rpcServer) AddAssetSellOrder(ctx context.Context,
	req *rfqrpc.AddAssetSellOrderRequest) (*rfqrpc.AddAssetSellOrderResponse,
	error) {

	if req.TimeoutSeconds == 0 {
		return nil, fmt.Errorf("timeout must be greater than 0")
	}

	// Unmarshal the order from the RPC form.
	sellOrder, err := unmarshalAssetSellOrder(req)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling sell order: %w",
			err)
	}

	// Currently, we require the peer to be specified in the buy order.
	peer, err := sellOrder.Peer.UnwrapOrErr(
		fmt.Errorf("sell order peer must be specified"),
	)
	if err != nil {
		return nil, err
	}

	// Check if we have a channel with the peer.
	err = r.checkPeerChannel(
		ctx, peer, sellOrder.AssetSpecifier, req.SkipAssetChannelCheck,
	)
	if err != nil {
		return nil, fmt.Errorf("error checking peer channel: %w", err)
	}

	rpcsLog.Debugf("[AddAssetSellOrder]: upserting sell order "+
		"(dest_peer=%s)", peer.String())

	// Register an event listener before actually inserting the order, so we
	// definitely don't miss any responses.
	eventSubscriber := fn.NewEventReceiver[fn.Event](fn.DefaultQueueSize)
	defer eventSubscriber.Stop()

	err = r.cfg.RfqManager.RegisterSubscriber(eventSubscriber, false, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to register event listener: %w",
			err)
	}

	defer func() {
		_ = r.cfg.RfqManager.RemoveSubscriber(eventSubscriber)
	}()

	// Upsert the order into the RFQ manager.
	err = r.cfg.RfqManager.UpsertAssetSellOrder(*sellOrder)
	if err != nil {
		return nil, fmt.Errorf("error upserting sell order into RFQ "+
			"manager: %w", err)
	}

	timeout := time.After(time.Second * time.Duration(req.TimeoutSeconds))

	for {
		type targetEventType = *rfq.PeerAcceptedSellQuoteEvent
		select {
		case event := <-eventSubscriber.NewItemCreated.ChanOut():
			acceptedQuote, ok := event.(targetEventType)
			if !ok {
				rpcsLog.Debugf("Received event of type %T "+
					"but expected accepted sell quote, "+
					"skipping", event)

				continue
			}

			if !acceptedQuote.MatchesOrder(*sellOrder) {
				rpcsLog.Debugf("Received event of type %T "+
					"but order doesn't match, skipping",
					event)

				continue
			}

			resp, err := rfq.NewAddAssetSellOrderResponse(event)
			if err != nil {
				return nil, fmt.Errorf("error marshalling "+
					"sell order response: %w", err)
			}

			return resp, nil

		case <-r.quit:
			return nil, fmt.Errorf("server shutting down")

		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response "+
				"from peer %s", peer.String())
		}
	}
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

// AddAssetBuyOffer upserts a new buy offer for the given asset into the RFQ
// manager. If the offer already exists for the given asset, it will be updated.
//
// A buy offer is used by the node to selectively accept or reject incoming
// asset sell quote requests before price is considered.
func (r *rpcServer) AddAssetBuyOffer(_ context.Context,
	req *rfqrpc.AddAssetBuyOfferRequest) (*rfqrpc.AddAssetBuyOfferResponse,
	error) {

	// Unmarshal the asset specifier from the RPC form.
	assetID, assetGroupKey, err := unmarshalAssetSpecifier(
		req.AssetSpecifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling asset specifier: "+
			"%w", err)
	}

	// Upsert the offer into the RFQ manager.
	buyOffer := rfq.BuyOffer{
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		MaxUnits:      req.MaxUnits,
	}
	rpcsLog.Debugf("[AddAssetBuyOffer]: upserting buy offer (buy_offer=%v)",
		buyOffer)
	err = r.cfg.RfqManager.UpsertAssetBuyOffer(buyOffer)
	if err != nil {
		return nil, fmt.Errorf("error upserting buy offer into RFQ "+
			"manager: %w", err)
	}

	return &rfqrpc.AddAssetBuyOfferResponse{}, nil
}

// marshalPeerAcceptedBuyQuotes marshals a map of peer accepted asset buy quotes
// into the RPC form. These are quotes that were requested by our node and have
// been accepted by our peers.
func marshalPeerAcceptedBuyQuotes(
	quotes map[rfq.SerialisedScid]rfqmsg.BuyAccept) (
	[]*rfqrpc.PeerAcceptedBuyQuote, error) {

	// Marshal the accepted quotes into the RPC form.
	rpcQuotes := make(
		[]*rfqrpc.PeerAcceptedBuyQuote, 0, len(quotes),
	)
	for scid, quote := range quotes {
		coefficient := quote.AssetRate.Rate.Coefficient.String()
		rpcAskAssetRate := &rfqrpc.FixedPoint{
			Coefficient: coefficient,
			Scale:       uint32(quote.AssetRate.Rate.Scale),
		}

		rpcQuote := &rfqrpc.PeerAcceptedBuyQuote{
			Peer:           quote.Peer.String(),
			Id:             quote.ID[:],
			Scid:           uint64(scid),
			AssetMaxAmount: quote.Request.AssetMaxAmt,
			AskAssetRate:   rpcAskAssetRate,
			Expiry:         uint64(quote.AssetRate.Expiry.Unix()),
		}
		rpcQuotes = append(rpcQuotes, rpcQuote)
	}

	return rpcQuotes, nil
}

// marshalPeerAcceptedSellQuotes marshals a map of peer accepted asset sell
// quotes into the RPC form. These are quotes that were requested by our node
// and have been accepted by our peers.
//
// nolint: lll
func marshalPeerAcceptedSellQuotes(quotes map[rfq.SerialisedScid]rfqmsg.SellAccept) (
	[]*rfqrpc.PeerAcceptedSellQuote, error) {

	// Marshal the accepted quotes into the RPC form.
	rpcQuotes := make([]*rfqrpc.PeerAcceptedSellQuote, 0, len(quotes))
	for scid, quote := range quotes {
		rpcAssetRate := &rfqrpc.FixedPoint{
			Coefficient: quote.AssetRate.Rate.Coefficient.String(),
			Scale:       uint32(quote.AssetRate.Rate.Scale),
		}

		// TODO(ffranr): Add SellRequest payment max amount to
		//  PeerAcceptedSellQuote.
		rpcQuote := &rfqrpc.PeerAcceptedSellQuote{
			Peer:         quote.Peer.String(),
			Id:           quote.ID[:],
			Scid:         uint64(scid),
			BidAssetRate: rpcAssetRate,
			Expiry:       uint64(quote.AssetRate.Expiry.Unix()),
		}
		rpcQuotes = append(rpcQuotes, rpcQuote)
	}

	return rpcQuotes, nil
}

// QueryPeerAcceptedQuotes is used to query for quotes that were requested by
// our node and have been accepted our peers.
func (r *rpcServer) QueryPeerAcceptedQuotes(_ context.Context,
	_ *rfqrpc.QueryPeerAcceptedQuotesRequest) (
	*rfqrpc.QueryPeerAcceptedQuotesResponse, error) {

	// Query the RFQ manager for quotes that were requested by our node and
	// have been accepted by our peers.
	peerAcceptedBuyQuotes := r.cfg.RfqManager.PeerAcceptedBuyQuotes()
	peerAcceptedSellQuotes := r.cfg.RfqManager.PeerAcceptedSellQuotes()

	rpcBuyQuotes, err := marshalPeerAcceptedBuyQuotes(peerAcceptedBuyQuotes)
	if err != nil {
		return nil, fmt.Errorf("error marshalling peer accepted buy "+
			"quotes: %w", err)
	}

	rpcSellQuotes, err := marshalPeerAcceptedSellQuotes(
		peerAcceptedSellQuotes,
	)
	if err != nil {
		return nil, fmt.Errorf("error marshalling peer accepted sell "+
			"quotes: %w", err)
	}

	return &rfqrpc.QueryPeerAcceptedQuotesResponse{
		BuyQuotes:  rpcBuyQuotes,
		SellQuotes: rpcSellQuotes,
	}, nil
}

// marshallRfqEvent marshals an RFQ event into the RPC form.
func marshallRfqEvent(eventInterface fn.Event) (*rfqrpc.RfqEvent, error) {
	timestamp := eventInterface.Timestamp().UTC().UnixMicro()

	switch event := eventInterface.(type) {
	case *rfq.PeerAcceptedBuyQuoteEvent:
		acceptedQuote, err := rfq.MarshalAcceptedBuyQuoteEvent(event)
		if err != nil {
			return nil, err
		}

		eventRpc := &rfqrpc.RfqEvent_PeerAcceptedBuyQuote{
			PeerAcceptedBuyQuote: &rfqrpc.PeerAcceptedBuyQuoteEvent{
				Timestamp:            uint64(timestamp),
				PeerAcceptedBuyQuote: acceptedQuote,
			},
		}
		return &rfqrpc.RfqEvent{
			Event: eventRpc,
		}, nil

	case *rfq.PeerAcceptedSellQuoteEvent:
		rpcAcceptedQuote := rfq.MarshalAcceptedSellQuoteEvent(
			event,
		)

		eventRpc := &rfqrpc.RfqEvent_PeerAcceptedSellQuote{
			PeerAcceptedSellQuote: &rfqrpc.PeerAcceptedSellQuoteEvent{
				Timestamp:             uint64(timestamp),
				PeerAcceptedSellQuote: rpcAcceptedQuote,
			},
		}
		return &rfqrpc.RfqEvent{
			Event: eventRpc,
		}, nil

	case *rfq.AcceptHtlcEvent:
		eventRpc := &rfqrpc.RfqEvent_AcceptHtlc{
			AcceptHtlc: &rfqrpc.AcceptHtlcEvent{
				Timestamp: uint64(timestamp),
				Scid:      event.Policy.Scid(),
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

	filter := func(event fn.Event) (bool, error) {
		return true, nil
	}

	return handleEvents[uint64, *rfqrpc.RfqEvent](
		r.cfg.RfqManager, ntfnStream, marshallRfqEvent, filter, r.quit,
		0,
	)
}

// FundChannel initiates the channel funding negotiation with a peer for the
// creation of a channel that contains a specified amount of a given asset.
func (r *rpcServer) FundChannel(ctx context.Context,
	req *tchrpc.FundChannelRequest) (*tchrpc.FundChannelResponse,
	error) {

	// If we're not running inside litd, we cannot offer this functionality.
	if !r.cfg.EnableChannelFeatures {
		return nil, fmt.Errorf("the Taproot Asset channel " +
			"functionality is only available when running inside " +
			"Lightning Terminal daemon (litd), with lnd and tapd " +
			"both running in 'integrated' mode")
	}

	peerPub, err := btcec.ParsePubKey(req.PeerPubkey)
	if err != nil {
		return nil, fmt.Errorf("error parsing peer pubkey: %w", err)
	}

	assetID, groupKey, err := parseAssetSpecifier(
		req.GetAssetId(), "", req.GetGroupKey(), "",
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing asset specifier: %w", err)
	}

	// For channel funding, we need to make sure that the group key is set
	// if the asset is grouped.
	assetSpecifier, err := r.specifierWithGroupKeyLookup(
		ctx, assetID, groupKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating asset specifier: %w",
			err)
	}

	if req.AssetAmount == 0 {
		return nil, fmt.Errorf("asset amount must be specified")
	}
	if req.FeeRateSatPerVbyte == 0 {
		return nil, fmt.Errorf("fee rate must be specified")
	}

	fundReq := tapchannel.FundReq{
		PeerPub:        *peerPub,
		AssetSpecifier: assetSpecifier,
		AssetAmount:    req.AssetAmount,
		FeeRate:        chainfee.SatPerVByte(req.FeeRateSatPerVbyte),
		PushAmount:     btcutil.Amount(req.PushSat),
	}

	chanPoint, err := r.cfg.AuxFundingController.FundChannel(ctx, fundReq)
	if err != nil {
		return nil, fmt.Errorf("error funding channel: %w", err)
	}

	return &tchrpc.FundChannelResponse{
		Txid:        chanPoint.Hash.String(),
		OutputIndex: int32(chanPoint.Index),
	}, nil
}

// specifierWithGroupKeyLookup returns an asset specifier that has the group key
// set if it's a grouped asset.
func (r *rpcServer) specifierWithGroupKeyLookup(ctx context.Context,
	assetID *asset.ID, groupKey *btcec.PublicKey) (asset.Specifier, error) {

	var result asset.Specifier

	if assetID != nil && groupKey == nil {
		dbGroupKey, err := r.cfg.TapAddrBook.QueryAssetGroup(
			ctx, *assetID,
		)
		switch {
		case err == nil && dbGroupKey.GroupKey != nil:
			groupKey = &dbGroupKey.GroupPubKey

		case err != nil:
			return result, fmt.Errorf("unable to query asset "+
				"group: %w", err)
		}
	}

	return asset.NewSpecifier(assetID, groupKey, nil, true)
}

// EncodeCustomRecords allows RPC users to encode Taproot Asset channel related
// data into the TLV format that is used in the custom records of the lnd
// payment or other channel related RPCs. This RPC is completely stateless and
// does not perform any checks on the data provided, other than pure format
// validation.
func (r *rpcServer) EncodeCustomRecords(_ context.Context,
	in *tchrpc.EncodeCustomRecordsRequest) (
	*tchrpc.EncodeCustomRecordsResponse, error) {

	switch i := in.Input.(type) {
	case *tchrpc.EncodeCustomRecordsRequest_RouterSendPayment:
		req := i.RouterSendPayment

		assetAmounts := make(
			[]*rfqmsg.AssetBalance, 0, len(req.AssetAmounts),
		)
		for idStr, amount := range req.AssetAmounts {
			idBytes, err := hex.DecodeString(idStr)
			if err != nil {
				return nil, fmt.Errorf("error decoding asset "+
					"ID: %w", err)
			}

			if len(idBytes) != sha256.Size {
				return nil, fmt.Errorf("asset ID must be 32 " +
					"bytes")
			}

			if amount == 0 {
				return nil, fmt.Errorf("asset amount must be " +
					"specified")
			}

			var assetID asset.ID
			copy(assetID[:], idBytes)

			assetAmounts = append(
				assetAmounts, rfqmsg.NewAssetBalance(
					assetID, amount,
				),
			)
		}

		rfqID := fn.None[rfqmsg.ID]()
		if len(req.RfqId) > 0 {
			if len(req.RfqId) != sha256.Size {
				return nil, fmt.Errorf("RFQ ID must be empty " +
					"or exactly 32 bytes")
			}

			var id rfqmsg.ID
			copy(id[:], req.RfqId)

			rfqID = fn.Some[rfqmsg.ID](id)
		}

		htlc := rfqmsg.NewHtlc(assetAmounts, rfqID)

		// We'll now map the HTLC struct into a set of TLV records,
		// which we can then encode into the map format expected.
		htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
		if err != nil {
			return nil, fmt.Errorf("unable to encode records as "+
				"map: %w", err)
		}

		return &tchrpc.EncodeCustomRecordsResponse{
			CustomRecords: htlcMapRecords,
		}, nil

	default:
		return nil, fmt.Errorf("unknown input type: %T", i)
	}
}

// SendPayment is a wrapper around lnd's routerrpc.SendPaymentV2 RPC method
// with asset specific parameters. It allows RPC users to send asset keysend
// payments (direct payments) or payments to an invoice with a specified asset
// amount.
func (r *rpcServer) SendPayment(req *tchrpc.SendPaymentRequest,
	stream tchrpc.TaprootAssetChannels_SendPaymentServer) error {

	if len(req.AssetId) > 0 && len(req.GroupKey) > 0 {
		return fmt.Errorf("cannot set both asset id and group key")
	}

	if req.PaymentRequest == nil {
		return fmt.Errorf("payment request must be specified")
	}
	pReq := req.PaymentRequest
	ctx := stream.Context()

	assetID, groupKey, err := parseAssetSpecifier(
		req.AssetId, "", req.GroupKey, "",
	)
	if err != nil {
		return err
	}

	specifier, err := asset.NewExclusiveSpecifier(assetID, groupKey)
	if err != nil {
		return err
	}

	// Now that we know we have at least _some_ asset balance, we'll figure
	// out what kind of payment this is, so we can determine _how many_
	// asset units we need.
	destRecords := pReq.DestCustomRecords
	_, isKeysend := destRecords[record.KeySendType]
	firstHopRecords := pReq.FirstHopCustomRecords

	switch {
	// Both payment request and keysend is set, which isn't a supported
	// combination.
	case pReq.PaymentRequest != "" && isKeysend:
		return fmt.Errorf("payment request and keysend custom " +
			"records cannot be set at the same time")

	// RFQ ID and keysend is set, which isn't a supported combination.
	case req.RfqId != nil && isKeysend:
		return fmt.Errorf("RFQ ID and keysend custom records " +
			"cannot be set at the same time")

	// A payment must either be a keysend payment or pay an invoice.
	case !isKeysend && pReq.PaymentRequest == "":
		return fmt.Errorf("payment request or keysend custom records " +
			"must be set")

	// There are custom records for the first hop set, which means RFQ
	// negotiation has already happened (or this is a keysend payment and
	// the correct asset amount is already encoded). So we don't need to do
	// anything special and can just forward the payment to lnd.
	case len(firstHopRecords) > 0:
		// Continue below.

	// The user specified a custom RFQ ID for a quote that should be used
	// for the payment.
	case req.RfqId != nil:
		// Check if the provided RFQ ID matches the expected length.
		if len(req.RfqId) != 32 {
			return fmt.Errorf("RFQ ID must be 32 bytes in length")
		}

		// Now let's try to perform an internal lookup to see if there's
		// an actual quote on this ID.
		var rfqID rfqmsg.ID
		copy(rfqID[:], req.RfqId)

		var quote *rfqmsg.SellAccept
		for _, q := range r.cfg.RfqManager.PeerAcceptedSellQuotes() {
			if q.ID == rfqID {
				qCopy := q
				quote = &qCopy
				break
			}
		}

		// This quote ID did not match anything.
		if quote == nil {
			return fmt.Errorf("quote ID did not match an " +
				"accepted quote")
		}

		// Calculate the equivalent asset units for the given invoice
		// amount based on the asset-to-BTC conversion rate.
		sellOrder := rfq.MarshalAcceptedSellQuote(*quote)

		// paymentMaxAmt is the maximum amount that the counterparty is
		// expected to pay. This is the amount that the invoice is
		// asking for plus the fee limit in milli-satoshis.
		paymentMaxAmt, _, err := r.parseRequest(pReq)
		if err != nil {
			return err
		}

		// Check if the payment requires overpayment based on the quote.
		err = checkOverpayment(
			sellOrder, paymentMaxAmt, req.AllowOverpay,
		)
		if err != nil {
			return err
		}

		// Send out the information about the quote on the stream.
		err = stream.Send(&tchrpc.SendPaymentResponse{
			Result: &tchrpc.SendPaymentResponse_AcceptedSellOrder{
				AcceptedSellOrder: sellOrder,
			},
		})
		if err != nil {
			return fmt.Errorf("payment failed to send accepted "+
				"sell order over stream: %v", err)
		}

		rpcsLog.Infof("Using quote for %v asset units at %v asset/BTC "+
			"from peer %x with SCID %d", sellOrder.AssetAmount,
			quote.AssetRate.String(), quote.Peer, quote.ID.Scid())

		htlc := rfqmsg.NewHtlc(nil, fn.Some(quote.ID))

		// We'll now map the HTLC struct into a set of TLV records,
		// which we can then encode into the expected map format.
		htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
		if err != nil {
			return fmt.Errorf("unable to encode records as map: %w",
				err)
		}

		pReq.FirstHopCustomRecords = htlcMapRecords

	// The request wants to pay a specific invoice.
	case pReq.PaymentRequest != "":
		// The peer public key is optional if there is only a single
		// asset channel.
		var peerPubKey *route.Vertex
		if len(req.PeerPubkey) > 0 {
			parsedKey, err := route.NewVertexFromBytes(
				req.PeerPubkey,
			)
			if err != nil {
				return fmt.Errorf("error parsing peer pubkey: "+
					"%w", err)
			}

			peerPubKey = &parsedKey
		}

		rpcSpecifier := marshalAssetSpecifier(specifier)

		// We can now query the asset channels we have.
		assetChan, err := r.rfqChannel(
			ctx, specifier, peerPubKey, SendIntention,
		)
		if err != nil {
			return fmt.Errorf("error finding asset channel to "+
				"use: %w", err)
		}

		// Even if the user didn't specify the peer public key before,
		// we definitely know it now. So let's make sure it's always
		// set.
		peerPubKey = &assetChan.channelInfo.PubKeyBytes

		// paymentMaxAmt is the maximum amount that the counterparty is
		// expected to pay. This is the amount that the invoice is
		// asking for plus the fee limit in milli-satoshis.
		paymentMaxAmt, expiry, err := r.parseRequest(pReq)
		if err != nil {
			return err
		}

		resp, err := r.AddAssetSellOrder(
			ctx, &rfqrpc.AddAssetSellOrderRequest{
				AssetSpecifier: &rpcSpecifier,
				PaymentMaxAmt:  uint64(paymentMaxAmt),
				Expiry:         uint64(expiry.Unix()),
				PeerPubKey:     peerPubKey[:],
				TimeoutSeconds: uint32(
					rfq.DefaultTimeout.Seconds(),
				),
			},
		)
		if err != nil {
			return fmt.Errorf("error adding sell order: %w", err)
		}

		var acceptedQuote *rfqrpc.PeerAcceptedSellQuote
		switch r := resp.Response.(type) {
		case *rfqrpc.AddAssetSellOrderResponse_AcceptedQuote:
			acceptedQuote = r.AcceptedQuote

		case *rfqrpc.AddAssetSellOrderResponse_InvalidQuote:
			return fmt.Errorf("peer %v sent back an invalid "+
				"quote, status: %v", r.InvalidQuote.Peer,
				r.InvalidQuote.Status.String())

		case *rfqrpc.AddAssetSellOrderResponse_RejectedQuote:
			return fmt.Errorf("peer %v rejected the quote, code: "+
				"%v, error message: %v", r.RejectedQuote.Peer,
				r.RejectedQuote.ErrorCode,
				r.RejectedQuote.ErrorMessage)

		default:
			return fmt.Errorf("unexpected response type: %T", r)
		}

		// Check if the payment requires overpayment based on the quote.
		err = checkOverpayment(
			acceptedQuote, paymentMaxAmt, req.AllowOverpay,
		)
		if err != nil {
			return err
		}

		// Send out the information about the quote on the stream.
		err = stream.Send(&tchrpc.SendPaymentResponse{
			Result: &tchrpc.SendPaymentResponse_AcceptedSellOrder{
				AcceptedSellOrder: acceptedQuote,
			},
		})
		if err != nil {
			return err
		}

		// Unmarshall the accepted quote's asset rate.
		assetRate, err := rpcutils.UnmarshalRfqFixedPoint(
			acceptedQuote.BidAssetRate,
		)
		if err != nil {
			return fmt.Errorf("error unmarshalling asset rate: %w",
				err)
		}

		rpcsLog.Infof("Got quote for %v asset units at %v asset/BTC "+
			"from peer %x with SCID %d", acceptedQuote.AssetAmount,
			assetRate, peerPubKey, acceptedQuote.Scid)

		var rfqID rfqmsg.ID
		copy(rfqID[:], acceptedQuote.Id)

		htlc := rfqmsg.NewHtlc(nil, fn.Some(rfqID))

		// We'll now map the HTLC struct into a set of TLV records,
		// which we can then encode into the expected map format.
		htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
		if err != nil {
			return fmt.Errorf("unable to encode records as map: %w",
				err)
		}

		pReq.FirstHopCustomRecords = htlcMapRecords

	// The payment request is a keysend payment.
	case isKeysend:
		if req.AssetAmount == 0 {
			return fmt.Errorf("asset amount must be specified " +
				"for keysend payment")
		}

		var balances []*rfqmsg.AssetBalance

		switch {
		case specifier.HasId():
			balances = []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(
					*specifier.UnwrapIdToPtr(),
					req.AssetAmount,
				),
			}

		case specifier.HasGroupPubKey():
			groupKey := specifier.UnwrapGroupKeyToPtr()
			groupKeyX := schnorr.SerializePubKey(groupKey)

			// We can't distribute the amount over distinct asset ID
			// balances, so we provide the total amount under the
			// dummy asset ID that is produced by hashing the group
			// key.
			balances = []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(
					asset.ID(groupKeyX), req.AssetAmount,
				),
			}
		}

		htlc := rfqmsg.NewHtlc(balances, fn.None[rfqmsg.ID]())

		// We'll now map the HTLC struct into a set of TLV records,
		// which we can then encode into the map format expected.
		htlcMapRecords, err := tlv.RecordsToMap(htlc.Records())
		if err != nil {
			return fmt.Errorf("unable to encode records as map: %w",
				err)
		}

		pReq.FirstHopCustomRecords = htlcMapRecords
	}

	rpcCtx, _, routerClient := r.cfg.Lnd.Router.RawClientWithMacAuth(ctx)
	updateStream, err := routerClient.SendPaymentV2(rpcCtx, pReq)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-r.quit:
			return fmt.Errorf("server shutting down")

		default:
		}

		update, err := updateStream.Recv()
		if err != nil {
			// Stream is closed; no more updates.
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to receive payment "+
				"update: %w", err)
		}

		err = stream.Send(&tchrpc.SendPaymentResponse{
			Result: &tchrpc.SendPaymentResponse_PaymentResult{
				PaymentResult: update,
			},
		})
		if err != nil {
			return err
		}

		// If the payment failed, return an error and stop listening
		// for updates immediately.
		if update.Status == lnrpc.Payment_FAILED {
			return fmt.Errorf("payment failed: %s",
				update.FailureReason.String())
		}
	}
}

// parseRequest parses the payment request and returns the payment maximum
// amount and the expiry time.
func (r *rpcServer) parseRequest(
	req *routerrpc.SendPaymentRequest) (lnwire.MilliSatoshi, time.Time,
	error) {

	invoice, err := zpay32.Decode(req.PaymentRequest, r.cfg.Lnd.ChainParams)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("error decoding payment "+
			"request: %w", err)
	}

	var paymentMaxAmt lnwire.MilliSatoshi
	if invoice.MilliSat == nil {
		amt, err := lnrpc.UnmarshallAmt(req.Amt, req.AmtMsat)
		if err != nil {
			return 0, time.Time{}, fmt.Errorf("error "+
				"unmarshalling amount: %w", err)
		}
		if amt == 0 {
			return 0, time.Time{}, errors.New("amount must be " +
				"specified when paying a zero amount invoice")
		}

		paymentMaxAmt = amt
	} else {
		paymentMaxAmt = *invoice.MilliSat
	}

	// Calculate the fee limit that should be used for this payment.
	feeLimit, err := lnrpc.UnmarshallAmt(
		req.FeeLimitSat, req.FeeLimitMsat,
	)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("error unmarshalling fee "+
			"limit: %w", err)
	}

	paymentMaxAmt += feeLimit

	expiry := invoice.Timestamp.Add(invoice.Expiry())
	return paymentMaxAmt, expiry, nil
}

// checkOverpayment checks if paying a certain invoice amount requires
// overpayment when using assets to pay, given the rate from the accepted quote
// and the minimum non-dust HTLC amount dictated by the protocol.
func checkOverpayment(quote *rfqrpc.PeerAcceptedSellQuote,
	paymentAmount lnwire.MilliSatoshi, allowOverpay bool) error {

	rateFP, err := rpcutils.UnmarshalRfqFixedPoint(quote.BidAssetRate)
	if err != nil {
		return fmt.Errorf("cannot unmarshal asset rate: %w", err)
	}

	// If the calculated asset amount is zero, we can't pay this amount
	// using assets, so we'll reject the payment even if the user has set
	// the override flag.
	if quote.AssetAmount == 0 {
		oneUnit := rfqmath.NewBigIntFixedPoint(1, 0)
		oneUnitAsMSat := rfqmath.UnitsToMilliSatoshi(oneUnit, *rateFP)
		return fmt.Errorf("rejecting payment of %v (invoice amount + "+
			"user-defined routing fee limit), smallest payable "+
			"amount with assets is equivalent to %v",
			paymentAmount, oneUnitAsMSat)
	}

	srvrLog.Debugf("Checking if payment is economical (min transportable "+
		"mSat: %d, paymentAmount: %d, allowOverpay=%v)",
		quote.MinTransportableMsat, paymentAmount, allowOverpay)

	// If the override flag is set, we ignore this check and return early.
	if allowOverpay {
		return nil
	}

	// If the payment amount is less than the minimal transportable amount
	// dictated by the quote, we'll return an error to inform the user. They
	// can still override this check if they want to proceed anyway.
	if lnwire.MilliSatoshi(quote.MinTransportableMsat) > paymentAmount {
		return fmt.Errorf("rejecting payment of %v (invoice "+
			"amount + user-defined routing fee limit), minimum "+
			"amount for an asset payment is %v mSAT with the "+
			"current rate of %v units/BTC; override this check "+
			"by specifying the allow_overpay flag",
			paymentAmount, quote.MinTransportableMsat,
			rateFP.String())
	}

	// The amount checks out, we can proceed with the payment.
	return nil
}

// AddInvoice is a wrapper around lnd's lnrpc.AddInvoice method with asset
// specific parameters. It allows RPC users to create invoices that correspond
// to the specified asset amount.
func (r *rpcServer) AddInvoice(ctx context.Context,
	req *tchrpc.AddInvoiceRequest) (*tchrpc.AddInvoiceResponse, error) {

	if len(req.AssetId) > 0 && len(req.GroupKey) > 0 {
		return nil, fmt.Errorf("cannot set both asset id and group key")
	}

	if req.InvoiceRequest == nil {
		return nil, fmt.Errorf("invoice request must be specified")
	}
	iReq := req.InvoiceRequest

	assetID, groupKey, err := parseAssetSpecifier(
		req.AssetId, "", req.GroupKey, "",
	)
	if err != nil {
		return nil, err
	}

	specifier, err := asset.NewExclusiveSpecifier(assetID, groupKey)
	if err != nil {
		return nil, err
	}

	// The peer public key is optional if there is only a single asset
	// channel.
	var peerPubKey *route.Vertex
	if len(req.PeerPubkey) > 0 {
		parsedKey, err := route.NewVertexFromBytes(req.PeerPubkey)
		if err != nil {
			return nil, fmt.Errorf("error parsing peer pubkey: %w",
				err)
		}

		peerPubKey = &parsedKey
	}

	// We can now query the asset channels we have.
	assetChan, err := r.rfqChannel(
		ctx, specifier, peerPubKey, ReceiveIntention,
	)
	if err != nil {
		return nil, fmt.Errorf("error finding asset channel to use: %w",
			err)
	}

	// Even if the user didn't specify the peer public key before, we
	// definitely know it now. So let's make sure it's always set.
	peerPubKey = &assetChan.channelInfo.PubKeyBytes

	expirySeconds := iReq.Expiry
	if expirySeconds == 0 {
		expirySeconds = int64(rfq.DefaultInvoiceExpiry.Seconds())
	}
	expiryTimestamp := time.Now().Add(
		time.Duration(expirySeconds) * time.Second,
	)

	// We now want to calculate the upper bound of the RFQ order, which
	// either is the asset amount specified by the user, or the converted
	// satoshi amount of the invoice, expressed in asset units, using the
	// local price oracle's conversion rate.
	maxUnits, err := calculateAssetMaxAmount(
		ctx, r.cfg.PriceOracle, specifier, req.AssetAmount, iReq,
		r.cfg.RfqManager.GetPriceDeviationPpm(),
	)
	if err != nil {
		return nil, fmt.Errorf("error calculating asset max "+
			"amount: %w", err)
	}

	rpcSpecifier := marshalAssetSpecifier(specifier)

	resp, err := r.AddAssetBuyOrder(ctx, &rfqrpc.AddAssetBuyOrderRequest{
		AssetSpecifier: &rpcSpecifier,
		AssetMaxAmt:    maxUnits,
		Expiry:         uint64(expiryTimestamp.Unix()),
		PeerPubKey:     peerPubKey[:],
		TimeoutSeconds: uint32(
			rfq.DefaultTimeout.Seconds(),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("error adding buy order: %w", err)
	}

	var acceptedQuote *rfqrpc.PeerAcceptedBuyQuote
	switch r := resp.Response.(type) {
	case *rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote:
		acceptedQuote = r.AcceptedQuote

	case *rfqrpc.AddAssetBuyOrderResponse_InvalidQuote:
		return nil, fmt.Errorf("peer %v sent back an invalid quote, "+
			"status: %v", r.InvalidQuote.Peer,
			r.InvalidQuote.Status.String())

	case *rfqrpc.AddAssetBuyOrderResponse_RejectedQuote:
		return nil, fmt.Errorf("peer %v rejected the quote, code: %v, "+
			"error message: %v", r.RejectedQuote.Peer,
			r.RejectedQuote.ErrorCode, r.RejectedQuote.ErrorMessage)

	default:
		return nil, fmt.Errorf("unexpected response type: %T", r)
	}

	// Now that we have the accepted quote, we know the amount in (milli)
	// Satoshi that we need to pay. We can now update the invoice with this
	// amount.
	invoiceAmtMsat, err := validateInvoiceAmount(
		acceptedQuote, req.AssetAmount, iReq,
	)
	if err != nil {
		return nil, fmt.Errorf("error validating invoice amount: %w",
			err)
	}
	iReq.ValueMsat = int64(invoiceAmtMsat)

	// The last step is to create a hop hint that includes the fake SCID of
	// the quote, alongside the channel's routing policy. We need to choose
	// the policy that points towards us, as the payment will be flowing in.
	// So we get the policy that's being set by the remote peer.
	channelID := assetChan.channelInfo.ChannelID
	inboundPolicy, err := r.getInboundPolicy(
		ctx, channelID, peerPubKey.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get inbound channel policy "+
			"for channel with ID %d: %w", channelID, err)
	}

	// If this is a hodl invoice, then we'll copy over the relevant fields,
	// then route this through the invoicerpc instead.
	if req.HodlInvoice != nil {
		payHash, err := lntypes.MakeHash(req.HodlInvoice.PaymentHash)
		if err != nil {
			return nil, fmt.Errorf("error creating payment "+
				"hash: %w", err)
		}

		peerPub, err := btcec.ParsePubKey(peerPubKey[:])
		if err != nil {
			return nil, fmt.Errorf("error parsing peer "+
				"pubkey: %w", err)
		}

		hopHint := []zpay32.HopHint{
			{
				NodeID:      peerPub,
				ChannelID:   acceptedQuote.Scid,
				FeeBaseMSat: uint32(inboundPolicy.FeeBaseMsat),
				FeeProportionalMillionths: uint32(
					inboundPolicy.FeeRateMilliMsat,
				),
				CLTVExpiryDelta: uint16(
					inboundPolicy.TimeLockDelta,
				),
			},
		}

		payReq, err := r.cfg.Lnd.Invoices.AddHoldInvoice(
			ctx, &invoicesrpc.AddInvoiceData{
				Memo: iReq.Memo,
				Value: lnwire.MilliSatoshi(
					iReq.ValueMsat,
				),
				Hash:            &payHash,
				DescriptionHash: iReq.DescriptionHash,
				Expiry:          iReq.Expiry,
				// We set private to false as we don't want to
				// add any hop hints other than this one.
				Private:     false,
				HodlInvoice: true,
				RouteHints:  [][]zpay32.HopHint{hopHint},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("error creating hodl invoice: "+
				"%w", err)
		}

		return &tchrpc.AddInvoiceResponse{
			AcceptedBuyQuote: acceptedQuote,
			InvoiceResult: &lnrpc.AddInvoiceResponse{
				PaymentRequest: payReq,
			},
		}, nil
	}

	// Otherwise, we'll make this into a normal invoice.
	hopHint := &lnrpc.HopHint{
		NodeId:      peerPubKey.String(),
		ChanId:      acceptedQuote.Scid,
		FeeBaseMsat: uint32(inboundPolicy.FeeBaseMsat),
		FeeProportionalMillionths: uint32(
			inboundPolicy.FeeRateMilliMsat,
		),
		CltvExpiryDelta: inboundPolicy.TimeLockDelta,
	}
	iReq.RouteHints = []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				hopHint,
			},
		},
	}

	rpcCtx, _, rawClient := r.cfg.Lnd.Client.RawClientWithMacAuth(ctx)
	invoiceResp, err := rawClient.AddInvoice(rpcCtx, iReq)
	if err != nil {
		return nil, fmt.Errorf("error creating invoice: %w", err)
	}

	return &tchrpc.AddInvoiceResponse{
		AcceptedBuyQuote: acceptedQuote,
		InvoiceResult:    invoiceResp,
	}, nil
}

// calculateAssetMaxAmount calculates the max units to be placed in the invoice
// RFQ quote order. When adding invoices based on asset units, that value is
// directly returned. If using the value/value_msat fields of the invoice then
// a price oracle query will take place to calculate the max units of the quote.
func calculateAssetMaxAmount(ctx context.Context, priceOracle rfq.PriceOracle,
	specifier asset.Specifier, requestAssetAmount uint64,
	inv *lnrpc.Invoice, deviationPPM uint64) (uint64, error) {

	// Let's unmarshall the satoshi related fields to see if an amount was
	// set based on those.
	amtMsat, err := lnrpc.UnmarshallAmt(inv.Value, inv.ValueMsat)
	if err != nil {
		return 0, err
	}

	// Let's make sure that only one type of amount is set, in order to
	// avoid ambiguous behavior. This field dictates the actual value of the
	// invoice so let's be strict and only allow one possible value to be
	// set.
	if requestAssetAmount > 0 && amtMsat != 0 {
		return 0, fmt.Errorf("cannot set both asset amount and sats " +
			"amount")
	}

	// If the invoice is being added based on asset units, there's nothing
	// to do so return the amount directly.
	if amtMsat == 0 {
		return requestAssetAmount, nil
	}

	// If the invoice defines the desired amount in satoshis, we need to
	// query our oracle first to get an estimation on the asset rate. This
	// will help us establish a quote with the correct amount of asset
	// units.
	maxUnits, err := rfq.EstimateAssetUnits(
		ctx, priceOracle, specifier, amtMsat,
	)
	if err != nil {
		return 0, err
	}

	maxMathUnits := rfqmath.NewBigIntFromUint64(maxUnits)

	// Since we used a different oracle price query above calculate the max
	// amount of units, we want to add some breathing room to account for
	// price fluctuations caused by the small-time delay, plus the fact that
	// the agreed upon quote may be different. If we don't add this safety
	// window the peer may allow a routable amount that evaluates to less
	// than what we ask for.
	// Apply the tolerance margin twice. Once due to the ask/bid price
	// deviation that may occur during rfq negotiation, and once for the
	// price movement that may occur between querying the oracle and
	// acquiring the quote. We don't really care about this margin being too
	// big, this only affects the max units our peer agrees to route.
	tolerance := rfqmath.NewBigIntFromUint64(deviationPPM)

	maxMathUnits = rfqmath.AddTolerance(maxMathUnits, tolerance)
	maxMathUnits = rfqmath.AddTolerance(maxMathUnits, tolerance)

	return maxMathUnits.ToUint64(), nil
}

// validateInvoiceAmount validates the quote against the invoice we're trying to
// add. It returns the value in msat that should be included in the invoice.
func validateInvoiceAmount(acceptedQuote *rfqrpc.PeerAcceptedBuyQuote,
	requestAssetAmount uint64, inv *lnrpc.Invoice) (lnwire.MilliSatoshi,
	error) {

	invoiceAmtMsat, err := lnrpc.UnmarshallAmt(inv.Value, inv.ValueMsat)
	if err != nil {
		return 0, err
	}

	// Now that we have the accepted quote, we know the amount in Satoshi
	// that we need to pay. We can now update the invoice with this amount.
	//
	// First, un-marshall the ask asset rate from the accepted quote.
	askAssetRate, err := rpcutils.UnmarshalRfqFixedPoint(
		acceptedQuote.AskAssetRate,
	)
	if err != nil {
		return 0, fmt.Errorf("error unmarshalling ask asset rate: %w",
			err)
	}

	// We either have a requested amount in milli satoshi that we want to
	// validate against the quote's max amount (in which case we overwrite
	// the invoiceUnits), or we have a requested amount in asset units that
	// we want to convert into milli satoshis (and overwrite
	// newInvoiceAmtMsat).
	var (
		newInvoiceAmtMsat = invoiceAmtMsat
		invoiceUnits      = requestAssetAmount
	)
	switch {
	case invoiceAmtMsat != 0:
		// If the invoice was created with a satoshi amount, we need to
		// calculate the units.
		invoiceUnits = rfqmath.MilliSatoshiToUnits(
			invoiceAmtMsat, *askAssetRate,
		).ScaleTo(0).ToUint64()

		// Now let's see if the negotiated quote can actually route the
		// amount we need in msat.
		maxFixedUnits := rfqmath.NewBigIntFixedPoint(
			acceptedQuote.AssetMaxAmount, 0,
		)
		maxRoutableMsat := rfqmath.UnitsToMilliSatoshi(
			maxFixedUnits, *askAssetRate,
		)

		if maxRoutableMsat <= invoiceAmtMsat {
			return 0, fmt.Errorf("cannot create invoice for %v "+
				"msat, max routable amount is %v msat",
				invoiceAmtMsat, maxRoutableMsat)
		}

	default:
		// Convert the asset amount into a fixed-point.
		assetAmount := rfqmath.NewBigIntFixedPoint(invoiceUnits, 0)

		// Calculate the invoice amount in msat.
		newInvoiceAmtMsat = rfqmath.UnitsToMilliSatoshi(
			assetAmount, *askAssetRate,
		)
	}

	// If the invoice is for an asset unit amount smaller than the minimal
	// transportable amount, we'll return an error, as it wouldn't be
	// payable by the network.
	if acceptedQuote.MinTransportableUnits > invoiceUnits {
		return 0, fmt.Errorf("cannot create invoice for %d asset "+
			"units, as the minimal transportable amount is %d "+
			"units with the current rate of %v units/BTC",
			invoiceUnits, acceptedQuote.MinTransportableUnits,
			acceptedQuote.AskAssetRate)
	}

	return newInvoiceAmtMsat, nil
}

// DeclareScriptKey declares a new script key to the wallet. This is useful
// when the script key contains scripts, which would mean it wouldn't be
// recognized by the wallet automatically. Declaring a script key will make any
// assets sent to the script key be recognized as being local assets.
func (r *rpcServer) DeclareScriptKey(ctx context.Context,
	in *wrpc.DeclareScriptKeyRequest) (*wrpc.DeclareScriptKeyResponse,
	error) {

	scriptKey, err := rpcutils.UnmarshalScriptKey(in.ScriptKey)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling script key: %w",
			err)
	}

	// Because we've been given the key over the RPC interface, we can't be
	// 100% sure of the type, if it wasn't declared. But we can make a
	// best-effort guess based on the fields the user has set. This is a
	// no-op if the type is already set.
	scriptKey.Type = scriptKey.DetermineType()

	// The user is declaring the key, so they should know what type it is.
	// So if they didn't set it, and it wasn't an obvious one, we'll require
	// them to set it.
	if scriptKey.Type == asset.ScriptKeyUnknown {
		return nil, fmt.Errorf("script key type must be set")
	}

	err = r.cfg.TapAddrBook.InsertScriptKey(ctx, *scriptKey, scriptKey.Type)
	if err != nil {
		return nil, fmt.Errorf("error inserting script key: %w", err)
	}

	return &wrpc.DeclareScriptKeyResponse{
		ScriptKey: rpcutils.MarshalScriptKey(*scriptKey),
	}, nil
}

// serialize is a helper function that serializes a serializable object into a
// byte slice.
func serialize(s interface{ Serialize(io.Writer) error }) ([]byte, error) {
	var b bytes.Buffer
	err := s.Serialize(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// decodeVirtualPackets decodes a slice of raw virtual packet bytes into a slice
// of virtual packets.
func decodeVirtualPackets(rawPackets [][]byte) ([]*tappsbt.VPacket, error) {
	packets := make([]*tappsbt.VPacket, len(rawPackets))
	for idx := range rawPackets {
		var err error
		packets[idx], err = tappsbt.Decode(rawPackets[idx])
		if err != nil {
			return nil, fmt.Errorf("error decoding virtual packet "+
				"at index %d: %w", idx, err)
		}
	}

	return packets, nil
}

// encodeVirtualPackets encodes a slice of virtual packets into a slice of raw
// virtual packet bytes.
func encodeVirtualPackets(packets []*tappsbt.VPacket) ([][]byte, error) {
	rawPackets := make([][]byte, len(packets))
	for idx := range packets {
		var err error
		rawPackets[idx], err = tappsbt.Encode(packets[idx])
		if err != nil {
			return nil, fmt.Errorf("error serializing packet: %w",
				err)
		}
	}

	return rawPackets, nil
}

// DecDisplayForAssetID attempts to fetch the meta reveal for a specific asset
// ID and extract the decimal display value from it.
func (r *rpcServer) DecDisplayForAssetID(ctx context.Context,
	id asset.ID) (fn.Option[uint32], error) {

	meta, err := r.cfg.AddrBook.FetchAssetMetaForAsset(ctx, id)
	if err != nil {
		return fn.None[uint32](), fmt.Errorf("unable to fetch asset "+
			"meta for asset_id=%v :%v", id, err)
	}

	return meta.DecDisplayOption()
}

// chanIntention defines the intention of calling rfqChannel. This helps with
// returning the channel that is most suitable for what we want to do.
type chanIntention uint8

const (
	// NoIntention defines the absence of any intention, signalling that we
	// don't really care which channel is returned.
	NoIntention chanIntention = iota

	// SendIntention defines the intention to send over an asset channel.
	SendIntention

	// ReceiveIntention defines the intention to receive over an asset
	// channel.
	ReceiveIntention
)

// rfqChannel returns the channel to use for RFQ operations. If a peer public
// key is specified, the channels are filtered by that peer. If there are
// multiple channels for the same specifier, the user must specify the peer
// public key.
func (r *rpcServer) rfqChannel(ctx context.Context, specifier asset.Specifier,
	peerPubKey *route.Vertex,
	intention chanIntention) (*channelWithSpecifier, error) {

	balances, err := r.computeChannelAssetBalance(ctx, specifier)
	if err != nil {
		return nil, fmt.Errorf("error computing available asset "+
			"channel balance: %w", err)
	}

	if len(balances) == 0 {
		return nil, fmt.Errorf("no asset channel balance found for %s",
			&specifier)
	}

	// If a peer public key was specified, we always want to use that to
	// filter the asset channels.
	if peerPubKey != nil {
		balances = fn.Filter(
			balances, func(c channelWithSpecifier) bool {
				return c.channelInfo.PubKeyBytes == *peerPubKey
			},
		)
	}

	switch {
	// If there are multiple asset channels for the same specifier, we need
	// to ask the user to specify the peer public key. Otherwise, we don't
	// know who to ask for a quote.
	case len(balances) > 1 && peerPubKey == nil:
		return nil, fmt.Errorf("multiple asset channels found for "+
			"%s, please specify the peer pubkey", &specifier)

	// We don't have any channels with that asset ID and peer.
	case len(balances) == 0:
		return nil, fmt.Errorf("no asset channel found for %s",
			&specifier)
	}

	// If the user specified a peer public key, and we still have multiple
	// channels, it means we have multiple channels with the same asset and
	// the same peer, as we ruled out the rest of the cases above.

	// Initialize best balance to first channel of the list.
	bestBalance := balances[0]

	switch intention {
	case ReceiveIntention:
		// If the intention is to receive, return the channel
		// with the best remote balance.
		fn.ForEach(balances, func(b channelWithSpecifier) {
			if b.assetInfo.RemoteBalance >
				bestBalance.assetInfo.RemoteBalance {

				bestBalance = b
			}
		})

	case SendIntention:
		// If the intention is to send, return the channel with
		// the best local balance.
		fn.ForEach(balances, func(b channelWithSpecifier) {
			if b.assetInfo.LocalBalance >
				bestBalance.assetInfo.LocalBalance {

				bestBalance = b
			}
		})

	case NoIntention:
		// Do nothing. Just return the first element that was
		// assigned above.
	}

	return &bestBalance, nil
}

// channelWithSpecifier is a helper struct that combines the information of an
// asset specifier that is satisfied by a channel with the channels' general
// information.
type channelWithSpecifier struct {
	// specifier is the asset specifier that is satisfied by this channels'
	// assets.
	specifier asset.Specifier

	// channelInfo is the information about the channel the asset is
	// committed to.
	channelInfo lndclient.ChannelInfo

	// assetInfo contains the asset related info of the channel.
	assetInfo rfqmsg.JsonAssetChannel
}

// computeChannelAssetBalance computes the total local and remote balance for
// each asset channel that matches the provided asset specifier.
func (r *rpcServer) computeChannelAssetBalance(ctx context.Context,
	specifier asset.Specifier) ([]channelWithSpecifier, error) {

	activeChannels, err := r.cfg.Lnd.Client.ListChannels(ctx, true, false)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch channels: %w", err)
	}

	channels := make([]channelWithSpecifier, 0)
	for chanIdx := range activeChannels {
		openChan := activeChannels[chanIdx]
		if len(openChan.CustomChannelData) == 0 {
			continue
		}

		var assetData rfqmsg.JsonAssetChannel
		err = json.Unmarshal(openChan.CustomChannelData, &assetData)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal asset "+
				"data: %w", err)
		}

		// Check if the assets of this channel match the provided
		// specifier.
		pass, err := r.cfg.RfqManager.ChannelCompatible(
			ctx, assetData, specifier,
		)
		if err != nil {
			return nil, err
		}

		if pass {
			channels = append(channels, channelWithSpecifier{
				specifier:   specifier,
				channelInfo: openChan,
				assetInfo:   assetData,
			})
		}
	}

	return channels, nil
}

// getInboundPolicy returns the policy of the given channel that points towards
// our node, so it's the policy set by the remote peer.
func (r *rpcServer) getInboundPolicy(ctx context.Context, chanID uint64,
	remotePubStr string) (*lnrpc.RoutingPolicy, error) {

	rpcCtx, _, rawClient := r.cfg.Lnd.Client.RawClientWithMacAuth(ctx)
	edge, err := rawClient.GetChanInfo(rpcCtx, &lnrpc.ChanInfoRequest{
		ChanId: chanID,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch channel: %w", err)
	}

	policy := edge.Node2Policy
	if edge.Node2Pub == remotePubStr {
		policy = edge.Node1Policy
	}

	return policy, nil
}

// assetInvoiceAmt calculates the amount of asset units to pay for an invoice
// which is expressed in sats.
func (r *rpcServer) assetInvoiceAmt(ctx context.Context,
	targetAsset asset.Specifier,
	invoiceAmt lnwire.MilliSatoshi) (uint64, error) {

	oracle := r.cfg.PriceOracle

	oracleResp, err := oracle.QueryAskPrice(
		ctx, targetAsset, fn.None[uint64](), fn.Some(invoiceAmt),
		fn.None[rfqmsg.AssetRate](),
	)
	if err != nil {
		return 0, fmt.Errorf("error querying ask price: %w", err)
	}
	if oracleResp.Err != nil {
		return 0, fmt.Errorf("error querying ask price: %w",
			oracleResp.Err)
	}

	assetRate := oracleResp.AssetRate.Rate

	numAssetUnits := rfqmath.MilliSatoshiToUnits(
		invoiceAmt, assetRate,
	).ScaleTo(0)

	return numAssetUnits.ToUint64(), nil
}

// DecodeAssetPayReq decodes an incoming invoice, then uses the RFQ system to
// map the BTC amount to the amount of asset units for the specified asset ID.
func (r *rpcServer) DecodeAssetPayReq(ctx context.Context,
	payReq *tchrpc.AssetPayReq) (*tchrpc.AssetPayReqResponse, error) {

	if r.cfg.PriceOracle == nil {
		return nil, fmt.Errorf("price oracle is not set")
	}

	// First, we'll perform some basic input validation.
	switch {
	case len(payReq.AssetId) == 0:
		return nil, fmt.Errorf("asset ID must be specified")

	case len(payReq.AssetId) != 32:
		return nil, fmt.Errorf("asset ID must be 32 bytes, "+
			"was %d", len(payReq.AssetId))

	case len(payReq.PayReqString) == 0:
		return nil, fmt.Errorf("payment request must be specified")
	}

	var (
		resp    tchrpc.AssetPayReqResponse
		assetID asset.ID
	)

	copy(assetID[:], payReq.AssetId)

	// With the inputs validated, we'll first call out to lnd to decode the
	// payment request.
	rpcCtx, _, rawClient := r.cfg.Lnd.Client.RawClientWithMacAuth(ctx)
	payReqInfo, err := rawClient.DecodePayReq(rpcCtx, &lnrpc.PayReqString{
		PayReq: payReq.PayReqString,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch channel: %w", err)
	}

	resp.PayReq = payReqInfo

	// Next, we'll fetch the information for this asset ID through the addr
	// book. This'll automatically fetch the asset if needed.
	assetGroup, err := r.cfg.AddrBook.QueryAssetInfo(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch asset info for "+
			"asset_id=%x: %w", assetID[:], err)
	}

	resp.GenesisInfo = &taprpc.GenesisInfo{
		GenesisPoint: assetGroup.FirstPrevOut.String(),
		AssetType:    taprpc.AssetType(assetGroup.Type),
		Name:         assetGroup.Tag,
		MetaHash:     assetGroup.MetaHash[:],
		AssetId:      assetID[:],
	}

	// If this asset ID belongs to an asset group, then we'll display that
	// information as well.
	//
	// nolint:lll
	if assetGroup.GroupKey != nil {
		groupInfo := assetGroup.GroupKey
		resp.AssetGroup = &taprpc.AssetGroup{
			RawGroupKey:     groupInfo.RawKey.PubKey.SerializeCompressed(),
			TweakedGroupKey: groupInfo.GroupPubKey.SerializeCompressed(),
			TapscriptRoot:   groupInfo.TapscriptRoot,
		}

		if len(groupInfo.Witness) != 0 {
			resp.AssetGroup.AssetWitness, err = asset.SerializeGroupWitness(
				groupInfo.Witness,
			)
			if err != nil {
				return nil, err
			}
		}
	}

	// Now that we have the basic invoice information, we'll query the RFQ
	// system to obtain a quote to send this amount of BTC. Note that this
	// doesn't factor in the fee limit, so this attempts just to map the
	// sats amount to an asset unit.
	numMsat := lnwire.NewMSatFromSatoshis(
		btcutil.Amount(payReqInfo.NumSatoshis),
	)
	targetAsset := asset.NewSpecifierOptionalGroupKey(
		assetGroup.ID(), assetGroup.GroupKey,
	)
	invoiceAmt, err := r.assetInvoiceAmt(ctx, targetAsset, numMsat)
	if err != nil {
		return nil, fmt.Errorf("error deriving asset amount: %w", err)
	}

	resp.AssetAmount = invoiceAmt

	// The final piece of information we need is the decimal display
	// information for this asset ID.
	decDisplay, err := r.DecDisplayForAssetID(ctx, assetID)
	if err != nil {
		return nil, err
	}

	resp.DecimalDisplay = fn.MapOptionZ(
		decDisplay, func(d uint32) *taprpc.DecimalDisplay {
			return &taprpc.DecimalDisplay{
				DecimalDisplay: d,
			}
		},
	)

	return &resp, nil
}

// RegisterTransfer informs the daemon about a new inbound transfer that has
// happened. This is used for interactive transfers where no TAP address is
// involved and the recipient is aware of the transfer through an out-of-band
// protocol but the daemon hasn't been informed about the completion of the
// transfer. For this to work, the proof must already be in the recipient's
// local universe (e.g. through the use of the universerpc.ImportProof RPC or
// the universe proof courier and universe sync mechanisms) and this call
// simply instructs the daemon to detect the transfer as an asset it owns.
func (r *rpcServer) RegisterTransfer(ctx context.Context,
	req *taprpc.RegisterTransferRequest) (*taprpc.RegisterTransferResponse,
	error) {

	// First, we'll perform some basic input validation.
	switch {
	case len(req.AssetId) == 0:
		return nil, fmt.Errorf("asset ID must be specified")

	case len(req.AssetId) != 32:
		return nil, fmt.Errorf("asset ID must be 32 bytes, was %d",
			len(req.AssetId))

	case len(req.GroupKey) > 0 && len(req.GroupKey) != 33:
		return nil, fmt.Errorf("group key must be 33 bytes, was %d",
			len(req.GroupKey))

	case len(req.ScriptKey) == 0:
		return nil, fmt.Errorf("script key must be specified")

	case len(req.ScriptKey) != 33:
		return nil, fmt.Errorf("script key must be 33 bytes, was %d",
			len(req.ScriptKey))

	case req.Outpoint == nil:
		return nil, fmt.Errorf("outpoint must be specified")
	}

	// We'll query our local universe for the full proof. Since we're
	// talking about a transfer here, we'll only look at transfer proofs.
	var (
		locator = proof.Locator{
			AssetID: &asset.ID{},
		}
		err error
	)
	copy(locator.AssetID[:], req.AssetId)

	if len(req.GroupKey) > 0 {
		locator.GroupKey, err = btcec.ParsePubKey(req.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing group key: %w",
				err)
		}
	}

	scriptPubKey, err := btcec.ParsePubKey(req.ScriptKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing script key: %w", err)
	}
	locator.ScriptKey = *scriptPubKey

	hash, err := chainhash.NewHash(req.Outpoint.Txid)
	if err != nil {
		return nil, err
	}
	locator.OutPoint = &wire.OutPoint{
		Hash:  *hash,
		Index: req.Outpoint.OutputIndex,
	}

	// Before we query for the proof, we want to make sure the script key is
	// already known to us. In an interactive transfer, we'd expect a script
	// key to be derived on the recipient node, so it should already be
	// registered. This is mainly to prevent the user from importing a proof
	// for an asset that they won't be able to spend, because it doesn't
	// belong to this node (which is the main issue with the old
	// tapdevrpc.ImportProof RPC).
	_, err = r.cfg.DatabaseConfig.TapAddrBook.FetchScriptKey(
		ctx, scriptPubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching script key, consider "+
			"declaring it with DeclareScriptKey if it does "+
			"belong to this node: %w", err)
	}

	// Next, we make sure we don't already have this proof in the local
	// archive (only in the universe). If we have, it means the user already
	// imported it, and we don't want to overwrite it.
	haveProof, err := r.cfg.ProofArchive.HasProof(ctx, locator)
	if err != nil {
		return nil, fmt.Errorf("error checking if proof is available: "+
			"%w", err)
	}
	if haveProof {
		return nil, fmt.Errorf("proof already exists for this transfer")
	}

	// We now fetch the full proof file from the local multiverse store,
	// making sure we have the full proof chain for this transfer.
	fullProvenance, err := r.cfg.Multiverse.FetchProof(ctx, locator)
	if err != nil {
		return nil, fmt.Errorf("error fetching full proof: %w", err)
	}

	// Let's make sure we can parse it as a file.
	proofFile, err := fullProvenance.AsFile()
	if err != nil {
		return nil, fmt.Errorf("error converting proof to file: %w",
			err)
	}

	// All seems well, we can now import the proof into our local proof
	// archive, which will also materialize an asset in the asset database.
	headerVerifier := tapgarden.GenHeaderVerifier(ctx, r.cfg.ChainBridge)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, r.cfg.MintingStore)

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: r.cfg.ChainBridge,
	}

	err = r.cfg.ProofArchive.ImportProofs(
		ctx, vCtx, false, &proof.AnnotatedProof{
			Locator: locator,
			Blob:    fullProvenance,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error importing proof: %w", err)
	}

	// In case this proof hasn't been buried sufficiently, let's also hand
	// it to the re-org watcher.
	err = r.cfg.ReOrgWatcher.MaybeWatch(
		proofFile, r.cfg.ReOrgWatcher.DefaultUpdateCallback(),
	)
	if err != nil {
		return nil, fmt.Errorf("error watching received proof: %w", err)
	}

	lastProof, err := proofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("error getting last proof: %w", err)
	}

	chainAsset, err := lastProof.ToChainAsset()
	if err != nil {
		return nil, fmt.Errorf("unable to convert proof to chain "+
			"asset: %w", err)
	}

	rpcAsset, err := r.MarshalChainAsset(
		ctx, chainAsset, lastProof.MetaReveal, false, r.cfg.AddrBook,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal chain asset: %w",
			err)
	}

	return &taprpc.RegisterTransferResponse{
		RegisteredAsset: rpcAsset,
	}, nil
}
