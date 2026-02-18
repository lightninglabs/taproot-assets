package custom_channels

import (
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
)

// Variables are prefixed with "cc" (custom channels) to avoid name collisions
// with identically-named vars in other itest files (e.g. multi_send_test.go).
var (
	ccDummyMetaData = &taprpc.AssetMeta{
		Data: []byte("some metadata"),
	}

	ccItestAsset = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-cents",
		AssetMeta: ccDummyMetaData,
		Amount:    1_000_000,
	}

	ccShortTimeout = time.Second * 10

	// ccTransferTimeout is the timeout used when waiting for an asset
	// transfer to appear as confirmed. On CI runners with multiple
	// parallel tranches, tapd block processing can be slow so we use a
	// generous timeout.
	ccTransferTimeout = 2 * time.Minute
)

// lndArgsTemplate contains lnd flags used by all custom channel test nodes.
var lndArgsTemplate = []string{
	"--trickledelay=50",
	"--gossip.sub-batch-delay=5ms",
	"--caches.rpc-graph-cache-duration=100ms",
	"--default-remote-max-htlcs=483",
	"--dust-threshold=5000000",
	"--rpcmiddleware.enable",
	"--protocol.anchors",
	"--protocol.option-scid-alias",
	"--protocol.zero-conf",
	"--protocol.simple-taproot-chans",
	"--protocol.simple-taproot-overlay-chans",
	"--protocol.custom-message=17",
	"--accept-keysend",
	"--debuglevel=debug,BTCN=info,NTFN=info,DISC=info",
	"--height-hint-cache-query-disable",
}

// tapdArgsTemplateNoOracle contains tapd flags without the price oracle. The
// --taproot-assets. prefix is omitted because prefixArgs() adds it
// automatically when building the integrated binary command line.
var tapdArgsTemplateNoOracle = []string{
	"--debuglevel=debug,UNIV=info,PROF=info",
	"--allow-public-uni-proof-courier",
	"--universe.public-access=rw",
	"--universe.sync-all-assets",
	"--universerpccourier.skipinitdelay",
	"--universerpccourier.backoffresetwait=100ms",
	"--universerpccourier.numtries=5",
	"--universerpccourier.initialbackoff=300ms",
	"--universerpccourier.maxbackoff=600ms",
	"--custodianproofretrievaldelay=500ms",
}

// tapdArgsTemplate includes the default mock price oracle configuration on
// top of tapdArgsTemplateNoOracle.
//
//nolint:lll
var tapdArgsTemplate = append(tapdArgsTemplateNoOracle, []string{
	"--experimental.rfq.priceoracleaddress=" +
		"use_mock_price_oracle_service_promise_to_" +
		"not_use_on_mainnet",
	"--experimental.rfq.mockoracleassetsperbtc=5820600",
	"--experimental.rfq.acceptpricedeviationppm=50000",
}...)

// tapdArgsTemplateDiffOracle is like tapdArgsTemplate but with a different
// mock oracle rate (used for multi-RFQ tests).
//
//nolint:lll
var tapdArgsTemplateDiffOracle = append(tapdArgsTemplateNoOracle, []string{
	"--experimental.rfq.priceoracleaddress=" +
		"use_mock_price_oracle_service_promise_to_" +
		"not_use_on_mainnet",
	"--experimental.rfq.mockoracleassetsperbtc=8820600",
	"--experimental.rfq.acceptpricedeviationppm=50000",
}...)

// nolint:lll
var (
	failureNoBalance        = lnrpc.PaymentFailureReason_FAILURE_REASON_INSUFFICIENT_BALANCE
	failureNoRoute          = lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE
	failureIncorrectDetails = lnrpc.PaymentFailureReason_FAILURE_REASON_INCORRECT_PAYMENT_DETAILS
	failureTimeout          = lnrpc.PaymentFailureReason_FAILURE_REASON_TIMEOUT
	failureNone             = lnrpc.PaymentFailureReason_FAILURE_REASON_NONE
)

// burnAddr is a regtest address used to drain wallet funds.
var burnAddr = "bcrt1qlthqw0zmup27nx35hcy82vkc4qjcxgmkvhnjtc"

const (
	fundingAmount = 50_000
	startAmount   = fundingAmount * 2

	// PaymentTimeout is the default payment timeout used in custom
	// channel tests.
	PaymentTimeout = 12 * time.Second

	// DefaultPushSat is the default push amount in satoshis when opening
	// custom channels.
	DefaultPushSat int64 = 1062

	// assetBurnConfirmationText is the text that needs to be set on the
	// RPC to confirm an asset burn.
	assetBurnConfirmationText = "assets will be destroyed"
)
