package lndservices

import (
	"errors"
	"testing"

	btcwalletchain "github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDefinitivePublishError(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		err        error
		definitive bool
	}{
		{
			name: "collapsed missing or spent input is ambiguous",
			err: status.Error(
				codes.Unknown, lnwallet.ErrDoubleSpend.Error(),
			),
			definitive: false,
		},
		{
			name: "mempool fee with detail",
			err: status.Error(
				codes.Unknown, lnwallet.ErrMempoolFee.Error()+
					": min relay fee not met",
			),
			definitive: true,
		},
		{
			name: "non final transaction",
			err: status.Error(
				codes.Unknown, "non-final",
			),
			definitive: true,
		},
		{
			name: "invalid argument is not the pinned wallet path",
			err: status.Error(
				codes.InvalidArgument,
				"transaction rejected: non final",
			),
			definitive: false,
		},
		{
			name: "failed precondition is not pinned wallet path",
			err: status.Error(
				codes.FailedPrecondition,
				"mandatory-script-verify-flag failed",
			),
			definitive: false,
		},
		{
			name: "bounded dust marker",
			err: status.Error(
				codes.Unknown, "dusting service failed",
			),
			definitive: false,
		},
		{
			name: "incidental standalone dust marker",
			err: status.Error(
				codes.Unknown, "backend dust cache unavailable",
			),
			definitive: false,
		},
		{
			name: "explicitly framed dust rejection",
			err: status.Error(
				codes.Unknown, "transaction rejected: dust",
			),
			definitive: true,
		},
		{
			name: "incidental nonstandard marker",
			err: status.Error(
				codes.Unknown,
				"backend nonstandard cache failure",
			),
			definitive: false,
		},
		{
			name: "bounded fee marker",
			err: status.Error(
				codes.Unknown, "insufficient feedback",
			),
			definitive: false,
		},
		{
			name: "missing inputs override policy marker",
			err: status.Error(
				codes.Unknown,
				"bad-txns-inputs-missingorspent: "+
					"insufficient fee",
			),
			definitive: false,
		},
		{
			name: "mempool conflict overrides dust marker",
			err: status.Error(
				codes.Unknown, "txn-mempool-conflict: dust",
			),
			definitive: false,
		},
		{
			name: "plural conflict overrides dust marker",
			err: status.Error(
				codes.Unknown,
				"transaction conflicts with mempool: dust",
			),
			definitive: false,
		},
		{
			name: "double spend overrides fee marker",
			err: status.Error(
				codes.Unknown, "double-spend: insufficient fee",
			),
			definitive: false,
		},
		{
			name: "replacement conflict overrides fee marker",
			err: status.Error(
				codes.Unknown,
				"replacement transaction underpriced: "+
					"min relay fee not met",
			),
			definitive: false,
		},
		{
			name: "already known overrides policy marker",
			err: status.Error(
				codes.Unknown,
				"txn-already-known: mempool min fee",
			),
			definitive: false,
		},
		{
			name: "known transaction overrides policy marker",
			err: status.Error(
				codes.Unknown,
				"transaction known: mempool min fee",
			),
			definitive: false,
		},
		{
			name: "already in block chain",
			err: status.Error(
				codes.Unknown,
				"transaction already in block chain: dust",
			),
			definitive: false,
		},
		{
			name: "bad txns allowlist entry",
			err: status.Error(
				codes.Unknown, "bad-txns-vout-negative",
			),
			definitive: true,
		},
		{
			name: "unrecognized bad txns reason",
			err: status.Error(
				codes.Unknown, "bad-txns-future-new-reason",
			),
			definitive: false,
		},
		{
			name: "generic application error",
			err: status.Error(
				codes.Unknown, "backend failure",
			),
			definitive: false,
		},
		{
			name: "transport failure",
			err: status.Error(
				codes.Unavailable, "connection closed",
			),
			definitive: false,
		},
		{
			name: "transport failure with policy text",
			err: status.Error(
				codes.Unavailable, "dust",
			),
			definitive: false,
		},
		{
			name: "internal failure with policy text",
			err: status.Error(
				codes.Internal, "insufficient fee",
			),
			definitive: false,
		},
		{
			name: "canceled with policy text",
			err: status.Error(
				codes.Canceled, "non-final",
			),
			definitive: false,
		},
		{
			name: "deadline exceeded with policy text",
			err: status.Error(
				codes.DeadlineExceeded, "dust",
			),
			definitive: false,
		},
		{
			name: "undefined application error with policy text",
			err: status.Error(
				codes.Unknown, "undefined: non-final",
			),
			definitive: false,
		},
		{
			name:       "plain error",
			err:        errors.New("local failure"),
			definitive: false,
		},
		{
			name:       "plain error with policy text",
			err:        errors.New("non-final"),
			definitive: false,
		},
		{
			name:       "raw undefined error with policy text",
			err:        errors.New("undefined: non-final"),
			definitive: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t, testCase.definitive,
				isDefinitivePublishError(testCase.err),
			)
		})
	}
}

func TestDefinitivePublishRPCErrReasons(t *testing.T) {
	t.Parallel()

	definitive := []btcwalletchain.RPCErr{
		btcwalletchain.ErrInsufficientFee,
		btcwalletchain.ErrMempoolMinFeeNotMet,
		btcwalletchain.ErrMinRelayFeeNotMet,
		btcwalletchain.ErrMempoolChainTooLong,
		btcwalletchain.ErrEmptyOutput,
		btcwalletchain.ErrEmptyInput,
		btcwalletchain.ErrTxTooSmall,
		btcwalletchain.ErrDuplicateInput,
		btcwalletchain.ErrEmptyPrevOut,
		btcwalletchain.ErrBelowOutValue,
		btcwalletchain.ErrNegativeOutput,
		btcwalletchain.ErrLargeOutput,
		btcwalletchain.ErrLargeTotalOutput,
		btcwalletchain.ErrScriptVerifyFlag,
		btcwalletchain.ErrTooManySigOps,
		btcwalletchain.ErrOversizeTx,
		btcwalletchain.ErrNonStandardScript,
		btcwalletchain.ErrTxTooLarge,
		btcwalletchain.ErrDust,
		btcwalletchain.ErrNonFinal,
		btcwalletchain.ErrNonBIP68Final,
		btcwalletchain.ErrNonMandatoryScriptVerifyFlag,
	}
	for _, reason := range definitive {
		reason := reason
		t.Run(reason.Error(), func(t *testing.T) {
			err := status.Error(codes.Unknown, reason.Error())
			require.True(t, isDefinitivePublishError(err))
		})
	}

	ambiguous := []btcwalletchain.RPCErr{
		btcwalletchain.ErrMissingInputsOrSpent,
		btcwalletchain.ErrTxAlreadyKnown,
		btcwalletchain.ErrTxAlreadyConfirmed,
		btcwalletchain.ErrMempoolConflict,
		btcwalletchain.ErrReplacementAddsUnconfirmed,
		btcwalletchain.ErrTooManyReplacements,
		btcwalletchain.ErrConflictingTx,
		btcwalletchain.ErrTxAlreadyInMempool,
		btcwalletchain.ErrMissingInputs,
		btcwalletchain.ErrSameNonWitnessData,
	}
	for _, reason := range ambiguous {
		reason := reason
		t.Run(reason.Error(), func(t *testing.T) {
			err := status.Error(codes.Unknown, reason.Error())
			require.False(t, isDefinitivePublishError(err))
		})
	}
}

func TestWrapValidateAndPublishError(t *testing.T) {
	t.Parallel()

	definitiveSource := status.Error(codes.Unknown, "non-final")
	definitiveErr := wrapValidateAndPublishError(definitiveSource)
	require.ErrorContains(
		t, definitiveErr, "unable to validate and publish transaction",
	)
	require.True(t, tapnode.IsDefinitivePublishError(definitiveErr))
	require.ErrorIs(t, definitiveErr, definitiveSource)
	require.Equal(t, codes.Unknown, status.Code(definitiveErr))

	ambiguousSource := status.Error(codes.Unavailable, "connection closed")
	ambiguousErr := wrapValidateAndPublishError(ambiguousSource)
	require.ErrorContains(
		t, ambiguousErr, "unable to validate and publish transaction",
	)
	require.False(t, tapnode.IsDefinitivePublishError(ambiguousErr))
	require.ErrorIs(t, ambiguousErr, ambiguousSource)
	require.Equal(t, codes.Unavailable, status.Code(ambiguousErr))
}
