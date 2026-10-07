package lndservices

import (
	"testing"

	btcwalletchain "github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

	definitiveSource := status.Error(
		codes.Unknown, btcwalletchain.ErrNonFinal.Error(),
	)
	definitiveErr := wrapValidateAndPublishError(definitiveSource)
	require.ErrorContains(
		t, definitiveErr, "unable to validate and publish transaction",
	)
	require.True(t, tapnode.IsDefinitivePublishError(definitiveErr))
	require.ErrorIs(t, definitiveErr, definitiveSource)
	require.Equal(t, codes.Unknown, status.Code(definitiveErr))
}
