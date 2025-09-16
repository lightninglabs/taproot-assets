package rpcassert

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
)

const (
	defaultWaitTimeout = lntest.DefaultTimeout
)

// NewAddrRPC calls the NewAddr RPC and asserts that the returned address
// matches the given predicate. If the predicate is nil, only basic checks are
// performed (non-nil response).
//
// If the assertion fails, the test is failed.
func NewAddrRPC(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient,
	assertPredicate func(*taprpc.Addr) error,
	req *taprpc.NewAddrRequest) *taprpc.Addr {

	t.Helper()

	var resp *taprpc.Addr
	err := wait.NoError(func() error {
		var err error
		resp, err = client.NewAddr(ctx, req)
		if err != nil {
			return err
		}

		if resp == nil {
			return fmt.Errorf("nil response")
		}

		if assertPredicate != nil {
			return assertPredicate(resp)
		}

		return nil
	}, defaultWaitTimeout)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}
