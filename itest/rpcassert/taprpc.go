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

// ListBalancesRPC calls ListBalances RPC with the given request until the
// given assertion predicate returns no error or the timeout is reached. If the
// predicate is nil, only basic checks are performed (non-nil response).
//
// If the assertion fails, the test is failed.
func ListBalancesRPC(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient,
	assertPredicate func(*taprpc.ListBalancesResponse) error,
	req *taprpc.ListBalancesRequest) *taprpc.ListBalancesResponse {

	t.Helper()

	var resp *taprpc.ListBalancesResponse
	err := wait.NoError(func() error {
		var err error
		resp, err = client.ListBalances(ctx, req)
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

// ListAssetsRPC calls ListAssets RPC with the given request until the
// given assertion predicate returns no error or the timeout is reached. If the
// predicate is nil, only basic checks are performed (non-nil response).
//
// If the assertion fails, the test is failed.
func ListAssetsRPC(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient,
	assertPredicate func(*taprpc.ListAssetResponse) error,
	req *taprpc.ListAssetRequest) *taprpc.ListAssetResponse {

	t.Helper()

	var resp *taprpc.ListAssetResponse
	err := wait.NoError(func() error {
		var err error
		resp, err = client.ListAssets(ctx, req)
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

// ListUtxosRPC calls ListUtxos RPC with the given request until the
// given assertion predicate returns no error or the timeout is reached. If the
// predicate is nil, only basic checks are performed (non-nil response).
//
// If the assertion fails, the test is failed.
func ListUtxosRPC(t *testing.T, ctx context.Context,
	client taprpc.TaprootAssetsClient,
	assertPredicate func(*taprpc.ListUtxosResponse) error,
	req *taprpc.ListUtxosRequest) *taprpc.ListUtxosResponse {

	t.Helper()

	var resp *taprpc.ListUtxosResponse
	err := wait.NoError(func() error {
		var err error
		resp, err = client.ListUtxos(ctx, req)
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
