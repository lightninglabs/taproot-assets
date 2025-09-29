package rpcassert

import (
	"context"
	"fmt"
	"testing"

	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
)

// FetchSupplyCommitRPC calls the FetchSupplyCommit RPC and asserts that the
// returned response matches the given predicate. If the predicate is nil, only
// basic checks are performed (non-nil response).
//
// If the assertion fails, the test is failed.
func FetchSupplyCommitRPC(t *testing.T, ctx context.Context,
	client unirpc.UniverseClient,
	assertPredicate func(*unirpc.FetchSupplyCommitResponse) error,
	req *unirpc.FetchSupplyCommitRequest) *unirpc.FetchSupplyCommitResponse { // nolint: lll

	t.Helper()

	var resp *unirpc.FetchSupplyCommitResponse
	err := wait.NoError(func() error {
		var err error
		resp, err = client.FetchSupplyCommit(ctx, req)
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
