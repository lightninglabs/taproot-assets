package lndservices

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

type customAnchorWalletKitMock struct {
	lndclient.WalletKitClient

	leases            []lndclient.LeaseDescriptor
	listUnspentCalled bool
}

func (m *customAnchorWalletKitMock) ListLeases(
	context.Context) ([]lndclient.LeaseDescriptor, error) {

	return m.leases, nil
}

func (m *customAnchorWalletKitMock) ListUnspent(context.Context, int32,
	int32, ...lndclient.ListUnspentOption) ([]*lnwallet.Utxo, error) {

	m.listUnspentCalled = true
	return nil, nil
}

func TestCustomAnchorLeaseRejectsForeignLock(t *testing.T) {
	var op wire.OutPoint
	op.Index = 7
	foreignID := wtxmgr.LockID(sha256.Sum256([]byte("another-subsystem")))
	walletKit := &customAnchorWalletKitMock{
		leases: []lndclient.LeaseDescriptor{{
			LockID: foreignID, Outpoint: op, Expiration: time.Now().Add(time.Hour),
		}},
	}
	wallet := NewLndRpcWalletAnchor(&lndclient.LndServices{
		WalletKit: walletKit,
	})

	owned, err := wallet.LeaseInput(t.Context(), op)
	require.False(t, owned)
	require.ErrorContains(t, err, "already leased by another subsystem")
	require.False(t, walletKit.listUnspentCalled)
}
