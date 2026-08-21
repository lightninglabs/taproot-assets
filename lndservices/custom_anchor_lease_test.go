package lndservices

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

type customAnchorWalletKitMock struct {
	lndclient.WalletKitClient

	leases            []lndclient.LeaseDescriptor
	utxos             []*lnwallet.Utxo
	leaseCalls        []lndclient.LeaseDescriptor
	releaseCalls      []lndclient.LeaseDescriptor
	listUnspentCalled bool
}

func (m *customAnchorWalletKitMock) ListLeases(
	context.Context) ([]lndclient.LeaseDescriptor, error) {

	return m.leases, nil
}

func (m *customAnchorWalletKitMock) ListUnspent(context.Context, int32,
	int32, ...lndclient.ListUnspentOption) ([]*lnwallet.Utxo, error) {

	m.listUnspentCalled = true
	return m.utxos, nil
}

func (m *customAnchorWalletKitMock) LeaseOutput(_ context.Context,
	lockID wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	expiration := time.Now().Add(duration)
	lease := lndclient.LeaseDescriptor{
		LockID:     lockID,
		Outpoint:   op,
		Expiration: expiration,
	}
	for idx := range m.leases {
		if m.leases[idx].Outpoint == op {
			m.leases[idx] = lease
			m.leaseCalls = append(m.leaseCalls, lease)
			return expiration, nil
		}
	}

	m.leases = append(m.leases, lease)
	m.leaseCalls = append(m.leaseCalls, lease)
	return expiration, nil
}

func (m *customAnchorWalletKitMock) ReleaseOutput(_ context.Context,
	lockID wtxmgr.LockID, op wire.OutPoint) error {

	for idx := range m.leases {
		lease := m.leases[idx]
		if lease.Outpoint != op || lease.LockID != lockID {
			continue
		}

		m.releaseCalls = append(m.releaseCalls, lease)
		m.leases = append(m.leases[:idx], m.leases[idx+1:]...)
		return nil
	}

	return nil
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

	leaseID := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-a")))
	owned, err := wallet.LeaseInput(t.Context(), leaseID, op)
	require.False(t, owned)
	require.ErrorContains(t, err, "already leased by another")
	require.False(t, walletKit.listUnspentCalled)
}

func TestCustomAnchorLeaseIsScopedToBatch(t *testing.T) {
	var op wire.OutPoint
	op.Index = 8
	walletKit := &customAnchorWalletKitMock{
		utxos: []*lnwallet.Utxo{{OutPoint: op}},
	}
	wallet := NewLndRpcWalletAnchor(&lndclient.LndServices{
		WalletKit: walletKit,
	})
	leaseIDA := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-a")))
	leaseIDB := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-b")))

	owned, err := wallet.LeaseInput(t.Context(), leaseIDA, op)
	require.NoError(t, err)
	require.True(t, owned)
	require.Len(t, walletKit.leaseCalls, 1)
	require.Equal(t, wtxmgr.LockID(leaseIDA), walletKit.leaseCalls[0].LockID)

	// A second batch cannot renew A's lease or release it by presenting its
	// own owner ID.
	owned, err = wallet.LeaseInput(t.Context(), leaseIDB, op)
	require.False(t, owned)
	require.ErrorContains(t, err, "another batch or subsystem")
	require.NoError(t, wallet.ReleaseInput(t.Context(), leaseIDB, op))
	require.Empty(t, walletKit.releaseCalls)
	require.Len(t, walletKit.leases, 1)
	require.Equal(t, wtxmgr.LockID(leaseIDA), walletKit.leases[0].LockID)

	// The rightful owner can renew and release the same lease.
	owned, err = wallet.LeaseInput(t.Context(), leaseIDA, op)
	require.NoError(t, err)
	require.True(t, owned)
	require.Len(t, walletKit.leaseCalls, 2)
	require.NoError(t, wallet.ReleaseInput(t.Context(), leaseIDA, op))
	require.Len(t, walletKit.releaseCalls, 1)
	require.Empty(t, walletKit.leases)
}
