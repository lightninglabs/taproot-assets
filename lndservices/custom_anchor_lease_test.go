package lndservices

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
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
	listLeasesCalls   int
	listUnspentCalls  int
	leaseErrors       map[wire.OutPoint]error
}

func (m *customAnchorWalletKitMock) ListLeases(
	context.Context) ([]lndclient.LeaseDescriptor, error) {

	m.listLeasesCalls++
	return m.leases, nil
}

func (m *customAnchorWalletKitMock) ListUnspent(context.Context, int32,
	int32, ...lndclient.ListUnspentOption) ([]*lnwallet.Utxo, error) {

	m.listUnspentCalled = true
	m.listUnspentCalls++
	return m.utxos, nil
}

func (m *customAnchorWalletKitMock) LeaseOutput(_ context.Context,
	lockID wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	if err := m.leaseErrors[op]; err != nil {
		return time.Time{}, err
	}

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
			LockID:     foreignID,
			Outpoint:   op,
			Expiration: time.Now().Add(time.Hour),
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
	leaseIDA := tapnode.CustomAnchorLeaseID(
		sha256.Sum256([]byte("batch-a")),
	)
	leaseIDB := tapnode.CustomAnchorLeaseID(
		sha256.Sum256([]byte("batch-b")),
	)

	owned, err := wallet.LeaseInput(t.Context(), leaseIDA, op)
	require.NoError(t, err)
	require.True(t, owned)
	require.Len(t, walletKit.leaseCalls, 1)
	require.Equal(
		t, wtxmgr.LockID(leaseIDA), walletKit.leaseCalls[0].LockID,
	)

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

func TestCustomAnchorBatchLeaseSnapshotsOnce(t *testing.T) {
	leaseID := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-a")))
	lockID := wtxmgr.LockID(leaseID)
	var hash chainhash.Hash
	hash[0] = 1

	ops := make([]wire.OutPoint, 0, 1002)
	for idx := uint32(0); idx < 1000; idx++ {
		ops = append(ops, wire.OutPoint{Hash: hash, Index: idx})
	}
	current := wire.OutPoint{Hash: hash, Index: 1000}
	owned := wire.OutPoint{Hash: hash, Index: 1001}
	ops = append(ops, current, owned)

	walletKit := &customAnchorWalletKitMock{
		leases: []lndclient.LeaseDescriptor{{
			LockID: lockID, Outpoint: current,
			Expiration: time.Now().Add(time.Hour),
		}},
		utxos: []*lnwallet.Utxo{{OutPoint: owned}},
	}
	wallet := NewLndRpcWalletAnchor(&lndclient.LndServices{
		WalletKit: walletKit,
	})

	locked, err := wallet.LeaseInputs(t.Context(), leaseID, ops)
	require.NoError(t, err)
	require.Equal(t, []wire.OutPoint{current, owned}, locked)
	require.Equal(t, 1, walletKit.listLeasesCalls)
	require.Equal(t, 1, walletKit.listUnspentCalls)
	require.Len(t, walletKit.leaseCalls, 2)
	require.Equal(t, current, walletKit.leaseCalls[0].Outpoint)
	require.Equal(t, owned, walletKit.leaseCalls[1].Outpoint)
}

func TestCustomAnchorBatchLeasePreflightsConflict(t *testing.T) {
	leaseID := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-a")))
	foreignID := wtxmgr.LockID(sha256.Sum256([]byte("another-subsystem")))
	owned := wire.OutPoint{Index: 1}
	conflict := wire.OutPoint{Index: 2}
	walletKit := &customAnchorWalletKitMock{
		leases: []lndclient.LeaseDescriptor{{
			LockID: foreignID, Outpoint: conflict,
			Expiration: time.Now().Add(time.Hour),
		}},
		utxos: []*lnwallet.Utxo{{OutPoint: owned}},
	}
	wallet := NewLndRpcWalletAnchor(&lndclient.LndServices{
		WalletKit: walletKit,
	})

	locked, err := wallet.LeaseInputs(
		t.Context(), leaseID, []wire.OutPoint{owned, conflict},
	)
	require.Nil(t, locked)
	require.ErrorContains(t, err, "already leased by another")
	require.Equal(t, 1, walletKit.listLeasesCalls)
	require.Zero(t, walletKit.listUnspentCalls)
	require.Empty(t, walletKit.leaseCalls)
}

func TestCustomAnchorBatchLeasePartialRollback(t *testing.T) {
	leaseID := tapnode.CustomAnchorLeaseID(sha256.Sum256([]byte("batch-a")))
	lockID := wtxmgr.LockID(leaseID)
	current := wire.OutPoint{Index: 1}
	newInput := wire.OutPoint{Index: 2}
	failing := wire.OutPoint{Index: 3}
	walletKit := &customAnchorWalletKitMock{
		leases: []lndclient.LeaseDescriptor{{
			LockID: lockID, Outpoint: current,
			Expiration: time.Now().Add(time.Hour),
		}},
		utxos: []*lnwallet.Utxo{
			{OutPoint: newInput}, {OutPoint: failing},
		},
		leaseErrors: map[wire.OutPoint]error{
			failing: errors.New("injected lease failure"),
		},
	}
	wallet := NewLndRpcWalletAnchor(&lndclient.LndServices{
		WalletKit: walletKit,
	})

	locked, err := wallet.LeaseInputs(
		t.Context(), leaseID,
		[]wire.OutPoint{current, newInput, failing},
	)
	require.ErrorContains(t, err, "injected lease failure")
	require.Equal(t, []wire.OutPoint{current, newInput}, locked)

	// This mirrors the planter's owner-aware rollback: the existing lease
	// is excluded, while the new lease is released in one snapshot.
	require.NoError(t, wallet.ReleaseInputs(
		t.Context(), leaseID, []wire.OutPoint{newInput},
	))
	require.Len(t, walletKit.leases, 1)
	require.Equal(t, current, walletKit.leases[0].Outpoint)
	require.Len(t, walletKit.releaseCalls, 1)
	require.Equal(t, newInput, walletKit.releaseCalls[0].Outpoint)
	require.Equal(t, 2, walletKit.listLeasesCalls)
	require.Equal(t, 1, walletKit.listUnspentCalls)
}
