package tapdb

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
)

// TestAddressEventRejectsOutputIndexOutOfRange asserts that the address book
// rejects a transfer whose output index does not exist in the transaction,
// rather than indexing past the outputs.
func TestAddressEventRejectsOutputIndexOutOfRange(t *testing.T) {
	t.Parallel()

	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)
	ctx := context.Background()

	courier := address.RandProofCourierAddrForVersion(t, address.V2)
	addr, _, _ := address.RandAddrWithVersion(
		t, chainParams, courier, address.V2,
	)

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	src := address.IncomingTransfer{
		Addr:      addr,
		Tx:        tx,
		OutputIdx: 5,
	}

	_, err := addrBook.GetOrCreateEvent(
		ctx, address.StatusTransactionDetected, src,
	)
	require.ErrorContains(t, err, "out of range")
}
