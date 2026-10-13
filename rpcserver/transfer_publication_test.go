package rpcserver

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicationPorter exposes recorded parcels only. Replays must never reach
// RequestShipment or revalidate the spent asset inputs.
type publicationPorter struct {
	tapfreighter.Porter
	t       *testing.T
	txid    chainhash.Hash
	parcels []*tapfreighter.OutboundParcel
	err     error

	// entered, if set, is signalled on every lookup, which then blocks
	// until release is closed.
	entered chan struct{}
	release chan struct{}
}

func (p *publicationPorter) QueryParcels(_ context.Context,
	txid fn.Option[chainhash.Hash], pending bool) (
	[]*tapfreighter.OutboundParcel, error) {

	assert.Equal(p.t, fn.Some(p.txid), txid)
	assert.False(p.t, pending)

	if p.entered != nil {
		p.entered <- struct{}{}
		<-p.release
	}

	return p.parcels, p.err
}

// newPublicationRequest returns a request whose anchor PSBT is finalized,
// together with its extracted transaction.
func newPublicationRequest(t *testing.T) (*wrpc.PublishAndLogRequest,
	*wire.MsgTx) {

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	packet.Inputs[0].FinalScriptWitness = []byte{1, 1, 1}
	var anchor bytes.Buffer
	require.NoError(t, packet.Serialize(&anchor))
	tx, err = psbt.Extract(packet)
	require.NoError(t, err)

	return &wrpc.PublishAndLogRequest{
		AnchorPsbt:   anchor.Bytes(),
		VirtualPsbts: [][]byte{{1}},
	}, tx
}

func newPublicationServer(porter tapfreighter.Porter) *RPCServer {
	r := NewRPCServer()
	r.cfg = &tapconfig.Config{
		DatabaseConfig: &tapconfig.DatabaseConfig{},
		ChainPorter:    porter,
	}

	return r
}

// TestPublicationReplay verifies that recorded transfers bypass input
// validation, while absent transfers still take the normal validation path.
func TestPublicationReplay(t *testing.T) {
	t.Parallel()

	req, tx := newPublicationRequest(t)
	want, err := fn.Serialize(tx)
	require.NoError(t, err)

	tests := []struct {
		name        string
		recorded    bool
		blockHeight uint32
		lookupErr   error
		wantErr     string
	}{
		{name: "pending", recorded: true},
		{name: "confirmed", recorded: true, blockHeight: 100},
		{name: "absent", wantErr: "error decoding active packets"},
		{
			name:      "lookup failure",
			lookupErr: errors.New("lookup failed"),
			wantErr:   "lookup failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			porter := &publicationPorter{
				t: t, txid: tx.TxHash(), err: test.lookupErr,
			}
			if test.recorded {
				parcel := &tapfreighter.OutboundParcel{
					AnchorTx: tx, TransferTime: time.Now(),
					AnchorTxBlockHeight: test.blockHeight,
				}
				porter.parcels = []*tapfreighter.OutboundParcel{
					parcel,
				}
			}
			r := newPublicationServer(porter)
			resp, err := r.PublishAndLogTransfer(
				context.Background(), req,
			)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, want, resp.Transfer.AnchorTx)
			require.Equal(t, test.blockHeight,
				resp.Transfer.AnchorTxBlockHeight)
		})
	}
}

// TestPublicationSerialized verifies that a submission of an anchor
// transaction that is already being published waits for that publication
// instead of running alongside it.
func TestPublicationSerialized(t *testing.T) {
	t.Parallel()

	req, tx := newPublicationRequest(t)
	porter := &publicationPorter{
		t: t, txid: tx.TxHash(),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	r := newPublicationServer(porter)

	const callers = 2
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := r.PublishAndLogTransfer(
				context.Background(), req,
			)
			errs <- err
		}()
	}

	<-porter.entered
	select {
	case <-porter.entered:
		t.Fatal("overlapping submission looked up the transfer")

	case <-time.After(100 * time.Millisecond):
	}
	close(porter.release)

	for range callers {
		err := <-errs
		require.ErrorContains(t, err, "error decoding active packets")
	}
}
