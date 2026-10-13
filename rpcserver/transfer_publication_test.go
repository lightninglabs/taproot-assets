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
}

func (p *publicationPorter) QueryParcels(_ context.Context,
	txid fn.Option[chainhash.Hash], pending bool) (
	[]*tapfreighter.OutboundParcel, error) {

	require.Equal(p.t, fn.Some(p.txid), txid)
	require.False(p.t, pending)
	return p.parcels, p.err
}

// TestPublicationReplay verifies that recorded transfers bypass input
// validation, while absent transfers still take the normal validation path.
func TestPublicationReplay(t *testing.T) {
	t.Parallel()

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
			r := NewRPCServer()
			r.cfg = &tapconfig.Config{
				DatabaseConfig: &tapconfig.DatabaseConfig{},
				ChainPorter:    porter,
			}
			req := &wrpc.PublishAndLogRequest{
				AnchorPsbt:   anchor.Bytes(),
				VirtualPsbts: [][]byte{{1}},
			}
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
