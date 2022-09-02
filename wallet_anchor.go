package taro

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// LndRpcWalletAnchor is an implementation of the tarogarden.WalletAnchor
// interfaced backed by an active remote lnd node.
type LndRpcWalletAnchor struct {
	lnd *lndclient.LndServices
}

// NewLndRpcWalletAnchor returns a new wallet anchor instance using the passed
// lnd node.
func NewLndRpcWalletAnchor(lnd *lndclient.LndServices) *LndRpcWalletAnchor {
	return &LndRpcWalletAnchor{
		lnd: lnd,
	}
}

// FundPsbt attaches enough inputs to the target PSBT packet for it to be
// valid.
func (l *LndRpcWalletAnchor) FundPsbt(ctx context.Context, packet *psbt.Packet,
	minConfs uint32,
	feeRate chainfee.SatPerKWeight) (tarogarden.FundedPsbt, error) {

	var psbtBuf bytes.Buffer
	if err := packet.Serialize(&psbtBuf); err != nil {
		return tarogarden.FundedPsbt{}, fmt.Errorf("unable to encode "+
			"psbt: %w", err)
	}

	pkt, changeIndex, leasedUtxos, err := l.lnd.WalletKit.FundPsbt(
		ctx, &walletrpc.FundPsbtRequest{
			Template: &walletrpc.FundPsbtRequest_Psbt{
				Psbt: psbtBuf.Bytes(),
			},
			Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
				SatPerVbyte: uint64(feeRate.FeePerKVByte()) / 1000,
			},
			MinConfs: 1,
		},
	)
	if err != nil {
		return tarogarden.FundedPsbt{}, fmt.Errorf("unable to fund "+
			"psbt: %w", err)
	}

	lockedUtxos := make([]wire.OutPoint, len(leasedUtxos))
	for i, utxo := range leasedUtxos {
		txid, err := chainhash.NewHash(utxo.Outpoint.TxidBytes)
		if err != nil {
			return tarogarden.FundedPsbt{}, err
		}
		lockedUtxos[i] = wire.OutPoint{
			Hash:  *txid,
			Index: utxo.Outpoint.OutputIndex,
		}
	}

	return tarogarden.FundedPsbt{
		Pkt:               pkt,
		ChangeOutputIndex: uint32(changeIndex),
		LockedUTXOs:       lockedUtxos,
	}, nil
}

// SignAndFinalizePsbt fully signs and finalizes the target PSBT packet.
func (l *LndRpcWalletAnchor) SignAndFinalizePsbt(ctx context.Context,
	pkt *psbt.Packet) (*psbt.Packet, error) {

	pkt, _, err := l.lnd.WalletKit.FinalizePsbt(ctx, pkt, "")
	if err != nil {
		return nil, err
	}

	return pkt, nil
}

// ImportPubKey imports a new public key into the wallet, as a P2TR output.
func (l *LndRpcWalletAnchor) ImportPubKey(_ context.Context,
	pub *btcec.PublicKey) error {

	// TODO(roasbeef): actually need to use ImportTaprootScript here, but
	// not yet exposed on RPC
	//
	//return l.lnd.WalletKit.ImportPublicKey(
	//	context.Background(), pub, lnwallet.TaprootPubkey,
	//)
	return nil
}

// UnlockInput unlocks the set of target inputs after a batch is abandoned.
func (l *LndRpcWalletAnchor) UnlockInput(ctx context.Context) error {
	return nil
}

// A compile time assertion to ensure LndRpcWalletAnchor meets the
// tarogarden.WalletAnchor interface.
var _ tarogarden.WalletAnchor = (*LndRpcWalletAnchor)(nil)
