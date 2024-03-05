package taprootassets

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// LndRpcWalletAnchor is an implementation of the tapgarden.WalletAnchor
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

const (
	// defaultChangeType is the default change type we'll use when using the
	// PSBT APIs.
	defaultChangeType = walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR
)

// FundPsbt attaches enough inputs to the target PSBT packet for it to be
// valid.
func (l *LndRpcWalletAnchor) FundPsbt(ctx context.Context, packet *psbt.Packet,
	minConfs uint32, feeRate chainfee.SatPerKWeight) (*tapsend.FundedPsbt,
	error) {

	var psbtBuf bytes.Buffer
	if err := packet.Serialize(&psbtBuf); err != nil {
		return nil, fmt.Errorf("unable to encode psbt: %w", err)
	}

	pkt, changeIndex, leasedUtxos, err := l.lnd.WalletKit.FundPsbt(
		ctx, &walletrpc.FundPsbtRequest{
			Template: &walletrpc.FundPsbtRequest_Psbt{
				Psbt: psbtBuf.Bytes(),
			},
			Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
				SatPerVbyte: uint64(feeRate.FeePerKVByte()) / 1000,
			},
			MinConfs:   int32(minConfs),
			ChangeType: defaultChangeType,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	lockedUtxos := make([]wire.OutPoint, len(leasedUtxos))
	for i, utxo := range leasedUtxos {
		txid, err := chainhash.NewHash(utxo.Outpoint.TxidBytes)
		if err != nil {
			return nil, err
		}
		lockedUtxos[i] = wire.OutPoint{
			Hash:  *txid,
			Index: utxo.Outpoint.OutputIndex,
		}
	}

	return &tapsend.FundedPsbt{
		Pkt:               pkt,
		ChangeOutputIndex: changeIndex,
		LockedUTXOs:       lockedUtxos,
	}, nil
}

// SignPsbt...
func (l *LndRpcWalletAnchor) SignPsbt(ctx context.Context,
	packet *psbt.Packet) (*psbt.Packet, error) {

	pkt, err := l.lnd.WalletKit.SignPsbt(ctx, packet)
	if err != nil {
		return nil, err
	}

	return pkt, nil
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

// ImportTaprootOutput imports a new public key into the wallet, as a P2TR
// output.
func (l *LndRpcWalletAnchor) ImportTaprootOutput(ctx context.Context,
	pub *btcec.PublicKey) (btcutil.Address, error) {

	addr, err := l.lnd.WalletKit.ImportTaprootScript(
		ctx, &waddrmgr.Tapscript{
			Type:          waddrmgr.TaprootFullKeyOnly,
			FullOutputKey: pub,
		},
	)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// UnlockInput unlocks the set of target inputs after a batch is abandoned.
func (l *LndRpcWalletAnchor) UnlockInput(ctx context.Context) error {
	return nil
}

// ListUnspentImportScripts lists all UTXOs of the imported Taproot scripts.
func (l *LndRpcWalletAnchor) ListUnspentImportScripts(
	ctx context.Context) ([]*lnwallet.Utxo, error) {

	return l.lnd.WalletKit.ListUnspent(
		ctx, 0, math.MaxInt32,
		lndclient.WithUnspentAccount(waddrmgr.ImportedAddrAccountName),
	)
}

// SubscribeTransactions creates a uni-directional stream from the server to the
// client in which any newly discovered transactions relevant to the wallet are
// sent over.
func (l *LndRpcWalletAnchor) SubscribeTransactions(
	ctx context.Context) (<-chan lndclient.Transaction, <-chan error,
	error) {

	return l.lnd.Client.SubscribeTransactions(ctx)
}

// ListTransactions returns all known transactions of the backing lnd node. It
// takes a start and end block height which can be used to limit the block range
// that we query over. These values can be left as zero to include all blocks.
// To include unconfirmed transactions in the query, endHeight must be set to
// -1.
func (l *LndRpcWalletAnchor) ListTransactions(ctx context.Context, startHeight,
	endHeight int32, account string) ([]lndclient.Transaction, error) {

	return l.lnd.Client.ListTransactions(
		ctx, startHeight, endHeight,
		lndclient.WithTransactionsAccount(account),
	)
}

// A compile time assertion to ensure LndRpcWalletAnchor meets the
// tapgarden.WalletAnchor interface.
var _ tapgarden.WalletAnchor = (*LndRpcWalletAnchor)(nil)

var _ tapfreighter.WalletAnchor = (*LndRpcWalletAnchor)(nil)
