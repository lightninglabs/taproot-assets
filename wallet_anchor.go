package taprootassets

import (
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
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
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
	minConfs uint32, feeRate chainfee.SatPerKWeight,
	changeIdx int32) (*tapsend.FundedPsbt, error) {

	psbtBytes, err := fn.Serialize(packet)
	if err != nil {
		return nil, fmt.Errorf("unable to encode psbt: %w", err)
	}

	var fundTemplate *walletrpc.FundPsbtRequest_CoinSelect

	if changeIdx < 0 {
		fundTemplate = &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt: psbtBytes,
				ChangeOutput: &walletrpc.PsbtCoinSelect_Add{
					Add: true,
				},
			},
		}
	} else {
		change := &walletrpc.PsbtCoinSelect_ExistingOutputIndex{
			ExistingOutputIndex: changeIdx,
		}

		fundTemplate = &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt:         psbtBytes,
				ChangeOutput: change,
			},
		}
	}

	pkt, changeIndex, leasedUtxos, err := l.lnd.WalletKit.FundPsbt(
		ctx, &walletrpc.FundPsbtRequest{
			Template: fundTemplate,
			Fees: &walletrpc.FundPsbtRequest_SatPerKw{
				SatPerKw: uint64(feeRate),
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

// UnlockInput unlocks the set of target inputs after a batch or send
// transaction is abandoned.
func (l *LndRpcWalletAnchor) UnlockInput(ctx context.Context,
	op wire.OutPoint) error {

	leases, err := l.lnd.WalletKit.ListLeases(ctx)
	if err != nil {
		return fmt.Errorf("error listing existing leases: %w", err)
	}

	for _, lease := range leases {
		if lease.Outpoint == op {
			err = l.lnd.WalletKit.ReleaseOutput(
				ctx, lease.LockID, lease.Outpoint,
			)
			if err != nil {
				return fmt.Errorf("error releasing lease: %w",
					err)
			}
		}
	}

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

// ListChannels returns the list of active channels of the backing lnd node.
func (l *LndRpcWalletAnchor) ListChannels(
	ctx context.Context) ([]lndclient.ChannelInfo, error) {

	return l.lnd.Client.ListChannels(ctx, true, false)
}

// MinRelayFee estimates the minimum fee rate required for a
// transaction.
func (l *LndRpcWalletAnchor) MinRelayFee(
	ctx context.Context) (chainfee.SatPerKWeight, error) {

	return l.lnd.WalletKit.MinRelayFee(ctx)
}

// DeriveNextKey derives the next key in the taproot assets key family.
func (l *LndRpcWalletAnchor) DeriveNextKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	keyFam := asset.TaprootAssetsKeyFamily

	tapdLog.Debugf("Deriving new key for fam_family=%v", keyFam)

	keyDesc, err := l.lnd.WalletKit.DeriveNextKey(ctx, int32(keyFam))
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// A compile time assertion to ensure LndRpcWalletAnchor meets the
// tapgarden.WalletAnchor interface.
var _ tapgarden.WalletAnchor = (*LndRpcWalletAnchor)(nil)

var _ tapfreighter.WalletAnchor = (*LndRpcWalletAnchor)(nil)
