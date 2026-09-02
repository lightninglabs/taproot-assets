package lndservices

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	btcaddr "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// DefaultPsbtMaxFeeRatio is the maximum ratio between fees paid and total
// output amount produced. Since taproot assets can be anchored to outpoints
// that may carry relatively small bitcoin amounts, we want to bump the allowed
// ratio between fees paid and total produced output amount. This can prove
// useful in high fee environments where we'd otherwise fail to fund the psbt.
const DefaultPsbtMaxFeeRatio = 0.75

// LndRpcWalletAnchor is an implementation of the tapnode.WalletAnchor
// interfaced backed by an active remote lnd node.
type LndRpcWalletAnchor struct {
	lnd *lndclient.LndServices
	cfg *WalletAnchorConfig
}

// WalletAnchorConfig is a configuration for the wallet anchor.
type WalletAnchorConfig struct {
	psbtMaxFeeRatio float64
}

// defaultWalletAnchorConfig returns the default configuration for the wallet
// anchor.
func defaultWalletAnchorConfig() *WalletAnchorConfig {
	return &WalletAnchorConfig{
		psbtMaxFeeRatio: DefaultPsbtMaxFeeRatio,
	}
}

// WalletAnchorOption is an optional argument that modifies the wallet anchor
// configuration.
type WalletAnchorOption func(cfg *WalletAnchorConfig)

// WithPsbtMaxFeeRatio is an optional argument that provides a custom psbt
// max fee ratio.
func WithPsbtMaxFeeRatio(val float64) WalletAnchorOption {
	return func(cfg *WalletAnchorConfig) {
		cfg.psbtMaxFeeRatio = val
	}
}

// NewLndRpcWalletAnchor returns a new wallet anchor instance using the passed
// lnd node.
func NewLndRpcWalletAnchor(lnd *lndclient.LndServices,
	opts ...WalletAnchorOption) *LndRpcWalletAnchor {

	cfg := defaultWalletAnchorConfig()

	for _, opt := range opts {
		opt(cfg)
	}

	return &LndRpcWalletAnchor{
		lnd: lnd,
		cfg: cfg,
	}
}

const (
	// defaultChangeType is the default change type we'll use when using the
	// PSBT APIs.
	defaultChangeType = walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR

	// External signing may involve offline or multi-party coordination.
	// Keep the lease long enough for that workflow, and renew it on restart
	// and immediately before finalization.
	customAnchorLeaseDuration = 24 * time.Hour
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
			MinConfs:    int32(minConfs),
			ChangeType:  defaultChangeType,
			MaxFeeRatio: l.cfg.psbtMaxFeeRatio,
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

// SignPsbt expects a partial transaction with all inputs and outputs fully
// declared and tries to sign all unsigned inputs that have all required fields
// (UTXO information, BIP32 derivation information, witness or sig scripts) set.
// If no error is returned, the PSBT is ready to be given to the next signer or
// to be finalized if lnd was the last signer.
//
// NOTE: See lndclient.WalletKitClient for further details.
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
	pub *btcec.PublicKey) (btcaddr.Address, error) {

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

// LeaseInput leases one input with the calling batch's custom-anchor lock ID.
// It delegates to the batch operation so ownership discovery has one source of
// truth.
func (l *LndRpcWalletAnchor) LeaseInput(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) (bool, error) {

	locked, err := l.LeaseInputs(ctx, leaseID, []wire.OutPoint{op})
	return len(locked) == 1, err
}

// LeaseInputs snapshots leases and wallet UTXOs once, then leases only the
// wallet-owned members of ops. Foreign inputs don't increase ownership-query
// traffic. A partial result lets the caller roll back only newly acquired
// leases if a later LeaseOutput call fails.
func (l *LndRpcWalletAnchor) LeaseInputs(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID,
	ops []wire.OutPoint) ([]wire.OutPoint, error) {

	if len(ops) == 0 {
		return nil, nil
	}

	seen := make(map[wire.OutPoint]struct{}, len(ops))
	for _, op := range ops {
		if _, ok := seen[op]; ok {
			return nil, fmt.Errorf("custom anchor input is repeated: %v", op)
		}
		seen[op] = struct{}{}
	}

	lockID := wtxmgr.LockID(leaseID)
	leases, err := l.lnd.WalletKit.ListLeases(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing existing leases: %w", err)
	}
	leaseByOutpoint := make(map[wire.OutPoint]lndclient.LeaseDescriptor,
		len(leases))
	for _, lease := range leases {
		leaseByOutpoint[lease.Outpoint] = lease
	}

	// Reject all ownership conflicts before renewing or creating any lease.
	for _, op := range ops {
		lease, ok := leaseByOutpoint[op]
		if ok && lease.LockID != lockID {
			return nil, fmt.Errorf("wallet input %v is already leased by "+
				"another batch or subsystem", op)
		}
	}

	needUnspent := false
	for _, op := range ops {
		if _, ok := leaseByOutpoint[op]; !ok {
			needUnspent = true
			break
		}
	}
	walletInputs := make(map[wire.OutPoint]struct{})
	if needUnspent {
		utxos, err := l.lnd.WalletKit.ListUnspent(
			ctx, 0, math.MaxInt32,
		)
		if err != nil {
			return nil, fmt.Errorf("error listing wallet inputs: %w", err)
		}
		walletInputs = make(map[wire.OutPoint]struct{}, len(utxos))
		for _, utxo := range utxos {
			walletInputs[utxo.OutPoint] = struct{}{}
		}
	}

	locked := make([]wire.OutPoint, 0, len(ops))
	for _, op := range ops {
		_, alreadyLeased := leaseByOutpoint[op]
		_, walletOwned := walletInputs[op]
		if !alreadyLeased && !walletOwned {
			continue
		}

		_, err := l.lnd.WalletKit.LeaseOutput(
			ctx, lockID, op, customAnchorLeaseDuration,
		)
		if err != nil {
			return locked, fmt.Errorf(
				"unable to lease wallet input %v: %w", op, err,
			)
		}
		locked = append(locked, op)
	}

	return locked, nil
}

// ReleaseInput releases only the calling batch's custom-anchor lease for an
// input.
func (l *LndRpcWalletAnchor) ReleaseInput(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) error {

	return l.ReleaseInputs(ctx, leaseID, []wire.OutPoint{op})
}

// ReleaseInputs snapshots leases once and releases every requested lease owned
// by leaseID. It never releases another subsystem's lease.
func (l *LndRpcWalletAnchor) ReleaseInputs(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID, ops []wire.OutPoint) error {

	if len(ops) == 0 {
		return nil
	}

	lockID := wtxmgr.LockID(leaseID)

	leases, err := l.lnd.WalletKit.ListLeases(ctx)
	if err != nil {
		return fmt.Errorf("error listing existing leases: %w", err)
	}
	owned := make(map[wire.OutPoint]struct{}, len(leases))
	for _, lease := range leases {
		if lease.LockID == lockID {
			owned[lease.Outpoint] = struct{}{}
		}
	}

	var releaseErr error
	for _, op := range ops {
		if _, ok := owned[op]; !ok {
			continue
		}
		if err := l.lnd.WalletKit.ReleaseOutput(ctx, lockID, op); err != nil {
			releaseErr = errors.Join(releaseErr, fmt.Errorf(
				"error releasing custom anchor lease %v: %w", op, err,
			))
		}
	}

	return releaseErr
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

// A compile time assertion to ensure LndRpcWalletAnchor meets the
// tapnode.WalletAnchor interface.
var _ tapnode.WalletAnchor = (*LndRpcWalletAnchor)(nil)
var _ tapnode.CustomAnchorLeaser = (*LndRpcWalletAnchor)(nil)
var _ tapnode.CustomAnchorBatchLeaser = (*LndRpcWalletAnchor)(nil)

var _ tapfreighter.WalletAnchor = (*LndRpcWalletAnchor)(nil)
