package tapnode

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// WalletAnchor is the main wallet interface used to manage PSBT
// packets, and import public keys into the wallet.
type WalletAnchor interface {
	// FundPsbt attaches enough inputs to the target PSBT packet for
	// it to be valid.
	FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
		feeRate chainfee.SatPerKWeight,
		changeIdx int32) (*tapsend.FundedPsbt, error)

	// SignAndFinalizePsbt fully signs and finalizes the target PSBT
	// packet.
	SignAndFinalizePsbt(context.Context, *psbt.Packet) (*psbt.Packet, error)

	// ImportTaprootOutput imports a new public key into the wallet,
	// as a P2TR output.
	ImportTaprootOutput(context.Context, *btcec.PublicKey) (btcutil.Address,
		error)

	// UnlockInput unlocks the set of target inputs after a batch or
	// send transaction is abandoned.
	UnlockInput(context.Context, wire.OutPoint) error

	// ListUnspentImportScripts lists all UTXOs of the imported
	// Taproot scripts.
	ListUnspentImportScripts(ctx context.Context) ([]*lnwallet.Utxo, error)

	// ListTransactions returns all known transactions of the backing
	// lnd node. It takes a start and end block height which can be
	// used to limit the block range that we query over. These values
	// can be left as zero to include all blocks. To include
	// unconfirmed transactions in the query, endHeight must be set
	// to -1.
	ListTransactions(ctx context.Context, startHeight, endHeight int32,
		account string) ([]lndclient.Transaction, error)

	// SubscribeTransactions creates a uni-directional stream from
	// the server to the client in which any newly discovered
	// transactions relevant to the wallet are sent over.
	SubscribeTransactions(context.Context) (<-chan lndclient.Transaction,
		<-chan error, error)

	// MinRelayFee returns the current minimum relay fee based on our
	// chain backend in sat/kw.
	MinRelayFee(ctx context.Context) (chainfee.SatPerKWeight, error)
}
