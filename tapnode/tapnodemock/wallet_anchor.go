package tapnodemock

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// WalletAnchor is an in-memory mock implementation of tapnode.WalletAnchor.
type WalletAnchor struct {
	FundPsbtSignal     chan *tapsend.FundedPsbt
	SignPsbtSignal     chan struct{}
	ImportPubKeySignal chan *btcec.PublicKey
	ListUnspentSignal  chan struct{}
	SubscribeTxSignal  chan struct{}
	SubscribeTx        chan lndclient.Transaction
	ListTxnsSignal     chan struct{}

	Transactions  []lndclient.Transaction
	ImportedUtxos []*lnwallet.Utxo
}

// NewWalletAnchor returns a freshly-initialised mock WalletAnchor.
func NewWalletAnchor() *WalletAnchor {
	return &WalletAnchor{
		FundPsbtSignal:     make(chan *tapsend.FundedPsbt),
		SignPsbtSignal:     make(chan struct{}),
		ImportPubKeySignal: make(chan *btcec.PublicKey),
		ListUnspentSignal:  make(chan struct{}),
		SubscribeTxSignal:  make(chan struct{}),
		SubscribeTx:        make(chan lndclient.Transaction),
		ListTxnsSignal:     make(chan struct{}),
	}
}

// NewGenesisTx creates a funded genesis PSBT with the given fee rate.
func NewGenesisTx(t testing.TB, feeRate chainfee.SatPerKWeight) psbt.Packet {
	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	require.NoError(t, err)

	FundGenesisTx(genesisPkt, feeRate)
	return *genesisPkt
}

// FundGenesisTx add a genesis input and change output to a 1-output TX and
// returns the index of the change output.
func FundGenesisTx(packet *psbt.Packet, feeRate chainfee.SatPerKWeight) uint32 {
	const anchorBalance = int64(100000)

	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: test.RandInt[uint32](),
		},
	})

	anchorInput := psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    anchorBalance,
			PkScript: bytes.Clone(tapsend.GenesisDummyScript),
		},
		SighashType: txscript.SigHashDefault,
	}
	packet.Inputs = append(packet.Inputs, anchorInput)

	changeOutput := wire.TxOut{
		Value:    anchorBalance - packet.UnsignedTx.TxOut[0].Value,
		PkScript: bytes.Clone(tapsend.GenesisDummyScript),
	}
	changeOutput.PkScript[0] = txscript.OP_0
	packet.UnsignedTx.AddTxOut(&changeOutput)
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	_, fee := tapscript.EstimateFee(
		[][]byte{tapsend.GenesisDummyScript}, packet.UnsignedTx.TxOut,
		feeRate,
	)
	changeOutputIdx := len(packet.UnsignedTx.TxOut) - 1
	packet.UnsignedTx.TxOut[changeOutputIdx].Value -= int64(fee)

	return uint32(changeOutputIdx)
}

// FundPsbt funds a PSBT.
func (m *WalletAnchor) FundPsbt(_ context.Context, packet *psbt.Packet,
	_ uint32, _ chainfee.SatPerKWeight,
	changeIdx int32) (*tapsend.FundedPsbt, error) {

	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: rand.Uint32(),
		},
	})

	anchorInput := psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    100000,
			PkScript: bytes.Clone(tapsend.GenesisDummyScript),
		},
		SighashType: txscript.SigHashDefault,
	}
	packet.Inputs = append(packet.Inputs, anchorInput)

	changeOutput := wire.TxOut{
		Value:    50000,
		PkScript: bytes.Clone(tapsend.GenesisDummyScript),
	}
	changeOutput.PkScript[0] = txscript.OP_0
	packet.UnsignedTx.AddTxOut(&changeOutput)
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	changeIdx = int32(len(packet.Outputs) - 1)

	pkt := &tapsend.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: changeIdx,
	}

	m.FundPsbtSignal <- pkt

	return pkt, nil
}

// SignAndFinalizePsbt fully signs and finalizes the target PSBT packet.
func (m *WalletAnchor) SignAndFinalizePsbt(ctx context.Context,
	pkt *psbt.Packet) (*psbt.Packet, error) {

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	default:
	}

	// We'll modify the packet by attaching a "signature" so the PSBT
	// appears to actually be finalized.
	pkt.Inputs[0].FinalScriptSig = []byte{}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	case m.SignPsbtSignal <- struct{}{}:
	}

	return pkt, nil
}

// ImportTaprootOutput imports a new public key into the wallet, as a P2TR
// output.
func (m *WalletAnchor) ImportTaprootOutput(ctx context.Context,
	pub *btcec.PublicKey) (btcutil.Address, error) {

	select {
	case m.ImportPubKeySignal <- pub:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(pub), &chaincfg.RegressionNetParams,
	)
}

// UnlockInput unlocks the set of target inputs after a batch or send
// transaction is abandoned.
func (m *WalletAnchor) UnlockInput(context.Context, wire.OutPoint) error {
	return nil
}

// ListUnspentImportScripts lists all UTXOs of the imported Taproot scripts.
func (m *WalletAnchor) ListUnspentImportScripts(
	ctx context.Context) ([]*lnwallet.Utxo, error) {

	select {
	case m.ListUnspentSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return m.ImportedUtxos, nil
}

// ImportTapscript imports a Taproot output script into the wallet to track it
// on-chain in a watch-only manner. (Not part of tapnode.WalletAnchor; provided
// here for tests that exercise the broader wallet-anchor surface.)
func (m *WalletAnchor) ImportTapscript(_ context.Context,
	ts *waddrmgr.Tapscript) (btcutil.Address, error) {

	taprootKey, err := ts.TaprootKey()
	if err != nil {
		return nil, err
	}

	return btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey),
		&chaincfg.RegressionNetParams,
	)
}

// SubscribeTransactions creates a uni-directional stream from the server to the
// client in which any newly discovered transactions relevant to the wallet are
// sent over.
func (m *WalletAnchor) SubscribeTransactions(
	ctx context.Context) (<-chan lndclient.Transaction, <-chan error, error) {

	select {
	case m.SubscribeTxSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	}

	errChan := make(chan error)
	return m.SubscribeTx, errChan, nil
}

// ListTransactions returns all known transactions of the backing lnd node.
func (m *WalletAnchor) ListTransactions(ctx context.Context, _, _ int32,
	_ string) ([]lndclient.Transaction, error) {

	select {
	case m.ListTxnsSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return m.Transactions, nil
}

// MinRelayFee returns a fixed mock minimum relay fee.
func (m *WalletAnchor) MinRelayFee(
	_ context.Context) (chainfee.SatPerKWeight, error) {

	return chainfee.SatPerKWeight(10), nil
}

var _ tapnode.WalletAnchor = (*WalletAnchor)(nil)
