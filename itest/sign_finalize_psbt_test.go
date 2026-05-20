package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/lndservices"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testSignAndFinalizePsbtDeterministic pins the assumption that
// Wallet.SignAndFinalizePsbt produces byte-identical output when invoked
// twice on the same unsigned PSBT. The minting caretaker's Committed
// branch relies on this on restart: a crash after sign-and-finalize but
// before persisting the signed PSBT causes the next run to re-sign the
// same unsigned PSBT loaded from disk, and we expect the resulting
// signed bytes to match. lnd uses BIP-340 RFC-6979 deterministic
// Schnorr nonces, so this should hold, but it is load-bearing for
// idempotent restart semantics and worth verifying directly.
func testSignAndFinalizePsbtDeterministic(t *harnessTest) {
	ctxb := context.Background()
	ctx, cancel := context.WithCancel(ctxb)
	defer cancel()

	lndClient, err := t.newLndClient(t.tapd.cfg.LndNode)
	require.NoError(t.t, err)
	defer lndClient.Close()

	walletAnchor := lndservices.NewLndRpcWalletAnchor(
		&lndClient.LndServices,
	)

	// Build a minimal unsigned tx with one P2TR-shaped dummy output;
	// lnd will fund it by adding a wallet input and a change output.
	dummyScript := append(
		[]byte{txscript.OP_1, txscript.OP_DATA_32},
		bytes.Repeat([]byte{0x00}, 32)...,
	)
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{
		Value:    int64(btcutil.Amount(1000)),
		PkScript: dummyScript,
	})

	unsignedPkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t.t, err)

	fundedPkt, err := walletAnchor.FundPsbt(
		ctx, unsignedPkt, 1, chainfee.SatPerKWeight(3000), -1,
	)
	require.NoError(t.t, err)

	// SignAndFinalizePsbt mutates the input, so each call gets its
	// own deep-cloned copy of the unsigned-but-funded PSBT. Round-
	// tripping through Serialize/NewFromRawBytes is the cleanest way
	// to get an independent value.
	clonePsbt := func(p *psbt.Packet) *psbt.Packet {
		var buf bytes.Buffer
		require.NoError(t.t, p.Serialize(&buf))
		clone, err := psbt.NewFromRawBytes(
			bytes.NewReader(buf.Bytes()), false,
		)
		require.NoError(t.t, err)
		return clone
	}

	signed1, err := walletAnchor.SignAndFinalizePsbt(
		ctx, clonePsbt(fundedPkt.Pkt),
	)
	require.NoError(t.t, err)

	signed2, err := walletAnchor.SignAndFinalizePsbt(
		ctx, clonePsbt(fundedPkt.Pkt),
	)
	require.NoError(t.t, err)

	var buf1, buf2 bytes.Buffer
	require.NoError(t.t, signed1.Serialize(&buf1))
	require.NoError(t.t, signed2.Serialize(&buf2))

	require.Equal(t.t, buf1.Bytes(), buf2.Bytes(),
		"SignAndFinalizePsbt must produce byte-identical output "+
			"for the same unsigned input; the minting caretaker "+
			"restart path relies on this")
}
