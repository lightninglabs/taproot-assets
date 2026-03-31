package itest

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAuthMailboxCleanup tests that the mailbox server periodically cleans up
// messages whose claimed outpoints have been spent on chain.
func testAuthMailboxCleanup(t *harnessTest) {
	ctx := context.Background()

	// We create a dedicated universe server with a short cleanup interval
	// so we can observe the cleanup within the test timeout.
	cleanupInterval := 2 * time.Second
	uniLnd := t.lndHarness.NewNodeWithCoins("UniCleanup", nil)
	uniService, err := newTapdHarness(
		t.t, t, tapdConfig{
			NetParams: harnessNetParams,
			LndNode:   uniLnd,
		},
		withDisableSupplyVerifierChainWatch(),
		withMboxCleanupInterval(cleanupInterval),
	)
	require.NoError(t.t, err)
	require.NoError(t.t, uniService.start(false))
	defer func() {
		require.NoError(t.t, uniService.stop(!*noDelete))
	}()

	// Generate a key pair for a P2TR output. We keep the private key so
	// we can spend it later to trigger cleanup.
	privKey := test.RandPrivKey()
	internalKey := privKey.PubKey()

	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(internalKey),
	)
	require.NoError(t.t, err)

	// Fund the P2TR output from the miner.
	txHash, err := SendOutputs(t.lndHarness.Miner(), []*wire.TxOut{
		{
			Value:    100_000,
			PkScript: pkScript,
		},
	}, 10)
	require.NoError(t.t, err)

	blockHash := t.lndHarness.Miner().GenerateBlocks(1)[0]
	_, blockHeight := t.lndHarness.Miner().GetBestBlock()
	block := t.lndHarness.Miner().GetBlock(blockHash)

	// Find our transaction and output in the block.
	var (
		proofTx   *wire.MsgTx
		txIdx     int
		outputIdx uint32
	)
	for i, blockTx := range block.Transactions {
		if blockTx.TxHash() == *txHash {
			proofTx = blockTx
			txIdx = i

			for j, out := range blockTx.TxOut {
				if bytes.Equal(out.PkScript, pkScript) {
					outputIdx = uint32(j)

					break
				}
			}

			break
		}
	}
	require.NotNil(t.t, proofTx, "tx not found in block")

	txMerkleProof, err := proof.NewTxMerkleProof(
		block.Transactions, txIdx,
	)
	require.NoError(t.t, err)

	txProof := proof.TxProof{
		MsgTx:       *proofTx,
		BlockHeader: block.Header,
		BlockHeight: uint32(blockHeight),
		MerkleProof: *txMerkleProof,
		ClaimedOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: outputIdx,
		},
		InternalKey: *internalKey,
	}

	// Create a mailbox client and send a message to the cleanup server.
	lndClient, err := t.newLndClient(uniLnd)
	require.NoError(t.t, err)

	receiverKey, err := lndClient.WalletKit.DeriveNextKey(
		ctx, int32(asset.TaprootAssetsKeyFamily),
	)
	require.NoError(t.t, err)

	mboxClient := authmailbox.NewClient(&authmailbox.ClientConfig{
		ServerAddress: uniService.rpcHost(),
		SkipTlsVerify: true,
		Signer:        lndClient.Signer,
		MinBackoff:    time.Second,
		MaxBackoff:    time.Second,
	})
	require.NoError(t.t, mboxClient.Start())
	t.t.Cleanup(func() {
		require.NoError(t.t, mboxClient.Stop())
	})

	msgID, err := mboxClient.SendMessage(
		ctx, *receiverKey.PubKey, []byte("test cleanup msg"),
		txProof,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, msgID, uint64(0))

	// Verify the message is stored.
	info, err := uniService.MailboxInfo(
		ctx, &authmailboxrpc.MailboxInfoRequest{},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 1, info.MessageCount)

	// Spend the P2TR output by constructing and broadcasting a raw
	// key-spend transaction.
	spendOutpoint := wire.OutPoint{Hash: *txHash, Index: outputIdx}

	minerAddr := t.lndHarness.Miner().NewMinerAddress()
	minerPkScript, err := txscript.PayToAddrScript(minerAddr)
	require.NoError(t.t, err)

	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: spendOutpoint,
	})
	spendTx.AddTxOut(&wire.TxOut{
		Value:    90_000,
		PkScript: minerPkScript,
	})

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		pkScript, 100_000,
	)
	sigHashes := txscript.NewTxSigHashes(spendTx, prevOutFetcher)

	// RawTxInTaprootSignature applies the BIP-86 tap tweak internally,
	// so we pass the raw (untweaked) private key.
	sig, err := txscript.RawTxInTaprootSignature(
		spendTx, sigHashes, 0, 100_000, pkScript,
		nil, txscript.SigHashDefault, privKey,
	)
	require.NoError(t.t, err)

	spendTx.TxIn[0].Witness = wire.TxWitness{sig}

	_, err = t.lndHarness.Miner().SendRawTransaction(
		spendTx, true,
	)
	require.NoError(t.t, err)

	// Mine to confirm the spend.
	t.lndHarness.Miner().GenerateBlocks(1)

	// Wait for the cleanup to detect the spent outpoint and delete the
	// message. The cleanup interval is 2s, so we give it some margin.
	err = wait.NoError(func() error {
		info, err := uniService.MailboxInfo(
			ctx, &authmailboxrpc.MailboxInfoRequest{},
		)
		if err != nil {
			return err
		}

		if info.MessageCount > 0 {
			return fmt.Errorf("expected 0 messages, got %d",
				info.MessageCount)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)
}
