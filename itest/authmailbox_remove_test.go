package itest

import (
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

// testAuthMailboxRemoveMessage tests that a receiver can remove their own
// messages from the mailbox server using the RemoveMessage RPC, and that
// messages belonging to other receivers cannot be removed.
func testAuthMailboxRemoveMessage(t *harnessTest) {
	ctx := context.Background()

	// Create two on-chain P2TR outputs to use as tx proofs for two
	// separate messages.
	internalKey := test.RandPubKey(t.t)

	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(internalKey),
	)
	require.NoError(t.t, err)

	txHash, err := t.lndHarness.Miner().SendOutputs([]*wire.TxOut{
		{
			Value:    100_000,
			PkScript: pkScript,
		},
		{
			Value:    100_000,
			PkScript: pkScript,
		},
	}, 10)
	require.NoError(t.t, err)

	blockHash := t.lndHarness.Miner().GenerateBlocks(1)[0]
	_, blockHeight := t.lndHarness.Miner().GetBestBlock()
	block := t.lndHarness.Miner().GetBlock(blockHash)

	require.Len(t.t, block.Transactions, 2)
	tx := block.Transactions[1]
	require.Equal(t.t, tx.TxHash(), *txHash)

	txMerkleProof, err := proof.NewTxMerkleProof(block.Transactions, 1)
	require.NoError(t.t, err)

	txProof1 := proof.TxProof{
		MsgTx:       *tx,
		BlockHeader: block.Header,
		BlockHeight: uint32(blockHeight),
		MerkleProof: *txMerkleProof,
		ClaimedOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: 0,
		},
		InternalKey: *internalKey,
	}
	txProof2 := proof.TxProof{
		MsgTx:       *tx,
		BlockHeader: block.Header,
		BlockHeight: uint32(blockHeight),
		MerkleProof: *txMerkleProof,
		ClaimedOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: 1,
		},
		InternalKey: *internalKey,
	}

	// Derive two distinct receiver keys.
	lndClient, err := t.newLndClient(t.tapd.cfg.LndNode)
	require.NoError(t.t, err)

	receiverKey1, err := lndClient.WalletKit.DeriveNextKey(
		ctx, int32(asset.TaprootAssetsKeyFamily),
	)
	require.NoError(t.t, err)
	receiverKey2, err := lndClient.WalletKit.DeriveNextKey(
		ctx, int32(asset.TaprootAssetsKeyFamily),
	)
	require.NoError(t.t, err)

	// Create a mailbox client that we'll use to send and remove messages.
	mboxClient := authmailbox.NewClient(&authmailbox.ClientConfig{
		ServerAddress: t.tapd.rpcHost(),
		SkipTlsVerify: true,
		Signer:        lndClient.Signer,
		MinBackoff:    time.Second,
		MaxBackoff:    time.Second,
	})
	require.NoError(t.t, mboxClient.Start())
	t.t.Cleanup(func() {
		require.NoError(t.t, mboxClient.Stop())
	})

	// Send one message to receiverKey1 and one to receiverKey2.
	id1, err := mboxClient.SendMessage(
		ctx, *receiverKey1.PubKey, []byte("msg for key1"), txProof1,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, id1, uint64(0))

	id2, err := mboxClient.SendMessage(
		ctx, *receiverKey2.PubKey, []byte("msg for key2"), txProof2,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, id2, uint64(0))

	// Verify both messages are in the mailbox.
	info, err := t.tapd.MailboxInfo(
		ctx, &authmailboxrpc.MailboxInfoRequest{},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 2, info.MessageCount)

	// --- Test 1: Receiver1 cannot remove Receiver2's message. ---
	numRemoved, err := mboxClient.RemoveMessages(
		ctx, *receiverKey1, []uint64{id2},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 0, numRemoved)

	// Count should still be 2.
	info, err = t.tapd.MailboxInfo(
		ctx, &authmailboxrpc.MailboxInfoRequest{},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 2, info.MessageCount)

	// --- Test 2: Receiver1 removes their own message. ---
	numRemoved, err = mboxClient.RemoveMessages(
		ctx, *receiverKey1, []uint64{id1},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 1, numRemoved)

	// Count should now be 1.
	info, err = t.tapd.MailboxInfo(
		ctx, &authmailboxrpc.MailboxInfoRequest{},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 1, info.MessageCount)

	// --- Test 3: Idempotent removal (same ID again). ---
	numRemoved, err = mboxClient.RemoveMessages(
		ctx, *receiverKey1, []uint64{id1},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 0, numRemoved)

	// --- Test 4: Non-existent message ID. ---
	numRemoved, err = mboxClient.RemoveMessages(
		ctx, *receiverKey1, []uint64{999999},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 0, numRemoved)

	// --- Test 5: Receiver2 removes their message. ---
	numRemoved, err = mboxClient.RemoveMessages(
		ctx, *receiverKey2, []uint64{id2},
	)
	require.NoError(t.t, err)
	require.EqualValues(t.t, 1, numRemoved)

	// Mailbox should now be empty.
	err = wait.NoError(func() error {
		info, err = t.tapd.MailboxInfo(
			ctx, &authmailboxrpc.MailboxInfoRequest{},
		)
		if err != nil {
			return err
		}

		if info.MessageCount != 0 {
			return fmt.Errorf("expected 0 messages, got %d",
				info.MessageCount)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)
}
