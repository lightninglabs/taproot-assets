package itest

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAuthMailboxStoreAndFetchMessage tests that we can store and fetch auth
// mailbox messages using the auth mailbox server.
func testAuthMailboxStoreAndFetchMessage(t *harnessTest) {
	ctx := context.Background()

	// We first need to create two on-chain outputs that we can use to
	// send messages to the auth mailbox server.
	internalKey := test.RandPubKey(t.t)
	merkleRoot := test.RandBytes(32)

	pkScriptBip86, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(internalKey),
	)
	require.NoError(t.t, err)

	pkScriptTapscript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(
			internalKey, merkleRoot,
		),
	)
	require.NoError(t.t, err)

	txHash, err := t.lndHarness.Miner().SendOutputs([]*wire.TxOut{
		{
			Value:    100000,
			PkScript: pkScriptBip86,
		},
		{
			Value:    100000,
			PkScript: pkScriptTapscript,
		},
	}, 10)
	require.NoError(t.t, err)

	blockHash := t.lndHarness.Miner().GenerateBlocks(1)[0]
	bestBlockHash, blockHeight := t.lndHarness.Miner().GetBestBlock()
	require.Equal(t.t, blockHash, bestBlockHash)

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
		MerkleRoot:  merkleRoot,
	}

	// Before we store any message, we set up a listener to make sure we
	// can receive messages.
	lndClient, err := t.newLndClient(t.tapd.cfg.LndNode)
	require.NoError(t.t, err)
	receiverKey, err := lndClient.WalletKit.DeriveNextKey(
		ctx, int32(asset.TaprootAssetsKeyFamily),
	)
	require.NoError(t.t, err)

	mboxClient := authmailbox.NewClient(&authmailbox.ClientConfig{
		ServerAddress: t.tapd.rpcHost(),
		SkipTlsVerify: true,
		Signer:        lndClient.Signer,
		MinBackoff:    time.Second,
		MaxBackoff:    time.Second,
	})
	require.NoError(t.t, mboxClient.Start())

	inboundChan := make(chan *authmailbox.ReceivedMessages, 10)
	subscription, err := mboxClient.StartAccountSubscription(
		ctx, inboundChan, *receiverKey, authmailbox.MessageFilter{},
	)
	require.NoError(t.t, err)

	require.Eventually(t.t, func() bool {
		return subscription.IsSubscribed()
	}, defaultTimeout, wait.PollInterval)

	t.t.Cleanup(func() {
		require.NoError(t.t, subscription.Stop())
		require.NoError(t.t, mboxClient.Stop())
	})

	// Now we can start sending messages to the mailbox server.
	id, err := mboxClient.SendMessage(
		ctx, *receiverKey.PubKey, []byte("message 1"), txProof1, 1234,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, id, uint64(0))
	id2, err := mboxClient.SendMessage(
		ctx, *receiverKey.PubKey, []byte("message 2"), txProof2, 2345,
	)
	require.NoError(t.t, err)
	require.Greater(t.t, id2, uint64(0))

	// We check that we can't use the same tx proof again.
	_, err = mboxClient.SendMessage(
		ctx, *receiverKey.PubKey, []byte("message 3"), txProof1, 3456,
	)
	require.ErrorContains(t.t, err, proof.ErrTxMerkleProofExists.Error())

	// We also make sure that the TX proof is properly validated.
	txProof1.MerkleRoot = test.RandBytes(32)
	_, err = mboxClient.SendMessage(
		ctx, *receiverKey.PubKey, []byte("message 3"), txProof1, 3456,
	)
	require.ErrorContains(
		t.t, err, "validating proof: claimed output pk script doesn't "+
			"match constructed Taproot output key pk script",
	)

	// And now we should have two messages in the mailbox.
	select {
	case msgs := <-inboundChan:
		require.Len(t.t, msgs.Messages, 1)
		msg := msgs.Messages[0]
		require.Equal(t.t, id, msg.MessageId)
		require.Equal(t.t, []byte("message 1"), msg.EncryptedPayload)

	case <-time.After(defaultTimeout):
		require.Fail(t.t, "timed out waiting for message 1")
	}

	select {
	case msgs := <-inboundChan:
		require.Len(t.t, msgs.Messages, 1)
		msg := msgs.Messages[0]
		require.Equal(t.t, id2, msg.MessageId)
		require.Equal(t.t, []byte("message 2"), msg.EncryptedPayload)

	case <-time.After(defaultTimeout):
		require.Fail(t.t, "timed out waiting for message 2")
	}
}
