//nolint:lll
package tapgarden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type trackedCustomAnchorWallet struct {
	*tapnodemock.WalletAnchor

	mu       sync.Mutex
	leases   map[wire.OutPoint]tapnode.CustomAnchorLeaseID
	releases []customAnchorLeaseRequest
}

type customAnchorLeaseRequest struct {
	leaseID tapnode.CustomAnchorLeaseID
	op      wire.OutPoint
}

type blockingCustomAnchorWallet struct {
	*trackedCustomAnchorWallet

	blockOn       wire.OutPoint
	releaseCtxErr chan error
}

type batchCustomAnchorWallet struct {
	*tapnodemock.WalletAnchor

	leaseInputCalls int
	batchLeaseCalls int
	batchLocked     []wire.OutPoint
	batchLeaseErr   error
	batchReleases   [][]wire.OutPoint
}

func (w *batchCustomAnchorWallet) LeaseInput(context.Context,
	tapnode.CustomAnchorLeaseID, wire.OutPoint) (bool, error) {

	w.leaseInputCalls++
	return false, nil
}

func (w *batchCustomAnchorWallet) LeaseInputs(context.Context,
	tapnode.CustomAnchorLeaseID,
	[]wire.OutPoint) ([]wire.OutPoint, error) {

	w.batchLeaseCalls++
	return fn.CopySlice(w.batchLocked), w.batchLeaseErr
}

func (w *batchCustomAnchorWallet) ReleaseInputs(_ context.Context,
	_ tapnode.CustomAnchorLeaseID, ops []wire.OutPoint) error {

	w.batchReleases = append(w.batchReleases, fn.CopySlice(ops))
	return nil
}

func (w *blockingCustomAnchorWallet) LeaseInput(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) (bool, error) {

	if op == w.blockOn {
		<-ctx.Done()
		return false, ctx.Err()
	}

	return w.trackedCustomAnchorWallet.LeaseInput(ctx, leaseID, op)
}

func (w *blockingCustomAnchorWallet) ReleaseInput(ctx context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) error {

	w.releaseCtxErr <- ctx.Err()
	return w.trackedCustomAnchorWallet.ReleaseInput(ctx, leaseID, op)
}

func newTrackedCustomAnchorWallet() *trackedCustomAnchorWallet {
	return &trackedCustomAnchorWallet{
		WalletAnchor: tapnodemock.NewWalletAnchor(),
		leases:       make(map[wire.OutPoint]tapnode.CustomAnchorLeaseID),
	}
}

func (w *trackedCustomAnchorWallet) LeaseInput(_ context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) (bool, error) {

	w.mu.Lock()
	defer w.mu.Unlock()

	owner, ok := w.leases[op]
	if ok && owner != leaseID {
		return false, fmt.Errorf("input leased by another batch")
	}

	w.leases[op] = leaseID
	return true, nil
}

func (w *trackedCustomAnchorWallet) ReleaseInput(_ context.Context,
	leaseID tapnode.CustomAnchorLeaseID, op wire.OutPoint) error {

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.leases[op] != leaseID {
		return nil
	}

	delete(w.leases, op)
	w.releases = append(w.releases, customAnchorLeaseRequest{
		leaseID: leaseID,
		op:      op,
	})

	return nil
}

func TestCustomAnchorLeaseMarkerValidation(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	markCustomAnchorPsbt(pkt)

	ops, state, err := parseCustomAnchorLockedUTXOs(pkt)
	require.NoError(t, err)
	require.Nil(t, ops)
	require.Equal(t, customAnchorLeaseMarkerLegacy, state)

	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	SetCustomAnchorLockedUTXOs(pkt, []wire.OutPoint{op})
	ops, state, err = parseCustomAnchorLockedUTXOs(pkt)
	require.NoError(t, err)
	require.Equal(t, customAnchorLeaseMarkerCurrent, state)
	require.Equal(t, []wire.OutPoint{op}, ops)

	var marker *psbt.Unknown
	for _, unknown := range pkt.Unknowns {
		if bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			marker = unknown
		}
	}
	require.NotNil(t, marker)
	marker.Value = []byte{1, 1, 0, 0, 0}
	_, _, err = parseCustomAnchorLockedUTXOs(pkt)
	require.ErrorContains(t, err, "marker length")
	require.Nil(t, CustomAnchorLockedUTXOs(pkt))

	marker.Value = []byte{1}
	pkt.Unknowns = append(pkt.Unknowns, &psbt.Unknown{
		Key: fn.CopySlice(customAnchorPsbtMarker), Value: []byte{1},
	})
	_, _, err = parseCustomAnchorLockedUTXOs(pkt)
	require.ErrorContains(t, err, "duplicate custom anchor lease marker")

	// The setter canonicalizes any retained duplicates into one current
	// marker before the packet is stored again.
	SetCustomAnchorLockedUTXOs(pkt, []wire.OutPoint{op})
	markerCount := 0
	for _, unknown := range pkt.Unknowns {
		if bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			markerCount++
		}
	}
	require.Equal(t, 1, markerCount)
	ops, state, err = parseCustomAnchorLockedUTXOs(pkt)
	require.NoError(t, err)
	require.Equal(t, customAnchorLeaseMarkerCurrent, state)
	require.Equal(t, []wire.OutPoint{op}, ops)

	foreign := op
	foreign.Index++
	SetCustomAnchorLockedUTXOs(pkt, []wire.OutPoint{foreign})
	_, _, err = parseCustomAnchorLockedUTXOs(pkt)
	require.ErrorContains(t, err, "is not in the transaction")
}

func TestLegacyCustomAnchorLeaseMarkerReacquiresOwnedInputs(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	markCustomAnchorPsbt(pkt)
	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	wallet := tapnodemock.NewWalletAnchor()
	wallet.SetOwnedInput(op, true)
	funded := &FundedMintAnchorPsbt{
		FundedPsbt: tapsend.FundedPsbt{Pkt: pkt},
	}
	_, batchKey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))

	require.NoError(t, renewCustomAnchorLeases(
		context.Background(), wallet, customAnchorLeaseID(batchKey), funded,
	))
	require.Equal(t, op, <-wallet.LeaseInputSignal)
	require.Equal(t, []wire.OutPoint{op}, funded.LockedUTXOs)
	ops, state, err := parseCustomAnchorLockedUTXOs(pkt)
	require.NoError(t, err)
	require.Equal(t, customAnchorLeaseMarkerCurrent, state)
	require.Equal(t, []wire.OutPoint{op}, ops)
	select {
	case duplicate := <-wallet.LeaseInputSignal:
		t.Fatalf("legacy input leased twice during marker upgrade: %v",
			duplicate)
	default:
	}
}

// TestCustomAnchorLeasesAreBatchScoped proves that a failing second batch
// cannot mistake the first batch's input lease for its own and release it
// during rollback.
func TestCustomAnchorLeasesAreBatchScoped(t *testing.T) {
	wallet := newTrackedCustomAnchorWallet()
	ctx := context.Background()

	_, batchKeyA := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))
	_, batchKeyB := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	leaseIDA := customAnchorLeaseID(batchKeyA)
	leaseIDB := customAnchorLeaseID(batchKeyB)
	require.NotEqual(t, leaseIDA, leaseIDB)

	packetA := testCustomAnchorPacket(t)
	inputX := packetA.UnsignedTx.TxIn[0].PreviousOutPoint
	lockedA, err := acquireCustomAnchorLeases(
		ctx, wallet, leaseIDA, packetA, nil,
	)
	require.NoError(t, err)
	require.Equal(t, []wire.OutPoint{inputX}, lockedA)
	require.Equal(t, leaseIDA, wallet.leases[inputX])

	// Batch B acquires Y first, then collides with A's X. Its rollback must
	// release only Y using B's owner ID, leaving A protected.
	packetB := testCustomAnchorPacket(t)
	inputY := packetB.UnsignedTx.TxIn[0].PreviousOutPoint
	inputY.Index++
	packetB.UnsignedTx.TxIn[0].PreviousOutPoint = inputY
	packetB.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputX})
	packetB.Inputs = append(packetB.Inputs, packetB.Inputs[0])

	_, err = acquireCustomAnchorLeases(
		ctx, wallet, leaseIDB, packetB, nil,
	)
	require.ErrorContains(t, err, "another batch")
	require.Equal(t, leaseIDA, wallet.leases[inputX])
	_, yStillLeased := wallet.leases[inputY]
	require.False(t, yStillLeased)
	require.Equal(t, []customAnchorLeaseRequest{{
		leaseID: leaseIDB,
		op:      inputY,
	}}, wallet.releases)

	// Even an explicit B release request for X is ownership-scoped and
	// cannot disturb A. A can still renew the recorded lease afterwards.
	require.NoError(t, releaseCustomAnchorOutpoints(
		ctx, wallet, leaseIDB, []wire.OutPoint{inputX},
	))
	require.Equal(t, leaseIDA, wallet.leases[inputX])
	SetCustomAnchorLockedUTXOs(packetA, lockedA)
	require.NoError(t, renewCustomAnchorLeases(
		ctx, wallet, leaseIDA, &FundedMintAnchorPsbt{
			FundedPsbt: tapsend.FundedPsbt{
				Pkt:         packetA,
				LockedUTXOs: lockedA,
			},
		},
	))
	require.Equal(t, leaseIDA, wallet.leases[inputX])
}

func TestCustomAnchorBatchLeasePath(t *testing.T) {
	packet := testCustomAnchorPacket(t)
	first := packet.UnsignedTx.TxIn[0].PreviousOutPoint
	for idx := uint32(1); idx < 1000; idx++ {
		op := first
		op.Index += idx
		packet.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: op})
		packet.Inputs = append(packet.Inputs, packet.Inputs[0])
	}

	wallet := &batchCustomAnchorWallet{
		WalletAnchor: tapnodemock.NewWalletAnchor(),
		batchLocked:  []wire.OutPoint{first},
	}
	var leaseID tapnode.CustomAnchorLeaseID
	locked, err := acquireCustomAnchorLeases(
		t.Context(), wallet, leaseID, packet, nil,
	)
	require.NoError(t, err)
	require.Equal(t, []wire.OutPoint{first}, locked)
	require.Equal(t, 1, wallet.batchLeaseCalls)
	require.Zero(t, wallet.leaseInputCalls)
}

func TestCustomAnchorBatchLeaseDuplicatePreflight(t *testing.T) {
	packet := testCustomAnchorPacket(t)
	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: packet.UnsignedTx.TxIn[0].PreviousOutPoint,
	})
	packet.Inputs = append(packet.Inputs, packet.Inputs[0])
	wallet := &batchCustomAnchorWallet{
		WalletAnchor: tapnodemock.NewWalletAnchor(),
	}

	_, err := acquireCustomAnchorLeases(
		t.Context(), wallet, tapnode.CustomAnchorLeaseID{}, packet, nil,
	)
	require.ErrorContains(t, err, "repeats input")
	require.Zero(t, wallet.batchLeaseCalls)
	require.Zero(t, wallet.leaseInputCalls)
}

func TestCustomAnchorBatchLeaseRollback(t *testing.T) {
	packet := testCustomAnchorPacket(t)
	current := packet.UnsignedTx.TxIn[0].PreviousOutPoint
	newInput := current
	newInput.Index++
	packet.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: newInput})
	packet.Inputs = append(packet.Inputs, packet.Inputs[0])
	wallet := &batchCustomAnchorWallet{
		WalletAnchor:  tapnodemock.NewWalletAnchor(),
		batchLocked:   []wire.OutPoint{current, newInput},
		batchLeaseErr: errors.New("injected batch lease failure"),
	}

	_, err := acquireCustomAnchorLeases(
		t.Context(), wallet, tapnode.CustomAnchorLeaseID{}, packet,
		[]wire.OutPoint{current},
	)
	require.ErrorContains(t, err, "injected batch lease failure")
	require.Equal(t, 1, wallet.batchLeaseCalls)
	require.Zero(t, wallet.leaseInputCalls)
	require.Equal(t, [][]wire.OutPoint{{newInput}}, wallet.batchReleases)
}

// TestCustomAnchorLeaseRollbackUsesLiveContext proves that an acquisition
// timeout doesn't poison cleanup and leave earlier leases untracked.
func TestCustomAnchorLeaseRollbackUsesLiveContext(t *testing.T) {
	trackedWallet := newTrackedCustomAnchorWallet()
	wallet := &blockingCustomAnchorWallet{
		trackedCustomAnchorWallet: trackedWallet,
		releaseCtxErr:             make(chan error, 1),
	}
	_, batchKey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{4}, 32))
	leaseID := customAnchorLeaseID(batchKey)

	packet := testCustomAnchorPacket(t)
	inputX := packet.UnsignedTx.TxIn[0].PreviousOutPoint
	inputY := inputX
	inputY.Index++
	wallet.blockOn = inputY
	packet.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputY})
	packet.Inputs = append(packet.Inputs, packet.Inputs[0])

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := acquireCustomAnchorLeases(
		ctx, wallet, leaseID, packet, nil,
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case releaseCtxErr := <-wallet.releaseCtxErr:
		require.NoError(t, releaseCtxErr)

	case <-time.After(time.Second):
		t.Fatal("rollback did not release the earlier lease")
	}
	_, xStillLeased := trackedWallet.leases[inputX]
	require.False(t, xStillLeased)
	require.Equal(t, []customAnchorLeaseRequest{{
		leaseID: leaseID,
		op:      inputX,
	}}, trackedWallet.releases)
}

func testCustomAnchorPacket(t *testing.T) *psbt.Packet {
	t.Helper()

	_, pub := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	pkScript, err := txscript.PayToTaprootScript(pub)
	require.NoError(t, err)
	var prevHash chainhash.Hash
	prevHash[0] = 1
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: prevHash, Index: 1,
	}})
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})
	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	pkt.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 2_000, PkScript: pkScript,
	}
	pkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(pub)
	keyDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: asset.TaprootAssetsKeyFamily,
			Index:  1,
		},
		PubKey: pub,
	}
	bip32Derivation, taprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			keyDesc, address.TestNet3Tap.HDCoinType,
		)
	pkt.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	pkt.Outputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootDerivation}
	pkt.Unknowns = []*psbt.Unknown{{Key: []byte{0x50}, Value: []byte("x")}}

	return pkt
}

func TestCustomGenesisPsbtValidation(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	funded, err := customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, pkt, 0, -1,
		noneUint32(), NoOpAugmenter{},
	)
	require.NoError(t, err)
	require.True(t, isCustomAnchorPsbt(funded.Pkt))
	require.True(t, funded.GenesisOutpoint().IsSome())

	missingDerivation := testCustomAnchorPacket(t)
	missingDerivation.Outputs[0].Bip32Derivation = nil
	missingDerivation.Outputs[0].TaprootBip32Derivation = nil
	_, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil,
		missingDerivation, 0, -1, noneUint32(), NoOpAugmenter{},
	)
	require.ErrorContains(t, err, "exactly one BIP32")

	forgedMarker := testCustomAnchorPacket(t)
	forgedMarker.Unknowns = append(forgedMarker.Unknowns, &psbt.Unknown{
		Key:   fn.CopySlice(customAnchorPublishMarker),
		Value: []byte{1},
	})
	funded, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, forgedMarker, 0,
		-1, noneUint32(), NoOpAugmenter{},
	)
	require.NoError(t, err)
	require.Equal(
		t, customAnchorPublishNone,
		getCustomAnchorPublishState(funded.Pkt),
	)

	bad := testCustomAnchorPacket(t)
	bad.Inputs = nil
	_, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, bad, 0, -1,
		noneUint32(), NoOpAugmenter{},
	)
	require.ErrorContains(t, err, "input maps")

	underfunded := testCustomAnchorPacket(t)
	underfunded.Inputs[0].WitnessUtxo.Value = 500
	_, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, underfunded, 0,
		-1, noneUint32(), NoOpAugmenter{},
	)
	require.ErrorContains(t, err, "outputs exceed")

	dust := testCustomAnchorPacket(t)
	dust.UnsignedTx.TxOut[0].Value = 1
	dust.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_RETURN}
	_, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, dust, 0, -1,
		noneUint32(), NoOpAugmenter{},
	)
	require.ErrorContains(t, err, "anchor output is dust")

	for _, tapTree := range [][]byte{{}, {0x00}} {
		anchorTapTree := testCustomAnchorPacket(t)
		anchorTapTree.Outputs[0].TaprootTapTree = tapTree
		_, err = customGenesisPsbt(
			context.Background(), address.TestNet3Tap, nil,
			anchorTapTree, 0, -1, noneUint32(), NoOpAugmenter{},
		)
		require.ErrorContains(t, err, "must not specify a PSBT tap tree")
	}

	// Every non-anchor P2TR output needs enough metadata to construct an
	// exclusion proof after the mint confirms.
	for _, testCase := range []struct {
		name        string
		output      psbt.POutput
		errContains string
	}{
		{
			name:        "missing internal key",
			errContains: "output 1 is a P2TR output but is missing",
		},
		{
			name: "invalid internal key",
			output: psbt.POutput{
				TaprootInternalKey: bytes.Repeat([]byte{0xff}, 32),
			},
			errContains: "internal key is invalid",
		},
		{
			name: "metadata mismatch",
			output: psbt.POutput{
				TaprootInternalKey: fn.CopySlice(
					testCustomAnchorPacket(t).Outputs[0].
						TaprootInternalKey,
				),
			},
			errContains: "metadata does not match",
		},
		{
			name: "malformed tap tree",
			output: psbt.POutput{
				TaprootInternalKey: fn.CopySlice(
					testCustomAnchorPacket(t).Outputs[0].
						TaprootInternalKey,
				),
				TaprootTapTree: []byte{0x00},
			},
			errContains: "invalid PSBT tap tree",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			invalid := testCustomAnchorPacket(t)
			invalid.UnsignedTx.AddTxOut(&wire.TxOut{
				Value: 1_000,
				PkScript: fn.CopySlice(
					invalid.UnsignedTx.TxOut[0].PkScript,
				),
			})
			invalid.Outputs = append(invalid.Outputs, testCase.output)
			_, err := customGenesisPsbt(
				context.Background(), address.TestNet3Tap, nil,
				invalid, 0, -1, noneUint32(), NoOpAugmenter{},
			)
			require.ErrorContains(t, err, testCase.errContains)
		})
	}

	validMetadata := testCustomAnchorPacket(t)
	validInternalKey, err := schnorr.ParsePubKey(
		validMetadata.Outputs[0].TaprootInternalKey,
	)
	require.NoError(t, err)
	validOutputKey := txscript.ComputeTaprootKeyNoScript(validInternalKey)
	validOutputScript, err := txscript.PayToTaprootScript(validOutputKey)
	require.NoError(t, err)
	validMetadata.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: validOutputScript,
	})
	validMetadata.Outputs = append(validMetadata.Outputs, psbt.POutput{
		TaprootInternalKey: fn.CopySlice(
			validMetadata.Outputs[0].TaprootInternalKey,
		),
	})
	_, err = customGenesisPsbt(
		context.Background(), address.TestNet3Tap, nil, validMetadata, 0,
		-1, noneUint32(), NoOpAugmenter{},
	)
	require.NoError(t, err)
}

func TestFinalizedAnchorPsbtBoundsWitnessCount(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	pkt.Inputs[0].FinalScriptWitness = append(
		[]byte{0xff}, bytes.Repeat([]byte{0xff}, 8)...,
	)

	require.ErrorContains(
		t, validateFinalizedAnchorPsbt(pkt), "witness item count",
	)
}

func TestCustomAnchorPublicationPending(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	markCustomAnchorPsbt(pkt)
	setCustomAnchorPublishState(pkt, customAnchorPublishPending)
	batch := &MintingBatch{
		GenesisPacket: &FundedMintAnchorPsbt{
			FundedPsbt: tapsend.FundedPsbt{Pkt: pkt},
		},
	}
	require.True(t, customAnchorPublicationPending(batch))

	setCustomAnchorPublishState(pkt, customAnchorImportPending)
	require.True(t, customAnchorPublicationPending(batch))

	setCustomAnchorPublishState(pkt, customAnchorPublishRejected)
	require.True(t, customAnchorPublicationPending(batch))
}

func TestMergeSignedCustomPsbt(t *testing.T) {
	stored := testCustomAnchorPacket(t)
	markCustomAnchorPsbt(stored)
	signed := clonePsbt(t, stored)
	signed.Inputs[0].FinalScriptSig = []byte{}
	signed.Inputs[0].FinalScriptWitness = []byte{1, 0}
	signed.Inputs[0].TaprootInternalKey = nil
	stripTapdCustomAnchorMarkers(signed)

	merged, err := mergeSignedCustomPsbt(stored, signed)
	require.NoError(t, err)
	require.NotNil(t, merged.Inputs[0].FinalScriptSig)
	require.NotEmpty(t, merged.Inputs[0].FinalScriptWitness)
	require.Equal(t, stored.Inputs[0].WitnessUtxo,
		merged.Inputs[0].WitnessUtxo)
	require.True(t, isCustomAnchorPsbt(merged))

	mutated := clonePsbt(t, signed)
	mutated.Inputs[0].WitnessUtxo.Value++
	_, err = mergeSignedCustomPsbt(stored, mutated)
	require.ErrorContains(t, err, "changes input UTXO")
	require.Nil(t, stored.Inputs[0].FinalScriptSig)
}

func TestFundedMintAnchorPsbtCopyPreservesMetadata(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	pkt.Outputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x51}, Value: []byte("output"),
	}}
	pkt.Inputs[0].SighashType = txscript.SigHashSingle
	original := &FundedMintAnchorPsbt{FundedPsbt: fundedPsbt(pkt)}

	copyAnchor, err := original.Copy()
	require.NoError(t, err)
	copyPkt := copyAnchor.Pkt
	require.Equal(t, pkt.Unknowns, copyPkt.Unknowns)
	require.Equal(t, pkt.Outputs, copyPkt.Outputs)
	require.Equal(t, pkt.Inputs, copyPkt.Inputs)
	copyPkt.Unknowns[0].Value[0] ^= 1
	require.NotEqual(t, pkt.Unknowns, copyPkt.Unknowns)
}

type customAnchorBindAugmenter struct {
	NoOpAugmenter
	bind func(*MintingBatch) (fn.Option[PreCommitBindData], error)
}

func (a customAnchorBindAugmenter) BindData(_ context.Context,
	batch *MintingBatch) (fn.Option[PreCommitBindData], error) {

	return a.bind(batch)
}

// TestCustomGenesisPsbtStagedBatch verifies that binding uses an independent
// batch and that neither successful nor failed binding changes its source.
func TestCustomGenesisPsbtStagedBatch(t *testing.T) {
	bindErr := errors.New("injected bind failure")
	for _, test := range []struct {
		name      string
		bindErr   error
		copyError bool
	}{
		{name: "success"},
		{name: "bind error", bindErr: bindErr},
		{name: "copy error", copyError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &FundedMintAnchorPsbt{
				FundedPsbt: fundedPsbt(testCustomAnchorPacket(t)),
			}
			if test.copyError {
				original.Pkt.UnsignedTx = nil
			}
			batch := &MintingBatch{
				GenesisPacket: original,
				Seedlings: map[string]*Seedling{
					"seed": {AssetName: "original"},
				},
			}
			batch.setState(BatchStateFrozen)
			pkt := testCustomAnchorPacket(t)
			var before bytes.Buffer
			require.NoError(t, pkt.Serialize(&before))
			bindCalled := false
			augmenter := customAnchorBindAugmenter{
				bind: func(staged *MintingBatch) (
					fn.Option[PreCommitBindData], error) {

					bindCalled = true
					require.NotSame(t, batch, staged)
					require.Equal(t, batch.State(), staged.State())
					require.NotSame(t, original, staged.GenesisPacket)
					require.NotSame(t, pkt, staged.GenesisPacket.Pkt)
					require.True(t, isCustomAnchorPsbt(
						staged.GenesisPacket.Pkt,
					))
					staged.setState(BatchStatePending)
					staged.Seedlings["seed"].AssetName = "staged"
					return fn.None[PreCommitBindData](), test.bindErr
				},
			}
			_, err := customGenesisPsbt(
				t.Context(), address.TestNet3Tap, batch, pkt, 0,
				-1, noneUint32(), augmenter,
			)
			switch {
			case test.copyError:
				require.ErrorContains(t, err, "copy pending batch")
				require.False(t, bindCalled)
			case test.bindErr != nil:
				require.ErrorIs(t, err, test.bindErr)
				require.True(t, bindCalled)
			default:
				require.NoError(t, err)
				require.True(t, bindCalled)
			}
			require.Same(t, original, batch.GenesisPacket)
			require.Equal(t, BatchStateFrozen, batch.State())
			require.Equal(t, "original", batch.Seedlings["seed"].AssetName)
			var after bytes.Buffer
			require.NoError(t, pkt.Serialize(&after))
			require.Equal(t, before.Bytes(), after.Bytes())
		})
	}
}

func TestCustomGenesisPsbtSupplyPreCommitment(t *testing.T) {
	ctx := context.Background()
	augmenter := mockSupplyCommitAugmenter{
		chainParams: address.TestNet3Tap,
	}
	seedling := RandGroupAnchorSeedling(t, "supply-anchor", true)
	batch := &MintingBatch{
		Seedlings: map[string]*Seedling{
			seedling.AssetName: &seedling,
		},
		SupplyCommitments: true,
	}

	pkt := testCustomAnchorPacket(t)
	delegationKey, err := seedling.DelegationKey.UnwrapOrErr(
		errors.New("delegation key missing"),
	)
	require.NoError(t, err)
	preCommitOut, err := mockPreCommitTxOut(*delegationKey.PubKey)
	require.NoError(t, err)
	pkt.UnsignedTx.AddTxOut(&preCommitOut)
	pkt.Outputs = append(pkt.Outputs, psbt.POutput{})

	_, err = customGenesisPsbt(
		ctx, address.TestNet3Tap, batch, clonePsbt(t, pkt), 0, -1,
		noneUint32(), augmenter,
	)
	require.ErrorContains(t, err, "requires a pre-commitment output index")

	wrong := clonePsbt(t, pkt)
	wrong.UnsignedTx.TxOut[1].PkScript[0] ^= 1
	_, err = customGenesisPsbt(
		ctx, address.TestNet3Tap, batch, wrong, 0, -1,
		fn.Some(uint32(1)), augmenter,
	)
	require.ErrorContains(t, err, "unique output matching the augmenter")

	wrongValue := clonePsbt(t, pkt)
	wrongValue.UnsignedTx.TxOut[1].Value--
	_, err = customGenesisPsbt(
		ctx, address.TestNet3Tap, batch, wrongValue, 0, -1,
		fn.Some(uint32(1)), augmenter,
	)
	require.ErrorContains(t, err, "unique output matching the augmenter")

	duplicate := clonePsbt(t, pkt)
	duplicate.Inputs[0].WitnessUtxo.Value += preCommitOut.Value
	duplicate.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    preCommitOut.Value,
		PkScript: fn.CopySlice(preCommitOut.PkScript),
	})
	duplicate.Outputs = append(duplicate.Outputs, psbt.POutput{})
	_, err = customGenesisPsbt(
		ctx, address.TestNet3Tap, batch, duplicate, 0, -1,
		fn.Some(uint32(1)), augmenter,
	)
	require.ErrorContains(t, err, "unique output matching the augmenter")

	_, err = customGenesisPsbt(
		ctx, address.TestNet3Tap, nil, clonePsbt(t, pkt), 0, -1,
		fn.Some(uint32(1)), NoOpAugmenter{},
	)
	require.ErrorContains(t, err, "without augmenter output")

	funded, err := customGenesisPsbt(
		ctx, address.TestNet3Tap, batch, clonePsbt(t, pkt), 0, -1,
		fn.Some(uint32(1)), augmenter,
	)
	require.NoError(t, err)
	batch.GenesisPacket = &funded
	bindData, err := augmenter.BindData(ctx, batch)
	require.NoError(t, err)
	preCommit, err := bindData.UnwrapOrErr(
		errors.New("pre-commitment output missing"),
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), preCommit.OutputIndex)
	require.Equal(t, schnorr.SerializePubKey(delegationKey.PubKey),
		funded.Pkt.Outputs[1].TaprootInternalKey)
	require.Len(t, funded.Pkt.Outputs[1].Bip32Derivation, 1)
	require.Len(t, funded.Pkt.Outputs[1].TaprootBip32Derivation, 1)
}

func noneUint32() fn.Option[uint32] { return fn.None[uint32]() }

func fundedPsbt(pkt *psbt.Packet) tapsend.FundedPsbt {
	return tapsend.FundedPsbt{Pkt: pkt, ChangeOutputIndex: -1}
}

func clonePsbt(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	clone, err := psbt.NewFromRawBytes(&buf, false)
	require.NoError(t, err)
	return clone
}
