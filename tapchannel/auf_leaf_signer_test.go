package tapchannel

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	testChainParams = &address.RegressionNetTap

	// Block 100002 with 9 transactions on bitcoin mainnet.
	oddTxBlockHexFileName = filepath.Join(
		testDataFileName, "odd-block.hex",
	)

	testTimeout = time.Second
)

// RandCommitmentKeyRing generates a commitment key ring used to derive HTLC
// signatures.
func RandCommitmentKeyRing(t *testing.T) lnwallet.CommitmentKeyRing {
	return lnwallet.CommitmentKeyRing{
		CommitPoint:         test.RandPubKey(t),
		LocalCommitKeyTweak: test.RandBytes(32),
		LocalHtlcKeyTweak:   test.RandBytes(32),
		LocalHtlcKey:        test.RandPubKey(t),
		RemoteHtlcKey:       test.RandPubKey(t),
		ToLocalKey:          test.RandPubKey(t),
		ToRemoteKey:         test.RandPubKey(t),
		RevocationKey:       test.RandPubKey(t),
	}
}

// RandAuxSigJob generates a basic aux signer job with random key material.
func RandAuxSigJob(t *testing.T, cancelChan chan struct{},
	commitBlob lfn.Option[[]byte], outputIdx int32) lnwallet.AuxSigJob {

	keyDesc, _ := test.RandKeyDesc(t)
	keyRing := RandCommitmentKeyRing(t)

	return lnwallet.AuxSigJob{
		SignDesc: input.SignDescriptor{
			KeyDesc: keyDesc,
		},
		BaseAuxJob: lnwallet.BaseAuxJob{
			OutputIndex: outputIdx,
			KeyRing:     keyRing,
			HTLC: lnwallet.PaymentDescriptor{
				HtlcIndex: 0,
				Amount: lnwire.NewMSatFromSatoshis(
					354,
				),
				EntryType: lnwallet.Add,
			},
			Incoming:   false,
			CommitBlob: commitBlob,
			HtlcLeaf:   input.AuxTapLeaf{},
		},
		Resp:   make(chan lnwallet.AuxSigJobResp, 1),
		Cancel: cancelChan,
	}
}

// TestAuxLeafSigner tests the AuxLeafSigner implementation.
func TestAuxLeafSigner(t *testing.T) {
	cfg := &LeafSignerConfig{
		ChainParams: testChainParams,
		Signer:      &mockVirtualSigner{},
	}

	signer := NewAuxLeafSigner(cfg)
	require.NoError(t, signer.Start())

	defer func() {
		require.NoError(t, signer.Stop())
	}()

	chanState := &channeldb.OpenChannel{
		ChanType: channeldb.AnchorOutputsBit |
			channeldb.ScidAliasChanBit | channeldb.SingleFunderBit |
			channeldb.SimpleTaprootFeatureBit |
			channeldb.TapscriptRootBit,
		IsInitiator: true,
	}
	randInputProof := randProof(t)
	commitTx := &randInputProof.AnchorTx
	outgoingHtlcs := make(map[input.HtlcIndex][]*cmsg.AssetOutput)
	outgoingHtlcs[0] = []*cmsg.AssetOutput{
		cmsg.NewAssetOutput(
			randInputProof.Asset.ID(), randInputProof.Asset.Amount,
			randInputProof,
		),
	}

	com := cmsg.NewCommitment(
		nil, nil, outgoingHtlcs, nil, lnwallet.CommitAuxLeaves{},
	)
	cancelChan := make(chan struct{})
	job := RandAuxSigJob(t, cancelChan, lfn.Some[tlv.Blob](com.Bytes()), 0)
	jobs := []lnwallet.AuxSigJob{job}

	err := signer.SubmitSecondLevelSigBatch(chanState, commitTx, jobs)
	require.NoError(t, err)

	select {
	case resp := <-jobs[0].Resp:
		require.NoError(t, resp.Err)
		require.True(t, resp.SigBlob.IsSome())
		require.True(t, bytes.Contains(
			resp.SigBlob.UnwrapOr(nil),
			[]byte("this is a signature"),
		))

	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for response")
	}
}

// TestAuxLeafSignerCancel tests that the AuxLeafSigner will handle a cancel
// signal correctly, which involves skipping all remaining sig jobs.
func TestAuxLeafSignerCancel(t *testing.T) {
	cfg := &LeafSignerConfig{
		ChainParams: testChainParams,
		Signer:      &mockVirtualSigner{},
	}

	signer := NewAuxLeafSigner(cfg)
	require.NoError(t, signer.Start())

	defer func() {
		require.NoError(t, signer.Stop())
	}()

	chanState := &channeldb.OpenChannel{
		ChanType: channeldb.AnchorOutputsBit |
			channeldb.ScidAliasChanBit | channeldb.SingleFunderBit |
			channeldb.SimpleTaprootFeatureBit |
			channeldb.TapscriptRootBit,
		IsInitiator: true,
	}
	randInputProof := randProof(t)
	commitTx := &randInputProof.AnchorTx
	outgoingHtlcs := make(map[input.HtlcIndex][]*cmsg.AssetOutput)
	outgoingHtlcs[0] = []*cmsg.AssetOutput{
		cmsg.NewAssetOutput(
			randInputProof.Asset.ID(), randInputProof.Asset.Amount,
			randInputProof,
		),
	}

	com := cmsg.NewCommitment(
		nil, nil, outgoingHtlcs, nil, lnwallet.CommitAuxLeaves{},
	)
	cancelChan := make(chan struct{})

	// Constructing multiple jobs will allow us to assert that later jobs
	// are cancelled successfully.
	numSigJobs := 10
	jobs := make([]lnwallet.AuxSigJob, 0, numSigJobs)
	outputIdxCounter := int32(0)

	for range numSigJobs {
		newJob := RandAuxSigJob(
			t, cancelChan, lfn.Some[tlv.Blob](com.Bytes()),
			outputIdxCounter,
		)
		jobs = append(jobs, newJob)
		outputIdxCounter++
	}

	// We'll try to cancel all signature jobs once the aux signer completes
	// a third of the batch.
	cancelThreshold := numSigJobs / 3

	err := signer.SubmitSecondLevelSigBatch(chanState, commitTx, jobs)
	require.NoError(t, err)

	select {
	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for response")
	case <-jobs[cancelThreshold].Resp:
		// Send the cancel signal; jobs at the end of the batch should
		// not be processed.
		close(cancelChan)
	}

	signer.Wg.Wait()

	// Once the aux signer finishes handling the batch, the last job of the
	// batch should have an empty response. Otherwise, the signer failed
	// to skip that job after the cancel channel was closed.
	select {
	case <-jobs[numSigJobs-1].Resp:
		t.Fatalf("Job cancellation failed")
	default:
	}
}

// TestAuxLeafSignerCancelAndQuit tests that the AuxLeafSigner will handle a
// quit signal correctly, which involves ending sig job handling as soon as
// possible. This test also sends a cancel signal before the quit signal, to
// check that quits are handled correctly alongside other sent signals.
func TestAuxLeafSignerCancelAndQuit(t *testing.T) {
	cfg := &LeafSignerConfig{
		ChainParams: testChainParams,
		Signer:      &mockVirtualSigner{},
	}

	signer := NewAuxLeafSigner(cfg)
	require.NoError(t, signer.Start())

	defer func() {
		require.NoError(t, signer.Stop())
	}()

	chanState := &channeldb.OpenChannel{
		ChanType: channeldb.AnchorOutputsBit |
			channeldb.ScidAliasChanBit | channeldb.SingleFunderBit |
			channeldb.SimpleTaprootFeatureBit |
			channeldb.TapscriptRootBit,
		IsInitiator: true,
	}
	randInputProof := randProof(t)
	commitTx := &randInputProof.AnchorTx
	outgoingHtlcs := make(map[input.HtlcIndex][]*cmsg.AssetOutput)
	outgoingHtlcs[0] = []*cmsg.AssetOutput{
		cmsg.NewAssetOutput(
			randInputProof.Asset.ID(), randInputProof.Asset.Amount,
			randInputProof,
		),
	}

	com := cmsg.NewCommitment(
		nil, nil, outgoingHtlcs, nil, lnwallet.CommitAuxLeaves{},
	)
	cancelChan := make(chan struct{})

	// Constructing multiple jobs will allow us to assert that later jobs
	// are skipped successfully after sending the quit signal.
	numSigJobs := 10
	jobs := make([]lnwallet.AuxSigJob, 0, numSigJobs)
	outputIdxCounter := int32(0)

	for range numSigJobs {
		newJob := RandAuxSigJob(
			t, cancelChan, lfn.Some[tlv.Blob](com.Bytes()),
			outputIdxCounter,
		)
		jobs = append(jobs, newJob)
		outputIdxCounter++
	}

	// We'll send the quit signal once the aux signer completes a third of
	// the batch.
	cancelThreshold := numSigJobs / 3

	err := signer.SubmitSecondLevelSigBatch(chanState, commitTx, jobs)
	require.NoError(t, err)

	select {
	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for response")
	case <-jobs[cancelThreshold].Resp:
		// Another component could have sent the cancel signal; we'll
		// send that before the quit signal.
		close(cancelChan)
		time.Sleep(time.Millisecond)

		// Send the quit signal; jobs at the end of the batch should not
		// be processed.
		require.NoError(t, signer.Stop())
	}

	// Once the aux signer stops, the last job of the batch should have an
	// an empty response. Otherwise, the signer failed to stop as soon as
	// the quit signal was sent.
	select {
	case <-jobs[numSigJobs-1].Resp:
		t.Fatalf("Aux signer quitting failed")
	default:
	}
}

// mockVirtualSigner is a mock implementation of the VirtualSigner interface.
type mockVirtualSigner struct {
}

// SignVirtualPacket signs the virtual transaction of the given packet and
// returns the input indexes that were signed.
//
// NOTE: This is part of the VirtualPacketSigner interface.
func (m *mockVirtualSigner) SignVirtualPacket(vPkt *tappsbt.VPacket,
	_ ...tapfreighter.SignVirtualPacketOption) ([]uint32,
	error) {

	// A second-level HTLC transaction is always a one-in-one-out virtual
	// transaction, so there's always just one (non-split) output.
	vPkt.Outputs[0].Asset.PrevWitnesses[0].TxWitness = [][]byte{
		[]byte("this is a signature"),
	}

	return []uint32{0}, nil
}

// A compile time check to ensure mockVirtualSigner implements the
// VirtualPacketSigner interface.
var _ VirtualPacketSigner = (*mockVirtualSigner)(nil)

// randProof returns a random proof that contains all information required for
// it to be successfully serialized.
func randProof(t *testing.T) proof.Proof {
	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	randGen := asset.RandGenesis(t, asset.Normal)
	scriptKey1 := test.RandPubKey(t)
	originalRandProof := proof.RandProof(
		t, randGen, scriptKey1, oddTxBlock, 0, 0,
	)

	// Proofs don't Encode everything, so we need to do a quick Encode/
	// Decode cycle to make sure we can compare it afterward.
	proofBytes, err := proof.Encode(&originalRandProof)
	require.NoError(t, err)
	p, err := proof.Decode(proofBytes)
	require.NoError(t, err)

	return *p
}
