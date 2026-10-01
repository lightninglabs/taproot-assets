package tapsend

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

// spenderTestPackets returns a split, along with a full value transfer that is
// anchored in the output of the split root.
func spenderTestPackets(t *testing.T,
	internalKey *btcec.PublicKey) []*tappsbt.VPacket {

	const (
		rootOutput  = 0
		splitOutput = 1
	)

	return []*tappsbt.VPacket{
		createPacket(
			t, randTransferAsset(t, asset.Normal), true,
			internalKey, splitOutput,
		),
		createPacket(
			t, randTransferAsset(t, asset.Normal), false,
			internalKey, rootOutput,
		),
	}
}

// commitTestPackets creates the output commitments of the given packets and
// commits them to a fresh anchor transaction with the given number of outputs.
func commitTestPackets(t *testing.T, internalKey *btcec.PublicKey,
	numOutputs int, vPackets []*tappsbt.VPacket,
	opts ...OutputCommitmentOption) (*psbt.Packet,
	tappsbt.OutputCommitments) {

	commitments, err := CreateOutputCommitments(vPackets, opts...)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for i := 0; i < numOutputs; i++ {
		tx.AddTxOut(CreateDummyOutput())
	}

	anchor, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for idx := range anchor.Outputs {
		anchor.Outputs[idx].TaprootInternalKey =
			schnorr.SerializePubKey(internalKey)
	}
	for _, vPkt := range vPackets {
		require.NoError(t, UpdateTaprootOutputKeys(
			anchor, vPkt, commitments,
		))
	}

	return anchor, commitments
}

// TestCreateOutputCommitmentsSpenderLeaves tests that the spender leaves of the
// inputs are only committed to on request, next to their STXOs.
func TestCreateOutputCommitmentsSpenderLeaves(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		opts     []OutputCommitmentOption
		stxos    bool
		spenders bool
	}{{
		name:  "STXOs",
		stxos: true,
	}, {
		name: "STXOs and spender leaves",
		opts: []OutputCommitmentOption{
			WithSpenderLeaves(),
		},
		stxos:    true,
		spenders: true,
	}, {
		name: "no STXOs",
		opts: []OutputCommitmentOption{
			WithNoSTXOProofs(), WithSpenderLeaves(),
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testCreateOutputCommitmentsSpenderLeaves(
				t, tc.stxos, tc.spenders, tc.opts...,
			)
		})
	}
}

func testCreateOutputCommitmentsSpenderLeaves(t *testing.T, stxos,
	spenders bool, opts ...OutputCommitmentOption) {

	const (
		rootOutput  = 0
		splitOutput = 1
	)

	// Each transfer spends a single input.
	var numAltLeaves int
	if stxos {
		numAltLeaves++
	}
	if spenders {
		numAltLeaves++
	}

	vPackets := spenderTestPackets(t, test.RandPubKey(t))
	commitments, err := CreateOutputCommitments(vPackets, opts...)
	require.NoError(t, err)

	// The root assets of both transfers share an anchor output.
	rootLeaves, err := commitments[rootOutput].FetchAltLeaves()
	require.NoError(t, err)
	require.Len(t, rootLeaves, len(vPackets)*numAltLeaves)

	// A split asset spends no inputs of its own.
	splitLeaves, err := commitments[splitOutput].FetchAltLeaves()
	require.NoError(t, err)
	require.Empty(t, splitLeaves)

	for _, vPkt := range vPackets {
		root := vPkt.Outputs[0]
		require.True(t, root.Asset.IsTransferRoot())

		spenderLeaves, err := asset.CollectSpenders(root.Asset)
		require.NoError(t, err)
		require.Len(t, spenderLeaves, 1)

		spenderLeaf := spenderLeaves[0].(*asset.Asset)
		committed, _, err := commitments[rootOutput].Proof(
			spenderLeaf.TapCommitmentKey(),
			spenderLeaf.AssetCommitmentKey(),
		)
		require.NoError(t, err)
		require.Equal(t, spenders, committed != nil)

		// The leaves are carried by the packet, across its encoding.
		encoded, err := tappsbt.Encode(vPkt)
		require.NoError(t, err)
		decoded, err := tappsbt.Decode(encoded)
		require.NoError(t, err)

		decodedLeaves := decoded.Outputs[0].AltLeaves
		require.Len(t, decodedLeaves, numAltLeaves)
		asset.CompareAltLeaves(t, root.AltLeaves, decodedLeaves)
	}
}

// TestCreateProofSuffixSpenderProofs tests that the suffix proofs of a transfer
// carry the spender proofs for the inputs spent by its root asset, if the
// spender leaves are committed to.
func TestCreateProofSuffixSpenderProofs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		opts     []OutputCommitmentOption
		spenders int
	}{{
		name: "spender leaves",
		opts: []OutputCommitmentOption{
			WithSpenderLeaves(),
		},
		spenders: 1,
	}, {
		name: "no spender leaves",
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testCreateProofSuffixSpenderProofs(
				t, tc.spenders, tc.opts...,
			)
		})
	}
}

func testCreateProofSuffixSpenderProofs(t *testing.T, spenders int,
	opts ...OutputCommitmentOption) {

	const numOutputs = 2

	internalKey := test.RandPubKey(t)
	vPackets := spenderTestPackets(t, internalKey)
	anchor, commitments := commitTestPackets(
		t, internalKey, numOutputs, vPackets, opts...,
	)

	for _, vPkt := range vPackets {
		for outIdx := range vPkt.Outputs {
			suffix, err := CreateProofSuffix(
				anchor.UnsignedTx, anchor.Outputs, vPkt,
				commitments, outIdx, vPackets,
				proof.WithVersion(proof.TransitionV1),
			)
			require.NoError(t, err)

			assertProofsValid(t, vPkt, suffix)

			// The proof for the anchor output of the root asset
			// carries the spender proofs.
			ownProof := suffix.InclusionProof.CommitmentProof
			carrier := ownProof
			if suffix.SplitRootProof != nil {
				carrier = suffix.SplitRootProof.CommitmentProof

				require.Empty(t, ownProof.SpenderProofs)
			}

			require.Len(t, carrier.SpenderProofs, spenders)
			require.Len(t, carrier.STXOProofs, 1)
		}
	}
}
