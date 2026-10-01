package tapchannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestNewSTXOFeatures tests that the STXO features of a peer follow from its
// feature bits, and that the spender leaves presuppose the STXOs.
func TestNewSTXOFeatures(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		bits []lnwire.FeatureBit
		want STXOFeatures
	}{{
		name: "none",
	}, {
		name: "stxo",
		bits: []lnwire.FeatureBit{tapfeatures.STXOOptional},
		want: STXOFeatures{STXO: true},
	}, {
		name: "stxo required",
		bits: []lnwire.FeatureBit{tapfeatures.STXORequired},
		want: STXOFeatures{STXO: true},
	}, {
		name: "spender without stxo",
		bits: []lnwire.FeatureBit{tapfeatures.STXOSpenderOptional},
	}, {
		name: "stxo and spender",
		bits: []lnwire.FeatureBit{
			tapfeatures.STXOOptional,
			tapfeatures.STXOSpenderOptional,
		},
		want: STXOFeatures{STXO: true, Spender: true},
	}, {
		name: "stxo and spender required",
		bits: []lnwire.FeatureBit{
			tapfeatures.STXORequired,
			tapfeatures.STXOSpenderRequired,
		},
		want: STXOFeatures{STXO: true, Spender: true},
	}}

	// The required and optional bits of a feature are only taken for one
	// another if the vector knows them as a pair, as the negotiator's
	// vectors do.
	featureNames := map[lnwire.FeatureBit]string{
		tapfeatures.STXORequired:        "stxo-proofs",
		tapfeatures.STXOOptional:        "stxo-proofs",
		tapfeatures.STXOSpenderRequired: "stxo-spender",
		tapfeatures.STXOSpenderOptional: "stxo-spender",
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			features := lnwire.NewFeatureVector(
				lnwire.NewRawFeatureVector(tc.bits...),
				featureNames,
			)
			require.Equal(t, tc.want, NewSTXOFeatures(*features))
		})
	}
}

// TestCommitmentSTXOFeatures tests that the STXO features of a commitment are
// carried across its encoding, and that a commitment that predates the
// spender flag decodes without it.
func TestCommitmentSTXOFeatures(t *testing.T) {
	t.Parallel()

	allFeatures := []STXOFeatures{
		{},
		{STXO: true},
		{STXO: true, Spender: true},
	}
	for _, stxoFeatures := range allFeatures {
		commitment := cmsg.NewCommitment(
			nil, nil, nil, nil, lnwallet.CommitAuxLeaves{},
			stxoFeatures.STXO, stxoFeatures.Spender,
		)
		require.Equal(
			t, stxoFeatures, CommitmentSTXOFeatures(commitment),
		)

		decoded, err := cmsg.DecodeCommitment(commitment.Bytes())
		require.NoError(t, err)
		require.Equal(t, stxoFeatures, CommitmentSTXOFeatures(decoded))
	}

	// A commitment that records the spender flag without the STXO flag
	// carries no alt leaves at all.
	commitment := cmsg.NewCommitment(
		nil, nil, nil, nil, lnwallet.CommitAuxLeaves{}, false, true,
	)
	require.Equal(t, STXOFeatures{}, CommitmentSTXOFeatures(commitment))

	// A commitment encoded before the spender flag existed carries the
	// STXO flag alone.
	legacy := cmsg.NewCommitment(
		nil, nil, nil, nil, lnwallet.CommitAuxLeaves{}, true, true,
	)
	var encoded bytes.Buffer
	require.NoError(t, legacy.Encode(&encoded))

	// The spender flag is the last record of the commitment: type 7,
	// length 1, value 1.
	withoutSpender, spenderRecord := bytes.CutSuffix(
		encoded.Bytes(), []byte{0x07, 0x01, 0x01},
	)
	require.True(t, spenderRecord)

	decoded, err := cmsg.DecodeCommitment(withoutSpender)
	require.NoError(t, err)
	require.Equal(
		t, STXOFeatures{STXO: true}, CommitmentSTXOFeatures(decoded),
	)
}

// TestDecodeCloseInfoSTXOVersion tests that the close info of a channel that
// was closed before the spender flag was recorded still decodes.
func TestDecodeCloseInfoSTXOVersion(t *testing.T) {
	t.Parallel()

	for _, supportSTXO := range []bool{false, true} {
		var buf bytes.Buffer
		require.NoError(t, binary.Write(
			&buf, binary.BigEndian, closeInfoFormatVersionSTXO,
		))
		require.NoError(t, binary.Write(
			&buf, binary.BigEndian, int64(12345),
		))

		var stxoByte uint8
		if supportSTXO {
			stxoByte = 1
		}
		require.NoError(t, binary.Write(
			&buf, binary.BigEndian, stxoByte,
		))
		require.NoError(t, writeVPacketList(&buf, nil))
		require.NoError(t, writeVPacketList(&buf, nil))
		require.NoError(t, binary.Write(
			&buf, binary.BigEndian, uint32(0),
		))

		info, err := decodeCloseInfo(&buf)
		require.NoError(t, err)
		require.Equal(t, int64(12345), info.closeFee)
		require.Equal(
			t, STXOFeatures{STXO: supportSTXO}, info.stxoFeatures,
		)
	}
}

// TestFundingCommitmentSTXOFeatures tests that a funding commitment carries
// the alt leaves of the negotiated STXO features, that the funding proofs
// prove them, and that the commitment root is reproduced from the funding
// outputs whatever the features.
func TestFundingCommitmentSTXOFeatures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := []struct {
		name         string
		stxoFeatures STXOFeatures
		numAltLeaves int
	}{{
		name: "none",
	}, {
		name:         "stxo",
		stxoFeatures: STXOFeatures{STXO: true},
		numAltLeaves: 1,
	}, {
		name:         "stxo and spender",
		stxoFeatures: STXOFeatures{STXO: true, Spender: true},
		numAltLeaves: 2,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const numAssets = 2

			h := newFundingHarnessWithFeatures(
				t, numAssets, 0, false, tc.stxoFeatures,
			)

			// Each funding asset spends a single input.
			altLeaves, err := h.fundingState.
				fundingAssetCommitment.FetchAltLeaves()
			require.NoError(t, err)
			require.Len(t, altLeaves, numAssets*tc.numAltLeaves)

			for _, output := range h.outputs {
				carrier := output.Proof.Val.InclusionProof.
					CommitmentProof

				if !tc.stxoFeatures.STXO {
					require.Empty(t, carrier.STXOProofs)
					require.Empty(t, carrier.SpenderProofs)

					continue
				}

				require.Len(t, carrier.STXOProofs, 1)
				if tc.stxoFeatures.Spender {
					require.Len(t, carrier.SpenderProofs, 1)
				} else {
					require.Empty(t, carrier.SpenderProofs)
				}
			}

			err = validateFundingProofs(
				ctx, proof.MockVerifierCtx, h.fundingState,
				h.outputs,
			)
			require.NoError(t, err)

			root := h.fundingState.fundingAssetCommitment.
				TapscriptRoot(nil)
			require.NoError(
				t, checkFundingCommitmentRoot(h.outputs, root),
			)

			// A funding commitment with an asset the proofs don't
			// cover is not reproduced.
			err = h.fundingState.addToFundingCommitment(
				asset.RandAsset(t, asset.Normal),
				tc.stxoFeatures,
			)
			require.NoError(t, err)

			otherRoot := h.fundingState.fundingAssetCommitment.
				TapscriptRoot(nil)
			err = checkFundingCommitmentRoot(h.outputs, otherRoot)
			require.ErrorContains(t, err, "do not reproduce")
		})
	}
}

// TestSweepSTXOFeatures tests that the sweeper reproduces the alt leaves a
// pre-signed output was signed for, as recorded by its resolution, and
// commits to all of them for an output of its own.
func TestSweepSTXOFeatures(t *testing.T) {
	t.Parallel()

	newBlob := func(res cmsg.ContractResolution) lfn.Option[tlv.Blob] {
		var buf bytes.Buffer
		require.NoError(t, res.Encode(&buf))

		return lfn.Some[tlv.Blob](buf.Bytes())
	}

	// A resolution that predates the record, and one for each set of
	// features.
	legacy := cmsg.ContractResolution{}
	var legacyBuf bytes.Buffer
	require.NoError(t, legacy.Encode(&legacyBuf))
	legacyBlob := lfn.Some[tlv.Blob](legacyBuf.Bytes())

	noSigDesc := lfn.None[cmsg.TapscriptSigDesc]()
	testCases := []struct {
		name        string
		witnessType input.WitnessType
		blob        lfn.Option[tlv.Blob]
		want        STXOFeatures
	}{{
		name:        "pre-signed, legacy resolution",
		witnessType: input.TaprootHtlcAcceptedLocalSuccess,
		blob:        legacyBlob,
		want:        STXOFeatures{STXO: true},
	}, {
		name:        "pre-signed, no leaves",
		witnessType: input.TaprootHtlcLocalOfferedTimeout,
		blob: newBlob(cmsg.NewContractResolution(
			nil, nil, noSigDesc, false, false,
		)),
	}, {
		name:        "pre-signed, stxo",
		witnessType: input.TaprootHtlcAcceptedLocalSuccess,
		blob: newBlob(cmsg.NewContractResolution(
			nil, nil, noSigDesc, true, false,
		)),
		want: STXOFeatures{STXO: true},
	}, {
		name:        "pre-signed, stxo and spender",
		witnessType: input.TaprootHtlcLocalOfferedTimeout,
		blob: newBlob(cmsg.NewContractResolution(
			nil, nil, noSigDesc, true, true,
		)),
		want: STXOFeatures{STXO: true, Spender: true},
	}, {
		name:        "pre-signed, spender without stxo",
		witnessType: input.TaprootHtlcAcceptedLocalSuccess,
		blob: newBlob(cmsg.NewContractResolution(
			nil, nil, noSigDesc, false, true,
		)),
	}, {
		name:        "own output, legacy resolution",
		witnessType: input.TaprootLocalCommitSpend,
		blob:        legacyBlob,
		want:        sweepOutputSTXOFeatures,
	}, {
		name:        "own output, no leaves recorded",
		witnessType: input.TaprootRemoteCommitSpend,
		blob: newBlob(cmsg.NewContractResolution(
			nil, nil, noSigDesc, false, false,
		)),
		want: sweepOutputSTXOFeatures,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sweepInput := input.NewBaseInput(
				&wire.OutPoint{}, tc.witnessType,
				&input.SignDescriptor{}, 0,
				input.WithResolutionBlob(tc.blob),
			)

			sets, err := extractInputVPackets(
				[]input.Input{sweepInput},
			).Unpack()
			require.NoError(t, err)

			allSets := sets.allVpktsWithInput()
			require.Len(t, allSets, 1)
			require.Equal(t, tc.want, allSets[0].stxoFeatures)
		})
	}
}
