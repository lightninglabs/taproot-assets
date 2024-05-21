package tapchannelmsg

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	// Block 100002 with 9 transactions on bitcoin mainnet.
	oddTxBlockHexFileName = filepath.Join(
		testDataFileName, "odd-block.hex",
	)
)

// TestOpenChannel tests encoding and decoding of the OpenChannel struct.
func TestOpenChannel(t *testing.T) {
	t.Parallel()

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
		t, randGen, scriptKey1, oddTxBlock, 0, 1,
	)

	// Proofs don't Encode everything, so we need to do a quick Encode/
	// Decode cycle to make sure we can compare it afterward.
	proofBytes, err := proof.Encode(&originalRandProof)
	require.NoError(t, err)
	randProof, err := proof.Decode(proofBytes)
	require.NoError(t, err)

	testCases := []struct {
		name    string
		channel *OpenChannel
	}{
		{
			name:    "empty channel",
			channel: &OpenChannel{},
		},
		{
			name: "channel with funded asset",
			channel: NewOpenChannel([]*AssetOutput{
				NewAssetOutput([32]byte{1}, 1000, *randProof),
			}),
		},
		{
			name: "channel with multiple funded assets",
			channel: NewOpenChannel([]*AssetOutput{
				NewAssetOutput([32]byte{1}, 1000, *randProof),
				NewAssetOutput([32]byte{2}, 2000, *randProof),
			}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the channel and then deserialize it again.
			var b bytes.Buffer
			err := tc.channel.Encode(&b)
			require.NoError(t, err)

			deserializedChannel := &OpenChannel{}
			err = deserializedChannel.Decode(&b)
			require.NoError(t, err)

			require.Equal(t, tc.channel, deserializedChannel)
		})
	}
}

// TestAuxLeaves tests encoding and decoding of the AuxLeaves struct.
func TestAuxLeaves(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		leaves AuxLeaves
	}{
		{
			name:   "empty aux leaves",
			leaves: AuxLeaves{},
		},
		{
			name: "aux leaves with just balance",
			leaves: NewAuxLeaves(
				lfn.Some(test.RandTapLeaf(nil)),
				lfn.Some(test.RandTapLeaf(nil)),
				nil, nil,
			),
		},
		{
			name: "aux leaves with HTLCs",
			leaves: NewAuxLeaves(
				lfn.Some(test.RandTapLeaf(nil)),
				lfn.Some(test.RandTapLeaf(nil)),
				input.AuxTapLeaves{
					0: input.HtlcAuxLeaf{
						AuxTapLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
					},
					999999: input.HtlcAuxLeaf{
						AuxTapLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
						SecondLevelLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
					},
				},
				input.AuxTapLeaves{
					0: input.HtlcAuxLeaf{
						AuxTapLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
					},
					999999: input.HtlcAuxLeaf{
						AuxTapLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
						SecondLevelLeaf: lfn.Some(
							test.RandTapLeaf(nil),
						),
					},
				},
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the aux leaves and then deserialize them
			// again.
			var b bytes.Buffer
			err := tc.leaves.Encode(&b)
			require.NoError(t, err)

			var deserializedLeaves AuxLeaves
			err = deserializedLeaves.Decode(&b)
			require.NoError(t, err)

			require.Equal(t, tc.leaves, deserializedLeaves)
		})
	}
}

// TestCommitment tests encoding and decoding of the Commitment struct.
func TestCommitment(t *testing.T) {
	t.Parallel()

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
		t, randGen, scriptKey1, oddTxBlock, 0, 1,
	)

	// Proofs don't Encode everything, so we need to do a quick Encode/
	// Decode cycle to make sure we can compare it afterward.
	proofBytes, err := proof.Encode(&originalRandProof)
	require.NoError(t, err)
	randProof, err := proof.Decode(proofBytes)
	require.NoError(t, err)

	randLeaf := lfn.Some(test.RandTapLeaf(nil))
	testCases := []struct {
		name       string
		commitment *Commitment
	}{
		{
			name:       "empty commitment",
			commitment: &Commitment{},
		},
		{
			name: "commitment with empty HTLC maps",
			commitment: NewCommitment(
				nil, nil, nil, nil, lnwallet.CommitAuxLeaves{},
			),
		},
		{
			name: "commitment with balances",
			commitment: NewCommitment(
				[]*AssetOutput{
					NewAssetOutput(
						[32]byte{1}, 1000, *randProof,
					),
				}, []*AssetOutput{
					NewAssetOutput(
						[32]byte{1}, 1000, *randProof,
					),
				}, nil, nil, lnwallet.CommitAuxLeaves{},
			),
		},
		{
			name: "commitment with multiple outputs",
			commitment: NewCommitment(
				[]*AssetOutput{
					NewAssetOutput(
						[32]byte{1}, 1000, *randProof,
					),
					NewAssetOutput(
						[32]byte{2}, 2000, *randProof,
					),
				}, []*AssetOutput{
					NewAssetOutput(
						[32]byte{1}, 1000, *randProof,
					),
					NewAssetOutput(
						[32]byte{2}, 2000, *randProof,
					),
				},
				map[input.HtlcIndex][]*AssetOutput{
					0: {
						NewAssetOutput(
							[32]byte{1}, 1000,
							*randProof,
						),
						NewAssetOutput(
							[32]byte{2}, 2000,
							*randProof,
						),
					},
					1: {
						NewAssetOutput(
							[32]byte{1}, 1000,
							*randProof,
						),
						NewAssetOutput(
							[32]byte{2}, 2000,
							*randProof,
						),
					},
				}, map[input.HtlcIndex][]*AssetOutput{
					0: {
						NewAssetOutput(
							[32]byte{1}, 1000,
							*randProof,
						),
						NewAssetOutput(
							[32]byte{2}, 2000,
							*randProof,
						),
					},
					1: {
						NewAssetOutput(
							[32]byte{1}, 1000,
							*randProof,
						),
						NewAssetOutput(
							[32]byte{2}, 2000,
							*randProof,
						),
					},
				}, lnwallet.CommitAuxLeaves{
					LocalAuxLeaf: lfn.Some(
						test.RandTapLeaf(nil),
					),
					RemoteAuxLeaf: lfn.Some(
						test.RandTapLeaf(nil),
					),
					OutgoingHtlcLeaves: input.AuxTapLeaves{
						0: input.HtlcAuxLeaf{
							AuxTapLeaf: randLeaf,
						},
						//nolint:lll
						999999: input.HtlcAuxLeaf{
							AuxTapLeaf:      randLeaf,
							SecondLevelLeaf: randLeaf,
						},
					},
					IncomingHtlcLeaves: input.AuxTapLeaves{
						0: input.HtlcAuxLeaf{
							AuxTapLeaf: randLeaf,
						},
						//nolint:lll
						999999: input.HtlcAuxLeaf{
							AuxTapLeaf:      randLeaf,
							SecondLevelLeaf: randLeaf,
						},
					},
				},
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the commitment and then deserialize it
			// again.
			var b bytes.Buffer
			err := tc.commitment.Encode(&b)
			require.NoError(t, err)

			deserializedCommitment := &Commitment{}
			err = deserializedCommitment.Decode(&b)
			require.NoError(t, err)

			require.Equal(t, tc.commitment, deserializedCommitment)
		})
	}
}
