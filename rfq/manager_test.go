package rfq

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	tpchmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

var (
	asset1 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "111",
		},
	}
	asset2 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "222",
		},
	}
	asset3 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "333",
		},
	}
	testAssetID1 = asset1.ID()
	testAssetID2 = asset2.ID()
	testAssetID3 = asset3.ID()
	proof1       = proof.Proof{
		Asset: asset1,
	}
	proof2 = proof.Proof{
		Asset: asset2,
	}
	proof3 = proof.Proof{
		Asset: asset3,
	}
	testGroupKey = pubKeyFromUint64(2121)
	peer1        = route.Vertex{88}
	peer2        = route.Vertex{77}
)

// GroupLookupMock mocks the GroupLookup interface that is required by the
// rfq manager to check asset IDs against asset specifiers.
type GroupLookupMock struct{}

// QueryAssetGroup fetches the group information of an asset, if it belongs in a
// group.
func (g *GroupLookupMock) QueryAssetGroup(_ context.Context,
	id asset.ID) (*asset.AssetGroup, error) {

	// We only consider testAssetID1 and testAssetID2 to be in the group.
	if id == testAssetID1 || id == testAssetID2 {
		return &asset.AssetGroup{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *testGroupKey,
			},
		}, nil
	}

	return nil, address.ErrAssetGroupUnknown
}

// testCaseComputeChannelAssetBalance is a test case for computing the channel
// asset balances.
type testCaseComputeChannelAssetBalance struct {
	name               string
	activeChannels     []lndclient.ChannelInfo
	specifier          asset.Specifier
	expectedValidPeers int
	expectedLocalBal   uint64
	expectedRemoteBal  uint64
}

// createChannelWithCustomData creates a dummy channel with only the custom data
// and peer fields populated. The custom data encode the local and remote
// balances of the given asset ID.
func createChannelWithCustomData(t *testing.T, id asset.ID, localBalance,
	remoteBalance uint64, proof proof.Proof,
	peer route.Vertex) lndclient.ChannelInfo {

	customData := tpchmsg.ChannelCustomData{
		LocalCommit: *tpchmsg.NewCommitment(
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id, localBalance, proof,
				),
			},
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id, remoteBalance, proof,
				),
			},
			nil, nil, lnwallet.CommitAuxLeaves{},
		),
		OpenChan: *tpchmsg.NewOpenChannel(
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id,
					localBalance+remoteBalance, proof,
				),
			}, 0, nil,
		),
	}

	data, err := customData.AsJson()
	require.NoError(t, err)

	return lndclient.ChannelInfo{
		CustomChannelData: data,
		PubKeyBytes:       peer,
	}
}

// assertComputeChannelAssetBalance asserts that the manager can compute the
// correct asset balances for the test case. It also compares the results
// against some expected values.
func assertComputeChannelAssetBalance(t *testing.T,
	tc testCaseComputeChannelAssetBalance) {

	mockGroupLookup := &GroupLookupMock{}
	cfg := ManagerCfg{
		GroupLookup: mockGroupLookup,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctxt, cancel := context.WithTimeout(
		context.Background(), DefaultTimeout,
	)
	defer cancel()

	chanMap, _, err := manager.ComputeChannelAssetBalance(
		ctxt, tc.activeChannels, tc.specifier,
	)
	require.NoError(t, err)

	// We avoid using require.Len directly on the map here as it will print
	// the whole map on fail.
	require.Equal(t, tc.expectedValidPeers, len(chanMap))

	var totalLocal, totalRemote uint64

	for _, v := range chanMap {
		for _, ch := range v {
			totalLocal += ch.AssetInfo.LocalBalance
			totalRemote += ch.AssetInfo.RemoteBalance
		}
	}

	require.Equal(t, tc.expectedLocalBal, totalLocal)
	require.Equal(t, tc.expectedRemoteBal, totalRemote)
}

// TestComputeChannelAssetBalance tests that the rfq manager can correctly
// filter the channels according to the asset ID of the channel and the provided
// asset specifier.
func TestComputeChannelAssetBlanace(t *testing.T) {
	testCases := []testCaseComputeChannelAssetBalance{
		{
			name: "1 asset 1 channel 1 peer",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   10_000,
			expectedRemoteBal:  15_000,
		},
		{
			name: "1 asset 2 channels 1 peer",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "1 asset 2 channels 2 peers",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "2 assets 2 channels 2 peers, asset specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   10_000,
			expectedRemoteBal:  15_000,
		},
		{
			name: "2 assets 2 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "3 assets 3 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "3 assets 6 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   40_000,
			expectedRemoteBal:  60_000,
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		success := t.Run(tc.name, func(t *testing.T) {
			assertComputeChannelAssetBalance(t, tc)
		})
		if !success {
			break
		}
	}
}

// pubKeyFromUint64 is a helper function that generates a public key from a
// uint64 value.
func pubKeyFromUint64(num uint64) *btcec.PublicKey {
	var (
		buf    = make([]byte, 8)
		scalar = new(secp256k1.ModNScalar)
	)
	binary.BigEndian.PutUint64(buf, num)
	_ = scalar.SetByteSlice(buf)
	return secp256k1.NewPrivateKey(scalar).PubKey()
}
