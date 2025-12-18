package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// testAssetID is a dummy asset ID for testing.
var testAssetID = asset.ID{1, 2, 3, 4}

// HTLC entry type constants for convenience in tests.
const (
	htlcSettle  = uint8(lnwallet.Settle)
	htlcFail    = uint8(lnwallet.Fail)
	htlcNoOpAdd = uint8(lnwallet.NoOpAdd)
)

// assetHtlc defines an asset HTLC for testing with all the parameters needed
// to create a test descriptor.
type assetHtlc struct {
	amount             uint64
	htlcIndex          uint64
	parentIndex        uint64
	entryType          uint8
	addHeightLocal     uint64
	addHeightRemote    uint64
	removeHeightLocal  uint64
	removeHeightRemote uint64
}

// viewConfig defines the configuration for creating an AuxHtlcView.
type viewConfig struct {
	nextHeight     uint64
	localHtlcs     []assetHtlc
	remoteHtlcs    []assetHtlc
	localNonAsset  bool
	remoteNonAsset bool
}

// testCase defines a test case for ComputeView.
type testCase struct {
	name string

	// Inputs to ComputeView.
	ourBalance   uint64
	theirBalance uint64
	whoseCommit  lntypes.ChannelParty
	viewConfig   viewConfig

	// Expected outputs.
	expectError           bool
	expectedOurBalance    uint64
	expectedTheirBalance  uint64
	expectedOurUpdates    int
	expectedTheirUpdates  int
	expectedNonAssetOur   int
	expectedNonAssetTheir int

	// Optional custom validation function
	validate func(t *testing.T, ourResult, theirResult uint64,
		filteredView, nonAssetView *DecodedView)
}

// createView creates an AuxHtlcView from a viewConfig, handling all the
// boilerplate of creating HTLCs with proper asset records.
func createView(t *testing.T, cfg viewConfig) lnwallet.AuxHtlcView {
	// Helper to create asset custom records
	makeAssetRecords := func(amount uint64) lnwire.CustomRecords {
		assetBalance := rfqmsg.NewAssetBalance(testAssetID, amount)
		htlcData := rfqmsg.NewHtlc(
			[]*rfqmsg.AssetBalance{assetBalance},
			fn.None[rfqmsg.ID](), fn.None[[]rfqmsg.ID](),
		)
		records, err := lnwire.ParseCustomRecords(htlcData.Bytes())
		require.NoError(t, err)
		return records
	}

	var localDescriptors []lnwallet.AuxHtlcDescriptor
	var remoteDescriptors []lnwallet.AuxHtlcDescriptor

	// Create local HTLCs
	for _, htlc := range cfg.localHtlcs {
		desc := lnwallet.NewTestAuxHtlcDescriptor(
			lnwire.ChannelID{},
			lnwallet.PaymentHash{byte(htlc.htlcIndex)},
			100,
			lnwire.MilliSatoshi(10000000),
			htlc.htlcIndex,
			htlc.parentIndex,
			htlc.entryType,
			makeAssetRecords(htlc.amount),
			htlc.addHeightLocal,
			htlc.addHeightRemote,
			htlc.removeHeightLocal,
			htlc.removeHeightRemote,
		)
		localDescriptors = append(localDescriptors, desc)
	}

	// Create remote HTLCs
	for _, htlc := range cfg.remoteHtlcs {
		desc := lnwallet.NewTestAuxHtlcDescriptor(
			lnwire.ChannelID{},
			lnwallet.PaymentHash{byte(htlc.htlcIndex)},
			100,
			lnwire.MilliSatoshi(10000000),
			htlc.htlcIndex,
			htlc.parentIndex,
			htlc.entryType,
			makeAssetRecords(htlc.amount),
			htlc.addHeightLocal,
			htlc.addHeightRemote,
			htlc.removeHeightLocal,
			htlc.removeHeightRemote,
		)
		remoteDescriptors = append(remoteDescriptors, desc)
	}

	// Add non-asset HTLC if requested
	if cfg.localNonAsset {
		localDescriptors = append(
			localDescriptors,
			lnwallet.AuxHtlcDescriptor{
				ChanID:        lnwire.ChannelID{},
				RHash:         lnwallet.PaymentHash{},
				Timeout:       100,
				Amount:        lnwire.MilliSatoshi(10000000),
				HtlcIndex:     999,
				ParentIndex:   0,
				CustomRecords: nil, // No assets
			},
		)
	}
	if cfg.remoteNonAsset {
		remoteDescriptors = append(
			remoteDescriptors,
			lnwallet.AuxHtlcDescriptor{
				ChanID:        lnwire.ChannelID{},
				RHash:         lnwallet.PaymentHash{},
				Timeout:       100,
				Amount:        lnwire.MilliSatoshi(10000000),
				HtlcIndex:     999,
				ParentIndex:   0,
				CustomRecords: nil, // No assets
			},
		)
	}

	return lnwallet.AuxHtlcView{
		NextHeight: cfg.nextHeight,
		FeePerKw:   1000,
		Updates: lntypes.Dual[[]lnwallet.AuxHtlcDescriptor]{
			Local:  localDescriptors,
			Remote: remoteDescriptors,
		},
	}
}

// TestComputeView runs table-driven tests for the ComputeView function.
func TestComputeView(t *testing.T) {
	t.Parallel()

	testCases := []testCase{
		{
			name:         "empty view",
			ourBalance:   100000,
			theirBalance: 50000,
			whoseCommit:  lntypes.Local,
			viewConfig: viewConfig{
				nextHeight: 1,
			},
			expectError:           false,
			expectedOurBalance:    100000,
			expectedTheirBalance:  50000,
			expectedOurUpdates:    0,
			expectedTheirUpdates:  0,
			expectedNonAssetOur:   0,
			expectedNonAssetTheir: 0,
		},
		{
			name:         "non-asset HTLC",
			ourBalance:   100000,
			theirBalance: 50000,
			whoseCommit:  lntypes.Local,
			viewConfig: viewConfig{
				nextHeight:    1,
				localNonAsset: true,
			},
			expectError:           false,
			expectedOurBalance:    100000,
			expectedTheirBalance:  50000,
			expectedOurUpdates:    0,
			expectedTheirUpdates:  0,
			expectedNonAssetOur:   1,
			expectedNonAssetTheir: 0,
		},
		{
			name:         "htlc at old height",
			ourBalance:   100000,
			theirBalance: 50000,
			whoseCommit:  lntypes.Local,
			viewConfig: viewConfig{
				nextHeight: 3,
				localHtlcs: []assetHtlc{
					{
						amount:         10000,
						htlcIndex:      0,
						parentIndex:    0,
						entryType:      htlcNoOpAdd,
						addHeightLocal: 2,
					},
				},
			},
			expectError:           false,
			expectedOurBalance:    100000,
			expectedTheirBalance:  50000,
			expectedOurUpdates:    1,
			expectedTheirUpdates:  0,
			expectedNonAssetOur:   0,
			expectedNonAssetTheir: 0,
			validate: func(t *testing.T, ourResult,
				theirResult uint64, filteredView,
				nonAssetView *DecodedView) {

				require.Len(t, filteredView.OurUpdates, 1)
				decoded := filteredView.OurUpdates[0]
				require.Equal(t, uint64(10000),
					rfqmsg.Sum(decoded.AssetBalances),
					"asset balance should be decoded "+
						"correctly")
			},
		},
		{
			name:         "multiple heights, filter by nextHeight",
			ourBalance:   20000,
			theirBalance: 50000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 52,
				localHtlcs: []assetHtlc{
					{
						amount:          7812,
						htlcIndex:       41,
						entryType:       htlcNoOpAdd,
						addHeightLocal:  49,
						addHeightRemote: 49,
					},
					{
						amount:          7812,
						htlcIndex:       45,
						entryType:       htlcNoOpAdd,
						addHeightLocal:  50,
						addHeightRemote: 50,
					},
					{
						amount:          7812,
						htlcIndex:       47,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 51,
					},
					// Being committed NOW
					{
						amount:          7812,
						htlcIndex:       52,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 52,
					},
					// Being committed NOW
					{
						amount:          7812,
						htlcIndex:       53,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 52,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   20000 - (7812 * 2),
			expectedTheirBalance: 50000,
			expectedOurUpdates:   5,
			expectedTheirUpdates: 0,
		},
		{
			name:         "1 add, 1 settle",
			ourBalance:   100000,
			theirBalance: 50000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 51,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          10000,
						htlcIndex:       42,
						parentIndex:     0,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 51,
					},
				},
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:             10000,
						htlcIndex:          43,
						parentIndex:        42,
						entryType:          htlcSettle,
						removeHeightRemote: 51,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000,
			expectedTheirBalance: 50000 + 10000,
			expectedOurUpdates:   0,
			expectedTheirUpdates: 0,
		},
		{
			name:         "2 local adds, 2 remote adds",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:          3000,
						htlcIndex:       11,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          7000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:          2000,
						htlcIndex:       21,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 - 8000,
			expectedTheirBalance: 100000 - 9000,
			expectedOurUpdates:   2,
			expectedTheirUpdates: 2,
		},
		{
			name:         "1 old add, 1 new add, 1 settle",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 49,
					},
					// Being committed NOW
					{
						amount:          3000,
						htlcIndex:       11,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:             5000,
						htlcIndex:          30,
						parentIndex:        10,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 - 3000,
			expectedTheirBalance: 100000 + 5000,
			expectedOurUpdates:   1,
			expectedTheirUpdates: 0,
		},
		{
			name:         "remote: 1 old add, 1 new add, 1 settle",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				remoteHtlcs: []assetHtlc{
					{
						amount:          8000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 49,
					},
					// Being committed NOW
					{
						amount:          4000,
						htlcIndex:       21,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:             8000,
						htlcIndex:          40,
						parentIndex:        20,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 + 8000,
			expectedTheirBalance: 100000 - 4000,
			expectedOurUpdates:   0,
			expectedTheirUpdates: 1,
		},
		{
			name:         "2 adds, 2 settles",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:          3000,
						htlcIndex:       11,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:             7000,
						htlcIndex:          12,
						parentIndex:        20,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
				remoteHtlcs: []assetHtlc{
					{
						amount:          7000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 49,
					},
					// Being committed NOW
					{
						amount:          2000,
						htlcIndex:       21,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:             3000,
						htlcIndex:          22,
						parentIndex:        11,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 - 5000 + 7000,
			expectedTheirBalance: 100000 - 2000 + 3000,
			expectedOurUpdates:   1,
			expectedTheirUpdates: 1,
		},
		{
			name:         "1 add, 1 settle",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          10000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:             10000,
						htlcIndex:          20,
						parentIndex:        10,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000,
			expectedTheirBalance: 100000 + 10000,
			expectedOurUpdates:   0,
			expectedTheirUpdates: 0,
		},
		{
			name:         "2 adds, 2 fails",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:             8000,
						htlcIndex:          11,
						parentIndex:        20,
						entryType:          htlcFail,
						removeHeightRemote: 50,
					},
				},
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          8000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:             5000,
						htlcIndex:          21,
						parentIndex:        10,
						entryType:          htlcFail,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 + 5000,
			expectedTheirBalance: 100000 + 8000,
			expectedOurUpdates:   0,
			expectedTheirUpdates: 0,
		},
		{
			name:         "settle wrong location (error)",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
					{
						amount:             5000,
						htlcIndex:          11,
						parentIndex:        10,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError: true,
		},
		{
			name:         "remote add, local settle",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 50,
				remoteHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:          5000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 50,
					},
				},
				localHtlcs: []assetHtlc{
					// Being committed NOW
					{
						amount:             5000,
						htlcIndex:          10,
						parentIndex:        20,
						entryType:          htlcSettle,
						removeHeightRemote: 50,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 + 5000,
			expectedTheirBalance: 100000,
			expectedOurUpdates:   0,
			expectedTheirUpdates: 0,
		},
		{
			name:         "uncommitted entries with nextHeight=0",
			ourBalance:   100000,
			theirBalance: 100000,
			whoseCommit:  lntypes.Remote,
			viewConfig: viewConfig{
				nextHeight: 0,
				localHtlcs: []assetHtlc{
					{
						amount:          5000,
						htlcIndex:       10,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 49,
					},
					// Being committed NOW
					{
						amount:    3000,
						htlcIndex: 11,
						entryType: htlcNoOpAdd,
					},
					{
						amount:          2000,
						htlcIndex:       12,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 48,
					},
					// Being committed NOW
					{
						amount:             7000,
						htlcIndex:          30,
						parentIndex:        20,
						entryType:          htlcFail,
						removeHeightRemote: 0,
					},
				},
				remoteHtlcs: []assetHtlc{
					{
						amount:          7000,
						htlcIndex:       20,
						entryType:       htlcNoOpAdd,
						addHeightRemote: 48,
					},
					{
						amount:             5000,
						htlcIndex:          22,
						parentIndex:        10,
						entryType:          htlcSettle,
						removeHeightRemote: 47,
					},
					// Being committed NOW
					{
						amount:    4000,
						htlcIndex: 21,
						entryType: htlcNoOpAdd,
					},
					// Being committed NOW
					{
						amount:      2000,
						htlcIndex:   23,
						parentIndex: 12,
						entryType:   htlcSettle,
					},
				},
			},
			expectError:          false,
			expectedOurBalance:   100000 - 3000,
			expectedTheirBalance: 100000 - 4000 + 2000 + 7000,
			expectedOurUpdates:   1,
			expectedTheirUpdates: 1,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			view := createView(t, tc.viewConfig)

			ourBal, theirBal, filtered, btcView, err := ComputeView(
				tc.ourBalance, tc.theirBalance, tc.whoseCommit,
				view,
			)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(
				t, tc.expectedOurBalance, ourBal,
				"our balance mismatch",
			)
			require.Equal(
				t, tc.expectedTheirBalance, theirBal,
				"their balance mismatch",
			)
			require.Len(
				t, filtered.OurUpdates, tc.expectedOurUpdates,
				"our filtered updates count mismatch",
			)
			require.Len(
				t, filtered.TheirUpdates,
				tc.expectedTheirUpdates,
				"their filtered updates count mismatch",
			)
			require.Len(
				t, btcView.OurUpdates, tc.expectedNonAssetOur,
				"our non-asset updates count mismatch",
			)
			require.Len(
				t, btcView.TheirUpdates,
				tc.expectedNonAssetTheir,
				"their non-asset updates count mismatch",
			)

			if tc.validate != nil {
				tc.validate(
					t, ourBal, theirBal, filtered, btcView,
				)
			}
		})
	}
}
