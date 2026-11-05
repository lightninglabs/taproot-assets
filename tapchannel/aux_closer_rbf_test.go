package tapchannel

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwallet/types"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestSettledBtcAmount asserts that with the legacy close flow the
// commitment fee is credited to the channel initiator, and that the close
// fee is charged to it.
func TestSettledBtcAmount(t *testing.T) {
	t.Parallel()

	const (
		amt       btcutil.Amount = 100_000
		commitFee btcutil.Amount = 1_000
		closeFee  btcutil.Amount = 300
	)

	tests := []struct {
		name       string
		initiator  bool
		wantLocal  btcutil.Amount
		wantRemote btcutil.Amount
	}{
		{
			name:       "we are initiator",
			initiator:  true,
			wantLocal:  amt + commitFee - closeFee,
			wantRemote: amt,
		},
		{
			name:       "they are initiator",
			initiator:  false,
			wantLocal:  amt,
			wantRemote: amt + commitFee - closeFee,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			desc := types.AuxCloseDesc{
				AuxShutdownReq: types.AuxShutdownReq{
					Initiator: tc.initiator,
				},
				CloseFee:  closeFee,
				CommitFee: commitFee,
			}

			require.Equal(
				t, tc.wantLocal,
				settledBtcAmount(desc, true, amt),
			)
			require.Equal(
				t, tc.wantRemote,
				settledBtcAmount(desc, false, amt),
			)
		})
	}
}

// newCloseCandidate returns a close info with the given asset outputs.
func newCloseCandidate(outputs ...closeAssetOutput) *assetCloseInfo {
	return &assetCloseInfo{
		assetOutputs: outputs,
	}
}

// newCloseTx returns a close transaction with the given output scripts.
func newCloseTx(pkScripts ...[]byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for _, pkScript := range pkScripts {
		tx.AddTxOut(&wire.TxOut{PkScript: pkScript, Value: 1000})
	}

	return tx
}

// bip86Script returns the BIP 86 P2TR script of the given internal key.
func bip86Script(t *testing.T, internalKey *btcec.PublicKey) []byte {
	t.Helper()

	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	pkScript, err := txscript.PayToTaprootScript(taprootKey)
	require.NoError(t, err)

	return pkScript
}

// TestMatchCloseCandidate asserts that the close candidate that produced a
// confirmed close transaction is found by its asset outputs.
func TestMatchCloseCandidate(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)
	scriptC := test.RandBytes(34)

	// Two shutdown exchanges produced different output orders.
	first := newCloseCandidate(
		closeAssetOutput{outputIndex: 0, pkScript: scriptA},
		closeAssetOutput{outputIndex: 2, pkScript: scriptB},
	)
	second := newCloseCandidate(
		closeAssetOutput{outputIndex: 1, pkScript: scriptA},
		closeAssetOutput{outputIndex: 2, pkScript: scriptB},
	)
	candidates := []*assetCloseInfo{first, second}

	// The transaction of the first candidate confirmed.
	match, ok := matchCloseCandidate(
		newCloseTx(scriptA, scriptC, scriptB), candidates,
	)
	require.True(t, ok)
	require.Same(t, first, match)

	// The transaction of the second candidate confirmed.
	match, ok = matchCloseCandidate(
		newCloseTx(scriptC, scriptA, scriptB), candidates,
	)
	require.True(t, ok)
	require.Same(t, second, match)

	// A transaction that carries only some of the outputs, or has them
	// at other indexes, doesn't match.
	_, ok = matchCloseCandidate(newCloseTx(scriptA, scriptC), candidates)
	require.False(t, ok)
	_, ok = matchCloseCandidate(
		newCloseTx(scriptB, scriptC, scriptA), candidates,
	)
	require.False(t, ok)

	// Without candidates nothing matches.
	_, ok = matchCloseCandidate(newCloseTx(scriptA, scriptB), nil)
	require.False(t, ok)

	// A single candidate without asset outputs (written before the asset
	// outputs were recorded) is used as is.
	legacy := newCloseCandidate()
	match, ok = matchCloseCandidate(
		newCloseTx(scriptC), []*assetCloseInfo{legacy},
	)
	require.True(t, ok)
	require.Same(t, legacy, match)

	// But not if there are other candidates.
	_, ok = matchCloseCandidate(
		newCloseTx(scriptC), []*assetCloseInfo{legacy, first},
	)
	require.False(t, ok)
}

// TestAddCloseCandidate asserts that close candidates are collected per set
// of asset outputs, that the same asset outputs replace their earlier entry,
// and that the oldest candidates are dropped beyond the cap.
func TestAddCloseCandidate(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)

	first := newCloseCandidate(
		closeAssetOutput{outputIndex: 0, pkScript: scriptA},
	)
	second := newCloseCandidate(
		closeAssetOutput{outputIndex: 1, pkScript: scriptA},
	)

	candidates := addCloseCandidate(nil, first)
	candidates = addCloseCandidate(candidates, second)
	require.Equal(t, []*assetCloseInfo{first, second}, candidates)

	// The same asset outputs again replace the entry rather than adding
	// a duplicate, whatever fee the candidate records.
	firstAgain := newCloseCandidate(
		closeAssetOutput{outputIndex: 0, pkScript: scriptA},
	)
	firstAgain.closeFee = 100
	candidates = addCloseCandidate(candidates, firstAgain)
	require.Len(t, candidates, 2)
	require.Same(t, firstAgain, candidates[0])
	require.Same(t, second, candidates[1])

	// Other asset outputs are a new candidate.
	third := newCloseCandidate(
		closeAssetOutput{outputIndex: 0, pkScript: scriptB},
	)
	candidates = addCloseCandidate(candidates, third)
	require.Len(t, candidates, 3)

	// Beyond the cap, the oldest candidates are dropped.
	for i := 0; i < maxCloseCandidates; i++ {
		candidate := newCloseCandidate(closeAssetOutput{
			outputIndex: 0,
			pkScript:    test.RandBytes(34),
		})
		candidate.closeFee = int64(1000 + i)
		candidates = addCloseCandidate(candidates, candidate)
	}
	require.Len(t, candidates, maxCloseCandidates)
	require.EqualValues(t, 1000, candidates[0].closeFee)
	require.EqualValues(
		t, 1000+maxCloseCandidates-1,
		candidates[maxCloseCandidates-1].closeFee,
	)
}

// TestSortCloseAllocsByKey asserts that the close allocations of the RBF
// close flow are ordered by their kind and key alone, whatever their BTC
// amounts.
func TestSortCloseAllocsByKey(t *testing.T) {
	t.Parallel()

	localAssets := &tapsend.Allocation{
		Type:                tapsend.CommitAllocationToLocal,
		BtcAmount:           1000,
		SortTaprootKeyBytes: []byte{0x02, 0x09},
	}
	remoteAssets := &tapsend.Allocation{
		Type:                tapsend.CommitAllocationToRemote,
		BtcAmount:           1000,
		SortTaprootKeyBytes: []byte{0x02, 0x01},
	}
	localBtc := &tapsend.Allocation{
		Type:                tapsend.AllocationTypeNoAssets,
		BtcAmount:           500,
		SortTaprootKeyBytes: []byte{0x05},
	}
	remoteBtc := &tapsend.Allocation{
		Type:                tapsend.AllocationTypeNoAssets,
		BtcAmount:           90_000,
		SortTaprootKeyBytes: []byte{0x03},
	}

	allocs := []*tapsend.Allocation{
		localBtc, localAssets, remoteBtc, remoteAssets,
	}
	sortCloseAllocsByKey(allocs)
	require.Equal(t, []*tapsend.Allocation{
		remoteAssets, localAssets, remoteBtc, localBtc,
	}, allocs)

	// The amounts don't matter.
	localBtc.BtcAmount, remoteBtc.BtcAmount = 1, 2
	localAssets.BtcAmount = 1_000_000
	sortCloseAllocsByKey(allocs)
	require.Equal(t, []*tapsend.Allocation{
		remoteAssets, localAssets, remoteBtc, localBtc,
	}, allocs)
}

// TestCloseOutputSort asserts that the close transactions of the RBF close
// flow are sorted by script alone: the asset outputs first in the order
// they were signed for, then the BTC outputs by script.
func TestCloseOutputSort(t *testing.T) {
	t.Parallel()

	assetA := append([]byte{0x51, 0x20, 0x0a}, test.RandBytes(31)...)
	assetB := append([]byte{0x51, 0x20, 0x0b}, test.RandBytes(31)...)
	btcA := append([]byte{0x51, 0x20, 0x01}, test.RandBytes(31)...)
	btcB := append([]byte{0x51, 0x20, 0x02}, test.RandBytes(31)...)

	// The asset outputs were signed for indexes 0 and 1, B before A.
	sortFunc := closeOutputSort([][]byte{assetB, assetA})

	newOut := func(pkScript []byte, value int64) *wire.TxOut {
		return &wire.TxOut{PkScript: pkScript, Value: value}
	}
	scripts := func(tx *wire.MsgTx) [][]byte {
		var scripts [][]byte
		for _, txOut := range tx.TxOut {
			scripts = append(scripts, txOut.PkScript)
		}

		return scripts
	}

	// Whatever the values, the order is the same.
	for _, values := range [][]int64{
		{1000, 1000, 50_000, 40_000},
		{1000, 1000, 400, 40_000},
		{1000, 1000, 50_000, 400},
	} {
		tx := wire.NewMsgTx(2)
		tx.AddTxOut(newOut(btcB, values[3]))
		tx.AddTxOut(newOut(assetA, values[0]))
		tx.AddTxOut(newOut(btcA, values[2]))
		tx.AddTxOut(newOut(assetB, values[1]))

		require.NoError(t, sortFunc(tx))
		require.Equal(
			t, [][]byte{assetB, assetA, btcA, btcB}, scripts(tx),
		)
	}

	// A BTC output that was merged into an asset output is sorted by the
	// asset script it then carries.
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(newOut(btcB, 40_000))
	tx.AddTxOut(newOut(assetA, 1000))
	tx.AddTxOut(newOut(assetB, 1354))

	require.NoError(t, sortFunc(tx))
	require.Equal(t, [][]byte{assetB, assetA, btcB}, scripts(tx))
}

// TestBtcCloseAllocations asserts that the BTC allocations the exclusion
// proofs of a close are built from follow the confirmed close transaction.
func TestBtcCloseAllocations(t *testing.T) {
	t.Parallel()

	localKey := test.RandPubKey(t)
	remoteKey := test.RandPubKey(t)
	localScript := bip86Script(t, localKey)
	remoteScript := bip86Script(t, remoteKey)
	assetScript := test.RandBytes(34)

	// The close info was created with the BTC outputs at indexes 1 and
	// 2.
	closeInfo := &assetCloseInfo{
		allocations: []*tapsend.Allocation{
			{
				Type:        tapsend.CommitAllocationToLocal,
				OutputIndex: 0,
			},
			{
				Type:        tapsend.AllocationTypeNoAssets,
				OutputIndex: 1,
				InternalKey: localKey,
			},
			{
				Type:        tapsend.AllocationTypeNoAssets,
				OutputIndex: 2,
				InternalKey: remoteKey,
			},
		},
		assetOutputs: []closeAssetOutput{{
			outputIndex: 0,
			pkScript:    assetScript,
		}},
	}

	// The confirmed transaction has them the other way around.
	allocs, err := btcCloseAllocations(
		newCloseTx(assetScript, remoteScript, localScript), closeInfo,
	)
	require.NoError(t, err)
	require.Len(t, allocs, 2)
	require.EqualValues(t, 1, allocs[0].OutputIndex)
	require.Equal(t, remoteKey, allocs[0].InternalKey)
	require.EqualValues(t, 2, allocs[1].OutputIndex)
	require.Equal(t, localKey, allocs[1].InternalKey)
	require.EqualValues(t, 1000, allocs[1].BtcAmount)

	// The local BTC output was merged into the asset output.
	allocs, err = btcCloseAllocations(
		newCloseTx(assetScript, remoteScript), closeInfo,
	)
	require.NoError(t, err)
	require.Len(t, allocs, 1)
	require.EqualValues(t, 1, allocs[0].OutputIndex)
	require.Equal(t, remoteKey, allocs[0].InternalKey)

	// An output that pays to neither party is unknown to the close.
	_, err = btcCloseAllocations(
		newCloseTx(assetScript, remoteScript, test.RandBytes(34)),
		closeInfo,
	)
	require.ErrorContains(t, err, "unknown script")

	// A close info that predates the asset output record keeps its
	// allocations as they are.
	legacy := &assetCloseInfo{
		allocations: closeInfo.allocations,
	}
	allocs, err = btcCloseAllocations(
		newCloseTx(assetScript, remoteScript), legacy,
	)
	require.NoError(t, err)
	require.Equal(t, closeInfo.allocations, allocs)
}

// TestValidateShutdownBtcKey asserts that a close output's delivery script
// must be the P2TR script of the BTC internal key sent in the shutdown
// records.
func TestValidateShutdownBtcKey(t *testing.T) {
	t.Parallel()

	internalKey := test.RandPubKey(t)
	pkScript := bip86Script(t, internalKey)

	shutdownMsg := tapchannelmsg.NewAuxShutdownMsg(
		internalKey, test.RandPubKey(t), nil, nil,
	)

	// The matching script passes.
	require.NoError(t, validateShutdownBtcKey(pkScript, *shutdownMsg))

	// A script for another key fails.
	otherScript := bip86Script(t, test.RandPubKey(t))
	require.ErrorContains(
		t, validateShutdownBtcKey(otherScript, *shutdownMsg),
		"doesn't match BTC internal key",
	)

	// A non P2TR script fails.
	p2wpkh := append([]byte{0x00, 0x14}, bytes.Repeat([]byte{1}, 20)...)
	require.ErrorContains(
		t, validateShutdownBtcKey(p2wpkh, *shutdownMsg), "not P2TR",
	)

	// Shutdown records without a BTC internal key fail.
	var noKey tapchannelmsg.AuxShutdownMsg
	require.ErrorContains(
		t, validateShutdownBtcKey(pkScript, noKey),
		"no BTC internal key",
	)
}

// TestSupportsRbfClose asserts that the RBF close flow is only reported as
// supported for peers that signalled the feature.
func TestSupportsRbfClose(t *testing.T) {
	t.Parallel()

	negotiator := tapfeatures.NewAuxChannelNegotiator()
	closer := NewAuxChanCloser(AuxChanCloserCfg{
		AuxChanNegotiator: negotiator,
	})

	peer := route.Vertex{1, 2, 3}
	chanID := lnwire.ChannelID{4, 5, 6}

	// Unknown peers don't support it.
	require.False(t, closer.SupportsRbfClose(chanID, peer))

	// A peer with features, but without the RBF close bit, doesn't
	// support it either.
	records := auxInitRecords(t, lnwire.NewRawFeatureVector(
		tapfeatures.STXOOptional,
	))
	require.NoError(t, negotiator.ProcessInitRecords(peer, records))
	require.False(t, closer.SupportsRbfClose(chanID, peer))

	// Once the bit is signalled, it does.
	records = auxInitRecords(t, lnwire.NewRawFeatureVector(
		tapfeatures.STXOOptional, tapfeatures.RbfCoopCloseOptional,
	))
	require.NoError(t, negotiator.ProcessInitRecords(peer, records))
	require.True(t, closer.SupportsRbfClose(chanID, peer))

	// Another peer is unaffected.
	require.False(t, closer.SupportsRbfClose(chanID, route.Vertex{7}))
}

// auxInitRecords encodes the given feature vector the way a peer's init
// message carries it.
func auxInitRecords(t *testing.T,
	features *lnwire.RawFeatureVector) lnwire.CustomRecords {

	var buf bytes.Buffer
	require.NoError(t, features.Encode(&buf))

	tlvMap := make(tlv.TypeMap, 1)
	tlvMap[tapfeatures.AuxFeatureBitsTLV] = buf.Bytes()

	records, err := lnwire.NewCustomRecords(tlvMap)
	require.NoError(t, err)

	return records
}
