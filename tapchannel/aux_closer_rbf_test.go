package tapchannel

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/types"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestSettledBtcAmount asserts that the commitment fee is credited to the
// channel initiator, and that the close fee is charged to the party that
// pays it: the initiator unless the close description says otherwise.
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
		feePayer   lfn.Option[lntypes.ChannelParty]
		wantLocal  btcutil.Amount
		wantRemote btcutil.Amount
	}{
		{
			name:       "legacy, we are initiator",
			initiator:  true,
			feePayer:   lfn.None[lntypes.ChannelParty](),
			wantLocal:  amt + commitFee - closeFee,
			wantRemote: amt,
		},
		{
			name:       "legacy, they are initiator",
			initiator:  false,
			feePayer:   lfn.None[lntypes.ChannelParty](),
			wantLocal:  amt,
			wantRemote: amt + commitFee - closeFee,
		},
		{
			name:       "rbf, we are initiator and closer",
			initiator:  true,
			feePayer:   lfn.Some(lntypes.Local),
			wantLocal:  amt + commitFee - closeFee,
			wantRemote: amt,
		},
		{
			name:       "rbf, we are initiator, they close",
			initiator:  true,
			feePayer:   lfn.Some(lntypes.Remote),
			wantLocal:  amt + commitFee,
			wantRemote: amt - closeFee,
		},
		{
			name:       "rbf, they are initiator, we close",
			initiator:  false,
			feePayer:   lfn.Some(lntypes.Local),
			wantLocal:  amt - closeFee,
			wantRemote: amt + commitFee,
		},
		{
			name:       "rbf, they are initiator and closer",
			initiator:  false,
			feePayer:   lfn.Some(lntypes.Remote),
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
				FeePayer:  tc.feePayer,
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

// newCloseCandidate returns a close info for the given fee with the given
// asset outputs.
func newCloseCandidate(closeFee int64,
	outputs ...closeAssetOutput) *assetCloseInfo {

	return &assetCloseInfo{
		closeFee:     closeFee,
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

// TestMatchCloseCandidate asserts that the close candidate that produced a
// confirmed close transaction is found by its asset outputs.
func TestMatchCloseCandidate(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)
	scriptC := test.RandBytes(34)

	// Two RBF rounds produced different output orders.
	round1 := newCloseCandidate(
		100,
		closeAssetOutput{outputIndex: 0, pkScript: scriptA},
		closeAssetOutput{outputIndex: 2, pkScript: scriptB},
	)
	round2 := newCloseCandidate(
		200,
		closeAssetOutput{outputIndex: 1, pkScript: scriptA},
		closeAssetOutput{outputIndex: 2, pkScript: scriptB},
	)
	candidates := []*assetCloseInfo{round1, round2}

	// The transaction of the first round confirmed.
	match, ok := matchCloseCandidate(
		newCloseTx(scriptA, scriptC, scriptB), candidates,
	)
	require.True(t, ok)
	require.Same(t, round1, match)

	// The transaction of the second round confirmed.
	match, ok = matchCloseCandidate(
		newCloseTx(scriptC, scriptA, scriptB), candidates,
	)
	require.True(t, ok)
	require.Same(t, round2, match)

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

	// A single candidate without asset outputs (written before RBF
	// closes were supported) is used as is.
	legacy := newCloseCandidate(100)
	match, ok = matchCloseCandidate(
		newCloseTx(scriptC), []*assetCloseInfo{legacy},
	)
	require.True(t, ok)
	require.Same(t, legacy, match)

	// But not if there are other candidates.
	_, ok = matchCloseCandidate(
		newCloseTx(scriptC), []*assetCloseInfo{legacy, round1},
	)
	require.False(t, ok)
}

// TestAddCloseCandidate asserts that close candidates are collected per
// round, that a repeated round replaces its earlier entry, and that the
// oldest candidates are dropped beyond the cap.
func TestAddCloseCandidate(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)

	round1 := newCloseCandidate(
		100, closeAssetOutput{outputIndex: 0, pkScript: scriptA},
	)
	round2 := newCloseCandidate(
		200, closeAssetOutput{outputIndex: 1, pkScript: scriptA},
	)

	candidates := addCloseCandidate(nil, round1)
	candidates = addCloseCandidate(candidates, round2)
	require.Equal(t, []*assetCloseInfo{round1, round2}, candidates)

	// The same round again (same fee, same outputs) replaces the entry
	// rather than adding a duplicate.
	round1Again := newCloseCandidate(
		100, closeAssetOutput{outputIndex: 0, pkScript: scriptA},
	)
	candidates = addCloseCandidate(candidates, round1Again)
	require.Len(t, candidates, 2)
	require.Same(t, round1Again, candidates[0])
	require.Same(t, round2, candidates[1])

	// The same fee with different outputs is a new candidate.
	round3 := newCloseCandidate(
		100, closeAssetOutput{outputIndex: 0, pkScript: scriptB},
	)
	candidates = addCloseCandidate(candidates, round3)
	require.Len(t, candidates, 3)

	// Beyond the cap, the oldest candidates are dropped.
	for i := 0; i < maxCloseCandidates; i++ {
		candidates = addCloseCandidate(
			candidates, newCloseCandidate(
				int64(1000+i), closeAssetOutput{
					outputIndex: 0,
					pkScript:    test.RandBytes(34),
				},
			),
		)
	}
	require.Len(t, candidates, maxCloseCandidates)
	require.EqualValues(t, 1000, candidates[0].closeFee)
	require.EqualValues(
		t, 1000+maxCloseCandidates-1,
		candidates[maxCloseCandidates-1].closeFee,
	)
}

// TestValidateShutdownBtcKey asserts that a close output's delivery script
// must be the P2TR script of the BTC internal key sent in the shutdown
// records.
func TestValidateShutdownBtcKey(t *testing.T) {
	t.Parallel()

	internalKey := test.RandPubKey(t)
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	pkScript, err := txscript.PayToTaprootScript(taprootKey)
	require.NoError(t, err)

	shutdownMsg := tapchannelmsg.NewAuxShutdownMsg(
		internalKey, test.RandPubKey(t), nil, nil,
	)

	// The matching script passes.
	require.NoError(t, validateShutdownBtcKey(pkScript, *shutdownMsg))

	// A script for another key fails.
	otherKey := txscript.ComputeTaprootKeyNoScript(test.RandPubKey(t))
	otherScript, err := txscript.PayToTaprootScript(otherKey)
	require.NoError(t, err)
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
