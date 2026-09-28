package tapchannel

import (
	"bytes"
	"context"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
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

// newCloseInfo returns a close info with the given asset outputs.
func newCloseInfo(outputs ...closeAssetOutput) *assetCloseInfo {
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

// TestCloseInfoMatchesCloseTx asserts that a close info only matches a close
// transaction that carries its asset outputs at their indexes.
func TestCloseInfoMatchesCloseTx(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)
	scriptC := test.RandBytes(34)

	closeInfo := newCloseInfo(
		closeAssetOutput{outputIndex: 0, pkScript: scriptA},
		closeAssetOutput{outputIndex: 2, pkScript: scriptB},
	)

	// The transaction the info was built for matches, whatever the other
	// outputs are.
	require.True(t, closeInfo.matchesCloseTx(
		newCloseTx(scriptA, scriptC, scriptB),
	))
	require.True(t, closeInfo.matchesCloseTx(
		newCloseTx(scriptA, test.RandBytes(34), scriptB, scriptC),
	))

	// A transaction that carries only some of the outputs, or has them
	// at other indexes, doesn't match.
	require.False(t, closeInfo.matchesCloseTx(newCloseTx(scriptA, scriptC)))
	require.False(t, closeInfo.matchesCloseTx(
		newCloseTx(scriptC, scriptA, scriptB),
	))
	require.False(t, closeInfo.matchesCloseTx(newCloseTx(scriptA)))

	// A close info without asset outputs can't match anything.
	require.False(t, newCloseInfo().matchesCloseTx(newCloseTx(scriptA)))
}

// TestAuxCloseOutputsFromInfo asserts that the close outputs lnd gets are
// rebuilt from the asset outputs of the close info, along with its sort.
func TestAuxCloseOutputsFromInfo(t *testing.T) {
	t.Parallel()

	scriptA := test.RandBytes(34)
	scriptB := test.RandBytes(34)

	closeInfo := newCloseInfo(
		closeAssetOutput{
			outputIndex: 0,
			pkScript:    scriptA,
			value:       1000,
			isLocal:     true,
		},
		closeAssetOutput{
			outputIndex: 1,
			pkScript:    scriptB,
			value:       1000,
			isLocal:     false,
		},
	)
	closeInfo.sortFunc = closeOutputSort(closeInfo.assetScripts())

	outputs := closeInfo.auxCloseOutputs()
	require.Equal(t, []lnwallet.CloseOutput{
		{
			TxOut:   wire.TxOut{PkScript: scriptA, Value: 1000},
			IsLocal: true,
		},
		{
			TxOut:   wire.TxOut{PkScript: scriptB, Value: 1000},
			IsLocal: false,
		},
	}, outputs.ExtraCloseOutputs)
	require.NotNil(t, outputs.CustomSort)

	// The sort puts the asset outputs first, in their order.
	tx := newCloseTx(test.RandBytes(34), scriptB, scriptA)
	require.NoError(t, outputs.CustomSort(tx))
	require.Equal(t, scriptA, tx.TxOut[0].PkScript)
	require.Equal(t, scriptB, tx.TxOut[1].PkScript)
}

// randTemplateDesc returns a close template description with random
// content.
func randTemplateDesc(t *testing.T) types.AuxCloseTemplateDesc {
	t.Helper()

	return types.AuxCloseTemplateDesc{
		AuxShutdownReq: types.AuxShutdownReq{
			ChanPoint:   test.RandOp(t),
			Initiator:   true,
			CommitBlob:  lfn.Some[tlv.Blob](test.RandBytes(64)),
			FundingBlob: lfn.Some[tlv.Blob](test.RandBytes(64)),
		},
		LocalDeliveryScript:   test.RandBytes(34),
		LocalShutdownRecords:  lnwire.CustomRecords{65536: {1}},
		RemoteDeliveryScript:  test.RandBytes(34),
		RemoteShutdownRecords: lnwire.CustomRecords{65536: {2}},
	}
}

// TestNewCloseTemplateID asserts that the close template ID is derived from
// everything the asset outputs of the close depend on, and from nothing
// else.
func TestNewCloseTemplateID(t *testing.T) {
	t.Parallel()

	desc := randTemplateDesc(t)

	id, err := newCloseTemplateID(desc)
	require.NoError(t, err)
	require.False(t, id.IsZero())

	// The same description, requested again, gives the same ID. The
	// channel point and the short channel ID play no part.
	again := desc
	again.ChanPoint = test.RandOp(t)
	again.ShortChanID = lnwire.NewShortChanIDFromInt(123)
	again.InternalKey = lfn.Some(*test.RandPubKey(t))
	againID, err := newCloseTemplateID(again)
	require.NoError(t, err)
	require.Equal(t, id, againID)

	// Any of the terms the asset outputs depend on changes the ID.
	changes := map[string]func(d *types.AuxCloseTemplateDesc){
		"initiator": func(d *types.AuxCloseTemplateDesc) {
			d.Initiator = false
		},
		"commit blob": func(d *types.AuxCloseTemplateDesc) {
			d.CommitBlob = lfn.Some[tlv.Blob](test.RandBytes(64))
		},
		"funding blob": func(d *types.AuxCloseTemplateDesc) {
			d.FundingBlob = lfn.Some[tlv.Blob](test.RandBytes(64))
		},
		"local script": func(d *types.AuxCloseTemplateDesc) {
			d.LocalDeliveryScript = test.RandBytes(34)
		},
		"local records": func(d *types.AuxCloseTemplateDesc) {
			d.LocalShutdownRecords = lnwire.CustomRecords{
				65536: {3},
			}
		},
		"remote script": func(d *types.AuxCloseTemplateDesc) {
			d.RemoteDeliveryScript = test.RandBytes(34)
		},
		"remote records": func(d *types.AuxCloseTemplateDesc) {
			d.RemoteShutdownRecords = lnwire.CustomRecords{
				65536: {3},
			}
		},
		"records swapped": func(d *types.AuxCloseTemplateDesc) {
			d.LocalShutdownRecords, d.RemoteShutdownRecords =
				d.RemoteShutdownRecords, d.LocalShutdownRecords
		},
	}
	for name, change := range changes {
		changed := desc
		change(&changed)

		changedID, err := newCloseTemplateID(changed)
		require.NoError(t, err, name)
		require.NotEqual(t, id, changedID, name)
	}
}

// TestExistingCloseTemplate asserts how an existing close info of a channel
// is treated when its close template is requested.
func TestExistingCloseTemplate(t *testing.T) {
	t.Parallel()

	templateID := closeTemplateID{1}
	otherID := closeTemplateID{2}

	// Without a close info, a template needs to be built.
	info, err := existingCloseTemplate(nil, templateID)
	require.NoError(t, err)
	require.Nil(t, info)

	// A close info of a legacy negotiation is replaced.
	legacy := newCloseInfo()
	info, err = existingCloseTemplate(legacy, templateID)
	require.NoError(t, err)
	require.Nil(t, info)

	// The template itself is reused.
	template := newCloseInfo()
	template.templateID = templateID
	info, err = existingCloseTemplate(template, templateID)
	require.NoError(t, err)
	require.Same(t, template, info)

	// Another template is refused.
	_, err = existingCloseTemplate(template, otherID)
	require.ErrorIs(t, err, ErrCloseTemplateChanged)
}

// closeTestKeyRing hands out random keys.
type closeTestKeyRing struct {
	t *testing.T
}

func (k *closeTestKeyRing) DeriveNextTaprootAssetKey(
	context.Context) (keychain.KeyDescriptor, error) {

	desc, _ := test.RandKeyDesc(k.t)
	return desc, nil
}

func (k *closeTestKeyRing) DeriveNextKey(context.Context,
	keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	desc, _ := test.RandKeyDesc(k.t)
	return desc, nil
}

func (k *closeTestKeyRing) IsLocalKey(context.Context,
	keychain.KeyDescriptor) bool {

	return true
}

// closeTestKeyStore is an address book store that accepts key inserts and
// nothing else, which is all the shutdown path asks of it.
type closeTestKeyStore struct {
	scriptKeyStore
}

func (s *closeTestKeyStore) InsertInternalKey(context.Context,
	keychain.KeyDescriptor) error {

	return nil
}

// newShutdownTestCloser returns an aux closer that can produce shutdown
// records, backed by the given close store.
func newShutdownTestCloser(t *testing.T,
	closeStore AuxCloseStore) *AuxChanCloser {

	t.Helper()

	return NewAuxChanCloser(AuxChanCloserCfg{
		AddrBook: address.NewBook(address.BookConfig{
			Store:   &closeTestKeyStore{},
			KeyRing: &closeTestKeyRing{t: t},
		}),
		DefaultCourierAddr: &url.URL{Scheme: "universerpc"},
		CloseStore:         closeStore,
	})
}

// randFundingBlob returns the funding blob of a channel funded with a
// random asset.
func randFundingBlob(t *testing.T) (tlv.Blob, asset.ID) {
	t.Helper()

	genesis := asset.RandGenesis(t, asset.Normal)
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{Value: 1_000})
	block := wire.MsgBlock{Transactions: []*wire.MsgTx{anchorTx}}
	fundingProof := proof.RandProof(
		t, genesis, test.RandPubKey(t), block, 0, 0,
	)
	assetID := fundingProof.Asset.ID()

	funding := tapchannelmsg.NewOpenChannel(
		[]*tapchannelmsg.AssetOutput{tapchannelmsg.NewAssetOutput(
			assetID, fundingProof.Asset.Amount, fundingProof,
		)}, 0, nil,
	)

	return funding.Bytes(), assetID
}

// decodeShutdownRecords decodes the aux shutdown message from the records
// of a shutdown message.
func decodeShutdownRecords(t *testing.T,
	records lfn.Option[lnwire.CustomRecords]) tapchannelmsg.AuxShutdownMsg {

	t.Helper()

	blob, err := records.UnsafeFromSome().Serialize()
	require.NoError(t, err)

	var msg tapchannelmsg.AuxShutdownMsg
	require.NoError(t, msg.Decode(bytes.NewReader(blob)))

	return msg
}

// TestShutdownBlobReuse asserts that the shutdown records of a channel carry
// the same keys every time they're requested, until the close is finalized.
func TestShutdownBlobReuse(t *testing.T) {
	t.Parallel()

	fundingBlob, assetID := randFundingBlob(t)
	chanPoint := test.RandOp(t)
	btcKey := test.RandPubKey(t)

	req := types.AuxShutdownReq{
		ChanPoint:   chanPoint,
		InternalKey: lfn.Some(*btcKey),
		FundingBlob: lfn.Some(fundingBlob),
	}

	closeStore := NewSQLAuxCloseStore(newMemBlobStore(), errBlobMissing)
	closer := newShutdownTestCloser(t, closeStore)

	records, err := closer.ShutdownBlob(req)
	require.NoError(t, err)
	first := decodeShutdownRecords(t, records)
	require.True(t, btcKey.IsEqual(first.BtcInternalKey.Val))
	require.Contains(t, first.ScriptKeys.Val, assetID)

	// The records are persisted alongside the close state of the channel.
	ctx := context.Background()
	chanClose, err := closeStore.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.NotNil(t, chanClose.shutdownMsg)
	require.Nil(t, chanClose.closeInfo)

	// A second request, as after a reconnect, returns the same records.
	records, err = closer.ShutdownBlob(req)
	require.NoError(t, err)
	require.Equal(t, first, decodeShutdownRecords(t, records))

	// So does a request from a fresh closer, as after a restart. The BTC
	// internal key is always the one of the request.
	otherBtcKey := test.RandPubKey(t)
	restartReq := req
	restartReq.InternalKey = lfn.Some(*otherBtcKey)

	restarted := newShutdownTestCloser(t, closeStore)
	records, err = restarted.ShutdownBlob(restartReq)
	require.NoError(t, err)
	afterRestart := decodeShutdownRecords(t, records)
	require.True(t, otherBtcKey.IsEqual(afterRestart.BtcInternalKey.Val))
	require.True(t, first.AssetInternalKey.Val.IsEqual(
		afterRestart.AssetInternalKey.Val,
	))
	require.Equal(t, first.ScriptKeys.Val, afterRestart.ScriptKeys.Val)

	// Another channel gets its own keys.
	otherReq := req
	otherReq.ChanPoint = test.RandOp(t)
	records, err = closer.ShutdownBlob(otherReq)
	require.NoError(t, err)
	other := decodeShutdownRecords(t, records)
	require.False(t, first.AssetInternalKey.Val.IsEqual(
		other.AssetInternalKey.Val,
	))

	// Once the close state of the channel is gone, as it is after the
	// close is finalized, new keys are derived.
	require.NoError(t, closeStore.Delete(ctx, chanPoint))
	records, err = closer.ShutdownBlob(req)
	require.NoError(t, err)
	fresh := decodeShutdownRecords(t, records)
	require.False(t, first.AssetInternalKey.Val.IsEqual(
		fresh.AssetInternalKey.Val,
	))

	// Without a close store, every request derives new keys.
	noStore := newShutdownTestCloser(t, nil)
	records, err = noStore.ShutdownBlob(req)
	require.NoError(t, err)
	firstNoStore := decodeShutdownRecords(t, records)
	records, err = noStore.ShutdownBlob(req)
	require.NoError(t, err)
	secondNoStore := decodeShutdownRecords(t, records)
	require.False(t, firstNoStore.AssetInternalKey.Val.IsEqual(
		secondNoStore.AssetInternalKey.Val,
	))
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
