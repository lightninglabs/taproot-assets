package supplycommit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type testPreCommitReader struct{}

func (testPreCommitReader) FetchDelegationKey(context.Context,
	btcec.PublicKey) (fn.Option[keychain.KeyDescriptor], error) {

	return fn.None[keychain.KeyDescriptor](), nil
}

type testDelegationChecker struct {
	has bool
	err error
}

func (c testDelegationChecker) HasDelegationKey(context.Context,
	asset.ID) (bool, error) {

	return c.has, c.err
}

type testMintEmitter struct{}

func (testMintEmitter) SendMintEvent(context.Context, asset.Specifier,
	universe.UniqueLeafKey, universe.Leaf, uint32) error {

	return nil
}

// selectiveDelegationChecker reports delegation-key ownership per
// asset ID, so tests can mix owned and non-owned assets in one batch.
type selectiveDelegationChecker struct {
	owned map[asset.ID]bool
}

func (c selectiveDelegationChecker) HasDelegationKey(_ context.Context,
	id asset.ID) (bool, error) {

	return c.owned[id], nil
}

// recordingMintEmitter records every mint event key it is handed.
type recordingMintEmitter struct {
	keys []universe.UniqueLeafKey
}

func (e *recordingMintEmitter) SendMintEvent(_ context.Context,
	_ asset.Specifier, key universe.UniqueLeafKey, _ universe.Leaf,
	_ uint32) error {

	e.keys = append(e.keys, key)
	return nil
}

func validAugmenterCfg() supplycommit.GenesisAugmenterCfg {
	return supplycommit.GenesisAugmenterCfg{
		PreCommitStore:       testPreCommitReader{},
		KeyRing:              tapnodemock.NewKeyRing(),
		DelegationKeyChecker: testDelegationChecker{},
		MintEvents:           testMintEmitter{},
		ChainParams:          address.RegressionNetTap,
	}
}

func newTestAugmenter(t *testing.T) *supplycommit.GenesisAugmenter {
	t.Helper()

	aug, err := supplycommit.NewGenesisAugmenter(validAugmenterCfg())
	require.NoError(t, err)

	return aug
}

// TestNewGenesisAugmenterValidation asserts that all dependencies used by the
// augmenter are rejected at construction time when absent.
func TestNewGenesisAugmenterValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		expectErr string
		mutate    func(*supplycommit.GenesisAugmenterCfg)
	}{
		{
			name:      "pre-commit store",
			expectErr: "pre-commit store is required",
			mutate: func(cfg *supplycommit.GenesisAugmenterCfg) {
				cfg.PreCommitStore = nil
			},
		},
		{
			name:      "key ring",
			expectErr: "key ring is required",
			mutate: func(cfg *supplycommit.GenesisAugmenterCfg) {
				cfg.KeyRing = nil
			},
		},
		{
			name:      "delegation key checker",
			expectErr: "delegation key checker is required",
			mutate: func(cfg *supplycommit.GenesisAugmenterCfg) {
				cfg.DelegationKeyChecker = nil
			},
		},
		{
			name:      "mint event emitter",
			expectErr: "mint event emitter is required",
			mutate: func(cfg *supplycommit.GenesisAugmenterCfg) {
				cfg.MintEvents = nil
			},
		},
		{
			name:      "chain parameters",
			expectErr: "chain parameters are required",
			mutate: func(cfg *supplycommit.GenesisAugmenterCfg) {
				cfg.ChainParams = address.ChainParams{}
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cfg := validAugmenterCfg()
			testCase.mutate(&cfg)

			aug, err := supplycommit.NewGenesisAugmenter(cfg)
			require.Nil(t, aug)
			require.ErrorContains(t, err, testCase.expectErr)
		})
	}
}

// TestAugmenterDelegationCheckError verifies that confirmation fails instead
// of silently dropping an asset if ownership lookup fails.
func TestAugmenterDelegationCheckError(t *testing.T) {
	t.Parallel()

	cfg := validAugmenterCfg()
	cfg.DelegationKeyChecker = testDelegationChecker{
		err: fmt.Errorf("lookup failed"),
	}
	aug, err := supplycommit.NewGenesisAugmenter(cfg)
	require.NoError(t, err)

	batch := &tapgarden.MintingBatch{SupplyCommitments: true}
	mintedAsset := asset.RandAsset(t, asset.Normal)
	err = aug.OnBatchConfirmed(
		context.Background(), batch, []*asset.Asset{mintedAsset},
		nil, nil,
	)
	require.ErrorContains(t, err, "unable to check delegation key")
	require.ErrorContains(t, err, "lookup failed")
}

// TestAugmenterSkipsOrdinaryBatch verifies that OnBatchConfirmed is a no-op
// for batches without supply commitments: the delegation-key store is not
// consulted at all, so a failure there cannot delay an ordinary mint's
// confirmation.
func TestAugmenterSkipsOrdinaryBatch(t *testing.T) {
	t.Parallel()

	cfg := validAugmenterCfg()
	cfg.DelegationKeyChecker = testDelegationChecker{
		err: fmt.Errorf("lookup failed"),
	}
	aug, err := supplycommit.NewGenesisAugmenter(cfg)
	require.NoError(t, err)

	mintedAsset := asset.RandAsset(t, asset.Normal)
	assets := []*asset.Asset{mintedAsset}

	err = aug.OnBatchConfirmed(context.Background(), nil, assets, nil, nil)
	require.NoError(t, err)

	batch := &tapgarden.MintingBatch{SupplyCommitments: false}
	err = aug.OnBatchConfirmed(
		context.Background(), batch, assets, nil, nil,
	)
	require.NoError(t, err)
}

// TestAugmenterDelegationFiltering verifies the positive filtering path: in a
// supply-commit batch, assets whose delegation key the local node controls
// emit a mint event, and assets it does not control are skipped.
func TestAugmenterDelegationFiltering(t *testing.T) {
	t.Parallel()

	ownedAsset := asset.RandAsset(t, asset.Normal)
	otherAsset := asset.RandAsset(t, asset.Normal)

	emitter := &recordingMintEmitter{}
	cfg := validAugmenterCfg()
	cfg.DelegationKeyChecker = selectiveDelegationChecker{
		owned: map[asset.ID]bool{ownedAsset.ID(): true},
	}
	cfg.MintEvents = emitter
	aug, err := supplycommit.NewGenesisAugmenter(cfg)
	require.NoError(t, err)

	// Only the owned asset needs a minting proof: the non-owned asset
	// must be filtered out before its proof is ever looked up.
	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxIn(&wire.TxIn{})
	dummyTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte("dummy")})
	block := wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: time.Now(),
		},
		Transactions: []*wire.MsgTx{dummyTx},
	}
	ownedProof := proof.RandProof(
		t, ownedAsset.Genesis, ownedAsset.ScriptKey.PubKey, block, 0, 0,
	)
	mintingProofs := proof.AssetProofs{
		asset.ToSerialized(ownedAsset.ScriptKey.PubKey): &ownedProof,
	}

	batch := &tapgarden.MintingBatch{SupplyCommitments: true}
	err = aug.OnBatchConfirmed(
		context.Background(), batch,
		[]*asset.Asset{ownedAsset, otherAsset}, nil, mintingProofs,
	)
	require.NoError(t, err)

	require.Len(t, emitter.keys, 1)
	leafKey, ok := emitter.keys[0].(universe.AssetLeafKey)
	require.True(t, ok)
	require.Equal(t, ownedAsset.ID(), leafKey.AssetID)
}

// TestAugmenterValidateSeedling exercises the supply-commit
// invariants that the GenesisAugmenter enforces at seedling
// intake. These tests previously lived on
// MintingBatch.validateUniCommitment in tapgarden; they moved
// with the invariant.
func TestAugmenterValidateSeedling(t *testing.T) {
	t.Parallel()

	aug := newTestAugmenter(t)

	type tc struct {
		name      string
		candidate tapgarden.Seedling
		batch     *tapgarden.MintingBatch
		expectErr bool
	}

	cases := []tc{
		{
			// Multiple group anchors in a uni-commit batch
			// is not allowed.
			name: "populated batch with universe commitments; " +
				"candidate is a second group anchor; invalid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// A uni-commit candidate cannot enter a
			// non-uni-commit batch.
			name: "populated batch without universe commitments; " +
				"uni-commit candidate; invalid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "new-group-anchor", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// A non-anchor uni-commit candidate referencing
			// an absent anchor must be rejected.
			name: "populated batch without universe commitments; " +
				"non-anchor uni-commit candidate; invalid",
			candidate: tapgarden.RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(false),
			),
			expectErr: true,
		},
		{
			// A non-anchor uni-commit candidate referencing
			// an absent anchor in a uni-commit batch.
			name: "populated uni-commit batch; anchor absent; " +
				"invalid",
			candidate: tapgarden.RandNonAnchorGroupSeedling(
				t, asset.V1, asset.Normal, "some-anchor-name",
				[]byte{}, fn.None[keychain.KeyDescriptor](),
				true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithTotalGroups([]int{2}),
				tapgarden.WithUniverseCommitments(true),
			),
			expectErr: true,
		},
		{
			// Group anchor candidate into an empty unfunded
			// batch is fine.
			name: "empty unfunded batch; group anchor candidate; " +
				"valid",
			candidate: tapgarden.RandGroupAnchorSeedling(
				t, "some-anchor-name", true,
			),
			batch: tapgarden.RandMintingBatch(
				t, tapgarden.WithSkipFunding(),
			),
			expectErr: false,
		},
	}

	// Construct a positive case: a uni-commit batch with a
	// group anchor and a non-anchor candidate that correctly
	// references it.
	batch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalGroups([]int{2}),
		tapgarden.WithUniverseCommitments(true),
	)
	var anchor *tapgarden.Seedling
	for _, s := range batch.Seedlings {
		if s.GroupAnchor == nil {
			anchor = s
			break
		}
	}
	cases = append(cases, tc{
		name: "populated uni-commit batch; non-anchor " +
			"candidate references existing anchor; valid",
		candidate: tapgarden.RandNonAnchorGroupSeedling(
			t, anchor.AssetVersion, anchor.AssetType,
			anchor.AssetName, anchor.Meta.Data,
			anchor.DelegationKey, anchor.SupplyCommitments,
		),
		batch:     batch,
		expectErr: false,
	})

	// Funded-but-empty uni-commit batch must reject a
	// uni-commit candidate.
	fundedEmptyBatch := tapgarden.RandMintingBatch(t)
	fundedEmptyBatch.GenesisPacket = &tapgarden.FundedMintAnchorPsbt{}
	cases = append(cases, tc{
		name: "empty funded batch; uni-commit candidate; invalid",
		candidate: tapgarden.RandGroupAnchorSeedling(
			t, "some-anchor-name", true,
		),
		batch:     fundedEmptyBatch,
		expectErr: true,
	})
	cases = append(cases, tc{
		name: "empty funded batch; non-uni-commit candidate; valid",
		candidate: tapgarden.RandGroupAnchorSeedling(
			t, "some-anchor-name", false,
		),
		batch:     fundedEmptyBatch,
		expectErr: false,
	})

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := aug.ValidateSeedling(c.batch, c.candidate)
			if c.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestAugmenterBindDataFailsClosed asserts that a funded supply-commit batch
// cannot silently omit its persistence payload.
func TestAugmenterBindDataFailsClosed(t *testing.T) {
	t.Parallel()

	aug := newTestAugmenter(t)
	batch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalGroups([]int{1}),
		tapgarden.WithUniverseCommitments(true),
	)

	bind, err := aug.BindData(context.Background(), batch)
	require.NoError(t, err)
	require.True(t, bind.IsSome())

	bindData, err := bind.UnwrapOrErr(fmt.Errorf("bind data missing"))
	require.NoError(t, err)
	txOuts := batch.GenesisPacket.Pkt.UnsignedTx.TxOut
	txOuts[bindData.OutputIndex].PkScript = []byte{0x51}

	bind, err = aug.BindData(context.Background(), batch)
	require.ErrorContains(t, err, "pre-commit output not found")
	require.True(t, bind.IsNone())

	batch.GenesisPacket = nil
	bind, err = aug.BindData(context.Background(), batch)
	require.ErrorContains(t, err, "no funded genesis packet")
	require.True(t, bind.IsNone())
}
