package tapgarden

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// RandGroupAnchorSeedling generates a random seedling for a group anchor asset.
func RandGroupAnchorSeedling(t testing.TB, groupAnchorName string,
	uniCommitments bool) Seedling {

	scriptKey, _ := test.RandKeyDesc(t)

	// For now, we only test the v0 and v1 versions.
	assetVersion := asset.Version(test.RandIntn(2))
	assetType := asset.Normal

	assetGenesis := asset.RandGenesis(t, assetType)

	// Create asset group key.
	groupPrivateDesc, groupPrivateKey := test.RandKeyDesc(t)

	// Generate the signature for our group genesis asset.
	genSigner := asset.NewMockGenesisSigner(groupPrivateKey)
	genTxBuilder := asset.MockGroupTxBuilder{}

	genProtoAsset := asset.RandAssetWithValues(
		t, assetGenesis, nil, asset.RandScriptKey(t),
	)
	groupKeyRequest := asset.NewGroupKeyRequestNoErr(
		t, groupPrivateDesc, fn.None[asset.ExternalKey](), assetGenesis,
		genProtoAsset, nil, fn.None[chainhash.Hash](),
	)
	genTx, err := groupKeyRequest.BuildGroupVirtualTx(&genTxBuilder)
	require.NoError(t, err)

	groupKey, err := asset.DeriveGroupKey(
		genSigner, *genTx, *groupKeyRequest, nil,
	)
	require.NoError(t, err)

	// Generate a delegation key if we're using universe commitments.
	var delegationKey fn.Option[keychain.KeyDescriptor]
	if uniCommitments {
		keyDesc, _ := test.RandKeyDesc(t)
		delegationKey = fn.Some[keychain.KeyDescriptor](keyDesc)
	}

	return Seedling{
		AssetVersion: assetVersion,
		AssetType:    assetType,
		AssetName:    groupAnchorName,
		Meta: &proof.MetaReveal{
			Data: test.RandBytes(32),
		},
		Amount: uint64(test.RandInt[uint32]()),
		GroupInfo: &asset.AssetGroup{
			Genesis:  &assetGenesis,
			GroupKey: groupKey,
		},
		ScriptKey:         asset.NewScriptKeyBip86(scriptKey),
		EnableEmission:    true,
		SupplyCommitments: uniCommitments,
		DelegationKey:     delegationKey,
	}
}

// RandNonAnchorGroupSeedling generates a random seedling for a non-anchor asset
// in an asset group.
func RandNonAnchorGroupSeedling(t testing.TB, assetVersion asset.Version,
	assetType asset.Type, anchorName string, metaDataBlob []byte,
	delegationKey fn.Option[keychain.KeyDescriptor],
	uniCommitments bool) Seedling {

	seedlingName := hex.EncodeToString(test.RandBytes(32))
	scriptKey, _ := test.RandKeyDesc(t)

	seedling := Seedling{
		AssetVersion: assetVersion,
		AssetType:    assetType,
		AssetName:    seedlingName,
		GroupAnchor:  &anchorName,
		Meta: &proof.MetaReveal{
			Data: metaDataBlob,
		},
		Amount:            uint64(test.RandInt[uint32]()),
		ScriptKey:         asset.NewScriptKeyBip86(scriptKey),
		EnableEmission:    true,
		SupplyCommitments: uniCommitments,
		DelegationKey:     delegationKey,
	}
	return seedling
}

// RandGroupSeedlings generates a random set of seedlings which all belong to a
// single asset group.
func RandGroupSeedlings(t testing.TB, numSeedlings int,
	uniCommitments bool) []Seedling {

	// Formulate group anchor seedling.
	anchorName := hex.EncodeToString(test.RandBytes(32))

	anchor := RandGroupAnchorSeedling(t, anchorName, uniCommitments)
	seedlings := []Seedling{
		anchor,
	}

	// Formulate non-anchor group seedlings.
	for i := 0; i < numSeedlings-1; i++ {
		seedling := RandNonAnchorGroupSeedling(
			t, anchor.AssetVersion, anchor.AssetType, anchorName,
			anchor.Meta.Data, anchor.DelegationKey, uniCommitments,
		)
		seedlings = append(seedlings, seedling)
	}

	return seedlings
}

// MintBatchOptions is a set of options for creating a new minting batch.
type MintBatchOptions struct {
	// totalSeedlings specifies the number of seedlings to generate in this
	// minting batch. The seedlings are randomly assigned as grouped or
	// ungrouped.
	totalSeedlings int

	// totalGroups specifies the number of asset groups to generate in this
	// minting batch. Each element in the slice specifies the number of
	// seedlings to generate for the corresponding asset group.
	totalGroups []int

	// universeCommitments specifies whether to generate universe
	// commitments for the asset groups in this minting batch.
	universeCommitments bool

	// skipFunding specifies whether to skip funding the genesis PSBT.
	skipFunding bool
}

// MintBatchOption is a functional option for creating a new minting batch.
type MintBatchOption func(*MintBatchOptions)

// DefaultMintBatchOptions returns a new set of default minting batch options.
func DefaultMintBatchOptions() MintBatchOptions {
	return MintBatchOptions{}
}

// WithTotalSeedlings sets the total number of seedlings to populate in the
// minting batch.
func WithTotalSeedlings(count int) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.totalSeedlings = count
	}
}

// WithTotalGroups sets the total number of asset groups to populate in the
// minting batch. Each element in the slice specifies the number of seedlings
// to generate for the corresponding asset group.
func WithTotalGroups(counts []int) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.totalGroups = counts
	}
}

// WithUniverseCommitments specifies whether to generate universe commitments
// for the asset groups in the minting batch.
func WithUniverseCommitments(enabled bool) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.universeCommitments = enabled
	}
}

// WithSkipFunding specifies whether to skip funding the genesis PSBT.
func WithSkipFunding() MintBatchOption {
	return func(options *MintBatchOptions) {
		options.skipFunding = true
	}
}

// RandMintingBatch creates a new minting batch with only random seedlings
// populated for testing.
func RandMintingBatch(t testing.TB, opts ...MintBatchOption) *MintingBatch {
	// Construct options.
	options := DefaultMintBatchOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// If the total number of seedlings is unset, we set using the total
	// number of seedlings in the asset groups.
	if options.totalSeedlings == 0 {
		for _, count := range options.totalGroups {
			options.totalSeedlings += count
		}
	}

	// Create an empty minting batch.
	batchKey, _ := test.RandKeyDesc(t)
	batch := &MintingBatch{
		BatchKey:          batchKey,
		HeightHint:        test.RandInt[uint32](),
		CreationTime:      time.Now(),
		SupplyCommitments: options.universeCommitments,
	}

	// Generate seedlings for each asset group.
	for idx := range options.totalGroups {
		countSeedlingsInGroup := options.totalGroups[idx]

		groupSeedlings := RandGroupSeedlings(
			t, countSeedlingsInGroup, options.universeCommitments,
		)

		// Add the seedlings to the total seedlings map.
		for _, seedling := range groupSeedlings {
			err := batch.AddSeedling(seedling)
			require.NoError(t, err)
		}
	}

	// If the total number of seedlings generated so far is less than the
	// total number of seedlings requested, we generate the remaining
	// seedlings at random.
	if len(batch.Seedlings) < options.totalSeedlings {
		remaining := options.totalSeedlings - len(batch.Seedlings)
		randSeedlings := RandSeedlings(t, remaining)

		// Add the seedlings to the total seedlings map.
		for _, seedling := range randSeedlings {
			err := batch.AddSeedling(*seedling)
			require.NoError(t, err)
		}
	}

	// Randomly generating seedlings may result in overlaps with existing
	// ones, leading to fewer seedlings than intended. Sanity check to
	// ensure that the total number of seedlings generated matches the
	// requested amount. This check might help debug flakes in tests.
	require.Equal(t, options.totalSeedlings, len(batch.Seedlings))

	// Return early if funding is to be skipped.
	if options.skipFunding {
		return batch
	}

	walletFundPsbt := func(ctx context.Context,
		anchorPkt psbt.Packet) (tapsend.FundedPsbt, error) {

		changeOutputIdx := tapnodemock.FundGenesisTx(
			&anchorPkt, chainfee.FeePerKwFloor,
		)

		return tapsend.FundedPsbt{
			Pkt:               &anchorPkt,
			ChangeOutputIndex: int32(changeOutputIdx),
		}, nil
	}

	// Fund genesis packet.
	ctx := context.Background()
	fundedPsbt, err := fundGenesisPsbt(
		ctx, address.TestNet3Tap, batch, walletFundPsbt,
	)
	require.NoError(t, err)
	batch.GenesisPacket = &fundedPsbt

	return batch
}

// RandSeedlings creates a new set of random seedlings for testing.
func RandSeedlings(t testing.TB, numSeedlings int) map[string]*Seedling {
	seedlings := make(map[string]*Seedling)
	for i := 0; i < numSeedlings; i++ {
		metaBlob := test.RandBytes(32)
		assetName := hex.EncodeToString(test.RandBytes(32))
		scriptKey, _ := test.RandKeyDesc(t)
		seedlings[assetName] = &Seedling{
			// For now, we only test the v0 and v1 versions.
			AssetVersion: asset.Version(test.RandIntn(2)),
			AssetType:    asset.Type(test.RandIntn(2)),
			AssetName:    assetName,
			Meta: &proof.MetaReveal{
				Data: metaBlob,
			},
			Amount:         uint64(test.RandInt[uint32]()),
			ScriptKey:      asset.NewScriptKeyBip86(scriptKey),
			EnableEmission: test.RandBool(),
		}
	}

	return seedlings
}

type MockGenSigner struct {
	KeyRing     *tapnodemock.KeyRing
	failSigning atomic.Bool
}

func NewMockGenSigner(keyRing *tapnodemock.KeyRing) *MockGenSigner {
	return &MockGenSigner{
		KeyRing: keyRing,
	}
}

// FailSigningOnce updates the GenSigner such that the next call to
// SignVirtualTx will fail by returning an error.
func (m *MockGenSigner) FailSigningOnce() {
	m.failSigning.Store(true)
}

func (m *MockGenSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	virtualTx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature,
	error) {

	if m.failSigning.CompareAndSwap(true, false) {
		return nil, fmt.Errorf("failed to sign virtual tx")
	}

	priv := m.KeyRing.Keys[signDesc.KeyDesc.KeyLocator]
	signer := asset.NewMockGenesisSigner(priv)
	return signer.SignVirtualTx(signDesc, virtualTx, prevOut)
}

// A compile-time assertion to ensure MockGenSigner meets the GenesisSigner
// interface.
var _ asset.GenesisSigner = (*MockGenSigner)(nil)

type MockProofArchive struct {
}

func (m *MockProofArchive) FetchProof(ctx context.Context,
	id proof.Locator) (proof.Blob, error) {

	return nil, nil
}

func (m *MockProofArchive) HasProof(ctx context.Context,
	id proof.Locator) (bool, error) {

	return false, nil
}

func (m *MockProofArchive) FetchProofs(ctx context.Context,
	id asset.ID) ([]*proof.AnnotatedProof, error) {

	return nil, nil
}

func (m *MockProofArchive) ImportProofs(context.Context,
	proof.HeaderVerifier, proof.MerkleVerifier, proof.GroupVerifier,
	proof.ChainLookupGenerator, bool, ...*proof.AnnotatedProof) error {

	return nil
}

type MockProofWatcher struct {
}

func (m *MockProofWatcher) WatchProofs([]*proof.Proof,
	proof.UpdateCallback) error {

	return nil
}

func (m *MockProofWatcher) MaybeWatch(*proof.File, proof.UpdateCallback) error {
	return nil
}

func (m *MockProofWatcher) ShouldWatch(*proof.Proof) bool {
	return true
}

func (m *MockProofWatcher) DefaultUpdateCallback() proof.UpdateCallback {
	return func([]*proof.Proof) error {
		return nil
	}
}

type FallibleTapscriptTreeMgr struct {
	store               MintingStore
	FailLoad, FailStore bool
}

func (mgr FallibleTapscriptTreeMgr) DeleteTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) error {

	return mgr.store.DeleteTapscriptTree(ctx, rootHash)
}

func (mgr FallibleTapscriptTreeMgr) LoadTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) (*asset.TapscriptTreeNodes, error) {

	if mgr.FailLoad {
		return nil, fmt.Errorf("failed to load tapscript tree")
	}

	return mgr.store.LoadTapscriptTree(ctx, rootHash)
}

func (mgr FallibleTapscriptTreeMgr) StoreTapscriptTree(ctx context.Context,
	treeNodes asset.TapscriptTreeNodes) (*chainhash.Hash, error) {

	if mgr.FailStore {
		return nil, fmt.Errorf("unable to store tapscript tree")
	}

	return mgr.store.StoreTapscriptTree(ctx, treeNodes)
}

func NewFallibleTapscriptTreeMgr(store MintingStore) FallibleTapscriptTreeMgr {
	return FallibleTapscriptTreeMgr{
		store: store,
	}
}

var _ asset.TapscriptTreeManager = (*FallibleTapscriptTreeMgr)(nil)
