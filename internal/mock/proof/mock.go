package proof

import (
	"context"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/json"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func RandProof(t testing.TB, genesis asset.Genesis,
	scriptKey *btcec.PublicKey, block wire.MsgBlock, txIndex int,
	outputIndex uint32) proof.Proof {

	txMerkleProof, err := proof.NewTxMerkleProof(
		block.Transactions, txIndex,
	)
	require.NoError(t, err)

	tweakedScriptKey := asset.NewScriptKey(scriptKey)
	protoAsset := assetmock.NewAssetNoErr(
		t, genesis, 1, 0, 0, tweakedScriptKey, nil,
	)
	groupKey := assetmock.RandGroupKey(t, genesis, protoAsset)
	groupReveal := asset.GroupKeyReveal{
		RawKey:        asset.ToSerialized(&groupKey.GroupPubKey),
		TapscriptRoot: test.RandBytes(32),
	}

	amount := uint64(1)
	mintCommitment, assets, err := commitment.Mint(
		nil, genesis, groupKey, &commitment.AssetDetails{
			Type:             genesis.Type,
			ScriptKey:        test.PubToKeyDesc(scriptKey),
			Amount:           &amount,
			LockTime:         1337,
			RelativeLockTime: 6,
		},
	)
	require.NoError(t, err)
	proofAsset := assets[0]
	proofAsset.GroupKey.RawKey = keychain.KeyDescriptor{}

	// Empty the group witness, since it will eventually be stored as the
	// asset's witness within the proof.
	// TODO(guggero): Actually store the witness in the proof.
	proofAsset.GroupKey.Witness = nil

	// Empty the raw script key, since we only serialize the tweaked
	// pubkey. We'll also force the main script key to be an x-only key as
	// well.
	proofAsset.ScriptKey.PubKey, err = schnorr.ParsePubKey(
		schnorr.SerializePubKey(proofAsset.ScriptKey.PubKey),
	)
	require.NoError(t, err)

	proofAsset.ScriptKey.TweakedScriptKey = nil

	_, commitmentProof, err := mintCommitment.Proof(
		proofAsset.TapCommitmentKey(), proofAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	leaf1 := txscript.NewBaseTapLeaf([]byte{1})
	leaf2 := txscript.NewBaseTapLeaf([]byte{2})
	testLeafPreimage, err := commitment.NewPreimageFromLeaf(leaf1)
	require.NoError(t, err)
	testLeafPreimage2, err := commitment.NewPreimageFromLeaf(leaf2)
	require.NoError(t, err)
	testBranchPreimage := commitment.NewPreimageFromBranch(
		txscript.NewTapBranch(leaf1, leaf2),
	)
	return proof.Proof{
		PrevOut:       genesis.FirstPrevOut,
		BlockHeader:   block.Header,
		BlockHeight:   42,
		AnchorTx:      *block.Transactions[txIndex],
		TxMerkleProof: *txMerkleProof,
		Asset:         *proofAsset,
		InclusionProof: proof.TaprootProof{
			OutputIndex: outputIndex,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: testLeafPreimage,
			},
			TapscriptProof: nil,
		},
		ExclusionProofs: []proof.TaprootProof{
			{
				OutputIndex: 2,
				InternalKey: test.RandPubKey(t),
				CommitmentProof: &proof.CommitmentProof{
					Proof:              *commitmentProof,
					TapSiblingPreimage: testLeafPreimage,
				},
				TapscriptProof: nil,
			},
			{
				OutputIndex:     3,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &proof.TapscriptProof{
					TapPreimage1: &testBranchPreimage,
					TapPreimage2: testLeafPreimage2,
					Bip86:        true,
				},
			},
			{
				OutputIndex:     4,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &proof.TapscriptProof{
					Bip86: true,
				},
			},
		},
		SplitRootProof: &proof.TaprootProof{
			OutputIndex: 4,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: nil,
			},
		},
		MetaReveal: &proof.MetaReveal{
			Data: []byte("quoth the raven nevermore"),
			Type: proof.MetaOpaque,
		},
		ChallengeWitness: wire.TxWitness{[]byte("foo"), []byte("bar")},
		GenesisReveal:    &genesis,
		GroupKeyReveal:   &groupReveal,
	}
}

type MockVerifier struct {
	t *testing.T
}

func NewMockVerifier(t *testing.T) *MockVerifier {
	return &MockVerifier{
		t: t,
	}
}

func (m *MockVerifier) Verify(context.Context, io.Reader, proof.HeaderVerifier,
	proof.MerkleVerifier, proof.GroupVerifier,
	proof.ChainLookupGenerator) (*proof.AssetSnapshot, error) {

	return &proof.AssetSnapshot{
		Asset: &asset.Asset{

			GroupKey: &asset.GroupKey{
				GroupPubKey: *test.RandPubKey(m.t),
			},
			ScriptKey: asset.NewScriptKey(test.RandPubKey(m.t)),
		},
	}, nil
}

// MockHeaderVerifier is a mock verifier which approves of all block headers.
//
// Header verification usually involves cross-referencing with chain data.
// Chain data is not available in unit tests. This function is useful for unit
// tests which are not primarily concerned with block header verification.
func MockHeaderVerifier(header wire.BlockHeader, height uint32) error {
	return nil
}

// MockMerkleVerifier is a mock verifier which approves of all merkle proofs.
func MockMerkleVerifier(*wire.MsgTx, *proof.TxMerkleProof, [32]byte) error {
	return nil
}

// MockGroupVerifier is a mock verifier which approves of all group keys.
//
// Group key verification usually involves having imported the group anchor
// before verification, and many unit tests are not focused on group key
// functionality but still use functions that require a group verifier.
// This function is used in those cases.
func MockGroupVerifier(groupKey *btcec.PublicKey) error {
	return nil
}

// MockGroupAnchorVerifier is a mock verifier which approves of all group anchor
// geneses.
//
// Group anchor verification usually involves accurately computing a group key,
// and many unit tests are not focused on group key functionality but still use
// functions that require a group anchor verifier. This function is used in
// those cases.
func MockGroupAnchorVerifier(gen *asset.Genesis,
	groupKey *asset.GroupKey) error {

	return nil
}

// MockChainLookup is a mock for the ChainLookup interface.
var MockChainLookup = &mockChainLookup{}

// mockChainLookup is a mock implementation of the ChainLookup interface.
type mockChainLookup struct {
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (m *mockChainLookup) TxBlockHeight(context.Context,
	chainhash.Hash) (uint32, error) {

	return 123, nil
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 11 blocks.
func (m *mockChainLookup) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return time.Now(), nil
}

// CurrentHeight returns the current height of the main chain.
func (m *mockChainLookup) CurrentHeight(context.Context) (uint32, error) {
	return 123, nil
}

// GenFileChainLookup generates a chain lookup interface for the given
// proof file that can be used to validate proofs.
func (m *mockChainLookup) GenFileChainLookup(*proof.File) asset.ChainLookup {
	return m
}

// GenProofChainLookup generates a chain lookup interface for the given
// single proof that can be used to validate proofs.
func (m *mockChainLookup) GenProofChainLookup(*proof.Proof) (asset.ChainLookup,
	error) {

	return m, nil
}

var _ asset.ChainLookup = (*mockChainLookup)(nil)
var _ proof.ChainLookupGenerator = (*mockChainLookup)(nil)

// MockProofCourierDispatcher is a mock proof courier dispatcher which returns
// the same courier for all requests.
type MockProofCourierDispatcher struct {
	Courier proof.Courier
}

// NewCourier instantiates a new courier service handle given a service
// URL address.
func (m *MockProofCourierDispatcher) NewCourier(*url.URL,
	proof.Recipient) (proof.Courier, error) {

	return m.Courier, nil
}

// MockProofCourier is a mock proof courier which stores the last proof it
// received.
type MockProofCourier struct {
	sync.Mutex

	currentProofs map[asset.SerializedKey]*proof.AnnotatedProof

	subscribers map[uint64]*fn.EventReceiver[fn.Event]
}

// NewMockProofCourier returns a new mock proof courier.
func NewMockProofCourier() *MockProofCourier {
	return &MockProofCourier{
		currentProofs: make(
			map[asset.SerializedKey]*proof.AnnotatedProof,
		),
	}
}

// Start starts the proof courier service.
func (m *MockProofCourier) Start(chan error) error {
	return nil
}

// Stop stops the proof courier service.
func (m *MockProofCourier) Stop() error {
	return nil
}

// DeliverProof attempts to delivery a proof to the receiver, using the
// information in the Addr type.
func (m *MockProofCourier) DeliverProof(_ context.Context,
	proof *proof.AnnotatedProof) error {

	m.Lock()
	defer m.Unlock()

	m.currentProofs[asset.ToSerialized(&proof.ScriptKey)] = proof

	return nil
}

// ReceiveProof attempts to obtain a proof as identified by the passed
// locator from the source encapsulated within the specified address.
func (m *MockProofCourier) ReceiveProof(_ context.Context,
	loc proof.Locator) (*proof.AnnotatedProof, error) {

	m.Lock()
	defer m.Unlock()

	p, ok := m.currentProofs[asset.ToSerialized(&loc.ScriptKey)]
	if !ok {
		return nil, proof.ErrProofNotFound
	}

	return &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   p.Locator.AssetID,
			GroupKey:  p.Locator.GroupKey,
			ScriptKey: p.Locator.ScriptKey,
			OutPoint:  p.Locator.OutPoint,
		},
		Blob: p.Blob,
		AssetSnapshot: &proof.AssetSnapshot{
			Asset:             p.AssetSnapshot.Asset,
			OutPoint:          p.AssetSnapshot.OutPoint,
			AnchorBlockHash:   p.AssetSnapshot.AnchorBlockHash,
			AnchorBlockHeight: p.AssetSnapshot.AnchorBlockHeight,
			AnchorTxIndex:     p.AssetSnapshot.AnchorTxIndex,
			AnchorTx:          p.AssetSnapshot.AnchorTx,
			OutputIndex:       p.AssetSnapshot.OutputIndex,
			InternalKey:       p.AssetSnapshot.InternalKey,
			ScriptRoot:        p.AssetSnapshot.ScriptRoot,
			TapscriptSibling:  p.AssetSnapshot.TapscriptSibling,
			SplitAsset:        p.AssetSnapshot.SplitAsset,
			MetaReveal:        p.AssetSnapshot.MetaReveal,
		},
	}, nil
}

// SetSubscribers sets the set of subscribers that will be notified
// of proof courier related events.
func (m *MockProofCourier) SetSubscribers(
	subscribers map[uint64]*fn.EventReceiver[fn.Event]) {

	m.Lock()
	defer m.Unlock()

	m.subscribers = subscribers
}

// Close stops the courier instance.
func (m *MockProofCourier) Close() error {
	return nil
}

var _ proof.Courier = (*MockProofCourier)(nil)

type ValidTestCase struct {
	Proof    *json.Proof `json:"proof"`
	Expected string      `json:"expected"`
	Comment  string      `json:"comment"`
}

type ErrorTestCase struct {
	Proof   *json.Proof `json:"proof"`
	Error   string      `json:"error"`
	Comment string      `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
