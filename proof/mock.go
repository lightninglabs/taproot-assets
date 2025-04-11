package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
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
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	// MockVerifierCtx is a verifier context that uses mock implementations
	// for all the verifier interfaces.
	MockVerifierCtx = VerifierCtx{
		HeaderVerifier:      MockHeaderVerifier,
		MerkleVerifier:      MockMerkleVerifier,
		GroupVerifier:       MockGroupVerifier,
		GroupAnchorVerifier: MockGroupAnchorVerifier,
		ChainLookupGen:      MockChainLookup,
	}
)

func RandProof(t testing.TB, genesis asset.Genesis,
	scriptKey *btcec.PublicKey, block wire.MsgBlock, txIndex int,
	outputIndex uint32) Proof {

	txMerkleProof, err := NewTxMerkleProof(block.Transactions, txIndex)
	require.NoError(t, err)

	tweakedScriptKey := asset.NewScriptKey(scriptKey)
	protoAsset := asset.NewAssetNoErr(
		t, genesis, 1, 0, 0, tweakedScriptKey, nil,
	)
	groupKey := asset.RandGroupKey(t, genesis, protoAsset)
	groupReveal := asset.NewGroupKeyRevealV0(
		asset.ToSerialized(&groupKey.GroupPubKey),
		test.RandBytes(32),
	)

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
	return Proof{
		PrevOut:       genesis.FirstPrevOut,
		BlockHeader:   block.Header,
		BlockHeight:   42,
		AnchorTx:      *block.Transactions[txIndex],
		TxMerkleProof: *txMerkleProof,
		Asset:         *proofAsset,
		InclusionProof: TaprootProof{
			OutputIndex: outputIndex,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: testLeafPreimage,
			},
			TapscriptProof: nil,
		},
		ExclusionProofs: []TaprootProof{
			{
				OutputIndex: 2,
				InternalKey: test.RandPubKey(t),
				CommitmentProof: &CommitmentProof{
					Proof:              *commitmentProof,
					TapSiblingPreimage: testLeafPreimage,
				},
				TapscriptProof: nil,
			},
			{
				OutputIndex:     3,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					TapPreimage1: &testBranchPreimage,
					TapPreimage2: testLeafPreimage2,
					Bip86:        true,
				},
			},
			{
				OutputIndex:     4,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					Bip86: true,
				},
			},
		},
		SplitRootProof: &TaprootProof{
			OutputIndex: 4,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: nil,
			},
		},
		MetaReveal: &MetaReveal{
			Data: []byte("quoth the raven nevermore"),
			Type: MetaOpaque,
		},
		ChallengeWitness: wire.TxWitness{[]byte("foo"), []byte("bar")},
		GenesisReveal:    &genesis,
		GroupKeyReveal:   groupReveal,
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

func (m *MockVerifier) Verify(context.Context, io.Reader,
	VerifierCtx) (*AssetSnapshot, error) {

	return &AssetSnapshot{
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
func MockMerkleVerifier(*wire.MsgTx, *TxMerkleProof, [32]byte) error {
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
func (m *mockChainLookup) GenFileChainLookup(*File) asset.ChainLookup {
	return m
}

// GenProofChainLookup generates a chain lookup interface for the given
// single proof that can be used to validate proofs.
func (m *mockChainLookup) GenProofChainLookup(*Proof) (asset.ChainLookup,
	error) {

	return m, nil
}

var _ asset.ChainLookup = (*mockChainLookup)(nil)
var _ ChainLookupGenerator = (*mockChainLookup)(nil)

// MockProofArchive is a map that implements the Archiver interface.
type MockProofArchive struct {
	proofs   lnutils.SyncMap[[32]byte, Blob]
	locators lnutils.SyncMap[[132]byte, [32]byte]
}

// NewMockProofArchive creates a new mock proof archive.
func NewMockProofArchive() *MockProofArchive {
	return &MockProofArchive{
		proofs:   lnutils.SyncMap[[32]byte, Blob]{},
		locators: lnutils.SyncMap[[132]byte, [32]byte]{},
	}
}

// storeLocator stores the locator as a byte array to allow for pattern matching
// over the locators for the stored proofs, similar to the FileArchiver
// implementation of FetchIssuanceProof.
func (m *MockProofArchive) storeLocator(id Locator) error {
	var locBuf bytes.Buffer

	if id.AssetID == nil {
		return fmt.Errorf("missing asset ID")
	}

	locBuf.Write(id.AssetID[:])
	if id.GroupKey != nil {
		locBuf.Write(id.GroupKey.SerializeCompressed())
	} else {
		locBuf.Write(bytes.Repeat([]byte{0x00}, 33))
	}

	locBuf.Write(id.ScriptKey.SerializeCompressed())
	if id.OutPoint != nil {
		err := lnwire.WriteOutPoint(&locBuf, *id.OutPoint)
		if err != nil {
			return err
		}
	} else {
		locBuf.Write(bytes.Repeat([]byte{0x00}, 34))
	}

	var locArray [132]byte
	copy(locArray[:], locBuf.Bytes())

	locHash, err := id.Hash()
	if err != nil {
		return err
	}

	m.locators.Store(locArray, locHash)

	return nil
}

// FetchProof fetches a proof for an asset uniquely identified by the passed
// Locator. If a proof cannot be found, then ErrProofNotFound is returned.
func (m *MockProofArchive) FetchProof(_ context.Context,
	id Locator) (Blob, error) {

	idHash, err := id.Hash()
	if err != nil {
		return nil, err
	}

	proof, ok := m.proofs.Load(idHash)
	if !ok {
		return nil, ErrProofNotFound
	}

	return proof, nil
}

// FetchIssuanceProof fetches the issuance proof for an asset, given the
// anchor point of the issuance (NOT the genesis point for the asset).
//
// If a proof cannot be found, then ErrProofNotFound should be returned.
func (m *MockProofArchive) FetchIssuanceProof(_ context.Context,
	id asset.ID, anchorOutpoint wire.OutPoint) (Blob, error) {

	var outpointBuf bytes.Buffer
	err := lnwire.WriteOutPoint(&outpointBuf, anchorOutpoint)
	if err != nil {
		return nil, err
	}

	// Mimic the pattern matching done with proof file paths in
	// FileArchiver.FetchIssuanceProof().
	matchingHashes := make([][32]byte, 0)
	locMatcher := func(locBytes [132]byte, locHash [32]byte) error {
		if bytes.Equal(locBytes[:32], id[:]) &&
			bytes.Equal(locBytes[98:], outpointBuf.Bytes()) {

			matchingHashes = append(matchingHashes, locHash)
		}

		return nil
	}

	m.locators.ForEach(locMatcher)
	if len(matchingHashes) == 0 {
		return nil, ErrProofNotFound
	}

	matchingProofs := make([]Blob, 0)
	for _, locHash := range matchingHashes {
		proof, ok := m.proofs.Load(locHash)
		if !ok {
			return nil, ErrProofNotFound
		}

		matchingProofs = append(matchingProofs, proof)
	}

	switch {
	case len(matchingProofs) == 1:
		return matchingProofs[0], nil

	// Multiple proofs, return the smallest one.
	default:
		minProofIdx := 0
		minProofSize := len(matchingProofs[minProofIdx])
		for idx, proof := range matchingProofs {
			if len(proof) < minProofSize {
				minProofSize = len(proof)
				minProofIdx = idx
			}
		}

		return matchingProofs[minProofIdx], nil
	}
}

// HasProof returns true if the proof for the given locator exists.
func (m *MockProofArchive) HasProof(_ context.Context,
	id Locator) (bool, error) {

	idHash, err := id.Hash()
	if err != nil {
		return false, err
	}

	_, ok := m.proofs.Load(idHash)

	return ok, nil
}

// FetchProofs would fetch all proofs for a specific asset ID, but will always
// err for the mock proof archive.
func (m *MockProofArchive) FetchProofs(_ context.Context,
	id asset.ID) ([]*AnnotatedProof, error) {

	return nil, fmt.Errorf("not implemented")
}

// ImportProofs will store the given proofs, without performing any validation.
func (m *MockProofArchive) ImportProofs(_ context.Context, _ VerifierCtx,
	_ bool, proofs ...*AnnotatedProof) error {

	for _, proof := range proofs {
		err := m.storeLocator(proof.Locator)
		if err != nil {
			return fmt.Errorf("mock archive failed: %w", err)
		}

		locHash, err := proof.Locator.Hash()
		if err != nil {
			return err
		}

		m.proofs.Store(locHash, proof.Blob)
	}

	return nil
}

var _ Archiver = (*MockProofArchive)(nil)

// MockProofCourierDispatcher is a mock proof courier dispatcher which returns
// the same courier for all requests.
type MockProofCourierDispatcher struct {
	Courier Courier
}

// NewCourier instantiates a new courier service handle given a service
// URL address.
func (m *MockProofCourierDispatcher) NewCourier(context.Context,
	*url.URL, bool) (Courier, error) {

	return m.Courier, nil
}

// MockProofCourier is a mock proof courier which stores the last proof it
// received.
type MockProofCourier struct {
	sync.Mutex

	currentProofs map[asset.SerializedKey]*AnnotatedProof

	subscribers map[uint64]*fn.EventReceiver[fn.Event]
}

// NewMockProofCourier returns a new mock proof courier.
func NewMockProofCourier() *MockProofCourier {
	return &MockProofCourier{
		currentProofs: make(map[asset.SerializedKey]*AnnotatedProof),
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
	_ Recipient, proof *AnnotatedProof) error {

	m.Lock()
	defer m.Unlock()

	m.currentProofs[asset.ToSerialized(&proof.ScriptKey)] = proof

	return nil
}

// ReceiveProof attempts to obtain a proof as identified by the passed
// locator from the source encapsulated within the specified address.
func (m *MockProofCourier) ReceiveProof(_ context.Context,
	_ Recipient, loc Locator) (*AnnotatedProof, error) {

	m.Lock()
	defer m.Unlock()

	proof, ok := m.currentProofs[asset.ToSerialized(&loc.ScriptKey)]
	if !ok {
		return nil, ErrProofNotFound
	}

	return &AnnotatedProof{
		Locator: Locator{
			AssetID:   proof.Locator.AssetID,
			GroupKey:  proof.Locator.GroupKey,
			ScriptKey: proof.Locator.ScriptKey,
			OutPoint:  proof.Locator.OutPoint,
		},
		Blob: proof.Blob,
		AssetSnapshot: &AssetSnapshot{
			Asset:             proof.AssetSnapshot.Asset,
			OutPoint:          proof.AssetSnapshot.OutPoint,
			AnchorBlockHash:   proof.AssetSnapshot.AnchorBlockHash,
			AnchorBlockHeight: proof.AssetSnapshot.AnchorBlockHeight,
			AnchorTxIndex:     proof.AssetSnapshot.AnchorTxIndex,
			AnchorTx:          proof.AssetSnapshot.AnchorTx,
			OutputIndex:       proof.AssetSnapshot.OutputIndex,
			InternalKey:       proof.AssetSnapshot.InternalKey,
			ScriptRoot:        proof.AssetSnapshot.ScriptRoot,
			TapscriptSibling:  proof.AssetSnapshot.TapscriptSibling,
			SplitAsset:        proof.AssetSnapshot.SplitAsset,
			MetaReveal:        proof.AssetSnapshot.MetaReveal,
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

var _ Courier = (*MockProofCourier)(nil)

type ValidTestCase struct {
	Proof    *TestProof `json:"proof"`
	Expected string     `json:"expected"`
	Comment  string     `json:"comment"`
}

type ErrorTestCase struct {
	Proof   *TestProof `json:"proof"`
	Error   string     `json:"error"`
	Comment string     `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func NewTestFromProof(t testing.TB, p *Proof) *TestProof {
	t.Helper()

	tp := &TestProof{
		Version:         p.Version,
		PrevOut:         p.PrevOut.String(),
		BlockHeader:     NewTestFromBlockHeader(t, &p.BlockHeader),
		BlockHeight:     p.BlockHeight,
		AnchorTx:        test.HexTx(t, &p.AnchorTx),
		TxMerkleProof:   NewTestFromTxMerkleProof(t, &p.TxMerkleProof),
		Asset:           asset.NewTestFromAsset(t, &p.Asset),
		InclusionProof:  NewTestFromTaprootProof(t, &p.InclusionProof),
		UnknownOddTypes: p.UnknownOddTypes,
	}

	for i := range p.ExclusionProofs {
		tp.ExclusionProofs = append(
			tp.ExclusionProofs,
			NewTestFromTaprootProof(t, &p.ExclusionProofs[i]),
		)
	}

	if p.SplitRootProof != nil {
		tp.SplitRootProof = NewTestFromTaprootProof(t, p.SplitRootProof)
	}

	if p.MetaReveal != nil {
		tp.MetaReveal = NewTestFromMetaReveal(t, p.MetaReveal)
	}

	for i := range p.AdditionalInputs {
		var buf bytes.Buffer
		err := p.AdditionalInputs[i].Encode(&buf)
		require.NoError(t, err)

		tp.AdditionalInputs = append(
			tp.AdditionalInputs, hex.EncodeToString(buf.Bytes()),
		)
	}

	for i := range p.ChallengeWitness {
		tp.ChallengeWitness = append(
			tp.ChallengeWitness,
			hex.EncodeToString(p.ChallengeWitness[i]),
		)
	}

	if p.GenesisReveal != nil {
		tp.GenesisReveal = asset.NewTestFromGenesisReveal(
			t, p.GenesisReveal,
		)
	}

	if p.GroupKeyReveal != nil {
		tp.GroupKeyReveal = asset.NewTestFromGroupKeyReveal(
			t, p.GroupKeyReveal,
		)
	}

	if len(p.AltLeaves) > 0 {
		// Assert that the concrete type of AltLeaf is supported.
		require.IsTypef(
			t, &asset.Asset{}, p.AltLeaves[0],
			"AltLeaves must be of type *asset.Asset",
		)

		tp.AltLeaves = make([]*asset.TestAsset, len(p.AltLeaves))
		for idx := range p.AltLeaves {
			// We also need a type assertion on each leaf.
			leaf := p.AltLeaves[idx].(*asset.Asset)
			tp.AltLeaves[idx] = asset.NewTestFromAsset(t, leaf)
		}
	}

	return tp
}

type TestProof struct {
	Version          TransitionVersion         `json:"version"`
	PrevOut          string                    `json:"prev_out"`
	BlockHeader      *TestBlockHeader          `json:"block_header"`
	BlockHeight      uint32                    `json:"block_height"`
	AnchorTx         string                    `json:"anchor_tx"`
	TxMerkleProof    *TestTxMerkleProof        `json:"tx_merkle_proof"`
	Asset            *asset.TestAsset          `json:"asset"`
	InclusionProof   *TestTaprootProof         `json:"inclusion_proof"`
	ExclusionProofs  []*TestTaprootProof       `json:"exclusion_proofs"`
	SplitRootProof   *TestTaprootProof         `json:"split_root_proof"`
	MetaReveal       *TestMetaReveal           `json:"meta_reveal"`
	AdditionalInputs []string                  `json:"additional_inputs"`
	ChallengeWitness []string                  `json:"challenge_witness"`
	GenesisReveal    *asset.TestGenesisReveal  `json:"genesis_reveal"`
	GroupKeyReveal   *asset.TestGroupKeyReveal `json:"group_key_reveal"`
	AltLeaves        []*asset.TestAsset        `json:"alt_leaves"`
	UnknownOddTypes  tlv.TypeMap               `json:"unknown_odd_types"`
}

func (tp *TestProof) ToProof(t testing.TB) *Proof {
	t.Helper()

	p := &Proof{
		Version:         tp.Version,
		PrevOut:         test.ParseOutPoint(t, tp.PrevOut),
		BlockHeader:     *tp.BlockHeader.ToBlockHeader(t),
		BlockHeight:     tp.BlockHeight,
		AnchorTx:        *test.ParseTx(t, tp.AnchorTx),
		TxMerkleProof:   *tp.TxMerkleProof.ToTxMerkleProof(t),
		Asset:           *tp.Asset.ToAsset(t),
		InclusionProof:  *tp.InclusionProof.ToTaprootProof(t),
		UnknownOddTypes: tp.UnknownOddTypes,
	}

	for i := range tp.ExclusionProofs {
		p.ExclusionProofs = append(
			p.ExclusionProofs,
			*tp.ExclusionProofs[i].ToTaprootProof(t),
		)
	}

	if tp.SplitRootProof != nil {
		p.SplitRootProof = tp.SplitRootProof.ToTaprootProof(t)
	}

	if tp.MetaReveal != nil {
		p.MetaReveal = tp.MetaReveal.ToMetaReveal(t)
	}

	for i := range tp.AdditionalInputs {
		b, err := hex.DecodeString(tp.AdditionalInputs[i])
		require.NoError(t, err)

		var inputProof File
		err = inputProof.Decode(bytes.NewReader(b))
		require.NoError(t, err)

		p.AdditionalInputs = append(p.AdditionalInputs, inputProof)
	}

	for i := range tp.ChallengeWitness {
		b, err := hex.DecodeString(tp.ChallengeWitness[i])
		require.NoError(t, err)

		p.ChallengeWitness = append(p.ChallengeWitness, b)
	}

	if tp.GenesisReveal != nil {
		p.GenesisReveal = tp.GenesisReveal.ToGenesisReveal(t)
	}

	if tp.GroupKeyReveal != nil {
		p.GroupKeyReveal = tp.GroupKeyReveal.ToGroupKeyReveal(t)
	}

	if len(tp.AltLeaves) > 0 {
		p.AltLeaves = make(
			[]asset.AltLeaf[asset.Asset], len(tp.AltLeaves),
		)
		for idx, leaf := range tp.AltLeaves {
			p.AltLeaves[idx] = leaf.ToAsset(t)
		}
	}

	return p
}

func NewTestFromBlockHeader(t testing.TB,
	h *wire.BlockHeader) *TestBlockHeader {

	t.Helper()

	return &TestBlockHeader{
		Version:    h.Version,
		PrevBlock:  h.PrevBlock.String(),
		MerkleRoot: h.MerkleRoot.String(),
		Timestamp:  uint32(h.Timestamp.Unix()),
		Bits:       h.Bits,
		Nonce:      h.Nonce,
	}
}

type TestBlockHeader struct {
	Version    int32  `json:"version"`
	PrevBlock  string `json:"prev_block"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  uint32 `json:"timestamp"`
	Bits       uint32 `json:"bits"`
	Nonce      uint32 `json:"nonce"`
}

func (tbh *TestBlockHeader) ToBlockHeader(t testing.TB) *wire.BlockHeader {
	t.Helper()

	return &wire.BlockHeader{
		Version:    tbh.Version,
		PrevBlock:  test.ParseChainHash(t, tbh.PrevBlock),
		MerkleRoot: test.ParseChainHash(t, tbh.MerkleRoot),
		Timestamp:  time.Unix(int64(tbh.Timestamp), 0),
		Bits:       tbh.Bits,
		Nonce:      tbh.Nonce,
	}
}

func NewTestFromTxMerkleProof(t testing.TB,
	p *TxMerkleProof) *TestTxMerkleProof {

	t.Helper()

	nodes := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		nodes[i] = n.String()
	}

	return &TestTxMerkleProof{
		Nodes: nodes,
		Bits:  p.Bits,
	}
}

type TestTxMerkleProof struct {
	Nodes []string `json:"nodes"`
	Bits  []bool   `json:"bits"`
}

func (tmp *TestTxMerkleProof) ToTxMerkleProof(t testing.TB) *TxMerkleProof {
	t.Helper()

	nodes := make([]chainhash.Hash, len(tmp.Nodes))
	for i, n := range tmp.Nodes {
		nodes[i] = test.ParseChainHash(t, n)
	}

	return &TxMerkleProof{
		Nodes: nodes,
		Bits:  tmp.Bits,
	}
}

func NewTestFromTaprootProof(t testing.TB,
	p *TaprootProof) *TestTaprootProof {

	t.Helper()

	ttp := &TestTaprootProof{
		OutputIndex:     p.OutputIndex,
		InternalKey:     test.HexPubKey(p.InternalKey),
		UnknownOddTypes: p.UnknownOddTypes,
	}

	if p.CommitmentProof != nil {
		ttp.CommitmentProof = NewTestFromCommitmentProof(
			t, p.CommitmentProof,
		)
	}

	if p.TapscriptProof != nil {
		ttp.TapscriptProof = NewTestFromTapscriptProof(
			t, p.TapscriptProof,
		)
	}

	return ttp
}

type TestTaprootProof struct {
	OutputIndex     uint32               `json:"output_index"`
	InternalKey     string               `json:"internal_key"`
	CommitmentProof *TestCommitmentProof `json:"commitment_proof"`
	TapscriptProof  *TestTapscriptProof  `json:"tapscript_proof"`
	UnknownOddTypes tlv.TypeMap          `json:"unknown_odd_types"`
}

func (ttp *TestTaprootProof) ToTaprootProof(t testing.TB) *TaprootProof {
	t.Helper()

	p := &TaprootProof{
		OutputIndex:     ttp.OutputIndex,
		InternalKey:     test.ParsePubKey(t, ttp.InternalKey),
		UnknownOddTypes: ttp.UnknownOddTypes,
	}

	if ttp.CommitmentProof != nil {
		p.CommitmentProof = ttp.CommitmentProof.ToCommitmentProof(t)
	}

	if ttp.TapscriptProof != nil {
		p.TapscriptProof = ttp.TapscriptProof.ToTapscriptProof(t)
	}

	return p
}

func NewTestFromCommitmentProof(t testing.TB,
	p *CommitmentProof) *TestCommitmentProof {

	t.Helper()

	return &TestCommitmentProof{
		Proof: commitment.NewTestFromProof(t, &p.Proof),
		TapscriptSibling: commitment.HexTapscriptSibling(
			t, p.TapSiblingPreimage,
		),
		STXOProofs:      NewTestFromSTXOProofs(t, p),
		UnknownOddTypes: p.UnknownOddTypes,
	}
}

func NewTestFromSTXOProofs(t testing.TB,
	p *CommitmentProof) *map[string]commitment.TestProof {

	t.Helper()

	stxoProofs := make(map[string]commitment.TestProof)
	for key, proof := range p.STXOProofs {
		keyHex := hex.EncodeToString(key[:])
		stxoProofs[keyHex] = *commitment.NewTestFromProof(t, &proof)
	}
	return &stxoProofs
}

// nolint: lll
type TestCommitmentProof struct {
	Proof            *commitment.TestProof            `json:"proof"`
	TapscriptSibling string                           `json:"tapscript_sibling"`
	STXOProofs       *map[string]commitment.TestProof `json:"stxo_proofs"`
	UnknownOddTypes  tlv.TypeMap                      `json:"unknown_odd_types"`
}

func (tcp *TestCommitmentProof) ToCommitmentProof(
	t testing.TB) *CommitmentProof {

	t.Helper()

	stxoProofs := make(map[asset.SerializedKey]commitment.Proof)
	for key, proof := range *tcp.STXOProofs {
		keyBytes, err := hex.DecodeString(key)
		require.NoError(t, err)
		key := asset.SerializedKey(keyBytes)
		stxoProofs[key] = *proof.ToProof(t)
	}

	cp := &CommitmentProof{
		Proof: *tcp.Proof.ToProof(t),
		TapSiblingPreimage: commitment.ParseTapscriptSibling(
			t, tcp.TapscriptSibling,
		),
		UnknownOddTypes: tcp.UnknownOddTypes,
	}

	if len(stxoProofs) > 0 {
		cp.STXOProofs = stxoProofs
	}

	return cp
}

func NewTestFromTapscriptProof(t testing.TB,
	p *TapscriptProof) *TestTapscriptProof {

	t.Helper()

	return &TestTapscriptProof{
		TapPreimage1: commitment.HexTapscriptSibling(
			t, p.TapPreimage1,
		),
		TapPreimage2: commitment.HexTapscriptSibling(
			t, p.TapPreimage2,
		),
		Bip86:           p.Bip86,
		UnknownOddTypes: p.UnknownOddTypes,
	}
}

type TestTapscriptProof struct {
	TapPreimage1    string      `json:"tap_preimage_1"`
	TapPreimage2    string      `json:"tap_preimage_2"`
	Bip86           bool        `json:"bip86"`
	UnknownOddTypes tlv.TypeMap `json:"unknown_odd_types"`
}

func (ttp *TestTapscriptProof) ToTapscriptProof(t testing.TB) *TapscriptProof {
	t.Helper()

	return &TapscriptProof{
		TapPreimage1: commitment.ParseTapscriptSibling(
			t, ttp.TapPreimage1,
		),
		TapPreimage2: commitment.ParseTapscriptSibling(
			t, ttp.TapPreimage2,
		),
		Bip86:           ttp.Bip86,
		UnknownOddTypes: ttp.UnknownOddTypes,
	}
}

func NewTestFromMetaReveal(t testing.TB, m *MetaReveal) *TestMetaReveal {
	t.Helper()

	var universeCommitments *bool
	if m.UniverseCommitments {
		trueValue := true
		universeCommitments = &trueValue
	}

	var canonicalUniverses []string
	m.CanonicalUniverses.WhenSome(func(urls []url.URL) {
		canonicalUniverses = fn.Map(urls, func(u url.URL) string {
			return u.String()
		})
	})

	var delegationKey *string
	m.DelegationKey.WhenSome(func(key btcec.PublicKey) {
		keyBytes := key.SerializeCompressed()
		keyHex := hex.EncodeToString(keyBytes)
		delegationKey = &keyHex
	})

	return &TestMetaReveal{
		Type:                uint8(m.Type),
		Data:                hex.EncodeToString(m.Data),
		UniverseCommitments: universeCommitments,
		DecimalDisplay:      m.DecimalDisplay.UnwrapToPtr(),
		CanonicalUniverses:  canonicalUniverses,
		DelegationKey:       delegationKey,
		UnknownOddTypes:     m.UnknownOddTypes,
	}
}

type TestMetaReveal struct {
	Type                uint8       `json:"type"`
	Data                string      `json:"data"`
	DecimalDisplay      *uint32     `json:"decimal_display"`
	UniverseCommitments *bool       `json:"universe_commitments"`
	CanonicalUniverses  []string    `json:"canonical_universes"`
	DelegationKey       *string     `json:"delegation_key"`
	UnknownOddTypes     tlv.TypeMap `json:"unknown_odd_types"`
}

func (tmr *TestMetaReveal) ToMetaReveal(t testing.TB) *MetaReveal {
	t.Helper()

	data, err := hex.DecodeString(tmr.Data)
	require.NoError(t, err)

	var decimalDisplay fn.Option[uint32]
	if tmr.DecimalDisplay != nil {
		decimalDisplay = fn.Some(*tmr.DecimalDisplay)
	}

	var universeCommitments bool
	if tmr.UniverseCommitments != nil && *tmr.UniverseCommitments {
		universeCommitments = true
	}

	var canonicalUniverses fn.Option[[]url.URL]
	if len(tmr.CanonicalUniverses) > 0 {
		urls := make([]url.URL, len(tmr.CanonicalUniverses))
		for idx, u := range tmr.CanonicalUniverses {
			uniURL, err := url.Parse(u)
			require.NoError(t, err)

			urls[idx] = *uniURL
		}

		canonicalUniverses = fn.Some(urls)
	}

	var delegationKey fn.Option[btcec.PublicKey]
	if tmr.DelegationKey != nil {
		keyBytes, err := hex.DecodeString(*tmr.DelegationKey)
		require.NoError(t, err)

		key, err := btcec.ParsePubKey(keyBytes)
		require.NoError(t, err)

		delegationKey = fn.Some(*key)
	}

	return &MetaReveal{
		Type:                MetaType(tmr.Type),
		Data:                data,
		DecimalDisplay:      decimalDisplay,
		UniverseCommitments: universeCommitments,
		CanonicalUniverses:  canonicalUniverses,
		DelegationKey:       delegationKey,
		UnknownOddTypes:     tmr.UnknownOddTypes,
	}
}

type mockIgnoreChecker struct {
	ignoredAssetPoints fn.Set[AssetPoint]
	ignoreAll          bool
}

func newMockIgnoreChecker(ignoreAll bool,
	ignorePoints ...AssetPoint) *mockIgnoreChecker {

	return &mockIgnoreChecker{
		ignoredAssetPoints: fn.NewSet(ignorePoints...),
		ignoreAll:          ignoreAll,
	}
}

func (m *mockIgnoreChecker) IsIgnored(assetPoint AssetPoint) bool {
	return m.ignoreAll || m.ignoredAssetPoints.Contains(assetPoint)
}

// MockUniverseServer is a mock implementation of the UniverseServer
// interface. It implements the GetInfo RPC method, which returns an empty
// InfoResponse.
type MockUniverseServer struct {
	universerpc.UnimplementedUniverseServer
}

// Info is a mock implementation of the GetInfo RPC.
func (m *MockUniverseServer) Info(context.Context,
	*universerpc.InfoRequest) (*universerpc.InfoResponse, error) {

	return &universerpc.InfoResponse{}, nil
}

// MockCourierURL creates a new mock proof courier URL for the given protocol
// and address.
func MockCourierURL(t *testing.T, protocol, addr string) *url.URL {
	urlString := fmt.Sprintf("%s://%s", protocol, addr)
	proofCourierAddr, err := ParseCourierAddress(urlString)
	require.NoError(t, err)

	return proofCourierAddr
}
