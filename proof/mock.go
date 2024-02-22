package proof

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
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
	groupReveal := asset.GroupKeyReveal{
		RawKey:        asset.ToSerialized(&groupKey.GroupPubKey),
		TapscriptRoot: test.RandBytes(32),
	}

	amount := uint64(1)
	mintCommitment, assets, err := commitment.Mint(
		genesis, groupKey, &commitment.AssetDetails{
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

func (m *MockVerifier) Verify(context.Context, io.Reader,
	HeaderVerifier, MerkleVerifier, GroupVerifier) (*AssetSnapshot, error) {

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

// MockProofCourierDispatcher is a mock proof courier dispatcher which returns
// the same courier for all requests.
type MockProofCourierDispatcher struct {
	Courier Courier
}

// NewCourier instantiates a new courier service handle given a service
// URL address.
func (m *MockProofCourierDispatcher) NewCourier(*url.URL, Recipient) (Courier,
	error) {

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
	proof *AnnotatedProof) error {

	m.Lock()
	defer m.Unlock()

	m.currentProofs[asset.ToSerialized(&proof.ScriptKey)] = proof

	return nil
}

// ReceiveProof attempts to obtain a proof as identified by the passed
// locator from the source encapsulated within the specified address.
func (m *MockProofCourier) ReceiveProof(_ context.Context,
	loc Locator) (*AnnotatedProof, error) {

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
		PrevOut:        p.PrevOut.String(),
		BlockHeader:    NewTestFromBlockHeader(t, &p.BlockHeader),
		BlockHeight:    p.BlockHeight,
		AnchorTx:       test.HexTx(t, &p.AnchorTx),
		TxMerkleProof:  NewTestFromTxMerkleProof(t, &p.TxMerkleProof),
		Asset:          asset.NewTestFromAsset(t, &p.Asset),
		InclusionProof: NewTestFromTaprootProof(t, &p.InclusionProof),
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

	return tp
}

type TestProof struct {
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
}

func (tp *TestProof) ToProof(t testing.TB) *Proof {
	t.Helper()

	p := &Proof{
		PrevOut:        test.ParseOutPoint(t, tp.PrevOut),
		BlockHeader:    *tp.BlockHeader.ToBlockHeader(t),
		BlockHeight:    tp.BlockHeight,
		AnchorTx:       *test.ParseTx(t, tp.AnchorTx),
		TxMerkleProof:  *tp.TxMerkleProof.ToTxMerkleProof(t),
		Asset:          *tp.Asset.ToAsset(t),
		InclusionProof: *tp.InclusionProof.ToTaprootProof(t),
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
		OutputIndex: p.OutputIndex,
		InternalKey: test.HexPubKey(p.InternalKey),
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
}

func (ttp *TestTaprootProof) ToTaprootProof(t testing.TB) *TaprootProof {
	t.Helper()

	p := &TaprootProof{
		OutputIndex: ttp.OutputIndex,
		InternalKey: test.ParsePubKey(t, ttp.InternalKey),
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
	}
}

type TestCommitmentProof struct {
	Proof            *commitment.TestProof `json:"proof"`
	TapscriptSibling string                `json:"tapscript_sibling"`
}

func (tcp *TestCommitmentProof) ToCommitmentProof(
	t testing.TB) *CommitmentProof {

	t.Helper()

	return &CommitmentProof{
		Proof: *tcp.Proof.ToProof(t),
		TapSiblingPreimage: commitment.ParseTapscriptSibling(
			t, tcp.TapscriptSibling,
		),
	}
}

func NewTestFromTapscriptProof(t testing.TB,
	p *TapscriptProof) *TestTapscriptProof {

	t.Helper()

	return &TestTapscriptProof{
		TapPreimage1: commitment.HexTapscriptSibling(t, p.TapPreimage1),
		TapPreimage2: commitment.HexTapscriptSibling(t, p.TapPreimage2),
		Bip86:        p.Bip86,
	}
}

type TestTapscriptProof struct {
	TapPreimage1 string `json:"tap_preimage_1"`
	TapPreimage2 string `json:"tap_preimage_2"`
	Bip86        bool   `json:"bip86"`
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
		Bip86: ttp.Bip86,
	}
}

func NewTestFromMetaReveal(t testing.TB, m *MetaReveal) *TestMetaReveal {
	t.Helper()

	return &TestMetaReveal{
		Type: uint8(m.Type),
		Data: hex.EncodeToString(m.Data),
	}
}

type TestMetaReveal struct {
	Type uint8  `json:"type"`
	Data string `json:"data"`
}

func (tmr *TestMetaReveal) ToMetaReveal(t testing.TB) *MetaReveal {
	t.Helper()

	data, err := hex.DecodeString(tmr.Data)
	require.NoError(t, err)

	return &MetaReveal{
		Type: MetaType(tmr.Type),
		Data: data,
	}
}
