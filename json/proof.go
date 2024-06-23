package json

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

func HexTx(tx *wire.MsgTx) (string, error) {
	if tx == nil {
		return "", nil
	}

	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func NewProof(p *proof.Proof) (*Proof, error) {
	anchorTx, err := HexTx(&p.AnchorTx)
	if err != nil {
		return nil, err
	}

	a, err := NewAsset(&p.Asset)
	if err != nil {
		return nil, err
	}

	inclusionProof, err := NewTaprootProof(&p.InclusionProof)
	if err != nil {
		return nil, err
	}

	tp := &Proof{
		PrevOut:        p.PrevOut.String(),
		BlockHeader:    NewBlockHeader(&p.BlockHeader),
		BlockHeight:    p.BlockHeight,
		AnchorTx:       anchorTx,
		TxMerkleProof:  NewTxMerkleProof(&p.TxMerkleProof),
		Asset:          a,
		InclusionProof: inclusionProof,
	}

	for i := range p.ExclusionProofs {
		exclusionProof, err := NewTaprootProof(&p.ExclusionProofs[i])
		if err != nil {
			return nil, err
		}

		tp.ExclusionProofs = append(tp.ExclusionProofs, exclusionProof)
	}

	if p.SplitRootProof != nil {
		tp.SplitRootProof, err = NewTaprootProof(p.SplitRootProof)
		if err != nil {
			return nil, err
		}
	}

	if p.MetaReveal != nil {
		tp.MetaReveal = NewMetaReveal(p.MetaReveal)
	}

	for i := range p.AdditionalInputs {
		var buf bytes.Buffer
		err := p.AdditionalInputs[i].Encode(&buf)
		if err != nil {
			return nil, err
		}

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
		tp.GenesisReveal = NewGenesisReveal(p.GenesisReveal)
	}

	if p.GroupKeyReveal != nil {
		tp.GroupKeyReveal = NewGroupKeyReveal(p.GroupKeyReveal)
	}

	return tp, nil
}

type Proof struct {
	PrevOut          string          `json:"prev_out"`
	BlockHeader      *BlockHeader    `json:"block_header"`
	BlockHeight      uint32          `json:"block_height"`
	AnchorTx         string          `json:"anchor_tx"`
	TxMerkleProof    *TxMerkleProof  `json:"tx_merkle_proof"`
	Asset            *Asset          `json:"asset"`
	InclusionProof   *TaprootProof   `json:"inclusion_proof"`
	ExclusionProofs  []*TaprootProof `json:"exclusion_proofs"`
	SplitRootProof   *TaprootProof   `json:"split_root_proof"`
	MetaReveal       *MetaReveal     `json:"meta_reveal"`
	AdditionalInputs []string        `json:"additional_inputs"`
	ChallengeWitness []string        `json:"challenge_witness"`
	GenesisReveal    *GenesisReveal  `json:"genesis_reveal"`
	GroupKeyReveal   *GroupKeyReveal `json:"group_key_reveal"`
}

func (tp *Proof) ToProof(t testing.TB) *proof.Proof {
	t.Helper()

	p := &proof.Proof{
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

		var inputProof proof.File
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

func NewBlockHeader(h *wire.BlockHeader) *BlockHeader {
	return &BlockHeader{
		Version:    h.Version,
		PrevBlock:  h.PrevBlock.String(),
		MerkleRoot: h.MerkleRoot.String(),
		Timestamp:  uint32(h.Timestamp.Unix()),
		Bits:       h.Bits,
		Nonce:      h.Nonce,
	}
}

type BlockHeader struct {
	Version    int32  `json:"version"`
	PrevBlock  string `json:"prev_block"`
	MerkleRoot string `json:"merkle_root"`
	Timestamp  uint32 `json:"timestamp"`
	Bits       uint32 `json:"bits"`
	Nonce      uint32 `json:"nonce"`
}

func (tbh *BlockHeader) ToBlockHeader(t testing.TB) *wire.BlockHeader {
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

func NewTxMerkleProof(p *proof.TxMerkleProof) *TxMerkleProof {
	nodes := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		nodes[i] = n.String()
	}

	return &TxMerkleProof{
		Nodes: nodes,
		Bits:  p.Bits,
	}
}

type TxMerkleProof struct {
	Nodes []string `json:"nodes"`
	Bits  []bool   `json:"bits"`
}

func (tmp *TxMerkleProof) ToTxMerkleProof(
	t testing.TB) *proof.TxMerkleProof {

	t.Helper()

	nodes := make([]chainhash.Hash, len(tmp.Nodes))
	for i, n := range tmp.Nodes {
		nodes[i] = test.ParseChainHash(t, n)
	}

	return &proof.TxMerkleProof{
		Nodes: nodes,
		Bits:  tmp.Bits,
	}
}

func NewTaprootProof(p *proof.TaprootProof) (*TaprootProof, error) {
	ttp := &TaprootProof{
		OutputIndex: p.OutputIndex,
		InternalKey: test.HexPubKey(p.InternalKey),
	}

	var err error
	if p.CommitmentProof != nil {
		ttp.CommitmentProof, err = NewTaprootCommitmentProof(
			p.CommitmentProof,
		)
		if err != nil {
			return nil, err
		}
	}

	if p.TapscriptProof != nil {
		ttp.TapscriptProof, err = NewTapscriptProof(p.TapscriptProof)
		if err != nil {
			return nil, err
		}
	}

	return ttp, nil
}

type TaprootProof struct {
	OutputIndex     uint32                  `json:"output_index"`
	InternalKey     string                  `json:"internal_key"`
	CommitmentProof *TaprootCommitmentProof `json:"commitment_proof"`
	TapscriptProof  *TapscriptProof         `json:"tapscript_proof"`
}

func (ttp *TaprootProof) ToTaprootProof(t testing.TB) *proof.TaprootProof {
	t.Helper()

	p := &proof.TaprootProof{
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

func NewTaprootCommitmentProof(
	cp *proof.CommitmentProof) (*TaprootCommitmentProof, error) {

	sibling, err := HexTapscriptSibling(cp.TapSiblingPreimage)
	if err != nil {
		return nil, err
	}

	p, err := NewCommitmentProof(&cp.Proof)
	if err != nil {
		return nil, err
	}

	return &TaprootCommitmentProof{
		Proof:            p,
		TapscriptSibling: sibling,
	}, nil
}

type TaprootCommitmentProof struct {
	Proof            *CommitmentProof `json:"proof"`
	TapscriptSibling string           `json:"tapscript_sibling"`
}

func (tcp *TaprootCommitmentProof) ToCommitmentProof(
	t testing.TB) *proof.CommitmentProof {

	t.Helper()

	return &proof.CommitmentProof{
		Proof: *tcp.Proof.ToProof(t),
		TapSiblingPreimage: ParseTapscriptSibling(
			t, tcp.TapscriptSibling,
		),
	}
}

func NewTapscriptProof(p *proof.TapscriptProof) (*TapscriptProof, error) {
	p1, err := HexTapscriptSibling(p.TapPreimage1)
	if err != nil {
		return nil, err
	}

	p2, err := HexTapscriptSibling(p.TapPreimage2)
	if err != nil {
		return nil, err
	}

	return &TapscriptProof{
		TapPreimage1: p1,
		TapPreimage2: p2,
		Bip86:        p.Bip86,
	}, nil
}

type TapscriptProof struct {
	TapPreimage1 string `json:"tap_preimage_1"`
	TapPreimage2 string `json:"tap_preimage_2"`
	Bip86        bool   `json:"bip86"`
}

func (ttp *TapscriptProof) ToTapscriptProof(
	t testing.TB) *proof.TapscriptProof {

	t.Helper()

	return &proof.TapscriptProof{
		TapPreimage1: ParseTapscriptSibling(
			t, ttp.TapPreimage1,
		),
		TapPreimage2: ParseTapscriptSibling(
			t, ttp.TapPreimage2,
		),
		Bip86: ttp.Bip86,
	}
}

func NewMetaReveal(m *proof.MetaReveal) *MetaReveal {
	return &MetaReveal{
		Type: uint8(m.Type),
		Data: hex.EncodeToString(m.Data),
	}
}

type MetaReveal struct {
	Type uint8  `json:"type"`
	Data string `json:"data"`
}

func (tmr *MetaReveal) ToMetaReveal(t testing.TB) *proof.MetaReveal {
	t.Helper()

	data, err := hex.DecodeString(tmr.Data)
	require.NoError(t, err)

	return &proof.MetaReveal{
		Type: proof.MetaType(tmr.Type),
		Data: data,
	}
}
