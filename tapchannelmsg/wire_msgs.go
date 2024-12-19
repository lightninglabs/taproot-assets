package tapchannelmsg

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// TapMessageTypeBaseOffset is the Taproot Assets specific message type
	// identifier base offset. All Taproot Asset Protocol messages will have
	// a type identifier that is greater than or equal to this value.
	//
	// The range for custom message types starts at 32768 according to
	// BOLT-1. This offset was chosen as the concatenation of the
	// alphabetical index positions of the letters "t" (20), "a" (1), and
	// "p" (16).
	TapMessageTypeBaseOffset = 20116 + lnwire.CustomTypeStart

	// TapChannelMessageTypeOffset is the offset that is added to the type
	// of each message type related to Taproot Asset channel funding.
	TapChannelMessageTypeOffset = TapMessageTypeBaseOffset + 256

	// TxAssetInputProofType is the message type of the TxAssetInput
	// message.
	TxAssetInputProofType = TapChannelMessageTypeOffset + 0

	// TxAssetOutputProofType is the message type of the TxAssetOutput
	// message.
	TxAssetOutputProofType = TapChannelMessageTypeOffset + 1

	// AssetFundingCreatedType is the message type of the
	// AssetFundingCreated message.
	AssetFundingCreatedType = TapChannelMessageTypeOffset + 2

	// AssetFundingAckType is the message type of the AssetFundingAck
	// message.
	AssetFundingAckType = TapChannelMessageTypeOffset + 3
)

var (
	// ErrChunkSize is returned when the chunk size is invalid.
	ErrChunkSize = fmt.Errorf("chunk size must be positive")

	// ErrInvalidChunk is returned when the wrong number of chunks is
	// created.
	ErrImproperChunks = fmt.Errorf("improper number of chunks")

	// ErrChunkDistUniformity is returned when the chunk distribution is not
	// the same over all chunks.
	ErrChunkDistUniformity = fmt.Errorf("chunk distribution is not uniform")

	// ErrChunkDigestMismatch is returned when the chunk digest sum does not
	// match one encoded in the message.
	ErrChunkDigestMismatch = fmt.Errorf("chunk digest mismatch")

	// ErrNoChunks is returned when no chunks are provided.
	ErrNoChunks = fmt.Errorf("no chunks")
)

// AssetFundingMsg is an interface that represents a message that is sent
// during the asset funding process.
type AssetFundingMsg interface {
	lnwire.Message

	// PID returns the pending channel ID that was assigned to the channel.
	PID() funding.PendingChanID

	// Amt returns the amount of the asset that is committed to the channel.
	Amt() fn.Option[uint64]
}

// ProofChunk contains a chunk of a proof that would be too large to send as a
// single message.
type ProofChunk struct {
	// ChunkSumID is a digest sum over the final proof including all chunks.
	// This is used to identify which chunk belongs to which proofs, and can
	// be used to verify the integrity of the final proof.
	ChunkSumID tlv.RecordT[tlv.TlvType0, [sha256.Size]byte]

	// Chunk is a chunk of the proof.
	Chunk tlv.RecordT[tlv.TlvType1, []byte]

	// Last indicates whether this is the last chunk in the proof.
	Last tlv.RecordT[tlv.TlvType2, bool]
}

// Encode writes the message using the given io.Writer.
func (p *ProofChunk) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(
		p.ChunkSumID.Record(), p.Chunk.Record(), p.Last.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode reads the message using the given io.Reader.
func (p *ProofChunk) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(
		p.ChunkSumID.Record(), p.Chunk.Record(), p.Last.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// eProofChunk is a tlv encoding function for the ProofChunk type.
func eProofChunk(w io.Writer, val interface{}, _ *[8]byte) error {
	if v, ok := val.(*ProofChunk); ok {
		return v.Encode(w)
	}

	return tlv.NewTypeForEncodingErr(val, "*ProofChunk")
}

// dProofChunk is a tlv decoding function for the ProofChunk type.
func dProofChunk(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	if v, ok := val.(*ProofChunk); ok {
		return v.Decode(r)
	}

	return tlv.NewTypeForDecodingErr(val, "*ProofChunk", l, l)
}

// Record returns the tlv record of the proof chunk.
func (p *ProofChunk) Record() tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := p.Encode(&buf)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}

	return tlv.MakeDynamicRecord(
		0, p, sizeFunc, eProofChunk, dProofChunk,
	)
}

// NewProofChunk creates a new ProofChunk message.
func NewProofChunk(sum [32]byte, chunk []byte, last bool) ProofChunk {
	return ProofChunk{
		ChunkSumID: tlv.NewPrimitiveRecord[tlv.TlvType0](sum),
		Chunk:      tlv.NewPrimitiveRecord[tlv.TlvType1](chunk),
		Last:       tlv.NewPrimitiveRecord[tlv.TlvType2](last),
	}
}

// CreateProofChunks creates a list of proof chunks from a single proof, given a
// desired chunk size.
func CreateProofChunks(wholeProof proof.Proof,
	chunkSize int) ([]ProofChunk, error) {

	// The chunk size must be positive.
	if chunkSize <= 0 {
		return nil, fmt.Errorf("%w: chunk size is %v",
			ErrChunkSize, chunkSize)
	}

	// First, we'll encode the entire proof into a buffer so we can chunk it
	// up.
	var proofBuf bytes.Buffer
	err := wholeProof.Encode(&proofBuf)
	if err != nil {
		return nil, err
	}

	// We'll also obtain the hash digest of the proof as well.
	proofDigest := sha256.Sum256(proofBuf.Bytes())

	// If the length of the proof is below the chunk size, then we can
	// return just a single proof.
	if proofBuf.Len() <= chunkSize {
		return []ProofChunk{
			NewProofChunk(proofDigest, proofBuf.Bytes(), true),
		}, nil
	}

	numExpectedChunks := proofBuf.Len() / chunkSize
	if proofBuf.Len()%chunkSize != 0 {
		numExpectedChunks++
	}

	proofSize := proofBuf.Len()

	// Otherwise, we'll need to chunk up the proof into multiple chunks.
	var chunks []ProofChunk
	for i := 0; i < proofSize; i += chunkSize {
		// If this is the last chunk, then we'll set the last flag to
		// true.
		last := i+chunkSize >= proofBuf.Len()

		// We'll slice out the next chunk of the proof.
		chunk := proofBuf.Next(chunkSize)

		// With the chunk obtained, we'll create a new proof chunk and
		// add it to our list of chunks.
		chunks = append(
			chunks, NewProofChunk(proofDigest, chunk, last),
		)
	}

	// Verify that we created the correct number of chunks.
	if len(chunks) != numExpectedChunks {
		return nil, fmt.Errorf("%w: expected %v chunks, got %v",
			ErrImproperChunks, numExpectedChunks, len(chunks))
	}

	return chunks, nil
}

// AssembleProofChunks assembles a list of proof chunks into a single proof.
func AssembleProofChunks(chunks []ProofChunk) (*proof.Proof, error) {
	// We must have at least a single chunk.
	if len(chunks) == 0 {
		return nil, ErrNoChunks
	}

	// First, we'll iterate over all the chunks to ensure that they all have
	// the same digest sum.
	var proofDigest [sha256.Size]byte
	for i, chunk := range chunks {
		// If this is the first chunk, then we'll record the digest sum.
		if i == 0 {
			proofDigest = chunk.ChunkSumID.Val
		}

		// If the digest sum of this chunk doesn't match the one we
		// recorded, then we'll return an error.
		if proofDigest != chunk.ChunkSumID.Val {
			return nil, fmt.Errorf("%w: digest sum mismatch at "+
				"chunk %v", ErrChunkDistUniformity, i)
		}
	}

	// With the digest sum validated, we'll now concatenate all the chunks
	// together to obtain the full proof.
	var proofBuf bytes.Buffer
	for _, chunk := range chunks {
		_, err := proofBuf.Write(chunk.Chunk.Val)
		if err != nil {
			return nil, fmt.Errorf("unable to write chunk: %w", err)
		}
	}

	// Before we decode the full proof, we'll ensure that the proof digest
	// matches up.
	fullProofDigest := sha256.Sum256(proofBuf.Bytes())
	if proofDigest != fullProofDigest {
		return nil, fmt.Errorf("%w: digest sum mismatch: expected %x, "+
			"got %x", ErrChunkDigestMismatch, proofDigest,
			fullProofDigest)
	}

	// Finally, we'll decode the full proof from the buffer.
	var fullProof proof.Proof
	err := fullProof.Decode(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to decode full proof: %w", err)
	}

	return &fullProof, nil
}

// TxAssetInputProof is sent by the initiator of a channel funding request to
// prove to the upcoming responder that they are the owner of an asset input.
//
// TODO(roasbeef): once we have fixed the asset ownership proof to sign a
// challenge value, we can use temp chan ID as the challenge.
type TxAssetInputProof struct {
	// PendingChanID is the pending channel ID that was assigned to the
	// channel.
	PendingChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// AssetID is the ID of the asset that this output is associated with.
	AssetID tlv.RecordT[tlv.TlvType1, asset.ID]

	// Amount is the amount of the asset that this output represents.
	Amount tlv.RecordT[tlv.TlvType2, uint64]

	// ProofChunk is a set of proof chunks for the last transition proof
	// that proves this output was committed to in the Bitcoin transaction
	// that anchors this asset output.
	ProofChunk tlv.RecordT[tlv.TlvType3, ProofChunk]
}

// NewTxAssetInputProof creates a new TxAssetInputProof message.
func NewTxAssetInputProof(pid funding.PendingChanID, assetID asset.ID,
	amt uint64, chunk ProofChunk) *TxAssetInputProof {

	return &TxAssetInputProof{
		PendingChanID: tlv.NewPrimitiveRecord[tlv.TlvType0](pid),
		AssetID:       tlv.NewRecordT[tlv.TlvType1](assetID),
		Amount:        tlv.NewPrimitiveRecord[tlv.TlvType2](amt),
		ProofChunk:    tlv.NewRecordT[tlv.TlvType3](chunk),
	}
}

// MsgType returns the type of the message.
func (t *TxAssetInputProof) MsgType() lnwire.MessageType {
	return TxAssetInputProofType
}

// Decode reads the bytes stream and converts it to the object.
func (t *TxAssetInputProof) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.AssetID.Record(),
		t.Amount.Record(),
		t.ProofChunk.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the
// write buffer.
func (t *TxAssetInputProof) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.AssetID.Record(),
		t.Amount.Record(),
		t.ProofChunk.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PID returns the pending channel ID that was assigned to the channel.
func (t *TxAssetInputProof) PID() funding.PendingChanID {
	return t.PendingChanID.Val
}

// FundingAssetID returns the asset ID of the underlying asset.
func (t *TxAssetInputProof) FundingAssetID() fn.Option[asset.ID] {
	return fn.Some(t.AssetID.Val)
}

// Amt returns the amount of the asset that this output represents.
func (t *TxAssetInputProof) Amt() fn.Option[uint64] {
	return fn.Some(t.Amount.Val)
}

// A compile time check to ensure TxAssetInputProof implements the
// AssetFundingMsg interface.
var _ AssetFundingMsg = (*TxAssetInputProof)(nil)

// TxAssetOutputProof is sent by the initiator of the funding request *after*
// the inputs proofs. The proof contained in this message is the final signed
// asset funding output. Along with the input proofs, then the responder can
// verify the asset funding output witnesses in full.
type TxAssetOutputProof struct {
	// PendingChanID is the pending channel ID that was assigned to the
	// channel.
	PendingChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// AssetOutput is one of the funding UTXOs that'll be used in channel
	// funding.
	AssetOutput tlv.RecordT[tlv.TlvType1, asset.Asset]

	// Last indicates whether this is the last proof in the funding
	// process.
	Last tlv.RecordT[tlv.TlvType2, bool]
}

// NewTxAssetOutputProof creates a new TxAssetOutputProof message.
func NewTxAssetOutputProof(pid funding.PendingChanID, a asset.Asset,
	last bool) *TxAssetOutputProof {

	return &TxAssetOutputProof{
		PendingChanID: tlv.NewPrimitiveRecord[tlv.TlvType0](pid),
		AssetOutput:   tlv.NewRecordT[tlv.TlvType1](a),
		Last:          tlv.NewPrimitiveRecord[tlv.TlvType2](last),
	}
}

// MsgType returns the type of the message.
func (t *TxAssetOutputProof) MsgType() lnwire.MessageType {
	return TxAssetOutputProofType
}

// Decode reads the bytes stream and converts it to the object.
func (t *TxAssetOutputProof) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.AssetOutput.Record(),
		t.Last.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the write
// buffer.
func (t *TxAssetOutputProof) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.AssetOutput.Record(),
		t.Last.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PID returns the pending channel ID that was assigned to the channel.
func (t *TxAssetOutputProof) PID() funding.PendingChanID {
	return t.PendingChanID.Val
}

// Amt returns the amount of the asset that this output represents.
func (t *TxAssetOutputProof) Amt() fn.Option[uint64] {
	return fn.Some(t.AssetOutput.Val.Amount)
}

// A compile time check to ensure TxAssetOutputProof implements the
// AssetFundingMsg interface.
var _ AssetFundingMsg = (*TxAssetOutputProof)(nil)

// AssetFundingCreated is sent by the initiator of the funding flow after
// they've able to fully finalize the funding transaction. This message will be
// sent before the normal funding_created message.
type AssetFundingCreated struct {
	// PendingChanID is the pending channel ID that was assigned to the
	// channel.
	PendingChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// FundingOutputs are the completed set of funding output proofs. The
	// remote party will use the transition (suffix) proofs encoded in the
	// funding output to be able to create the aux funding+commitment
	// blobs.
	FundingOutputs tlv.RecordT[tlv.TlvType1, AssetOutputListRecord]

	// TODO(roasbeef): need to chunk this??
}

// NewAssetFundingCreated creates a new AssetFundingCreated message.
func NewAssetFundingCreated(pid funding.PendingChanID,
	outputs []*AssetOutput) *AssetFundingCreated {

	return &AssetFundingCreated{
		PendingChanID: tlv.NewPrimitiveRecord[tlv.TlvType0](pid),
		FundingOutputs: tlv.NewRecordT[tlv.TlvType1](
			AssetOutputListRecord{
				Outputs: outputs,
			},
		),
	}
}

// MsgType returns the type of the message.
func (t *AssetFundingCreated) MsgType() lnwire.MessageType {
	return AssetFundingCreatedType
}

// Decode reads the bytes stream and converts it to the object.
func (t *AssetFundingCreated) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.FundingOutputs.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the write
// buffer.
func (t *AssetFundingCreated) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.FundingOutputs.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PID returns the pending channel ID that was assigned to the channel.
func (t *AssetFundingCreated) PID() funding.PendingChanID {
	return t.PendingChanID.Val
}

// Amt returns the amount of the asset that this output represents.
func (t *AssetFundingCreated) Amt() fn.Option[uint64] {
	return fn.Some(t.FundingOutputs.Val.Sum())
}

// AssetFundingAck is sent by the responder of the funding flow after they've
// received the funding input and output proofs. If the responder is able to
// fully validate the proposed funding parameters, then they'll send this method
// with accept=true. Otherwise, they'll send with accept set to false.
type AssetFundingAck struct {
	// PendingChanID is the pending channel ID that was assigned to the
	// channel.
	PendingChanID tlv.RecordT[tlv.TlvType0, funding.PendingChanID]

	// Accept is a boolean that indicates if the responder is able to fully
	// validate the proofs sent in the prior step.
	Accept tlv.RecordT[tlv.TlvType1, bool]
}

// NewAssetFundingAck creates a new AssetFundingAck message.
func NewAssetFundingAck(pid funding.PendingChanID,
	accept bool) *AssetFundingAck {

	return &AssetFundingAck{
		PendingChanID: tlv.NewPrimitiveRecord[tlv.TlvType0](pid),
		Accept:        tlv.NewPrimitiveRecord[tlv.TlvType1](accept),
	}
}

// MsgType returns the type of the message.
func (t *AssetFundingAck) MsgType() lnwire.MessageType {
	return AssetFundingAckType
}

// Decode reads the bytes stream and converts it to the object.
func (t *AssetFundingAck) Decode(r io.Reader, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.Accept.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Decode(r)
}

// Encode converts object to the bytes stream and write it into the write
// buffer.
func (t *AssetFundingAck) Encode(w *bytes.Buffer, _ uint32) error {
	stream, err := tlv.NewStream(
		t.PendingChanID.Record(),
		t.Accept.Record(),
	)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// PID returns the pending channel ID that was assigned to the channel.
func (t *AssetFundingAck) PID() funding.PendingChanID {
	return t.PendingChanID.Val
}

// Amt returns the amount of the asset that this output represents.
func (t *AssetFundingAck) Amt() fn.Option[uint64] {
	return fn.None[uint64]()
}
