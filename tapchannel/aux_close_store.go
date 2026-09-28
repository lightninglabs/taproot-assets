package tapchannel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

// ErrNoAuxCloseInfo is returned when no persisted aux close info exists for a
// given channel point.
var ErrNoAuxCloseInfo = errors.New("no persisted aux close info")

// closeAssetOutput is an asset carrying output of the co-op close
// transaction: its index, script, BTC value and the party it belongs to.
// FinalizeClose uses the index and script to make sure the transaction that
// confirmed is the one the close info was built for, and the RBF close flow
// rebuilds the close outputs of its template from them.
type closeAssetOutput struct {
	outputIndex uint32
	pkScript    []byte
	value       int64
	isLocal     bool
}

// closeTemplateID identifies the close template of an RBF close negotiation:
// a hash over everything the asset outputs of the close transaction depend
// on. A close info built with the legacy close flow has a zero ID.
type closeTemplateID [sha256.Size]byte

// IsZero returns true if no template ID is set.
func (c closeTemplateID) IsZero() bool {
	return c == closeTemplateID{}
}

// persistedChanClose is the close state persisted for a channel: the
// shutdown records we sent, and the close info once the asset outputs of the
// close transaction are built.
type persistedChanClose struct {
	// shutdownMsg are the shutdown records we sent for the channel, if
	// any. A shutdown that is sent again, after a reconnect or a restart,
	// carries the same keys, as the asset outputs of the close commit to
	// them.
	shutdownMsg *tapchannelmsg.AuxShutdownMsg

	// closeInfo is the close info of the channel, nil until the asset
	// outputs of the close transaction are built.
	closeInfo *persistedCloseInfo
}

// persistedCloseInfo carries the minimum state needed to reconstruct an
// assetCloseInfo entry after a tapd restart between AuxCloseOutputs and
// FinalizeClose.
//
// We persist *two* copies of the vPackets: the pristine pre-mutation set is
// fed back through CreateOutputCommitments at finalize time to rebuild the
// output commitments map deterministically; the post-mutation set is used
// directly as the FinalizeClose vPackets so we don't have to re-run
// PrepareOutputAssets / UpdateTxWitness (which would risk subtle byte-level
// divergence from the originally-broadcast state).
type persistedCloseInfo struct {
	// vPackets is the post-mutation list — exactly the vPackets that
	// were originally stashed in the in-memory closeInfo.
	vPackets []*tappsbt.VPacket

	// pristineVPackets is a clone of the vPackets taken right after
	// CommitmentToPackets, before any of the downstream mutators
	// (signCommitVirtualPackets, CreateOutputCommitments) touched them.
	// Replaying CreateOutputCommitments on a fresh clone of these gives
	// us the same output commitments without double-mutating anything.
	pristineVPackets []*tappsbt.VPacket

	// noAssetAllocs is the slice of AllocationTypeNoAssets allocations.
	// FinalizeClose only consults these (via NonAssetExclusionProofs), so
	// we don't need to round-trip the asset-typed allocations.
	noAssetAllocs []noAssetAlloc

	// assetOutputs are the asset carrying outputs of the close
	// transaction this close info was built for.
	assetOutputs []closeAssetOutput

	// templateID identifies the close template this close info is, if it
	// was built for the RBF close flow. Zero for the legacy close flow.
	templateID closeTemplateID

	// closeFee is the BTC fee paid for the cooperative close transaction.
	closeFee int64

	// stxoFeatures records which STXO related leaves were enabled for
	// the channel at AuxCloseOutputs time. The negotiator's feature map
	// is in-memory only and would default to "no STXO" after a restart,
	// causing the recovery path to compute different commitments and
	// proofs. We persist this explicitly so the post-restart pipeline
	// replay matches the original run.
	stxoFeatures STXOFeatures
}

// noAssetAlloc is the minimal serializable subset of tapsend.Allocation we
// need for non-asset (P2TR BIP-86) outputs at finalize time.
type noAssetAlloc struct {
	outputIndex uint32
	internalKey *btcec.PublicKey
}

// AuxCloseStore persists the close state of a channel across restarts: the
// shutdown records to send again, and the close info FinalizeClose needs
// once the in-memory state is gone.
type AuxCloseStore interface {
	// Put writes the close state of the given channel point. Any
	// existing entry is overwritten.
	Put(ctx context.Context, chanPoint wire.OutPoint,
		chanClose *persistedChanClose) error

	// Get returns the persisted close state of the given channel point.
	// Returns ErrNoAuxCloseInfo if no entry exists.
	Get(ctx context.Context,
		chanPoint wire.OutPoint) (*persistedChanClose, error)

	// Delete removes the persisted close state of the given channel
	// point. A delete of a non-existent entry is a no-op.
	Delete(ctx context.Context, chanPoint wire.OutPoint) error
}

// AuxCloseBlobStore is the byte-level dependency the SQL-backed AuxCloseStore
// wraps. tapdb's PersistedAuxCloseStore satisfies it via duck typing — we
// don't import tapdb here so as not to bake the storage choice into the
// consumer.
type AuxCloseBlobStore interface {
	PutAuxCloseBlob(ctx context.Context, chanPoint wire.OutPoint,
		blob []byte) error

	FetchAuxCloseBlob(ctx context.Context,
		chanPoint wire.OutPoint) ([]byte, error)

	DeleteAuxCloseBlob(ctx context.Context, chanPoint wire.OutPoint) error
}

// SQLAuxCloseStore implements AuxCloseStore on top of a byte-level
// AuxCloseBlobStore. The on-disk encoding lives here in the consumer
// package; the storage layer just sees opaque blobs keyed by channel point.
type SQLAuxCloseStore struct {
	blobs AuxCloseBlobStore

	// errBlobNotFound is the error the wrapped store returns when no
	// blob exists for a key. We translate it to ErrNoAuxCloseInfo so
	// callers don't have to import the storage package's sentinel.
	errBlobNotFound error
}

// NewSQLAuxCloseStore wraps the given blob store. errNotFound is the sentinel
// the blob store returns on a missing key (e.g., tapdb.ErrNoAuxCloseInfo).
func NewSQLAuxCloseStore(blobs AuxCloseBlobStore,
	errNotFound error) *SQLAuxCloseStore {

	return &SQLAuxCloseStore{
		blobs:           blobs,
		errBlobNotFound: errNotFound,
	}
}

// Put implements AuxCloseStore.
func (s *SQLAuxCloseStore) Put(ctx context.Context, chanPoint wire.OutPoint,
	chanClose *persistedChanClose) error {

	var buf bytes.Buffer
	if err := encodeChanClose(&buf, chanClose); err != nil {
		return fmt.Errorf("encode close info: %w", err)
	}

	return s.blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes())
}

// Get implements AuxCloseStore.
func (s *SQLAuxCloseStore) Get(ctx context.Context,
	chanPoint wire.OutPoint) (*persistedChanClose, error) {

	blob, err := s.blobs.FetchAuxCloseBlob(ctx, chanPoint)
	switch {
	case errors.Is(err, s.errBlobNotFound):
		return nil, ErrNoAuxCloseInfo
	case err != nil:
		return nil, fmt.Errorf("fetch aux close blob: %w", err)
	}

	chanClose, err := decodeChanClose(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("decode close info: %w", err)
	}

	return chanClose, nil
}

// Delete implements AuxCloseStore.
func (s *SQLAuxCloseStore) Delete(ctx context.Context,
	chanPoint wire.OutPoint) error {

	return s.blobs.DeleteAuxCloseBlob(ctx, chanPoint)
}

// Sanity caps on length-prefixed fields in the on-disk encoding. The data
// flows in from a local DB so this isn't a remote-attacker vector, but a
// corrupt row shouldn't be able to wedge a daemon with a multi-gigabyte
// allocation. The caps are far above any plausible coop close shape.
const (
	maxVPacketCount      = 64
	maxVPacketBytes      = 1 << 20 // 1 MiB per packet.
	maxNoAssetAllocCount = 16
	maxAssetOutputCount  = 16
	maxPkScriptBytes     = 1000
	maxShutdownMsgBytes  = 1 << 16
)

// --- encoding ---

// File format (all integers big-endian):
//
//	uint8   format version (currently 4)
//	uint8   hasShutdownMsg (0 or 1)
//	  if set:
//	    uint32  length
//	    bytes   AuxShutdownMsg encoding
//	uint8   hasCloseInfo (0 or 1)
//	  if set:
//	    int64   closeFee
//	    uint8   supportSTXO (0 or 1)
//	    uint8   supportSpender (0 or 1, version 3 and up)
//	    uint32  numVPackets         (post-mutation)
//	      per vPacket:
//	        uint32 length
//	        bytes  VPacket.Serialize output
//	    uint32  numPristineVPackets (pre-mutation)
//	      per vPacket: same encoding as above
//	    uint32  numNoAssetAllocs
//	      per noAssetAlloc:
//	        uint32 outputIndex
//	        [33]byte compressed internalKey
//	    [32]byte templateID
//	    uint32  numAssetOutputs
//	      per assetOutput:
//	        uint32 outputIndex
//	        int64  value
//	        uint8  isLocal (0 or 1)
//	        uint16 pkScript length
//	        bytes  pkScript
//
// Version 2 and 3 blobs hold the close info alone, without the shutdown
// records, the template ID and the asset outputs, and are still read.
// Version 2 additionally lacks the spender flag.
const (
	closeInfoFormatVersion       uint8 = 4
	closeInfoFormatVersionSingle uint8 = 3
	closeInfoFormatVersionSTXO   uint8 = 2
)

func writeVPacketList(w io.Writer, pkts []*tappsbt.VPacket) error {
	if err := binary.Write(
		w, binary.BigEndian, uint32(len(pkts)),
	); err != nil {
		return err
	}
	for _, p := range pkts {
		var pktBuf bytes.Buffer
		if err := p.Serialize(&pktBuf); err != nil {
			return fmt.Errorf("serialize vPacket: %w", err)
		}
		if err := binary.Write(
			w, binary.BigEndian, uint32(pktBuf.Len()),
		); err != nil {
			return err
		}
		if _, err := w.Write(pktBuf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func readVPacketList(r io.Reader) ([]*tappsbt.VPacket, error) {
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > maxVPacketCount {
		return nil, fmt.Errorf("vPacket count %d exceeds cap %d",
			count, maxVPacketCount)
	}
	out := make([]*tappsbt.VPacket, 0, count)
	for i := uint32(0); i < count; i++ {
		var sz uint32
		if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
			return nil, err
		}
		if sz > maxVPacketBytes {
			return nil, fmt.Errorf("vPacket size %d exceeds "+
				"cap %d", sz, maxVPacketBytes)
		}
		buf := make([]byte, sz)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		pkt, err := tappsbt.NewFromRawBytes(bytes.NewReader(buf), false)
		if err != nil {
			return nil, fmt.Errorf("deserialize vPacket: %w", err)
		}
		out = append(out, pkt)
	}

	return out, nil
}

// encodeChanClose writes the given close state in the current format.
func encodeChanClose(w io.Writer, chanClose *persistedChanClose) error {
	err := binary.Write(w, binary.BigEndian, closeInfoFormatVersion)
	if err != nil {
		return err
	}

	if err := writeFlag(w, chanClose.shutdownMsg != nil); err != nil {
		return err
	}
	if chanClose.shutdownMsg != nil {
		var msgBuf bytes.Buffer
		if err := chanClose.shutdownMsg.Encode(&msgBuf); err != nil {
			return fmt.Errorf("encode shutdown msg: %w", err)
		}
		if msgBuf.Len() > maxShutdownMsgBytes {
			return fmt.Errorf("shutdown msg size %d exceeds cap "+
				"%d", msgBuf.Len(), maxShutdownMsgBytes)
		}
		if err := binary.Write(
			w, binary.BigEndian, uint32(msgBuf.Len()),
		); err != nil {
			return err
		}
		if _, err := w.Write(msgBuf.Bytes()); err != nil {
			return err
		}
	}

	if err := writeFlag(w, chanClose.closeInfo != nil); err != nil {
		return err
	}
	if chanClose.closeInfo == nil {
		return nil
	}

	info := chanClose.closeInfo
	if err := encodeCloseInfoBody(w, info, true); err != nil {
		return err
	}
	if _, err := w.Write(info.templateID[:]); err != nil {
		return err
	}

	return writeAssetOutputs(w, info.assetOutputs)
}

// writeFlag writes a boolean as a single byte.
func writeFlag(w io.Writer, flag bool) error {
	var b uint8
	if flag {
		b = 1
	}

	return binary.Write(w, binary.BigEndian, b)
}

// readFlag reads a boolean written by writeFlag.
func readFlag(r io.Reader) (bool, error) {
	var b uint8
	if err := binary.Read(r, binary.BigEndian, &b); err != nil {
		return false, err
	}

	return b != 0, nil
}

// encodeCloseInfoBody writes the fields of a single candidate that are shared
// between the single candidate (versions 2 and 3) and the list (version 4)
// formats. The spender flag is only part of the body from version 3 on.
func encodeCloseInfoBody(w io.Writer, info *persistedCloseInfo,
	withSpender bool) error {

	if err := binary.Write(w, binary.BigEndian, info.closeFee); err != nil {
		return err
	}
	var stxoByte, spenderByte uint8
	if info.stxoFeatures.STXO {
		stxoByte = 1
	}
	if info.stxoFeatures.Spender {
		spenderByte = 1
	}
	if err := binary.Write(w, binary.BigEndian, stxoByte); err != nil {
		return err
	}
	if withSpender {
		err := binary.Write(w, binary.BigEndian, spenderByte)
		if err != nil {
			return err
		}
	}
	if err := writeVPacketList(w, info.vPackets); err != nil {
		return err
	}
	if err := writeVPacketList(w, info.pristineVPackets); err != nil {
		return err
	}
	if err := binary.Write(
		w, binary.BigEndian, uint32(len(info.noAssetAllocs)),
	); err != nil {
		return err
	}
	for _, a := range info.noAssetAllocs {
		if a.internalKey == nil {
			return fmt.Errorf("internal key nil for " +
				"non-asset alloc")
		}
		if err := binary.Write(
			w, binary.BigEndian, a.outputIndex,
		); err != nil {
			return err
		}
		if _, err := w.Write(
			a.internalKey.SerializeCompressed(),
		); err != nil {
			return err
		}
	}

	return nil
}

func writeAssetOutputs(w io.Writer, outputs []closeAssetOutput) error {
	if err := binary.Write(
		w, binary.BigEndian, uint32(len(outputs)),
	); err != nil {
		return err
	}
	for _, out := range outputs {
		if len(out.pkScript) > maxPkScriptBytes {
			return fmt.Errorf("pkScript size %d exceeds cap %d",
				len(out.pkScript), maxPkScriptBytes)
		}
		if err := binary.Write(
			w, binary.BigEndian, out.outputIndex,
		); err != nil {
			return err
		}
		if err := binary.Write(
			w, binary.BigEndian, out.value,
		); err != nil {
			return err
		}
		if err := writeFlag(w, out.isLocal); err != nil {
			return err
		}
		if err := binary.Write(
			w, binary.BigEndian, uint16(len(out.pkScript)),
		); err != nil {
			return err
		}
		if _, err := w.Write(out.pkScript); err != nil {
			return err
		}
	}

	return nil
}

func readAssetOutputs(r io.Reader) ([]closeAssetOutput, error) {
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > maxAssetOutputCount {
		return nil, fmt.Errorf("asset output count %d exceeds cap %d",
			count, maxAssetOutputCount)
	}
	out := make([]closeAssetOutput, 0, count)
	for i := uint32(0); i < count; i++ {
		var entry closeAssetOutput
		if err := binary.Read(
			r, binary.BigEndian, &entry.outputIndex,
		); err != nil {
			return nil, err
		}
		if err := binary.Read(
			r, binary.BigEndian, &entry.value,
		); err != nil {
			return nil, err
		}
		isLocal, err := readFlag(r)
		if err != nil {
			return nil, err
		}
		entry.isLocal = isLocal
		var sz uint16
		if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
			return nil, err
		}
		if sz > maxPkScriptBytes {
			return nil, fmt.Errorf("pkScript size %d exceeds "+
				"cap %d", sz, maxPkScriptBytes)
		}
		entry.pkScript = make([]byte, sz)
		if _, err := io.ReadFull(r, entry.pkScript); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}

	return out, nil
}

// decodeChanClose reads the close state in either the current or one of the
// previous formats.
func decodeChanClose(r io.Reader) (*persistedChanClose, error) {
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, err
	}

	switch version {
	// The previous formats hold the close info alone, without the asset
	// outputs. The spender flag was recorded from version 3 on, any
	// earlier close predates the spender leaves.
	case closeInfoFormatVersionSTXO, closeInfoFormatVersionSingle:
		withSpender := version >= closeInfoFormatVersionSingle
		info, err := decodeCloseInfoBody(r, withSpender)
		if err != nil {
			return nil, err
		}

		return &persistedChanClose{closeInfo: info}, nil

	case closeInfoFormatVersion:
		var chanClose persistedChanClose

		hasShutdown, err := readFlag(r)
		if err != nil {
			return nil, err
		}
		if hasShutdown {
			var sz uint32
			err := binary.Read(r, binary.BigEndian, &sz)
			if err != nil {
				return nil, err
			}
			if sz > maxShutdownMsgBytes {
				return nil, fmt.Errorf("shutdown msg size %d "+
					"exceeds cap %d", sz,
					maxShutdownMsgBytes)
			}
			buf := make([]byte, sz)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}

			var msg tapchannelmsg.AuxShutdownMsg
			err = msg.Decode(bytes.NewReader(buf))
			if err != nil {
				return nil, fmt.Errorf("decode shutdown "+
					"msg: %w", err)
			}
			chanClose.shutdownMsg = &msg
		}

		hasCloseInfo, err := readFlag(r)
		if err != nil {
			return nil, err
		}
		if !hasCloseInfo {
			return &chanClose, nil
		}

		info, err := decodeCloseInfoBody(r, true)
		if err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, info.templateID[:]); err != nil {
			return nil, err
		}
		info.assetOutputs, err = readAssetOutputs(r)
		if err != nil {
			return nil, fmt.Errorf("read asset outputs: %w", err)
		}
		chanClose.closeInfo = info

		return &chanClose, nil

	default:
		return nil, fmt.Errorf(
			"unsupported close info version %d", version,
		)
	}
}

// decodeCloseInfoBody reads the fields of a single candidate that are shared
// between the single candidate and the list formats.
func decodeCloseInfoBody(r io.Reader,
	withSpender bool) (*persistedCloseInfo, error) {

	info := &persistedCloseInfo{}
	if err := binary.Read(
		r, binary.BigEndian, &info.closeFee,
	); err != nil {
		return nil, err
	}

	var stxoByte uint8
	if err := binary.Read(r, binary.BigEndian, &stxoByte); err != nil {
		return nil, err
	}
	info.stxoFeatures.STXO = stxoByte != 0

	if withSpender {
		var spenderByte uint8
		err := binary.Read(r, binary.BigEndian, &spenderByte)
		if err != nil {
			return nil, err
		}
		info.stxoFeatures.Spender = spenderByte != 0
	}

	pkts, err := readVPacketList(r)
	if err != nil {
		return nil, fmt.Errorf("read vPackets: %w", err)
	}
	info.vPackets = pkts

	pristine, err := readVPacketList(r)
	if err != nil {
		return nil, fmt.Errorf("read pristine vPackets: %w", err)
	}
	info.pristineVPackets = pristine

	var numAllocs uint32
	if err := binary.Read(r, binary.BigEndian, &numAllocs); err != nil {
		return nil, err
	}
	if numAllocs > maxNoAssetAllocCount {
		return nil, fmt.Errorf("no-asset alloc count %d exceeds "+
			"cap %d", numAllocs, maxNoAssetAllocCount)
	}
	info.noAssetAllocs = make([]noAssetAlloc, 0, numAllocs)
	for i := uint32(0); i < numAllocs; i++ {
		var entry noAssetAlloc
		if err := binary.Read(
			r, binary.BigEndian, &entry.outputIndex,
		); err != nil {
			return nil, err
		}
		var keyBuf [33]byte
		if _, err := io.ReadFull(r, keyBuf[:]); err != nil {
			return nil, err
		}
		key, err := btcec.ParsePubKey(keyBuf[:])
		if err != nil {
			return nil, fmt.Errorf("parse internal key: %w", err)
		}
		entry.internalKey = key
		info.noAssetAllocs = append(info.noAssetAllocs, entry)
	}

	return info, nil
}

// allocsFromNoAssetAllocs reconstructs a minimal []*tapsend.Allocation that's
// sufficient for NonAssetExclusionProofs.
func allocsFromNoAssetAllocs(
	entries []noAssetAlloc) []*tapsend.Allocation {

	out := make([]*tapsend.Allocation, len(entries))
	for i, e := range entries {
		out[i] = &tapsend.Allocation{
			Type:        tapsend.AllocationTypeNoAssets,
			OutputIndex: e.outputIndex,
			InternalKey: e.internalKey,
		}
	}

	return out
}

// extractNoAssetAllocs returns the persistable subset of the given allocations
// — i.e. the AllocationTypeNoAssets entries with the fields FinalizeClose
// actually reads.
func extractNoAssetAllocs(
	allocs []*tapsend.Allocation) []noAssetAlloc {

	var out []noAssetAlloc
	for _, a := range allocs {
		if a.Type != tapsend.AllocationTypeNoAssets {
			continue
		}
		out = append(out, noAssetAlloc{
			outputIndex: a.OutputIndex,
			internalKey: a.InternalKey,
		})
	}

	return out
}
