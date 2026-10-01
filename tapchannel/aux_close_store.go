package tapchannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

// ErrNoAuxCloseInfo is returned when no persisted aux close info exists for a
// given channel point.
var ErrNoAuxCloseInfo = errors.New("no persisted aux close info")

// closeAssetOutput identifies an asset carrying output of a co-op close
// transaction candidate: its index and pkScript. FinalizeClose uses these to
// find the candidate that matches the transaction that confirmed, as with the
// RBF close flow there can be several candidates per channel.
type closeAssetOutput struct {
	outputIndex uint32
	pkScript    []byte
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

	// assetOutputs are the asset carrying outputs of this close candidate,
	// used to match the candidate against the confirmed transaction.
	assetOutputs []closeAssetOutput

	// closeFee is the BTC fee paid for the cooperative close transaction.
	closeFee int64

	// supportSTXO records whether STXO proofs were enabled for the
	// channel at AuxCloseOutputs time. The negotiator's feature map is
	// in-memory only and would default to "no STXO" after a restart,
	// causing the recovery path to compute different commitments and
	// proofs. We persist this explicitly so the post-restart pipeline
	// replay matches the original run.
	supportSTXO bool
}

// noAssetAlloc is the minimal serializable subset of tapsend.Allocation we
// need for non-asset (P2TR BIP-86) outputs at finalize time.
type noAssetAlloc struct {
	outputIndex uint32
	internalKey *btcec.PublicKey
}

// AuxCloseStore persists per-channel close info across restarts so that
// FinalizeClose can recover when the in-memory closeInfo map has been wiped.
// A channel can have several close candidates, one per RBF close round, as
// any of them may end up confirming.
type AuxCloseStore interface {
	// Put writes the close candidates for the given channel point. Any
	// existing entry is overwritten.
	Put(ctx context.Context, chanPoint wire.OutPoint,
		infos []*persistedCloseInfo) error

	// Get returns the persisted close candidates for the given channel
	// point. Returns ErrNoAuxCloseInfo if no entry exists.
	Get(ctx context.Context,
		chanPoint wire.OutPoint) ([]*persistedCloseInfo, error)

	// Delete removes the persisted close info for the given channel
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
	infos []*persistedCloseInfo) error {

	var buf bytes.Buffer
	if err := encodeCloseInfos(&buf, infos); err != nil {
		return fmt.Errorf("encode close info: %w", err)
	}

	return s.blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes())
}

// Get implements AuxCloseStore.
func (s *SQLAuxCloseStore) Get(ctx context.Context,
	chanPoint wire.OutPoint) ([]*persistedCloseInfo, error) {

	blob, err := s.blobs.FetchAuxCloseBlob(ctx, chanPoint)
	switch {
	case errors.Is(err, s.errBlobNotFound):
		return nil, ErrNoAuxCloseInfo
	case err != nil:
		return nil, fmt.Errorf("fetch aux close blob: %w", err)
	}

	infos, err := decodeCloseInfos(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("decode close info: %w", err)
	}

	return infos, nil
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

	// maxCloseCandidates caps the number of close candidates we keep per
	// channel. Each RBF close round adds one, and the oldest ones are
	// the lowest fee ones that have long been replaced in the mempool, so
	// those are dropped first.
	maxCloseCandidates = 64
)

// --- encoding ---

// File format (all integers big-endian):
//
//	uint8   format version (currently 3)
//	uint32  numCandidates
//	  per candidate:
//	    int64   closeFee
//	    uint8   supportSTXO (0 or 1)
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
//	    uint32  numAssetOutputs
//	      per assetOutput:
//	        uint32 outputIndex
//	        uint16 pkScript length
//	        bytes  pkScript
//
// Version 2 blobs hold a single candidate without the numCandidates prefix
// and without the asset outputs, and are still read.
const (
	closeInfoFormatVersion       uint8 = 3
	closeInfoFormatVersionSingle uint8 = 2
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

// encodeCloseInfos writes the given close candidates in the current format.
func encodeCloseInfos(w io.Writer, infos []*persistedCloseInfo) error {
	if len(infos) > maxCloseCandidates {
		return fmt.Errorf("close candidate count %d exceeds cap %d",
			len(infos), maxCloseCandidates)
	}

	err := binary.Write(w, binary.BigEndian, closeInfoFormatVersion)
	if err != nil {
		return err
	}
	if err := binary.Write(
		w, binary.BigEndian, uint32(len(infos)),
	); err != nil {
		return err
	}

	for _, info := range infos {
		if err := encodeCloseInfoBody(w, info); err != nil {
			return err
		}
		if err := writeAssetOutputs(w, info.assetOutputs); err != nil {
			return err
		}
	}

	return nil
}

// encodeCloseInfoBody writes the fields of a single candidate that are shared
// between the single candidate (version 2) and the list (version 3) formats.
func encodeCloseInfoBody(w io.Writer, info *persistedCloseInfo) error {
	if err := binary.Write(w, binary.BigEndian, info.closeFee); err != nil {
		return err
	}
	var stxoByte uint8
	if info.supportSTXO {
		stxoByte = 1
	}
	if err := binary.Write(w, binary.BigEndian, stxoByte); err != nil {
		return err
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

// decodeCloseInfos reads close candidates in either the current or the
// previous single candidate format.
func decodeCloseInfos(r io.Reader) ([]*persistedCloseInfo, error) {
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, err
	}

	switch version {
	// The previous format holds a single candidate without asset
	// outputs. Such a candidate was written before RBF closes were
	// supported, so it's the only one there is for the channel.
	case closeInfoFormatVersionSingle:
		info, err := decodeCloseInfoBody(r)
		if err != nil {
			return nil, err
		}

		return []*persistedCloseInfo{info}, nil

	case closeInfoFormatVersion:
		var count uint32
		if err := binary.Read(
			r, binary.BigEndian, &count,
		); err != nil {
			return nil, err
		}
		if count > maxCloseCandidates {
			return nil, fmt.Errorf("close candidate count %d "+
				"exceeds cap %d", count, maxCloseCandidates)
		}

		infos := make([]*persistedCloseInfo, 0, count)
		for i := uint32(0); i < count; i++ {
			info, err := decodeCloseInfoBody(r)
			if err != nil {
				return nil, err
			}

			info.assetOutputs, err = readAssetOutputs(r)
			if err != nil {
				return nil, fmt.Errorf("read asset "+
					"outputs: %w", err)
			}

			infos = append(infos, info)
		}

		return infos, nil

	default:
		return nil, fmt.Errorf(
			"unsupported close info version %d", version,
		)
	}
}

// decodeCloseInfoBody reads the fields of a single candidate that are shared
// between the single candidate and the list formats.
func decodeCloseInfoBody(r io.Reader) (*persistedCloseInfo, error) {
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
	info.supportSTXO = stxoByte != 0

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
