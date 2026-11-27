package tapchannel

import (
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/tlv"
)

// DefaultHtlcStashSize is the default maximum number of commitments the
// HTLC stash holds. lnd fetches the aux leaves of a commitment right
// before it asks us to resolve any output of that commitment, so the
// entries relevant to an ongoing close are always among the most recently
// written ones.
const DefaultHtlcStashSize = 1024

// HtlcDescriptor describes a single HTLC that was in flight on a
// commitment transaction, as reported by lnd from its channel state. This
// is all the data needed to re-derive the HTLC's output script tree.
type HtlcDescriptor struct {
	// RHash is the payment hash of the HTLC.
	RHash [32]byte

	// Timeout is the absolute CLTV timeout of the HTLC.
	Timeout uint32

	// Index is the HTLC index within the channel.
	Index input.HtlcIndex

	// Incoming is true if we are the receiver of the HTLC.
	Incoming bool
}

// commitHtlcs is the stashed HTLC set of a single commitment transaction.
type commitHtlcs struct {
	// whoseCommit denotes which party's commitment this is.
	whoseCommit lntypes.ChannelParty

	// htlcs are the HTLCs that were in flight on the commitment.
	htlcs []HtlcDescriptor
}

// CommitHtlcStash records the HTLC sets of channel commitments, as
// reported by lnd when it fetches the auxiliary leaves of a commitment.
// Our own commitment blob only records HTLCs that carry assets, so the
// descriptors of plain BTC-only HTLCs would otherwise be unavailable when
// importing a force-closed commitment transaction.
type CommitHtlcStash struct {
	mu sync.Mutex

	// entries maps a commitment transaction hash to its HTLC set.
	entries map[chainhash.Hash]commitHtlcs

	// order holds the entry keys in insertion order, for eviction.
	order []chainhash.Hash

	// maxSize is the maximum number of entries held at once.
	maxSize int
}

// NewCommitHtlcStash creates a new stash that holds at most maxSize
// entries, evicting the oldest ones first.
func NewCommitHtlcStash(maxSize int) *CommitHtlcStash {
	return &CommitHtlcStash{
		entries: make(map[chainhash.Hash]commitHtlcs),
		maxSize: maxSize,
	}
}

// stash records the HTLC set of a commitment under the given transaction
// hash.
func (s *CommitHtlcStash) stash(txid chainhash.Hash, entry commitHtlcs) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[txid]; !ok {
		s.order = append(s.order, txid)
	}
	s.entries[txid] = entry

	for len(s.order) > s.maxSize {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, oldest)
	}
}

// Fetch returns the stashed HTLC set of the commitment transaction with
// the given hash, if known.
func (s *CommitHtlcStash) Fetch(
	txid chainhash.Hash) (lntypes.ChannelParty, []HtlcDescriptor, bool) {

	if s == nil {
		return lntypes.Local, nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[txid]
	if !ok {
		return lntypes.Local, nil, false
	}

	return entry.whoseCommit, entry.htlcs, true
}

// StashCommitHtlcs records the HTLC set of the given commitment, as
// reported by lnd from its channel state.
func StashCommitHtlcs(stash *CommitHtlcStash, com channeldb.ChannelCommitment,
	whoseCommit lntypes.ChannelParty) {

	if com.CommitTx == nil {
		return
	}

	htlcs := make([]HtlcDescriptor, 0, len(com.Htlcs))
	for _, htlc := range com.Htlcs {
		htlcs = append(htlcs, HtlcDescriptor{
			RHash:    htlc.RHash,
			Timeout:  htlc.RefundTimeout,
			Index:    htlc.HtlcIndex,
			Incoming: htlc.Incoming,
		})
	}

	stash.stash(com.CommitTx.TxHash(), commitHtlcs{
		whoseCommit: whoseCommit,
		htlcs:       htlcs,
	})
}

// StashRevokedHtlcs records the HTLC set of the given revoked
// (remote) commitment, as reported by lnd from its channel state.
func StashRevokedHtlcs(stash *CommitHtlcStash,
	revocation *channeldb.RevocationLog) {

	htlcs := make([]HtlcDescriptor, 0, len(revocation.HTLCEntries))
	for _, entry := range revocation.HTLCEntries {
		var htlcIndex uint64
		entry.HtlcIndex.ValOpt().WhenSome(
			func(idx tlv.BigSizeT[uint64]) {
				htlcIndex = idx.Int()
			},
		)

		htlcs = append(htlcs, HtlcDescriptor{
			RHash:    [32]byte(entry.RHash.Val),
			Timeout:  entry.RefundTimeout.Val,
			Incoming: entry.Incoming.Val,
			Index:    htlcIndex,
		})
	}

	// A revoked commitment is always a past state of the remote party.
	stash.stash(revocation.CommitTxHash.Val, commitHtlcs{
		whoseCommit: lntypes.Remote,
		htlcs:       htlcs,
	})
}
