package tapchannel

import (
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestVerifySecondLevelSigMissing tests that a verification job that carries
// no signature is only accepted for an HTLC that carries no assets. lnd hands
// us a job for every HTLC of a commitment, signed or not, because only we
// know which of them carry assets. A peer that simply leaves the signature
// of an asset HTLC out must be rejected: without it the second-level asset
// transition of that HTLC cannot be built, neither on our own commitment nor
// after a breach of theirs, which is exactly when the peer would benefit
// from having withheld it.
//
// The asset buckets of a commitment are keyed by HTLC index per direction,
// and both parties count their HTLCs from zero. So whether an HTLC carries
// assets must be decided in the bucket of the job's direction only.
func TestVerifySecondLevelSigMissing(t *testing.T) {
	t.Parallel()

	// The commitment holds assets for the outgoing HTLC with index 0 and
	// nothing else.
	commitTx, assetJob := htlcVerifyJob(t, 1)

	withoutSig := func(job lnwallet.AuxVerifyJob) lnwallet.AuxVerifyJob {
		job.SigBlob = lfn.None[tlv.Blob]()

		return job
	}

	testCases := []struct {
		name    string
		job     func() lnwallet.AuxVerifyJob
		wantErr string
	}{{
		name: "asset HTLC without a sig",
		job: func() lnwallet.AuxVerifyJob {
			return withoutSig(assetJob)
		},
		wantErr: "missing second level sig for asset HTLC",
	}, {
		// The incoming HTLC with the same index carries no assets.
		name: "BTC-only HTLC sharing the index of an asset HTLC",
		job: func() lnwallet.AuxVerifyJob {
			job := withoutSig(assetJob)
			job.Incoming = true

			return job
		},
	}, {
		name: "BTC-only HTLC with another index",
		job: func() lnwallet.AuxVerifyJob {
			job := withoutSig(assetJob)
			job.HTLC.HtlcIndex = 7

			return job
		},
	}, {
		name: "no commit blob",
		job: func() lnwallet.AuxVerifyJob {
			job := withoutSig(assetJob)
			job.CommitBlob = lfn.None[tlv.Blob]()

			return job
		},
	}, {
		// A sig blob that does not decode is rejected even for an
		// HTLC that would not need one.
		name: "BTC-only HTLC with a malformed sig",
		job: func() lnwallet.AuxVerifyJob {
			job := assetJob
			job.Incoming = true
			job.SigBlob = lfn.Some(tlv.Blob{0xff, 0xff, 0xff})

			return job
		},
		wantErr: "error decoding asset sig list record",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := VerifySecondLevelSigs(
				testChainParams, chanState, commitTx,
				[]lnwallet.AuxVerifyJob{tc.job()},
			)
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestSecondLevelHtlcIncoming tests that the direction of the HTLC behind a
// second-level resolution request is taken from the request and never
// guessed. For the sweeps of our own commitment the witness type tells it.
// For a breach it does not, as one type covers both directions, so the
// request must state it, and a request that does not is refused rather than
// resolved with the HTLC of the other direction that happens to share its
// index.
func TestSecondLevelHtlcIncoming(t *testing.T) {
	t.Parallel()

	chanPoint := wire.OutPoint{Index: 1}

	testCases := []struct {
		name         string
		reqType      input.WitnessType
		incoming     lfn.Option[bool]
		wantIncoming bool
		wantErr      string
	}{{
		name:         "local success is incoming",
		reqType:      input.TaprootHtlcAcceptedSuccessSecondLevel,
		wantIncoming: true,
	}, {
		// The stated direction is irrelevant when the type tells it.
		name:         "local success ignores the stated direction",
		reqType:      input.TaprootHtlcAcceptedSuccessSecondLevel,
		incoming:     lfn.Some(false),
		wantIncoming: true,
	}, {
		name:    "local timeout is outgoing",
		reqType: input.TaprootHtlcOfferedTimeoutSecondLevel,
	}, {
		name:         "breach, incoming",
		reqType:      input.TaprootHtlcSecondLevelRevoke,
		incoming:     lfn.Some(true),
		wantIncoming: true,
	}, {
		name:     "breach, outgoing",
		reqType:  input.TaprootHtlcSecondLevelRevoke,
		incoming: lfn.Some(false),
	}, {
		name:    "breach without a direction",
		reqType: input.TaprootHtlcSecondLevelRevoke,
		wantErr: "no HTLC direction",
	}, {
		name:     "not a second-level type",
		reqType:  input.TaprootHtlcOfferedRevoke,
		incoming: lfn.Some(true),
		wantErr:  "is not a second-level HTLC resolution type",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			incoming, err := secondLevelHtlcIncoming(
				lnwallet.ResolutionReq{
					ChanPoint:    chanPoint,
					Type:         tc.reqType,
					HtlcIncoming: tc.incoming,
				},
			)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantIncoming, incoming)
		})
	}
}
