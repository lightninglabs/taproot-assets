package supplyverifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/protofsm"
)

// ProcessEvent handles the initial state transition for the supply verifier.
func (s *InitState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch event.(type) {
	case *InitEvent:
		ctx := context.Background()

		// First, we'll query local db for the latest verified supply
		// commitment.
		latestCommit, err := env.SupplyCommitView.FetchLatestCommitment(
			ctx, env.AssetSpec,
		)
		switch {
		case errors.Is(err, ErrCommitmentNotFound):
			// If we don't have a supply commitment in our local db,
			// then we will kick things off by syncing supply
			// commitment proofs to catch up.
			return &StateTransition{
				NextState: &SyncVerifyState{},
				NewEvents: lfn.Some(FsmEvent{
					InternalEvent: []Event{
						&SyncVerifyEvent{},
					},
				}),
			}, nil

		case err != nil:
			return nil, fmt.Errorf("unable to fetch latest "+
				"verified commitment from db: %w", err)
		}

		// If we do have a prior verified commitment, then we'll
		// construct a watch event to watch for its spend, and also any
		// other un-spent pre-commitments.
		preCommits, err := env.SupplyCommitView.UnspentPrecommits(
			ctx, env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch unspent "+
				"pre-commitments: %w", err)
		}

		return &StateTransition{
			NextState: &WatchOutputsState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&WatchOutputsEvent{
						PreCommits:   preCommits,
						SupplyCommit: latestCommit,
					},
				},
			}),
		}, nil

	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, s)
	}
}

// ProcessEvent handles state transitions for the SyncVerifyState.
func (s *SyncVerifyState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *SyncVerifyEvent:
		ctx := context.Background()

		// Check to ensure that we haven't already processed a supply
		// commitment for the spent outpoint, if one was provided.
		if e.SpentCommitOutpoint.IsSome() {
			spentOutpoint, err := e.SpentCommitOutpoint.UnwrapOrErr(
				fmt.Errorf("no outpoint"),
			)
			if err != nil {
				return nil, err
			}

			commit, err := env.SupplyCommitView.
				FetchCommitmentBySpentOutpoint(
					ctx, env.AssetSpec, spentOutpoint,
				)
			switch {
			case errors.Is(err, ErrCommitmentNotFound):
				// This is the expected case, so we can
				// continue.
			case err != nil:
				return nil, fmt.Errorf("unable to query "+
					"db for commitment: %w", err)
			}

			// If we found a commitment, then we've already
			// processed this supply commit, so we can
			// transition to the watch state.
			watchEvent := WatchOutputsEvent{
				SupplyCommit: commit,
			}
			return &StateTransition{
				NextState: &WatchOutputsState{},
				NewEvents: lfn.Some(FsmEvent{
					InternalEvent: []Event{
						&watchEvent,
					},
				}),
			}, nil
		}

		// If we reach this point, then we need to actually sync pull
		// supply commitment(s).
		//
		// Retrieve latest canonical universe list from the latest
		// metadata for the asset group.
		metadata, err := supplycommit.FetchLatestAssetMetadata(
			ctx, env.AssetLookup, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch latest asset "+
				"metadata: %w", err)
		}

		canonicalUniverses := metadata.CanonicalUniverses.UnwrapOr(
			[]url.URL{},
		)

		res, err := env.SupplySyncer.PullSupplyCommitment(
			ctx, env.AssetSpec, e.SpentCommitOutpoint,
			canonicalUniverses,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to pull supply "+
				"commitment: %w", err)
		}

		// Verify the pulled commitment.
		supplyCommit, err := res.FetchResult.UnwrapOrErr(
			fmt.Errorf("no commitment found"),
		)
		if err != nil {
			return nil, err
		}

		verifier, err := NewVerifier(
			env.Chain, env.SupplyCommitView, env.SupplyTreeView,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create verifier: %w",
				err)
		}

		err = verifier.VerifyCommit(
			ctx, env.AssetSpec, supplyCommit.RootCommitment,
			supplyCommit.SupplyLeaves,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to verify supply "+
				"commitment: %w", err)
		}

		// Store the verified commitment.
		err = env.SupplyCommitView.InsertSupplyCommit(
			ctx, env.AssetSpec, supplyCommit.RootCommitment,
			supplyCommit.SupplyLeaves,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to store supply "+
				"commitment: %w", err)
		}

		// Now that we've synced and verified the latest commitment,
		// we'll transition to the watch state to await spends of this
		// commitment.
		watchEvent := WatchOutputsEvent{
			SupplyCommit: &supplyCommit.RootCommitment,
		}
		return &StateTransition{
			NextState: &WatchOutputsState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&watchEvent,
				},
			}),
		}, nil

	case *SpendEvent:
		// TODO(ffranr): This is basically the same as SyncVerifyEvent
		//  but we add a delay before syncing because the issuer may not
		//  have published the supply commitment yet.

		var spentCommitOutpoint fn.Option[wire.OutPoint]
		if e.SpentSupplyCommitment != nil {
			spentCommitOutpoint = fn.Some(
				e.SpentSupplyCommitment.CommitPoint(),
			)
		}

		syncEvent := SyncVerifyEvent{
			SpentCommitOutpoint: spentCommitOutpoint,
		}
		return &StateTransition{
			NextState: &SyncVerifyState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&syncEvent,
				},
			}),
		}, nil

	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, s)
	}
}

// ProcessEvent handles the state transition for the WatchOutputsState.
func (s *WatchOutputsState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *WatchOutputsEvent:
		preCommits := e.PreCommits

		// If no pre-commitments were provided, then we'll query our
		// local view for the set of unspent pre-commitments.
		if len(preCommits) == 0 {
			var (
				ctx = context.Background()
				err error
			)

			preCommits, err =
				env.SupplyCommitView.UnspentPrecommits(
					ctx, env.AssetSpec,
				).Unpack()
			if err != nil {
				return nil, fmt.Errorf("unable to fetch "+
					"unspent pre-commitments: %w", err)
			}
		}

		// Formulate registered spend events for each of the
		// pre-commitment outputs that should be watched.
		events := make(protofsm.DaemonEventSet, 0, len(preCommits)+1)
		for idx := range preCommits {
			preCommit := preCommits[idx]

			outpoint := wire.OutPoint{
				Hash:  preCommit.MintingTxn.TxHash(),
				Index: preCommit.OutIdx,
			}
			txOut := preCommit.MintingTxn.TxOut[preCommit.OutIdx]

			pc := preCommit
			mapper := func(spend *chainntnfs.SpendDetail) Event {
				spendEvent := &SpendEvent{
					SpendDetail:        spend,
					SpentPreCommitment: &pc,
					PreCommitments:     preCommits,
				}
				return spendEvent
			}

			events = append(events, &protofsm.RegisterSpend[Event]{
				OutPoint: outpoint,
				PkScript: txOut.PkScript,
				PostSpendEvent: lfn.Some(
					protofsm.SpendMapper[Event](mapper),
				),
			})
		}

		// If a supply commitment was provided, we'll also register a
		// spend event for its output.
		if e.SupplyCommit != nil {
			outpoint := wire.OutPoint{
				Hash:  e.SupplyCommit.Txn.TxHash(),
				Index: e.SupplyCommit.TxOutIdx,
			}
			txOutIdx := e.SupplyCommit.TxOutIdx
			txOut := e.SupplyCommit.Txn.TxOut[txOutIdx]

			sc := e.SupplyCommit
			mapper := func(spend *chainntnfs.SpendDetail) Event {
				return &SpendEvent{
					SpendDetail:           spend,
					SpentSupplyCommitment: sc,
					PreCommitments:        preCommits,
				}
			}

			events = append(events, &protofsm.RegisterSpend[Event]{
				OutPoint: outpoint,
				PkScript: txOut.PkScript,
				PostSpendEvent: lfn.Some(
					protofsm.SpendMapper[Event](mapper),
				),
			})
		}

		// Otherwise, we'll transition to the verify state to await
		// a spend of one of the outputs we're watching.
		return &StateTransition{
			NextState: &SyncVerifyState{},
			NewEvents: lfn.Some(FsmEvent{
				ExternalEvents: events,
			}),
		}, nil

	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, s)
	}
}
