package supplyverifier

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/protofsm"
)

// ProcessEvent handles the initial state transition for the supply verifier.
func (d *DefaultState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch event.(type) {
	case *InitEvent:
		ctx := context.Background()

		// First, we'll query for the last verified commitment.
		lastCommit, err := env.OnChainLookup.LastVerifiedCommitment(
			ctx, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch last "+
				"verified commitment: %w", err)
		}

		// If we don't have a last verified commitment, then this is the
		// first time we're verifying this asset group. We'll kick
		// things off by watching for the latest on-chain state.
		if lastCommit == nil {
			return &StateTransition{
				NextState: &WatchOutputsSpendState{},
				NewEvents: lfn.Some(FsmEvent{
					InternalEvent: []Event{
						&WatchLatestOutputsEvent{},
					},
				}),
			}, nil
		}

		// If we do have a prior verified commitment, then we'll
		// construct a watch event to watch for its spend, and also any
		// other un-spent pre-commitments.
		preCommits, err := env.OnChainLookup.UnspentPrecommits(
			ctx, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch unspent "+
				"pre-commitments: %w", err)
		}

		return &StateTransition{
			NextState: &WatchOutputsSpendState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&WatchOutputsEvent{
						PreCommits:   preCommits,
						SupplyCommit: lastCommit,
					},
				},
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in %T",
		ErrInvalidStateTransition, event, d)
}

// ProcessEvent handles the state transition for the WatchOutputsSpendState.
func (w *WatchOutputsSpendState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *WatchLatestOutputsEvent:
		ctx := context.Background()

		// We'll gather all the UTXOs we need to watch. We start with
		// the unspent pre-commitments.
		preCommits, err := env.OnChainLookup.UnspentPrecommits(
			ctx, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"pre-commitments: %w", err)
		}

		// Next, we'll check for the current supply commitment and
		// watch it if it's unspent.
		supplyCommit, err := env.OnChainLookup.SupplyCommit(
			ctx, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch latest "+
				"supply commitment: %w", err)
		}

		return &StateTransition{
			NextState: &WatchOutputsSpendState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&WatchOutputsEvent{
						PreCommits:   preCommits,
						SupplyCommit: supplyCommit,
					},
				},
			}),
		}, nil

	case *WatchOutputsEvent:
		// Formulate registered spend events for each of the
		// pre-commitment outputs that should be watched.
		events := make(protofsm.DaemonEventSet, 0, len(e.PreCommits)+1)
		for idx := range e.PreCommits {
			preCommit := e.PreCommits[idx]

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
					PreCommitments:     e.PreCommits,
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
					PreCommitments:        e.PreCommits,
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

		// If after all that, we have nothing to watch, we can just go
		// to the idle state.
		if len(events) == 0 {
			return &StateTransition{
				NextState: &IdleState{},
			}, nil
		}

		// Otherwise, we'll transition to the verify state to await
		// a spend of one of the outputs we're watching.
		return &StateTransition{
			NextState: &SyncSupplyProofsState{},
			NewEvents: lfn.Some(FsmEvent{
				ExternalEvents: events,
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in %T",
		ErrInvalidStateTransition, event, w)
}

// ProcessEvent handles state transitions for the SyncSupplyProofsState.
func (s *SyncSupplyProofsState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *SpendEvent:
		// We may have registered multiple spend notifiers for a set of
		// pre-commitments that are all spent in the same transaction.
		// To avoid processing the same spend event multiple times, we
		// check if we've already processed this transaction.
		spendingTxID := e.SpendDetail.SpendingTx.TxHash()
		if s.lastSpendTxID != nil &&
			*s.lastSpendTxID == spendingTxID {

			return &StateTransition{
				NextState: s,
			}, nil
		}

		ctx := context.Background()
		nextCommitment, err := env.OnChainLookup.SupplyCommit(
			ctx, env.AssetSpec,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch next "+
				"commitment: %w", err)
		}

		// TODO(ffranr): proof syncing logic here.

		return &StateTransition{
			NextState: &VerifySupplyCommitState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&ProofsSyncedEvent{
						nextCommitment: nextCommitment,
						spendEvent:     e,
					},
				},
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in %T",
		ErrInvalidStateTransition, event, s)
}

// ProcessEvent handles state transitions for the VerifySupplyCommitState.
func (v *VerifySupplyCommitState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch event.(type) {
	case *ProofsSyncedEvent:
		// TODO(ffranr): verification logic here. This should include
		// checking that there are no more unspent pre-commitments. All
		// the pre-commitments should have been spent in the same supply
		// commitment transaction.

		// Now that we've verified this commitment, we'll transition
		// back to the watch state to watch for the spend of this and
		// any other relevant outputs.
		return &StateTransition{
			NextState: &WatchOutputsSpendState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{
					&WatchLatestOutputsEvent{},
				},
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in %T",
		ErrInvalidStateTransition, event, v)
}

// ProcessEvent handles state transitions for the IdleState.
func (i *IdleState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *SpendEvent:
		return &StateTransition{
			NextState: &SyncSupplyProofsState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{e},
			}),
		}, nil
	}

	return nil, fmt.Errorf("%w: received %T while in %T",
		ErrInvalidStateTransition, event, i)
}
