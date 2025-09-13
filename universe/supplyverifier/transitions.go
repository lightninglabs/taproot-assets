package supplyverifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

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
		log.Debugf("Processing InitEvent for asset: %s",
			env.AssetSpec.String())

		ctx := context.Background()

		// Retrieve the set of unspent pre-commitments for the asset
		// group. We will need these later to watch their spends.
		preCommits, err := env.SupplyCommitView.UnspentPrecommits(
			ctx, env.AssetSpec, false,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch unspent "+
				"pre-commitments: %w", err)
		}

		// Query local db for the latest verified supply commitment.
		latestCommit, err := env.SupplyCommitView.FetchLatestCommitment(
			ctx, env.AssetSpec,
		)
		switch {
		case errors.Is(err, ErrCommitmentNotFound):
			// Continue without the latest commitment.

		case err != nil:
			return nil, fmt.Errorf("unable to fetch latest "+
				"verified commitment from db: %w", err)
		}

		// If at this point we don't have any pre-commitments or a
		// verified supply commitment, then we'll have to raise an
		// error. Something went wrong before this point.
		if latestCommit == nil && len(preCommits) == 0 {
			return nil, fmt.Errorf("no pre-commitments or " +
				"verified supply commitment found")
		}

		log.Infof("Transitioning from InitState to "+
			"WatchOutputsState for asset: %s, "+
			"pre_commits=%d, has_latest_commit=%v",
			env.AssetSpec.String(), len(preCommits),
			latestCommit != nil)

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

// maybeFetchSupplyCommit attempts to fetch a supply commitment by the
// specified spent outpoint. If no commitment is found, then a None option is
// returned.
func maybeFetchSupplyCommit(ctx context.Context, env *Environment,
	spentOutpoint wire.OutPoint) (fn.Option[supplycommit.RootCommitment],
	error) {

	var zero fn.Option[supplycommit.RootCommitment]

	commit, err := env.SupplyCommitView.FetchCommitmentBySpentOutpoint(
		ctx, env.AssetSpec, spentOutpoint,
	)
	switch {
	case errors.Is(err, ErrCommitmentNotFound):
		return zero, nil

	case err != nil:
		return zero, fmt.Errorf("unable to query db for commitment: %w",
			err)
	}

	return fn.MaybeSome(commit), nil
}

// ProcessEvent handles state transitions for the SyncVerifyState.
func (s *SyncVerifyState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch e := event.(type) {
	case *SyncVerifyEvent:
		log.Debugf("Processing SyncVerifyEvent (has_spent_commit=%v)",
			e.SpentCommitOutpoint.IsSome())

		ctx := context.Background()

		// Check to ensure that we haven't already processed a supply
		// commitment for the spent outpoint, if one was provided.
		if e.SpentCommitOutpoint.IsSome() {
			spentOutpoint, err := e.SpentCommitOutpoint.UnwrapOrErr(
				fmt.Errorf("spent outpoint unexpectedly " +
					"missing"),
			)
			if err != nil {
				return nil, err
			}

			log.Debugf("SyncVerifyEvent with spent commit "+
				"outpoint: %s", spentOutpoint.String())

			commitOpt, err := maybeFetchSupplyCommit(
				ctx, env, spentOutpoint,
			)
			if err != nil {
				return nil, err
			}

			// If we found a commitment, then we've already
			// processed this supply commit, so we can
			// transition to the watch state.
			if commitOpt.IsSome() {
				commit, err := commitOpt.UnwrapOrErr(
					fmt.Errorf("commitment missing"),
				)
				if err != nil {
					return nil, err
				}

				log.Debugf("Supply commitment already " +
					"processed, transitioning to " +
					"WatchOutputsState")

				watchEvent := WatchOutputsEvent{
					SupplyCommit: &commit,
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

		log.Debugf("Syncing supply commitment (asset=%s)",
			env.AssetSpec.String())
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

		// Fetch all known unspent pre-commitment outputs for the asset
		// group.
		unspentPreCommits, err :=
			env.SupplyCommitView.UnspentPrecommits(
				ctx, env.AssetSpec, false,
			).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch unspent "+
				"pre-commitments: %w", err)
		}

		verifier, err := NewVerifier(
			VerifierCfg{
				AssetSpec:        env.AssetSpec,
				ChainBridge:      env.Chain,
				AssetLookup:      env.AssetLookup,
				Lnd:              env.Lnd,
				GroupFetcher:     env.GroupFetcher,
				SupplyCommitView: env.SupplyCommitView,
				SupplyTreeView:   env.SupplyTreeView,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create verifier: %w",
				err)
		}

		err = verifier.VerifyCommit(
			ctx, env.AssetSpec, supplyCommit.RootCommitment,
			supplyCommit.SupplyLeaves, unspentPreCommits,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to verify supply "+
				"commitment: %w", err)
		}

		log.Debugf("Storing verified supply commitment")

		// Store the verified commitment.
		err = env.SupplyCommitView.InsertSupplyCommit(
			ctx, env.AssetSpec, supplyCommit.RootCommitment,
			supplyCommit.SupplyLeaves, unspentPreCommits,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to store supply "+
				"commitment: %w", err)
		}

		log.Infof("Successfully synced and verified supply "+
			"commitment for asset: %s, "+
			"transitioning to WatchOutputsState",
			env.AssetSpec.String())

		// After syncing, verifying, and storing the latest supply
		// commitment, transition to the watch state to await its spend.
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
		log.Infof("Received SpendEvent for asset: %s, spend_tx=%s",
			env.AssetSpec.String(),
			e.SpendDetail.SpendingTx.TxHash())

		// A watched output has been spent, so transition to the sync
		// state to fetch the new supply commitment. Before syncing,
		// apply a delay to give the issuer time to publish it.
		switch {
		case e.WatchStartTimestamp.IsZero():
			// No watch start timestamp: wait the full sync delay.
			log.Debugf("Waiting full sync delay of %v before "+
				"syncing", env.SpendSyncDelay)
			time.Sleep(env.SpendSyncDelay)

		default:
			// With a watch start timestamp: wait only the remaining
			// time if the elapsed time is less than the sync delay.
			timeSinceWatch := time.Since(e.WatchStartTimestamp)
			if timeSinceWatch < env.SpendSyncDelay {
				delay := env.SpendSyncDelay - timeSinceWatch

				env.Logger().Debugf("Waiting remaining sync "+
					"delay of %v before syncing", delay)

				time.Sleep(delay)
			}
		}

		// After the wait, transition to the sync state to fetch the new
		// supply commitment.
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
		env.Logger().Debugf("Processing WatchOutputsEvent")

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
					ctx, env.AssetSpec, false,
				).Unpack()
			if err != nil {
				return nil, fmt.Errorf("unable to fetch "+
					"unspent pre-commitments: %w", err)
			}
		}

		// Timestamp marking when output watching begins. Stored in the
		// spend event to calculate watch duration when a spend
		// notification arrives.
		watchStartTimestamp := time.Now().UTC()

		// Formulate registered spend events for each of the
		// pre-commitment outputs that should be watched.
		events := make(protofsm.DaemonEventSet, 0, len(preCommits)+1)
		for idx := range preCommits {
			preCommit := preCommits[idx]

			txOut := preCommit.MintingTxn.TxOut[preCommit.OutIdx]
			mapper := func(spend *chainntnfs.SpendDetail) Event {
				// nolint: lll
				return &SpendEvent{
					SpendDetail:         spend,
					SpentPreCommitment:  &preCommit,
					PreCommitments:      preCommits,
					WatchStartTimestamp: watchStartTimestamp,
				}
			}

			events = append(events, &protofsm.RegisterSpend[Event]{
				OutPoint:   preCommit.OutPoint(),
				PkScript:   txOut.PkScript,
				HeightHint: preCommit.BlockHeight,
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

			env.Logger().Debugf("Registering spend watch for "+
				"supply commitment outpoint: %s",
				outpoint.String())

			txOutIdx := e.SupplyCommit.TxOutIdx
			txOut := e.SupplyCommit.Txn.TxOut[txOutIdx]

			sc := e.SupplyCommit
			mapper := func(spend *chainntnfs.SpendDetail) Event {
				// nolint: lll
				return &SpendEvent{
					SpendDetail:           spend,
					SpentSupplyCommitment: sc,
					PreCommitments:        preCommits,
					WatchStartTimestamp:   watchStartTimestamp,
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

		env.Logger().Infof("WatchOutputsState: transitioning to "+
			"SyncVerifyState (watch_precommit_outputs=%d, "+
			"watch_supply_commit=%v)", len(preCommits),
			e.SupplyCommit != nil)

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
