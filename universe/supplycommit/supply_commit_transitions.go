package supplycommit

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
)

const (
	CommitConfTarget = 24
)

// ProcessEvent is used to transition from the default state to the
// UpdatePendingState once we receive a new request to update the current supply
// trees.
func (d *DefaultState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	// In this state, we'll receive one of three events: a new burn, a new
	// mint, or a new ignore. For all three types, we'll emit this as an
	// internal event as we transition to the UpdatePendingState.
	switch supplyEvent := event.(type) {
	case SupplyUpdateEvent:

		// We'll go to the next state, caching the pendingUpdate we just
		// received.
		return &StateTransition{
			NextState: &UpdatesPendingState{
				pendingUpdates: []SupplyUpdateEvent{
					supplyEvent,
				},
			},
		}, nil

	// If we get a tick in this state, then it's just a no-op. We'll
	// transition back to the same state.
	case *CommitTickEvent:
		return &StateTransition{
			NextState: d,
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, d)
	}
}

// ProcessEvent processes incoming events for the UpdatesPendingState. From
// here, we'll either be staging new events, or we'll attempt to start the
// commitment update process once a new commitment is received.
func (s *UpdatesPendingState) ProcessEvent(event Event, env *Environment) (
	*StateTransition, error) {

	switch newEvent := event.(type) {
	// We've received a new update event, we'll stage this in our local
	// state, and do a self transition.
	case SupplyUpdateEvent:

		// TODO(roasbeef): commit update to disk
		//
		// TODO(roasbeef): update state machine state on disk
		//   * for all states below

		// We'll go to the next state, caching the pendingUpdate we just
		// received.
		currentUpdates := append(s.pendingUpdates, newEvent)
		return &StateTransition{
			NextState: &UpdatesPendingState{
				pendingUpdates: currentUpdates,
			},
		}, nil

	// We just got a tick event, so from here we'll move to start creating
	// the new set of supply commitments. We'll emit the CreateTxEvent to
	// the next state will begin the process of making the new commitment.
	case *CommitTickEvent:
		return &StateTransition{
			NextState: &CommitTreeCreateState{},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&CreateTreeEvent{
					updatesToCommit: s.pendingUpdates,
				}},
			}),
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, s)
	}
}

// insertIntoTree is a helper method that inserts a new leaf into the given
// tree.
func insertIntoTree(tree mssmt.Tree, leafKey [32]byte,
	leafValue *mssmt.LeafNode) (mssmt.Tree, error) {

	// TODO(roasbeef): accept context for each arg?
	ctx := context.Background()

	return tree.Insert(ctx, leafKey, leafValue)
}

func applyTreeUpdates(
	supplyTrees SupplyTrees,
	pendingUpdates []SupplyUpdateEvent) (SupplyTrees, error) {

	for _, treeUpdate := range pendingUpdates {
		var (
			leafKey    universe.LeafKey
			leafValue  *mssmt.LeafNode
			targetTree mssmt.Tree
			err        error
		)

		// Burn events are similar to the issuance events, but
		// use a distinct universe key.
		switch update := treeUpdate.(type) {
		case *NewBurnEvent:
			leafKey = update.UniverseKey
			leafValue, err = update.UniverseLeafNode()
			if err != nil {
				return nil, fmt.Errorf("unable to "+
					"create leaf node for burn "+
					"event: %w", err)
			}

			// TODO(roasbeef): should be inserting negative
			// value items here

			targetTree = supplyTrees.FetchOrCreate(
				BurnTreeType,
			)

		// Ignore events use the same key structure, but
		// have a different leaf value.
		case *NewIgnoreEvent:
			leafKey = &update.SignedIgnoreTuple
			leafValue, err = update.UniverseLeafNode()
			if err != nil {
				return nil, fmt.Errorf("unable to "+
					"create leaf node for ignore "+
					"event: %w", err)
			}

			// TODO(roasbeef): should be inserting negative
			// value items here

			targetTree = supplyTrees.FetchOrCreate(
				IgnoreTreeType,
			)

		// Mint events are similar to burn events in leaf
		// structure.
		case *NewMintEvent:
			leafKey = update.LeafKey
			leafValue = update.IssuanceProof.SmtLeafNode()

			targetTree = supplyTrees.FetchOrCreate(
				MintTreeType,
			)
		}

		// With the leaf and value obtained, we'll insert it
		// into the target sub-tree.
		targetTree, err = insertIntoTree(
			targetTree, leafKey.UniverseKey(), leafValue,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to insert "+
				"leaf into target tree: %w", err)
		}
	}

	return supplyTrees, nil
}

// ProcessEvent processes incoming events for the CommitTreeCreateState. From
// this state, we'll take the set of pending changes, then create/read the
// components of the sub-supply trees, then use that to create the new finalized
// tree.
func (c *CommitTreeCreateState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	// TODO(roasbeef): cache attemps to add new elements? or main state
	// driver still single threaded?

	switch newEvent := event.(type) {
	// If we get a tick in this state, then it's just a no-op. We'll
	// transition back to the same state.
	case *CommitTickEvent:
		return &StateTransition{
			NextState: c,
		}, nil

	// Otherwise, if we got a CreateTreeEvent, then we'll being to create
	// the new set of supply root sub-trees based on the pending updates we
	// have.
	case *CreateTreeEvent:
		pendingUpdates := newEvent.updatesToCommit

		// First, we'll gather the current set of sub-trees for the
		// given asset specifier.
		//
		// TODO(roasbeef): sanity check on population of map?
		supplyTrees, err := env.TreeView.FetchSubTrees(
			env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch sub trees: %w",
				err)
		}

		// Next, based on the type of event, we'll create a new key+leaf
		// to insert into the respective sub-tree.
		supplyTrees, err = applyTreeUpdates(supplyTrees, pendingUpdates)
		if err != nil {
			return nil, fmt.Errorf("unable to apply "+
				"tree updates: %w", err)
		}

		// At this point, we have an updated version of the various
		// sub-trees created. We'll take those sub-trees, and insert
		// them into the unified supply tree.
		rootSupplyTree, err := env.TreeView.FetchRootSupplyTree(
			env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch root "+
				"supply tree: %w", err)
		}

		// Now we'll insert/update each of the read sub-trees into the
		// root supply tree.
		ctx := context.Background()
		for treeType, subTree := range supplyTrees {
			rootTreeKey := treeType.UniverseKey()

			subTreeRoot, err := subTree.Root(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to fetch "+
					"sub-tree root: %w", err)
			}

			rootTreeLeaf := mssmt.NewLeafNode(
				lnutils.ByteSlice(subTreeRoot.NodeHash()),
				uint64(subTreeRoot.NodeSum()),
			)

			rootSupplyTree, err = insertIntoTree(
				rootSupplyTree, rootTreeKey, rootTreeLeaf,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to insert "+
					"sub-tree into root supply tree: %w",
					err)
			}
		}

		// With all the components assembled, we'll now transition to
		// the next state. We'll also emit an internal event to
		// transition us to the next state.
		return &StateTransition{
			NextState: &CommitTxCreateState{
				UpdatedSupplyTrees: supplyTrees,
				RootSupplyTree:     rootSupplyTree,
				PendingUpdates:     pendingUpdates,
			},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&CreateTxEvent{}},
			}),
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, event, c)
	}
}

// ProcessEvent processes incoming events for the CommitTxCreateState. From
// here, we have the new set of updated supply trees, and also the root supply
// tree. We'll now create a transaction that spends any unspent pre-commitments,
// and the latest commitment to create a new commitment that reflects the
// current supply state.
func (c *CommitTxCreateState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	// TODO(roasbeef): persistence
	//   * update state in the prev, or current state?

	switch newEvent := event.(type) {

	// From here we'll create a new commitment update transaction that
	// spends the old set of commitments, and creates a new transaction that
	// commits to the root supply tree.
	case *CreateTxEvent:
		ctx := context.Background()
		newCommitTx := wire.NewMsgTx(2)

		// First, we'll fetch all the pre-commitments that are still
		// currently unspent.
		preCommits, err := env.Commitments.UnspentPrecommits(
			env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"unspent pre-commitments: %w", err)
		}

		// Now that we have the set of pre-commits, we'll add them to as
		// inputs into the new transaction.
		//
		// TODO(roasbeef): need index map for PSBT??
		//  * verify all inputs locked on restart, otherwise transition
		//  from sign//broadcast back to this state?
		for _, preCommit := range preCommits {
			newCommitTx.AddTxIn(preCommit.TxIn())
		}

		// With the pre-commitments added, we'll now add the current
		// commitment output to the transaction. This will be the output
		// that verifies are watching for spends.
		currentCommit, err := env.Commitments.SupplyCommit(
			env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"current supply commitment: %w", err)
		}

		// If there isn't an existing commitment in the chain, then
		// we'll have one less input on the transaction.
		currentCommit.WhenSome(func(r RootCommitment) {
			newCommitTx.AddTxIn(r.TxIn())
		})

		newSupplyRoot, err := c.RootSupplyTree.Root(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"root supply tree: %w", err)
		}

		internalKeyOpt := lfn.MapOption(func(r RootCommitment) *btcec.PublicKey {
			return r.InternalKey
		})(currentCommit)

		commitInternalKey, err := internalKeyOpt.UnwrapOrFuncErr(
			func() (*btcec.PublicKey, error) {
				newKey, err := env.Wallet.DeriveNextKey(ctx)
				if err != nil {
					return nil, fmt.Errorf("unable to derive "+
						"next key: %w", err)
				}

				return newKey.PubKey, nil
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"internal key: %w", err)
		}

		// With the inputs added, we'll now create our new commitment
		// output. We don't know the index yet, so we'll set this to 0.
		// We'll also re-use the current internal key for now.
		//
		// TODO(roasbeef): or is arbitrary here?
		newSupplyCommit := RootCommitment{
			Txn:         newCommitTx,
			TxOutIdx:    0,
			InternalKey: commitInternalKey,
			SupplyRoot:  newSupplyRoot,
		}
		supplyTxOut, err := newSupplyCommit.TxOut()
		if err != nil {
			return nil, fmt.Errorf("unable to create "+
				"commitment output: %w", err)
		}

		newCommitTx.AddTxOut(supplyTxOut)

		// If we just generated a new key, then we'll import that into
		// the wallet so it can track the sats for our commitment
		// output..
		if internalKeyOpt.IsNone() {
			_, err := env.Wallet.ImportTaprootOutput(
				ctx, commitInternalKey,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to "+
					"import taproot output: %w", err)
			}
		}

		// As a final step, we'll create a new PSBT that can be used to
		// sign the transaction. We'll handle that in the next state.
		commitPkt, err := psbt.NewFromUnsignedTx(newCommitTx)
		if err != nil {
			return nil, fmt.Errorf("unable to create "+
				"PSBT: %w", err)
		}

		feeRate, err := env.Chain.EstimateFee(
			ctx, CommitConfTarget,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to estimate fee: %w",
				err)
		}

		fundedCommitPkt, err := env.Wallet.FundPsbt(
			ctx, commitPkt, 1, feeRate, -1,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund "+
				"PSBT: %w", err)
		}

		// Now that we have the funded packet, we'll examine the outputs
		// to determine which one is our commitment output.
		for i, txOut := range fundedCommitPkt.Pkt.UnsignedTx.TxOut {
			// Skip the change output based on its index.
			if int32(i) == fundedCommitPkt.ChangeOutputIndex {
				continue
			}

			if bytes.Equal(txOut.PkScript, supplyTxOut.PkScript) {
				newSupplyCommit.TxOutIdx = uint32(i)
				break
			}
		}

		return &StateTransition{
			NextState: &CommitTxSignState{
				CommitTxCreateState: *c,
			},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&SignTxEvent{
					CommitPkt: fundedCommitPkt,
				}},
			}),
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, newEvent, c)
	}
}

// ProcessEvent processes incoming events for the CommitTxSignState. From here,
// we'll sign the transaction, then transition to the next state for broadcast.
func (c *CommitTxSignState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	return nil, nil
}
