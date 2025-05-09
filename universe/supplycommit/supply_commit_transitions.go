package supplycommit

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/protofsm"
)

const (
	CommitConfTarget = 24
)

// createCommitmentTxLabel constructs a descriptive label for the supply
// commitment transaction broadcast.
func createCommitmentTxLabel(assetSpec asset.Specifier,
	supplyTransition SupplyStateTransition) string {

	// Get the root hash and sum of the supply tree.
	rootNode := supplyTransition.NewCommitment.SupplyRoot
	rootHash := rootNode.NodeHash()
	nodeSum := rootNode.NodeSum()

	// Count the different types of updates included in this commitment.
	var mints, burns, ignores int
	for _, update := range supplyTransition.PendingUpdates {
		switch update.SupplySubTreeType() {
		case MintTreeType:
			mints++
		case BurnTreeType:
			burns++
		case IgnoreTreeType:
			ignores++
		}
	}

	// Format the label string including the asset specifier, root hash, and
	// counts of each update type.
	label := fmt.Sprintf(
		"supply_commit(%v):root=%x:sum=%v:m=%d,b=%d,i=%d",
		assetSpec, rootHash[:], nodeSum, mints, burns, ignores,
	)

	return label
}

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

		// Before we transition to the next state, we'll add this event
		// to our update log. This ensures that we'll remember to
		// process from this state after a restart.
		//
		// TODO(roasbeef): special error case here?
		ctx := context.Background()
		err := env.StateLog.InsertPendingUpdate(
			ctx, env.AssetSpec, supplyEvent,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to insert "+
				"pending update: %w", err)
		}

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

		// We just got a new pending update in addition to the one that
		// made us transition to this state. This ensures that we'll
		// remember to process from this state after a restart.
		ctx := context.Background()
		err := env.StateLog.InsertPendingUpdate(
			ctx, env.AssetSpec, newEvent,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to insert "+
				"pending update: %w", err)
		}

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
	//  * ProcessEvent on lnd state machine?
	ctx := context.Background()

	return tree.Insert(ctx, leafKey, leafValue)
}

// applyTreeUpdates takes the set of pending updates, and applies them to the
// given supply trees. It returns a new map containing the updated trees.
func applyTreeUpdates(supplyTrees SupplyTrees,
	pendingUpdates []SupplyUpdateEvent) (SupplyTrees, error) {

	ctx := context.Background()

	// Create a copy of the input map to avoid mutating the original.
	updatedSupplyTrees := make(SupplyTrees)
	for k, v := range supplyTrees {
		// Create a new tree for each entry in the map.
		newTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
		if err := v.Copy(ctx, newTree); err != nil {
			return nil, fmt.Errorf("unable to copy tree: %w", err)
		}

		updatedSupplyTrees[k] = newTree
	}

	// TODO(roasbeef): make new copy routine, passes in tree to copy into

	for _, treeUpdate := range pendingUpdates {
		// Obtain the universe leaf key and node directly from the event
		// using the interface methods.
		leafKey := treeUpdate.UniverseLeafKey()
		leafValue, err := treeUpdate.UniverseLeafNode()
		if err != nil {
			return nil, fmt.Errorf("unable to create leaf node "+
				"for update event %T: %w", treeUpdate, err)
		}

		// TODO(roasbeef): should be inserting negative value items here
		// for burn/ignore?

		targetTree := updatedSupplyTrees.FetchOrCreate(
			treeUpdate.SupplySubTreeType(),
		)

		// With the leaf and value obtained, we'll insert it into the
		// target sub-tree.
		targetTree, err = insertIntoTree(
			targetTree, leafKey.UniverseKey(), leafValue,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to insert "+
				"leaf into target tree %w", err)
		}

		// Update the map with the modified tree.
		updatedSupplyTrees[treeUpdate.SupplySubTreeType()] = targetTree
	}

	return updatedSupplyTrees, nil
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
		oldSupplyTrees, err := env.TreeView.FetchSubTrees(
			env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch old sub "+
				"trees: %w", err)
		}

		// Next, based on the type of event, we'll create a new key+leaf
		// to insert into the respective sub-tree.
		newSupplyTrees, err := applyTreeUpdates(
			oldSupplyTrees, pendingUpdates,
		)
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
		for treeType, subTree := range newSupplyTrees {
			subTreeRoot, err := subTree.Root(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to fetch "+
					"sub-tree root: %w", err)
			}

			rootTreeLeaf := mssmt.NewLeafNode(
				lnutils.ByteSlice(subTreeRoot.NodeHash()),
				subTreeRoot.NodeSum(),
			)

			rootTreeKey := treeType.UniverseKey()
			rootSupplyTree, err = insertIntoTree(
				rootSupplyTree, rootTreeKey, rootTreeLeaf,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to insert "+
					"sub-tree into root supply tree: %w",
					err)
			}
		}

		// Construct the state transition object. We'll begin to
		// persist. this state from here on.
		supplyTreeRoot, err := rootSupplyTree.Root(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch root "+
				"supply tree root: %w", err)
		}
		supplyTransition := SupplyStateTransition{
			//OldSupplyRoots: oldSupplyTrees,
			//NewSupplyRoots: newSupplyTrees,
			PendingUpdates: pendingUpdates,
			NewCommitment: RootCommitment{
				SupplyRoot: supplyTreeRoot,
			},
		}

		// With all the components assembled, we'll now transition to
		// the next state. We'll also emit an internal event to
		// transition us to the next state.
		return &StateTransition{
			NextState: &CommitTxCreateState{
				SupplyTransition: supplyTransition,
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

// newRootCommitment creates a new root commitment based on: the prior root
// commitment, any set of unspent pre commitments, and the new supply root.
func newRootCommitment(ctx context.Context,
	oldCommitment lfn.Option[RootCommitment],
	unspentPreCommits []PreCommitment, newSupplyRoot *mssmt.BranchNode,
	wallet Wallet) lfn.Result[RootCommitment] {

	newCommitTx := wire.NewMsgTx(2)

	// With the set of pre-commits, we'll add them to as inputs into the new
	// transaction.
	//
	// TODO(roasbeef): need index map for PSBT??
	//  * verify all inputs locked on restart, otherwise transition from
	//  sign//broadcast back to this state?
	for _, preCommit := range unspentPreCommits {
		newCommitTx.AddTxIn(preCommit.TxIn())
	}

	// If there isn't an existing commitment in the chain, then we'll have
	// one less input on the transaction.
	oldCommitment.WhenSome(func(r RootCommitment) {
		newCommitTx.AddTxIn(r.TxIn())
	})

	// If we have a prior root commitment, then we'll reuse the internal
	// key. Otherwise, we'll generate a fresh one.
	iKeyOpt := lfn.MapOption(func(r RootCommitment) *btcec.PublicKey {
		return r.InternalKey
	})(oldCommitment)
	commitInternalKey, err := iKeyOpt.UnwrapOrFuncErr(
		func() (*btcec.PublicKey, error) {
			newKey, err := wallet.DeriveNextKey(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to derive "+
					"next key: %w", err)
			}

			return newKey.PubKey, nil
		},
	)
	if err != nil {
		return lfn.Err[RootCommitment](err)
	}

	// If we just generated a new key, then we'll import that into the
	// wallet so it can track the sats for our commitment output.
	if iKeyOpt.IsNone() {
		_, err := wallet.ImportTaprootOutput(
			ctx, commitInternalKey,
		)
		if err != nil {
			return lfn.Errf[RootCommitment]("unable to import "+
				"taproot output: %w", err)
		}
	}

	// With the inputs added, we'll now create our new commitment output. We
	// don't know the index yet, so we'll set this to 0. We'll also re-use
	// the current internal key for now.
	//
	// TODO(roasbeef): use diff internal key?
	newSupplyCommit := RootCommitment{
		Txn:         newCommitTx,
		TxOutIdx:    0,
		InternalKey: commitInternalKey,
		SupplyRoot:  newSupplyRoot,
	}

	// Finally, we'll derive the new commitment output, and add that to the
	// update transaction.
	supplyTxOut, err := newSupplyCommit.TxOut()
	if err != nil {
		return lfn.Errf[RootCommitment]("unable to create "+
			"commitment output: %w", err)
	}
	newCommitTx.AddTxOut(supplyTxOut)

	return lfn.Ok(newSupplyCommit)
}

// fundSupplyCommitTx takes a newly created supply commitment transaction,
// creates a PSBT, estimates fees, funds the PSBT using the wallet, and locates
// the index of the supply commitment output within the funded transaction. It
// updates the TxOutIdx field of the passed supplyCommit directly.
func fundSupplyCommitTx(ctx context.Context, supplyCommit *RootCommitment,
	env *Environment) (*tapsend.FundedPsbt, error) {

	// Create a new PSBT from the unsigned transaction.
	commitPkt, err := psbt.NewFromUnsignedTx(supplyCommit.Txn)
	if err != nil {
		return nil, fmt.Errorf("unable to create PSBT: %w", err)
	}

	// Estimate the required fee rate.
	feeRate, err := env.Chain.EstimateFee(ctx, CommitConfTarget)
	if err != nil {
		return nil, fmt.Errorf("unable to estimate fee: %w", err)
	}

	// Fund the PSBT using the wallet. We assume a single confirmation
	// target and let the wallet choose the change output index (-1).
	fundedCommitPkt, err := env.Wallet.FundPsbt(
		ctx, commitPkt, 1, feeRate, -1,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund PSBT: %w", err)
	}

	// After funding, the transaction might have changed (new inputs, change
	// output). We need to find the index of our supply commitment output in
	// the potentially modified transaction within the funded PSBT.
	// We use the PkScript of the original output to find the matching one.
	originalSupplyTxOut, err := supplyCommit.TxOut()
	if err != nil {
		return nil, fmt.Errorf("unable to get original supply "+
			"tx out: %w", err)
	}
	foundOutput := false
	for i, txOut := range fundedCommitPkt.Pkt.UnsignedTx.TxOut {
		// Skip the designated change output.
		if int32(i) == fundedCommitPkt.ChangeOutputIndex {
			continue
		}

		// If the PkScript matches, we've found our output. Update the
		// index in the supplyCommit.
		if bytes.Equal(txOut.PkScript, originalSupplyTxOut.PkScript) {
			supplyCommit.TxOutIdx = uint32(i)
			foundOutput = true
			break
		}
	}

	// If we couldn't find the output after funding, something went wrong.
	if !foundOutput {
		return nil, fmt.Errorf("unable to find supply commitment " +
			"output in funded PSBT")
	}

	return fundedCommitPkt, nil
}

// ProcessEvent processes incoming events for the CommitTxCreateState. From
// here, we have the new set of updated supply trees, and also the root supply
// tree. We'll now create a transaction that spends any unspent pre-commitments,
// and the latest commitment to create a new commitment that reflects the
// current supply state.
func (c *CommitTxCreateState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch newEvent := event.(type) {
	// From here we'll create a new commitment update transaction that
	// spends the old set of commitments, and creates a new transaction that
	// commits to the root supply tree.
	case *CreateTxEvent:
		ctx := context.Background()

		// To create the new commitment, we'll fetch the unspent pre
		// commitments, the current supply root (which may not exist),
		// and the new supply root.
		preCommits, err := env.Commitments.UnspentPrecommits(
			ctx, env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"unspent pre-commitments: %w", err)
		}
		newSupplyRoot := c.SupplyTransition.NewCommitment.SupplyRoot
		oldCommitment, err := env.Commitments.SupplyCommit(
			ctx, env.AssetSpec,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to fetch "+
				"old supply commitment: %w", err)
		}

		// With all the inputs obtained, we'll create the new supply
		// commitment.
		newSupplyCommit, err := newRootCommitment(
			ctx, oldCommitment, preCommits, newSupplyRoot,
			env.Wallet,
		).Unpack()
		if err != nil {
			return nil, fmt.Errorf("unable to create "+
				"new root commitment: %w", err)
		}

		// Now, fund the transaction using the wallet. This call updates
		// the TxOutIdx field within the newSupplyCommit struct passed
		// to it.
		fundedCommitPkt, err := fundSupplyCommitTx(
			ctx, &newSupplyCommit, env,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund supply "+
				"commitment tx: %w", err)
		}

		// With the funded PSBT ready, transition to the signing state,
		// passing the PSBT and the new commitment via an event. Create
		// a new SupplyStateTransition for the next state.
		nextSupplyTransition := SupplyStateTransition{
			OldCommitment: oldCommitment,
			//OldSupplyRoots:    c.SupplyTransition.OldSupplyRoots,
			UnspentPreCommits: preCommits,
			PendingUpdates:    c.SupplyTransition.PendingUpdates,
			NewCommitment:     newSupplyCommit,
			//NewSupplyRoots:    c.SupplyTransition.NewSupplyRoots,
		}

		return &StateTransition{
			NextState: &CommitTxSignState{
				SupplyTransition: nextSupplyTransition,
			},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&SignTxEvent{
					CommitPkt:       fundedCommitPkt,
					NewSupplyCommit: newSupplyCommit,
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

	switch newEvent := event.(type) {
	// We've received the SignTxEvent that contains the PSBT to sign, and
	// the new supply commitment. We'll sign the PSBT, then transition to
	// the final broadcast phase.
	case *SignTxEvent:
		ctx := context.Background()

		stateTransition := c.SupplyTransition

		// After some initial validation, we'll now sign the PSBT.
		signedPsbt, err := env.Wallet.SignAndFinalizePsbt(
			ctx, newEvent.CommitPkt.Pkt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sign "+
				"commitment tx: %w", err)
		}
		commitTx, err := psbt.Extract(signedPsbt)
		if err != nil {
			return nil, fmt.Errorf("unable to extract "+
				"psbt: %w", err)
		}
		stateTransition.NewCommitment.Txn = commitTx

		// At this point, we have a fully signed PSBT, and also a state
		// transition that is nearly fully populated. We'll commit this
		// state to disk, and also mark that that we'll transition to
		// the CommitBroadcastState. We construct the SupplyCommitTxn
		// struct with the details from the finalized commitment.
		commitTxnDetails := SupplyCommitTxn{
			Txn:         commitTx,
			InternalKey: stateTransition.NewCommitment.InternalKey,
			OutputKey:   stateTransition.NewCommitment.OutputKey,
			OutputIndex: stateTransition.NewCommitment.TxOutIdx,
		}
		err = env.StateLog.InsertSignedCommitTx(
			ctx, env.AssetSpec, commitTxnDetails,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to commit "+
				"state transition: %w", err)
		}

		return &StateTransition{
			NextState: &CommitBroadcastState{
				SupplyTransition: stateTransition,
			},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&BroadcastEvent{
					SignedCommitPkt: signedPsbt,
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
func (c *CommitBroadcastState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch newEvent := event.(type) {
	// We're at the final step of the state machine. We'll broadcast the
	// signed commit tx, then register for a confirmation for when it
	// confirms.
	case *BroadcastEvent:
		// First, we'll extract the final signed transaction from the
		// PSBT.
		commitTx, err := psbt.Extract(newEvent.SignedCommitPkt)
		if err != nil {
			return nil, fmt.Errorf("unable to extract "+
				"psbt: %w", err)
		}

		// Construct a detailed label for the broadcast request using
		// the helper function.
		label := createCommitmentTxLabel(
			env.AssetSpec, c.SupplyTransition,
		)

		// We'll prep two daemon events: one to broadcast the
		// transaction, and one to register for a confirmation event.
		// For the conf event, we'll send our own custom conf event to
		// signal that things have been confirmed.
		broadcastReq := protofsm.BroadcastTxn{
			Tx:    commitTx,
			Label: label,
		}

		confMapper := func(conf *chainntnfs.TxConfirmation) ConfEvent {
			return ConfEvent{
				Tx:          conf.Tx,
				TxIndex:     conf.TxIndex,
				BlockHeight: conf.BlockHeight,
				Block:       conf.Block,
			}
		}
		confEvent := &protofsm.RegisterConf[ConfEvent]{
			Txid:     commitTx.TxHash(),
			PkScript: commitTx.TxOut[0].PkScript,
			// TODO(roasbeef): need to add a height hint here
			HeightHint:     0,
			NumConfs:       lfn.Some(uint32(1)),
			FullBlock:      true,
			PostConfMapper: lfn.Some[ConfMapper](confMapper),
		}

		// From here we'll wait in the broadcast state until we receive
		// the conf event.
		nextSupplyTransition := c.SupplyTransition

		return &StateTransition{
			NextState: &CommitBroadcastState{
				SupplyTransition: nextSupplyTransition,
			},
			NewEvents: lfn.Some(FsmEvent{
				ExternalEvents: protofsm.DaemonEventSet{
					&broadcastReq, confEvent,
				}}),
		}, nil

	// If we get the conf event, then we're done here. We''ll transition to
	// the CommitFinalizeState, which will finalize our supply transition
	// with the new root and sub-tree information.
	case *ConfEvent:
		stateTransition := c.SupplyTransition

		merkleProof, err := proof.NewTxMerkleProof(
			newEvent.Block.Transactions, int(newEvent.TxIndex),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create merkle "+
				"proof: %w", err)
		}

		stateTransition.ChainProof = lfn.Some(ChainProof{
			Header:      newEvent.Block.Header,
			BlockHeight: newEvent.BlockHeight,
			MerkleProof: *merkleProof,
			TxIndex:     newEvent.TxIndex,
		})

		// Now that the transaction has been confirmed, we'll construct
		// a merkle proof for the commitment transaction. This'll be
		// used to prove that the supply commit is canonical.
		//
		// TODO(roasbeef): need header and txindex, etc to construct

		// The commitment has been confirmed, so we'll transition to the
		// finalize state, but also log on disk that we no longer need
		// to request confirmations on restart.
		ctx := context.Background()
		err = env.StateLog.CommitState(
			ctx, env.AssetSpec, &CommitFinalizeState{},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to commit "+
				"state transition: %w", err)
		}

		return &StateTransition{
			NextState: &CommitFinalizeState{
				SupplyTransition: stateTransition,
			},
			NewEvents: lfn.Some(FsmEvent{
				InternalEvent: []Event{&FinalizeEvent{}}},
			),
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, newEvent, c)
	}
}

// ProcessEvent processes incoming events for the CommitFinalizeState. From
// here, we'll finalize the supply transition by updating the state machine
// state on disk, and updating the supply trees.
func (c *CommitFinalizeState) ProcessEvent(event Event,
	env *Environment) (*StateTransition, error) {

	switch newEvent := event.(type) {
	// We'll receive the FinalizeEvent that contains the supply transition
	// to finalize. We'll update the state machine state on disk, then
	// update the supply trees.
	case *FinalizeEvent:
		ctx := context.Background()

		// At this point, the commitment has been confirmed on disk, so
		// we can update: the state machine state on disk, and swap in
		// all the new supply tree information.
		//
		// First, we'll update the supply state on disk. This way when
		// we restart his is idempotent.
		err := env.StateLog.ApplyStateTransition(
			ctx, env.AssetSpec, c.SupplyTransition,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to apply "+
				"state transition: %w", err)
		}

		return &StateTransition{
			NextState: &DefaultState{},
		}, nil

	// Any other messages in this state will result in an error, as this is
	// an undefined state transition.
	default:
		return nil, fmt.Errorf("%w: received %T while in %T",
			ErrInvalidStateTransition, newEvent, c)
	}
}
