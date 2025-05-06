package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
)

// commitmentChainInfo holds optional chain confirmation details for a
// commitment.
type commitmentChainInfo struct {
	BlockHeader *wire.BlockHeader
	MerkleProof *proof.TxMerkleProof
	BlockHeight uint32
}

type (
	// UnspentPrecommits is an alias for the sqlc type representing an
	// unspent pre-commitment row.
	UnspentPrecommits = sqlc.FetchUnspentPrecommitsRow

	// SupplyCommit is an alias for the sqlc type.
	SupplyCommit = sqlc.FetchSupplyCommitRow

	// QuerySupplyStateMachineResp is an alias for the sqlc type
	// representing a state machine row.
	QuerySupplyStateMachineResp = sqlc.QuerySupplyCommitStateMachineRow

	// QuerySupplyUpdateResp is an alias for the sqlc type representing
	// supply update event rows.
	QuerySupplyUpdateResp = sqlc.QuerySupplyUpdateEventsRow

	// SupplyCommitment is an alias for the sqlc type representing a supply
	// commitment.
	SupplyCommitment = sqlc.SupplyCommitment

	// ChainTxn is an alias for the sqlc type representing a chain
	// transaction.
	ChainTxn = sqlc.ChainTxn

	// SupplyCommitTransition is an alias for the sqlc type representing a
	// supply
	// commit transition.
	SupplyCommitTransition = sqlc.SupplyCommitTransition

	// SupplyCommitMachineParams is an alias for the sqlc type.
	SupplyCommitMachineParams = sqlc.UpsertSupplyCommitStateMachineParams

	// InsertSupplyCommitTransition is an alias for the sqlc type.
	InsertSupplyCommitTransition = sqlc.InsertSupplyCommitTransitionParams

	// InsertSupplyUpdateEvent is an alias for the sqlc type.
	InsertSupplyUpdateEvent = sqlc.InsertSupplyUpdateEventParams

	// UpsertChainTxParams is an alias for the sqlc type.
	UpsertChainTxParams = sqlc.UpsertChainTxParams

	// SupplyCommitChainDetails is an alias for the sqlc type.
	SupplyCommitChainDetails = sqlc.UpdateSupplyCommitmentChainDetailsParams

	// FetchInternalKeyByIDRow is an alias for the sqlc type.
	FetchInternalKeyByIDRow = sqlc.FetchInternalKeyByIDRow

	// FetchChainTxByIDRow is an alias for the sqlc type.
	FetchChainTxByIDRow = sqlc.FetchChainTxByIDRow

	// FetchUniverseSupplyRootRow is an alias for the sqlc type.
	FetchUniverseSupplyRootRow = sqlc.FetchUniverseSupplyRootRow

	// UpdateSupplyCommitTransitionCommitmentParams is an alias for the
	// sqlc type.
	//nolint:lll
	UpdateSupplyCommitTransitionCommitmentParams = sqlc.UpdateSupplyCommitTransitionCommitmentParams

	// UpdateSupplyCommitmentRootParams is an alias for the sqlc type.
	UpdateSupplyCommitmentRootParams = sqlc.UpdateSupplyCommitmentRootParams
)

// SupplyCommitStore is the interface that provides the database methods needed
// to implement the supplycommit.CommitmentTracker and
// supplycommit.StateMachineStore interfaces.
type SupplyCommitStore interface {
	// FetchUnspentPrecommits fetches all unspent pre-commitments for a
	// given group key.
	FetchUnspentPrecommits(ctx context.Context,
		groupKey []byte) ([]UnspentPrecommits, error)

	// FetchSupplyCommit fetches the latest confirmed supply commitment for
	// a given group key.
	FetchSupplyCommit(ctx context.Context,
		groupKey []byte) (SupplyCommit, error)

	// UpsertSupplyCommitStateMachine upserts the state machine entry and
	// returns the resulting state ID and latest commitment ID.
	UpsertSupplyCommitStateMachine(
		ctx context.Context, arg SupplyCommitMachineParams,
	) (sqlc.UpsertSupplyCommitStateMachineRow, error)

	// QueryPendingSupplyCommitTransition fetches the latest non-finalized
	// transition for a group key.
	QueryPendingSupplyCommitTransition(ctx context.Context,
		groupKey []byte) (SupplyCommitTransition, error)

	// InsertSupplyCommitTransition inserts a new transition record.
	InsertSupplyCommitTransition(ctx context.Context,
		arg InsertSupplyCommitTransition) (int64, error)

	// InsertSupplyUpdateEvent inserts a new supply update event associated
	// with a transition.
	InsertSupplyUpdateEvent(ctx context.Context,
		arg InsertSupplyUpdateEvent) error

	// UpsertChainTx upserts a chain transaction.
	UpsertChainTx(
		ctx context.Context, arg UpsertChainTxParams,
	) (int64, error)

	// UpdateSupplyCommitTransitionCommitment updates the pending commit tx
	// ID for a
	// transition and the new commitment ID.
	UpdateSupplyCommitTransitionCommitment(ctx context.Context,
		arg UpdateSupplyCommitTransitionCommitmentParams) error

	// InsertSupplyCommitment inserts a new supply commitment record.
	InsertSupplyCommitment(ctx context.Context,
		arg sqlc.InsertSupplyCommitmentParams) (int64, error)

	// QuerySupplyCommitStateMachine fetches the state machine details.
	QuerySupplyCommitStateMachine(ctx context.Context,
		groupKey []byte) (QuerySupplyStateMachineResp, error)

	// QuerySupplyUpdateEvents fetches all update events for a transition.
	QuerySupplyUpdateEvents(ctx context.Context,
		transitionID int64) ([]QuerySupplyUpdateResp, error)

	// QuerySupplyCommitment fetches a specific supply commitment by ID.
	QuerySupplyCommitment(ctx context.Context,
		commitID int64) (sqlc.SupplyCommitment, error)

	// FetchChainTx fetches a chain transaction by its TXID.
	FetchChainTx(ctx context.Context, txid []byte) (ChainTxn, error)

	// UpdateSupplyCommitmentChainDetails updates the chain-specific details
	// of a supply commitment after confirmation.
	UpdateSupplyCommitmentChainDetails(ctx context.Context,
		arg SupplyCommitChainDetails) error

	// UpdateSupplyCommitmentRoot updates the SMT root hash and sum for a
	// given supply commitment.
	UpdateSupplyCommitmentRoot(ctx context.Context,
		arg UpdateSupplyCommitmentRootParams) error

	// FinalizeSupplyCommitTransition marks a transition as finalized.
	FinalizeSupplyCommitTransition(ctx context.Context,
		transitionID int64) error

	// QueryExistingPendingTransition fetches the ID of an existing
	// non-finalized transition for a group key. Returns sql.ErrNoRows if
	// none exists.
	QueryExistingPendingTransition(ctx context.Context,
		groupKey []byte) (int64, error)

	// FetchInternalKeyByID fetches an internal key by its primary key ID.
	FetchInternalKeyByID(ctx context.Context,
		keyID int64) (FetchInternalKeyByIDRow, error)

	// FetchChainTxByID fetches a chain transaction by its primary key ID.
	FetchChainTxByID(ctx context.Context,
		txnID int64) (FetchChainTxByIDRow, error)

	// FetchUniverseSupplyRoot fetches the root hash and sum for a supply
	// tree namespace.
	FetchUniverseSupplyRoot(ctx context.Context,
		namespaceRoot string) (FetchUniverseSupplyRootRow, error)

	TreeStore
	BaseUniverseStore
}

// SupplyCommitTxOptions defines the set of functional options that can be used
// to control the transaction behavior of the SupplyCommitMachine.
type SupplyCommitTxOptions struct {
	// readOnly governs if a read-only transaction is used or not.
	readOnly bool
}

// ReadOnly returns true if the transaction should be read only.
func (s *SupplyCommitTxOptions) ReadOnly() bool {
	return s.readOnly
}

// NewSupplyCommitReadTx creates a new read-only transaction option set.
func NewSupplyCommitReadTx() SupplyCommitTxOptions {
	return SupplyCommitTxOptions{
		readOnly: true,
	}
}

// BatchedSupplyCommitStore is a wrapper around the base SupplyCommitStore that
// allows us to perform batch queries within a single transaction.
type BatchedSupplyCommitStore interface {
	SupplyCommitStore

	// We embed the BatchedTx interface for BaseUniverseStore as it includes
	// TreeStore methods needed by SupplyCommitStore.
	BatchedTx[SupplyCommitStore]
}

// SupplyCommitMachine implements the supplycommit.CommitmentTracker and
// supplycommit.StateMachineStore interfaces using the database queries
// defined in SupplyCommitStore.
type SupplyCommitMachine struct {
	db BatchedSupplyCommitStore
}

// NewSupplyCommitMachine creates a new SupplyCommitMachine instance.
func NewSupplyCommitMachine(db BatchedSupplyCommitStore) *SupplyCommitMachine {
	return &SupplyCommitMachine{
		db: db,
	}
}

// UnspentPrecommits returns the set of unspent pre-commitments for a given
// asset spec. The asset spec will only specify a group key, and not also an
// asset ID.
func (s *SupplyCommitMachine) UnspentPrecommits(ctx context.Context,
	assetSpec asset.Specifier) lfn.Result[supplycommit.PreCommits] {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[supplycommit.PreCommits](ErrMissingGroupKey)
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	var preCommits supplycommit.PreCommits
	readTx := NewSupplyCommitReadTx()
	dbErr := s.db.ExecTx(ctx, &readTx, func(db SupplyCommitStore) error {
		rows, err := db.FetchUnspentPrecommits(ctx, groupKeyBytes)
		if err != nil {
			// It's okay if there are no unspent pre-commits.
			if err == sql.ErrNoRows {
				return nil
			}
			return fmt.Errorf("error fetching unspent "+
				"precommits: %w", err)
		}

		// For each pre-commitment, parse the internal key and group
		// key, and assemble the final struct as needed by the
		// interface.
		preCommits = make(supplycommit.PreCommits, 0, len(rows))
		for _, row := range rows {
			internalKey, err := btcec.ParsePubKey(
				row.TaprootInternalKey,
			)
			if err != nil {
				return fmt.Errorf("error parsing internal "+
					"key: %w", err)
			}

			groupPubKey, err := btcec.ParsePubKey(row.GroupKey)
			if err != nil {
				return fmt.Errorf("error parsing group key: %w",
					err)
			}

			var mintingTx wire.MsgTx
			err = mintingTx.Deserialize(bytes.NewReader(row.RawTx))
			if err != nil {
				return fmt.Errorf("error deserializing "+
					"minting tx: %w", err)
			}

			preOut := tapgarden.PreCommitmentOutput{
				OutIdx:      uint32(row.TxOutputIndex),
				InternalKey: *internalKey,
				GroupPubKey: *groupPubKey,
			}
			preCommit := supplycommit.PreCommitment{
				BlockHeight: uint32(
					row.BlockHeight.Int32,
				),
				MintingTxn:          &mintingTx,
				PreCommitmentOutput: preOut,
			}
			preCommits = append(preCommits, preCommit)
		}

		return nil
	})
	if dbErr != nil {
		return lfn.Err[supplycommit.PreCommits](dbErr)
	}

	return lfn.Ok(preCommits)
}

// SupplyCommit returns the root commitment for a given asset spec. From the PoV
// of the chain, this is a singleton instance.
func (s *SupplyCommitMachine) SupplyCommit(ctx context.Context,
	assetSpec asset.Specifier) supplycommit.RootCommitResp {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[lfn.Option[supplycommit.RootCommitment]](
			ErrMissingGroupKey,
		)
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	var rootCommitmentOpt lfn.Option[supplycommit.RootCommitment]

	readTx := NewSupplyCommitReadTx()
	dbErr := s.db.ExecTx(ctx, &readTx, func(db SupplyCommitStore) error {
		row, err := db.FetchSupplyCommit(ctx, groupKeyBytes)
		if err != nil {
			// If no commitment is found, return None.
			if err == sql.ErrNoRows {
				return nil
			}

			return fmt.Errorf("error fetching supply commit: %w",
				err)
		}

		internalKey, err := btcec.ParsePubKey(row.InternalKey)
		if err != nil {
			return fmt.Errorf("error parsing internal key: %w", err)
		}

		outputKey, err := btcec.ParsePubKey(row.OutputKey)
		if err != nil {
			return fmt.Errorf("error parsing output key: %w", err)
		}

		var commitTx wire.MsgTx
		err = commitTx.Deserialize(bytes.NewReader(row.RawTx))
		if err != nil {
			return fmt.Errorf("error deserializing commit tx: %w",
				err)
		}

		// Construct the root node directly from the stored hash and
		// sum. Handle potential NULL values if the root wasn't set yet
		// (though FetchSupplyCommit filters for confirmed TX, so it
		// should be set).
		var (
			rootHash mssmt.NodeHash
			rootSum  uint64
			rootNode *mssmt.BranchNode
		)
		if row.RootHash != nil && row.RootSum.Valid {
			copy(rootHash[:], row.RootHash)
			rootSum = uint64(row.RootSum.Int64)
			rootNode = mssmt.NewComputedBranch(rootHash, rootSum)
		} else {
			// Should not happen due to query filter, but handle
			// defensively.
			log.Warnf("SupplyCommit: Fetched confirmed commit %d "+
				"but root hash/sum is NULL", row.CommitID)

			rootNode = mssmt.NewComputedBranch(
				mssmt.EmptyTreeRootHash, 0,
			)
		}

		rootCommitment := supplycommit.RootCommitment{
			Txn:         &commitTx,
			TxOutIdx:    uint32(row.OutputIndex.Int32),
			InternalKey: internalKey,
			OutputKey:   outputKey,
			SupplyRoot:  rootNode,
		}
		rootCommitmentOpt = lfn.Some(rootCommitment)

		return nil
	})
	if dbErr != nil {
		return lfn.Err[lfn.Option[supplycommit.RootCommitment]](dbErr)
	}

	return lfn.Ok(rootCommitmentOpt)
}

// stateToDBString maps a supplycommit.State interface to its database string
// representation.
func stateToDBString(state supplycommit.State) (string, error) {
	switch state.(type) {
	case *supplycommit.DefaultState:
		return "DefaultState", nil
	case *supplycommit.UpdatesPendingState:
		return "UpdatesPendingState", nil
	case *supplycommit.CommitTreeCreateState:
		return "CommitTreeCreateState", nil
	case *supplycommit.CommitTxCreateState:
		return "CommitTxCreateState", nil
	case *supplycommit.CommitTxSignState:
		return "CommitTxSignState", nil
	case *supplycommit.CommitBroadcastState:
		return "CommitBroadcastState", nil
	case *supplycommit.CommitFinalizeState:
		return "CommitFinalizeState", nil
	default:
		return "", fmt.Errorf("unknown state type: %T", state)
	}
}

// stateToInt maps a supplycommit.State to its integer ID used in the DB.
func stateToInt(state supplycommit.State) (int32, error) {
	switch state.(type) {
	case *supplycommit.DefaultState:
		return 0, nil
	case *supplycommit.UpdatesPendingState:
		return 1, nil
	case *supplycommit.CommitTreeCreateState:
		return 2, nil
	case *supplycommit.CommitTxCreateState:
		return 3, nil
	case *supplycommit.CommitTxSignState:
		return 4, nil
	case *supplycommit.CommitBroadcastState:
		return 5, nil
	case *supplycommit.CommitFinalizeState:
		return 6, nil
	default:
		return -1, fmt.Errorf("unknown state type: %T", state)
	}
}

// intToState maps an integer state ID from the DB to a supplycommit.State.
func intToState(stateID int32) (supplycommit.State, error) {
	switch stateID {
	case 0:
		return &supplycommit.DefaultState{}, nil
	case 1:
		return &supplycommit.UpdatesPendingState{}, nil
	case 2:
		return &supplycommit.CommitTreeCreateState{}, nil
	case 3:
		return &supplycommit.CommitTxCreateState{}, nil
	case 4:
		return &supplycommit.CommitTxSignState{}, nil
	case 5:
		return &supplycommit.CommitBroadcastState{}, nil
	case 6:
		return &supplycommit.CommitFinalizeState{}, nil
	default:
		return nil, fmt.Errorf("unknown state ID: %d", stateID)
	}
}

// updateTypeToInt maps a supplycommit.SupplySubTree to its integer ID.
func updateTypeToInt(treeType supplycommit.SupplySubTree) (int32, error) {
	switch treeType {
	case supplycommit.MintTreeType:
		return 0, nil
	case supplycommit.BurnTreeType:
		return 1, nil
	case supplycommit.IgnoreTreeType:
		return 2, nil
	default:
		return -1, fmt.Errorf("unknown tree type: %v", treeType)
	}
}

// serializeSupplyUpdateEvent encodes a SupplyUpdateEvent into bytes.
func serializeSupplyUpdateEvent(w io.Writer,
	event supplycommit.SupplyUpdateEvent) error {

	switch e := event.(type) {
	case *supplycommit.NewMintEvent:
		return e.Encode(w)

	case *supplycommit.NewBurnEvent:
		return e.Encode(w)

	case *supplycommit.NewIgnoreEvent:
		return e.Encode(w)

	default:
		return fmt.Errorf("unknown event type: %T", event)
	}
}

// deserializeSupplyUpdateEvent decodes bytes into a SupplyUpdateEvent.
func deserializeSupplyUpdateEvent(typeName string,
	r io.Reader) (supplycommit.SupplyUpdateEvent, error) {

	switch typeName {
	case "mint":
		mint := new(supplycommit.NewMintEvent)
		if err := mint.Decode(r); err != nil {
			return nil, fmt.Errorf("failed to decode mint "+
				"event: %w", err)
		}

		return mint, nil
	case "burn":
		burn := new(supplycommit.NewBurnEvent)
		if err := burn.Decode(r); err != nil {
			return nil, fmt.Errorf("failed to decode burn "+
				"event: %w", err)
		}

		return burn, nil
	case "ignore":
		ignore := new(supplycommit.NewIgnoreEvent)
		if err := ignore.Decode(r); err != nil {
			return nil, fmt.Errorf("failed to decode ignore "+
				"event: %w", err)
		}

		return ignore, nil

	default:
		return nil, fmt.Errorf("unknown update type name: %s", typeName)
	}
}

// InsertPendingUpdate attempts to insert a new pending update into the
// update log of the target supply commit state machine.
func (s *SupplyCommitMachine) InsertPendingUpdate(ctx context.Context,
	assetSpec asset.Specifier, event supplycommit.SupplyUpdateEvent) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	var writeTx SupplyCommitTxOptions // Default read-write
	return s.db.ExecTx(ctx, &writeTx, func(db SupplyCommitStore) error {
		// First, we'll upsert a new state machine. We pass a null state
		// name, as it'll be made with default if doesn't exist. The
		// query returns the actual state ID set and the latest
		// commitment ID.
		upsertResult, err := db.UpsertSupplyCommitStateMachine(
			ctx, SupplyCommitMachineParams{
				GroupKey:  groupKeyBytes,
				StateName: sql.NullString{},
			},
		)
		if err != nil {
			return fmt.Errorf("failed initial upsert for "+
				"state machine: %w", err)
		}
		currentStateID := upsertResult.CurrentStateID

		// Make sure that we're in either the DefaultState or
		// UpdatesPendingState state as a sanity check.
		currentState, err := intToState(currentStateID)
		if err != nil {
			// This indicates an unexpected state ID returned
			// from the DB.
			return fmt.Errorf("invalid state ID %d "+
				"returned from upsert: %w", currentStateID, err)
		}
		currentStateName := currentState.String()
		if currentStateName != "DefaultState" &&
			currentStateName != "UpdatesPendingState" {

			return fmt.Errorf("cannot insert pending "+
				"update in state: %s", currentStateName)
		}

		// Now that we know the state machine is in the proper state,
		// we'll fetch the transition ID, which will be needed below.
		var transitionID int64
		existingTransitionID, err := db.QueryExistingPendingTransition(
			ctx, groupKeyBytes,
		)
		if err != nil {
			// If no existing pending transition, create one.
			if errors.Is(err, sql.ErrNoRows) {
				// Use the latest commitment ID returned by the
				// upsert.
				latestCommitmentID := upsertResult.LatestCommitmentID //nolint:lll

				transitionID, err = db.InsertSupplyCommitTransition( //nolint:lll
					ctx, InsertSupplyCommitTransition{
						StateMachineGroupKey: groupKeyBytes,      //nolint:lll
						OldCommitmentID:      latestCommitmentID, //nolint:lll
						Finalized:            false,
					},
				)
				if err != nil {
					return fmt.Errorf("failed to insert "+
						"new transition: %w", err)
				}
			} else {
				return fmt.Errorf("failed to query existing "+
					"pending transition: %w", err)
			}
		} else {
			// Found existing pending transition
			transitionID = existingTransitionID
		}

		// With the transition created or found, we can now serialize,
		// then insert the update event.
		var b bytes.Buffer
		err = serializeSupplyUpdateEvent(&b, event)
		if err != nil {
			return fmt.Errorf("failed to serialize event "+
				"data: %w", err)
		}
		updateTypeID, err := updateTypeToInt(event.SupplySubTreeType())
		if err != nil {
			return fmt.Errorf("failed to map update type: %w", err)
		}
		err = db.InsertSupplyUpdateEvent(
			ctx, InsertSupplyUpdateEvent{
				TransitionID: transitionID,
				UpdateTypeID: updateTypeID,
				EventData:    b.Bytes(),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to insert update "+
				"event: %w", err)
		}

		// Finally, we'll explicitly set the state machine to the
		// UpdatesPendingState.
		updatesPendingStateName, err := stateToDBString(
			&supplycommit.UpdatesPendingState{},
		)
		if err != nil {
			return fmt.Errorf("error getting pending "+
				"state name: %w", err)
		}
		// We only update the state name here, leaving the commitment ID
		// as is (by passing NULL).
		_, err = db.UpsertSupplyCommitStateMachine(
			ctx, SupplyCommitMachineParams{ //nolint:gocritic
				GroupKey:  groupKeyBytes,
				StateName: sqlStr(updatesPendingStateName),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update state "+
				"machine to pending: %w", err)
		}

		return nil
	})
}

// InsertSignedCommitTx associates a new signed commitment anchor transaction
// with the current active supply commitment state transition.
func (s *SupplyCommitMachine) InsertSignedCommitTx(ctx context.Context,
	assetSpec asset.Specifier, commitDetails supplycommit.SupplyCommitTxn,
) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	commitTx := commitDetails.Txn
	internalKey := commitDetails.InternalKey
	outputKey := commitDetails.OutputKey
	outputIndex := commitDetails.OutputIndex

	var writeTx SupplyCommitTxOptions
	return s.db.ExecTx(ctx, &writeTx, func(db SupplyCommitStore) error {
		// First, we'll locate the current pending transition for the
		// state machine.
		pendingTransition, err := db.QueryPendingSupplyCommitTransition(
			ctx, groupKeyBytes,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("no pending transition "+
					"found for group key %x",
					groupKeyBytes)
			}

			return fmt.Errorf("failed to query pending "+
				"transition: %w", err)
		}

		// Next, we'll upsert the chain transaction on disk. The block
		// related fields are nil as this hasn't been confirmed yet.
		var txBytes bytes.Buffer
		if err := commitTx.Serialize(&txBytes); err != nil {
			return fmt.Errorf("failed to serialize commit "+
				"tx: %w", err)
		}
		txid := commitTx.TxHash()
		chainTxID, err := db.UpsertChainTx(ctx, UpsertChainTxParams{
			Txid:  txid[:],
			RawTx: txBytes.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("failed to upsert commit chain tx: "+
				"%w", err)
		}

		// Upsert the internal key to get its ID. We assume key family
		// and index 0 for now, as this key is likely externally.
		internalKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
			RawKey: internalKey.SerializeCompressed(),
		})
		if err != nil {
			return fmt.Errorf("failed to upsert internal key %x: "+
				"%w",
				internalKey.SerializeCompressed(), err)
		}

		// Insert the new commitment record. Chain details (block
		// height, header, proof, output index) are NULL at this stage.
		//nolint:lll
		newCommitmentID, err := db.InsertSupplyCommitment(ctx, sqlc.InsertSupplyCommitmentParams{
			GroupKey:       groupKeyBytes,
			ChainTxnID:     chainTxID,
			InternalKeyID:  internalKeyID,
			OutputKey:      outputKey.SerializeCompressed(), //nolint:lll
			SupplyRootHash: nil,
			SupplyRootSum:  sql.NullInt64{},
			OutputIndex:    sqlInt32(outputIndex),
		})
		if err != nil {
			return fmt.Errorf("failed to insert new supply "+
				"commitment: %w", err)
		}

		// Update the transition record to link to the new commitment ID
		// and the pending chain transaction ID in a single query.
		err = db.UpdateSupplyCommitTransitionCommitment(
			ctx, UpdateSupplyCommitTransitionCommitmentParams{
				NewCommitmentID:    sqlInt64(newCommitmentID),
				PendingCommitTxnID: sqlInt64(chainTxID),
				TransitionID:       pendingTransition.TransitionID, //nolint:lll
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update transition "+
				"commitment: %w", err)
		}

		// As the final step, we'll now update the state on disk to move
		// broadcast the commit txn we just signed.
		// to the broadcast state. This ensures that on restart we'll
		broadcastStateName, err := stateToDBString(
			&supplycommit.CommitBroadcastState{},
		)
		if err != nil {
			return fmt.Errorf("error getting broadcast state "+
				"name: %w", err)
		}
		// We only update the state name here, leaving the commitment ID
		// as is (by passing NULL).
		_, err = db.UpsertSupplyCommitStateMachine(
			ctx, SupplyCommitMachineParams{
				GroupKey:  groupKeyBytes,
				StateName: sqlStr(broadcastStateName),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update state machine "+
				"state: %w", err)
		}

		return nil
	})
}

// CommitState commits the state of the state machine to disk.
func (s *SupplyCommitMachine) CommitState(ctx context.Context,
	assetSpec asset.Specifier, state supplycommit.State) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	newStateName, err := stateToDBString(state)
	if err != nil {
		return fmt.Errorf("failed to map state to string: %w", err)
	}

	var writeTx SupplyCommitTxOptions
	return s.db.ExecTx(ctx, &writeTx, func(db SupplyCommitStore) error {
		// We only update the state name here, leaving the commitment ID
		// as is (by passing NULL).
		_, err = db.UpsertSupplyCommitStateMachine(
			ctx, SupplyCommitMachineParams{
				GroupKey:  groupKeyBytes,
				StateName: sqlStr(newStateName),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update state machine "+
				"state: %w", err)
		}
		return nil
	})
}

// fetchCommitment is a helper to fetch and reconstruct a RootCommitment and
// its associated chain confirmation details.
func fetchCommitment(ctx context.Context, db SupplyCommitStore,
	commitID sql.NullInt64, groupKeyBytes []byte,
) (lfn.Option[supplycommit.RootCommitment], lfn.Option[commitmentChainInfo], error) { //nolint:lll

	if !commitID.Valid {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](), nil
	}

	// First, fetch the supply commitment itself.
	commit, err := db.QuerySupplyCommitment(ctx, commitID.Int64)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return lfn.None[supplycommit.RootCommitment](),
				lfn.None[commitmentChainInfo](), nil
		}
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to query commitment %d: %w",
				commitID.Int64, err)
	}

	// Fetch and parse keys.
	internalKeyRow, err := db.FetchInternalKeyByID(
		ctx, commit.InternalKeyID,
	)
	if err != nil {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to fetch internal key %d "+
				"for commit %d: %w",
				commit.InternalKeyID, commitID.Int64, err)
	}
	internalKey, err := btcec.ParsePubKey(internalKeyRow.RawKey)
	if err != nil {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to parse internal key for "+
				"commit %d: %w", commitID.Int64, err)
	}
	outputKey, err := btcec.ParsePubKey(commit.OutputKey)
	if err != nil {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to parse output key for "+
				"commit %d: %w", commitID.Int64, err)
	}

	// Fetch and deserialize the transaction.
	var commitTx wire.MsgTx
	chainTxRow, err := db.FetchChainTxByID(ctx, commit.ChainTxnID)
	if err != nil {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to fetch chain tx %d "+
				"for commit %d: %w",
				commit.ChainTxnID, commitID.Int64, err)
	}
	err = commitTx.Deserialize(bytes.NewReader(chainTxRow.RawTx))
	if err != nil {
		return lfn.None[supplycommit.RootCommitment](),
			lfn.None[commitmentChainInfo](),
			fmt.Errorf("failed to deserialize commit tx "+
				"for commit %d: %w", commitID.Int64, err)
	}

	// Construct the SMT root node from the stored hash and sum. If they are
	// NULL (e.g., initial commit before ApplyStateTransition ran), use the
	// empty root.
	var rootNode *mssmt.BranchNode
	if commit.SupplyRootHash == nil || !commit.SupplyRootSum.Valid {
		log.Warnf("fetchCommitment: Supply root hash/sum is NULL for "+
			"commit %d, using empty root", commitID.Int64)
		rootNode = mssmt.NewComputedBranch(mssmt.EmptyTreeRootHash, 0)
	} else {
		var rootHash mssmt.NodeHash
		copy(rootHash[:], commit.SupplyRootHash)
		rootSum := uint64(commit.SupplyRootSum.Int64)
		rootNode = mssmt.NewComputedBranch(rootHash, rootSum)
	}

	// Construct the main RootCommitment object.
	rootCommitment := supplycommit.RootCommitment{
		Txn:         &commitTx,
		TxOutIdx:    uint32(commit.OutputIndex.Int32),
		InternalKey: internalKey,
		OutputKey:   outputKey,
		SupplyRoot:  rootNode,
	}

	// Now, attempt to construct the chain info if confirmed.
	var chainInfoOpt lfn.Option[commitmentChainInfo]

	// Check if block height is valid first.
	if commit.BlockHeight.Valid {
		blockHeight := uint32(commit.BlockHeight.Int32)

		// Deserialize block header if present.
		var blockHeader *wire.BlockHeader
		if len(commit.BlockHeader) > 0 {
			blockHeader = &wire.BlockHeader{}
			err = blockHeader.Deserialize(
				bytes.NewReader(commit.BlockHeader),
			)
			if err != nil {
				// Log error but don't fail the whole fetch
				log.Errorf("fetchCommitment: failed to "+
					"deserialize block header "+
					"for commit %d: %v", commitID.Int64,
					err)
				blockHeader = nil
			}
		}

		// Deserialize merkle proof if present.
		var merkleProof *proof.TxMerkleProof
		if len(commit.MerkleProof) > 0 {
			merkleProof = &proof.TxMerkleProof{}
			err = merkleProof.Decode(bytes.NewReader(
				commit.MerkleProof,
			))
			if err != nil {
				// Log error but don't fail the whole fetch
				log.Errorf("fetchCommitment: failed to "+
					"decode merkle proof for commit %d: "+
					"%v", commitID.Int64, err)
				merkleProof = nil
			}
		}

		// If we have all parts, construct the chain info.
		if blockHeader != nil && merkleProof != nil {
			chainInfoOpt = lfn.Some(commitmentChainInfo{
				BlockHeader: blockHeader,
				MerkleProof: merkleProof,
				BlockHeight: blockHeight,
			})
		} else {
			log.Warnf("fetchCommitment: commit %d has block "+
				"height but missing header (%v) or proof (%v)",
				commitID.Int64, blockHeader == nil,
				merkleProof == nil)
		}
	}

	return lfn.Some(rootCommitment), chainInfoOpt, nil
}

// FetchState attempts to fetch the state of the state machine for the
// target asset specifier.
func (s *SupplyCommitMachine) FetchState(ctx context.Context,
	assetSpec asset.Specifier) (supplycommit.State,
	lfn.Option[supplycommit.SupplyStateTransition], error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, lfn.None[supplycommit.SupplyStateTransition](),
			ErrMissingGroupKey
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	var (
		state            supplycommit.State
		stateTransition  supplycommit.SupplyStateTransition
		foundTransition  bool
		pendingUpdates   []supplycommit.SupplyUpdateEvent
		oldCommitmentOpt lfn.Option[supplycommit.RootCommitment]
		newCommit        supplycommit.RootCommitment
		chainProofOpt    lfn.Option[supplycommit.ChainProof]
	)

	readTx := NewSupplyCommitReadTx()
	err := s.db.ExecTx(ctx, &readTx, func(db SupplyCommitStore) error {
		// First, we'll attempt to fetch the supply state machine for
		// this group key.
		stateMachine, err := db.QuerySupplyCommitStateMachine(
			ctx, groupKeyBytes,
		)
		if err != nil {
			// If no state machine exists, return default state and
			// no transition.
			if errors.Is(err, sql.ErrNoRows) {
				// Not an error, just no state persisted yet.
				state = &supplycommit.DefaultState{}
				return nil
			}
			return fmt.Errorf("failed to query state machine: "+
				"%w", err)
		}

		// Map the DB state ID to the interface state type.
		state, err = intToState(stateMachine.CurrentStateID)
		if err != nil {
			return fmt.Errorf("failed to map state ID: %w", err)
		}

		// Next, we'll fetch the current pending state transition, if it
		// exists for this group key. If not, then we can return early
		// as we only have the default state.
		dbTransition, err := db.QueryPendingSupplyCommitTransition(
			ctx, groupKeyBytes,
		)
		if err != nil {
			// No pending transition, state transition remains
			// empty.
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to query pending "+
				"transition: %w", err)
		}
		foundTransition = true

		// Now that we know we have a state transition, we'll query for
		// all the pending updates related to the state transition.
		eventRows, err := db.QuerySupplyUpdateEvents(
			ctx, dbTransition.TransitionID,
		)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to query update events: "+
				"%w", err)
		}
		pendingUpdates = make(
			[]supplycommit.SupplyUpdateEvent, 0, len(eventRows),
		)
		for _, eventRow := range eventRows {
			event, err := deserializeSupplyUpdateEvent(
				eventRow.UpdateTypeName,
				bytes.NewReader(eventRow.EventData),
			)
			if err != nil {
				return fmt.Errorf("failed to deserialize "+
					"event: %w", err)
			}
			pendingUpdates = append(pendingUpdates, event)
		}

		// Next, we'll fetch the old and new commitments. If this is the
		// very first state transition, there won't be an old
		// commitment.
		oldCommitmentOpt, _, err = fetchCommitment(
			ctx, db, dbTransition.OldCommitmentID, groupKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed fetching old "+
				"commitment: %w", err)
		}
		newCommitmentOpt, newCommitChainInfoOpt, err := fetchCommitment(
			ctx, db, dbTransition.NewCommitmentID, groupKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed fetching new "+
				"commitment: %w", err)
		}

		// Construct the ChainProof if the new commitment's chain info
		// is present.
		newCommitChainInfoOpt.WhenSome(func(info commitmentChainInfo) {
			if info.BlockHeader != nil && info.MerkleProof != nil {
				chainProofOpt = lfn.Some(supplycommit.ChainProof{ //nolint:lll
					Header:      *info.BlockHeader,
					BlockHeight: info.BlockHeight,
					MerkleProof: *info.MerkleProof,
				})
			}
		})

		newCommit = newCommitmentOpt.UnwrapOr(
			supplycommit.RootCommitment{},
		)

		return nil
	})
	if err != nil {
		return nil, lfn.None[supplycommit.SupplyStateTransition](), err
	}

	// If a transition was found, reconstruct it and wrap in Some.
	if foundTransition {
		stateTransition = supplycommit.SupplyStateTransition{
			OldCommitment:  oldCommitmentOpt,
			PendingUpdates: pendingUpdates,
			NewCommitment:  newCommit,
			ChainProof:     chainProofOpt,
		}
		return state, lfn.Some(stateTransition), nil
	}

	// No transition was found (err was sql.ErrNoRows earlier).
	return state, lfn.None[supplycommit.SupplyStateTransition](), nil
}

// ApplyStateTransition applies a new state transition to the target state
// machine.
func (s *SupplyCommitMachine) ApplyStateTransition(
	ctx context.Context, assetSpec asset.Specifier,
	transition supplycommit.SupplyStateTransition) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := groupKey.SerializeCompressed()

	// Ensure we have the new commitment details.
	newCommitment := transition.NewCommitment
	if newCommitment.SupplyRoot == nil || newCommitment.Txn == nil {
		return fmt.Errorf("ApplyStateTransition requires a complete " +
			"NewCommitment")
	}

	var writeTx SupplyCommitTxOptions
	return s.db.ExecTx(ctx, &writeTx, func(db SupplyCommitStore) error {
		// First, we'll locate the state transition that we need to
		// finalize based on the group key.
		dbTransition, err := db.QueryPendingSupplyCommitTransition(
			ctx, groupKeyBytes,
		)
		if err != nil {
			// If no pending transition exists, then we'll return an
			// error.
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("cannot apply transition, "+
					"no pending transition found for %x",
					groupKeyBytes)
			}
			return fmt.Errorf("failed to query pending "+
				"transition: %w", err)
		}
		transitionID := dbTransition.TransitionID

		// Next, we'll apply all the pending updates to the supply
		// sub-trees, then use that to update the root tree.
		_, err = applySupplyUpdatesInternal(
			ctx, db, assetSpec, transition.PendingUpdates,
		)
		if err != nil {
			return fmt.Errorf("failed to apply SMT updates: "+
				"%w", err)
		}

		// Next, we'll update the supply commitment data, before we do
		// that, perform some basic sanity checks.
		if !dbTransition.NewCommitmentID.Valid {
			return fmt.Errorf("pending transition %d has no "+
				"NewCommitmentID", transitionID)
		}
		newCommitmentID := dbTransition.NewCommitmentID.Int64
		if !dbTransition.PendingCommitTxnID.Valid {
			return fmt.Errorf("pending transition %d has no "+
				"PendingCommitTxnID", transitionID)
		}
		chainTxnID := dbTransition.PendingCommitTxnID.Int64

		// Update the commitment record with the calculated root hash
		// and sum.
		finalRootSupplyRoot, err := applySupplyUpdatesInternal(
			ctx, db, assetSpec, transition.PendingUpdates,
		)
		if err != nil {
			return fmt.Errorf("failed to apply SMT updates: "+
				"%w", err)
		}
		finalRootHash := finalRootSupplyRoot.NodeHash()
		finalRootSum := finalRootSupplyRoot.NodeSum()
		err = db.UpdateSupplyCommitmentRoot(
			ctx, UpdateSupplyCommitmentRootParams{
				CommitID:       newCommitmentID,
				SupplyRootHash: finalRootHash[:],
				SupplyRootSum:  sqlInt64(int64(finalRootSum)),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update commitment root "+
				"hash/sum for commit %d: %w",
				newCommitmentID, err)
		}

		// Next, we'll serialize the merkle proofs and block header, so
		// we can update them on disk.
		var (
			proofBuf  bytes.Buffer
			headerBuf bytes.Buffer
		)
		chainProof, err := transition.ChainProof.UnwrapOrErr(
			fmt.Errorf("chain proof is required"),
		)
		if err != nil {
			return fmt.Errorf("failed to unwrap "+
				"chain proof: %w", err)
		}
		err = chainProof.MerkleProof.Encode(&proofBuf)
		if err != nil {
			return fmt.Errorf("failed to encode "+
				"merkle proof: %w", err)
		}
		err = chainProof.Header.Serialize(&headerBuf)
		if err != nil {
			return fmt.Errorf("failed to "+
				"serialize block header: %w",
				err)
		}
		blockHeight := sqlInt32(chainProof.BlockHeight)

		// With all the information serialized above, we'll now update
		// the chain proof information for this current supply commit.
		err = db.UpdateSupplyCommitmentChainDetails(
			ctx, SupplyCommitChainDetails{
				CommitID:    newCommitmentID,
				MerkleProof: proofBuf.Bytes(),
				OutputIndex: sqlInt32(newCommitment.TxOutIdx),
				BlockHeader: headerBuf.Bytes(),
				ChainTxnID:  chainTxnID,
				BlockHeight: blockHeight,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to update commitment chain "+
				"details: %w", err)
		}

		// Also update the chain_txns record itself with the
		// confirmation details (block hash, height, index).
		var commitTxBytes bytes.Buffer
		err = newCommitment.Txn.Serialize(&commitTxBytes)
		if err != nil {
			return fmt.Errorf("failed to serialize commit tx for "+
				"update: %w", err)
		}
		commitTxid := newCommitment.Txn.TxHash()

		_, err = db.UpsertChainTx(ctx, UpsertChainTxParams{
			Txid:      commitTxid[:],
			RawTx:     commitTxBytes.Bytes(),
			ChainFees: 0,
			BlockHash: lnutils.ByteSlice(
				chainProof.Header.BlockHash(),
			),
			BlockHeight: blockHeight,
			TxIndex:     sqlInt32(chainProof.TxIndex),
		})
		if err != nil {
			return fmt.Errorf("failed to update chain_txns "+
				"confirmation: %w", err)
		}

		// To finish up our book keeping, we'll now finalize the state
		// transition on disk.
		err = db.FinalizeSupplyCommitTransition(ctx, transitionID)
		if err != nil {
			return fmt.Errorf("failed to finalize transition: "+
				"%w", err)
		}

		// Finally, we'll update the state on disk to be default again,
		// while also pointing to the _new_ supply commitment on disk.
		// We'll update both the state name and the latest commitment
		// ID.
		defaultStateName, err := stateToDBString(
			&supplycommit.DefaultState{},
		)
		if err != nil {
			return fmt.Errorf("error getting default state "+
				"name: %w", err)
		}

		_, err = db.UpsertSupplyCommitStateMachine(
			ctx, SupplyCommitMachineParams{
				GroupKey:           groupKeyBytes,
				StateName:          sqlStr(defaultStateName),
				LatestCommitmentID: dbTransition.NewCommitmentID, //nolint:lll
			})
		if err != nil {
			return fmt.Errorf("failed to update state machine to "+
				"default: %w", err)
		}

		return nil
	})
}

// Compile-time assertions to ensure SupplyCommitMachine implements the
// interfaces.
var _ supplycommit.CommitmentTracker = (*SupplyCommitMachine)(nil)
var _ supplycommit.StateMachineStore = (*SupplyCommitMachine)(nil)
