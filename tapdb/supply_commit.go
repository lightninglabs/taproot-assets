package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnutils"
)

type (
	// UnspentMintPreCommits is an alias for the sqlc type representing an
	// unspent supply pre-commitment row where the local node was the
	// issuer.
	UnspentMintPreCommits = sqlc.FetchUnspentMintSupplyPreCommitsRow

	// UnspentPreCommits is an alias for the sqlc type representing an
	// unspent supply pre-commitment row where a remote node was the
	// issuer.
	UnspentPreCommits = sqlc.FetchUnspentSupplyPreCommitsRow

	// SupplyCommit is an alias for the sqlc type.
	SupplyCommit = sqlc.FetchSupplyCommitRow

	// QuerySupplyStateMachineResp is an alias for the sqlc type
	// representing a state machine row.
	QuerySupplyStateMachineResp = sqlc.QuerySupplyCommitStateMachineRow

	// QuerySupplyUpdateResp is an alias for the sqlc type representing
	// supply update event rows.
	QuerySupplyUpdateResp = sqlc.QuerySupplyUpdateEventsRow

	// QueryDanglingSupplyUpdateResp is an alias for the sqlc type
	// representing dangling supply update event rows.
	QueryDanglingSupplyUpdateResp = sqlc.QueryDanglingSupplyUpdateEventsRow

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

	// LinkDanglingSupplyUpdateEventsParams is an alias for the sqlc type.
	//nolint:lll
	LinkDanglingSupplyUpdateEventsParams = sqlc.LinkDanglingSupplyUpdateEventsParams

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

	// PendingSupplyTransition is an alias for the sqlc type.
	PendingSupplyTransition = sqlc.QueryPendingSupplyCommitTransitionRow
)

// SupplyCommitStore is the interface that provides the database methods needed
// to implement the supplycommit.CommitmentTracker and
// supplycommit.StateMachineStore interfaces.
type SupplyCommitStore interface {
	TreeStore
	BaseUniverseStore

	// FetchUnspentMintSupplyPreCommits fetches all unspent supply
	// pre-commitments for the specified asset group key where the local
	// node was the issuer.
	FetchUnspentMintSupplyPreCommits(ctx context.Context,
		groupKey []byte) ([]UnspentMintPreCommits, error)

	// FetchUnspentSupplyPreCommits fetches all unspent supply
	// pre-commitments for the specified asset group key where a remote
	// node was the issuer.
	FetchUnspentSupplyPreCommits(ctx context.Context,
		groupKey []byte) ([]UnspentPreCommits, error)

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
		groupKey []byte) (PendingSupplyTransition, error)

	// FreezePendingTransition marks the current pending transition for a
	// group key as frozen.
	FreezePendingTransition(ctx context.Context, groupKey []byte) error

	// InsertSupplyCommitTransition inserts a new transition record.
	InsertSupplyCommitTransition(ctx context.Context,
		arg InsertSupplyCommitTransition) (int64, error)

	// InsertSupplyUpdateEvent inserts a new supply update event associated
	// with a transition.
	InsertSupplyUpdateEvent(ctx context.Context,
		arg InsertSupplyUpdateEvent) error

	// UpsertChainTx upserts a chain transaction.
	UpsertChainTx(ctx context.Context,
		arg UpsertChainTxParams) (int64, error)

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
		transitionID sql.NullInt64) ([]QuerySupplyUpdateResp, error)

	// QueryDanglingSupplyUpdateEvents fetches all update events for a group
	// key that are not yet associated with a transition.
	QueryDanglingSupplyUpdateEvents(ctx context.Context,
		groupKey []byte) ([]QueryDanglingSupplyUpdateResp, error)

	// LinkDanglingSupplyUpdateEvents associates all dangling update events
	// for a group key with the given transition ID.
	LinkDanglingSupplyUpdateEvents(ctx context.Context,
		arg LinkDanglingSupplyUpdateEventsParams) error

	// QuerySupplyCommitment fetches a specific supply commitment by ID.
	QuerySupplyCommitment(ctx context.Context,
		commitID int64) (sqlc.QuerySupplyCommitmentRow, error)

	// QuerySupplyCommitmentByOutpoint fetches a supply commitment by its
	// outpoint.
	QuerySupplyCommitmentByOutpoint(ctx context.Context,
		arg sqlc.QuerySupplyCommitmentByOutpointParams) (
		sqlc.QuerySupplyCommitmentByOutpointRow, error)

	// QuerySupplyCommitmentBySpentOutpoint fetches a supply commitment by
	// its spent outpoint.
	QuerySupplyCommitmentBySpentOutpoint(ctx context.Context,
		arg sqlc.QuerySupplyCommitmentBySpentOutpointParams) (
		sqlc.QuerySupplyCommitmentBySpentOutpointRow, error)

	// QueryStartingSupplyCommitment fetches the very first supply
	// commitment of an asset group.
	QueryStartingSupplyCommitment(ctx context.Context,
		groupKey []byte) (sqlc.QueryStartingSupplyCommitmentRow, error)

	// QueryLatestSupplyCommitment fetches the latest supply commitment
	// of an asset group based on highest block height.
	QueryLatestSupplyCommitment(ctx context.Context,
		groupKey []byte) (sqlc.QueryLatestSupplyCommitmentRow, error)

	// QuerySupplyCommitmentOutpoint fetches the outpoint of a supply
	// commitment by its ID.
	QuerySupplyCommitmentOutpoint(ctx context.Context,
		commitID int64) (sqlc.QuerySupplyCommitmentOutpointRow, error)

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

	// MarkMintPreCommitSpentByOutpoint marks a supply pre-commitment as
	// spent by its outpoint. The pre-commitment corresponds to an asset
	// issuance where the local node acted as the issuer.
	MarkMintPreCommitSpentByOutpoint(ctx context.Context,
		arg sqlc.MarkMintPreCommitSpentByOutpointParams) error

	// MarkPreCommitSpentByOutpoint marks a supply pre-commitment as spent
	// by its outpoint. The pre-commitment corresponds to an asset issuance
	// where a remote node acted as the issuer.
	MarkPreCommitSpentByOutpoint(ctx context.Context,
		arg sqlc.MarkPreCommitSpentByOutpointParams) error

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
	assetSpec asset.Specifier,
	localIssuerOnly bool) lfn.Result[supplycommit.PreCommits] {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[supplycommit.PreCommits](ErrMissingGroupKey)
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	var preCommits supplycommit.PreCommits
	readTx := ReadTxOption()
	dbErr := s.db.ExecTx(ctx, readTx, func(db SupplyCommitStore) error {
		mintRows, err := db.FetchUnspentMintSupplyPreCommits(
			ctx, groupKeyBytes,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// No unspent pre-commits minted by this local node
			// exist for this group key. Proceed to query for
			// pre-commits from other issuers.

		case err != nil:
			return fmt.Errorf("failed to fetch unspent local node "+
				"issued pre-commit outputs: %w", err)
		}

		// For each pre-commitment, parse the internal key and group
		// key, and assemble the final struct as needed by the
		// interface.
		preCommits = make(supplycommit.PreCommits, 0, len(mintRows))
		for _, row := range mintRows {
			internalKey, err := parseInternalKey(row.InternalKey)
			if err != nil {
				return fmt.Errorf("failed to parse "+
					"pre-commitment internal key: %w", err)
			}

			groupPubKey, err := schnorr.ParsePubKey(row.GroupKey)
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

			preCommit := supplycommit.PreCommitment{
				BlockHeight: uint32(
					row.BlockHeight.Int32,
				),
				MintingTxn:  &mintingTx,
				OutIdx:      uint32(row.TxOutputIndex),
				InternalKey: internalKey,
				GroupPubKey: *groupPubKey,
			}
			preCommits = append(preCommits, preCommit)
		}

		// If any pre-commits were found where we acted as the issuer,
		// return early and skip querying for pre-commits from other
		// issuers. Also return early if the caller explicitly requested
		// only pre-commits issued by the local node.
		if len(preCommits) > 0 || localIssuerOnly {
			return nil
		}

		// No pre-commits found where we were the issuer. So now
		// we'll query for pre-commits from other issuers.
		rows, err := db.FetchUnspentSupplyPreCommits(
			ctx, schnorr.SerializePubKey(groupKey),
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// No unspent pre-commits minted by peer issuer nodes
			// exist for this group key. Return early.
			return nil

		case err != nil:
			return fmt.Errorf("failed to fetch unspent remote "+
				"node issued pre-commit outputs: %w", err)
		}

		// Parse rows into pre-commitment structs.
		for _, row := range rows {
			pubKey, err := btcec.ParsePubKey(row.TaprootInternalKey)
			if err != nil {
				return fmt.Errorf("failed to parse internal "+
					"raw key: %w", err)
			}

			internalKey := keychain.KeyDescriptor{
				PubKey: pubKey,
			}

			groupPubKey, err := schnorr.ParsePubKey(row.GroupKey)
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

			var outpoint wire.OutPoint
			err = readOutPoint(
				bytes.NewReader(row.Outpoint), 0, 0, &outpoint,
			)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrReadOutpoint,
					err)
			}

			preCommit := supplycommit.PreCommitment{
				BlockHeight: uint32(
					row.BlockHeight.Int32,
				),
				MintingTxn:  &mintingTx,
				OutIdx:      outpoint.Index,
				InternalKey: internalKey,
				GroupPubKey: *groupPubKey,
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
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	var rootCommitmentOpt lfn.Option[supplycommit.RootCommitment]

	readTx := ReadTxOption()
	dbErr := s.db.ExecTx(ctx, readTx, func(db SupplyCommitStore) error {
		row, err := db.FetchSupplyCommit(ctx, groupKeyBytes)
		if err != nil {
			// If no commitment is found, return None.
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}

			return fmt.Errorf("error fetching supply commit: %w",
				err)
		}

		rootCommitment, err := parseSupplyCommitmentRow(
			ctx, row.SupplyCommitment, row.TxIndex, db,
		)
		if err != nil {
			return fmt.Errorf("failed to query commitment %d: %w",
				row.SupplyCommitment.CommitID, err)
		}

		rootCommitmentOpt = lfn.Some(*rootCommitment)

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
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// We'll use this helper function to serialize, then insert a
		// new supply update event into the database.
		insertUpdate := func(transitionID sql.NullInt64) error {
			var b bytes.Buffer
			err := serializeSupplyUpdateEvent(&b, event)
			if err != nil {
				return fmt.Errorf("failed to serialize event "+
					"data: %w", err)
			}

			updateTypeID, err := updateTypeToInt(
				event.SupplySubTreeType(),
			)
			if err != nil {
				return fmt.Errorf("failed to map update "+
					"type: %w", err)
			}

			return db.InsertSupplyUpdateEvent(
				ctx, InsertSupplyUpdateEvent{
					GroupKey:     groupKeyBytes,
					TransitionID: transitionID,
					UpdateTypeID: updateTypeID,
					EventData:    b.Bytes(),
				},
			)
		}

		// First, check if there's already a pending transition.
		//nolint:lll
		pendingTransitionRow, err := db.QueryPendingSupplyCommitTransition(
			ctx, groupKeyBytes,
		)

		// If a pending transition exists, insert the update with the
		// appropriate transition ID.
		if err == nil {
			//nolint:lll
			transition := pendingTransitionRow.SupplyCommitTransition

			// If frozen, insert as dangling (null transition ID).
			// Otherwise, associate with the existing transition.
			var transitionID sql.NullInt64
			if !transition.Frozen {
				transitionID = sqlInt64(transition.TransitionID)
			}

			return insertUpdate(transitionID)
		}

		// If the error is anything other than "no rows", it's a real
		// problem.
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to query existing "+
				"pending transition: %w", err)
		}

		// No pending transition exists. So we can create a new one.
		//
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

		// Make sure that we're in the DefaultState. We can only start a
		// new transition from here.
		currentState, err := intToState(currentStateID)
		if err != nil {
			return fmt.Errorf("invalid state ID %d "+
				"returned from upsert: %w", currentStateID, err)
		}
		currentStateName := currentState.String()
		if currentStateName != "DefaultState" {
			return fmt.Errorf("cannot start new transition "+
				"in state: %s", currentStateName)
		}

		// We're in the default state, so now we'll create a new
		// transition, which will reference the old commitment ID (the
		// only that we'll spend).
		latestCommitID := upsertResult.LatestCommitmentID

		transitionID, err := db.InsertSupplyCommitTransition(
			ctx, InsertSupplyCommitTransition{
				StateMachineGroupKey: groupKeyBytes,
				OldCommitmentID:      latestCommitID,
				Finalized:            false,
				Frozen:               false,
				CreationTime:         time.Now().Unix(),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to insert "+
				"new transition: %w", err)
		}

		// With the transition created, we can now insert the update
		// event, linking it to the new transition.
		err = insertUpdate(sqlInt64(transitionID))
		if err != nil {
			return err
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

// FreezePendingTransition marks the current pending transition for a group key
// as frozen, meaning it will no longer accept new updates.
func (s *SupplyCommitMachine) FreezePendingTransition(ctx context.Context,
	assetSpec asset.Specifier) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		return db.FreezePendingTransition(ctx, groupKeyBytes)
	})
}

// BindDanglingUpdatesToTransition finds any supply update events for the
// given asset specifier that are not yet associated with a transition,
// creates a new transition for them, and links them. It returns the
// list of events that were bound. If no dangling events are found, it
// returns an empty slice and no error.
func (s *SupplyCommitMachine) BindDanglingUpdatesToTransition(
	ctx context.Context, assetSpec asset.Specifier,
) ([]supplycommit.SupplyUpdateEvent, error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	var (
		boundEvents []supplycommit.SupplyUpdateEvent
	)
	writeTx := WriteTxOption()
	err := s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		eventRows, err := db.QueryDanglingSupplyUpdateEvents(
			ctx, groupKeyBytes,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to query dangling "+
				"events: %w", err)
		}

		if len(eventRows) == 0 {
			return nil
		}

		// We have dangling updates. So we'll now move to create a new
		// transition for them.
		stateMachine, err := db.QuerySupplyCommitStateMachine(
			ctx, groupKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed to query state "+
				"machine: %w", err)
		}
		latestCommitID := stateMachine.LatestCommitmentID

		transitionID, err := db.InsertSupplyCommitTransition(
			ctx, InsertSupplyCommitTransition{
				StateMachineGroupKey: groupKeyBytes,
				OldCommitmentID:      latestCommitID,
				Finalized:            false,
				CreationTime:         time.Now().Unix(),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to insert new "+
				"transition: %w", err)
		}

		// With the new transition created, we'll now link all the
		// dangling updates.
		err = db.LinkDanglingSupplyUpdateEvents(
			ctx, LinkDanglingSupplyUpdateEventsParams{
				GroupKey:     groupKeyBytes,
				TransitionID: sqlInt64(transitionID),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to link dangling "+
				"events: %w", err)
		}

		boundEvents = make(
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
			boundEvents = append(boundEvents, event)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return boundEvents, nil
}

// InsertSignedCommitTx associates a new signed commitment anchor transaction
// with the current active supply commitment state transition.
func (s *SupplyCommitMachine) InsertSignedCommitTx(ctx context.Context,
	assetSpec asset.Specifier,
	commitDetails supplycommit.SupplyCommitTxn) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	commitTx := commitDetails.Txn
	internalKeyDesc := commitDetails.InternalKey
	outputKey := commitDetails.OutputKey
	outputIndex := commitDetails.OutputIndex

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, we'll locate the current pending transition for the
		// state machine.
		//
		//nolint:lll
		pendingTransitionRow, err := db.QueryPendingSupplyCommitTransition(
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
		pendingTransition := pendingTransitionRow.SupplyCommitTransition

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

		// Upsert the internal key to get its ID, preserving the full
		// key derivation information for proper PSBT signing later.
		internalKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
			RawKey:    internalKeyDesc.PubKey.SerializeCompressed(),
			KeyFamily: int32(internalKeyDesc.Family),
			KeyIndex:  int32(internalKeyDesc.Index),
		})
		if err != nil {
			return fmt.Errorf("error upserting internal key %x: %w",
				internalKeyDesc.PubKey.SerializeCompressed(),
				err)
		}

		// Insert the new commitment record. Chain details (block
		// height, header, proof, output index) are NULL at this stage.
		params := sqlc.InsertSupplyCommitmentParams{
			GroupKey:        groupKeyBytes,
			ChainTxnID:      chainTxID,
			InternalKeyID:   internalKeyID,
			OutputKey:       outputKey.SerializeCompressed(),
			SupplyRootHash:  nil,
			SupplyRootSum:   sql.NullInt64{},
			OutputIndex:     sqlInt32(outputIndex),
			SpentCommitment: pendingTransition.OldCommitmentID,
		}
		newCommitmentID, err := db.InsertSupplyCommitment(ctx, params)
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

// InsertSupplyCommit inserts a new, fully complete supply commitment into the
// database.
func (s *SupplyCommitMachine) InsertSupplyCommit(ctx context.Context,
	assetSpec asset.Specifier, commit supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	commitTx := commit.Txn
	internalKey := commit.InternalKey
	outputKey := commit.OutputKey
	outputIndex := commit.TxOutIdx

	block, err := commit.CommitmentBlock.UnwrapOrErr(
		supplycommit.ErrNoBlockInfo,
	)
	if err != nil {
		return fmt.Errorf("failed to unwrap commitment block: %w", err)
	}

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
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
			RawKey:    internalKey.PubKey.SerializeCompressed(),
			KeyFamily: int32(internalKey.Family),
			KeyIndex:  int32(internalKey.Index),
		})
		if err != nil {
			return fmt.Errorf("failed to upsert internal key %x: "+
				"%w", internalKey.PubKey.SerializeCompressed(),
				err)
		}

		// Now we fetch the previous commitment that is being spent by
		// this one.
		var spentCommitment sql.NullInt64
		err = fn.MapOptionZ(
			commit.SpentCommitment, func(op wire.OutPoint) error {
				q := sqlc.QuerySupplyCommitmentByOutpointParams{
					GroupKey:    groupKeyBytes,
					Txid:        op.Hash[:],
					OutputIndex: sqlInt32(op.Index),
				}
				row, err := db.QuerySupplyCommitmentByOutpoint(
					ctx, q,
				)
				if err != nil {
					return fmt.Errorf("failed to query "+
						"spent commitment: %w", err)
				}

				spentCommitment = sqlInt64(
					row.SupplyCommitment.CommitID,
				)

				return nil
			},
		)
		if err != nil {
			return fmt.Errorf("failed to fetch spent commitment: "+
				"%w", err)
		}

		// Insert the new commitment record. Chain details (block
		// height, header, proof, output index) are NULL at this stage.
		params := sqlc.InsertSupplyCommitmentParams{
			GroupKey:        groupKeyBytes,
			ChainTxnID:      chainTxID,
			InternalKeyID:   internalKeyID,
			OutputKey:       outputKey.SerializeCompressed(),
			SupplyRootHash:  nil,
			SupplyRootSum:   sql.NullInt64{},
			OutputIndex:     sqlInt32(outputIndex),
			SpentCommitment: spentCommitment,
		}
		newCommitmentID, err := db.InsertSupplyCommitment(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to insert new supply "+
				"commitment: %w", err)
		}

		// Update the commitment record with the calculated root hash
		// and sum.
		finalRootSupplyRoot, err := applySupplyUpdatesInternal(
			ctx, db, assetSpec, leaves.AllUpdates(),
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

		err = block.MerkleProof.Encode(&proofBuf)
		if err != nil {
			return fmt.Errorf("failed to encode "+
				"merkle proof: %w", err)
		}
		err = block.BlockHeader.Serialize(&headerBuf)
		if err != nil {
			return fmt.Errorf("failed to "+
				"serialize block header: %w",
				err)
		}
		blockHeight := sqlInt32(block.Height)

		// With all the information serialized above, we'll now update
		// the chain proof information for this current supply commit.
		err = db.UpdateSupplyCommitmentChainDetails(
			ctx, SupplyCommitChainDetails{
				CommitID:    newCommitmentID,
				MerkleProof: proofBuf.Bytes(),
				OutputIndex: sqlInt32(commit.TxOutIdx),
				BlockHeader: headerBuf.Bytes(),
				ChainTxnID:  chainTxID,
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
		err = commit.Txn.Serialize(&commitTxBytes)
		if err != nil {
			return fmt.Errorf("failed to serialize commit tx for "+
				"update: %w", err)
		}
		commitTxid := commit.Txn.TxHash()

		_, err = db.UpsertChainTx(ctx, UpsertChainTxParams{
			Txid:      commitTxid[:],
			RawTx:     commitTxBytes.Bytes(),
			ChainFees: 0,
			BlockHash: lnutils.ByteSlice(
				block.BlockHeader.BlockHash(),
			),
			BlockHeight: blockHeight,
			TxIndex:     sqlInt32(block.TxIndex),
		})
		if err != nil {
			return fmt.Errorf("failed to update chain_txns "+
				"confirmation: %w", err)
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
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	newStateName, err := stateToDBString(state)
	if err != nil {
		return fmt.Errorf("failed to map state to string: %w", err)
	}

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
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
// its associated chain confirmation details. If no commitment is found,
// it returns None for both the commitment and chain info.
func fetchCommitment(ctx context.Context, db SupplyCommitStore,
	commitID sql.NullInt64) (lfn.Option[supplycommit.RootCommitment],
	error) {

	noneRootCommit := lfn.None[supplycommit.RootCommitment]()

	if !commitID.Valid {
		return noneRootCommit, nil
	}

	// First, fetch the supply commitment itself.
	commitRow, err := db.QuerySupplyCommitment(ctx, commitID.Int64)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return noneRootCommit, nil
		}
		return noneRootCommit, fmt.Errorf("failed to query "+
			"commitment %d: %w", commitID.Int64, err)
	}

	commit, err := parseSupplyCommitmentRow(
		ctx, commitRow.SupplyCommitment, commitRow.TxIndex, db,
	)
	if err != nil {
		return noneRootCommit, fmt.Errorf("failed to query "+
			"commitment %d: %w", commitID.Int64, err)
	}

	return lfn.Some(*commit), nil
}

// FetchCommitmentByOutpoint fetches a supply commitment by its outpoint and
// group key. If no commitment is found, it returns ErrCommitmentNotFound.
func (s *SupplyCommitMachine) FetchCommitmentByOutpoint(ctx context.Context,
	assetSpec asset.Specifier,
	outpoint wire.OutPoint) (*supplycommit.RootCommitment, error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}

	var (
		writeTx       = WriteTxOption()
		groupKeyBytes = schnorr.SerializePubKey(groupKey)
		commit        *supplycommit.RootCommitment
	)
	dbErr := s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, fetch the supply commitment by group key and outpoint.
		commitRow, err := db.QuerySupplyCommitmentByOutpoint(
			ctx, sqlc.QuerySupplyCommitmentByOutpointParams{
				GroupKey:    groupKeyBytes,
				OutputIndex: sqlInt32(outpoint.Index),
				Txid:        outpoint.Hash[:],
			},
		)
		if err != nil {
			return fmt.Errorf("failed to query commitment for "+
				"outpoint %s: %w", outpoint, err)
		}

		commit, err = parseSupplyCommitmentRow(
			ctx, commitRow.SupplyCommitment, commitRow.TxIndex, db,
		)
		if err != nil {
			return fmt.Errorf("failed to parse commitment for "+
				"outpoint %s: %w", outpoint, err)
		}

		return nil
	})
	if dbErr != nil {
		if errors.Is(dbErr, sql.ErrNoRows) {
			return nil, supplyverifier.ErrCommitmentNotFound
		}

		return nil, fmt.Errorf("failed to fetch commitment by "+
			"outpoint %s: %w", outpoint, dbErr)
	}

	return commit, nil
}

// FetchCommitmentBySpentOutpoint fetches a supply commitment by the outpoint it
// spent and group key. If no commitment is found, it returns
// ErrCommitmentNotFound.
func (s *SupplyCommitMachine) FetchCommitmentBySpentOutpoint(
	ctx context.Context, assetSpec asset.Specifier,
	spentOutpoint wire.OutPoint) (*supplycommit.RootCommitment, error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}

	var (
		writeTx       = WriteTxOption()
		groupKeyBytes = schnorr.SerializePubKey(groupKey)
		commit        *supplycommit.RootCommitment
	)
	dbErr := s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, fetch the supply commitment by group key and outpoint.
		commitRow, err := db.QuerySupplyCommitmentBySpentOutpoint(
			ctx, sqlc.QuerySupplyCommitmentBySpentOutpointParams{
				GroupKey:    groupKeyBytes,
				OutputIndex: sqlInt32(spentOutpoint.Index),
				Txid:        spentOutpoint.Hash[:],
			},
		)
		if err != nil {
			return fmt.Errorf("failed to query commitment for "+
				"spent outpoint %s: %w", spentOutpoint, err)
		}

		commit, err = parseSupplyCommitmentRow(
			ctx, commitRow.SupplyCommitment, commitRow.TxIndex, db,
		)
		if err != nil {
			return fmt.Errorf("failed to parse commitment for "+
				"spent outpoint %s: %w", spentOutpoint, err)
		}

		return nil
	})
	if dbErr != nil {
		if errors.Is(dbErr, sql.ErrNoRows) {
			return nil, supplyverifier.ErrCommitmentNotFound
		}

		return nil, fmt.Errorf("failed to fetch commitment by spent "+
			"outpoint %s: %w", spentOutpoint, dbErr)
	}

	return commit, nil
}

// FetchStartingCommitment fetches the very first supply commitment of an asset
// group. If no commitment is found, it returns ErrCommitmentNotFound.
func (s *SupplyCommitMachine) FetchStartingCommitment(ctx context.Context,
	assetSpec asset.Specifier) (*supplycommit.RootCommitment, error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}

	var (
		writeTx       = WriteTxOption()
		groupKeyBytes = schnorr.SerializePubKey(groupKey)
		commit        *supplycommit.RootCommitment
	)
	dbErr := s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, fetch the supply commitment by group key.
		commitRow, err := db.QueryStartingSupplyCommitment(
			ctx, groupKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed to query starting "+
				"commitment for group %x: %w", groupKeyBytes,
				err)
		}

		commit, err = parseSupplyCommitmentRow(
			ctx, commitRow.SupplyCommitment, commitRow.TxIndex, db,
		)
		if err != nil {
			return fmt.Errorf("failed to parse starting "+
				"commitment for group %x: %w", groupKeyBytes,
				err)
		}

		return nil
	})
	if dbErr != nil {
		if errors.Is(dbErr, sql.ErrNoRows) {
			return nil, supplyverifier.ErrCommitmentNotFound
		}

		return nil, fmt.Errorf("failed to fetch starting commitment "+
			"for group %x: %w", groupKeyBytes, dbErr)
	}

	return commit, nil
}

// FetchLatestCommitment fetches the latest supply commitment of an asset
// group based on highest block height. If no commitment is found, it returns
// ErrCommitmentNotFound.
func (s *SupplyCommitMachine) FetchLatestCommitment(ctx context.Context,
	assetSpec asset.Specifier) (*supplycommit.RootCommitment, error) {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}

	var (
		writeTx       = WriteTxOption()
		groupKeyBytes = groupKey.SerializeCompressed()
		commit        *supplycommit.RootCommitment
	)
	dbErr := s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, fetch the supply commitment by group key.
		commitRow, err := db.QueryLatestSupplyCommitment(
			ctx, groupKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed to query latest "+
				"commitment for group %x: %w", groupKeyBytes,
				err)
		}

		commit, err = parseSupplyCommitmentRow(
			ctx, commitRow.SupplyCommitment, commitRow.TxIndex, db,
		)
		if err != nil {
			return fmt.Errorf("failed to parse latest "+
				"commitment for group %x: %w", groupKeyBytes,
				err)
		}

		return nil
	})
	if dbErr != nil {
		if errors.Is(dbErr, sql.ErrNoRows) {
			return nil, supplyverifier.ErrCommitmentNotFound
		}

		return nil, fmt.Errorf("failed to fetch latest commitment "+
			"for group %x: %w", groupKeyBytes, dbErr)
	}

	return commit, nil
}

// parseSupplyCommitmentRow parses a SupplyCommitment row into a
// supplycommit.RootCommitment and optional commitmentChainInfo.
func parseSupplyCommitmentRow(ctx context.Context, commit SupplyCommitment,
	txIndex sql.NullInt32,
	db SupplyCommitStore) (*supplycommit.RootCommitment, error) {

	internalKeyRow, err := db.FetchInternalKeyByID(
		ctx, commit.InternalKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch internal key %d for "+
			"commit %d: %w", commit.InternalKeyID, commit.CommitID,
			err)
	}
	internalKey, err := parseInternalKey(sqlc.InternalKey{
		RawKey:    internalKeyRow.RawKey,
		KeyFamily: internalKeyRow.KeyFamily,
		KeyIndex:  internalKeyRow.KeyIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse internal key for "+
			"commit %d: %w", commit.CommitID, err)
	}
	outputKey, err := btcec.ParsePubKey(commit.OutputKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse output key for commit "+
			"%d: %w", commit.CommitID, err)
	}

	// Fetch and deserialize the transaction.
	var commitTx wire.MsgTx
	chainTxRow, err := db.FetchChainTxByID(ctx, commit.ChainTxnID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain tx %d for "+
			"commit %d: %w", commit.ChainTxnID, commit.CommitID,
			err)
	}
	err = commitTx.Deserialize(bytes.NewReader(chainTxRow.RawTx))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize commit tx for "+
			"commit %d: %w", commit.CommitID, err)
	}

	// Construct the SMT root node from the stored hash and sum. If they are
	// NULL (e.g., initial commit before ApplyStateTransition ran), use the
	// empty root.
	var rootNode *mssmt.BranchNode
	if len(commit.SupplyRootHash) == 0 || !commit.SupplyRootSum.Valid {
		log.Warnf("fetchCommitment: Supply root hash/sum is NULL for "+
			"commit %d, using empty root", commit.CommitID)
		rootNode = mssmt.NewComputedBranch(mssmt.EmptyTreeRootHash, 0)
	} else {
		var rootHash mssmt.NodeHash
		copy(rootHash[:], commit.SupplyRootHash)
		rootSum := uint64(commit.SupplyRootSum.Int64)
		rootNode = mssmt.NewComputedBranch(rootHash, rootSum)
	}

	rootCommitment := &supplycommit.RootCommitment{
		Txn:         &commitTx,
		TxOutIdx:    uint32(commit.OutputIndex.Int32),
		InternalKey: internalKey,
		OutputKey:   outputKey,
		SupplyRoot:  rootNode,
	}

	// If we have a valid block height, then that means that the block
	// header and/or merkle proof may also be present.
	if commit.BlockHeight.Valid {
		blockHeight := uint32(commit.BlockHeight.Int32)

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
					"for commit %d: %v", commit.CommitID,
					err)
				blockHeader = nil
			}
		}

		var merkleProof *proof.TxMerkleProof
		if len(commit.MerkleProof) > 0 {
			merkleProof = &proof.TxMerkleProof{}
			err = merkleProof.Decode(bytes.NewReader(
				commit.MerkleProof,
			))
			if err != nil {
				log.Errorf("fetchCommitment: failed to "+
					"decode merkle proof for commit %d: "+
					"%v", commit.CommitID, err)
				merkleProof = nil
			}
		}

		if blockHeader != nil && merkleProof != nil {
			rootCommitment.CommitmentBlock = fn.Some(
				supplycommit.CommitmentBlock{
					Height:      blockHeight,
					Hash:        blockHeader.BlockHash(),
					TxIndex:     uint32(txIndex.Int32),
					BlockHeader: blockHeader,
					MerkleProof: merkleProof,
				},
			)
		} else {
			log.Warnf("fetchCommitment: commit %d has block "+
				"height but missing header (%v) or proof (%v)",
				commit.CommitID, blockHeader == nil,
				merkleProof == nil)
		}
	}

	if commit.SpentCommitment.Valid {
		spentRow, err := db.QuerySupplyCommitmentOutpoint(
			ctx, commit.SpentCommitment.Int64,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to query spent "+
				"commitment with ID %d for commit %d: %w",
				commit.SpentCommitment.Int64, commit.CommitID,
				err)
		}

		hash, err := chainhash.NewHash(spentRow.Txid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spent "+
				"commitment txid %x for commit %d: %w",
				spentRow.Txid, commit.CommitID, err)
		}

		rootCommitment.SpentCommitment = fn.Some(wire.OutPoint{
			Hash:  *hash,
			Index: uint32(spentRow.OutputIndex.Int32),
		})
	}

	return rootCommitment, nil
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
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	var (
		state            supplycommit.State
		stateTransition  supplycommit.SupplyStateTransition
		foundTransition  bool
		pendingUpdates   []supplycommit.SupplyUpdateEvent
		oldCommitmentOpt lfn.Option[supplycommit.RootCommitment]
		newCommit        supplycommit.RootCommitment
		chainProofOpt    lfn.Option[supplycommit.ChainProof]
	)

	readTx := ReadTxOption()
	err := s.db.ExecTx(ctx, readTx, func(db SupplyCommitStore) error {
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
		dbTransitionRow, err := db.QueryPendingSupplyCommitTransition(
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
		dbTransition := dbTransitionRow.SupplyCommitTransition
		foundTransition = true

		// Now that we know we have a state transition, we'll query for
		// all the pending updates related to the state transition.
		eventRows, err := db.QuerySupplyUpdateEvents(
			ctx, sqlInt64(dbTransition.TransitionID),
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
		oldCommitmentOpt, err = fetchCommitment(
			ctx, db, dbTransition.OldCommitmentID,
		)
		if err != nil {
			return fmt.Errorf("failed fetching old "+
				"commitment: %w", err)
		}
		newCommitmentOpt, err := fetchCommitment(
			ctx, db, dbTransition.NewCommitmentID,
		)
		if err != nil {
			return fmt.Errorf("failed fetching new "+
				"commitment: %w", err)
		}

		newCommit = newCommitmentOpt.UnwrapOr(
			supplycommit.RootCommitment{},
		)

		newCommit.CommitmentBlock.WhenSome(
			func(b supplycommit.CommitmentBlock) {
				if b.BlockHeader == nil ||
					b.MerkleProof == nil {

					return
				}

				chainProofOpt = lfn.Some(
					supplycommit.ChainProof{
						Header:      *b.BlockHeader,
						BlockHeight: b.Height,
						MerkleProof: *b.MerkleProof,
						TxIndex:     b.TxIndex,
					},
				)
			},
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
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	// Ensure we have the new commitment details.
	newCommitment := transition.NewCommitment
	if newCommitment.SupplyRoot == nil || newCommitment.Txn == nil {
		return fmt.Errorf("ApplyStateTransition requires a complete " +
			"NewCommitment")
	}

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		// First, we'll locate the state transition that we need to
		// finalize based on the group key.
		dbTransitionRow, err := db.QueryPendingSupplyCommitTransition(
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
		dbTransition := dbTransitionRow.SupplyCommitTransition
		transitionID := dbTransition.TransitionID

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

		// Next, we'll apply all the pending updates to the supply
		// sub-trees, then use that to update the root tree.
		//
		finalRootSupplyRoot, err := applySupplyUpdatesInternal(
			ctx, db, assetSpec, transition.PendingUpdates,
		)
		if err != nil {
			return fmt.Errorf("failed to apply SMT updates: "+
				"%w", err)
		}

		// Update the commitment record with the calculated root hash
		// and sum.
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

		// Mark the specific pre-commitments that were spent in this
		// transaction as spent by the new commitment. We identify them
		// by looking at the transaction inputs.
		for _, txIn := range newCommitment.Txn.TxIn {
			outpointBytes, err := encodeOutpoint(
				txIn.PreviousOutPoint,
			)
			if err != nil {
				return fmt.Errorf("failed to encode "+
					"outpoint %v: %w",
					txIn.PreviousOutPoint, err)
			}

			log.Infof("Attempting to mark outpoint as "+
				"spent: %v (hash=%x, index=%d)",
				txIn.PreviousOutPoint,
				txIn.PreviousOutPoint.Hash[:],
				txIn.PreviousOutPoint.Index)

			// Mark this specific pre-commitment as spent.
			err = db.MarkMintPreCommitSpentByOutpoint(ctx,
				sqlc.MarkMintPreCommitSpentByOutpointParams{
					SpentByCommitID: sqlInt64(
						newCommitmentID,
					),
					Outpoint: outpointBytes,
				},
			)
			if err != nil {
				// It's OK if this outpoint doesn't exist in our
				// table - it might be an old commitment output
				// or a wallet input for fees. We only care
				// about marking actual pre-commitments as
				// spent.
				log.Debugf("Could not mark outpoint %v as "+
					"spent (may not be a "+
					"pre-commitment): %v",
					txIn.PreviousOutPoint, err)
			} else {
				log.Infof("Successfully marked outpoint "+
					"as spent: %v", txIn.PreviousOutPoint)
			}
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
			},
		)
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
