package tarodb

import (
	"context"
	"time"

	"github.com/lightninglabs/taro/tarodb/sqlc"
)

var (
	// DefaultStoreTimeout is the default timeout used for any interaction
	// with the storage/database.
	DefaultStoreTimeout = time.Second * 10
)

// TxOptions represents a set of options one can use to control what type of
// database transaction is created. Transaction can wither be read or write.
type TxOptions interface {
	// ReadOnly returns true if the transaction should be read only.
	ReadOnly() bool
}

// BatchedTx is a generic interface that represents the ability to execute
// several operations to a given storage interface in a single atomic
// transaction. Typically Q here will be some subset of the main sqlc.Querier
// interface allowing it to only depend on the routines it needs to implement
// any additional business logic.
type BatchedTx[Q any, O TxOptions] interface {
	// ExecTx will execute the passed txBody, operating upon generic
	// parameter Q (usually a storage interface) in a single transaction.
	// The set of TxOptions are passed in in order to allow the caller to
	// specify if a transaction should be read-only and optionally what
	// type of concurrency control should be used.
	ExecTx(ctx context.Context, txOptions O, txBody func(Q) error) error
}

// Tx represents a database transaction that can be committed or rolled back.
type Tx interface {
	// Commits the database transaction, an error should be returned if the
	// commit isn't possible.
	Commit() error

	// Rollback rolls back an incomplete database transaction.
	// Transactions that were able to be committed can still call this as a
	// noop.
	Rollback() error
}

// QueryCreator is a generic function that's used to create a Querier, which is
// a type of interface that implements storage related methods from a database
// transaction. This will be used to instantiate an object callers can use to
// apply multiple modifications to an object interface in a single atomic
// transaction.
type QueryCreator[Q any] func(Tx) Q

// BatchedQuerier is a generic interface that allows callers to create a new
// database transaction based on an abstract type that implements the TxOptions
// interface.
//
// TODO(roasbeef): just enough to pass in the interface here and drop the
// constraint? unclear if need additional flexibility given the
// sqlitestore.BeginTx method?
type BatchedQuerier[O TxOptions] interface {
	// Querier is the underlying query source, this is in place so we can
	// pass a BatchedQuerier implementation directly into objects that
	// create a batched version of the normal methods they need.
	sqlc.Querier

	// BeginTx creates a new database transaction given the set of
	// transaction options.
	BeginTx(ctx context.Context, options O) (Tx, error)
}

// TransactionExecutor is a generic struct that abstracts away from the type of
// query a type needs to run under a database transaction, and also the set of
// options for that transaction. The QueryCreator is used to create a query
// given a database transaction created by the BatchedQuerier.
type TransactionExecutor[Query any, TxOpts TxOptions] struct {
	BatchedQuerier[TxOpts]

	createQuery QueryCreator[Query]
}

// NewTransactionExecutor creates a new instance of a TransactionExecutor given
// a Querier query object and a concrete type for the type of transactions the
// Querier understands.
func NewTransactionExecutor[Querier any, TxOpts TxOptions](
	db BatchedQuerier[TxOpts],
	createQuery QueryCreator[Querier]) *TransactionExecutor[Querier, TxOpts] {

	return &TransactionExecutor[Querier, TxOpts]{
		BatchedQuerier: db,
		createQuery:    createQuery,
	}
}

// ExecTx is a wrapper for txBody to abstract the creation and commit of a db
// transaction. The db transaction is embedded in a `*Queries` that txBody
// needs to use when executing each one of the queries that need to be applied
// atomically. This can be used by other storage interfaces to parameterize the
// type of query and options run, in order to have access to batched operations
// related to a storage object.
func (t *TransactionExecutor[Q, O]) ExecTx(ctx context.Context, txOptions O,
	txBody func(Q) error) error {

	// Create the db transaction.
	tx, err := t.BatchedQuerier.BeginTx(ctx, txOptions)
	if err != nil {
		return err
	}

	// Rollback is safe to call even if the tx is already closed, so if the
	// tx commits successfully, this is a no-op.
	defer func() {
		_ = tx.Rollback()
	}()

	if err := txBody(t.createQuery(tx)); err != nil {
		return err
	}

	// Commit transaction.
	//
	// TODO(roasbeef): need to handle SQLITE_BUSY here?
	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}
