package sqlc

import (
	"fmt"
)

// BackendType is an enum that represents the type of database backend we're
// using.
type BackendType uint8

const (
	// BackendTypeUnknown indicates we're using an unknown backend.
	BackendTypeUnknown BackendType = iota

	// BackendTypeSqlite indicates we're using a SQLite backend.
	BackendTypeSqlite

	// BackendTypePostgres indicates we're using a Postgres backend.
	BackendTypePostgres
)

// wrappedTX is a wrapper around a DBTX that also stores the database backend
// type.
type wrappedTX struct {
	DBTX

	backendType BackendType
}

// Backend returns the type of database backend we're using.
func (q *Queries) Backend() BackendType {
	wtx, ok := q.db.(*wrappedTX)
	if !ok {
		// Shouldn't happen unless a new database backend type is added
		// but not initialized correctly.
		return BackendTypeUnknown
	}

	return wtx.backendType
}

// NewSqlite creates a new Queries instance for a SQLite database.
func NewSqlite(db DBTX) *Queries {
	return &Queries{db: &wrappedTX{db, BackendTypeSqlite}}
}

// NewPostgres creates a new Queries instance for a Postgres database.
func NewPostgres(db DBTX) *Queries {
	return &Queries{db: &wrappedTX{db, BackendTypePostgres}}
}

// makeQueryParams generates a string of query parameters for a SQL query. It is
// meant to replace the `?` placeholders in a SQL query with numbered parameters
// like `$1`, `$2`, etc. This is required for the sqlc /*SLICE:<field_name>*/
// workaround. See scripts/gen_sqlc_docker.sh for more details.
func makeQueryParams(numTotalArgs, numListArgs int) string {
	diff := numTotalArgs - numListArgs
	result := ""
	for i := diff + 1; i <= numTotalArgs; i++ {
		if i == numTotalArgs {
			result += fmt.Sprintf("$%d", i)

			continue
		}
		result += fmt.Sprintf("$%d,", i)
	}
	return result
}
