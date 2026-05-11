//go:build !test_db_postgres && !itest

package tapdb

import (
	"errors"
	"testing"
	"time"
)

var (
	// DefaultPostgresFixtureLifetime is the default maximum time a Postgres
	// test fixture is being kept alive. After that time the docker
	// container will be terminated forcefully, even if the tests aren't
	// fully executed yet. So this time needs to be chosen correctly to be
	// longer than the longest expected individual test run time.
	DefaultPostgresFixtureLifetime = 60 * time.Minute
)

// TestPgFixture is a placeholder for builds that don't enable Postgres or
// integration test fixtures.
type TestPgFixture struct{}

func errPostgresFixtureUnavailable() error {
	msg := "postgres test fixture requires the " +
		"test_db_postgres or itest build tag"

	return errors.New(msg)
}

// NewTestPgFixture constructs a new Postgres test fixture.
func NewTestPgFixture(t testing.TB, _ time.Duration, _ bool) *TestPgFixture {
	t.Helper()

	t.Fatal(errPostgresFixtureUnavailable())
	return nil
}

// GetDSN returns the DSN (Data Source Name) for the started Postgres node.
func (f *TestPgFixture) GetDSN() string {
	panic(errPostgresFixtureUnavailable())
}

// GetConfig returns the full config of the Postgres node.
func (f *TestPgFixture) GetConfig() *PostgresConfig {
	panic(errPostgresFixtureUnavailable())
}

// TearDown stops the underlying docker container.
func (f *TestPgFixture) TearDown(t testing.TB) {
	t.Helper()

	t.Fatal(errPostgresFixtureUnavailable())
}

// ClearDB clears the database.
func (f *TestPgFixture) ClearDB(t testing.TB) {
	t.Helper()

	t.Fatal(errPostgresFixtureUnavailable())
}
