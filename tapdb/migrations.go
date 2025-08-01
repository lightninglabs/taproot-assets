package tapdb

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/btcsuite/btclog/v2"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

const (
	// LatestMigrationVersion is the latest migration version of the
	// database.  This is used to implement downgrade protection for the
	// daemon.
	//
	// NOTE: This MUST be updated when a new migration is added.
	LatestMigrationVersion = 42
)

// DatabaseBackend is an interface that contains all methods our different
// Database backends implement.
type DatabaseBackend interface {
	BatchedQuerier
	WithTx(tx *sql.Tx) *sqlc.Queries
}

// MigrationTarget is a functional option that can be passed to applyMigrations
// to specify a target version to migrate to. `currentDbVersion` is the current
// (migration) version of the database, or None if unknown.
// `maxMigrationVersion` is the maximum migration version known to the driver,
// or None if unknown.
type MigrationTarget func(mig *migrate.Migrate,
	currentDbVersion int, maxMigrationVersion uint) error

var (
	// TargetLatest is a MigrationTarget that migrates to the latest
	// version available.
	TargetLatest = func(mig *migrate.Migrate, _ int, _ uint) error {
		return mig.Up()
	}

	// TargetVersion is a MigrationTarget that migrates to the given
	// version.
	TargetVersion = func(version uint) MigrationTarget {
		return func(mig *migrate.Migrate, _ int, _ uint) error {
			return mig.Migrate(version)
		}
	}
)

var (
	// ErrMigrationDowngrade is returned when a database downgrade is
	// detected.
	ErrMigrationDowngrade = errors.New("database downgrade detected")
)

// migrationOption is a functional option that can be passed to migrate related
// methods to modify their behavior.
type migrateOptions struct {
	latestVersion     fn.Option[uint]
	postStepCallbacks map[uint]migrate.PostStepCallback
}

// defaultMigrateOptions returns a new migrateOptions instance with default
// settings.
func defaultMigrateOptions() *migrateOptions {
	return &migrateOptions{
		postStepCallbacks: make(map[uint]migrate.PostStepCallback),
	}
}

// MigrateOpt is a functional option that can be passed to migrate related
// methods to modify behavior.
type MigrateOpt func(*migrateOptions)

// WithLatestVersion allows callers to override the default latest version
// setting.
func WithLatestVersion(version uint) MigrateOpt {
	return func(o *migrateOptions) {
		o.latestVersion = fn.Some(version)
	}
}

// WithPostStepCallbacks is an option that can be used to set a map of
// PostStepCallback functions that can be used to execute a Golang based
// migration step after a SQL based migration step has been executed. The key is
// the migration version and the value is the callback function that should be
// run _after_ the step was executed (but before the version is marked as
// cleanly executed). An error returned from the callback will cause the
// migration to fail and the step to be marked as dirty.
func WithPostStepCallbacks(
	postStepCallbacks map[uint]migrate.PostStepCallback) MigrateOpt {

	return func(o *migrateOptions) {
		o.postStepCallbacks = postStepCallbacks
	}
}

// migrationLogger is a logger that wraps the passed btclog.Logger so it can be
// used to log migrations.
type migrationLogger struct {
	log btclog.Logger
}

// Printf is like fmt.Printf. We map this to the target logger based on the
// current log level.
func (m *migrationLogger) Printf(format string, v ...interface{}) {
	// Trim trailing newlines from the format.
	format = strings.TrimRight(format, "\n")

	switch m.log.Level() {
	case btclog.LevelTrace:
		m.log.Tracef(format, v...)
	case btclog.LevelDebug:
		m.log.Debugf(format, v...)
	case btclog.LevelInfo:
		m.log.Infof(format, v...)
	case btclog.LevelWarn:
		m.log.Warnf(format, v...)
	case btclog.LevelError:
		m.log.Errorf(format, v...)
	case btclog.LevelCritical:
		m.log.Criticalf(format, v...)
	case btclog.LevelOff:
	}
}

// Verbose should return true when verbose logging output is wanted
func (m *migrationLogger) Verbose() bool {
	return m.log.Level() <= btclog.LevelDebug
}

// applyMigrations executes database migration files found in the given file
// system under the given path, using the passed database driver and database
// name, up to or down to the given target version.
func applyMigrations(fs fs.FS, driver database.Driver, path, dbName string,
	targetVersion MigrationTarget, opts *migrateOptions) error {

	// With the migrate instance open, we'll create a new migration source
	// using the embedded file system stored in sqlSchemas. The library
	// we're using can't handle a raw file system interface, so we wrap it
	// in this intermediate layer.
	migrateFileServer, err := httpfs.New(http.FS(fs), path)
	if err != nil {
		return err
	}

	// Finally, we'll run the migration with our driver above based on the
	// open DB, and also the migration source stored in the file system
	// above.
	sqlMigrate, err := migrate.NewWithInstance(
		"migrations", migrateFileServer, dbName, driver,
		migrate.WithPostStepCallbacks(opts.postStepCallbacks),
	)
	if err != nil {
		return err
	}

	migrationVersion, _, _ := sqlMigrate.Version()

	// As the down migrations may end up *dropping* data, we want to
	// prevent that without explicit accounting.
	latestVersion := opts.latestVersion.UnwrapOr(LatestMigrationVersion)
	if migrationVersion > latestVersion {
		return fmt.Errorf("%w: database version is newer than the "+
			"latest migration version, preventing downgrade: "+
			"db_version=%v, latest_migration_version=%v",
			ErrMigrationDowngrade, migrationVersion, latestVersion)
	}

	// Report the current version of the database before the migration.
	currentDbVersion, _, err := driver.Version()
	if err != nil {
		return fmt.Errorf("unable to get current db version: %w", err)
	}
	log.Infof("Attempting to apply migration(s) "+
		"(current_db_version=%v, latest_migration_version=%v)",
		currentDbVersion, latestVersion)

	// Apply our local logger to the migration instance.
	sqlMigrate.Log = &migrationLogger{log}

	// Execute the migration based on the target given.
	err = targetVersion(sqlMigrate, currentDbVersion, latestVersion)
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	// Report the current version of the database after the migration.
	currentDbVersion, _, err = driver.Version()
	if err != nil {
		return fmt.Errorf("unable to get current db version: %w", err)
	}
	log.Infof("Database version after migration: %v", currentDbVersion)

	return nil
}

// replacerFS is an implementation of a fs.FS virtual file system that wraps an
// existing file system but does a search-and-replace operation on each file
// when it is opened.
type replacerFS struct {
	parentFS fs.FS
	replaces map[string]string
}

// A compile-time assertion to make sure replacerFS implements the fs.FS
// interface.
var _ fs.FS = (*replacerFS)(nil)

// newReplacerFS creates a new replacer file system, wrapping the given parent
// virtual file system. Each file within the file system is undergoing a
// search-and-replace operation when it is opened, using the given map where the
// key denotes the search term and the value the term to replace each occurrence
// with.
func newReplacerFS(parent fs.FS, replaces map[string]string) *replacerFS {
	return &replacerFS{
		parentFS: parent,
		replaces: replaces,
	}
}

// Open opens a file in the virtual file system.
//
// NOTE: This is part of the fs.FS interface.
func (t *replacerFS) Open(name string) (fs.File, error) {
	f, err := t.parentFS.Open(name)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if stat.IsDir() {
		return f, err
	}

	return newReplacerFile(f, t.replaces)
}

type replacerFile struct {
	parentFile fs.File
	buf        bytes.Buffer
}

// A compile-time assertion to make sure replacerFile implements the fs.File
// interface.
var _ fs.File = (*replacerFile)(nil)

func newReplacerFile(parent fs.File, replaces map[string]string) (*replacerFile,
	error) {

	content, err := io.ReadAll(parent)
	if err != nil {
		return nil, err
	}

	contentStr := string(content)
	for from, to := range replaces {
		contentStr = strings.ReplaceAll(contentStr, from, to)
	}

	var buf bytes.Buffer
	_, err = buf.WriteString(contentStr)
	if err != nil {
		return nil, err
	}

	return &replacerFile{
		parentFile: parent,
		buf:        buf,
	}, nil
}

// Stat returns statistics/info about the file.
//
// NOTE: This is part of the fs.File interface.
func (t *replacerFile) Stat() (fs.FileInfo, error) {
	return t.parentFile.Stat()
}

// Read reads as many bytes as possible from the file into the given slice.
//
// NOTE: This is part of the fs.File interface.
func (t *replacerFile) Read(bytes []byte) (int, error) {
	return t.buf.Read(bytes)
}

// Close closes the underlying file.
//
// NOTE: This is part of the fs.File interface.
func (t *replacerFile) Close() error {
	// We already fully read and then closed the file when creating this
	// instance, so there's nothing to do for us here.
	return nil
}
