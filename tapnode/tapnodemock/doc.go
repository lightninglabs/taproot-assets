// Package tapnodemock provides in-memory mock implementations of the
// node-side interfaces declared in tapnode. They are intended for use
// in tests across the repo, where the lnd-backed implementations in
// lndservices are unavailable.
//
// The mocks live in their own subpackage rather than alongside the
// interfaces so that production code paths cannot depend on them
// transitively.
package tapnodemock
