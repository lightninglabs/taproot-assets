// Package tapreorg watches initially-confirmed anchor transactions
// until they reach a safe confirmation depth. If a re-org reverts an
// anchor, the watcher updates the affected proof(s) with the new
// block context and stores them in the proof archive.
//
// The substance is "guarding proof integrity in the face of chain
// re-orgs," distinct from the minting substance that lives in
// tapgarden. The watcher used to live alongside the planter and
// caretaker because that was the package that first needed it; it
// has been separated so the package name says what the package is.
package tapreorg
