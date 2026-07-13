// Package tapreorg watches initially-confirmed anchor transactions
// until they reach a safe confirmation depth. If a re-org reverts an
// anchor, the watcher updates the affected proof(s) with the new
// block context and stores them in the proof archive.
//
// The substance is "guarding proof integrity in the face of chain
// re-orgs," distinct from the minting substance that lives in
// tapgarden. The watcher used to live alongside the planter and
// cultivator because that was the package that first needed it; it
// has been separated so the package name says what the package is.
//
// # Terminal-absorption policy
//
// Buried and Abandoned are absorbing phases: once an anchoring has
// crossed its threshold, its phase does not advance further. This is
// intentional. The threshold — configured by --reorgsafedepth,
// defaulting to 6 confirmations on mainnet and 120 on testnet — is
// the point at which a subsystem's local state is safe to treat as
// chain-final, and the watcher's contract to sites is that anything
// past that point is committed. Every act-gated emission (universe
// publications, supply commitments, burn events, the porter's proof
// courier delivery) hangs on that commitment.
//
// A re-org deeper than the threshold contradicts that commitment. It
// is by design NOT silently recovered: the watcher continues to
// deliver phases up to the terminal it observed, and any subsystem
// state emitted under the buried assumption is out of the watcher's
// reach to reverse. The condition surfaces via the anchoring's Stuck
// flag on ListAnchorings / GetAnchoring and via the Prometheus
// collector's stuck-count gauge; operators are expected to observe
// these and take case-by-case action (typically: a manual audit
// against the chain, possibly a re-issuance or re-transfer, and a
// manual Withdraw on the affected anchorings).
//
// The right operational stance is: pick --reorgsafedepth so that a
// re-org past it is a network-consensus event, not a routine
// occurrence, and monitor the stuck-count gauge for a step change.
// The threshold trades off latency against the depth of re-org the
// daemon can transparently recover from; the default is calibrated
// for public-network block cadence.
package tapreorg
