// Package tapreorg is the re-org watcher: it records every stake a
// subsystem places on a future chain outcome as an anchoring, senses
// the chain into per-anchoring evidence, derives each anchoring's
// phase from that evidence, and delivers phase changes to the owning
// subsystem inside a transaction with the subsystem's own convergent
// handler.
//
// # Terminal-absorption policy
//
// Buried and Abandoned are absorbing phases: once an anchoring has
// crossed its threshold, its phase does not advance further. This is
// intentional. The threshold, configured by --reorgsafedepth and
// defaulting to 6 confirmations on mainnet and 120 on testnet, is the
// point at which a subsystem's local state is safe to treat as
// chain-final, and the watcher's contract to sites is that anything
// past that point is committed. Act-gated emissions (universe
// publications, supply commitments, burn events) hang on that
// commitment.
//
// A re-org deeper than the threshold contradicts that commitment. It
// is outside the watcher's contract: the watcher neither detects nor
// recovers it, and any subsystem state emitted under the buried
// assumption is out of its reach to reverse. The right operational
// stance is to pick --reorgsafedepth so that a re-org past it is a
// network-consensus event, not a routine occurrence. The threshold
// trades off latency against the depth of re-org the daemon can
// transparently recover from; the default is calibrated for
// public-network block cadence.
//
// The Stuck flag on ListAnchorings and the Prometheus stuck-count
// gauge report a different condition: delivery of a phase to its
// subsystem failing repeatedly. Retries continue regardless, and the
// anchoring's stuck reason carries the last error.
package tapreorg
