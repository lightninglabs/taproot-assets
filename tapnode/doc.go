// Package tapnode declares the abstractions over node-side services
// that tapd depends on: the chain backend, the on-chain wallet, the
// key ring, and small read-only accessors that are likewise satisfied
// by upstream services rather than tapd's own logic.
//
// Concrete implementations live in lndservices. Consumers
// (tapgarden, tapfreighter, tapchannel, universe/supplycommit,
// universe/supplyverifier, ...) import this package to obtain the
// interfaces alone; they need not depend on the lnd-backed
// implementations to compile.
//
// Historically these interfaces lived in tapgarden/interface.go,
// which conflated tapd's minting substance with the substrate it
// depends on. They were hoisted here so that the substrate is named
// for what it is.
package tapnode
