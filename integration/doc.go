// Package integration provides the glue layer for running lnd with tapd's
// custom channel support. It wires tapd's aux component implementations into
// lnd's AuxComponents interface, enabling Taproot Asset channels without
// requiring lightning-terminal.
//
// The primary entry point is BuildAuxComponents, which accepts a running tapd
// Server and returns a populated lnd.AuxComponents struct ready to be passed
// to lnd via ImplementationCfg.
package integration
