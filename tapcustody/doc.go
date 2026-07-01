// Package tapcustody takes custody of assets transferred to this
// node on-chain. The custodian watches the wallet for taproot
// outputs matching known Taproot Asset addresses, retrieves the
// corresponding provenance proofs from courier or auth-mailbox
// services, verifies them, and imports them into the local proof
// archive.
//
// The substance is "receiving assets," distinct from the minting
// substance that lives in tapgarden. The custodian used to live
// alongside the planter because that was the package that first
// needed it; it has been separated so the package name says what
// the package is.
package tapcustody
