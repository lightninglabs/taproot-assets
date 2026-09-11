package universe

// FederationPushReq describes a proof leaf federation push request.
type FederationPushReq struct {
	// ID identifies the Universe tree to push this new update out to.
	ID Identifier

	// Key is the leaf key in the Universe that the new leaf should be
	// added to.
	Key LeafKey

	// Leaf is the new leaf to add.
	Leaf *Leaf

	// resp is a channel that will be sent the asset issuance/transfer
	// proof and corresponding universe/multiverse inclusion proofs if the
	// federation proof push was successful.
	resp chan *Proof

	// LogProofSync is a boolean that indicates, if true, that the proof
	// leaf sync attempt should be logged and actively managed to ensure
	// that the federation push procedure is repeated in the event of a
	// failure.
	LogProofSync bool

	err chan error
}

// FederationProofBatchPushReq describes a batch of universe proof leaves to
// push to the federation.
type FederationProofBatchPushReq struct {
	Batch []*Item

	resp chan struct{}
	err  chan error
}
