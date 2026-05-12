package diagnostics

import (
	"time"
)

const (
	// StageProofVerificationPreBroadcast marks failures from pre-broadcast
	// proof validation.
	StageProofVerificationPreBroadcast = "pre_broadcast"

	// StageProofVerificationPostBroadcast marks failures from
	// post-broadcast
	// proof validation.
	StageProofVerificationPostBroadcast = "post_broadcast"
)

// ArtifactFile is a named binary artifact associated with a proof failure.
type ArtifactFile struct {
	FileName string
	Data     []byte
}

// ProofValidationFailure is an event emitted when proof validation fails.
type ProofValidationFailure struct {
	Timestamp time.Time

	Stage string
	Error string

	AnchorTxID string

	VPacketIndex        *int
	VPacketOutputIndex  *int
	TransferOutputIndex *int

	OutputProofs []ArtifactFile
	InputProofs  []ArtifactFile
}

// Recorder accepts proof-validation failures for asynchronous persistence.
type Recorder interface {
	CaptureProofValidationFailure(failure ProofValidationFailure)
}
