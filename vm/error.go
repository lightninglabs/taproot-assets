package vm

import (
	"fmt"

	"github.com/lightninglabs/taproot-assets/tapscript"
)

// ErrorKind uniquely identifies the kind of Error returned by the Taproot Asset
// VM.
type ErrorKind uint8

const (
	// ErrNoSplitCommitment represents an error case where a split
	// commitment root is not present when required.
	ErrNoSplitCommitment ErrorKind = iota

	// ErrIDMismatch represents an error case where an asset, or asset
	// split, do not match the asset genesis of their inputs.
	ErrIDMismatch

	// ErrTypeMismatch represents an error case where an asset, or asset
	// split, do not match the asset type of their inputs.
	ErrTypeMismatch

	// ErrScriptKeyMismatch represents an error case where an the script key
	// of an asset input does not match the one of the input provided to the
	// virtual machine.
	ErrScriptKeyMismatch

	// ErrAmountMismatch represents an error case where an asset, along with
	// its splits, do not match the total asset amount of their inputs.
	ErrAmountMismatch

	// ErrInvalidSigHashFlag represents an error case where an asset witness
	// contains signatures created with any sighash flag other than
	// SIGHASH_DEFAULT.
	ErrInvalidSigHashFlag

	// ErrInvalidGenesisStateTransition represents an error case where an
	// asset has a valid genesis witness but the virtual machine was
	// provided asset inputs.
	ErrInvalidGenesisStateTransition

	// ErrInvalidTransferWitness represents an error case where an asset
	// input has a malformed or invalid transfer witness as deemed by the
	// virtual machine.
	ErrInvalidTransferWitness

	// ErrInvalidSplitAssetType represents an error case where an asset
	// split type does not match the root asset.
	ErrInvalidSplitAssetType

	// ErrInvalidSplitCommitmentWitness represents an error case where an
	// asset input has a malformed split commitment witness.
	ErrInvalidSplitCommitmentWitness

	// ErrInvalidSplitCommitmentProof represents an error case where an
	// asset split has an invalid split commitment proof.
	ErrInvalidSplitCommitmentProof

	// ErrInvalidRootAsset represents an error case where the root asset
	// of an asset split has zero value but a spendable script key.
	ErrInvalidRootAsset
)

// Wrap select errors related to virtual TX handling to provide more
// context to callers.
var (
	// ErrInvalidScriptVersion represents an error case where an asset input
	// commits to an invalid script version.
	ErrInvalidScriptVersion = tapscript.ErrInvalidScriptVersion

	// ErrInputMismatch represents an error case where an asset's set of
	// inputs mismatch the set provided to the virtual machine.
	ErrInputMismatch = tapscript.ErrInputMismatch

	// ErrNoInputs represents an error case where an asset undergoing a
	// state transition does not have any or a specific input required.
	ErrNoInputs = tapscript.ErrNoInputs
)

func (k ErrorKind) String() string {
	switch k {
	case ErrNoSplitCommitment:
		return "missing asset split commitment root"
	case ErrIDMismatch:
		return "asset id mismatch"
	case ErrTypeMismatch:
		return "asset type mismatch"
	case ErrAmountMismatch:
		return "asset amount mismatch"
	case ErrScriptKeyMismatch:
		return "asset script key mismatch within state transition"
	case ErrInvalidSigHashFlag:
		return "invalid sig hash flag for asset witness signature"
	case ErrInvalidGenesisStateTransition:
		return "invalid genesis state transition"
	case ErrInvalidTransferWitness:
		return "invalid transfer asset witness"
	case ErrInvalidSplitAssetType:
		return "invalid split asset type"
	case ErrInvalidSplitCommitmentWitness:
		return "invalid split commitment asset witness"
	case ErrInvalidSplitCommitmentProof:
		return "invalid split commitment proof"
	case ErrInvalidRootAsset:
		return "invalid zero-value root asset"
	default:
		return "unknown"
	}
}

// Error represents an error returned by the Taproot Asset VM.
type Error struct {
	Kind  ErrorKind
	Inner error
}

// newErrKind returns a new error of a particular kind.
func newErrKind(kind ErrorKind) Error {
	return Error{Kind: kind}
}

// newErrInner returns a new error with a particular kind, that wraps an
// existing error. The inner error can be obtained via the Unwrap method.
func newErrInner(kind ErrorKind, inner error) Error {
	return Error{Kind: kind, Inner: inner}
}

// Error returns a human readable version of the error. This implements the
// main error interface.
func (e Error) Error() string {
	if e.Inner == nil {
		return e.Kind.String()
	}
	return fmt.Errorf("%v: %w", e.Kind, e.Inner).Error()
}

// String is the same as Error, but intended to be used for string formatting.
func (e Error) String() string {
	return e.Error()
}

// Unwrap implements the extended error interface, with the ability to expose a
// wrapped error to the caller.
func (e Error) Unwrap() error {
	return e.Inner
}
