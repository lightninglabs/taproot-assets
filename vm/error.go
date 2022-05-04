package vm

import (
	"fmt"
)

// ErrorKind uniquely identifies the kind of Error returned by the Taro VM.
type ErrorKind uint8

const (
	// ErrNoInputs represents an error case where an asset undergoing a
	// state transition does not have any or a specific input required.
	ErrNoInputs ErrorKind = iota

	// ErrNoSplitCommitment represents an error case where a split
	// commitment root is not present when required.
	ErrNoSplitCommitment

	// ErrInputMismatch represents an error case where an asset's set of
	// inputs mismatch the set provided to the virtual machine.
	ErrInputMismatch

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

	// ErrInvalidScriptVersion represents an error case where an asset input
	// commits to an invalid script version.
	ErrInvalidScriptVersion

	// ErrInvalidSplitAssetType represents an error case where an asset
	// split type is not `asset.Normal`.
	ErrInvalidSplitAssetType

	// ErrInvalidSplitCommitmentWitness represents an error case where an
	// asset input has a malformed split commitment witness.
	ErrInvalidSplitCommitmentWitness

	// ErrInvalidSplitCommitmentProof represents an error case where an
	// asset split has an invalid split commitment proof.
	ErrInvalidSplitCommitmentProof
)

func (k ErrorKind) String() string {
	switch k {
	case ErrNoInputs:
		return "missing asset input(s)"
	case ErrNoSplitCommitment:
		return "missing asset split commitment root"
	case ErrInputMismatch:
		return "asset input(s) mismatch"
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
	case ErrInvalidScriptVersion:
		return "invalid script version"
	case ErrInvalidSplitAssetType:
		return "invalid split asset type"
	case ErrInvalidSplitCommitmentWitness:
		return "invalid split commitment asset witness"
	case ErrInvalidSplitCommitmentProof:
		return "invalid split commitment proof"
	default:
		return "unknown"
	}
}

// Error represents an error returned by the Taro VM.
type Error struct {
	Kind  ErrorKind
	Inner error
}

func newErrKind(kind ErrorKind) Error {
	return Error{Kind: kind}
}

func newErrInner(kind ErrorKind, inner error) Error {
	return Error{Kind: kind, Inner: inner}
}

func (e Error) Error() string {
	if e.Inner == nil {
		return e.Kind.String()
	}
	return fmt.Errorf("%v: %w", e.Kind, e.Inner).Error()
}

func (e Error) String() string {
	return e.Error()
}
