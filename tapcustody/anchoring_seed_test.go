package tapcustody

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// trimmedTransferFile builds the shape a sender can choose to select
// the triggerless seed path: a single-proof file whose asset is an
// ordinary transfer — a real, non-zero previous ID — with its
// provenance carried in AdditionalInputs rather than in a preceding
// proof of the same file.
//
// Such a file verifies. proof.File.Verify starts with no predecessor
// and imposes no "first proof must be genesis" rule, and the linkage
// check that binds a proof to its predecessor's outpoint is applied
// only when a predecessor exists, so trimming the history off the
// front leaves the remaining proof individually valid. The asset's
// prevAssets are rebuilt from AdditionalInputs, which is exactly where
// this shape puts them.
func trimmedTransferFile(t *testing.T, anchorTx *wire.MsgTx,
	inputTx *wire.MsgTx) *proof.File {

	t.Helper()

	// The input the transfer spends: its own confirmed proof, which
	// travels along as an additional input.
	inputScriptKey := asset.NewScriptKey(test.RandPubKey(t))
	inputProof := proof.Proof{
		PrevOut: wire.OutPoint{Hash: chainhash.Hash{0x77}, Index: 0},
		BlockHeader: wire.BlockHeader{
			Version:    1,
			MerkleRoot: chainhash.Hash{0xcc, 0xdd},
		},
		BlockHeight:   690,
		AnchorTx:      *inputTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: inputScriptKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	inputFile, err := proof.NewFile(proof.V0, inputProof)
	require.NoError(t, err)

	// The tip: a genuine transfer, so a non-zero previous ID.
	prevID := asset.PrevID{
		OutPoint: wire.OutPoint{
			Hash:  inputTx.TxHash(),
			Index: 0,
		},
		ScriptKey: asset.ToSerialized(inputScriptKey.PubKey),
	}
	tip := proof.Proof{
		PrevOut: prevID.OutPoint,
		BlockHeader: wire.BlockHeader{
			Version:    1,
			MerkleRoot: chainhash.Hash{0xaa, 0xbb},
		},
		BlockHeight:   700,
		AnchorTx:      *anchorTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: asset.NewScriptKey(test.RandPubKey(t)),
			PrevWitnesses: []asset.Witness{{
				PrevID:    &prevID,
				TxWitness: wire.TxWitness{{0x01}},
			}},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
		AdditionalInputs: []proof.File{*inputFile},
	}

	file, err := proof.NewFile(proof.V0, tip)
	require.NoError(t, err)

	return file
}

// TestReceiveTriggerPointsTrimmedTransfer asserts that a sender cannot
// select the triggerless seed path for an ordinary transfer by trimming
// the proof file to a single entry.
//
// The seed path exists for a genesis, which has no prior outpoint for
// any foreign spender to foreclose against. An anchoring registered
// that way carries no trigger set, so the watcher opens no spend
// subscriptions for it and its phase can never derive Abandoned. Were
// a transfer admitted there, a sender could double-spend the anchor
// after delivery and the receiver would keep the materialized assets
// and a completed address event for a transaction the chain discarded,
// with no compensation ever running.
//
// The provenance is in AdditionalInputs, so the triggers are derivable
// and the ordinary path applies.
func TestReceiveTriggerPointsTrimmedTransfer(t *testing.T) {
	t.Parallel()

	inputTx := wire.NewMsgTx(2)
	inputTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	inputTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xcc}))

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: inputTx.TxHash(), Index: 0,
	}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	file := trimmedTransferFile(t, anchorTx, inputTx)
	require.EqualValues(t, 1, file.NumProofs())

	tip, err := file.ProofAt(0)
	require.NoError(t, err)
	require.False(
		t, tip.Asset.IsGenesisAsset(),
		"fixture must be an ordinary transfer, not a genesis",
	)

	points, err := receiveTriggerPoints(file, tip)
	require.NoError(t, err)
	require.NotErrorIs(
		t, err, ErrNoTriggers,
		"a trimmed transfer must not reach the seed path: the "+
			"anchoring it registers there can never be abandoned",
	)

	// The trigger is the outpoint the transfer actually spends, with
	// the script recovered from the additional input's own tip.
	require.Len(t, points, 1)
	require.Equal(
		t, wire.OutPoint{Hash: inputTx.TxHash(), Index: 0},
		points[0].OutPoint,
	)
	require.Equal(t, inputTx.TxOut[0].PkScript, points[0].PkScript)
	require.EqualValues(t, 690, points[0].HeightHint)
}

// TestReceiveTriggerPointsGenesisStillSeeds asserts the legitimate case
// still reaches the seed path: a genuine genesis has no asset-bearing
// previous outpoint, so there is nothing to watch and seeding the
// already-confirmed anchor transaction is the only way to stake it.
func TestReceiveTriggerPointsGenesisStillSeeds(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)
	require.True(t, tip.Asset.IsGenesisAsset())

	_, err = receiveTriggerPoints(file, tip)
	require.ErrorIs(t, err, ErrNoTriggers)
}

// TestReceiveTriggerPointsUntriggerableTransfer asserts that a
// non-genesis proof with no recoverable inputs at all is refused rather
// than quietly downgraded to a seed. It cannot be watched, and saying
// so lets the caller report the outcome instead of recording a
// registration that protects nothing.
func TestReceiveTriggerPointsUntriggerableTransfer(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	// A transfer witness, but no preceding proof and no additional
	// inputs to recover the spent outpoint's script from.
	tip := proof.Proof{
		PrevOut:     wire.OutPoint{Hash: chainhash.Hash{0x99}},
		BlockHeight: 700,
		AnchorTx:    *anchorTx,
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: asset.NewScriptKey(test.RandPubKey(t)),
			PrevWitnesses: []asset.Witness{{
				PrevID: &asset.PrevID{
					OutPoint: wire.OutPoint{
						Hash: chainhash.Hash{0x99},
					},
				},
				TxWitness: wire.TxWitness{{0x01}},
			}},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	file, err := proof.NewFile(proof.V0, tip)
	require.NoError(t, err)

	_, err = receiveTriggerPoints(file, &tip)
	require.Error(t, err)
	require.True(
		t, errors.Is(err, ErrUnwatchable),
		"expected ErrUnwatchable, got %v", err,
	)
	require.NotErrorIs(t, err, ErrNoTriggers)
}
